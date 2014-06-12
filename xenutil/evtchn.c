//
// evtchn.c - Support routines for communication between the
//            Xen event channel PCI device and paravirtualized
//            drivers.
//
// Copyright (c) 2006 XenSource, Inc. - All rights reserved.
//

/*
 * Copyright (c) 2014 Citrix Systems, Inc.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


#include "ntddk.h"
#define XSAPI_FUTURE_CONNECT_EVTCHN
#include "xsapi.h"
#include "xsapi-future.h"

#include "evtchn.h"
#include "scsiboot.h"

#include "hypercall.h"
#include "hvm.h"
#include "iohole.h"
#include "xenbus.h"
#include "debug.h"

#include <event_channel.h>

/* We implement the legacy port masking API */
#define XSAPI_LEGACY_PORT_MASK
#include "xsapi-legacy.h"

//
// Dont care about unreferenced formal parameters here
//
#pragma warning( disable : 4100 )

struct evtchn_port_handler {
    struct evtchn_port_handler *next, *prev;
    int xen_port;
    PEVTCHN_HANDLER_CB handler;
    void *handler_context;

    enum {
        EVTCHN_CLASS_INTERDOMAIN,
        EVTCHN_CLASS_INTERDOMAIN_DPC,
        EVTCHN_CLASS_FIXED,
        EVTCHN_CLASS_VIRQ,
        EVTCHN_CLASS_ALIEN
    } class;
    union {
        DOMAIN_ID interdomain;
        int virq;
        struct {
            DOMAIN_ID dom;
            KDPC dpc;

            /* DPC insertion control field.  This can be either 0 (DPC
               neither queued nor running), 1 (DPC either queued or
               running, but not both), or 2 (DPC both queued and
               currently running).  During normal operation, it is
               only accessed from CPU 0, but it may be accessed from
               another CPU if the port is stopped. */
            /* (Actually, we decrement it a little bit early when the
               DPC stops running.  It is, however, guaranteed that we
               won't touch the port again from the DPC after we've
               decremented the count. (Unless it gets inserted again,
               of course.)) */
            /* Think of it this way: there are two interesting and
             * orthoginal ``real'' state bits: is the DPC queued, and
             * is the DPC currently running.  Denote queued by Q, not
             * queued by q, running by R, and not running by r (where
             * running means ``could conceivably touch the port
             * structure before returning'').  You then get a state
             * transition diagram which looks like this:
             *
             *         F
             * +<-------------<+
             * v               ^
             * |               |
             * v   I       D   ^
             * qr >--> Qr >--> qR
             *         ^       v
             *         |       | I
             *         |       |
             *         ^   F   v
             *         +<-----<QR
             *
             * Where I is the interrupt queueing the DPC, D is the DPC
             * starting, and F is the DPC finishing with the port
             * structure.  If the interrupt fires in Qr or QR then
             * nothing happens, because the DPC is already queued (so
             * the I transition can't happen, even though the
             * interrupt has fired).  Likewise, D can't happen in a q
             * state, and F can't happen in an r state, so this
             * diagram covers all possible transitions.
             *
             * We abstract the state machine like so:
             *
             * qr -> 0
             * Qr -> 1
             * qR -> 1
             * QR -> 2
             *
             * because I and F are much easier to observe than D, and
             * we don't really care about D transitions.  That gives
             * us an abstract state machine which looks like this:
             *
             *       F
             * +<----------<+
             * v            ^
             * v     I      ^      I
             * 0 >--------> 1 >---------> 2
             *              ^             v
             *              ^             v
             *              +<-----------<+
             *                     F
             *
             * In other words, we increment the count every time we
             * queue the DPC, and decrement it every time it finishes.
             */
            LONG insert_count;
            BOOLEAN stopping;

            /* only valid if class == EVTCHN_CLASS_ALIEN */
            ALIEN_EVTCHN_PORT alien_port;
        } interdomain_dpc;
    } u;
};
MAKE_WRAPPER_PRIV(EVTCHN_PORT, struct evtchn_port_handler *)

extern BOOLEAN late_pre_suspend;

#define MAX_EVTCHN 256
static struct evtchn_port_handler *EventChannelHandlers[MAX_EVTCHN];
static struct evtchn_port_handler *HeadEvtchnHandler;
static BOOLEAN interrupt_live;

static struct irqsafe_lock EventChannelLock;
static EVTCHN_DEBUG_CALLBACK EvtchnDebugHandle;
static unsigned bogus_evtchn_interrupts;
static unsigned late_evtchn_interrupts;
static unsigned evtchn_interrupts;
static unsigned last_evtchn_serviced;
static unsigned evtchn_dpcs;
static unsigned bogus_dpcs;
static unsigned evtchn_counters[64];

static void
ClearBit(void *buffer, unsigned off)
{
    LONG *b = buffer;
    unsigned ind = off / 32;
    LONG mask = ~(1 << (off % 32));
    InterlockedAnd(&b[ind], mask);
}

static BOOLEAN
TestAndClearBit(void *buffer, unsigned off)
{
    LONG *b = buffer;
    unsigned ind = off / 32;
    LONG mask = ~(1 << (off % 32));
    LONG r;
    r = InterlockedAnd(&b[ind], mask);
    if (r & ~mask)
        return TRUE;
    else
        return FALSE;
}

static BOOLEAN
TestBit(void *buffer, unsigned off)
{
    LONG *b = buffer;
    unsigned ind = off / 32;

    if (b[ind] & (1 << (off % 32)))
        return TRUE;
    else
        return FALSE;
}

static void
SetBit(void *buffer, unsigned off)
{
    LONG *b = buffer;
    unsigned ind = off / 32;
    LONG mask = 1 << (off % 32);
    InterlockedOr(&b[ind], mask);
}

static void
EvtchnClearEvtchn(unsigned port)
{
    ClearBit(HYPERVISOR_shared_info->evtchn_pending, port);
}

static void
unmask_port(unsigned port)
{
    ClearBit(HYPERVISOR_shared_info->evtchn_mask, port);
}

static void
mask_port(unsigned port)
{
    SetBit(HYPERVISOR_shared_info->evtchn_mask, port);
}

void
EvtchnPortMask(__in EVTCHN_PORT _port)
{
    struct evtchn_port_handler *port = unwrap_EVTCHN_PORT(_port);
    XM_ASSERT(port->class != EVTCHN_CLASS_INTERDOMAIN_DPC);
    if (port->xen_port != -1)
        mask_port(port->xen_port);
}

/* Return true if @port is unmasked and pending. */
static BOOLEAN
EvtchnEvtchnPendingP(unsigned port)
{
    return
        !TestBit(HYPERVISOR_shared_info->evtchn_mask, port) &&
         TestBit(HYPERVISOR_shared_info->evtchn_pending, port);
}

/* Unmask a port, and return true if it's currently pending i.e. if
   we've lost an edge while it was masked.  Clears the pending bit in
   the process.  */
BOOLEAN
EvtchnPortUnmask(__in EVTCHN_PORT eport)
{
    struct evtchn_port_handler *port = unwrap_EVTCHN_PORT(eport);
    XM_ASSERT(port->class != EVTCHN_CLASS_INTERDOMAIN_DPC);
    if (port->xen_port == -1)
        return FALSE;
    unmask_port(port->xen_port);
    if (TestAndClearBit(HYPERVISOR_shared_info->evtchn_pending,
                        port->xen_port)) {
        return TRUE;
    } else {
        return FALSE;
    }
}

/* Cause Xen to inject a given port soon. */
VOID
EvtchnRaiseLocally(__in EVTCHN_PORT port)
{
    struct evtchn_unmask eum;

    XM_ASSERT(!is_null_EVTCHN_PORT(port));

    if (unwrap_EVTCHN_PORT(port)->xen_port == -1)
        return;

    eum.port = unwrap_EVTCHN_PORT(port)->xen_port;
#ifdef AMD64
    if ( HYPERVISOR_shared_info->evtchn_mask[eum.port >> 6] &
         (1ull << (eum.port & 63)) )
#else
    if ( HYPERVISOR_shared_info->evtchn_mask[eum.port >> 5] &
         (1 << (eum.port & 31)) )
#endif
    {
        /* The port is currently masked.  Set it pending and
         * return. */
        SetBit(HYPERVISOR_shared_info->evtchn_pending, eum.port);
#ifdef AMD64
        if ( HYPERVISOR_shared_info->evtchn_mask[eum.port >> 6] &
             (1ull << (eum.port & 63)) )
#else
        if ( HYPERVISOR_shared_info->evtchn_mask[eum.port >> 5] &
             (1 << (eum.port & 31)) )
#endif
        {
            /* It's pending and masked.  Whoever masked it will unmask
               it soon, at which point they'll notice it was pending
               and it becomes no longer our problem. */
            return;
        } else {
            /* We raced with someone unmasking the port.  Tell Xen to
               raise it. */
            mask_port(eum.port);
            HYPERVISOR_event_channel_op(EVTCHNOP_unmask, &eum);
        }
    } else {
        mask_port(eum.port);
        SetBit(HYPERVISOR_shared_info->evtchn_pending, eum.port);
        HYPERVISOR_event_channel_op(EVTCHNOP_unmask, &eum);
    }
}

/* Wait for the interrupt to finish firing. */
static void
SynchronizeWithInterrupt(void)
{
    /* We need to finish everything we're doing, look at
       interrupt_live, and then start whatever it is we want to do
       next i.e. memory barriers before and after the read of
       interrupt_live. */

    XsMemoryBarrier();

    while (interrupt_live)
        XsMemoryBarrier();

    XsMemoryBarrier();
}

static struct evtchn_port_handler *
allocate_handler(PEVTCHN_HANDLER_CB cb, PVOID Context)
{
    struct evtchn_port_handler *port;

    port = XmAllocateZeroedMemory(sizeof(*port));
    if (port) {
        port->handler = cb;
        port->handler_context = Context;
    }

    return port;
}

/* Add a handler to the main dispatch list.  Returns TRUE on success
   or FALSE on error.  The only way this can fail is if something else
   is already registered for that Xen port. */
static BOOLEAN
register_handler(struct evtchn_port_handler *port)
{
    BOOLEAN success;
    KIRQL irql;

    XM_ASSERT(port->xen_port >= 0 && port->xen_port < MAX_EVTCHN);

    irql = acquire_irqsafe_lock(&EventChannelLock);
    if (EventChannelHandlers[port->xen_port]) {
        success = FALSE;
    } else {
        /* We haven't turned off interrupts on other vcpus, so an
           evtchn event could come in while we're setting this up, and
           so we need to make sure that port is fully initialised
           before putting it in the table. */
        XsMemoryBarrier();
        EventChannelHandlers[port->xen_port] = port;
        port->next = HeadEvtchnHandler;
        port->prev = NULL;
        if (HeadEvtchnHandler)
            HeadEvtchnHandler->prev = port;
        HeadEvtchnHandler = port;
        unmask_port(port->xen_port);
        success = TRUE;
    }
    release_irqsafe_lock(&EventChannelLock, irql);

    return success;
}

/* Given an evtchn_port_handler, do whatever needs to be done to
   register it with Xen.  This is done for both initial allocation and
   recovery from save/restore.  Returns TRUE on success, FALSE on
   error. */
/* Note that for classes other than FIXED, this can change the
   xen_port field of @port. */
static BOOLEAN
reconstruct_handler(struct evtchn_port_handler *port)
{
    int err;
    /* Re-register with Xen */
    switch (port->class) {
    case EVTCHN_CLASS_INTERDOMAIN: 
    case EVTCHN_CLASS_INTERDOMAIN_DPC: {
        evtchn_alloc_unbound_t op;
        op.dom = DOMID_SELF;
        if (port->class == EVTCHN_CLASS_INTERDOMAIN_DPC) {
            op.remote_dom =
                (uint16_t)unwrap_DOMAIN_ID(port->u.interdomain_dpc.dom);
        } else {
            op.remote_dom = (uint16_t)unwrap_DOMAIN_ID(port->u.interdomain);
        }
        err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &op);
        if (err)
            return FALSE;
        port->xen_port = op.port;
        if (!register_handler(port))
            TraceBugCheck(("Failed to reconstruct handler for port %d\n",
                           port->xen_port));
        break;
    }
    case EVTCHN_CLASS_ALIEN: {
        evtchn_bind_interdomain_t bind;
        bind.remote_dom =
            (uint16_t)unwrap_DOMAIN_ID(port->u.interdomain_dpc.dom);
        bind.remote_port = unwrap_ALIEN_EVTCHN_PORT(port->u.interdomain_dpc.alien_port);
        bind.local_port = 0;
        err = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain, &bind);
        if (err)
            return FALSE;
        port->xen_port = bind.local_port;
        if (!register_handler(port))
            TraceBugCheck(("Failed to reconstruct alien handler for port %d\n",
                           port->xen_port));
        break;
    }
    case EVTCHN_CLASS_FIXED: {
        if (!register_handler(port)) {
            TraceWarning(("Multiple handlers for port %d?\n",
                          port->xen_port));
        }
        break;
    }
    case EVTCHN_CLASS_VIRQ: {
        evtchn_bind_virq_t op;
        op.virq = port->u.virq;
        op.vcpu = 0;

        err = HYPERVISOR_event_channel_op(EVTCHNOP_bind_virq, &op);
        if (err)
            return FALSE;
        port->xen_port = op.port;

        if (!register_handler(port))
            TraceBugCheck(("failed to rebind virq %d\n", port->u.virq));
        break;
    }
    }
    return TRUE;
}

/* Unregister a handler for a port.  Note that this can be called
   multiple times for the same port. */
void
EvtchnPortStop(EVTCHN_PORT eport)
{
    evtchn_close_t op;
    struct evtchn_port_handler *port;
    KIRQL irql;

    XM_ASSERT(!is_null_EVTCHN_PORT(eport));

    port = unwrap_EVTCHN_PORT(eport);

    irql = acquire_irqsafe_lock(&EventChannelLock);

    /* Only do this bit if we're currently registered */
    if (port->xen_port >= 0 &&
        EventChannelHandlers[port->xen_port] == port) {
        XM_ASSERT(port->xen_port >= 0 && port->xen_port < MAX_EVTCHN);

        op.port = port->xen_port;
        HYPERVISOR_event_channel_op(EVTCHNOP_close, &op);

        if (port->next)
            port->next->prev = port->prev;
        if (port->prev)
            port->prev->next = port->next;
        else
            HeadEvtchnHandler = port->next;

        EventChannelHandlers[port->xen_port] = NULL;
    } else {
        TraceVerbose(("Stopping an unregisted port?\n"));
    }

    release_irqsafe_lock(&EventChannelLock, irql);

    /* Wait for any extant invocations of the interrupt handler to
       finish, so that we can be certain that any invocations of the
       event channel handler have finished, and that there aren't any
       cached pointers to the handler structure. */

    SynchronizeWithInterrupt();

    /* If it's a DPC port, we need to wait for the DPC to finish.  We
       know that it can't get requeued because we've unhooked it from
       the array and synchronised with interrupts. */
    if (port->class == EVTCHN_CLASS_INTERDOMAIN_DPC ||
        port->class == EVTCHN_CLASS_ALIEN) {

        /*
         * We cannot spin for a DPC to finish if we're at DISPATCH level
         * since we may be holding it off the CPU. If we're lower than
         * dispatch then we need to yield the CPU and allow any queued
         * DPC to run.
         */
        port->u.interdomain_dpc.stopping = TRUE;
        _ReadWriteBarrier();

        while (port->u.interdomain_dpc.insert_count != 0) {
            LARGE_INTEGER interval;

            /* Back off 10ms and try again. */
            interval.QuadPart = -100000;

            XM_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
            KeDelayExecutionThread(KernelMode,
                                   FALSE,
                                   &interval);

            /* Need to have seen insert_count go clear before we
             * return. */
            XsMemoryBarrier();
        }
    }

    /* This must be after the interrupt handler and any DPC have
       finished with the port. */
    port->xen_port = -1;
    port->handler = NULL;
}

void
EvtchnClose(EVTCHN_PORT port)
{
    EvtchnPortStop(port);

    XmFreeMemory(unwrap_EVTCHN_PORT(port));
}

static void
DpcPortDpcHandler(PKDPC dpc, PVOID ctxt, PVOID ignore1, PVOID ignore2)
{
    struct evtchn_port_handler *port;
    BOOLEAN done_something = FALSE;

    UNREFERENCED_PARAMETER(ignore1);
    UNREFERENCED_PARAMETER(ignore2);

    port = ctxt;
    XM_ASSERT(dpc == &port->u.interdomain_dpc.dpc);

    evtchn_dpcs++;

    while (1) {
        /* Keep calling the handler until the port goes clear. */
        while (TestAndClearBit(HYPERVISOR_shared_info->evtchn_pending,
                               port->xen_port)) {
            done_something = TRUE;
            XM_ASSERT(port->handler != NULL);
            port->handler(port->handler_context);
        }

        /* It's currently idle.  Unmask it. */
        unmask_port(port->xen_port);

        if (!TestBit(HYPERVISOR_shared_info->evtchn_pending,
                     port->xen_port)) {
            /* The port is clear and unmasked.  The normal interrupt
               handler will queue the DPC again if it gets raised
               again. */

            /* This needs to be interlocked because it's used to
               synchronise with EvtchnPortStop(), which is about to
               release the port from another CPU. */
            _ReadWriteBarrier();
            InterlockedDecrement(&port->u.interdomain_dpc.insert_count);

            /* The DPC is logically not running at this point, because
               it's guaranteed not to touch the port again before it
               exits. */
            break;
        }

        /* The port may have been raised in between the last
           TestAndClear() and the unmask.  In that case, we are
           responsible for handling the event.  It's also possible
           that it was raised between the unmask_port and the
           TestBit(), in which case the interrupt handler is
           responsible for it.  It's not possible for us to
           distinguish these two situations, so assume it's our
           problem.  The interrupt will re-queue the DPC, so that
           we'll get run again redundantly, but that's okay: we handle
           the event-not-pending case correctly here (by just not
           doing anything), and it should be rare enough that it
           doesn't matter from a performance point of view. */
        mask_port(port->xen_port);
    }

    if (!done_something)
        bogus_dpcs++;
}

static void
FireHandler(struct evtchn_port_handler *handler)
{
    if (handler->class == EVTCHN_CLASS_INTERDOMAIN_DPC ||
        handler->class == EVTCHN_CLASS_ALIEN) {
        mask_port(handler->xen_port);
        if (KeInsertQueueDpc(&handler->u.interdomain_dpc.dpc,
                             NULL,
                             NULL)) {
            /* This isn't an interlocked operation.  It's accessed by
               the interrupt (i.e. us), the DPC (which isn't running,
               because we're an interrupt on the same CPU, so we'll
               have stopped it), and EvtchnPortStop().  Port stop will
               only test it once it's unhooked the port and done an
               interrupt barrier, so we can't race with that from
               here, so a non-interlocked operation is sufficient. */
            XM_ASSERT(!handler->u.interdomain_dpc.stopping);
            handler->u.interdomain_dpc.insert_count++;
        }
    } else {
        EvtchnClearEvtchn(handler->xen_port);
        handler->handler(handler->handler_context);
    }
}

#ifdef AMD64
#define EVTCHNS_PER_TOPLEVEL 64
#define EVTCHN_SUB_MASK(x) (1ull << (x))
#else
#define EVTCHNS_PER_TOPLEVEL 32
#define EVTCHN_SUB_MASK(x) (1 << (x))
#endif

/* XXX SMP */
BOOLEAN
EvtchnHandleInterrupt(
    IN PVOID Interrupt,
    IN OUT PVOID Context
)
{
    vcpu_info_t *vit = &HYPERVISOR_shared_info->vcpu_info[0];
    unsigned port;
    struct evtchn_port_handler *handler;
    int done_something = 0;
    ULONG_PTR evtchns_pending;
    ULONG_PTR sel;
    unsigned next_top_selector, next_sub_selector;

    interrupt_live = TRUE;

    evtchn_interrupts++;

    if (!vit->evtchn_upcall_pending)
        late_evtchn_interrupts++;

    while (vit->evtchn_upcall_pending) {
        vit->evtchn_upcall_pending = 0;

        /* We need this to act as a full memory barrier.  xchg is
           already a processor barrier, so just need to worry about
           the compiler. */
        _ReadWriteBarrier();
        sel =
            (ULONG_PTR)InterlockedExchangePointer(
                (PVOID*)&vit->evtchn_pending_sel,
                NULL);
        _ReadWriteBarrier();

        last_evtchn_serviced++;
        next_top_selector = last_evtchn_serviced / EVTCHNS_PER_TOPLEVEL;
        next_sub_selector = last_evtchn_serviced % EVTCHNS_PER_TOPLEVEL;

        while (sel) {
            if (sel & EVTCHN_SUB_MASK(next_top_selector)) {
                sel &= ~EVTCHN_SUB_MASK(next_top_selector);

                evtchns_pending =
                    HYPERVISOR_shared_info->evtchn_pending[next_top_selector]&
                    ~HYPERVISOR_shared_info->evtchn_mask[next_top_selector];

                while (evtchns_pending) {
                    if (evtchns_pending &
                        EVTCHN_SUB_MASK(next_sub_selector)) {
                        evtchns_pending &=
                            ~EVTCHN_SUB_MASK(next_sub_selector);

                        port =
                            next_top_selector * EVTCHNS_PER_TOPLEVEL +
                            next_sub_selector;
                        handler = EventChannelHandlers[port];
                        if (port < (sizeof(evtchn_counters) /
                                    sizeof(evtchn_counters[0])))
                            evtchn_counters[port]++;
                        last_evtchn_serviced = port;

                        if (handler) {
                            FireHandler(handler);
                        } else {
                            EvtchnClearEvtchn(port);
                            TraceWarning (("No handler for port %d?\n",
                                           port));
                        }

                        done_something = 1;
                    }
                    next_sub_selector = (next_sub_selector + 1) %
                        EVTCHNS_PER_TOPLEVEL;
                }
            }
            next_top_selector = (next_top_selector + 1) % EVTCHNS_PER_TOPLEVEL;
            next_sub_selector = 0;
        }
    }

    bogus_evtchn_interrupts += !done_something;

    /* Want to make sure all of the handlers really have finished
       before we clear interrupt_live. */
    XsMemoryBarrier();

    interrupt_live = FALSE;

    if (done_something)
        return TRUE;
    else
        return FALSE;
}

void
EvtchnNotifyRemote(__in EVTCHN_PORT port)
{
    evtchn_send_t op;
    int r;

    op.port = unwrap_EVTCHN_PORT(port)->xen_port;
    r = HYPERVISOR_event_channel_op(EVTCHNOP_send, &op);
    if (r != 0)
        TraceWarning (("Failed to send evtchn on port %d: %d.\n",
                       op.port, r));

}

/* Register a handler for a given port */
EVTCHN_PORT
EvtchnRegisterHandler(int xen_port, PEVTCHN_HANDLER_CB cb, PVOID Context)
{
    struct evtchn_port_handler *port;

    port = allocate_handler(cb, Context);
    if (!port)
        return null_EVTCHN_PORT();
    port->class = EVTCHN_CLASS_FIXED;
    port->xen_port = xen_port;

    if (!reconstruct_handler(port)) {
        XmFreeMemory(port);
        return null_EVTCHN_PORT();
    }
    return wrap_EVTCHN_PORT(port);
}

EVTCHN_PORT
EvtchnBindVirq(int virq, PEVTCHN_HANDLER_CB handler, PVOID context)
{
    struct evtchn_port_handler *port;

    port = allocate_handler(handler, context);
    if (!port)
        return null_EVTCHN_PORT();
    port->class = EVTCHN_CLASS_VIRQ;
    port->u.virq = virq;

    if (!reconstruct_handler(port)) {
        XmFreeMemory(port);
        return null_EVTCHN_PORT();
    } else {
        return wrap_EVTCHN_PORT(port);
    }
}

EVTCHN_PORT
EvtchnAllocUnboundDpc(DOMAIN_ID domid, PEVTCHN_HANDLER_CB cb, PVOID Context)
{
    struct evtchn_port_handler *port;

    XM_ASSERT(unwrap_DOMAIN_ID(domid) ==
              (uint16_t)unwrap_DOMAIN_ID(domid));

    port = allocate_handler(cb, Context);
    if (!port)
        return null_EVTCHN_PORT();
    port->class = EVTCHN_CLASS_INTERDOMAIN_DPC;
    port->u.interdomain_dpc.dom = domid;
    KeInitializeDpc(&port->u.interdomain_dpc.dpc,
                    DpcPortDpcHandler,
                    port);
    if (!reconstruct_handler(port)) {
        XmFreeMemory(port);
        return null_EVTCHN_PORT();
    } else {
        return wrap_EVTCHN_PORT(port);
    }
}

EVTCHN_PORT
EvtchnConnectRemotePort(DOMAIN_ID domid,
                        ALIEN_EVTCHN_PORT aport,
                        PEVTCHN_HANDLER_CB cb,
                        void *context)
{
    struct evtchn_port_handler *port;

    XM_ASSERT(unwrap_DOMAIN_ID(domid) ==
              (uint16_t)unwrap_DOMAIN_ID(domid));

    port = allocate_handler(cb, context);
    if (!port)
        return null_EVTCHN_PORT();
    port->class = EVTCHN_CLASS_ALIEN;
    port->u.interdomain_dpc.dom = domid;
    port->u.interdomain_dpc.alien_port = aport;
    KeInitializeDpc(&port->u.interdomain_dpc.dpc,
                    DpcPortDpcHandler,
                    port);
    if (!reconstruct_handler(port)) {
        XmFreeMemory(port);
        return null_EVTCHN_PORT();
    } else {
        return wrap_EVTCHN_PORT(port);
    }
}

EVTCHN_PORT
EvtchnAllocUnbound(DOMAIN_ID domid, PEVTCHN_HANDLER_CB cb, PVOID Context)
{
    struct evtchn_port_handler *port;

    XM_ASSERT(unwrap_DOMAIN_ID(domid) ==
              (uint16_t)unwrap_DOMAIN_ID(domid));

    port = allocate_handler(cb, Context);
    if (!port)
        return null_EVTCHN_PORT();
    port->class = EVTCHN_CLASS_INTERDOMAIN;
    port->u.interdomain = domid;

    if (!reconstruct_handler(port)) {
        XmFreeMemory(port);
        return null_EVTCHN_PORT();
    } else {
        return wrap_EVTCHN_PORT(port);
    }
}

static VOID
EvtchnDebug(VOID *ignore)
{
    int x;
    KIRQL kirql;

    UNREFERENCED_PARAMETER(ignore);

    TraceInternal(("%d evtchn interrupts, %d bogus, %d late.\n",
                  evtchn_interrupts, bogus_evtchn_interrupts,
                  late_evtchn_interrupts));
    TraceInternal(("%d DPCs, %d bogus,\n", evtchn_dpcs, bogus_dpcs));
    TraceInternal(("upcall pending %d, mask %d, sel %p.\n",
                  HYPERVISOR_shared_info->vcpu_info[0].evtchn_upcall_pending,
                  HYPERVISOR_shared_info->vcpu_info[0].evtchn_upcall_mask,
                  HYPERVISOR_shared_info->vcpu_info[0].evtchn_pending_sel));
    evtchn_interrupts = bogus_evtchn_interrupts = 0;
    late_evtchn_interrupts = 0;
    for (x = 0; x < 32; x++) {
        if (evtchn_counters[x])
            TraceInternal(("%d fired %d times, pending %d, mask %d.\n", x,
                          evtchn_counters[x],
                          HYPERVISOR_shared_info->evtchn_pending[0] &
                              ((ULONG_PTR)1 << x),
                          HYPERVISOR_shared_info->evtchn_mask[0] &
                              ((ULONG_PTR)1 << x)));
        evtchn_counters[x] = 0;
    }

    kirql = acquire_irqsafe_lock(&EventChannelLock);
    for (x = 0; x < MAX_EVTCHN; x++) {
        struct evtchn_port_handler *eph = EventChannelHandlers[x];
        if (eph) {
            int pending, mask;
            pending =
                !!(((PULONG)HYPERVISOR_shared_info->evtchn_pending)[x/32] &
                   (1 << (x % 32)));
            mask =
                !!(((PULONG)HYPERVISOR_shared_info->evtchn_mask)[x/32] &
                   (1 << (x % 32)));

            TraceInternal(("Port %d, class %d, pending %d, mask %d\n",
                         x, eph->class, pending, mask));
            if (eph->class == EVTCHN_CLASS_INTERDOMAIN) {
                TraceInternal(("dom %d\n",
                             unwrap_DOMAIN_ID(eph->u.interdomain)));
            } else if (eph->class == EVTCHN_CLASS_INTERDOMAIN_DPC) {
                TraceInternal(("dom DPC %d\n",
                             unwrap_DOMAIN_ID(eph->u.interdomain_dpc.dom)));
            } else if (eph->class == EVTCHN_CLASS_ALIEN) {
                TraceInternal(("alien %d::%d\n",
                             unwrap_DOMAIN_ID(eph->u.interdomain_dpc.dom),
                             unwrap_ALIEN_EVTCHN_PORT(eph->u.interdomain_dpc.alien_port)));
            } else if (eph->class == EVTCHN_CLASS_VIRQ) {
                TraceInternal(("virq %d\n", eph->u.virq));
            }
        }
    }
    release_irqsafe_lock(&EventChannelLock, kirql);
}

static void
EvtchnRecoverFromSuspend(VOID *ignore, SUSPEND_TOKEN token)
{
    struct evtchn_port_handler *h, *n;
    unsigned count;

    memset(EventChannelHandlers, 0, sizeof(EventChannelHandlers));

    /* Walk the handler list and re-register all of them. */
    count = 0;
    h = HeadEvtchnHandler;
    HeadEvtchnHandler = NULL;
    while (h) {
        n = h->next;
        reconstruct_handler(h);
        h = n;
        count++;
        if (count > MAX_EVTCHN)
            TraceBugCheck(("Event channel list is corrupt!\n"));
    }
}

static BOOLEAN EvtchnStarted = FALSE;

//
// This callback from blockfront notifies us of the physical
// resources assigned by xen.
//
NTSTATUS
EvtchnStart(void)
{
    NTSTATUS status = STATUS_SUCCESS;
    struct evtchn_port_handler *n;
    static struct SuspendHandler *suspend_handler;

    if (!AustereMode && EvtchnStarted) {
        TraceVerbose(("event channels already started\n"));
        return STATUS_SUCCESS;
    }

    if (!XenPVFeatureEnabled(DEBUG_HA_SAFEMODE)) {
        UnplugIoemu();
    }

    memset(EventChannelHandlers, 0, sizeof(EventChannelHandlers));

    /* When we come back from hibernation, we're likely to still have
       a bunch of event channel port handlers lying around.  They're
       not useful any more (everyone has to re-register handlers when
       they come back from hibernate), so free them. */
    /* Austere mode handlers are allocated from the austere heap,
       which is released automatically when hibernation completes. */
    if (!AustereMode) {
        while (HeadEvtchnHandler) {
            n = HeadEvtchnHandler->next;
            HeadEvtchnHandler->xen_port = -1;
            HeadEvtchnHandler->prev = NULL;
            HeadEvtchnHandler->next = NULL;
            HeadEvtchnHandler = n;
        }
    } else {
        HeadEvtchnHandler = NULL;
    }

    status = InitHvm();
    TraceVerbose (("HVM ready.\n"));
    if (!NT_SUCCESS(status)) {
        TraceError (("Failed to initialise hvm.\n"));
        return status;
    }

    if (AustereMode)
        TraceNotice(("HVM init done.\n"));

    if (!AustereMode)
        ConnectDebugVirq();

    if (!suspend_handler)
        suspend_handler =
            EvtchnRegisterSuspendHandler(EvtchnRecoverFromSuspend, NULL,
                                         "EvtchnRecoverFromSuspend",
                                         SUSPEND_CB_EARLY);

    /* The per-vcpu evtchn_upcall_mask is useless in HVM guests, since
       the interrupt flag in eflags does the same thing better.  We
       therefore force it to zero.  Xen is somewhat inconsistent about
       the initial value of this field across configuration options
       and versions, and forcing it here makes things a bit
       simpler. */
    HYPERVISOR_shared_info->vcpu_info[0].evtchn_upcall_mask = 0;

    EvtchnDebugHandle = EvtchnSetupDebugCallback(EvtchnDebug, NULL);

    EvtchnStarted = TRUE;

    return status;
}

static ULONG EvtchnVector;

VOID
EvtchnSetVector(ULONG vector)
{
    EvtchnVector = vector;
}

ULONG
EvtchnGetVector(void)
{
    return EvtchnVector;
}

static BOOLEAN XenbusFrozen = FALSE;

// Undo the effects of EvtchnStart.  Scsiport is expected to have
// stopped and synchronised the interrupt before calling this.
VOID
EvtchnStop(VOID)
{
    //
    // Xenvbd is unloading. 
    // Go back to our own interrupt vector so event channels continue to work.
    //
    HvmSetCallbackIrq(EvtchnVector);

    DisconnectDebugVirq();

    //
    // Cleanup during hibernate as there are assumptions in xenvbd.
    //
    EvtchnReleaseDebugCallback(EvtchnDebugHandle);
    EvtchnDebugHandle = null_EVTCHN_DEBUG_CALLBACK();

    TraceDebug(("Shutting down HVM...\n"));
    CleanupHvm();

    TraceDebug(("Event channels stopped.\n"));
    EvtchnStarted = FALSE;
}

VOID
XenbusSetFrozen(BOOLEAN State)
{
    XenbusFrozen = State;
}

BOOLEAN
XenbusIsFrozen(VOID)
{
    return XenbusFrozen;
}

SYSTEM_POWER_STATE XenSystemPowerState = PowerSystemWorking;

VOID
XenSetSystemPowerState(
    IN  SYSTEM_POWER_STATE State
    )
{
    XenSystemPowerState = State;
}

SYSTEM_POWER_STATE
XenGetSystemPowerState(
    VOID
    )
{
    return XenSystemPowerState;
}


NTSTATUS
EvtchnReadRegistryParametersDword(PVOID Path, PCWSTR KeyName, PULONG Val)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;
    PUNICODE_STRING RegistryPath = Path;
    UNICODE_STRING ukey;
    UNICODE_STRING regbase;
    HANDLE hKey;
    WCHAR regpath[256];

    XM_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    regbase.Buffer = regpath;
    regbase.Length = 0;
    regbase.MaximumLength = 256 * sizeof(WCHAR);

    RtlInitUnicodeString(&ukey, KeyName);

    RtlCopyUnicodeString(&regbase, RegistryPath);
    RtlAppendUnicodeToString(&regbase, L"\\Parameters");

    InitializeObjectAttributes(&oa, &regbase,
                   OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                   NULL, NULL);
    status = ZwOpenKey(&hKey, KEY_READ, &oa);
    if (NT_SUCCESS(status)) {
        UNICODE_STRING valname;
        PKEY_VALUE_PARTIAL_INFORMATION pip;
        ULONG size;

        TraceDebug (("ZwOpenKey Succeeds\n"));
        pip = XmAllocateMemory(32);
        if (!pip) {
            ZwClose(hKey);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        TraceDebug (("XmAllocayeMemory said %p.\n", pip));
        RtlInitUnicodeString(&valname, KeyName);
        status = ZwQueryValueKey(hKey, &valname,
                     KeyValuePartialInformation, pip, 32,
                     &size);
        if (NT_SUCCESS(status)) {
            TraceDebug (("QueryValueKey Succeeds\n"));
            *Val = *(PULONG)pip->Data;
        } else {
            TraceInfo (("QueryValueKey Fails %x\n", status));
        }
        XmFreeMemory(pip);
    }
    ZwClose(hKey);
    return status;
}

/* Hack: when resuming from hibernation, we need to find out the
   current Windows version from high IRQL in order to decide which
   binpatches we're going to apply.  Cache the results so that they're
   available when they're needed. */

typedef
NTSTATUS
(*PFN_RTL_GET_VERSION)(
    IN OUT PRTL_OSVERSIONINFOW
    );


typedef
BOOLEAN
(*PFN_PS_GET_VERSION)(
    OUT PULONG,
    OUT PULONG,
    OUT PULONG,
    IN OUT PUNICODE_STRING
    );

VOID
XenutilGetVersionInfo(PRTL_OSVERSIONINFOEXW out)
{
    UNICODE_STRING functionName;
    PFN_RTL_GET_VERSION rtlGetVersion;
    PFN_PS_GET_VERSION psGetVersion;
    static RTL_OSVERSIONINFOEXW info;
    static int have_info;

    if (have_info) {
        *out = info;
        return;
    }
    XM_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    RtlZeroMemory(&info, sizeof(info));
    info.dwOSVersionInfoSize = sizeof(info);

    // Note: MmGetSystemRoutineAddress is supported in Windows 2000
    // and later systems.  RtlGetVersion was added in Windows XP.
    RtlInitUnicodeString(&functionName, L"RtlGetVersion");
    rtlGetVersion = (PFN_RTL_GET_VERSION)(ULONG_PTR)
                    MmGetSystemRoutineAddress(&functionName);

    if (rtlGetVersion != NULL)
    {
        rtlGetVersion((PRTL_OSVERSIONINFOW)&info);
    }
    else
    {
        // Must be pre XP (ie must be Windows 2000).  We could just
        // set the information but let's slurp it from PsGetVersion.
        // Note that PsGetVersion is obsolete so use
        // MmGetSystemRoutinAddress again rather than calling it
        // directly and risk some more modern system failing to load
        // this driver.

        RtlInitUnicodeString(&functionName, L"PsGetVersion");
        psGetVersion = (PFN_PS_GET_VERSION)(ULONG_PTR)
                       MmGetSystemRoutineAddress(&functionName);
        if (psGetVersion != NULL)
        {
            ULONG major;
            ULONG minor;
            ULONG buildNumber;

            psGetVersion(&major, &minor, &buildNumber, NULL);

            info.dwMajorVersion = major;
            info.dwMinorVersion = minor;
            info.dwBuildNumber  = buildNumber;
        }
        else
        {
            info.dwMajorVersion = 5; // fake it, windows 2000.
            info.dwMinorVersion = 0;
        }
    }
    have_info = 1;
    *out = info;
    return;
}

NTSTATUS
xenbus_write_evtchn_port(xenbus_transaction_t xbt, const char *prefix,
                         const char *node, EVTCHN_PORT eport)
{
    int port = unwrap_EVTCHN_PORT(eport)->xen_port;
    if (port == -1) {
        xenbus_fail_transaction(xbt, STATUS_INVALID_HANDLE);
        return STATUS_INVALID_HANDLE;
    }
    return xenbus_printf(xbt, prefix, node, "%u", port);
}

NTSTATUS
xenbus_read_evtchn_port(xenbus_transaction_t xbt, const char *prefix,
                        const char *node, ALIEN_EVTCHN_PORT *eport)
{
    ULONG64 res;
    NTSTATUS status;

    *eport = null_ALIEN_EVTCHN_PORT();
    status = xenbus_read_int(xbt, prefix, node, &res);
    if (!NT_SUCCESS(status))
        return status;
    if (res != (unsigned)res) {
        xenbus_fail_transaction(xbt, STATUS_DATA_ERROR);
        return STATUS_DATA_ERROR;
    }
    *eport = wrap_ALIEN_EVTCHN_PORT((unsigned)res);
    return STATUS_SUCCESS;
}

unsigned
xen_EVTCHN_PORT(EVTCHN_PORT port)
{
    return unwrap_EVTCHN_PORT(port)->xen_port;
}
