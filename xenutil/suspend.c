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

/* Basic suspend infrastructure */
#include "ntddk.h"
#include "xsapi.h"
#include "xsmtcapi.h"
#include "hvm.h"
#include "xenbus.h"
#include "hypercall.h"
#include "scsiboot.h"
#include "xenutl.h"

#include <sched.h>

/* Returns TRUE if the specified callback type is a supported type */
#define IS_VALID_CB_TYPE(type)  ((type == SUSPEND_CB_EARLY_TYPE)     ||           \
                                 (type == SUSPEND_CB_LATE_TYPE)      ||           \
                                 (type == PRE_SUSPEND_CB_EARLY_TYPE) ||           \
                                 (type == PRE_SUSPEND_CB_LATE_TYPE))

/* Initialise it to something which will be reasonably obvious. */
static ULONG suspend_count = 0xbeeffeed;

struct SuspendHandler {
    LIST_ENTRY le;
    char name[64];
    void (*cb)(void *data, SUSPEND_TOKEN token);
    void *data;
    int cb_type;
    BOOLEAN defunct;     /* Ignore this handler */
    BOOLEAN pending_run; /* True if the suspend thread is holding this
                            for handler later use.  Only set under
                            quiesce system.  Clearing this is the last
                            thing which the suspend thread does with a
                            late handler. */
    BOOLEAN running;
};

struct SuspendToken {
    LIST_ENTRY le;
    char name[64];
};
__MAKE_WRAPPER_PRIV(SUSPEND_TOKEN, struct SuspendToken *)
/* We want to make a NULL SuspendToken not the same as a
   null_SUSPEND_TOKEN(), so that EvtchnAllocateSuspendToken() can
   always succeed in a good way. */
#define wrap_SUSPEND_TOKEN(x) __wrap_SUSPEND_TOKEN((x) + 1)
#define unwrap_SUSPEND_TOKEN(x) (__unwrap_SUSPEND_TOKEN(x) - 1)

static struct SuspendToken SuspendCbToken;

#define MAX_NR_LATE_SUSPEND_HANDLERS 32

static KSPIN_LOCK _g_QuiesceLock;
/* The number of processors which haven't been captured in their DPCs
   yet. */
static LONG _g_ProcessorSpinCount1;
/* A refcount on the processorCount local in QuiesceSystem(), in that
   that stack location won't be reused until this has gone to 0. */
static LONG _g_ProcessorSpinCount2;
static LONG _g_QuiescePhase;
static KDPC _g_ProcessorSpinDpc[MAXIMUM_PROCESSORS];
static BOOLEAN _g_Quiesced;
static BOOLEAN _g_XenTraceKdDisabledOld;

static struct irqsafe_lock      SuspendHandlersLock;
static LIST_ENTRY               SuspendHandlersList;

static struct irqsafe_lock      suspend_token_lock;
static LIST_ENTRY               suspend_token_list;
static ULONG                    anonymous_token_count;

static struct xm_thread         *suspend_thread;
static KEVENT                   suspend_thread_idle;
static LONG                     pending_suspend_thread_launches;
static EVTCHN_DEBUG_CALLBACK    debug_callback;

/* At various points we need to capture all of the processors in the
   system and get them into a known state (e.g. binpatch,
   suspend/resume).  The protocol goes as follows:

   0) We start in phase 0.

   1) Thread A decides it wants to quiesce the system.

   2) Thread A acquires the QuiesceLock.  This locks it to a
      particular vcpu (say vcpu A), raises to DISPATCH_LEVEL, and
      prevents any other thread trying to do a quiesce at the same
      time.

   3) Vcpu A sets SpinCount1 to the number of vcpus not currently
      running our stuff at DPC level (i.e. nr_cpus - 1).  It sets
      processorCount to the number of vcpus with interrupts enabled
      (i.e. the total number of cpus).  It sets SpinCount2 to the
      number of other vcpus which might be referencing processorCount
      (i.e. nr_cpus - 1).

   4) Vcpu A launches DPCs at every other vcpu in the system.  The
      vcpus acknowledge that they're running by decrementing
      SpinCount1.  Vcpu A waits for SpinCount1 to hit 0, which
      indicates that every vcpu is now captured at DISPATCH_LEVEL.
      i.e. we no longer have to worry about deadlocking with someone
      else's DPC.

   5) Once every other vcpu is spinning in our DPC, we go to phase 1.
      This causes the other vcpus to disable interrupts and decrement
      processorCount.  Once processorCount goes to 0, every vcpu
      advances to the next phase. This is tricky, because we could
      still deadlock if an interrupt ever sends a synchronous IPI, and
      it looks like some bits of Windows do that.  We therefore have a
      timeout.  Each vcpu runs the timeout independently.  If it
      fires, we cmpxchg processorCount back up again (if it's gone to
      0, we need to continue), re-enable interrupts, back off a bit,
      and retry.

   6) Once a vcpu has seen processorCount go to 0, it decrements
      SpinCount2 to publicise that fact.  If it's an auxiliary vcpu,
      it's now finished with the quiesce, and sits waiting for an
      unquiesce.

   7) If it was the initiating vcpu, it waits for SpinCount2 to go to
      zero, so that it can deallocate processorCount.

   8) Once SpinCount2 goes to 0 on the initiator, the system is fully
      quiescent, and QuiesceSystem() returns.

   9) Eventually, we finish whatever it was we were doing in the
      quiescent critical section, and call UnquiesceSystem().
      UnquiesceSystem() sets the QuiescePhase back to 0, releasing the
      auxiliaries which are waiting at step 6.  The auxiliaries
      reenable interrupts and return from their DPCs.

   10) The initiator finally drops the quiesce lock and continues
       running normally.

   We need to do a two-stage capture to avoid a three-way deadlock
   with IPIs: vcpu A starts to quiesce the system at the same time as
   vcpu B tries to IPI vcpu C for a TLB flush.  If vcpu A gets to C
   before B does, C will be stuck spinning waiting for the quiesce to
   complete, but that can't happen until A captures B, but that can't
   happen until C completes the flush for B.  Leaving interrupts
   enabled until all vcpus are in the DPC prevents this, since only
   interrupts can preempt a DPC and we know that Windos never sends
   IPIs from interrupts.
*/

#define TSC_SPIN_LIMIT 2000000000

static KIRQL
GatherInterruptDisabledProcessors(
    IN  PLONG Count
    )
{
    KIRQL oldIrql;
    int spinCount;
    ULONG64 tsc_start = ReadTimeStampCounter();
    ULONG64 tsc_now;

    do
    {
        tsc_now = ReadTimeStampCounter();
        if (tsc_now - tsc_start >= TSC_SPIN_LIMIT) {
            TraceWarning(("Took a very long time to corral all processors with interrupts disabled %d: started at %I64x, still going at %I64x\n",
                          KeGetCurrentProcessorNumber(), tsc_start, tsc_now));
            tsc_start = tsc_now;
        }

        /* Raise to high level, blocking all interrupts. */
        KeRaiseIrql(HIGH_LEVEL, &oldIrql);
        InterlockedDecrement(Count);

        spinCount = 0;
        while (*Count)
        {
            spinCount++;
#define QUIESCE_WAIT 2048
            if (spinCount > QUIESCE_WAIT)
            {
                /* Back off.  Bump the number of processors which haven't
                 * achieved interrupt disabled state and reenable interrupts.
                 * N.B. Must never bump from zero as if zero is seen other
                 * processors will have advanced out of this routine. */
                LONG old = *Count;
                LONG new = old + 1;

                if (old == 0)
                {
                    break;
                }
                if (InterlockedCompareExchange(Count, new, old) == old)
                {
                    /* The exchange happened, the count has been safely
                     * incremented. */
                    KeLowerIrql(oldIrql);
                    spinCount = 0;
                    break;
                }
            }
        }
        HYPERVISOR_sched_op(SCHEDOP_yield, NULL);
        XsMemoryBarrier();
    } while (*Count);

    return oldIrql;
}

static VOID
SpinProcessorDpc(
    IN  PKDPC Dpc,
    IN  PVOID DeferredContext,
    IN  PVOID SystemArgument1,
    IN  PVOID SystemArgument2
    )
{
    ULONG me;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    me = KeGetCurrentProcessorNumber();
    TraceNotice(("%s (CPU%d): =====>\n", __FUNCTION__, me));

    /* Tell the initiator that we're in the DPC. */
    ASSERT(_g_ProcessorSpinCount1 > 0);
    InterlockedDecrement(&_g_ProcessorSpinCount1);

    /* Wait for every other vcpu to get ready. */
    while ( _g_QuiescePhase == 0 )
    {
        HYPERVISOR_sched_op(SCHEDOP_yield, NULL);
        XsMemoryBarrier();
    }

    oldIrql = GatherInterruptDisabledProcessors((PLONG)DeferredContext);

    /* Tell the initiator we're now fully quiescent. */
    /* You're not allowed to touch DeferredContext after this
     * completes. */
    ASSERT(_g_ProcessorSpinCount2 > 0);
    InterlockedDecrement(&_g_ProcessorSpinCount2);

    /* Wait for the initiator to release us. */
    while ( _g_QuiescePhase != 0 )
    {
        HYPERVISOR_sched_op(SCHEDOP_yield, NULL);
        XsMemoryBarrier();
    }

    /* We're done. */
    XsMemoryBarrier();
    FLUSH_PIPELINE();

    KeLowerIrql(oldIrql);

    TraceNotice(("%s (CPU%d): <=====\n", __FUNCTION__, me));
}

/* Get every other CPU into a known state (spinning in
 * SpinProcessDpc).  Raises IRQL to HIGH_LEVEL and returns the old
 * IRQL.  The idea is that once you've called this, nothing apart from
 * you will run until you call UnquiesceSystem. */
/* It's really easy to deadlock yourself using this.  If you ever have
 * a DPC which waits for something on another CPU, anywhere in the
 * system, we can deadlock with it.  Even worse, this is a fundamental
 * property of the thing we're trying to achieve.  Work around this
 * using a timeout which backs off and retries if it looks like we're
 * taking too long. */
KIRQL
QuiesceSystem(void)
{
    UCHAR number;
    ULONG me;
    KIRQL oldIrql;
    PKDPC dpc;
    LONG NumberOfCpus = KeNumberProcessors;
    ULONG64 tsc_start;
    ULONG64 tsc_now;
    LONG processorCount;

    ASSERT(_g_QuiescePhase == 0);

    KeAcquireSpinLock(&_g_QuiesceLock, &oldIrql);

    me = KeGetCurrentProcessorNumber();
    TraceNotice(("%s (CPU%d): =====>\n", __FUNCTION__, me));

    /* We don't want to use system time for the main capture process,
       because some HALs update it from a ticker interrupt, and we
       might have turned the ticker off on some subset of the CPUs
       when things go wrong. */
    tsc_start = ReadTimeStampCounter();

    _g_ProcessorSpinCount1 = _g_ProcessorSpinCount2 = NumberOfCpus - 1;

    processorCount = NumberOfCpus;

    for (number = 0; number < NumberOfCpus; number++)
    {
        if (number == me)
        {
            //
            // Don't send a message to yourself.
            //

            continue;
        }
        dpc = &_g_ProcessorSpinDpc[number];
        KeInitializeDpc(dpc, SpinProcessorDpc, &processorCount);
        KeSetTargetProcessorDpc(dpc, number);
        KeSetImportanceDpc(dpc, HighImportance);
        KeInsertQueueDpc(dpc, NULL, NULL);
    }

    /* Wait for the DPCs to start on all vcpus. */
    while (_g_ProcessorSpinCount1) {
        HYPERVISOR_sched_op(SCHEDOP_yield, NULL);
        XsMemoryBarrier();

        tsc_now = ReadTimeStampCounter();
        /* XXX Arbitrary limit of 2000000000 cycles before we print a
           warning.  This gives a plausible timeout for any processor
           with a clockspeed between about 500MHz and about 20GHz, and
           avoids needing to calibrate the TSC or rely on the system
           timers. */
        if (tsc_now - tsc_start >= TSC_SPIN_LIMIT) {
            TraceWarning(("Took a very long time to start DPCs: started at %I64x, still going at %I64x\n",
                          tsc_start, tsc_now));
        }
    }

    /* N.B. We cannot log to the kernel debugger while interrupts are
       disabled as the kernel debugger depends on being able to send
       interrupts to other processors (on x86, x64 uses NMI). */
    _g_XenTraceKdDisabledOld = XenDbgDisableKdLog(TRUE);

    /* All CPUs captured.  Turn interrupts off on other cpus. */
    _g_QuiescePhase = 1;

    /* Capture other cpus and disable interrupts. */
    GatherInterruptDisabledProcessors(&processorCount);

    /* Wait for other CPUs to acknowledge they have advanced out of the loop
     * where they were waiting for everyone to disable interrupts.
     *
     * WARNING: Don't return from this routine until you *KNOW* that all DPCs
     * have advanced beyond the point where they are using the DPC's deferred
     * context parameter which is the local variable processorCount in this
     * routine.
     *
     * This wait accomplishes that goal.  Also, the two global SpinCounts are
     * not used again after this loop on any processor, until the next suspend.
     */

    tsc_start = ReadTimeStampCounter();
    while (_g_ProcessorSpinCount2) {
        HYPERVISOR_sched_op(SCHEDOP_yield, NULL);
        XsMemoryBarrier();

        tsc_now = ReadTimeStampCounter();
        if (tsc_now - tsc_start >= TSC_SPIN_LIMIT) {
            TraceWarning(("Took a very long time to advance DPCs beyond wait for interrupts disabled: started at %I64x, still going at %I64x\n",
                          tsc_start, tsc_now));
            tsc_start = tsc_now;
        }
    }

    _g_Quiesced = TRUE;

    /* We need to have seen _g_ProcessorSpinCount2 go to 0 before it's
     * safe to reuse the stack location which holds processorCount. */
    XsMemoryBarrier();

    TraceNotice(("%s: <====\n", __FUNCTION__));
    return oldIrql;
}

/* Undo the effect of UnquiesceAllProcessors.  This is also a very
 * strong memory barrier, including flushing processor pipelines
 * etc. */
void
UnquiesceSystem(
    IN  KIRQL OldIrql
    )
{
    TraceNotice(("%s: =====>\n", __FUNCTION__));
    _g_Quiesced = FALSE;

    XsMemoryBarrier();
    FLUSH_PIPELINE();

    /* Release the other vcpus */
    _g_QuiescePhase = 0;

    /* Pacify driver verifier, which insists that spin locks are only
       ever released from DISPATCH_LEVEL. Note: This could be achieved
       by using KeReleaseSpinLockFromDpcLevel but we' d then have to 
       lower IRQL to OldIrql (despite what the name might imply).
       However, we also need to reenable logging to KD if it was previously
       disabled and we can't do that until interrupts are reenabled so
       we do that here.*/
    KeLowerIrql(DISPATCH_LEVEL);

    XenDbgDisableKdLog(_g_XenTraceKdDisabledOld);

    KeReleaseSpinLock(&_g_QuiesceLock, OldIrql);

    TraceNotice(("%s: <=====\n", __FUNCTION__));
}

#undef TSC_SPIN_LIMIT

static const CHAR *
HandlerType(
    IN  int Type
    )
{
#define _TYPE_NAME(_Type)   \
    case _Type ## _TYPE:    \
        return #_Type;

    switch (Type) {
    _TYPE_NAME(PRE_SUSPEND_CB_EARLY);
    _TYPE_NAME(PRE_SUSPEND_CB_LATE);
    _TYPE_NAME(SUSPEND_CB_EARLY);
    _TYPE_NAME(SUSPEND_CB_LATE);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _TYPE_NAME
}

/* Walks the list of registered suspend handlers and invokes
 * the callback routine for handlers of the type specified.
 * This routine can only be called when IRQL is PASSIVE_LEVEL
 * (for early pre-suspend and late post-suspend) or HIGH_LEVEL
 * (for late pre-suspend or early post-suspend).
 */ 
static VOID
InvokeSuspendHandlers(
    IN  int                 cb_type
    )
{
    KIRQL                   old_irql = PASSIVE_LEVEL;
    unsigned                cntr;
    LIST_ENTRY              *le;
    ULONG                   pending;

    TraceNotice(("%s: ====>\n", __FUNCTION__));

    switch (cb_type) {
    case PRE_SUSPEND_CB_LATE_TYPE:
    case SUSPEND_CB_EARLY_TYPE:
        break;

    case PRE_SUSPEND_CB_EARLY_TYPE:
    case SUSPEND_CB_LATE_TYPE:
        old_irql = acquire_irqsafe_lock(&SuspendHandlersLock);
        break;

    default:
        XM_BUG();
        break;
    }

    /* Since the suspend handler list items are only removed when
     * at passive_level, we can now safely walk it, even if when our
     * caller's IRQL higher than passive.
     */
    pending = 0;
    cntr = 0;
    for (le = SuspendHandlersList.Flink; le != &SuspendHandlersList; le = le->Flink) {
        struct SuspendHandler *sh = CONTAINING_RECORD(le, struct SuspendHandler, le);

        cntr++;
        if (cntr % 1024 == 0)
            TraceWarning(("Having trouble running suspend handlers, %d iterations so far\n",
                          cntr));

        if (sh->cb_type != cb_type || sh->defunct)
            continue;

        switch (cb_type) {
        case PRE_SUSPEND_CB_LATE_TYPE:
        case SUSPEND_CB_EARLY_TYPE:
            /*
             * Call these handlers here as we know that we are running
             * single threaded and thus nothing can modify the
             * handler list under our feet.
             */
            TraceNotice(("%s handler %p (%s)...\n", HandlerType(sh->cb_type),
                         sh, sh->name));
            sh->cb(sh->data, wrap_SUSPEND_TOKEN(&SuspendCbToken));
            TraceNotice(("Completed handler %p (%s)\n", sh, sh->name));

            break;

        case PRE_SUSPEND_CB_EARLY_TYPE:
        case SUSPEND_CB_LATE_TYPE:
            /*
             * These handlers need to be run at PASSIVE_LEVEL so we're
             * going to need to drop SuspendHandlersLock before the
             * call. This allows the list to change, so rather than
             * calling the handler here, just state our intent to
             * call it.
             */
            sh->pending_run = TRUE;
            pending++;
            break;

        default:
            XM_BUG();
            break;
        }
    }

    switch (cb_type) {
    case PRE_SUSPEND_CB_LATE_TYPE:
    case SUSPEND_CB_EARLY_TYPE:
        goto done;

    case PRE_SUSPEND_CB_EARLY_TYPE:
    case SUSPEND_CB_LATE_TYPE:
        release_irqsafe_lock(&SuspendHandlersLock, old_irql);
        break;

    default:
        XM_BUG();
        break;
    }

    if (pending == 0)
        goto done;

retry:
    old_irql = acquire_irqsafe_lock(&SuspendHandlersLock);
    for (le = SuspendHandlersList.Flink; le != &SuspendHandlersList; le = le->Flink) {
        struct SuspendHandler *sh = CONTAINING_RECORD(le, struct SuspendHandler, le);

        if (!sh->pending_run)
            continue;

        XM_ASSERT(sh->cb_type == PRE_SUSPEND_CB_EARLY_TYPE ||
                  sh->cb_type == SUSPEND_CB_LATE_TYPE);
        XM_ASSERT(!sh->defunct);

        /*
         * We're protected against the suspend handler disappearing
         * underneath us because pending_run is TRUE.
         */
        sh->pending_run = FALSE;
        sh->running = TRUE;
        release_irqsafe_lock(&SuspendHandlersLock, old_irql);

        TraceNotice(("%s handler %p (%s)...\n", HandlerType(sh->cb_type),
                     sh, sh->name));
        sh->cb(sh->data, wrap_SUSPEND_TOKEN(&SuspendCbToken));
        TraceNotice(("Completed handler %p (%s)\n", sh, sh->name));

        sh->running = FALSE;
        XM_ASSERT(pending != 0);
        pending--;

        /*
         * We dropped the SuspendHandlersLock so we musy assume the
         * suspend handlers list may have changed.
         */
        goto retry;
    }
    release_irqsafe_lock(&SuspendHandlersLock, old_irql);

done:
    XM_ASSERT3U(pending, ==, 0);
    TraceNotice(("%s: <====\n", __FUNCTION__));
}

static VOID
DoSuspend(VOID)
{
    KIRQL old_irql;
    struct sched_shutdown sched_shutdown;
    int res;

    /* Notify interested parties that we're about to suspend.
     * MTC: This is needed for Marathon Technologies' Lockstep Feature
     * In particular, it will invoke a handler that turns off xenbus
     * driver access.  This must be done at passive level.
     */ 
    InvokeSuspendHandlers(PRE_SUSPEND_CB_EARLY_TYPE);

    old_irql = QuiesceSystem();

    /* Invoke callback handlers for those interested when the system has
     * been quiesced.  IRQL is expected to be at HIGH_LEVEL here.
     * Set a flag to let the EvtchnClose() is safe to be called at an
     * IRQL level > DISPATCH.  This allows the MTC callback to close its
     * ports during this phase.
     */
    InvokeSuspendHandlers(PRE_SUSPEND_CB_LATE_TYPE);

    TraceNotice(("about to suspend...\n"));
    sched_shutdown.reason = SHUTDOWN_suspend;
    res = HYPERVISOR_sched_op(SCHEDOP_shutdown, &sched_shutdown);
    TraceNotice(("suspend completed (%d)\n", res));

    if (!XenPVFeatureEnabled(DEBUG_MTC_PROTECTED_VM) && (res == 1)) {
        UnquiesceSystem(old_irql);
        return;
    }

    suspend_count++;

    InvokeSuspendHandlers(SUSPEND_CB_EARLY_TYPE);

    UnquiesceSystem(old_irql);

    InvokeSuspendHandlers(SUSPEND_CB_LATE_TYPE);
}

/*
 * This should only ever be called from SuspendThread() as it assumes
 * serialization with DoSuspend().
 */
static VOID
SuspendCleanup(VOID)
{
    LIST_ENTRY *le;
    KIRQL old_irql;

retry:
    old_irql = acquire_irqsafe_lock(&SuspendHandlersLock);
    le = SuspendHandlersList.Flink;
    while (le != &SuspendHandlersList) {
        LIST_ENTRY *next = le->Flink;
        struct SuspendHandler *sh = CONTAINING_RECORD(le, struct SuspendHandler, le);

        if (!sh->defunct) {
            le = next;
            continue;
        }

        XM_ASSERT(!sh->pending_run && !sh->running);

        RemoveEntryList(le);

        TraceInfo(("%s: Deregistered %s suspend handler %p (%s)\n", __FUNCTION__,
                   HandlerType(sh->cb_type), sh, sh->name));

        release_irqsafe_lock(&SuspendHandlersLock, old_irql);

        ExFreePool(sh);
        goto retry;
    }
    release_irqsafe_lock(&SuspendHandlersLock, old_irql);
}

static NTSTATUS
SuspendThread(struct xm_thread *t, PVOID ignore)
{
    struct xenbus_watch_handler *wh;
    char *res;
    NTSTATUS stat;

    UNREFERENCED_PARAMETER(ignore);

    if (!xenbus_await_initialisation())
        return STATUS_INSUFFICIENT_RESOURCES;

    wh = xenbus_watch_path_event("control/shutdown", &t->event);
    if (!wh) {
        TraceWarning(("Couldn't watch control/shutdown for suspend requests!\n"));
        return STATUS_UNSUCCESSFUL;
    }

    /* Make things a bit easier for the tools by binding ourselves to
     * vcpu 0. */
    KeSetSystemAffinityThread(1);

    xenbus_write_feature_flag(XBT_NIL, "control", "feature-suspend", TRUE);

    for (;;) {
        SuspendCleanup();

        KeSetEvent(&suspend_thread_idle, IO_NO_INCREMENT, FALSE);
        if (XmThreadWait(t) < 0)
            break;
        KeClearEvent(&suspend_thread_idle);

        stat = xenbus_read(XBT_NIL, "control/shutdown", &res);
        if (!NT_SUCCESS(stat)) {
            if (stat != STATUS_OBJECT_NAME_NOT_FOUND)
                TraceWarning(("Couldn't read control/shutdown for shutdown reason.\n"));
            else
                TraceDebug(("Not shutting down yet...\n"));
        } else {
            if (!strcmp(res, "suspend")) {
                if (anonymous_token_count == 0 &&
                    IsListEmpty(&suspend_token_list)) {
                    /* It would be possible for suspend_token_list to go
                       non-empty here if someone were allocating a token.
                       If that happens, EvtchnAllocateSuspendToken() will
                       wait for the suspend_thread_idle event, so the race
                       doesn't matter. */
                    xenbus_remove(XBT_NIL, "control/shutdown");
                    DoSuspend();
                } else {
                    KIRQL old_irql;

                    old_irql = acquire_irqsafe_lock(&suspend_token_lock);
                    if (anonymous_token_count != 0)
                        TraceWarning(("%s: %d pending anonymous tokens\n", __FUNCTION__, anonymous_token_count));

                    if (!IsListEmpty(&suspend_token_list)) {
                        LIST_ENTRY *le;

                        TraceWarning(("%s: pending tokens:\n", __FUNCTION__));
                        for (le = suspend_token_list.Flink; le != &suspend_token_list; le = le->Flink) {
                            struct SuspendToken *tok = CONTAINING_RECORD(le, struct SuspendToken, le);

                            TraceWarning(("%s: %s\n", __FUNCTION__, tok->name));
                        }
                    }
                    release_irqsafe_lock(&suspend_token_lock, old_irql);
                }
            } else if (!strcmp(res, "bugcheck")) {
                TraceBugCheck(("%s\n", __FUNCTION__));
            } else if (!strcmp(res, "assert")) {
                XM_ASSERT(FALSE);
            } else if (!strcmp(res, "assert3u")) {
                XM_ASSERT3U(1, <, 0);
            } else if (!strcmp(res, "assert3s")) {
                XM_ASSERT3S(1, <, 0);
            } else if (!strcmp(res, "assert3p")) {
                XM_ASSERT3U((UCHAR *)1, <, (UCHAR *)0);
            }
            XmFreeMemory(res);
        }
    }

    TraceVerbose (("Suspend thread exiting.\n"));
    xenbus_unregister_watch(wh);

    return STATUS_SUCCESS;
}

static void
SuspendDebugCb(void *ignore)
{
    NTSTATUS stat;
    KIRQL old_irql;

    UNREFERENCED_PARAMETER(ignore);

    stat = try_acquire_irqsafe_lock(&suspend_token_lock, &old_irql);
    if (NT_SUCCESS(stat)) {
        if (anonymous_token_count != 0)
            TraceInternal(("%s: %d pending anonymous tokens\n", __FUNCTION__, anonymous_token_count));

        if (!IsListEmpty(&suspend_token_list)) {
            LIST_ENTRY *le;

            TraceWarning(("%s: pending tokens:\n", __FUNCTION__));
            for (le = suspend_token_list.Flink; le != &suspend_token_list; le = le->Flink) {
                struct SuspendToken *tok = CONTAINING_RECORD(le, struct SuspendToken, le);

                TraceInternal(("%s: %s\n", __FUNCTION__, tok->name));
            }
        }
        release_irqsafe_lock(&suspend_token_lock, old_irql);
    } else {
        TraceInternal(("suspend token lock busy\n"));
    }

    stat = try_acquire_irqsafe_lock(&SuspendHandlersLock, &old_irql);
    if (NT_SUCCESS(stat)) {
        if (!IsListEmpty(&SuspendHandlersList)) {
            LIST_ENTRY *le;

            for (le = SuspendHandlersList.Flink; le != &SuspendHandlersList; le = le->Flink) {
                struct SuspendHandler *sh = CONTAINING_RECORD(le, struct SuspendHandler, le);

                TraceInternal(("%s handler %p (%s) %s%s\n",
                               HandlerType(sh->cb_type),
                               sh, sh->name,
                               (sh->pending_run) ? "[PENDING]" : "",
                               (sh->running) ? "[RUNNING]" : ""));
            }
        }
        release_irqsafe_lock(&SuspendHandlersLock, old_irql);
    } else {
        TraceInternal(("suspend handlers lock busy\n"));
    }
}

VOID
SuspendPreInit(VOID)
{
    InitializeListHead(&SuspendHandlersList);
    InitializeListHead(&suspend_token_list);
    KeInitializeSpinLock(&_g_QuiesceLock);
    KeInitializeEvent(&suspend_thread_idle, NotificationEvent, FALSE);

    EvtchnSetupDebugCallback(SuspendDebugCb, NULL);
}

static void
LaunchSuspendThread(PVOID ignore)
{
    UNREFERENCED_PARAMETER(ignore);

    if (!suspend_thread) {
        TraceInfo(("Launch suspend thread.\n"));
        suspend_thread = XmSpawnThread(SuspendThread, NULL);
        if (suspend_thread)
            KeSetPriorityThread(suspend_thread->thread, HIGH_PRIORITY);
    }
    InterlockedDecrement(&pending_suspend_thread_launches);
}

VOID
KillSuspendThread(VOID)
{
    while (pending_suspend_thread_launches != 0) {
        LARGE_INTEGER i;
        i.QuadPart = -100000;
        KeDelayExecutionThread(KernelMode, FALSE, &i);
    }
    XmKillThread(suspend_thread);
    suspend_thread = NULL;
}

#define MIN(x, y) ((x) < (y) ? (x) : (y))

struct SuspendHandler *
EvtchnRegisterSuspendHandler(void (*cb)(void *data, SUSPEND_TOKEN token),
                             void *data, char *name,
                             SUSPEND_CB_TYPE _type)
{
    KIRQL old_irql;
    struct SuspendHandler *work;
    int type = unwrap_SUSPEND_CB_TYPE(_type);
    size_t len;

    XM_ASSERT(IS_VALID_CB_TYPE(type));

    if (AustereMode)
        return NULL;

    work = ExAllocatePoolWithTag(NonPagedPool, sizeof(*work), 'sshn');
    if (!work)
        return NULL;

    memset(work, 0, sizeof(*work));

    len = MIN(strlen(name) + 1, 64);
    memcpy(work->name, name, len);
    work->name[len-1] = '\0';

    work->cb = cb;
    work->data = data;
    work->cb_type = type;

    old_irql = acquire_irqsafe_lock(&SuspendHandlersLock);
    InsertTailList(&SuspendHandlersList, &work->le);
    release_irqsafe_lock(&SuspendHandlersLock, old_irql);

    TraceInfo(("%s: Registered %s suspend handler %p (%s)\n", __FUNCTION__,
               HandlerType(work->cb_type), work, work->name));
    return work;
}

void
EvtchnUnregisterSuspendHandler(struct SuspendHandler *sh)
{
    XM_ASSERT3U(KeGetCurrentIrql(), <=, DISPATCH_LEVEL);
    XM_ASSERT(sh != NULL);

    // This needs to be properly synchronized with the suspend
    // thread so the easiest thing to do is have the suspend thread
    // do the work.
    sh->defunct = TRUE;
    if (suspend_thread) 
        KeSetEvent(&suspend_thread->event, IO_NO_INCREMENT, FALSE);
}

SUSPEND_TOKEN
EvtchnAllocateSuspendToken(PCSTR name)
{
    struct SuspendToken *tok;
    KIRQL old_irql;

    if (AustereMode)
        return null_SUSPEND_TOKEN();

    /* You really don't want to allocate suspend tokens when
        you're on the suspend thread, or you'll get an instant
        deadlock. */
    XM_ASSERT(IMPLY(suspend_thread != NULL, KeGetCurrentThread() != suspend_thread->thread));

    tok = XmAllocateMemory(sizeof(*tok));

    old_irql = acquire_irqsafe_lock(&suspend_token_lock);
    if (tok != NULL) {
        size_t len;

        len = MIN(strlen(name) + 1, 64);
        memcpy(tok->name, name, len);
        tok->name[len-1] = '\0';
        InsertTailList(&suspend_token_list, &tok->le);
    } else {
        anonymous_token_count++;
    }
    release_irqsafe_lock(&suspend_token_lock, old_irql);

    if (suspend_thread) {
        /* Wait for the suspend thread to finish whatever it's
         * doing. */
        XM_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
        KeWaitForSingleObject(&suspend_thread_idle, Executive,
                              KernelMode, FALSE, NULL);
    }

    return wrap_SUSPEND_TOKEN(tok);
}

void
EvtchnReleaseSuspendToken(SUSPEND_TOKEN token)
{
    struct SuspendToken *tok;
    KIRQL old_irql;

    if (AustereMode)
        return;

    XM_ASSERT(!is_null_SUSPEND_TOKEN(token));
    tok = unwrap_SUSPEND_TOKEN(token);
    XM_ASSERT(tok != &SuspendCbToken);

    old_irql = acquire_irqsafe_lock(&suspend_token_lock);
    if (tok != NULL) {
        RemoveEntryList(&tok->le);
    } else {
        XM_ASSERT(anonymous_token_count != 0);
        anonymous_token_count++;
    }
    release_irqsafe_lock(&suspend_token_lock, old_irql);

    if (tok != NULL)
        XmFreeMemory(tok);

    if (suspend_thread) {
        XM_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
        KeSetEvent(&suspend_thread->event, IO_NO_INCREMENT, FALSE);
    }
}

void
EvtchnLaunchSuspendThread(VOID)
{
    NTSTATUS status;

    status = XenQueueWork(LaunchSuspendThread, NULL);

    if (NT_SUCCESS(status))
        InterlockedIncrement(&pending_suspend_thread_launches);
}

ULONG
SuspendGetCount(void)
{
    return suspend_count;
}
