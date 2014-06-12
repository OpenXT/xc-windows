/*
 * Copyright (c) 2009 Citrix Systems, Inc.
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

#include <ntddk.h>
#include <ntstrsafe.h>
#define XSAPI_FUTURE_GRANT_MAP
#define XSAPI_FUTURE_CONNECT_EVTCHN
#include "xsapi.h"
#include "xsapi-future.h"
#include "scsiboot.h"
#include "../xenutil/evtchn.h"

#define V2V_API_EXPORTS
#include "v2vk.h"

#include "vring.h"
#include "v2v_private.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define MAX_RING_PAGE_ORDER 4
#define MAX_RING_PAGES (1 << MAX_RING_PAGE_ORDER)

#define CONSUMER_SPIN_LIMIT 2048

#define GREF_STRING_LEN 32

struct v2v_channel {
    struct xenbus_watch_handler *remote_state_watch;
    char *local_prefix;  /* non-paged mem, use ExFreePoolWithTag(..., V2V_TAG) */
    char *remote_prefix; /* non-paged mem, use ExFreePoolWithTag(..., V2V_TAG) */
    DOMAIN_ID peer_domid;    

    void *prod_sring;
    const void *cons_sring;
    void *control;
    EVTCHN_PORT receive_evtchn_port;
    EVTCHN_PORT send_evtchn_port;
    EVTCHN_DEBUG_CALLBACK debug_callback;

    unsigned nr_prod_ring_pages;
    unsigned nr_cons_ring_pages;

    unsigned current_message_size;

    struct nc2_ring_pair nc2_rings;
    
    KEVENT control_event;
    BOOLEAN is_sync;

    union {
        struct {
            KEVENT receive_event;
            KEVENT send_event;
        } sync;
        struct {
            void (*control_cb)(void *);
            void *control_ctx;    
        } async;
    } s;

    BOOLEAN is_temple;
    
    union {
        struct {            
            struct grant_cache *grant_cache;

            GRANT_REF prod_grefs[MAX_RING_PAGES];
            GRANT_REF cons_grefs[MAX_RING_PAGES];
            GRANT_REF control_gref;

            BOOLEAN accepted;
        } temple;
        struct {
            struct grant_map_detail *prod_detail;
            struct grant_map_detail *cons_detail;
            struct grant_map_detail *control_detail;

            ALIEN_GRANT_REF prod_grefs[MAX_RING_PAGES];
            ALIEN_GRANT_REF cons_grefs[MAX_RING_PAGES];
            ALIEN_GRANT_REF control_gref;
            ALIEN_EVTCHN_PORT prod_evtchn_port;
            ALIEN_EVTCHN_PORT cons_evtchn_port;
        } supplicant;
    } u;
};

static void
v2v_dpc(void *ctxt)
{
    KeSetEvent((PKEVENT)ctxt, EVENT_INCREMENT, FALSE);
}

static void
v2v_control_handler(void *ctx)
{
    struct v2v_channel *channel = (struct v2v_channel *)ctx;
    
    /* Set the event for us and other who may be interested */
    KeSetEvent(&(channel->control_event), IO_NO_INCREMENT, FALSE);
    /* Callback interested parties that regitered a control callback */
    if (channel->is_temple && !channel->u.temple.accepted)
        return;
    if (channel->s.async.control_cb)
        channel->s.async.control_cb(channel->s.async.control_ctx);
}

static void
v2v_debug_dump(struct v2v_channel *channel)
{
    TraceNotice(("Xen-v2vk instance %p\n", channel));
    TraceNotice(("Local prefix %s\n", (channel->local_prefix ? channel->local_prefix : "[unknown]")));
    TraceNotice(("Remote prefix %s\n", (channel->remote_prefix ? channel->remote_prefix : "[unknown]")));
    TraceNotice(("Peer domain %d\n", unwrap_DOMAIN_ID(channel->peer_domid)));
    TraceNotice(("Listener %s\n", (channel->is_temple ? "yes" : "no")));
    TraceNotice(("Synchronous %s\n", (channel->is_sync ? "yes" : "no")));
}

static __inline PSTRING
v2v_make_cs(PSTRING dst, PCSZ src)
{
    RtlInitString(dst, src);
    return dst;
}

static void
v2v_destroy_channel(const struct v2v_channel *_chan, BOOLEAN free_temple)
{
    struct v2v_channel *chan = (struct v2v_channel *)_chan;
    unsigned x;

    if (chan->remote_state_watch)
        xenbus_unregister_watch(chan->remote_state_watch);
    if (chan->local_prefix)
        ExFreePoolWithTag(chan->local_prefix, V2V_TAG);
    if (chan->remote_prefix)
		ExFreePoolWithTag(chan->remote_prefix, V2V_TAG);
    
    if (!chan->is_temple) {
        v2v_xenops_grant_unmap((void *)chan->cons_sring, chan->u.supplicant.prod_detail);
        v2v_xenops_grant_unmap(chan->prod_sring, chan->u.supplicant.cons_detail);
        v2v_xenops_grant_unmap(chan->control, chan->u.supplicant.control_detail);
    }
    else if (free_temple) { /* and is temple */
        if (chan->u.temple.grant_cache) {
            for (x = 0; x < chan->nr_prod_ring_pages; x++) {
                if (!is_null_GRANT_REF(chan->u.temple.prod_grefs[x]))
                    GnttabEndForeignAccessCache(chan->u.temple.prod_grefs[x],
                                                chan->u.temple.grant_cache);
            }
            for (x = 0; x < chan->nr_cons_ring_pages; x++) {
                if (!is_null_GRANT_REF(chan->u.temple.cons_grefs[x]))
                    GnttabEndForeignAccessCache(chan->u.temple.cons_grefs[x],
                                                chan->u.temple.grant_cache);
            }

            if (!is_null_GRANT_REF(chan->u.temple.control_gref))
                GnttabEndForeignAccessCache(chan->u.temple.control_gref,
                                            chan->u.temple.grant_cache);
            
            GnttabFreeCache(chan->u.temple.grant_cache);
        }
            
        if (chan->prod_sring)
            ExFreePoolWithTag(chan->prod_sring, V2V_TAG);
        if (chan->cons_sring)
            ExFreePoolWithTag((void*)chan->cons_sring, V2V_TAG);                
        if (chan->control)
            ExFreePoolWithTag(chan->control, V2V_TAG);
    }

    if (!is_null_EVTCHN_PORT(chan->receive_evtchn_port))
        EvtchnClose(chan->receive_evtchn_port);
    if (!is_null_EVTCHN_PORT(chan->send_evtchn_port))
        EvtchnClose(chan->send_evtchn_port);

    EvtchnReleaseDebugCallback(chan->debug_callback);

    ExFreePoolWithTag(chan, V2V_TAG);
}

static NTSTATUS
v2v_read_peer_domid(struct v2v_channel *chan)
{
    NTSTATUS status;
    char *str;
    int val, ret;

    status = 
        v2v_xenstore_readv_string(&str, XBT_NIL, chan->local_prefix, "peer-domid", NULL);
    if (!NT_SUCCESS(status))
        return status;

    ret = v2v_string_to_num(str, &val);
    ExFreePoolWithTag(str, V2V_TAG);
    if (ret != 1 || val < 0 || val > 0xffff)
        return STATUS_DATA_ERROR;
    
    chan->peer_domid = wrap_DOMAIN_ID(val);

    return STATUS_SUCCESS;
}

static struct v2v_channel *
v2v_make_channel(const char *xenbus_prefix, struct v2v_async *async_values)
{
    struct v2v_channel *chan;

    chan = (struct v2v_channel*)ExAllocatePoolWithTag(NonPagedPool, sizeof(*chan), V2V_TAG);
    if (!chan)
        return NULL;
    RtlZeroMemory(chan, sizeof(*chan));    

    chan->debug_callback = EvtchnSetupDebugCallback(v2v_debug_dump, chan);

    KeInitializeEvent(&chan->control_event, SynchronizationEvent, FALSE);
    if (async_values) {        
        chan->s.async.control_cb = async_values->control_cb;
        chan->s.async.control_ctx = async_values->control_ctx;
        chan->is_sync = FALSE;
    }
    else {
        KeInitializeEvent(&chan->s.sync.receive_event, SynchronizationEvent, FALSE);
        KeInitializeEvent(&chan->s.sync.send_event, SynchronizationEvent, TRUE);
        chan->is_sync = TRUE;
    }       

    chan->local_prefix = v2v_string_dup(xenbus_prefix, TRUE);
    if (!chan->local_prefix) {
        v2v_destroy_channel(chan, FALSE);
        return NULL;
    }
    
    return chan;
}

static NTSTATUS
v2v_connect_channel_xenbus(struct v2v_channel *chan, xenbus_transaction_t xbt)
{
    NTSTATUS status;
    char *str = NULL;

    status = 
        v2v_xenstore_readv_string(&str,
                                  xbt,
                                  chan->local_prefix,
                                  "backend",
                                  NULL);
    if (!NT_SUCCESS(status))
        return status;

    /* this one we want as non-paged so it can be reported in the crash handler */
    chan->remote_prefix = v2v_string_dup(str, TRUE);
    ExFreePoolWithTag(str, V2V_TAG);
    if (!chan->remote_prefix)
        return STATUS_NO_MEMORY;

    status = v2v_read_peer_domid(chan);
    if (!NT_SUCCESS(status))
        return status;

    if (chan->is_sync) {
        status = 
            v2v_xenstore_watchv(&chan->remote_state_watch,
                                &chan->control_event,
                                chan->remote_prefix,
                                "state",
                                NULL);
    }
    else {
        status = 
            v2v_xenstore_watchv_cb(&chan->remote_state_watch,
                                   v2v_control_handler,
                                   chan,
                                   chan->remote_prefix,
                                   "state",
                                   NULL);
    }
    return status;
}

static void
v2v_nc2_attach_rings_temple(struct nc2_ring_pair *ncrp,
                            const volatile void *cons_sring,
                            unsigned cons_ring_size,
                            void *prod_sring,
                            unsigned prod_ring_size,
                            struct netchannel2_frontend_shared *control)
{
    memset(ncrp, 0, sizeof(*ncrp));
    ncrp->local_endpoint = &control->a;
    ncrp->remote_endpoint = &control->b;
    ncrp->producer_payload_bytes = prod_ring_size;
    ncrp->producer_payload = prod_sring;
    ncrp->consumer_payload_bytes = cons_ring_size;
    ncrp->consumer_payload = cons_sring;

    ncrp->local_endpoint->prod_event = ncrp->remote_endpoint->prod + 1;
}

static void
v2v_nc2_attach_rings_supplicant(struct nc2_ring_pair *ncrp,
                                const volatile void *cons_sring,
                                unsigned cons_ring_size,
                                void *prod_sring,
                                unsigned prod_ring_size,
                                struct netchannel2_backend_shared *control)
{
    memset(ncrp, 0, sizeof(*ncrp));
    ncrp->local_endpoint = &control->a;
    ncrp->remote_endpoint = &control->b;
    ncrp->producer_payload_bytes = prod_ring_size;
    ncrp->producer_payload = prod_sring;
    ncrp->consumer_payload_bytes = cons_ring_size;
    ncrp->consumer_payload = cons_sring;

    ncrp->local_endpoint->prod_event = ncrp->remote_endpoint->prod + 1;
}

const char *
v2v_endpoint_state_name(enum v2v_endpoint_state state)
{
    switch (state) {
    case v2v_state_unknown:
        return "unknown";
    case v2v_state_unready:
        return "unready";
    case v2v_state_listening:
        return "listening";
    case v2v_state_connected:
        return "connected";
    case v2v_state_disconnecting:
        return "disconnecting";
    case v2v_state_disconnected:
        return "disconnected";
    case v2v_state_crashed:
        return "crashed";
    }
    return "v2v_state_invalid";
}

static NTSTATUS
v2v_change_local_state(struct v2v_channel *channel, xenbus_transaction_t xbt, enum v2v_endpoint_state state)
{
    return v2v_xenstore_printfv(xbt,
                                channel->local_prefix,
                                "state",
                                NULL,
                                v2v_endpoint_state_name(state));
}

static NTSTATUS
v2v_write_grantref(struct v2v_channel *chan, xenbus_transaction_t xbt, int x, BOOLEAN is_prod)
{
    NTSTATUS status = STATUS_SUCCESS;
    const char *fmt = (is_prod ? "prod-gref-%d" : "cons-gref-%d");
    GRANT_REF *gref = (is_prod ? &chan->u.temple.prod_grefs[x] : &chan->u.temple.cons_grefs[x]);
    char buf[GREF_STRING_LEN];
    uint32_t xen_gref;

    xen_gref = xen_GRANT_REF(*gref);

    status = RtlStringCchPrintfA(buf, GREF_STRING_LEN, fmt, x);
    if (!NT_SUCCESS(status))
        return status;

    return v2v_xenstore_printfv(xbt, chan->local_prefix, buf, NULL, "%d", xen_gref);
}

NTSTATUS
v2v_listen(const char *xenbus_prefix, struct v2v_channel **channel,
           unsigned prod_ring_page_order, unsigned cons_ring_page_order,
           struct v2v_async *async_values)
{
    NTSTATUS status = STATUS_SUCCESS;
    unsigned prod_ring_size = PAGE_SIZE << prod_ring_page_order;
    unsigned cons_ring_size = PAGE_SIZE << cons_ring_page_order;
    struct v2v_channel *chan;
    xenbus_transaction_t xbt = {0};
    BOOLEAN xbt_pending = FALSE;
    PHYSICAL_ADDRESS pa;
    unsigned x;
    unsigned xen_receive_port, xen_send_port;
    uint32_t xen_gref;

    XM_ASSERT(channel != NULL);
    XM_ASSERT(xenbus_prefix != NULL);

    if (prod_ring_page_order > MAX_RING_PAGE_ORDER ||
        cons_ring_page_order > MAX_RING_PAGE_ORDER)
        return STATUS_INVALID_PARAMETER;

    if (async_values && 
       (!async_values->receive_dpc || !async_values->send_dpc))
        return STATUS_INVALID_PARAMETER;

    *channel = NULL;

    if (!xenbus_await_initialisation())
        return STATUS_NO_SUCH_DEVICE;

    chan = v2v_make_channel(xenbus_prefix, async_values);
    if (!chan)
        return STATUS_NO_MEMORY;

    chan->is_temple = TRUE;

    chan->prod_sring = ExAllocatePoolWithTag(NonPagedPool, prod_ring_size, V2V_TAG);
    chan->cons_sring = ExAllocatePoolWithTag(NonPagedPool, cons_ring_size, V2V_TAG);
    chan->control = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, V2V_TAG);
    if (!chan->prod_sring || !chan->cons_sring || !chan->control)
        goto err_nomem;

    RtlZeroMemory(chan->prod_sring, prod_ring_size);
    RtlZeroMemory((void *)chan->cons_sring, cons_ring_size);
    RtlZeroMemory(chan->control, PAGE_SIZE);

    chan->nr_prod_ring_pages = 1 << prod_ring_page_order;
    chan->nr_cons_ring_pages = 1 << cons_ring_page_order;

    /* pre-allocate the granf refs we are going to need below in a grant cache */
    chan->u.temple.grant_cache =
        GnttabAllocCache(chan->nr_prod_ring_pages + chan->nr_cons_ring_pages + 1);
    if (!chan->u.temple.grant_cache)
        goto err_nomem;

    v2v_nc2_attach_rings_temple(&chan->nc2_rings,
                                chan->cons_sring,
                                cons_ring_size,
                                chan->prod_sring,
                                prod_ring_size,
                                chan->control);

    for (;;) {
        xenbus_transaction_start(&xbt);        
        xbt_pending = TRUE;
        
        status = v2v_connect_channel_xenbus(chan, xbt);
        if (!NT_SUCCESS(status))
            goto err;        

        for (x = 0; x < 1u << prod_ring_page_order; x++) {
            pa = MmGetPhysicalAddress((void *)((ULONG_PTR)chan->prod_sring + x * PAGE_SIZE));
            chan->u.temple.prod_grefs[x] =
                GnttabGrantForeignAccessCache(chan->peer_domid,
                                              PHYS_TO_PFN(pa),
                                              GRANT_MODE_RO,
                                              chan->u.temple.grant_cache);
            XM_ASSERT(!is_null_GRANT_REF(chan->u.temple.prod_grefs[x]));

            status = v2v_write_grantref(chan, xbt, x, TRUE);
            if (!NT_SUCCESS(status))          
                goto err;
        }

        for (x = 0; x < 1u << cons_ring_page_order; x++) {
            pa = MmGetPhysicalAddress((void *)((ULONG_PTR)chan->cons_sring + x * PAGE_SIZE));
            chan->u.temple.cons_grefs[x] =
                GnttabGrantForeignAccessCache(chan->peer_domid,
                                              PHYS_TO_PFN(pa),
                                              GRANT_MODE_RW,
                                              chan->u.temple.grant_cache);
            XM_ASSERT(!is_null_GRANT_REF(chan->u.temple.cons_grefs[x]));

            status = v2v_write_grantref(chan, xbt, x, FALSE);
            if (!NT_SUCCESS(status))
                goto err;
        }

        pa = MmGetPhysicalAddress((void *)((ULONG_PTR)chan->control));
        chan->u.temple.control_gref =
            GnttabGrantForeignAccessCache(chan->peer_domid,
                                          PHYS_TO_PFN(pa),
                                          GRANT_MODE_RW,
                                          chan->u.temple.grant_cache);
        XM_ASSERT(!is_null_GRANT_REF(chan->u.temple.control_gref));

        chan->receive_evtchn_port = 
            EvtchnAllocUnboundDpc(chan->peer_domid,
                                  (chan->is_sync ? v2v_dpc : async_values->receive_dpc),
                                  (chan->is_sync ? &chan->s.sync.receive_event : async_values->receive_ctx));
        if (is_null_EVTCHN_PORT(chan->receive_evtchn_port)) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto err;
        }
        xen_receive_port = xen_EVTCHN_PORT(chan->receive_evtchn_port);

        chan->send_evtchn_port = 
            EvtchnAllocUnboundDpc(chan->peer_domid,
                                  (chan->is_sync ? v2v_dpc : async_values->send_dpc),
                                  (chan->is_sync ? &chan->s.sync.send_event : async_values->send_ctx));
        if (is_null_EVTCHN_PORT(chan->send_evtchn_port)) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto err;
        }
        xen_send_port = xen_EVTCHN_PORT(chan->send_evtchn_port);

        xen_gref = xen_GRANT_REF(chan->u.temple.control_gref);
        status = 
            v2v_xenstore_scatter(xbt, chan->local_prefix,
                                 "prod-order", xenstore_scatter_type_int,
                                     prod_ring_page_order,
                                 "cons-order", xenstore_scatter_type_int,
                                     cons_ring_page_order,
                                 "control-gref", xenstore_scatter_type_grant_ref,
                                     xen_gref,
                                 "prod-evtchn",xenstore_scatter_type_evtchn_port,
                                     xen_send_port,
                                 "cons-evtchn",xenstore_scatter_type_evtchn_port,
                                     xen_receive_port,
                                 NULL);
        if (!NT_SUCCESS(status))
            goto err;

        status = v2v_change_local_state(chan, xbt, v2v_state_listening);
        if (!NT_SUCCESS(status))
            goto err;

        status = xenbus_transaction_end(xbt, 0);
        xbt_pending = FALSE;
        if (NT_SUCCESS(status))
            break;
        if (status != STATUS_RETRY)
            goto err;

        /* cleanup for retry */
        for (x = 0; x < 1u << prod_ring_page_order; x++) {
            GnttabEndForeignAccessCache(chan->u.temple.prod_grefs[x],
                                        chan->u.temple.grant_cache);
        }
        RtlZeroMemory(chan->u.temple.prod_grefs, sizeof(chan->u.temple.prod_grefs));

        for (x = 0; x < 1u << cons_ring_page_order; x++) {
            GnttabEndForeignAccessCache(chan->u.temple.cons_grefs[x],
                                        chan->u.temple.grant_cache);
        }
        RtlZeroMemory(chan->u.temple.cons_grefs, sizeof(chan->u.temple.cons_grefs));

        GnttabEndForeignAccessCache(chan->u.temple.control_gref,
                                    chan->u.temple.grant_cache);
        chan->u.temple.control_gref = null_GRANT_REF();

        EvtchnClose(chan->receive_evtchn_port);
        chan->receive_evtchn_port = null_EVTCHN_PORT();
        EvtchnClose(chan->send_evtchn_port);
        chan->send_evtchn_port = null_EVTCHN_PORT();

        xenbus_unregister_watch(chan->remote_state_watch);
        chan->remote_state_watch = NULL;
        ExFreePoolWithTag(chan->remote_prefix, V2V_TAG);
        chan->remote_prefix = NULL;
    }

    *channel = chan;

    return STATUS_SUCCESS;

err_nomem:
    status = STATUS_NO_MEMORY;
err:
    if (xbt_pending)
        xenbus_transaction_end(xbt, 1);
    /* since the channel has never been connected here, it is safe 
       to free any temple resources that may have been allocated in 
       this routine */
    v2v_destroy_channel(chan, TRUE);
    return status;
}

static NTSTATUS
v2v_get_remote_state_internal(xenbus_transaction_t xbt,
                              struct v2v_channel *channel,
                              enum v2v_endpoint_state *state)
{
    NTSTATUS status;
    char *raw;
    STRING s1, s2;

    XM_ASSERT(channel != NULL);
    XM_ASSERT(state != NULL);

    *state = v2v_state_unknown;

    status = v2v_xenstore_readv_string(&raw,
                                       xbt,
                                       channel->remote_prefix,
                                       "state",
                                       NULL);
    if (!NT_SUCCESS(status))
        return status;

    RtlInitString(&s1, raw);

    if (RtlCompareString(&s1, v2v_make_cs(&s2, "unready"), FALSE) == 0)
        *state = v2v_state_unready;
    else if (RtlCompareString(&s1, v2v_make_cs(&s2, "listening"), FALSE) == 0)
        *state = v2v_state_listening;
    else if (RtlCompareString(&s1, v2v_make_cs(&s2, "connected"), FALSE) == 0)
        *state = v2v_state_connected;
    else if (RtlCompareString(&s1, v2v_make_cs(&s2, "disconnecting"), FALSE) == 0)
        *state = v2v_state_disconnecting;
    else if (RtlCompareString(&s1, v2v_make_cs(&s2, "disconnected"), FALSE) == 0)
        *state = v2v_state_disconnected;
    else if (RtlCompareString(&s1, v2v_make_cs(&s2, "crashed"), FALSE) == 0)
        *state = v2v_state_crashed;    

    ExFreePoolWithTag(raw, V2V_TAG);    
    
    return (*state != v2v_state_unknown ? STATUS_SUCCESS : STATUS_DATA_ERROR); 
}

NTSTATUS
v2v_get_remote_state(struct v2v_channel *channel, enum v2v_endpoint_state *state)
{
    return v2v_get_remote_state_internal(XBT_NIL, channel, state);
}

NTSTATUS
v2v_accept(struct v2v_channel *channel)
{
    NTSTATUS status = STATUS_SUCCESS;
    xenbus_transaction_t xbt = {0};
    enum v2v_endpoint_state remote_state;

    XM_ASSERT(channel != NULL);

    for (;;) {
        xenbus_transaction_start(&xbt);        
        status = v2v_get_remote_state_internal(xbt, channel, &remote_state);
        switch (remote_state) {
        case v2v_state_unready:
        case v2v_state_disconnected:
        case v2v_state_crashed:
            xenbus_transaction_end(xbt, 1);
            KeWaitForSingleObject(&channel->control_event, Executive,
                                  KernelMode, FALSE, NULL);            
            break;
        case v2v_state_listening:
            xenbus_transaction_end(xbt, 1);
            return STATUS_POSSIBLE_DEADLOCK;
        case v2v_state_disconnecting:
            xenbus_transaction_end(xbt, 1);
            return STATUS_VIRTUAL_CIRCUIT_CLOSED;
        case v2v_state_unknown:
            xenbus_transaction_end(xbt, 1);
            return status; /* return the error from get state call */
        case v2v_state_connected:
            status = v2v_change_local_state(channel, xbt, v2v_state_connected);
            if (!NT_SUCCESS(status)) {
                xenbus_transaction_end(xbt, 1);
                return status;
            }
            status = xenbus_transaction_end(xbt, 0);
            if (NT_SUCCESS(status)) {
                channel->u.temple.accepted = TRUE;
                return STATUS_SUCCESS;
            }
            if (status != STATUS_RETRY)
                return status;
            break; /* try again */                     
        }          
    }
}

static NTSTATUS
v2v_read_grantref(struct v2v_channel *chan, xenbus_transaction_t xbt, int x, BOOLEAN is_prod)
{
    NTSTATUS status = STATUS_SUCCESS;
    const char *fmt = (is_prod ? "prod-gref-%d" : "cons-gref-%d");
    ALIEN_GRANT_REF *gref = (is_prod ? &chan->u.supplicant.prod_grefs[x] : &chan->u.supplicant.cons_grefs[x]);
    char buf[GREF_STRING_LEN];

    status = RtlStringCchPrintfA(buf, GREF_STRING_LEN, fmt, x);
    if (!NT_SUCCESS(status))
        return status;

    return v2v_xenstore_gather(xbt, chan->remote_prefix, buf, xenstore_gather_type_alien_grant_ref,
                               gref, NULL);
}

NTSTATUS
v2v_connect(const char *xenbus_prefix, struct v2v_channel **channel,
            struct v2v_async *async_values)
{
    NTSTATUS status = STATUS_SUCCESS;
    xenbus_transaction_t xbt = {0};
    struct v2v_channel *chan;
    enum v2v_endpoint_state remote_state;
    int producer_ring_order;
    int consumer_ring_order;
    int x;    
    BOOLEAN xbt_pending = FALSE;

    XM_ASSERT(channel != NULL);
    XM_ASSERT(xenbus_prefix != NULL);

    if (async_values && 
       (!async_values->receive_dpc || !async_values->send_dpc))
        return STATUS_INVALID_PARAMETER;

    *channel = NULL;

    for (;;) {
        chan = v2v_make_channel(xenbus_prefix, async_values);
        if (!chan)
            return STATUS_NO_MEMORY;

        xenbus_transaction_start(&xbt);
        xbt_pending = TRUE;

        status = v2v_connect_channel_xenbus(chan, xbt);
        if (!NT_SUCCESS(status))
            goto err; 

        status = v2v_get_remote_state_internal(xbt, chan, &remote_state);
        if (remote_state == v2v_state_unknown)
            goto err; /* status set to error code */
        if (remote_state != v2v_state_listening) {
            status = STATUS_NO_SUCH_DEVICE;
            goto err;
        }
    
        status = 
            v2v_xenstore_gather(xbt, chan->remote_prefix,
                             "prod-order",
                                 xenstore_gather_type_int,
                                 &producer_ring_order,
                             "cons-order",
                                 xenstore_gather_type_int,
                                 &consumer_ring_order,
                             "control-gref",
                                  xenstore_gather_type_alien_grant_ref,
                                  &chan->u.supplicant.control_gref,
                             "prod-evtchn",
                                  xenstore_gather_type_alien_evtchn_port,
                                  &chan->u.supplicant.prod_evtchn_port,
                             "cons-evtchn",
                                  xenstore_gather_type_alien_evtchn_port,
                                  &chan->u.supplicant.cons_evtchn_port,
                             NULL);
        if (!NT_SUCCESS(status))
            goto err;

        if (producer_ring_order > MAX_RING_PAGE_ORDER ||
            consumer_ring_order > MAX_RING_PAGE_ORDER) {
            status = STATUS_INVALID_PARAMETER;
            goto err;
        }

        for (x = 0; x < 1 << producer_ring_order; x++) {
            status = v2v_read_grantref(chan, xbt, x, TRUE);
            if (!NT_SUCCESS(status))
                goto err;
        }

        for (x = 0; x < 1 << consumer_ring_order; x++) {
            status = v2v_read_grantref(chan, xbt, x, FALSE);
            if (!NT_SUCCESS(status))
                goto err;
        }
        
        status = 
            v2v_xenops_grant_map((volatile void **)&chan->cons_sring,
                                 &chan->u.supplicant.prod_detail,
                                 chan->peer_domid,
                                 1 << producer_ring_order,
                                 chan->u.supplicant.prod_grefs,
                                 TRUE);
        if (!NT_SUCCESS(status))
            goto err;
        status = 
            v2v_xenops_grant_map((volatile void **)&chan->prod_sring,
                                 &chan->u.supplicant.cons_detail,
                                 chan->peer_domid,
                                 1 << consumer_ring_order,
                                 chan->u.supplicant.cons_grefs,
                                 FALSE);
        if (!NT_SUCCESS(status))
            goto err;
        status = 
            v2v_xenops_grant_map((volatile void **)&chan->control,
                                 &chan->u.supplicant.control_detail,
                                 chan->peer_domid,
                                 1,
                                 &chan->u.supplicant.control_gref,
                                 FALSE);
        if (!NT_SUCCESS(status))
            goto err;

        chan->receive_evtchn_port = 
            EvtchnConnectRemotePort(chan->peer_domid,
                                    chan->u.supplicant.prod_evtchn_port,
                                    (chan->is_sync ? v2v_dpc : async_values->receive_dpc),
                                    (chan->is_sync ? &chan->s.sync.receive_event : async_values->receive_ctx));
        if (is_null_EVTCHN_PORT(chan->receive_evtchn_port)) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto err;
        }

        chan->send_evtchn_port = 
            EvtchnConnectRemotePort(chan->peer_domid,
                                    chan->u.supplicant.cons_evtchn_port,
                                    (chan->is_sync ? v2v_dpc : async_values->send_dpc),
                                    (chan->is_sync ? &chan->s.sync.send_event : async_values->send_ctx));
        if (is_null_EVTCHN_PORT(chan->send_evtchn_port)) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto err;
        }

        status = v2v_change_local_state(chan, xbt, v2v_state_connected);
        if (!NT_SUCCESS(status))
            goto err;

        status = xenbus_transaction_end(xbt, 0);
        xbt_pending = FALSE;
        if (NT_SUCCESS(status))
            break;
        if (status != STATUS_RETRY)
            goto err;

        /* cleanup and try again */
        v2v_destroy_channel(chan, FALSE);      
    }

    /* Swap them round: *_ring_order is from the point of view of the
       temple, but we need the supplicant's viewpoint. */
    chan->nr_prod_ring_pages = 1 << consumer_ring_order;
    chan->nr_cons_ring_pages = 1 << producer_ring_order;

    v2v_nc2_attach_rings_supplicant(&chan->nc2_rings,
                                    chan->cons_sring,
                                    PAGE_SIZE << producer_ring_order,
                                    chan->prod_sring,
                                    PAGE_SIZE << consumer_ring_order,
                                    chan->control);

    *channel = chan;
 
    return STATUS_SUCCESS;

err:
    if (xbt_pending)
        xenbus_transaction_end(xbt, 1);
    v2v_destroy_channel(chan, FALSE);
    return status;
}

static NTSTATUS
v2v_disconnect_temple(const struct v2v_channel *_channel)
{
    NTSTATUS status = STATUS_SUCCESS;
    xenbus_transaction_t xbt = {0};
    struct v2v_channel *channel = (struct v2v_channel *)_channel;
    enum v2v_endpoint_state remote_state;
    BOOLEAN failed, any_failed = FALSE;
    unsigned x;

    status = v2v_change_local_state(channel, XBT_NIL, v2v_state_disconnecting);
    if (!NT_SUCCESS(status))
        return status;
    channel->u.temple.accepted = FALSE;

    /* Get the other end to disconnect */
    for (;;) {
        xenbus_transaction_start(&xbt);
        status = v2v_get_remote_state_internal(xbt, channel, &remote_state);
        switch (remote_state) {
        case v2v_state_unknown:            
            if (status == STATUS_OBJECT_NAME_NOT_FOUND)
                break;
            xenbus_transaction_end(xbt, 1);
            return status;

            /* The first two shouldn't really happen, but sometimes
               can if we've managed to screw (e.g.  if two processes
               try to use the same endpoint).  Try to recover. */
        case v2v_state_unready:
        case v2v_state_listening:
        case v2v_state_disconnecting:

        case v2v_state_disconnected:
        case v2v_state_crashed:
            break;
        case v2v_state_connected:
            xenbus_transaction_end(xbt, 1);
            KeWaitForSingleObject(&channel->control_event, Executive,
                                  KernelMode, FALSE, NULL);
            continue;
        }
        status = v2v_change_local_state(channel, xbt, v2v_state_disconnected);
        if (!NT_SUCCESS(status)) {            
            xenbus_transaction_end(xbt, 1);
            return status;
        }

        status = xenbus_transaction_end(xbt, 0);
        if (NT_SUCCESS(status))
            break; /* drop out of loop and do rest */
        if (status == STATUS_RETRY)
            continue; /* try again */
        return status; /* else return the error */
    }

    XM_ASSERT(channel->u.temple.grant_cache != NULL);

    failed = FALSE;
    for (x = 0; x < channel->nr_prod_ring_pages; x++) {
        if (!is_null_GRANT_REF(channel->u.temple.prod_grefs[x])) {
            status = GnttabEndForeignAccessCache(channel->u.temple.prod_grefs[x],
                                                 channel->u.temple.grant_cache);
            if (NT_SUCCESS(status))
                channel->u.temple.prod_grefs[x] = null_GRANT_REF();
            else
                failed = any_failed = TRUE;
        }
    }
    if (!failed) {
        ExFreePoolWithTag(channel->prod_sring, V2V_TAG);
        channel->prod_sring = NULL;
    }

    failed = FALSE;
    for (x = 0; x < channel->nr_cons_ring_pages; x++) {
        if (!is_null_GRANT_REF(channel->u.temple.cons_grefs[x])) {
            status = GnttabEndForeignAccessCache(channel->u.temple.cons_grefs[x],
                                                 channel->u.temple.grant_cache);
            if (NT_SUCCESS(status))
                channel->u.temple.cons_grefs[x] = null_GRANT_REF();
            else
                failed = any_failed = TRUE;
        }
    }
    if (!failed) {
		ExFreePoolWithTag((void *)channel->cons_sring, V2V_TAG);
        channel->cons_sring = NULL;
    }

    if (!is_null_GRANT_REF(channel->u.temple.control_gref)) {
        status = GnttabEndForeignAccessCache(channel->u.temple.control_gref,
                                             channel->u.temple.grant_cache);
        if (NT_SUCCESS(status)) {
            channel->u.temple.control_gref = null_GRANT_REF();
			ExFreePoolWithTag(channel->control, V2V_TAG);
            channel->control = NULL;
        }
        else
            any_failed = TRUE;
    }

    if (!any_failed)
        GnttabFreeCache(channel->u.temple.grant_cache);

    if (!is_null_EVTCHN_PORT(channel->receive_evtchn_port)) {
        EvtchnClose(channel->receive_evtchn_port);
        channel->receive_evtchn_port = null_EVTCHN_PORT();
    }
    if (!is_null_EVTCHN_PORT(channel->send_evtchn_port)) {
        EvtchnClose(channel->send_evtchn_port);
        channel->send_evtchn_port = null_EVTCHN_PORT();
    }

    /* We either freed the rings here or they could not be freed. Prevent
       v2v_destroy_channel() from trying to free grants/rings with 
       outstanding grant refs */
    v2v_destroy_channel(channel, FALSE);
    
    return STATUS_SUCCESS;
}

static NTSTATUS
v2v_disconnect_supplicant(const struct v2v_channel *_channel)
{
    NTSTATUS status;
    struct v2v_channel *channel = (struct v2v_channel *)_channel;

    v2v_xenops_grant_unmap((void *)channel->cons_sring, channel->u.supplicant.prod_detail);
    v2v_xenops_grant_unmap(channel->prod_sring, channel->u.supplicant.cons_detail);
    v2v_xenops_grant_unmap(channel->control, channel->u.supplicant.control_detail);
    channel->u.supplicant.prod_detail = NULL;
    channel->u.supplicant.cons_detail = NULL;
    channel->u.supplicant.control_detail = NULL;
    channel->prod_sring = NULL;
    channel->cons_sring = NULL;
    channel->control = NULL;

    if (!is_null_EVTCHN_PORT(channel->receive_evtchn_port)) {
        EvtchnClose(channel->receive_evtchn_port);
        channel->receive_evtchn_port = null_EVTCHN_PORT();
    }
    if (!is_null_EVTCHN_PORT(channel->send_evtchn_port)) {
        EvtchnClose(channel->send_evtchn_port);
        channel->send_evtchn_port = null_EVTCHN_PORT();
    }

    status = v2v_change_local_state(channel, XBT_NIL, v2v_state_disconnected);
    if (!NT_SUCCESS(status))
        return status;
    
    v2v_destroy_channel(channel, FALSE);

    return STATUS_SUCCESS;
}

NTSTATUS
v2v_disconnect(const struct v2v_channel *channel)
{
    XM_ASSERT(channel != NULL);

    if (channel->is_temple)
        return v2v_disconnect_temple(channel);
    else
        return v2v_disconnect_supplicant(channel);
}

PKEVENT
v2v_get_control_event(struct v2v_channel *channel)
{
    XM_ASSERT(channel != NULL);

    return &channel->control_event;
}

PKEVENT
v2v_get_send_event(struct v2v_channel *channel)
{
    XM_ASSERT(channel != NULL);

    return (channel->is_sync ? &channel->s.sync.send_event : NULL);    
}

PKEVENT
v2v_get_receive_event(struct v2v_channel *channel)
{
    XM_ASSERT(channel != NULL);

    return (channel->is_sync ? &channel->s.sync.receive_event : NULL);    
}

NTSTATUS
v2v_nc2_get_message(struct v2v_channel *channel,
                    const volatile void **msg,
                    size_t *out_size,
                    unsigned *type,
                    unsigned *flags)
{
    RING_IDX prod;
    RING_IDX cons_pvt;
    const volatile struct netchannel2_msg_hdr *hdr;
    unsigned size;
    unsigned counter;

    XM_ASSERT(channel != NULL);
    XM_ASSERT((msg != NULL)&&(out_size != NULL)&&(type != NULL)&&(flags != NULL));

    counter = 0;

retry:
    cons_pvt = channel->nc2_rings.local_cons_pvt;
    prod = channel->nc2_rings.remote_endpoint->prod;
    rmb();
    if (prod == cons_pvt) {
        if (channel->nc2_rings.remote_endpoint->producer_active &&
            counter < CONSUMER_SPIN_LIMIT) {
            channel->nc2_rings.local_endpoint->consumer_spinning = 1;
            while (channel->nc2_rings.remote_endpoint->producer_active &&
                   counter++ < CONSUMER_SPIN_LIMIT)
                ;
            channel->nc2_rings.local_endpoint->consumer_spinning = 0;
            /* The write to local_endpoint->consumer_spinning needs to
               come before any write of prod_event which might happen
               shortly.  Fortunately, they're both volatile, so happen
               in-order, and we don't need any explicit barriers. */
            goto retry;
        }
        if (channel->is_sync)
            KeResetEvent(&channel->s.sync.receive_event);
        if (nc2_final_check_for_messages(&channel->nc2_rings, prod)) {
            if (channel->is_sync)
                KeSetEvent(&channel->s.sync.receive_event, IO_NO_INCREMENT, FALSE);
            goto retry;
        }
        return STATUS_NO_MORE_ENTRIES;
    }
    hdr = __nc2_incoming_message(&channel->nc2_rings);
    if (!__nc2_contained_in_cons_ring(&channel->nc2_rings,
                                      hdr,
                                      sizeof(*hdr))) {
        /* This can't happen, unless the other end is misbehaving. */
invalid_message:
        return STATUS_DATA_ERROR;
    }
    size = hdr->size;
    if (size < sizeof(*hdr) ||
        !__nc2_contained_in_cons_ring(&channel->nc2_rings, hdr, size))
        goto invalid_message;
    if (hdr->type == NETCHANNEL2_MSG_PAD) {
        /* Discard pad message */
        channel->nc2_rings.local_cons_pvt += size;
        goto retry;
    }

    *msg = hdr + 1;
    *out_size = channel->current_message_size = size - sizeof(*hdr);
    *type = hdr->type;
    *flags = hdr->flags;

    return STATUS_SUCCESS;
}

void
v2v_nc2_finish_message(struct v2v_channel *channel)
{
    XM_ASSERT(channel != NULL);

    channel->nc2_rings.local_cons_pvt +=
        (channel->current_message_size + sizeof(struct netchannel2_msg_hdr) + 7) & ~7;
    if (nc2_finish_messages(&channel->nc2_rings)) {
        XM_ASSERT(!is_null_EVTCHN_PORT(channel->receive_evtchn_port));
        EvtchnNotifyRemote(channel->receive_evtchn_port);
    }
}

NTSTATUS
v2v_nc2_prep_message(struct v2v_channel *channel,
                     size_t msg_size,
                     unsigned char type,
                     unsigned char flags,
                     volatile void **payload)
{
    volatile struct netchannel2_msg_hdr *hdr;
    unsigned short size;
    unsigned short rounded_size;

    XM_ASSERT(channel != NULL);
    XM_ASSERT(payload != NULL);

    msg_size += sizeof(*hdr);
    if ( ((msg_size + 7) & ~7) >
         channel->nc2_rings.producer_payload_bytes )
        return STATUS_INVALID_PARAMETER;

    if (type >= NETCHANNEL2_MSG_PAD)
        return STATUS_NOT_IMPLEMENTED;

    size = (unsigned short)msg_size;
    rounded_size = (size + 7) & ~7;

    if (channel->nc2_rings.remote_endpoint->consumer_active)
        v2v_nc2_send_messages(channel);
    if (!nc2_can_send_payload_bytes(&channel->nc2_rings, rounded_size)) {
        if (channel->is_sync)
            KeResetEvent(&channel->s.sync.send_event);
        if (!nc2_can_send_payload_bytes(&channel->nc2_rings, rounded_size))
            return STATUS_RETRY;
        if (channel->is_sync)
            KeSetEvent(&channel->s.sync.send_event, IO_NO_INCREMENT, FALSE);
    }
    __nc2_avoid_ring_wrap(&channel->nc2_rings, rounded_size);
    hdr = __nc2_get_message_ptr(&channel->nc2_rings);
    hdr->size = size;
    hdr->type = type;
    hdr->flags = flags;
    *payload = hdr + 1;
    channel->nc2_rings.local_prod_pvt += rounded_size;
    channel->nc2_rings.local_prod_bytes_available -= rounded_size;

    if (channel->nc2_rings.remote_endpoint->consumer_active &&
        !channel->nc2_rings.local_producer_active &&
        __nc2_flush_would_trigger_event(&channel->nc2_rings)) {
        channel->nc2_rings.local_endpoint->producer_active = 1;
        channel->nc2_rings.local_producer_active = 1;
        XM_ASSERT(!is_null_EVTCHN_PORT(channel->send_evtchn_port));
        EvtchnNotifyRemote(channel->send_evtchn_port);
    }

    return STATUS_SUCCESS;
}

/* A rough estimate of the largest size you can pass to prep_message()
   without needing to either block or generate a pad message */
unsigned
v2v_nc2_producer_bytes_available(struct v2v_channel *channel)
{
    RING_IDX cons;
    RING_IDX prod;
    unsigned mask;
    unsigned res;

    XM_ASSERT(channel != NULL);

    cons = channel->nc2_rings.remote_endpoint->cons;
    prod = channel->nc2_rings.local_prod_pvt;
    mask = channel->nc2_rings.producer_payload_bytes - 1;
    if ( (cons & mask) > (prod & mask) ) {
        res = (cons & mask) - (prod & mask);
    } else {
        res = channel->nc2_rings.producer_payload_bytes - (prod & mask);
        if (res < 16)
            res = cons & mask;
    }
    if (res < sizeof(struct netchannel2_msg_hdr) + 8)
        return 0;
    else
        return res - sizeof(struct netchannel2_msg_hdr) - 8;
}

void
v2v_nc2_send_messages(struct v2v_channel *channel)
{
    XM_ASSERT(channel != NULL);

    if (nc2_flush_ring(&channel->nc2_rings)) {
        /* The read of consumer_spinning needs to be after the read of
         * prod_event in nc2_flush_ring().  Both fields are volatile,
         * so the compiler gives us that for free and we don't need
         * explicit barriers. */
        if (!channel->nc2_rings.remote_endpoint->consumer_spinning) {
            XM_ASSERT(!is_null_EVTCHN_PORT(channel->send_evtchn_port));
            EvtchnNotifyRemote(channel->send_evtchn_port);            
        }
        if (channel->nc2_rings.local_producer_active) {
            channel->nc2_rings.local_producer_active = 0;
            channel->nc2_rings.local_endpoint->producer_active = 0;
        }
    }
}

void
v2v_nc2_request_fast_receive(struct v2v_channel *channel)
{
    XM_ASSERT(channel != NULL);

    channel->nc2_rings.local_endpoint->consumer_active = 1;
}

void
v2v_nc2_cancel_fast_receive(struct v2v_channel *channel)
{
    XM_ASSERT(channel != NULL);

    channel->nc2_rings.local_endpoint->consumer_active = 0;
}

BOOLEAN
v2v_nc2_remote_requested_fast_wakeup(struct v2v_channel *channel)
{
    XM_ASSERT(channel != NULL);

    if (channel->nc2_rings.remote_endpoint->consumer_active)
        return TRUE;
    else
        return FALSE;
}

