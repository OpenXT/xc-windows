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

#include <windows.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <xs2.h>
#include <xenops.h>
#include <xs_private.h>

#define V2V_API_EXPORTS
#include "v2v.h"

#include "vring.h"
#include "v2v_private.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define MAX_RING_PAGE_ORDER 4
#define MAX_RING_PAGES (1 << MAX_RING_PAGE_ORDER)

#define CONSUMER_SPIN_LIMIT 2048

struct v2v_channel {
    struct xs2_handle *xs2;
    struct xs2_watch *remote_state_watch;
    struct xenops_handle *xenops;
    char *local_prefix;
    char *remote_prefix; /* xs2_free() */
    DOMAIN_ID peer_domid;
    HANDLE control_event;
    HANDLE receive_event;
    HANDLE send_event;

    void *prod_sring;
    const void *cons_sring;
    void *control;
    EVTCHN_PORT receive_evtchn_port;
    EVTCHN_PORT send_evtchn_port;
    WRITE_ON_CLOSE_HANDLE set_crashed_on_close;

    unsigned nr_prod_ring_pages;
    unsigned nr_cons_ring_pages;

    unsigned current_message_size;

    struct nc2_ring_pair nc2_rings;

    BOOL is_temple;
    union {
        struct {
            GRANT_REF prod_grefs[MAX_RING_PAGES];
            GRANT_REF cons_grefs[MAX_RING_PAGES];
            GRANT_REF control_gref;
        } temple;
        struct {
            GRANT_MAP_HANDLE prod_handle;
            GRANT_MAP_HANDLE cons_handle;
            GRANT_MAP_HANDLE control_handle;

            ALIEN_GRANT_REF prod_grefs[MAX_RING_PAGES];
            ALIEN_GRANT_REF cons_grefs[MAX_RING_PAGES];
            ALIEN_GRANT_REF control_gref;
            ALIEN_EVTCHN_PORT prod_evtchn_port;
            ALIEN_EVTCHN_PORT cons_evtchn_port;
        } supplicant;
    } u;
};

static void
destroy_channel(const struct v2v_channel *_chan)
{
    struct v2v_channel *chan = (struct v2v_channel *)_chan;
    unsigned x;

    if (chan->remote_state_watch)
        xs2_unwatch(chan->remote_state_watch);
    free(chan->local_prefix);
    xs2_free(chan->remote_prefix);
    if (chan->xs2)
        xs2_close(chan->xs2);
    if (chan->control_event)
        CloseHandle(chan->control_event);
    if (chan->receive_event)
        CloseHandle(chan->receive_event);
    if (chan->send_event)
        CloseHandle(chan->send_event);
    if (chan->is_temple) {
        if (chan->xenops) {
            for (x = 0; x < chan->nr_prod_ring_pages; x++)
                xenops_ungrant(chan->xenops, chan->u.temple.prod_grefs[x]);
            for (x = 0; x < chan->nr_cons_ring_pages; x++)
                xenops_ungrant(chan->xenops, chan->u.temple.cons_grefs[x]);
            xenops_ungrant(chan->xenops, chan->u.temple.control_gref);
        }
        VirtualFree(chan->prod_sring, 0, MEM_RELEASE);
        VirtualFree((void *)chan->cons_sring, 0, MEM_RELEASE);
        VirtualFree(chan->control, 0, MEM_RELEASE);
    } else {
        if (chan->xenops) {
            xenops_unmap_grant(chan->xenops,
                               chan->u.supplicant.prod_handle);
            xenops_unmap_grant(chan->xenops,
                               chan->u.supplicant.cons_handle);
            xenops_unmap_grant(chan->xenops,
                               chan->u.supplicant.control_handle);
        }
    }

    if (chan->xenops)
        xenops_close(chan->xenops);

    yfree(chan);
}

static void
cancel_crashed_on_crash(struct v2v_channel *chan)
{
    xs2_cancel_write_on_close(chan->xs2, chan->set_crashed_on_close);
}

static BOOL
setup_crashed_on_crash(struct v2v_channel *chan)
{
    char *path;
    const char *s;

    path = xs_asprintf("%s/state", chan->local_prefix);
    if (!path) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    s = v2v_endpoint_state_name(v2v_state_crashed);
    chan->set_crashed_on_close = xs2_write_on_close(chan->xs2,
                                                    path,
                                                    s,
                                                    strlen(s));
    yfree(path);
    if (is_null_WRITE_ON_CLOSE_HANDLE(chan->set_crashed_on_close))
        return FALSE;
    else
        return TRUE;
}

static BOOL
read_peer_domid(struct v2v_channel *chan)
{
    char *s;
    long r;
    char *s2;

    s = xenstore_readv_string(chan->xs2, chan->local_prefix, "peer-domid",
                              NULL);
    if (!s)
        return FALSE;
    r = strtol(s, &s2, 10);
    if (*s2 || r < 0 || r > 0xffff) {
        xs2_free(s);
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }
    xs2_free(s);
    chan->peer_domid = wrap_DOMAIN_ID(r);
    return TRUE;
}

static struct v2v_channel *
make_channel(const char *xenbus_prefix)
{
    struct v2v_channel *chan;
    DWORD err;

    chan = ymalloc(sizeof(*chan));
    if (!chan)
        return NULL;

    chan->control_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    chan->receive_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    chan->send_event = CreateEvent(NULL, FALSE, TRUE, NULL);
    if (!chan->control_event || !chan->receive_event || !chan->send_event)
        goto err;
    /* xenops *must* be opened before xs2, or the crash bits don't
     * work.  This is a truly horrible hack. */
    chan->xenops = xenops_open();
    if (!chan->xenops)
        goto err;
    chan->xs2 = xs2_open();
    if (!chan->xs2)
        goto err;
    chan->local_prefix = ystrdup(xenbus_prefix);
    if (!chan->local_prefix)
        goto err;

    return chan;

err:
    err = GetLastError();
    destroy_channel(chan);
    SetLastError(err);
    return NULL;
}

static BOOL
connect_channel_xenbus(struct v2v_channel *chan)
{
    chan->remote_prefix = xenstore_readv_string(chan->xs2,
                                                chan->local_prefix,
                                                "backend",
                                                NULL);
    if (!chan->remote_prefix)
        return FALSE;
    if (!read_peer_domid(chan))
        return FALSE;
    chan->remote_state_watch = xenstore_watchv(chan->xs2,
                                               chan->control_event,
                                               chan->remote_prefix,
                                               "state",
                                               NULL);
    if (!chan->remote_state_watch)
        return FALSE;
    else
        return TRUE;
}

static void
nc2_attach_rings_temple(struct nc2_ring_pair *ncrp,
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
nc2_attach_rings_supplicant(struct nc2_ring_pair *ncrp,
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

static BOOL
change_local_state(struct v2v_channel *channel, enum v2v_endpoint_state state)
{
    return xenstore_printfv(channel->xs2,
                            channel->local_prefix,
                            "state",
                            NULL,
                            v2v_endpoint_state_name(state));
}

BOOL
v2v_listen(const char *xenbus_prefix, struct v2v_channel **channel,
           unsigned prod_ring_page_order, unsigned cons_ring_page_order)
{
    unsigned prod_ring_size = PAGE_SIZE << prod_ring_page_order;
    unsigned cons_ring_size = PAGE_SIZE << cons_ring_page_order;
    struct v2v_channel *chan;
    DWORD err;
    unsigned x;
    char buf[32];

    if (prod_ring_page_order > MAX_RING_PAGE_ORDER ||
        cons_ring_page_order > MAX_RING_PAGE_ORDER) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *channel = NULL;

    chan = make_channel(xenbus_prefix);
    if (!chan)
        return FALSE;

    chan->is_temple = TRUE;

    chan->prod_sring = VirtualAlloc(NULL, prod_ring_size, MEM_COMMIT,
                                    PAGE_READWRITE);
    chan->cons_sring = VirtualAlloc(NULL, cons_ring_size, MEM_COMMIT,
                                    PAGE_READWRITE);
    chan->control = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT,
                                 PAGE_READWRITE);
    if (!chan->prod_sring || !chan->cons_sring || !chan->control)
        goto err;

    chan->nr_prod_ring_pages = 1 << prod_ring_page_order;
    chan->nr_cons_ring_pages = 1 << cons_ring_page_order;

    nc2_attach_rings_temple(&chan->nc2_rings,
                            chan->cons_sring,
                            cons_ring_size,
                            chan->prod_sring,
                            prod_ring_size,
                            chan->control);

    for (;;) {
        xs2_transaction_start(chan->xs2);

        if (!connect_channel_xenbus(chan))
            goto err;

        for (x = 0; x < 1u << prod_ring_page_order; x++) {
            if (!xenops_grant_readonly(chan->xenops,
                                       chan->peer_domid,
                                       (void *)((ULONG_PTR)chan->prod_sring + x * PAGE_SIZE),
                                       chan->u.temple.prod_grefs + x))
                goto err;
            sprintf(buf, "prod-gref-%d", x);
            if (!xenstore_printfv(chan->xs2, chan->local_prefix, buf, NULL,
                                  "%d",
                                  xen_GRANT_REF(chan->u.temple.prod_grefs[x])))
                goto err;
        }

        for (x = 0; x < 1u << cons_ring_page_order; x++) {
            if (!xenops_grant_readwrite(chan->xenops,
                                        chan->peer_domid,
                                        (void *)((ULONG_PTR)chan->cons_sring + x * PAGE_SIZE),
                                        &chan->u.temple.cons_grefs[x]))
                goto err;
            sprintf(buf, "cons-gref-%d", x);
            if (!xenstore_printfv(chan->xs2, chan->local_prefix, buf, NULL,
                                  "%d",
                                  xen_GRANT_REF(chan->u.temple.cons_grefs[x])))
                goto err;
        }

        if (!xenops_grant_readwrite(chan->xenops,
                                    chan->peer_domid,
                                    chan->control,
                                    &chan->u.temple.control_gref) ||
            !xenops_evtchn_listen(chan->xenops,
                                  chan->peer_domid,
                                  chan->receive_event,
                                  &chan->receive_evtchn_port) ||
            !xenops_evtchn_listen(chan->xenops,
                                  chan->peer_domid,
                                  chan->send_event,
                                  &chan->send_evtchn_port))
            goto err;

        if (!xenstore_scatter(chan->xs2, chan->local_prefix,
                              "prod-order", xenstore_scatter_type_int,
                                  prod_ring_page_order,
                              "cons-order", xenstore_scatter_type_int,
                                  cons_ring_page_order,
                              "control-gref", xenstore_scatter_type_grant_ref,
                                  chan->u.temple.control_gref,
                              "prod-evtchn",xenstore_scatter_type_evtchn_port,
                                  chan->send_evtchn_port,
                              "cons-evtchn",xenstore_scatter_type_evtchn_port,
                                  chan->receive_evtchn_port,
                              NULL))
            goto err;
        if (!setup_crashed_on_crash(chan))
            goto err;
        if (!change_local_state(chan, v2v_state_listening))
            goto err;
        if (xs2_transaction_commit(chan->xs2))
            break;
        if (GetLastError() != ERROR_RETRY)
            goto err;

        for (x = 0; x < 1u << prod_ring_page_order; x++)
            xenops_ungrant(chan->xenops, chan->u.temple.prod_grefs[x]);
        memset(chan->u.temple.prod_grefs, 0,
               sizeof(chan->u.temple.prod_grefs));
        for (x = 0; x < 1u << cons_ring_page_order; x++)
            xenops_ungrant(chan->xenops, chan->u.temple.cons_grefs[x]);
        memset(chan->u.temple.cons_grefs, 0,
               sizeof(chan->u.temple.cons_grefs));

        xenops_ungrant(chan->xenops, chan->u.temple.control_gref);
        chan->u.temple.control_gref = null_GRANT_REF();
        xenops_evtchn_close(chan->xenops, chan->receive_evtchn_port);
        chan->receive_evtchn_port = null_EVTCHN_PORT();
        xenops_evtchn_close(chan->xenops, chan->send_evtchn_port);
        chan->send_evtchn_port = null_EVTCHN_PORT();
        xs2_unwatch(chan->remote_state_watch);
        chan->remote_state_watch = NULL;
        xs2_free(chan->remote_prefix);
        chan->remote_prefix = NULL;
        cancel_crashed_on_crash(chan);
    }

    *channel = chan;

    return TRUE;

err:
    err = GetLastError();
    destroy_channel(chan);
    SetLastError(err);
    return FALSE;
}

enum v2v_endpoint_state
v2v_get_remote_state(struct v2v_channel *channel)
{
    char *raw;
    enum v2v_endpoint_state res;

    raw = xenstore_readv_string(channel->xs2,
                                channel->remote_prefix,
                                "state",
                                NULL);
    if (!raw)
        return v2v_state_unknown;
    if (!strcmp(raw, "unready"))
        res = v2v_state_unready;
    else if (!strcmp(raw, "listening"))
        res = v2v_state_listening;
    else if (!strcmp(raw, "connected"))
        res = v2v_state_connected;
    else if (!strcmp(raw, "disconnecting"))
        res = v2v_state_disconnecting;
    else if (!strcmp(raw, "disconnected"))
        res = v2v_state_disconnected;
    else if (!strcmp(raw, "crashed"))
        res = v2v_state_crashed;
    else
        res = v2v_state_unknown;
    xs2_free(raw);
    if (res == v2v_state_unknown)
        SetLastError(ERROR_INVALID_DATA);
    return res;
}

BOOL
v2v_accept(struct v2v_channel *channel)
{
    enum v2v_endpoint_state remote_state;
    BOOL ret;
    DWORD err;

    while (1) {
        xs2_transaction_start(channel->xs2);
        remote_state = v2v_get_remote_state(channel);
        switch (remote_state) {
        case v2v_state_unready:
        case v2v_state_disconnected:
        case v2v_state_crashed:
            xs2_transaction_abort(channel->xs2);
            WaitForSingleObject(channel->control_event, INFINITE);
            break;
        case v2v_state_listening:
            xs2_transaction_abort(channel->xs2);
            SetLastError(ERROR_POSSIBLE_DEADLOCK);
            return FALSE;
        case v2v_state_disconnecting:
            xs2_transaction_abort(channel->xs2);
            SetLastError(ERROR_VC_DISCONNECTED);
            return FALSE;
        case v2v_state_unknown:
            xs2_transaction_abort(channel->xs2);
            return FALSE;
        case v2v_state_connected:
            ret = change_local_state(channel, v2v_state_connected);
            if (!ret) {
                err = GetLastError();
                xs2_transaction_abort(channel->xs2);
                SetLastError(err);
                return FALSE;
            }
            if (xs2_transaction_commit(channel->xs2))
                return TRUE;
            if (GetLastError() != ERROR_RETRY)
                return FALSE;
            break;
        }
    }
}

BOOL
v2v_connect(const char *xenbus_prefix, struct v2v_channel **channel)
{
    struct v2v_channel *chan;
    enum v2v_endpoint_state remote_state;
    DWORD err;
    int producer_ring_order;
    int consumer_ring_order;
    int x;
    char buf[32];

    *channel = NULL;

    for (;;) {
        chan = make_channel(xenbus_prefix);
        if (!chan)
            return FALSE;

        xs2_transaction_start(chan->xs2);

        if (!connect_channel_xenbus(chan))
            goto err;

        remote_state = v2v_get_remote_state(chan);
        if (remote_state == v2v_state_unknown)
            goto err;
        if (remote_state != v2v_state_listening) {
            SetLastError(ERROR_NOT_READY);
            goto err;
        }

        if (!xenstore_gather(chan->xs2,
                             chan->remote_prefix,
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
                             NULL))
            goto err;

        if (producer_ring_order > MAX_RING_PAGE_ORDER ||
            consumer_ring_order > MAX_RING_PAGE_ORDER) {
            SetLastError(ERROR_INVALID_PARAMETER);
            goto err;
        }

        for (x = 0; x < 1 << producer_ring_order; x++) {
            sprintf(buf, "prod-gref-%d", x);
            if (!xenstore_gather(chan->xs2, chan->remote_prefix,
                                 buf, xenstore_gather_type_alien_grant_ref,
                                 chan->u.supplicant.prod_grefs + x, NULL))
                goto err;
        }

        for (x = 0; x < 1 << consumer_ring_order; x++) {
            sprintf(buf, "cons-gref-%d", x);
            if (!xenstore_gather(chan->xs2, chan->remote_prefix,
                                 buf, xenstore_gather_type_alien_grant_ref,
                                 chan->u.supplicant.cons_grefs + x, NULL))
                goto err;
        }

        if (!xenops_grant_map_readonly(chan->xenops,
                                       chan->peer_domid,
                                       1 << producer_ring_order,
                                       chan->u.supplicant.prod_grefs,
                                       &chan->u.supplicant.prod_handle,
                                       &chan->cons_sring) ||
            !xenops_grant_map_readwrite(chan->xenops,
                                        chan->peer_domid,
                                        1 << consumer_ring_order,
                                        chan->u.supplicant.cons_grefs,
                                        &chan->u.supplicant.cons_handle,
                                        &chan->prod_sring) ||
            !xenops_grant_map_readwrite(chan->xenops,
                                        chan->peer_domid,
                                        1,
                                        &chan->u.supplicant.control_gref,
                                        &chan->u.supplicant.control_handle,
                                        &chan->control) ||
            !xenops_evtchn_connect(chan->xenops,
                                   chan->peer_domid,
                                   chan->u.supplicant.prod_evtchn_port,
                                   chan->receive_event,
                                   &chan->receive_evtchn_port) ||
            !xenops_evtchn_connect(chan->xenops,
                                   chan->peer_domid,
                                   chan->u.supplicant.cons_evtchn_port,
                                   chan->send_event,
                                   &chan->send_evtchn_port))
            goto err;

        if (!setup_crashed_on_crash(chan))
            goto err;

        if (!change_local_state(chan, v2v_state_connected))
            goto err;

        if (xs2_transaction_commit(chan->xs2))
            break;
        if (GetLastError() != ERROR_RETRY)
            goto err;

        cancel_crashed_on_crash(chan);

        destroy_channel(chan);
    }

    /* Swap them round: *_ring_order is from the point of view of the
       temple, but we need the supplicant's viewpoint. */
    chan->nr_prod_ring_pages = 1 << consumer_ring_order;
    chan->nr_cons_ring_pages = 1 << producer_ring_order;

    nc2_attach_rings_supplicant(&chan->nc2_rings,
                                chan->cons_sring,
                                PAGE_SIZE << producer_ring_order,
                                chan->prod_sring,
                                PAGE_SIZE << consumer_ring_order,
                                chan->control);

    *channel = chan;

    return TRUE;

err:
    err = GetLastError();
    cancel_crashed_on_crash(chan);
    destroy_channel(chan);
    SetLastError(err);
    return FALSE;
}

static BOOL
v2v_disconnect_temple(const struct v2v_channel *_channel)
{
    struct v2v_channel *channel = (struct v2v_channel *)_channel;
    enum v2v_endpoint_state remote_state;
    DWORD err;
    BOOL failed;
    unsigned x;

    if (!change_local_state(channel, v2v_state_disconnecting))
        return FALSE;

    /* Get the other end to disconnect */
    for (;;) {
        xs2_transaction_start(channel->xs2);
        remote_state = v2v_get_remote_state(channel);
        switch (remote_state) {
        case v2v_state_unknown:
            err = GetLastError();
            if (err == ERROR_FILE_NOT_FOUND)
                break;
            xs2_transaction_abort(channel->xs2);
            SetLastError(err);
            return FALSE;

            /* The first two shouldn't really happen, but sometimes
               can if we've managed to screw (e.g.  if two processes
               try to use the same endpoint).  Try to recover. */
        case v2v_state_unready:
        case v2v_state_listening:

        case v2v_state_disconnected:
        case v2v_state_crashed:
            break;
        case v2v_state_connected:
            xs2_transaction_abort(channel->xs2);
            WaitForSingleObject(channel->control_event, INFINITE);
            continue;
        }
        if (!change_local_state(channel, v2v_state_disconnected)) {
            err = GetLastError();
            xs2_transaction_abort(channel->xs2);
            SetLastError(err);
            return FALSE;
        }
        if (xs2_transaction_commit(channel->xs2))
            break;
        if (GetLastError() == ERROR_RETRY)
            continue;
        return FALSE;
    }

    cancel_crashed_on_crash(channel);

    failed = FALSE;
    for (x = 0; x < channel->nr_prod_ring_pages; x++) {
        if (!is_null_GRANT_REF(channel->u.temple.prod_grefs[x])) {
            if (xenops_ungrant(channel->xenops,
                               channel->u.temple.prod_grefs[x]))
                channel->u.temple.prod_grefs[x] = null_GRANT_REF();
            else
                failed = TRUE;
        }
    }
    if (!failed) {
        VirtualFree(channel->prod_sring, 0, MEM_RELEASE);
        channel->prod_sring = NULL;
    }

    failed = FALSE;
    for (x = 0; x < channel->nr_cons_ring_pages; x++) {
        if (!is_null_GRANT_REF(channel->u.temple.cons_grefs[x])) {
            if (xenops_ungrant(channel->xenops,
                               channel->u.temple.cons_grefs[x]))
                channel->u.temple.cons_grefs[x] = null_GRANT_REF();
            else
                failed = TRUE;
        }
    }
    if (!failed) {
        VirtualFree((void *)channel->cons_sring, 0, MEM_RELEASE);
        channel->cons_sring = NULL;
    }

    if (xenops_ungrant(channel->xenops, channel->u.temple.control_gref)) {
        channel->u.temple.control_gref = null_GRANT_REF();
        VirtualFree(channel->control, 0, MEM_RELEASE);
        channel->control = NULL;
    }

    destroy_channel(channel);
    return TRUE;
}

static BOOL
v2v_disconnect_supplicant(const struct v2v_channel *_channel)
{
    struct v2v_channel *channel = (struct v2v_channel *)_channel;

    xenops_unmap_grant(channel->xenops, channel->u.supplicant.prod_handle);
    xenops_unmap_grant(channel->xenops, channel->u.supplicant.cons_handle);
    xenops_unmap_grant(channel->xenops, channel->u.supplicant.control_handle);
    channel->u.supplicant.prod_handle = null_GRANT_MAP_HANDLE();
    channel->u.supplicant.cons_handle = null_GRANT_MAP_HANDLE();
    channel->u.supplicant.control_handle = null_GRANT_MAP_HANDLE();
    channel->prod_sring = NULL;
    channel->cons_sring = NULL;
    channel->control = NULL;

    xenops_evtchn_close(channel->xenops, channel->send_evtchn_port);
    xenops_evtchn_close(channel->xenops, channel->receive_evtchn_port);

    if (!change_local_state(channel, v2v_state_disconnected))
        return FALSE;
    cancel_crashed_on_crash(channel);
    destroy_channel(channel);
    return TRUE;
}

BOOL
v2v_disconnect(const struct v2v_channel *channel)
{
    if (channel->is_temple)
        return v2v_disconnect_temple(channel);
    else
        return v2v_disconnect_supplicant(channel);
}

HANDLE
v2v_get_control_event(struct v2v_channel *channel)
{
    return channel->control_event;
}

HANDLE
v2v_get_send_event(struct v2v_channel *channel)
{
    return channel->send_event;
}

HANDLE
v2v_get_receive_event(struct v2v_channel *channel)
{
    return channel->receive_event;
}

BOOL
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
        ResetEvent(channel->receive_event);
        if (nc2_final_check_for_messages(&channel->nc2_rings, prod)) {
            SetEvent(channel->receive_event);
            goto retry;
        }
        SetLastError(ERROR_NO_MORE_ITEMS);
        return FALSE;
    }
    hdr = __nc2_incoming_message(&channel->nc2_rings);
    if (!__nc2_contained_in_cons_ring(&channel->nc2_rings,
                                      hdr,
                                      sizeof(*hdr))) {
        /* This can't happen, unless the other end is misbehaving. */
    invalid_message:
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
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

    return TRUE;
}

void
v2v_nc2_finish_message(struct v2v_channel *channel)
{
    channel->nc2_rings.local_cons_pvt +=
        (channel->current_message_size + sizeof(struct netchannel2_msg_hdr) + 7) & ~7;
    if (nc2_finish_messages(&channel->nc2_rings))
        xenops_evtchn_notify(channel->xenops, channel->receive_evtchn_port);
}

BOOL
v2v_nc2_prep_message(struct v2v_channel *channel,
                     size_t msg_size,
                     unsigned char type,
                     unsigned char flags,
                     volatile void **payload)
{
    volatile struct netchannel2_msg_hdr *hdr;
    unsigned short size;
    unsigned short rounded_size;
    msg_size += sizeof(*hdr);
    if ( ((msg_size + 7) & ~7) >
         channel->nc2_rings.producer_payload_bytes ) {
        SetLastError(ERROR_BAD_LENGTH);
        return FALSE;
    }
    if (type >= NETCHANNEL2_MSG_PAD) {
        SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
    }
    size = (unsigned short)msg_size;
    rounded_size = (size + 7) & ~7;

    if (channel->nc2_rings.remote_endpoint->consumer_active)
        v2v_nc2_send_messages(channel);
    if (!nc2_can_send_payload_bytes(&channel->nc2_rings, rounded_size)) {
        ResetEvent(channel->send_event);
        if (!nc2_can_send_payload_bytes(&channel->nc2_rings, rounded_size)){
            SetLastError(ERROR_RETRY);
            return FALSE;
        }
        SetEvent(channel->send_event);
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
        xenops_evtchn_notify(channel->xenops, channel->send_evtchn_port);
    }

    return TRUE;
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
    if (nc2_flush_ring(&channel->nc2_rings)) {
        /* The read of consumer_spinning needs to be after the read of
         * prod_event in nc2_flush_ring().  Both fields are volatile,
         * so the compiler gives us that for free and we don't need
         * explicit barriers. */
        if (!channel->nc2_rings.remote_endpoint->consumer_spinning)
            xenops_evtchn_notify(channel->xenops, channel->send_evtchn_port);
        if (channel->nc2_rings.local_producer_active) {
            channel->nc2_rings.local_producer_active = 0;
            channel->nc2_rings.local_endpoint->producer_active = 0;
        }
    }
}

void
v2v_nc2_request_fast_receive(struct v2v_channel *channel)
{
    channel->nc2_rings.local_endpoint->consumer_active = 1;
}

void
v2v_nc2_cancel_fast_receive(struct v2v_channel *channel)
{
    channel->nc2_rings.local_endpoint->consumer_active = 0;
}

BOOL
v2v_nc2_remote_requested_fast_wakeup(struct v2v_channel *channel)
{
    if (channel->nc2_rings.remote_endpoint->consumer_active)
        return TRUE;
    else
        return FALSE;
}

