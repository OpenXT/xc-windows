/*
 * Copyright (c) 2010 Citrix Systems, Inc.
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

#include <stdlib.h>
#include "ntddk.h"
#include "ntddstor.h"
#pragma warning (push, 3)
#include "srb.h"
#include "classpnp.h"
#pragma warning (pop)
#include "xsapi.h"
#include "scsiboot.h"
#include "scsifilt.h"

/* Find the path to the backend associated with @sf.  The backend path
   remains correct as long as @token remains extant.  The caller must
   XmFreeMemory() the returned string.  Returns NULL on error. */
static char *
get_backend_path(struct scsifilt *sf, SUSPEND_TOKEN token)
{
    char *res;
    char *res_nul;
    NTSTATUS stat;
    size_t s;

    UNREFERENCED_PARAMETER(token);

    stat = xenbus_read_bin(XBT_NIL, sf->frontend_path, "backend",
                           &res, &s);
    if (!NT_SUCCESS(stat)) {
        TraceWarning(("%x reading backend path.\n", stat));
        return NULL;
    }
    res_nul = XmAllocateMemory(s + 1);
    if (!res_nul) {
        TraceWarning(("Can't get %d bytes for backend path\n", s));
        XmFreeMemory(res);
        return NULL;
    }
    memcpy(res_nul, res, s);
    res_nul[s] = 0;
    XmFreeMemory(res);
    return res_nul;
}

static void
ungrant_ring(struct scsifilt *sf)
{
    int i;

    for (i = 0; i < (1 << sf->ring_order); i++) {
        if (!is_null_GRANT_REF(sf->ring_gref[i])) {
            (VOID) GnttabEndForeignAccessCache(sf->ring_gref[i], sf->grant_cache);
            sf->ring_gref[i] = null_GRANT_REF();
        }
    }
}

static PFN_NUMBER
virt_to_pfn(void *va)
{
    PHYSICAL_ADDRESS pa;

    pa = MmGetPhysicalAddress(va);
    return (ULONG_PTR)(pa.QuadPart >> 12);
}

static void
grant_ring(struct scsifilt *sf)
{
    DOMAIN_ID domid = sf->backend_domid;
    ULONG_PTR frame;
    int i;

    ungrant_ring(sf);

    for (i = 0; i < (1 << sf->ring_order); i++) {
        frame = virt_to_pfn((void*) ((ULONG_PTR)sf->ring_shared + 
                                     (ULONG_PTR)((i)*PAGE_SIZE)));
        sf->ring_gref[i] = GnttabGrantForeignAccessCache(domid,
                                                         frame,
                                                         GRANT_MODE_RW,
                                                         sf->grant_cache);

        /* Because the grant cache always contains enough grefs to cover
           the ring itself. */
        XM_ASSERT(!is_null_GRANT_REF(sf->ring_gref[i]));
    }
}

static void
close_evtchn(struct scsifilt *sf)
{
    if (!is_null_EVTCHN_PORT(sf->evtchn_port))
        EvtchnClose(sf->evtchn_port);
    sf->evtchn_port = null_EVTCHN_PORT();
}

static NTSTATUS
open_evtchn(struct scsifilt *sf)
{
    DOMAIN_ID domid = sf->backend_domid;

    close_evtchn(sf);
    sf->evtchn_port = EvtchnAllocUnbound(domid, handle_evtchn, sf);
    if (is_null_EVTCHN_PORT(sf->evtchn_port))
        return STATUS_INSUFFICIENT_RESOURCES;
    else
        return STATUS_SUCCESS;
}

static XENBUS_STATE
get_fe_state(xenbus_transaction_t xbt, struct scsifilt *sf)
{
    NTSTATUS status;
    XENBUS_STATE res;

    status = xenbus_read_state(xbt, sf->frontend_path, "state", &res);
    if (NT_SUCCESS(status))
        return res;
    else
        return null_XENBUS_STATE();
}

/* Set the frontend to state @state.  The frontend may be in CLOSED to
   begin with, so there's a risk that the tools might try to tear it
   down.  Make sure that we don't race and bring it back to life by
   mistake. */
/* Returns STATUS_SUCCESS on success, STATUS_OBJECT_NAME_NOT_FOUND if
   we race, or some other STATUS_ on error. */
static NTSTATUS
set_fe_state_careful(struct scsifilt *sf, XENBUS_STATE state)
{
    return xenbus_change_state(XBT_NIL, sf->frontend_path, "state", state);
}

/* Parse sf->frontend_path and use it to set sf->handle. */
static void
find_backend_handle(struct scsifilt *sf)
{
    sf->handle = (USHORT)atoi(strrchr(sf->frontend_path, '/') + 1);
}

/* similar to xenvbd:ProbeBackendCapabiities() */
static void
probe_backend_capabilities(struct scsifilt *sf)
{
    NTSTATUS status;
    ULONG64 order;

    status = xenbus_read_domain_id(XBT_NIL, sf->frontend_path,
                                   "backend-id", &sf->backend_domid);
    if (!NT_SUCCESS(status)) {
        TraceError(("Failed to read backend id from %s (%x)\n",
                    sf->frontend_path, status));
        sf->backend_domid = DOMAIN_ID_0();
    }

    /* check to see if we used a multi-page handshake previously */
    status = xenbus_read_int(XBT_NIL, sf->frontend_path, "ring-page-order",
                             &order);
    if (NT_SUCCESS(status)) {
        XM_ASSERT3U(order, <=, MAX_RING_PAGE_ORDER);

        sf->single_page = FALSE;
        sf->ring_order = (ULONG)order;

        return;
    }

    /* assume single page handshake */
    sf->single_page = TRUE;
    sf->ring_order = 0;

    status = xenbus_read_int(XBT_NIL, sf->backend_path, "max-ring-page-order",
                             &order);
    if (NT_SUCCESS(status)) {
        if (order > MAX_RING_PAGE_ORDER)
            order = MAX_RING_PAGE_ORDER;

        sf->single_page = FALSE;
        sf->ring_order = (ULONG)order;
    }

    TraceInfo(("Using %u sring page(s).\n", 1 << sf->ring_order));
}

static NTSTATUS
get_backend_info(struct scsifilt *sf)
{
    NTSTATUS status;
    ULONG64 tmp;

    status = xenbus_read_int(XBT_NIL, sf->backend_path, "info",
                             &tmp);
    if (!NT_SUCCESS(status))
        return status;

    XM_ASSERT(sf->set_target_info != NULL);
    sf->set_target_info(sf->target_id, (ULONG)tmp);

    status = xenbus_read_int(XBT_NIL, sf->backend_path, "sector-size",
                             &tmp);
    if (!NT_SUCCESS(status))
        return status;

    sf->sector_size = (ULONG)tmp;

    return STATUS_SUCCESS;
}

static VOID
close_frontend(struct scsifilt *sf, SUSPEND_TOKEN token)
{
    XENBUS_STATE frontend_state;
    XENBUS_STATE backend_state;
    NTSTATUS status;

    TraceNotice(("target %d: closing frontend...\n", sf->target_id));

    // Get initial frontend state
    status = xenbus_read_state(XBT_NIL, sf->frontend_path, "state", &frontend_state);
    if (!NT_SUCCESS(status))
        frontend_state = null_XENBUS_STATE();

    // Wait for the backend to stabilise
    backend_state = null_XENBUS_STATE();
    do {
        backend_state = XenbusWaitForBackendStateChange(sf->backend_path, backend_state,
                                                        NULL, token);
    } while (same_XENBUS_STATE(backend_state, XENBUS_STATE_INITIALISING));

    TraceVerbose(("%s: target %d: backend state = %s, frontend state = %s\n",
                  __FUNCTION__, sf->target_id,
                  XenbusStateName(backend_state),
                  XenbusStateName(frontend_state)));

    frontend_state = XENBUS_STATE_CLOSING;
    while (!same_XENBUS_STATE(backend_state, XENBUS_STATE_CLOSING) &&
           !same_XENBUS_STATE(backend_state, XENBUS_STATE_CLOSED) &&
           !is_null_XENBUS_STATE(backend_state)) {
        xenbus_change_state(XBT_NIL, sf->frontend_path, "state", frontend_state);
        backend_state = XenbusWaitForBackendStateChange(sf->backend_path, backend_state,
                                                        NULL, token);
    }

    TraceVerbose(("%s: target %d: backend state = %s, frontend state = %s\n",
                  __FUNCTION__, sf->target_id,
                  XenbusStateName(backend_state),
                  XenbusStateName(frontend_state)));

    frontend_state = XENBUS_STATE_CLOSED;
    while (!same_XENBUS_STATE(backend_state, XENBUS_STATE_CLOSED) &&
           !is_null_XENBUS_STATE(backend_state)) {
        xenbus_change_state(XBT_NIL, sf->frontend_path, "state", frontend_state);
        backend_state = XenbusWaitForBackendStateChange(sf->backend_path, backend_state,
                                                        NULL, token);
    }

    TraceVerbose(("%s: target %d: backend state = %s, frontend state = %s\n",
                  __FUNCTION__, sf->target_id,
                  XenbusStateName(backend_state),
                  XenbusStateName(frontend_state)));

    TraceNotice(("target %d: backend closed\n", sf->target_id));
}

/* We've bound the scsifilt instance to a xenvbd instance, and we've
   disconnected xenvbd from the shared ring.  Connect scsifilt. */
NTSTATUS
connect_scsifilt_with_token(struct scsifilt *sf, SUSPEND_TOKEN token)
{
    XENBUS_STATE state;
    blkif_sring_t *ring_shared;
    NTSTATUS status;
    KIRQL irql;

    if (sf->backend_path != NULL) {
        TraceVerbose(("Releasing old backend path (%p)\n", sf->backend_path));

        XmFreeMemory(sf->backend_path);
        sf->backend_path = NULL;
    }

    if (sf->ring_shared != NULL) {
        TraceVerbose(("Releasing old shared ring (%p)\n", sf->ring_shared));

        XmFreeMemory(sf->ring_shared);
        sf->ring_shared = NULL;
        sf->ring.sring = NULL;
    }

    find_backend_handle(sf);

    status = STATUS_UNSUCCESSFUL;
    sf->backend_path = get_backend_path(sf, token);
    if (sf->backend_path == NULL)
        goto fail1;

    sf->target_resume(sf->target_id, token);

    if (sf->stopped) {
        sf->target_start(sf->target_id, sf->backend_path, token);
        sf->stopped = FALSE;
    }

    state = XenbusWaitForBackendStateChange(sf->backend_path,
                                            null_XENBUS_STATE(),
                                            NULL,
                                            token);
    if (!same_XENBUS_STATE(state, XENBUS_STATE_INITWAIT))
        goto fail2;

    probe_backend_capabilities(sf);

    status = STATUS_NO_MEMORY;
    ring_shared = XmAllocateZeroedMemory(PAGE_SIZE << sf->ring_order);
    if (ring_shared == NULL)
        goto fail3;

    KeAcquireSpinLock(&sf->ring_lock, &irql);
    sf->ring_shared = ring_shared;
    SHARED_RING_INIT(sf->ring_shared);
    FRONT_RING_INIT(&sf->ring, sf->ring_shared, PAGE_SIZE << sf->ring_order);
    KeReleaseSpinLock(&sf->ring_lock, irql);

    grant_ring(sf);

    status = open_evtchn(sf);
    if (!NT_SUCCESS(status))
        goto fail4;

    do {
        xenbus_transaction_t xbt;

        xenbus_transaction_start(&xbt);

        xenbus_write_evtchn_port(xbt,
                                 sf->frontend_path,
                                 "event-channel",
                                 sf->evtchn_port);

        if (sf->single_page) {
            XM_ASSERT3U(sf->ring_order, ==, 0);

            TraceNotice(("%s: using single page handshake\n", sf->frontend_path));

            /* single page handshake */
            xenbus_write_grant_ref(xbt,
                                   sf->frontend_path,
                                   "ring-ref",
                                   sf->ring_gref[0]);
        } else {
            int i;

            TraceNotice(("%s: using multi-page handshake\n", sf->frontend_path));

            xenbus_printf(xbt, sf->frontend_path, "ring-page-order", "%u",
                          sf->ring_order);

            for (i = 0; i < (1 << sf->ring_order); i++) {
                char buffer[10];

                Xmsnprintf(buffer, sizeof(buffer), "ring-ref%1u", i);
                xenbus_write_grant_ref(xbt, sf->frontend_path, buffer,
                                       sf->ring_gref[i]);
            }
        }

        xenbus_printf(xbt, sf->frontend_path, "protocol", "x86_32-abi");
        xenbus_write_feature_flag(xbt, sf->frontend_path, "feature-surprise-remove",
                                  TRUE);
        xenbus_write_feature_flag(xbt, sf->frontend_path, "feature-online-resize",
                                  TRUE);
        xenbus_change_state(xbt, sf->frontend_path, "state",
                            XENBUS_STATE_INITIALISED);

        status = xenbus_transaction_end(xbt, 0);
    } while (status == STATUS_RETRY);

    if (!NT_SUCCESS(status))
        goto fail5;

    /* wait for backend to become connected */
    state = null_XENBUS_STATE();
    do {
        state = XenbusWaitForBackendStateChange(sf->backend_path,
                                                state,
                                                NULL,
                                                token);
    } while (same_XENBUS_STATE(state, XENBUS_STATE_INITWAIT) ||
             same_XENBUS_STATE(state, XENBUS_STATE_INITIALISING) ||
             same_XENBUS_STATE(state, XENBUS_STATE_INITIALISED));

    status = STATUS_UNSUCCESSFUL;
    if (!same_XENBUS_STATE(state, XENBUS_STATE_CONNECTED)) {
        TraceError(("%s: backend state is %s (expected CONNECTED)\n",
                    __FUNCTION__, XenbusStateName(state)));
        goto fail6;
    }

    xenbus_change_state(XBT_NIL, sf->frontend_path, "state",
                        XENBUS_STATE_CONNECTED);

    TraceInfo(("target %d: connected to %s\n", sf->target_id, sf->backend_path));

    status = get_backend_info(sf);
    if (!NT_SUCCESS(status))
        goto fail7;

    replay_pending_requests(sf);
    XM_ASSERT3U(sf->nr_inflight, ==, 0);

    return STATUS_SUCCESS;

fail7:
    TraceError(("%s: fail7\n", __FUNCTION__));

fail6:
    TraceError(("%s: fail6\n", __FUNCTION__));

fail5:
    TraceError(("%s: fail5\n", __FUNCTION__));

    close_frontend(sf, token);

fail4:
    TraceError(("%s: fail4\n", __FUNCTION__));

    close_evtchn(sf);

    ungrant_ring(sf);

    KeAcquireSpinLock(&sf->ring_lock, &irql);
    XM_ASSERT(sf->ring_shared != NULL);
    sf->ring_shared = NULL;
    KeReleaseSpinLock(&sf->ring_lock, irql);

    XmFreeMemory(ring_shared);

fail3:
    TraceError(("%s: fail3\n", __FUNCTION__));

fail2:
    TraceError(("%s: fail2\n", __FUNCTION__));

    XmFreeMemory(sf->backend_path);
    sf->backend_path = NULL;

fail1:
    TraceError(("%s: fail1 (%08x)\n", __FUNCTION__, status));

    return status;
}

NTSTATUS
connect_scsifilt(struct scsifilt *sf)
{
    SUSPEND_TOKEN token;
    NTSTATUS status;

    token = EvtchnAllocateSuspendToken("connect_scsifilt");
    status = connect_scsifilt_with_token(sf, token);
    EvtchnReleaseSuspendToken(token);
    return status;
}

/* Note that it is possible for a call to early_suspend_cb() to not be
   followed by a matching call to late_suspend_cb() if we destroy the
   device before the late callback can run. */
static VOID
early_suspend_cb(void *ctxt, SUSPEND_TOKEN token)
{
    struct scsifilt *const sf = ctxt;

    UNREFERENCED_PARAMETER(token);

    /* No need to lock since we're at high IRQL here */

    /* Stop any more requests getting dropped on the ring. */
    sf->pause_count++;
    /* Stop wakeup IOCTLs until we're fully resumed */
    sf->suspended = TRUE;

    /* And get all of the currently in-flight requests to be replayed
     * later. */
    XmListSplice(&sf->requests_needing_replay, &sf->inflight_requests);
    InitializeListHead(&sf->inflight_requests);
    sf->nr_replay_outstanding += sf->nr_inflight;
    sf->nr_inflight = 0;

    /* Make sure connect_scsifilt() notices that the backend domain ID
       may have changed. */
    sf->backend_domid = null_DOMAIN_ID();
}

static void
late_suspend_cb(void *ctxt, SUSPEND_TOKEN token)
{
    struct scsifilt *const sf = ctxt;
    NTSTATUS status;

    if (sf->current_power_state != PowerDeviceD0)
        goto done;

    /* Reconnect to the backend */
    status = connect_scsifilt_with_token(sf, token);
    if (!NT_SUCCESS(status)) {
        TraceError(("Failed to reconnect device %s after migration!\n",
                    sf->frontend_path));
        return;
    }

done:
    /* And start everything going again. */
    sf->suspended = FALSE;
    unpause_datapath(sf);

    TraceNotice(("%s recovered from migration.\n", sf->frontend_path));
}

/* Undo the effects of initialise_xenvbd_bits() */
void
cleanup_xenvbd_bits(struct scsifilt *sf)
{
    if (sf->late_suspend_handler)
        EvtchnUnregisterSuspendHandler(sf->late_suspend_handler);
    sf->late_suspend_handler = NULL;
    if (sf->early_suspend_handler)
        EvtchnUnregisterSuspendHandler(sf->early_suspend_handler);
    sf->early_suspend_handler = NULL;

    if (sf->grant_cache) {
        if (is_null_GRANT_REF(sf->ring_gref[0]))
            GnttabFreeCache(sf->grant_cache);
        else
            TraceWarning(("Leaking grant cache.\n"));
        sf->grant_cache = NULL;
    }
}

NTSTATUS
initialise_xenvbd_bits(struct scsifilt *sf)
{
    sf->grant_cache =
        GnttabAllocCache(BLKIF_MAX_SEGMENTS_PER_REQUEST + MAX_RING_PAGES);
    if (!sf->grant_cache)
        return STATUS_INSUFFICIENT_RESOURCES;

    sf->early_suspend_handler =
        EvtchnRegisterSuspendHandler(early_suspend_cb,
                                     sf,
                                     "scsifilt::early_suspend_cb",
                                     SUSPEND_CB_EARLY);
    if (!sf->early_suspend_handler)
        return STATUS_INSUFFICIENT_RESOURCES;
    sf->late_suspend_handler =
        EvtchnRegisterSuspendHandler(late_suspend_cb,
                                     sf,
                                     "scsifilt::late_suspend_cb",
                                     SUSPEND_CB_LATE);
    if (!sf->late_suspend_handler)
        return STATUS_INSUFFICIENT_RESOURCES;

    KeInitializeSpinLock(&sf->ring_lock);
    KeInitializeDpc(&sf->dpc, handle_dpc, sf);
    initialise_schedule(&sf->schedule);
    InitializeListHead(&sf->inflight_requests);
    return STATUS_SUCCESS;
}

/* Make the backend disconnect from the rings.  The caller is expected
   to have already mande sure there are no requests outstanding. */
void
close_scsifilt(struct scsifilt *sf)
{
    blkif_sring_t *ring_shared = sf->ring_shared;
    SUSPEND_TOKEN token;
    KIRQL irql;

    if (!sf->frontend_path) {
        TraceWarning(("Asked to stop a non-started scsifilt?\n"));
        return;
    }

    token = EvtchnAllocateSuspendToken("close_scsifilt");

    if (sf->backend_path == NULL) {
        sf->backend_path = get_backend_path(sf, token);
        if (sf->backend_path == NULL) {
            TraceError(("No backend path connecting %s.\n", sf->frontend_path));
            EvtchnReleaseSuspendToken(token);
            return;
        }
    }

    close_frontend(sf, token);

    close_evtchn(sf);
    ungrant_ring(sf);

    KeAcquireSpinLock(&sf->ring_lock, &irql);
    sf->ring_shared = NULL;
    KeReleaseSpinLock(&sf->ring_lock, irql);

    if (ring_shared != NULL)
        XmFreeMemory(ring_shared);

    XmFreeMemory(sf->backend_path);
    sf->backend_path = NULL;

    EvtchnReleaseSuspendToken(token);

    return;
}

static ULONG
bswab32(ULONG in)
{
    return (in << 24) |
        ((in & 0xff00) << 8) |
        ((in & 0xff0000) >> 8) |
        (in >> 24);
}

static ULONG64
bswab64(ULONG64 in)
{
    return ((ULONG64)bswab32((ULONG)in)) << 32 |
        bswab32((ULONG)(in >> 32));
}

static NTSTATUS
get_nr_sectors(struct scsifilt *sf, ULONG64 *res)
{
    SUSPEND_TOKEN token;
    char *backend;
    NTSTATUS status;

    token = EvtchnAllocateSuspendToken("filter_process_capacity_irp");
    backend = get_backend_path(sf, token);
    if (!backend) {
        TraceError(("Can't find backend path for capacity IRP.\n"));
        EvtchnReleaseSuspendToken(token);
        return (ULONG64)-1;
    }
    status = xenbus_read_int(XBT_NIL, backend, "sectors", res);
    XmFreeMemory(backend);
    EvtchnReleaseSuspendToken(token);

    return status;
}

NTSTATUS
filter_process_capacity_irp(struct scsifilt *sf, PIRP irp,
                            PSCSI_REQUEST_BLOCK srb)
{
    READ_CAPACITY_DATA *outbuf;
    ULONG last_block;
    ULONG64 nr_sectors;
    NTSTATUS status;

    /* During resume from S4 it seems these can be called at DISPATCH_LEVEL
       in a DPC. None of this code can handle that. */
    if (KeGetCurrentIrql() > APC_LEVEL) {
        srb->SrbStatus = SRB_STATUS_INTERNAL_ERROR;
        return complete_irp(irp, STATUS_UNSUCCESSFUL);
    }

    outbuf = map_srb_data_buffer(srb, irp->MdlAddress, NormalPagePriority);
    if (outbuf == NULL) {
        srb->SrbStatus = SRB_STATUS_INTERNAL_ERROR;
        return complete_irp(irp, STATUS_INSUFFICIENT_RESOURCES);
    }

    status = get_nr_sectors(sf, &nr_sectors);
    if (!NT_SUCCESS(status))
        return complete_irp(irp, status);

    if (nr_sectors == (ULONG)nr_sectors)
        last_block = (ULONG)nr_sectors - 1;
    else
        last_block = ~(ULONG)0;

    outbuf->LogicalBlockAddress = bswab32(last_block);
    outbuf->BytesPerBlock = bswab32(sf->sector_size);

    srb->SrbStatus = SRB_STATUS_SUCCESS;
    srb->ScsiStatus = 0;
    irp->IoStatus.Information = sizeof(*outbuf);
    return complete_irp(irp, STATUS_SUCCESS);
}

NTSTATUS
filter_process_capacity_ex_irp(struct scsifilt *sf, PIRP irp,
                               PSCSI_REQUEST_BLOCK srb)
{
    READ_CAPACITY_DATA_EX *outbuf;
    ULONG64 nr_sectors;
    NTSTATUS status;

    /* During resume from S4 it seems these can be called at DISPATCH_LEVEL
       in a DPC. None of this code can handle that. */
    if (KeGetCurrentIrql() > APC_LEVEL) {
        srb->SrbStatus = SRB_STATUS_INTERNAL_ERROR;
        return complete_irp(irp, STATUS_UNSUCCESSFUL);
    }

    outbuf = map_srb_data_buffer(srb, irp->MdlAddress, NormalPagePriority);
    if (outbuf == NULL) {
        srb->SrbStatus = SRB_STATUS_INTERNAL_ERROR;
        return complete_irp(irp, STATUS_INSUFFICIENT_RESOURCES);
    }

    status = get_nr_sectors(sf, &nr_sectors);
    if (!NT_SUCCESS(status))
        return complete_irp(irp, status);

    outbuf->LogicalBlockAddress.QuadPart = bswab64(nr_sectors - 1);
    outbuf->BytesPerBlock = bswab32(sf->sector_size);

    srb->SrbStatus = SRB_STATUS_SUCCESS;
    srb->ScsiStatus = 0;
    irp->IoStatus.Information = sizeof(*outbuf);
    return complete_irp(irp, STATUS_SUCCESS);
}

void
filter_wait_for_idle(struct scsifilt *sf)
{
    LARGE_INTEGER interval;

    if (sf->cur_outstanding == 0)
        return;
    TraceNotice(("%s: Waiting for %d requests to complete so that we can shut down...\n",
                 sf->frontend_path, sf->cur_outstanding));
    while (sf->cur_outstanding != 0) {
        interval.QuadPart = -100000000;
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        if (sf->cur_outstanding)
            TraceWarning(("Taking a long time to stop %s (%d left)\n",
                          sf->frontend_path, sf->cur_outstanding));
    }
}
