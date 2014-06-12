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

#include "ntddk.h"
#include "ntddstor.h"
#pragma warning (push, 3)
#include "srb.h"
#include "classpnp.h"
#pragma warning (pop)
#include "xsapi.h"
#include "scsiboot.h"
#include "scsifilt.h"

#include "scsifilt_wpp.h"
#include "rings.tmh"

#define wmb() XsMemoryBarrier()
#define mb() XsMemoryBarrier()

static void
dump_scsifilt_request(struct scsifilt_request *sfr)
{
    unsigned x;

    TraceNotice(("Operation %d, count %d, sect %I64x\n",
                 sfr->operation,
                 sfr->nr_segments,
                 sfr->start_sector));
    for (x = 0; x < sfr->nr_segments; x++)
        TraceNotice(("\t%x\t%x.%d.%d\n", x,
                     sfr->fragments[x].pfn,
                     sfr->fragments[x].start_sect,
                     sfr->fragments[x].last_sect));
}

static void
ungrant_request(struct scsifilt *sf, struct scsifilt_request *sfr)
{
    unsigned x;
    NTSTATUS status;

    for (x = 0; x < sfr->nr_segments; x++) {
        status = GnttabEndForeignAccessCache(sfr->fragments[x].gref,
                                             sf->grant_cache);
        XM_ASSERT(NT_SUCCESS(status));
    }
}

static NTSTATUS
prepare_request(struct scsifilt *sf, struct scsifilt_request *sfr)
{
    unsigned x;
    GRANT_MODE mode;
    NTSTATUS status;

    if (sfr->operation == BLKIF_OP_READ)
        mode = GRANT_MODE_RW;
    else
        mode = GRANT_MODE_RO;

    /* We don't need a token for backend_domid because we're at
       DISPATCH_LEVEL */
    for (x = 0; x < sfr->nr_segments; x++) {
        sfr->fragments[x].gref =
            GnttabGrantForeignAccessCache(sf->backend_domid,
                                          sfr->fragments[x].pfn,
                                          mode,
                                          sf->grant_cache);
        if (is_null_GRANT_REF(sfr->fragments[x].gref))
            goto no_grefs;
    }
    return STATUS_SUCCESS;

no_grefs:
    while (x > 0) {
        x--;
        status = GnttabEndForeignAccessCache(sfr->fragments[x].gref,
                                             sf->grant_cache);
        XM_ASSERT(NT_SUCCESS(status));
    }
    return STATUS_DEVICE_BUSY;
}

static void
copy_request_to_ring(struct scsifilt *sf, struct scsifilt_request *sfr)
{
    blkif_request_t *ring_req;
    unsigned x;
    unsigned nr_sectors;

    sfr->submitted_to_backend = __rdtsc();

    ring_req = RING_GET_REQUEST(&sf->ring, sf->ring.req_prod_pvt);
    ring_req->operation = sfr->operation;
    ring_req->nr_segments = sfr->nr_segments;
    ring_req->handle = sf->handle;
    ring_req->id = (uint64_t)(ULONG_PTR)sfr;
    ring_req->sector_number = sfr->start_sector;
    nr_sectors = 0;
    for (x = 0; x < sfr->nr_segments; x++) {
        ring_req->seg[x].gref = xen_GRANT_REF(sfr->fragments[x].gref);
        ring_req->seg[x].first_sect = sfr->fragments[x].start_sect;
        ring_req->seg[x].last_sect = sfr->fragments[x].last_sect;
        nr_sectors +=
            ring_req->seg[x].last_sect - ring_req->seg[x].first_sect;
    }
    nr_sectors += sfr->nr_segments;
    sf->ring.req_prod_pvt = RING_IDX_PLUS(sf->ring.req_prod_pvt, 1);

    if (sfr->start_sector != sf->seek_free_sector_nr)
        sf->nr_seeks++;
    sf->seek_free_sector_nr = sfr->start_sector + nr_sectors;
    sf->nr_sectors_transferred += nr_sectors;

    DoTraceMessage(FLAG_LOWER_EDGE,
                   "%s %p on ring, start %I64d, operation %d, nr_sectors %d",
                   sf->frontend_path, sfr, sfr->start_sector,
                   sfr->operation, nr_sectors);
}

static NTSTATUS
start_this_request(struct scsifilt *sf,
                   struct scsifilt_request *sfr)
{
    NTSTATUS status;

    XM_ASSERT3U(sfr->state, ==, SfrStateQueued);

    status = prepare_request(sf, sfr);
    if (!NT_SUCCESS(status))
        return status;

    RemoveEntryList(&sfr->list);
    sf->schedule.nr_scheduled--;
    copy_request_to_ring(sf, sfr);
    InsertTailList(&sf->inflight_requests, &sfr->list);
    sf->nr_inflight++;

    sfr->state = SfrStateSubmitted;

    return STATUS_SUCCESS;
}

void
handle_dpc(PKDPC dpc, void *ctxt, void *ignore1, void *ignore2)
{
    struct scsifilt *const sf = ctxt;
    LIST_ENTRY completed_requests;
    KIRQL irql;
    int notify;
    int not_done;
    RING_IDX prod;
    struct scsifilt_request *sfr;
    blkif_response_t *resp;

    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(ignore1);
    UNREFERENCED_PARAMETER(ignore2);

    XM_ASSERT3U(sf->magic, ==, SCSIFILT_MAGIC);

    DoTraceMessage(FLAG_LOWER_EDGE, "%s DPC", sf->frontend_path);

    InitializeListHead(&completed_requests);
    KeAcquireSpinLock(&sf->ring_lock, &irql);

    if (sf->ring_shared == NULL) {
        TraceWarning(("handle_dpc before ring is allocated?\n"));
        KeReleaseSpinLock(&sf->ring_lock, irql);
        return;
    }

    if (sf->pause_count != 0) {
        TraceWarning(("handle_dpc while paused (%d), %d outstanding?\n",
                      sf->pause_count, sf->nr_inflight));
        if (sf->nr_inflight == 0) {
            KeReleaseSpinLock(&sf->ring_lock, irql);
            return;
        }
    }

    notify = 0;
top:
    prod = sf->ring_shared->rsp_prod;
    XsMemoryBarrier();
    while (!RING_IDXS_EQ(sf->ring.rsp_cons, prod)) {
        resp = RING_GET_RESPONSE(&sf->ring, sf->ring.rsp_cons);
        sfr = (struct scsifilt_request *)(ULONG_PTR)resp->id;

        XM_ASSERT3U(sfr->state, ==, SfrStateSubmitted);

        sfr->returned_by_backend = __rdtsc();

        DoTraceMessage(FLAG_LOWER_EDGE, "%s backend completed %p",
                       sf->frontend_path, sfr);

        /* Revoke backend access to the buffers */
        ungrant_request(sf, sfr);

        if (resp->status != BLKIF_RSP_OKAY) {
            TraceNotice(("Failed a request to %s with status %d!\n",
                         sf->frontend_path, resp->status));
            dump_scsifilt_request(sfr);
        }
        sfr->result = resp->status;

        /* We're finished with this request */
        sf->ring.rsp_cons = RING_IDX_PLUS(sf->ring.rsp_cons, 1);

        /* Move the request to the completed list. */
        RemoveEntryList(&sfr->list);
        InsertTailList(&completed_requests, &sfr->list);

        sf->nr_inflight--;

        sfr->state = SfrStateProcessed;

        /* Push the next request on the ring, if we have one. */
        sfr = get_next_request(&sf->schedule);
        if (sfr != NULL) {
            int _notify;
            NTSTATUS status;

            status = start_this_request(sf, sfr);
            if (NT_SUCCESS(status)) {
                RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&sf->ring, _notify);
                notify |= _notify;
            }
        }
    }
    RING_FINAL_CHECK_FOR_RESPONSES(&sf->ring, not_done);
    if (not_done)
        goto top;

    KeReleaseSpinLock(&sf->ring_lock, irql);

    /* If we sent the backend more requests, it may need a kick to
       start processing them. */
    if (notify) {
        sf->last_notify_prod = sf->ring_shared->req_prod;
        EvtchnNotifyRemote(sf->evtchn_port);
        DoTraceMessage(FLAG_LOWER_EDGE, "%s notify backend",
                       sf->frontend_path);
    }

    /* Tell scsifilt proper that it's got some more requests to complete. */
    if (!IsListEmpty(&completed_requests))
        finish_requests(sf, &completed_requests);
}

void
handle_evtchn(void *ctxt)
{
    struct scsifilt *const sf = ctxt;

    XM_ASSERT3U(sf->magic, ==, SCSIFILT_MAGIC);

    KeInsertQueueDpc(&sf->dpc, NULL, NULL);
    DoTraceMessage(FLAG_LOWER_EDGE, "%s event channel", sf->frontend_path);
}

static void
start_requests(struct scsifilt *sf)
{
    struct scsifilt_request *sfr;
    int notify;
    NTSTATUS status;

    if (sf->pause_count != 0) {
        TraceVerbose(("datapath paused (%d)\n", sf->pause_count));

        if (sf->shutdown_type == PowerActionNone &&
            !sf->suspended)
            wakeup_scsiport(sf, __FUNCTION__);

        return;
    }

    if (sf->ring_shared == NULL) {
        TraceError(("ring has not been allocated\n"));
        return;
    }

    while (!RING_FULL(&sf->ring)) {
        sfr = get_next_request(&sf->schedule);
        if (sfr == NULL)
            break;
        status = start_this_request(sf, sfr);
        if (!NT_SUCCESS(status))
            break;
    }
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&sf->ring, notify);
    if (notify) {
        sf->last_notify_prod = sf->ring_shared->req_prod;
        EvtchnNotifyRemote(sf->evtchn_port);
        DoTraceMessage(FLAG_LOWER_EDGE, "%s notify backend",
                       sf->frontend_path);
    }
}

void
schedule_requests(struct scsifilt *sf, PLIST_ENTRY requests)
{
    KIRQL irql;
    struct scsifilt_request *sfr;
    PLIST_ENTRY le;
    PLIST_ENTRY next_le;

    KeAcquireSpinLock(&sf->ring_lock, &irql);
    for (le = requests->Flink; le != requests; le = next_le) {
        next_le = le->Flink;
        sfr = CONTAINING_RECORD(le, struct scsifilt_request, list);
        XM_ASSERT3U(sfr->state, ==, SfrStateInitialised);
        enqueue_request(&sf->schedule, sfr);
    }
    start_requests(sf);
    KeReleaseSpinLock(&sf->ring_lock, irql);
}

void
pause_datapath(struct scsifilt *sf)
{
    KIRQL irql;
    LARGE_INTEGER interval;

    XM_ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    KeAcquireSpinLock(&sf->ring_lock, &irql);
    sf->pause_count++;

    TraceVerbose(("target %d: pausing datapath\n", sf->target_id, sf->pause_count));

    XM_ASSERT(sf->pause_count == 1 || sf->nr_inflight == 0);
    while (sf->nr_inflight != 0) {
        KeReleaseSpinLock(&sf->ring_lock, irql);
        interval.QuadPart = -10000000;
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        KeAcquireSpinLock(&sf->ring_lock, &irql);
        if (sf->nr_inflight)
            TraceWarning(("Having trouble pausing scsifilt, %d left.\n",
                          sf->nr_inflight));
    }
    KeReleaseSpinLock(&sf->ring_lock, irql);
}

void
unpause_datapath(struct scsifilt *sf)
{
    KIRQL irql;

    KeAcquireSpinLock(&sf->ring_lock, &irql);
    sf->pause_count--;

    TraceVerbose(("target %d: unpaused datapath (%d)\n", sf->target_id, sf->pause_count));

    if (sf->pause_count == 0)
        start_requests(sf);
    KeReleaseSpinLock(&sf->ring_lock, irql);
}

/* Ick... when we're hibernating, the power-down request comes in
 * *before* Windows has finished writing to the disk, and so we pretty
 * much just ignore the request.  This means that when we come back
 * from hibernate, we have somewhat inconsistent state.  Fix
 * everything up. */
/* This is kind-of equivalent to a pause_datapath(), except that we
 * think we've sent some requests which won't actually have made it to
 * the backend.  We also record that the backend domain ID may have
 * changed, so that connect_scsifilt() actually connects to the right
 * one. */
void
datapath_notice_dehibernated(struct scsifilt *sf)
{
    KIRQL irql;
    LIST_ENTRY requests_needing_replay;
    unsigned expected_nr_inflight;

    KeAcquireSpinLock(&sf->ring_lock, &irql);

    /* Make sure we don't send any more requests until we're properly
       connected. */
    sf->pause_count++;

    /* Requests which we believe are inflight really aren't. */
    XmListTransplant(&requests_needing_replay, &sf->inflight_requests);
    expected_nr_inflight = sf->nr_inflight;
    sf->nr_inflight = 0;

    KeReleaseSpinLock(&sf->ring_lock, irql);

    /* Schedule the requests for replay at some later stage. */
    KeAcquireSpinLock(&sf->request_replay_lock, &irql);
    XmListSplice(&sf->requests_needing_replay, &requests_needing_replay);
    sf->nr_replay_outstanding += expected_nr_inflight;
    KeReleaseSpinLock(&sf->request_replay_lock, irql);

    TraceNotice(("Bounced %d requests to needing_replay.\n",
                 expected_nr_inflight));

    KeRaiseIrql(DISPATCH_LEVEL, &irql);
    /* Hackity hack: this is enough to make connect_scsifilt() realise
       we've lost our grant references and evetn channel ports, and
       reconnect them for us. */
    /* (We assume that somebody else is going to take responsibility
       for actually making sure that connect_scsifilt() gets
       called) */
    /* We rely on being at DISPATCH_LEVEL to synchronise this for us.
       We only need to synchronise against suspend handlers, and they
       can't run unless every CPU is at PASSIVE. */
    sf->backend_domid = null_DOMAIN_ID();
    KeLowerIrql(irql);
}

void
replay_pending_requests(struct scsifilt *sf)
{
    KIRQL irql;
    PLIST_ENTRY ple;
    PLIST_ENTRY next_ple;
    struct scsifilt_request *sfr;
    LIST_ENTRY requests_needing_replay;
    unsigned expected_nr_replay;

    /* Grab the need-replay list from @sf */
    KeAcquireSpinLock(&sf->request_replay_lock, &irql);
    XmListTransplant(&requests_needing_replay, &sf->requests_needing_replay);
    expected_nr_replay = sf->nr_replay_outstanding;
    sf->nr_replay_outstanding = 0;
    KeReleaseSpinLock(&sf->request_replay_lock, irql);

    TraceNotice(("Replaying %d requests.\n", expected_nr_replay));

    /* Replay it back into the schedule.  We need to rewind the
       requests all the way back to state Initialised, which means
       ungranting them. */
    KeAcquireSpinLock(&sf->ring_lock, &irql);
    for (ple = requests_needing_replay.Flink;
         ple != &requests_needing_replay;
         ple = next_ple) {
        next_ple = ple->Flink;
        sfr = CONTAINING_RECORD(ple, struct scsifilt_request, list);
        XM_ASSERT3U(sfr->state, ==, SfrStateSubmitted);
        sfr->state = SfrStateInitialised;
        ungrant_request(sf, sfr);
        expected_nr_replay--;
        RemoveEntryList(&sfr->list);
        enqueue_request(&sf->schedule, sfr);
    }
    XM_ASSERT3U(expected_nr_replay, ==, 0);
    KeReleaseSpinLock(&sf->ring_lock, irql);
}

/* The scsifilt instance is being destroyed.  Any remaining pending
   replay requests are almost certainly doomed.  Abort them. */
void
abort_pending_requests(struct scsifilt *sf)
{
    KIRQL irql;
    LIST_ENTRY requests;
    unsigned nr_requests_expected;
    unsigned nr_requests_processed;
    PLIST_ENTRY ple;
    struct scsifilt_request *sfr;

    /* Grab the replay request list */
    KeAcquireSpinLock(&sf->request_replay_lock, &irql);
    XmListTransplant(&requests, &sf->requests_needing_replay);
    nr_requests_expected = sf->nr_replay_outstanding;
    sf->nr_replay_outstanding = 0;
    KeReleaseSpinLock(&sf->request_replay_lock, irql);

    /* Easy case: no requests outstanding. */
    if (IsListEmpty(&requests)) {
        XM_ASSERT3U(nr_requests_expected, ==, 0);
        return;
    }

    /* For the benefit of ungrant_request() */
    KeAcquireSpinLock(&sf->ring_lock, &irql);

    /* Walk the request list and fail every one */
    nr_requests_processed = 0;
    for (ple = requests.Flink; ple != &requests; ple = ple->Flink) {
        sfr = CONTAINING_RECORD(ple, struct scsifilt_request, list);
        XM_ASSERT3U(sfr->state, ==, SfrStateSubmitted);
        ungrant_request(sf, sfr);
        sfr->result = BLKIF_RSP_ERROR;
        sfr->returned_by_backend = __rdtsc();
        sfr->state = SfrStateProcessed;
        nr_requests_processed++;
    }

    XM_ASSERT3U(nr_requests_processed, ==, nr_requests_expected);

    KeReleaseSpinLock(&sf->ring_lock, irql);

    /* Tell scsifilt proper about what we've done. */
    finish_requests(sf, &requests);
}
