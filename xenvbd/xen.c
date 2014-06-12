//
// xen.c - Xen interfaces for SCSI Miniport driver.
//
// Copyright (c) 2006 XenSource, Inc.
//

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


#pragma warning (push, 3)

#include "xenvbd.h"
#include "scsiboot.h"
#include "xsapi.h"

#include "../xenutil/xenbus.h"
#include "../xenutil/reexport.h"

#pragma warning (pop)

//
// Dont care about unreferenced formal parameters here
//
#pragma warning( disable : 4100 )

VOID XenvbdEvtchnCallback(PVOID Context);
static BOOLEAN SubmitSrb(PXHBD_TARGET_INFO ptargetInfo, PSCSI_REQUEST_BLOCK srb);
static void FreeBounceBuffer(int bid);
static VOID XenvbdCompleteRequests(PXHBD_TARGET_INFO ptargetInfo);

static VOID
SortDeviceListToMatchQemu(
    IN OUT PCHAR *devices, 
    IN OUT int *deviceIds, 
    IN OUT PCHAR *names, 
    IN ULONG numVbds
)
/*++

Description:

   Sort the device list so that it matches the order in which qemu
   will present them

--*/
{
    ULONG div;
    ULONG probe;
    int this_device_id;
    CHAR *this_device;
    ULONG i;

    TraceDebug(("Before sort:\n"));
    for (i = 0; i < numVbds; i++) 
    {
        TraceDebug(("%d -> %s-%s.\n", deviceIds[i], devices[i], names[i]));
    }

    //
    // insertion sort
    //

    for (div = 1; div < numVbds; div++) 
    {
        for (probe = 0; probe < div; probe++) 
        {
            //
            // check for SCSI (Major number 0x8)
            // if probe is SCSI and div is not, then probe is larger
            // if probe is IDE and div is SCSI, then div is larger
            // if probe and div are IDE, then sort on device_id
            // if probe and div are SCSI, then sort on device_id
            //

            if ((((deviceIds[probe] & 0xff00) == 0x800) && 
                 ((deviceIds[div] & 0xff00) == 0x800)) ||
                (((deviceIds[probe] & 0xff00) != 0x800) &&
                 ((deviceIds[div] & 0xff00) != 0x800)) ||
                 (((deviceIds[probe] & 0xff00) == 0x800) &&
                 ((deviceIds[div] & 0xff00) != 0x800)))
            {
                //
                // 1) probe and div are either both SCSI or both IDE
                // OR 
                // 2) probe is SCSI and div is IDE
                //
                //

                if (deviceIds[div] < deviceIds[probe])
                {
                    this_device_id = deviceIds[probe];
                    deviceIds[probe] = deviceIds[div];
                    deviceIds[div] = this_device_id;

                    this_device = devices[probe];
                    devices[probe] = devices[div];
                    devices[div] = this_device;

                    this_device = names[probe];
                    names[probe] = names[div];
                    names[div] = this_device;
                }
            }
        }        
    }

    TraceDebug(("After sort:\n"));
    for (i = 0; i < numVbds; i++) 
    {
        TraceDebug(("%d -> %s-%s.\n", deviceIds[i], devices[i], names[i]));
    }
}

PCHAR
find_backend_path(PXHBD_TARGET_INFO ptargetInfo, SUSPEND_TOKEN token)
{
    PCHAR tmp, devPath;

    /* backend_path = ptargetInfo->xenbusNodeName + "/backend"; */
    tmp = Xmasprintf("%s/backend", ptargetInfo->xenbusNodeName);
    if (!tmp) {
        TraceError(("cannot find backend path for %s.\n",
                    ptargetInfo->xenbusNodeName));
        return NULL;
    }

    xenbus_read(XBT_NIL, tmp, &devPath);
    XmFreeMemory(tmp);

    TraceDebug(("backend path is %s.\n", devPath));

    return devPath;
}

static NTSTATUS
XenbusGetBackendInfo(
    PXHBD_TARGET_INFO ptargetInfo,
    CHAR *BackendPath,
    SUSPEND_TOKEN token
)
{
    ULONG64 tmp;
    NTSTATUS status;

    status = xenbus_read_int(XBT_NIL, BackendPath, "info",
                             &tmp);
    if (!NT_SUCCESS(status))
        return status;
    ptargetInfo->info = (ULONG)tmp;

    status = xenbus_read_int(XBT_NIL, BackendPath, "sectors",
                             &ptargetInfo->sectors);
    if (!NT_SUCCESS(status))
        return status;

    status = xenbus_read_int(XBT_NIL, BackendPath, "sector-size",
                             &tmp);
    if (!NT_SUCCESS(status))
        return status;
    ptargetInfo->sector_size = (ULONG)tmp;

    return STATUS_SUCCESS;
}

VOID
CloseFrontend(
    IN  PXHBD_TARGET_INFO   ptargetInfo,
    IN  PCHAR               backend_path,
    IN  SUSPEND_TOKEN       token
    )
{
    CHAR *prefix = ptargetInfo->xenbusNodeName;
    XENBUS_STATE frontend_state;
    XENBUS_STATE backend_state;
    NTSTATUS status;

    TraceNotice(("target %d: closing frontend...\n", ptargetInfo->targetId));

    // Get initial frontend state
    status = xenbus_read_state(XBT_NIL, prefix, "state", &frontend_state);
    if (!NT_SUCCESS(status))
        frontend_state = null_XENBUS_STATE();

    // Wait for the backend to stabilise
    backend_state = null_XENBUS_STATE();
    do {
        backend_state = XenbusWaitForBackendStateChange(backend_path, backend_state,
                                                        NULL, token);
    } while (same_XENBUS_STATE(backend_state, XENBUS_STATE_INITIALISING));

    TraceVerbose(("%s: target %d: backend state = %s, frontend state = %s\n",
                  __FUNCTION__,
                  ptargetInfo->targetId, XenbusStateName(backend_state),
                  XenbusStateName(frontend_state)));

    frontend_state = XENBUS_STATE_CLOSING;
    while (!same_XENBUS_STATE(backend_state, XENBUS_STATE_CLOSING) &&
           !same_XENBUS_STATE(backend_state, XENBUS_STATE_CLOSED) &&
           !is_null_XENBUS_STATE(backend_state)) {
        xenbus_change_state(XBT_NIL, prefix, "state", frontend_state);
        backend_state = XenbusWaitForBackendStateChange(backend_path, backend_state,
                                                        NULL, token);
    }

    TraceVerbose(("%s: target %d: backend state = %s, frontend state = %s\n",
                  __FUNCTION__,
                  ptargetInfo->targetId, XenbusStateName(backend_state),
                  XenbusStateName(frontend_state)));

    frontend_state = XENBUS_STATE_CLOSED;
    while (!same_XENBUS_STATE(backend_state, XENBUS_STATE_CLOSED) &&
           !is_null_XENBUS_STATE(backend_state)) {
        xenbus_change_state(XBT_NIL, prefix, "state", frontend_state);
        backend_state = XenbusWaitForBackendStateChange(backend_path, backend_state,
                                                        NULL, token);
    }

    TraceVerbose(("%s: target %d: backend state = %s, frontend state = %s\n",
                  __FUNCTION__,
                  ptargetInfo->targetId, XenbusStateName(backend_state),
                  XenbusStateName(frontend_state)));

    TraceNotice(("target %d: backend is closed\n", ptargetInfo->targetId));
}

NTSTATUS
PrepareBackendForReconnect(
    IN  PXHBD_TARGET_INFO   Target,
    IN  PCHAR               backend_path,
    IN  SUSPEND_TOKEN       token
    )
{
    CHAR *prefix = Target->xenbusNodeName;
    XENBUS_STATE frontend_state;
    XENBUS_STATE backend_state;
    NTSTATUS status;

    TraceNotice(("target %d: preparing backend for reconnection...\n",
                 Target->targetId));

    frontend_state = null_XENBUS_STATE();
    do {
        xenbus_transaction_t    xbt;
        ULONG64                 Id;

        xenbus_transaction_start(&xbt);

        status = xenbus_read_state(xbt, Target->xenbusNodeName, "state",
                                   &frontend_state);
        if (!NT_SUCCESS(status)) {
            TraceWarning(("target %d: VBD %d frontend area has disappeared.\n",
                          Target->targetId, Target->handle));
            (VOID) xenbus_transaction_end(xbt, 1);
            break;
        }

        // Check we're still talking to the same incarnation of the frontend area that we
        // originally enumerated.
        status = xenbus_read_int(xbt, Target->xenbusNodeName, "target-id", &Id);
        if (!NT_SUCCESS(status) || Id != (ULONG64)Target->targetId) {
            TraceWarning(("target %d: VBD %d frontend area has been re-created?\n",
                          Target->targetId, Target->handle));
            (VOID) xenbus_transaction_end(xbt, 1);
            break;
        }

        status = STATUS_UNSUCCESSFUL;
        if (!same_XENBUS_STATE(frontend_state, XENBUS_STATE_CLOSED)) {
            TraceWarning(("target %d: VBD %d frontend area is not CLOSED.\n",
                          Target->targetId, Target->handle));
            (VOID) xenbus_transaction_end(xbt, 1);
            break;
        }

        frontend_state = XENBUS_STATE_INITIALISING;
        xenbus_change_state(xbt, prefix, "state", frontend_state);

        status = xenbus_transaction_end(xbt, 0);
    } while (status == STATUS_RETRY);

    if (!NT_SUCCESS(status))
        goto fail1;

    // Wait for the backend
    backend_state = null_XENBUS_STATE();
    do {
        backend_state = XenbusWaitForBackendStateChange(backend_path, backend_state,
                                                        NULL, token);
    } while (same_XENBUS_STATE(backend_state, XENBUS_STATE_CLOSED) ||
             same_XENBUS_STATE(backend_state, XENBUS_STATE_INITIALISING));

    TraceVerbose(("%s: target %d: backend state = %s, frontend state = %s\n",
                  __FUNCTION__,
                  Target->targetId, XenbusStateName(backend_state),
                  XenbusStateName(frontend_state)));

    status = STATUS_UNSUCCESSFUL;
    if (!same_XENBUS_STATE(backend_state, XENBUS_STATE_INITWAIT))
        goto fail2;

    TraceNotice(("target %d: backend is waiting\n", Target->targetId));

    return STATUS_SUCCESS;

fail2:
    TraceError(("%s: fail2\n", __FUNCTION__));

    CloseFrontend(Target, backend_path, token);

fail1:
    TraceError(("%s: fail1 (%08x)\n", __FUNCTION__, status));

    return status;
}

static VOID
InitialiseSharedRing(PXHBD_TARGET_INFO ptargetInfo)
{
    SHARED_RING_INIT(ptargetInfo->sring);
    FRONT_RING_INIT(&ptargetInfo->ring, ptargetInfo->sring,
                    PAGE_SIZE << ptargetInfo->sring_order);
}

/* Allocate Xen-side resources for a target: sring grant reference and
   event channel port. */
static NTSTATUS
XenvbdSetupTargetXen(PXHBD_TARGET_INFO ptargetInfo)
{
    NTSTATUS stat;
    PHYSICAL_ADDRESS pa;
    unsigned min_grefs;
    unsigned nr_ring_pages;
    unsigned x;

    /* The scsifilt IO path can tolerate running out of grefs by just
       re-queueing the request, provided it can always keep at least
       one request outstanding.  The non-scsifilt path can't, and we
       need to guarantee that we always have enough grefs available
       for it. */
    if (!AustereMode)
        min_grefs = XENVBD_MAX_SEGMENTS_PER_SRB;
    else
        min_grefs = XENVBD_MAX_SEGMENTS_PER_SRB * BLK_RING_SIZE;

    /* Make sure we can share the ring itself. */
    nr_ring_pages = 1 << ptargetInfo->sring_order;
    min_grefs += nr_ring_pages;

    ptargetInfo->grant_cache = GnttabAllocCache(min_grefs);
    if (!ptargetInfo->grant_cache) {
        TraceError(("Failed to set up grant cache.\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    for (x = 0; x < nr_ring_pages; x++) {
        pa = XenGetPhysicalAddress((PVOID)((ULONG_PTR)ptargetInfo->sring +
                                                      (x * PAGE_SIZE)));
        ptargetInfo->ring_refs[x] =
            GnttabGrantForeignAccessCache(ptargetInfo->backendId,
                                          PHYS_TO_PFN(pa),
                                          GRANT_MODE_RW,
                                          ptargetInfo->grant_cache);
        XM_ASSERT(!is_null_GRANT_REF(ptargetInfo->ring_refs[x]));
    }

    ptargetInfo->evtchn_port =
        EvtchnAllocUnbound(ptargetInfo->backendId,XenvbdEvtchnCallback,
                           ptargetInfo);

    if (is_null_EVTCHN_PORT(ptargetInfo->evtchn_port)) {
        TraceError(("Failed to allocate event channel port.\n"));
        for (x = 0; x < nr_ring_pages; x++) {
            stat = GnttabEndForeignAccessCache(ptargetInfo->ring_refs[x],
                                               ptargetInfo->grant_cache);
            XM_ASSERT(NT_SUCCESS(stat));
            ptargetInfo->ring_refs[x] = null_GRANT_REF();
        }
        GnttabFreeCache(ptargetInfo->grant_cache);
        ptargetInfo->grant_cache = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

/* Final stage of connecting to a backend: do the xenbus transaction
 * and wait for the backend to give us the go-ahead.  This is invoked
 * from both initial ring connection and a late recover from suspend
 * handler.  The latter provides very little synchronisation: there
 * are requests coming in all the time while this is running.  On the
 * plus side, nobody's going to try and free the target info or change
 * xenbusNodeName, and that's pretty much all we need. */
static NTSTATUS
XenvbdSetupTargetXenbus(PXHBD_TARGET_INFO ptargetInfo,
                        CHAR *BackendPath,
                        SUSPEND_TOKEN token)
{
    XENBUS_STATE state;
    NTSTATUS status;
    xenbus_transaction_t xbt;
    PCHAR xenbusNode = ptargetInfo->xenbusNodeName;
    unsigned x;
    char buffer[16];

    do {
        TraceDebug(("XBST: tx start %s\n", xenbusNode));
        xenbus_transaction_start(&xbt);
        xenbus_write_evtchn_port(xbt, xenbusNode, "event-channel",
                                 ptargetInfo->evtchn_port);
        if (ptargetInfo->sring_single_page) {
            TraceNotice(("%s: using single page handshake\n", xenbusNode));
            xenbus_write_grant_ref(xbt, xenbusNode, "ring-ref",
                                   ptargetInfo->ring_refs[0]);
        } else {
            TraceNotice(("%s: using multi-page handshake\n", xenbusNode));
            xenbus_printf(xbt, xenbusNode, "ring-page-order", "%u",
                          ptargetInfo->sring_order);
            for (x = 0; x < (1u << ptargetInfo->sring_order); x++) {
                Xmsnprintf(buffer, sizeof(buffer), "ring-ref%d", x);
                xenbus_write_grant_ref(xbt, xenbusNode, buffer,
                                       ptargetInfo->ring_refs[x]);
            }
        }
        xenbus_printf(xbt, xenbusNode, "protocol", "x86_32-abi");
        xenbus_write_feature_flag(xbt, xenbusNode, "feature-surprise-remove",
                                  TRUE);
        xenbus_write_feature_flag(xbt, xenbusNode, "feature-online-resize",
                                  TRUE);
        xenbus_change_state(xbt, xenbusNode, "state",
                            XENBUS_STATE_INITIALISED);
        TraceDebug(("XBST: tx end\n"));
        status = xenbus_transaction_end(xbt, 0);
        TraceDebug(("XBST: tx end status = %x\n", status));
    } while (status == STATUS_RETRY);

    if (status != STATUS_SUCCESS) {
        TraceError(("XenbusSetupTarget: trans failed: %x\n",
                    status));
        return status;
    }

    /* Wait for backend to become connected. */
    state = null_XENBUS_STATE();
    do {
        state = XenbusWaitForBackendStateChange(BackendPath, state, NULL,
                                                token);
    } while (same_XENBUS_STATE(state, XENBUS_STATE_INITWAIT) ||
             same_XENBUS_STATE(state, XENBUS_STATE_INITIALISING) ||
             same_XENBUS_STATE(state, XENBUS_STATE_INITIALISED));

    status = STATUS_UNSUCCESSFUL;
    if (!same_XENBUS_STATE(state, XENBUS_STATE_CONNECTED)) {
        TraceVerbose(("backend not connected.\n"));
        return status;
    }

    xenbus_change_state(XBT_NIL, xenbusNode, "state",
                        XENBUS_STATE_CONNECTED);

    return STATUS_SUCCESS;
}

void
CompleteSrb(PSCSI_REQUEST_BLOCK srb)
{
    ScsiPortNotification(RequestComplete, XenvbdDeviceExtension, srb);

    XM_ASSERT(XenvbdDeviceExtension->totInFlight != 0);
    XenvbdDeviceExtension->totInFlight--;
}

static void
CleanupSrb(PXHBD_TARGET_INFO TargetInfo, PSCSI_REQUEST_BLOCK srb)
{
    PSRB_EXTENSION srb_ext = SrbExtension(srb);
    ULONG i;

    for (i = 0; i < srb_ext->nr_requests; i++) {
        xenvbd_request_t *request = &(srb_ext->request[i]);
        ULONG j;

        for (j = 0; j < request->nr_segments; j++) {
            GRANT_REF gref = request->seg[j].gref;

            XM_ASSERT(!is_null_GRANT_REF(gref));
            GnttabEndForeignAccessCache(gref, TargetInfo->grant_cache);

            if (srb_ext->bounced) {
                BUFFER_ID bid = request->seg[j].bid;

                XM_ASSERT(bid >= 0);
                FreeBounceBuffer(bid);
            }
        }
        memset(request, 0, sizeof (xenvbd_request_t));
    }
}

static void
AbortSrbQueue(PSRB_QUEUE_RAW queue, PXHBD_TARGET_INFO TargetInfo,
              BOOLEAN releaseResources)
{
    PSCSI_REQUEST_BLOCK srb;

    while ((srb = DequeueSrbRaw(queue)) != NULL) {
        if (releaseResources)
            CleanupSrb(TargetInfo, srb);

        srb->ScsiStatus = 0x40; /* SCSI_ABORTED */
        CompleteSrb(srb);
    }
}

VOID
XenbusUpdateTargetUsage(
    IN  XHBD_TARGET_INFO    *Target
    )
{
    XM_ASSERT(!AustereMode);

    (VOID) xenbus_write_feature_flag(XBT_NIL, Target->targetPath, "paging",
                                     Target->Paging);

    (VOID) xenbus_write_feature_flag(XBT_NIL, Target->targetPath, "hibernation",
                                     Target->Hibernation);

    (VOID) xenbus_write_feature_flag(XBT_NIL, Target->targetPath, "dump",
                                     Target->DumpFile);
}

VOID
XenbusEjectTarget(
    IN  XHBD_TARGET_INFO    *Target
    )
{
    NTSTATUS                status;

    Target->Ejected = TRUE;

    do {
        xenbus_transaction_t    xbt;
        XENBUS_STATE            State;
        ULONG64                 Id;

        xenbus_transaction_start(&xbt);

        // Check we're still talking to the same incarnation of the frontend area that we
        // originally enumerated.
        status = xenbus_read_int(XBT_NIL, Target->xenbusNodeName, "target-id", &Id);
        if (!NT_SUCCESS(status) || Id != (ULONG64)Target->targetId) {
            (VOID) xenbus_transaction_end(xbt, 1);
            return;
        }

        status = xenbus_read_state(xbt, Target->xenbusNodeName, "state",
                                   &State);
        if (!NT_SUCCESS(status)) {
            (VOID) xenbus_transaction_end(xbt, 1);
            return;
        }

        // Prevent re-enumeration once the target is destroyed
        (VOID) xenbus_write_feature_flag(xbt, Target->xenbusNodeName, "ejected", TRUE);

        status = xenbus_transaction_end(xbt, 0);
    } while (status == STATUS_RETRY);

    if (!NT_SUCCESS(status))
        TraceVerbose(("target %d: VBD %d frontend area has disappeared.\n",
                      Target->targetId, Target->handle));
}

// Should only be called from XenvbdScanTargets
VOID
XenbusDestroyTarget(
    IN  PXHBD_TARGET_INFO TargetInfo
    )
{
    ULONG targetId = TargetInfo->targetId;
    ULONG References;

    XM_ASSERT(TargetInfo->Next == NULL);
    XM_ASSERT(KeGetCurrentThread() != XenvbdEnumLock.Owner);

    while ((References = TargetInfo->References) != 0) {
        LARGE_INTEGER   Period;

        TraceVerbose(("%s: %d thing(s) are holding a reference to target %d.\n",
                      __FUNCTION__, References, targetId));
        Period.QuadPart = -100000;
        KeDelayExecutionThread(KernelMode, FALSE, &Period);
    }

    XM_ASSERT(TargetInfo->FilterTarget.scsifilt == NULL);

    xenbus_remove(XBT_NIL, TargetInfo->targetPath);
    XmFreeMemory(TargetInfo->targetPath);

    XM_ASSERT(PeekSrb(&TargetInfo->FreshSrbs) == NULL);
    XM_ASSERT(PeekSrb(&TargetInfo->PreparedSrbs) == NULL);
    XM_ASSERT(PeekSrb(&TargetInfo->SubmittedSrbs) == NULL);

    if (TargetInfo->LateSuspendHandler != NULL)
        EvtchnUnregisterSuspendHandler(TargetInfo->LateSuspendHandler);

    if (TargetInfo->EarlySuspendHandler != NULL)
        EvtchnUnregisterSuspendHandler(TargetInfo->EarlySuspendHandler);

    if (TargetInfo->BackendStateWatch != NULL)
        xenbus_unregister_watch(TargetInfo->BackendStateWatch);

    XM_ASSERT(is_null_EVTCHN_PORT(TargetInfo->evtchn_port));

    XM_ASSERT(TargetInfo->grant_cache == NULL);
    XM_ASSERT(TargetInfo->sring == NULL);

    ReleaseScsiInquiryData(TargetInfo);

    XmFreeMemory(TargetInfo->xenbusNodeName);
    XmFreeMemory(TargetInfo);

    TraceNotice(("target %d: destroyed\n", targetId));
    return;
}

static void
ProbeBackendCapabilities(PXHBD_TARGET_INFO ptargetInfo, CHAR *BackendPath)
{
    NTSTATUS status;
    ULONG64 order;

    status = xenbus_read_domain_id(XBT_NIL, ptargetInfo->xenbusNodeName,
                                   "backend-id", &ptargetInfo->backendId);
    if (!NT_SUCCESS(status)) {
        TraceError(("Failed to read backend id from %s (%x)\n",
                    ptargetInfo->xenbusNodeName, status));
        /* Assume dom0.  The alternative is pretty much just to
         * crash. */
        ptargetInfo->backendId = DOMAIN_ID_0();
    }

    /* Set defaults for when we can't probe. */
    ptargetInfo->sring_single_page = TRUE;
    ptargetInfo->sring_order = 0;

    status = xenbus_read_int(XBT_NIL, BackendPath, "max-ring-page-order", &order);
    if (NT_SUCCESS(status)) {
        if (XenvbdDeviceExtension->MaxRingPageOrder >= 0 &&
            order > (ULONG64)XenvbdDeviceExtension->MaxRingPageOrder)
            order = (ULONG64)XenvbdDeviceExtension->MaxRingPageOrder;

        if (order > MAX_RING_PAGE_ORDER)
            order = MAX_RING_PAGE_ORDER;

        if (AustereMode)
            order = 0;

        ptargetInfo->sring_single_page = FALSE;
        ptargetInfo->sring_order = (ULONG)order;
    }

    TraceInfo(("Using %u sring page(s).\n", 1 << ptargetInfo->sring_order));
}

NTSTATUS
XenvbdConnectTarget(
    IN  XHBD_TARGET_INFO    *Target,
    IN  CHAR                *BackendPath,
    IN  SUSPEND_TOKEN       Token
    )
{
    ULONG                   x;
    XENBUS_STATE            state;
    NTSTATUS                status;

    state = XenbusWaitForBackendStateChange(BackendPath, null_XENBUS_STATE(), NULL,
                                            Token);

    status = STATUS_UNSUCCESSFUL;
    if (!same_XENBUS_STATE(state, XENBUS_STATE_INITWAIT))
        goto fail1;

    ProbeBackendCapabilities(Target, BackendPath);

    Target->sring = XmAllocateZeroedMemory(PAGE_SIZE << Target->sring_order);

    status = STATUS_NO_MEMORY;
    if (Target->sring == NULL)
        goto fail2;

    status = XenvbdSetupTargetXen(Target);
    if (status != STATUS_SUCCESS)
        goto fail3;

    InitialiseSharedRing(Target);

    status = XenvbdSetupTargetXenbus(Target, BackendPath, Token);
    if (status != STATUS_SUCCESS)
        goto fail4;

    XenbusGetBackendInfo(Target, BackendPath, Token);

    return STATUS_SUCCESS;

fail4:
    TraceError(("%s: fail4\n", __FUNCTION__));

    CloseFrontend(Target, BackendPath, Token);

    for (x = 0; x < (1u << Target->sring_order); x++) {
        if (!is_null_GRANT_REF(Target->ring_refs[x])) {
            GnttabEndForeignAccessCache(Target->ring_refs[x],
                                        Target->grant_cache);
            Target->ring_refs[x] = null_GRANT_REF();
        }
    }

    GnttabFreeCache(Target->grant_cache);
    Target->grant_cache = NULL;

    Target->ring.sring = NULL;

fail3:
    TraceError(("%s: fail3\n", __FUNCTION__));

    XmFreeMemory(Target->sring);
    Target->sring = NULL;

fail2:
    TraceError(("%s: fail2\n", __FUNCTION__));

fail1:
    TraceError(("%s: fail1 (0x%08x)\n", __FUNCTION__, status));

    return status;
}

VOID
XenvbdDisconnectTarget(
    IN  XHBD_TARGET_INFO    *Target,
    IN  CHAR                *BackendPath,
    IN  SUSPEND_TOKEN       Token
    )
{
    AbortSrbQueue(&Target->FreshSrbs, Target, FALSE);
    AbortSrbQueue(&Target->PreparedSrbs, Target, TRUE);
    AbortSrbQueue(&Target->SubmittedSrbs, Target, TRUE);

    EvtchnClose(Target->evtchn_port);
    Target->evtchn_port = null_EVTCHN_PORT();

    if (Target->grant_cache) {
        ULONG x;

        for (x = 0; x < (1u << Target->sring_order); x++) {
            if (!is_null_GRANT_REF(Target->ring_refs[x])) {
                GnttabEndForeignAccessCache(Target->ring_refs[x],
                                            Target->grant_cache);
                Target->ring_refs[x] = null_GRANT_REF();
            }
        }

        GnttabFreeCache(Target->grant_cache);
        Target->grant_cache = NULL;
    }

    Target->ring.sring = NULL;

    if (Target->sring) {
        XmFreeMemory(Target->sring);
        Target->sring = NULL;
    }
}

static VOID
BackendStateChanged(
    IN  VOID            *Context
    )
{
    ULONG               TargetID = (ULONG)(ULONG_PTR)Context;
    XHBD_TARGET_INFO    *Target;
    SUSPEND_TOKEN       Token;
    CHAR                *BackendPath;
    XENBUS_STATE        BackendState;
    CHAR                *FrontendPath;
    XENBUS_STATE        FrontendState;
    KIRQL               Irql;
    NTSTATUS            status;

    Irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    Target = XenvbdTargetInfo[TargetID];

    if (Target == NULL)
        goto unlock;

    if (Target->Suspended)
        goto unlock;

    Target->References++;
    release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

    FrontendPath = Target->xenbusNodeName;

    Token = EvtchnAllocateSuspendToken(__FUNCTION__);
    
    BackendPath = find_backend_path(Target, Token);
    if (BackendPath == NULL)
        goto done;

    FrontendState = null_XENBUS_STATE();
    BackendState = null_XENBUS_STATE();

    do {
        xenbus_transaction_t    xbt;

        xenbus_transaction_start(&xbt);

        status = xenbus_read_state(xbt, BackendPath, "state", &BackendState);
        if (!NT_SUCCESS(status)) {
            (VOID) xenbus_transaction_end(xbt, 1);
            break;
        }

        status = xenbus_read_state(xbt, FrontendPath, "state", &FrontendState);
        if (!NT_SUCCESS(status)) {
            (VOID) xenbus_transaction_end(xbt, 1);
            break;
        }

        status = xenbus_transaction_end(xbt, 0);
    } while (status == STATUS_RETRY);

    if (!NT_SUCCESS(status))
        goto done;

    TraceVerbose(("%s: target %d: backend state = %s, frontend state = %s\n",
                    __FUNCTION__, TargetID,
                    XenbusStateName(BackendState),
                    XenbusStateName(FrontendState)));

    if (same_XENBUS_STATE(FrontendState, XENBUS_STATE_CONNECTED) &&
        (same_XENBUS_STATE(BackendState, XENBUS_STATE_CLOSING) ||
         same_XENBUS_STATE(BackendState, XENBUS_STATE_CLOSED))) {
        BOOLEAN DoEject;

        DoEject = FALSE;
        KeAcquireSpinLock(&Target->EjectLock, &Irql);
        if (Target->DeviceObject != NULL) {
            DoEject = TRUE;
            Target->EjectRequested = TRUE;
        } else {
            Target->EjectPending = TRUE;
        }
        KeReleaseSpinLock(&Target->EjectLock, Irql);

        if (DoEject) {
            TraceNotice(("%s: Issuing eject request for target %d\n",
                         __FUNCTION__, TargetID));
            IoRequestDeviceEject(Target->DeviceObject);
        }
    }

done:
    EvtchnReleaseSuspendToken(Token);

    Irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    Target->References--;

unlock:
    release_irqsafe_lock(XenvbdTargetInfoLock, Irql);
}

static VOID
SetupBackendStateWatch(
    IN  XHBD_TARGET_INFO    *Target,
    IN  CHAR                *BackendPath
    )
{
    CHAR                    *StatePath;
    NTSTATUS                status;

    if (AustereMode)
        return;

    StatePath = Xmasprintf("%s/state", BackendPath);

    status = STATUS_NO_MEMORY;
    if (StatePath == NULL)
        goto fail1;

    if (Target->BackendStateWatch != NULL) {
        status = xenbus_redirect_watch(Target->BackendStateWatch, StatePath);
        if (!NT_SUCCESS(status))
            goto fail2;
    } else {
        Target->BackendStateWatch = xenbus_watch_path(StatePath,
                                                      BackendStateChanged,
                                                      (VOID *)(ULONG_PTR)Target->targetId);

        status = STATUS_UNSUCCESSFUL;
        if (Target->BackendStateWatch == NULL) {
            goto fail2;
        }
    }

    XmFreeMemory(StatePath);
    return;

fail2:
    TraceError(("%s: fail2\n", __FUNCTION__));

    XmFreeMemory(StatePath);

fail1:
    TraceError(("%s: fail1 (0x%08x)\n", __FUNCTION__, status));
}

static NTSTATUS
ClaimFrontend(
    IN  XHBD_TARGET_INFO    *Target,
    IN  CHAR                *BackendPath,
    IN  SUSPEND_TOKEN       Token
    )
{
    xenbus_transaction_t    xbt;
    XENBUS_STATE            FrontendState;
    XENBUS_STATE            BackendState;
    NTSTATUS                status;

    TraceNotice(("target %d: claiming frontend...\n", Target->targetId));

    BackendState = XenbusWaitForBackendStateChange(BackendPath,
                                                   null_XENBUS_STATE(),
                                                   NULL,
                                                   Token);

    if (same_XENBUS_STATE(BackendState, XENBUS_STATE_INITIALISING)) {
        LARGE_INTEGER   Timeout;

        // The tools create the frontend and backend areas in state
        // INITIALISING, and the backend then quickly moves to INITWAIT.
        // Check that the observed states are sane and then write our
        // target ID into the frontend area to claim that we have
        // enumerated it.
        // If the backend is buggy it may never move out of INITIALISING
        // so, after a suitably long time, just fail to claim and hope
        // the tools can clean up.
        Timeout.QuadPart = -1    // Relative
                         * 10    // to us
                         * 1000  // to ms
                         * 1000  // to s
                         * 30;

        BackendState = XenbusWaitForBackendStateChange(BackendPath,
                                                       XENBUS_STATE_INITIALISING,
                                                       &Timeout,
                                                       Token);
    }

    // The backend may still be stuck in INITIALISING
    status = STATUS_UNSUCCESSFUL;
    if (same_XENBUS_STATE(BackendState, XENBUS_STATE_INITIALISING))
        goto done;

    if (!AustereMode) {
        do {
            xenbus_transaction_start(&xbt);

            status = xenbus_read_state(xbt, Target->xenbusNodeName, "state", &FrontendState);
            if (!NT_SUCCESS(status))
                goto abort;

            status = xenbus_read_state(xbt, BackendPath, "state", &BackendState);
            if (!NT_SUCCESS(status))
                goto abort;

            if (same_XENBUS_STATE(FrontendState, XENBUS_STATE_INITIALISING) &&
                same_XENBUS_STATE(BackendState, XENBUS_STATE_INITWAIT)) {
                // Claim the target
                status = xenbus_printf(xbt, Target->xenbusNodeName, "target-id", "%d",
                                       Target->targetId);
                if (!NT_SUCCESS(status))
                    goto abort;
            } else {
                // Give up
                (VOID) xenbus_change_state(xbt, Target->xenbusNodeName, "state", XENBUS_STATE_CLOSED);

                // Prevent re-enumeration until the tools re-create the VBD
                (VOID) xenbus_write_feature_flag(xbt, Target->xenbusNodeName, "ejected", TRUE);
            }

            status = xenbus_transaction_end(xbt, 0);
        } while (status == STATUS_RETRY);
    } else {
        status = xenbus_printf(XBT_NIL, Target->xenbusNodeName, "target-id", "%d",
                                Target->targetId);
    }

done:
    if (NT_SUCCESS(status)) {
        TraceNotice(("target %d: successfuly claimed %s\n", Target->targetId, Target->xenbusNodeName));
    } else {
        TraceNotice(("target %d: failed to claim %s\n", Target->targetId, Target->xenbusNodeName));
    }

    return status;

abort:
    TraceNotice(("target %d: aborted claim %s\n", Target->targetId, Target->xenbusNodeName));

    (VOID) xenbus_transaction_end(xbt, 1);
    return status;
}

VOID
SuspendTarget(
    IN  XHBD_TARGET_INFO    *Target
    )
{
    Target->References++;

    Target->Suspended = TRUE;

    TraceNotice(("target %d: suspended\n", Target->targetId));
}

static VOID
TargetEarlyResume(
    IN  VOID            *Context,
    IN  SUSPEND_TOKEN   Token
    )
{
    PXHBD_TARGET_INFO   Target = Context;

    XM_ASSERT(!AustereMode);

    // No need to lock since we're at high IRQL running on a single CPU
    SuspendTarget(Target);
}

VOID
ResumeTarget(
    IN  XHBD_TARGET_INFO    *Target,
    IN  SUSPEND_TOKEN       Token
    )
{
    CHAR                    *BackendPath;
    ULONG64                 Id;
    KIRQL                   Irql;
    NTSTATUS                status;

    XM_ASSERT(!AustereMode);
    XM_ASSERT(Target->Resuming);

    TraceVerbose(("%s(%d): ====>\n", __FUNCTION__, Target->targetId));

    BackendPath = find_backend_path(Target, Token);

    status = STATUS_NO_MEMORY;
    if (!BackendPath)
        goto fail1;

    ExAcquireFastMutex(&Target->StateLock);

    // If the target-id is present then the VBD has not been re-created, so we
    // can skip most things.
    status = xenbus_read_int(XBT_NIL, Target->xenbusNodeName, "target-id", &Id);
    if (NT_SUCCESS(status) && Id == (ULONG64)Target->targetId)
        goto done;

    // This is a new incarnation of the VBD so we need to claim it.
    status = ClaimFrontend(Target, BackendPath, Token);
    if (!NT_SUCCESS(status))
        goto fail2;

    // Backend should be in INITWAIT if we get here so it is now safe to sample some
    // backend features.
    xenbus_read_feature_flag(XBT_NIL, BackendPath, "removable", &Target->removable);

    // Get the front and backends into CLOSED
    CloseFrontend(Target, BackendPath, Token);

    // Set up watches
    SetupBackendStateWatch(Target, BackendPath);

    // Restore target frontend key
    status = xenbus_printf(XBT_NIL, Target->targetPath, "frontend", "%s",
                           Target->xenbusNodeName);
    if (!NT_SUCCESS(status))
        goto fail3;

    // Restore target filter key
    status = xenbus_printf(XBT_NIL, Target->targetPath, "filter",
                           (Target->FilterTarget.scsifilt != NULL) ? "present" : "absent");
    if (!NT_SUCCESS(status))
        goto fail4;

    XenbusUpdateTargetUsage(Target);

done:
    // If the target was started then prepare for
    // reconnection.
    if (Target->Started) {
        status = PrepareBackendForReconnect(Target, BackendPath, Token);
        if (!NT_SUCCESS(status))
            goto fail5;

        if (Target->Connected) {
            status = XenvbdConnectTarget(Target, BackendPath, Token);
            if (!NT_SUCCESS(status))
                goto fail6;
        }
    }

    ExReleaseFastMutex(&Target->StateLock);

    XmFreeMemory(BackendPath);

    Irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    Target->Resuming = FALSE;
    Target->Resumed = TRUE;

    XM_ASSERT(Target->References != 0);
    Target->References--;
    release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

    TraceNotice(("target %d: resumed\n", Target->targetId));

    TraceVerbose(("%s(%d): <====\n", __FUNCTION__, Target->targetId));
    return;

fail6:
    TraceError(("%s: fail6\n", __FUNCTION__));

fail5:
    TraceError(("%s: fail5\n", __FUNCTION__));

fail4:
    TraceError(("%s: fail4\n", __FUNCTION__));

fail3:
    TraceError(("%s: fail3\n", __FUNCTION__));

fail2:
    TraceError(("%s: fail2\n", __FUNCTION__));

    ExReleaseFastMutex(&Target->StateLock);

    XmFreeMemory(BackendPath);

fail1:
    TraceError(("%s: fail1 (0x%08x)\n", __FUNCTION__, status));

    // Behave as if the target was resumed as there is nothing more we can do
    Irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    Target->Resuming = FALSE;
    Target->Resumed = TRUE;

    XM_ASSERT(Target->References != 0);
    Target->References--;
    release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

    TraceVerbose(("%s(%d): <====\n", __FUNCTION__, Target->targetId));
}

VOID
WaitTarget(
    IN  XHBD_TARGET_INFO    *Target
    )
{
    KIRQL                   Irql;
    ULONG                   Count;

    TraceVerbose(("%s(%d): ====>\n", __FUNCTION__, Target->targetId));

    TraceNotice(("target %d: waiting for resume...\n", Target->targetId));

    Irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    Count = 0;
    for (;;) {
        LARGE_INTEGER   Period;

        if (!Target->Resuming)
            break;

        release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

        if (++Count > 100) {
            TraceNotice(("target %d: waiting for a long time...\n", Target->targetId));
            Count = 0;
        }

        Period.QuadPart = -100000;
        KeDelayExecutionThread(KernelMode, FALSE, &Period);

        Irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    }
    release_irqsafe_lock(XenvbdTargetInfoLock, Irql);
    
    TraceNotice(("target %d: wait complete\n", Target->targetId));

    TraceVerbose(("%s(%d): <====\n", __FUNCTION__, Target->targetId));
}

static VOID
TargetLateResume(
    IN  VOID            *Context,
    IN  SUSPEND_TOKEN   Token
    )
{
    PXHBD_TARGET_INFO   Target = Context;
    KIRQL               Irql;

    XM_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    TraceVerbose(("%s: ====>\n", __FUNCTION__));

    Irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    if (Target->Suspended) {
        Target->Suspended = FALSE;
        Target->Resuming = TRUE;
        release_irqsafe_lock(XenvbdTargetInfoLock, Irql);
        
        ResumeTarget(Target, Token);
    } else {
        release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

        WaitTarget(Target);
    }

    TraceVerbose(("%s: <====\n", __FUNCTION__));
}

static NTSTATUS
XenbusSetupTarget(
    ULONG targetId,
    PCHAR xenbusNode
)
{
    PXHBD_TARGET_INFO ptargetInfo;
    SUSPEND_TOKEN token = null_SUSPEND_TOKEN();
    CHAR *BackendPath;
    unsigned x;
    KIRQL irql;
    NTSTATUS status;

    BackendPath = NULL;

    ptargetInfo = XmAllocateZeroedMemory(sizeof(XHBD_TARGET_INFO));
    if (!ptargetInfo) {
        TraceWarning(("Out of memory for TARGET_INFO structure.\n"));
        goto err;
    }

    KeInitializeSpinLock(&ptargetInfo->EjectLock);
    ExInitializeFastMutex(&ptargetInfo->StateLock);

    ptargetInfo->targetId = targetId;
    ptargetInfo->xenbusNodeName = xenbusNode;

    ptargetInfo->handle = (USHORT)atoi(strrchr(xenbusNode, '/') + 1); // this must match the backend

    token = EvtchnAllocateSuspendToken("xenvbd");

    BackendPath = find_backend_path(ptargetInfo, token);
    if (!BackendPath) {
        TraceError(("Cannot find backend path for %s\n", xenbusNode));
        goto err;
    }

    status = ClaimFrontend(ptargetInfo, BackendPath, token);
    if (!NT_SUCCESS(status)) {
        TraceError(("Cannot claim frontend for %s\n", xenbusNode));
        goto err;
    }

    // Backend should be in INITWAIT if we get here so it is now safe to sample some
    // backend features.
    xenbus_read_feature_flag(XBT_NIL, BackendPath, "removable", &ptargetInfo->removable);

    status = ReadScsiInquiryData(ptargetInfo, BackendPath);
    if (!NT_SUCCESS(status)) {
        TraceError(("Cannot create inquiry data for %s\n", xenbusNode));
        goto err;
    }

    // Get the front and backends into CLOSED
    CloseFrontend(ptargetInfo, BackendPath, token);

    if (!AustereMode) {
        // Set up the suspend handlers
        ptargetInfo->EarlySuspendHandler = EvtchnRegisterSuspendHandler(TargetEarlyResume, ptargetInfo,
                                                                       "xenvbd::early_resume",
                                                                       SUSPEND_CB_EARLY);
        if (ptargetInfo->EarlySuspendHandler == NULL) {
            TraceError(("Cannot register early suspend handler for %s\n",
                        xenbusNode));
            goto err;
        }

        ptargetInfo->LateSuspendHandler = EvtchnRegisterSuspendHandler(TargetLateResume, ptargetInfo,
                                                                       "xenvbd::late_resume",
                                                                       SUSPEND_CB_LATE);
        if (ptargetInfo->LateSuspendHandler == NULL) {
            TraceError(("Cannot register late suspend handler for %s\n",
                        xenbusNode));
            goto err;
        }

        // Set up watches
        SetupBackendStateWatch(ptargetInfo, BackendPath);

        ptargetInfo->targetPath = Xmasprintf("data/scsi/target/%d", targetId);
        if (ptargetInfo->targetPath == NULL) {
            TraceError(("Out of memory getting target path for %s\n",
                        xenbusNode));
            goto err;
        }

        // Note the frontend path. This is used for austere mode enumeration.
        status = xenbus_printf(XBT_NIL, ptargetInfo->targetPath, "frontend", "%s",
                                ptargetInfo->xenbusNodeName);
        if (!NT_SUCCESS(status)) {
            TraceError(("Failed to set frontend key for %s (%s, %x)\n",
                        ptargetInfo->targetPath, ptargetInfo->xenbusNodeName,
                        status));
            goto err;
        }

        // This xenstore key should be set to "present" if scsifilt loads correctly
        status = xenbus_printf(XBT_NIL, ptargetInfo->targetPath, "filter", "absent");
        if (!NT_SUCCESS(status)) {
            TraceNotice(("Can't flag filter as absent on %s\n", xenbusNode));
            goto err;
        }

        TraceVerbose(("%s/filter -> absent\n", ptargetInfo->targetPath));

        XenbusUpdateTargetUsage(ptargetInfo);
    }

    // Leave connection to scsifilt's PnP IRP handler unless we're
    // not expecting it to attach
    if (AustereMode) {
        ptargetInfo->Started = TRUE;

        PrepareBackendForReconnect(ptargetInfo, BackendPath, token);

        status = XenvbdConnectTarget(ptargetInfo, BackendPath, token);
        if (!NT_SUCCESS(status)) {
            TraceError(("%x connecting %s\n", status, xenbusNode));
            goto err;
        }

        ptargetInfo->Connected = TRUE;
    }

    EvtchnReleaseSuspendToken(token);

    irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    XM_ASSERT(XenvbdTargetInfo[targetId] == NULL);
    XenvbdTargetInfo[targetId] = ptargetInfo;
    release_irqsafe_lock(XenvbdTargetInfoLock, irql);

    XmFreeMemory(BackendPath);

    TraceNotice(("target %d: created\n", targetId));
    return STATUS_SUCCESS;

err:
    if (!is_null_SUSPEND_TOKEN(token))
        EvtchnReleaseSuspendToken(token);

    if (ptargetInfo->targetPath != NULL)
        XmFreeMemory(ptargetInfo->targetPath);

    if (ptargetInfo) {
        if (ptargetInfo->grant_cache) {
            for (x = 0; x < (1u << ptargetInfo->sring_order); x++) {
                if (!is_null_GRANT_REF(ptargetInfo->ring_refs[x])) {
                    GnttabEndForeignAccessCache(ptargetInfo->ring_refs[x],
                                                ptargetInfo->grant_cache);
                }
            }

            GnttabFreeCache(ptargetInfo->grant_cache);
        }

        XmFreeMemory(ptargetInfo->sring);
    }

    if (ptargetInfo->BackendStateWatch != NULL)
        xenbus_unregister_watch(ptargetInfo->BackendStateWatch);

    if (ptargetInfo->LateSuspendHandler != NULL)
        EvtchnUnregisterSuspendHandler(ptargetInfo->LateSuspendHandler);

    if (ptargetInfo->EarlySuspendHandler != NULL)
        EvtchnUnregisterSuspendHandler(ptargetInfo->EarlySuspendHandler);

    ReleaseScsiInquiryData(ptargetInfo);

    if (BackendPath != NULL)
        XmFreeMemory(BackendPath);

    XmFreeMemory(ptargetInfo);

    return STATUS_UNSUCCESSFUL;
}

static XENBUS_STATE
read_frontend_state(PXHBD_TARGET_INFO targetInfo)
{
    NTSTATUS stat;
    XENBUS_STATE res;

    stat = xenbus_read_state(XBT_NIL, targetInfo->xenbusNodeName, "state",
                             &res);
    if (NT_SUCCESS(stat))
        return res;
    else
        return null_XENBUS_STATE();
}

// Should only ever be called by XenvbdScanTargets
static NTSTATUS

XenbusFindVbds(
    VOID)
{
    char **dirEntries;
    NTSTATUS res;
    int nrDirEntries;
    char **newDisks = NULL;
    int nrNewDisks = 0;
    int i, j;
    char **devicePaths = NULL;
    int *deviceIds = NULL;
    PXHBD_TARGET_INFO targetInfo;
    KIRQL Irql;

    TraceVerbose(("%s: ====>\n", __FUNCTION__));

    res = xenbus_ls(XBT_NIL, "device/vbd", &dirEntries);
    if (res != STATUS_SUCCESS) {
        TraceError(("%s: failed to ls device/vbd: %x\n", __FUNCTION__, res));
        goto out;
    }
    for (nrDirEntries = 0; dirEntries[nrDirEntries]; nrDirEntries++)
        ;

    Irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    /* Mark existing targets in case any have gone away */
    for (i = 0; i < XENVBD_MAX_DISKS; i++) {
        targetInfo = XenvbdTargetInfo[i];
        if (targetInfo != NULL)
            targetInfo->EnumPending = TRUE;
    }
    release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

    /* Figure out what disks are present */
    newDisks = XmAllocateMemory(nrDirEntries * sizeof(newDisks[0]));
    for (i = 0; i < nrDirEntries; i++) {
        char *FrontendPath;
        char *deviceTypePath;
        ULONG64 id;
        BOOLEAN ejected;
        char *deviceType;
        NTSTATUS status;

        /* HACK: If we're in boot-emulated mode then we need to ignore
           the primary master. */
        /* (768 == the Linux block device number for hda) */
        if (XenPVFeatureEnabled(DEBUG_BOOT_EMULATED) &&
            !strcmp(dirEntries[i], "768")) {
            TraceNotice(("%s: ignoring primary master; should be handled by emulated drivers\n", __FUNCTION__));
            continue;
        }

        FrontendPath = Xmasprintf("device/vbd/%s", dirEntries[i]);
        if (!FrontendPath) {
            res = STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }

        // Ignore ejected devices
        (VOID) xenbus_read_feature_flag(XBT_NIL, FrontendPath, "ejected", &ejected);

        if (ejected) {
            TraceVerbose(("%s: ignoring ejected VBD: %s\n", __FUNCTION__, dirEntries[i]));
            XmFreeMemory(FrontendPath);
            continue;
        }

        // Skip anything we'e already enumerated
        status = xenbus_read_int(XBT_NIL, FrontendPath, "target-id", &id);
        if (NT_SUCCESS(status)) {
            XM_ASSERT(id < (ULONG64)XENVBD_MAX_DISKS);
            targetInfo = XenvbdTargetInfo[id];

            XM_ASSERT(targetInfo != NULL);
            targetInfo->EnumPending = FALSE;

            TraceVerbose(("%s: VBD %s has already been enumerated\n", __FUNCTION__, dirEntries[i]));

            XmFreeMemory(FrontendPath);
            continue;
        }

        XmFreeMemory(FrontendPath);

        // Ignore non-disk devices
        deviceTypePath = Xmasprintf("device/vbd/%s/device-type",
                                    dirEntries[i]);
        if (!deviceTypePath) {
            res = STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }
        res = xenbus_read(XBT_NIL, deviceTypePath, &deviceType);
        XmFreeMemory(deviceTypePath);
        if (res != STATUS_SUCCESS)
        {
            TraceError(("%s: failed to read device type for VBD %s (%08x)\n",
                        __FUNCTION__, dirEntries[i], res));
            goto out;
        }
        if (strcmp(deviceType, "disk")) {
            TraceNotice(("%s: ignoring %s (VBD %s)\n", __FUNCTION__, deviceType, dirEntries[i]));
            XmFreeMemory(deviceType);
            continue;
        }

        XmFreeMemory(deviceType);

        TraceNotice(("%s: found new disk (VBD %s)\n", __FUNCTION__, dirEntries[i]));
        newDisks[nrNewDisks++] = dirEntries[i];
        dirEntries[i] = NULL;
    }

    /* Check for targets that have been ejected or have disappeared */
    Irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    for (i = 0; i < XENVBD_MAX_DISKS; i++) {
        targetInfo = XenvbdTargetInfo[i];
        if (targetInfo != NULL) {
            XM_ASSERT(!targetInfo->Condemned);
            if (targetInfo->Ejected) {
                TraceNotice (("%s: ejected disk %d.\n", __FUNCTION__, targetInfo->handle));
                targetInfo->Condemned = TRUE;
                release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

                XenvbdRequestRescan();

                res = STATUS_SUCCESS;
                goto out;
            } else if (targetInfo->SurpriseRemoved) {
                TraceNotice (("%s: surprise removed disk %d.\n", __FUNCTION__, targetInfo->handle));
                targetInfo->Condemned = TRUE;
                release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

                XenvbdRequestRescan();

                res = STATUS_SUCCESS;
                goto out;
            } else if (targetInfo->Disappeared) {
                TraceNotice (("%s: disk %d disappeared.\n", __FUNCTION__, targetInfo->handle));
                targetInfo->Condemned = TRUE;
                release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

                XenvbdRequestRescan();

                res = STATUS_SUCCESS;
                goto out;
            } else if (targetInfo->Suspended || targetInfo->Resuming) {
                TraceNotice (("%s: disk %d suspended.\n", __FUNCTION__, targetInfo->handle));
                release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

                XenvbdRequestRescan();

                res = STATUS_SUCCESS;
                goto out;
            } else if (targetInfo->Resumed) {
                targetInfo->Resumed = FALSE;
                release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

                XenvbdRequestRescan();

                res = STATUS_SUCCESS;
                goto out;

            } else if (targetInfo->EnumPending) {
                targetInfo->Disappeared = TRUE;
                release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

                XenvbdRequestInvalidate(); // Invalidate to cause SURPRISE_REMOVAL (unless EJECT is pending)

                res = STATUS_SUCCESS;
                goto out;
            }
        }
    }
    release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

    if (nrNewDisks == 0) {
        /* No new entries -> don't do anything */
        res = STATUS_SUCCESS;
        goto out;
    }

    /* For each new device, figure out where it is in xenbus and what
       its device id is. */
    devicePaths = XmAllocateZeroedMemory(nrNewDisks * sizeof(devicePaths[0]));
    deviceIds = XmAllocateZeroedMemory(nrNewDisks * sizeof(deviceIds[0]));
    if (devicePaths == NULL || deviceIds == NULL) {
        res = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    for (i = 0; i < nrNewDisks; i++) {
        ULONG64 tmp;

        devicePaths[i] = Xmasprintf("device/vbd/%s", newDisks[i]);
        if (!devicePaths[i]) {
            res = STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }

        (void)xenbus_read_int(XBT_NIL, devicePaths[i], "virtual-device",
                              &tmp);
        deviceIds[i] = (int)tmp;
    }

    /* Sort the list so that hda appears as slot 0, hdb as 1, etc. */
    SortDeviceListToMatchQemu(devicePaths, deviceIds, newDisks, nrNewDisks);

    /* Merge them in. */
    for (i = 0; i < nrNewDisks; i++) {
        for (j = 0; j < XENVBD_MAX_DISKS; j++) {
            targetInfo = XenvbdTargetInfo[j];
            if (targetInfo != NULL) {
                XM_ASSERT(strcmp(targetInfo->xenbusNodeName, devicePaths[i]) != 0);
                continue;
            }

            res = XenbusSetupTarget(j, devicePaths[i]);
            if (NT_SUCCESS(res)) {
                devicePaths[i] = NULL;
                break;
            }

            TraceWarning(("%s: failed to set up %s...\n", __FUNCTION__, devicePaths[i]));
            goto out;
        }
        if (j == XENVBD_MAX_DISKS)
            TraceWarning (("%s: couldn't attach all disks, ignoring VBD %s.\n",
                           __FUNCTION__, devicePaths[i]));
    }

    XenvbdRequestInvalidate();
    res = STATUS_SUCCESS;

 out:
    if (dirEntries) {
        for (i = 0; dirEntries[i]; i++)
            XmFreeMemory(dirEntries[i]);
        XmFreeMemory(dirEntries);
    }
    if (devicePaths) {
        for (i = 0; i < nrNewDisks; i++)
            XmFreeMemory(devicePaths[i]);
        XmFreeMemory(devicePaths);
    }
    if (newDisks) {
        for (i = 0; i < nrNewDisks; i++)
            XmFreeMemory(newDisks[i]);
        XmFreeMemory(newDisks);
    }
    XmFreeMemory(deviceIds);

    TraceVerbose(("%s: <====\n", __FUNCTION__));
    return res;
}

FAST_MUTEX XenvbdEnumLock;

VOID
__XenvbdScanTargets(
    IN  const CHAR      *Caller
    )
{
    XHBD_TARGET_INFO    *List = NULL;
    ULONG               TargetId;
    KIRQL               Irql;

    XM_ASSERT(!AustereMode);
    XM_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    TraceNotice(("%s: scanning targets...\n", Caller));

    ExAcquireFastMutex(&XenvbdEnumLock);

    XenbusFindVbds();

    // Before we drop the mutex we need to extract any condemned targets
    // from the array
    Irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    for (TargetId = 0; TargetId < (ULONG)XENVBD_MAX_DISKS; TargetId++) {
        XHBD_TARGET_INFO *Target = XenvbdTargetInfo[TargetId];

        if (Target == NULL)
            continue;

        if (Target->Suspended)
            continue;

        if (Target->Condemned) {
            // Clear the target from the array to prevent any further references
            // from being taken
            XenvbdTargetInfo[TargetId] = NULL;

            // Add it to the condemned list
            XM_ASSERT(Target->Next == NULL);
            Target->Next = List;
            List = Target;

            continue;
        }

        TraceNotice(("%s: target %d -> %s %s\n", __FUNCTION__,
                     TargetId,
                     Target->xenbusNodeName,
                     (Target->Disappeared) ? "[DISAPPEARED]" : ""));
    }
    release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

    ExReleaseFastMutex(&XenvbdEnumLock);

    // Destroy any condemned targets
    while (List != NULL) {
        XHBD_TARGET_INFO    *Target = List;
        BOOLEAN             Destroy;

        List = Target->Next;
        Target->Next = NULL;

        ExAcquireFastMutex(&Target->StateLock);
        // If the target is started then we must wait for the SURPRISE_REMOVAL or EJECT IRP to clean up
        // as scsifilt may be attached.
        // If the target is not started then we cannot rely on getting a SURPRISE_REMOVAL
        // IRP, but there is no chance of scsifilt having attached so we can clean
        // up immediately.
        Destroy = !Target->Started;
        ExReleaseFastMutex(&Target->StateLock);

        if (Destroy)
            XenbusDestroyTarget(Target);
        else
            TraceNotice(("target %d: deferring destruction.\n", List->targetId));
    }
}

VOID
XenvbdSetupAustereTarget(
    VOID)
{
    ULONG   TargetId;
    ULONG   OperatingMode = GetOperatingMode();
    BOOLEAN Enumerated;

    XM_ASSERT(OperatingMode != NORMAL_MODE);

    TraceNotice(("%s: ====>\n", __FUNCTION__));

    Enumerated = FALSE;
    for (TargetId = 0; TargetId < (ULONG)XENVBD_MAX_DISKS; TargetId++) {
        CHAR *TargetPath;
        BOOLEAN Hibernation;
        BOOLEAN DumpFile;
        CHAR *Path;
        CHAR *FrontendPath;
        NTSTATUS status;

        TargetPath = Xmasprintf("data/scsi/target/%d", TargetId);
        XM_ASSERT(TargetPath != NULL);

        (VOID) xenbus_read_feature_flag(XBT_NIL, TargetPath, "hibernation", &Hibernation);
        (VOID) xenbus_read_feature_flag(XBT_NIL, TargetPath, "dump", &DumpFile);

        XmFreeMemory(TargetPath);

        if (OperatingMode == HIBER_MODE) {
            if (!Hibernation)
                continue;
        } else if (OperatingMode == DUMP_MODE) {
            if (!DumpFile)
                continue;
        }

    use_this_device:
        Path = Xmasprintf("data/scsi/target/%d/frontend", TargetId);
        XM_ASSERT(Path != NULL);

        status = xenbus_read(XBT_NIL, Path, &FrontendPath);
        XmFreeMemory(Path);

        if (!NT_SUCCESS(status))
            continue;

        XM_ASSERT(FrontendPath != NULL);
        TraceInfo(("target %d -> %s\n", TargetId, FrontendPath));

        status = XenbusSetupTarget(TargetId, FrontendPath);
        XM_ASSERT(NT_SUCCESS(status));

        XmFreeMemory(FrontendPath);

        Enumerated = TRUE;
        break;
    }

    if (!Enumerated && OperatingMode == DUMP_MODE) {
        /* Didn't find a crash device, probably means we crashed in an
           unfortunate place while reinitialising following
           suspend/resume.  Assume that we just need the first one. */
        TargetId = 0;
        goto use_this_device;
    }

    XM_ASSERT(Enumerated);

    TraceNotice(("%s: <====\n", __FUNCTION__));
}

struct bounce_buffer {
    int next;
    PVOID vaddr;
    PHYSICAL_ADDRESS paddr;
};

#define NR_BOUNCE_BUFFERS 128

static struct bounce_buffer BounceBuffers[NR_BOUNCE_BUFFERS];
static int NextBounceBuffer;
static int FreeBounceBuffers;
static int MinFreeBounceBuffers;
#define FREE_BOUNCE_BUFFER_THRESH MAX_SG_SEGMENTS
static struct irqsafe_lock BounceBufferLock;

void InitBounceBuffers(void)
{
    int x;
    int target_buffers;
    int prev = -1;

    /* In austere mode, we don't support scatter gather or large
       requests, so we can get away with a very small pool of
       bounce buffers. */
    if (AustereMode)
        target_buffers = 2;
    else
        target_buffers = NR_BOUNCE_BUFFERS;
    NextBounceBuffer = 0;
    FreeBounceBuffers = 0;
    for (x = 0; x < target_buffers; x++) {
        if (!BounceBuffers[x].vaddr) {
            BounceBuffers[x].vaddr =
                XmAllocatePhysMemory(PAGE_SIZE,
                                     &BounceBuffers[x].paddr);
        }
        if (!BounceBuffers[x].vaddr)
            continue; /* Ignore this one and hope for the best.  This
                         shouldn't ever happen: we're called early
                         enough that we should always be able to get
                         enough memory and grant references. */
        /* Hook it into the free list. */
        if (prev != -1)
            BounceBuffers[prev].next = x;
        FreeBounceBuffers++;
        prev = x;
    }
    MinFreeBounceBuffers = FreeBounceBuffers;
    if (prev == -1)
        NextBounceBuffer = -1;
    else
        BounceBuffers[prev].next = -1;
}

typedef int BUFFER_ID;

static BUFFER_ID AllocateBounceBuffer(void)
{
    int res;
    KIRQL irql;
    static int warned;

    irql = acquire_irqsafe_lock(&BounceBufferLock);
    res = NextBounceBuffer;
    if (res == -1) {
        release_irqsafe_lock(&BounceBufferLock, irql);
        if (!warned) {
            TraceWarning(("Out of bounce buffers!\n"));
            warned = 1;
        }
        return res;
    }
    NextBounceBuffer = BounceBuffers[res].next;
    XM_ASSERT(FreeBounceBuffers != 0);
    FreeBounceBuffers--;
    if (FreeBounceBuffers < MinFreeBounceBuffers)
        MinFreeBounceBuffers = FreeBounceBuffers;
    release_irqsafe_lock(&BounceBufferLock, irql);
    return res;
}

static void FreeBounceBuffer(BUFFER_ID bid)
{
    KIRQL irql;
    int x;

    irql = acquire_irqsafe_lock(&BounceBufferLock);
    BounceBuffers[bid].next = NextBounceBuffer;
    NextBounceBuffer = bid;
    FreeBounceBuffers++;
    release_irqsafe_lock(&BounceBufferLock, irql);

    irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    for (x = 0; x < XENVBD_MAX_DISKS; x++) {
        PXHBD_TARGET_INFO ptargetInfo = XenvbdTargetInfo[x];
        
        if (ptargetInfo != NULL &&
            ptargetInfo->NeedsWakeWhenBuffersAvail) {
            ptargetInfo->NeedsWakeWhenBuffersAvail = FALSE;
            EvtchnRaiseLocally(ptargetInfo->evtchn_port);
        }
    }
    release_irqsafe_lock(XenvbdTargetInfoLock, irql);
}

#define GetBounceBuffer(x) (&BounceBuffers[(x)])

static ULONG64
GetStartLogicalBlock(
    IN  PSCSI_REQUEST_BLOCK Srb)
{
    PCDB                    Cdb = (PCDB)Srb->Cdb;
    ULONG64                 Index = 0;

    switch (Srb->CdbLength) {
    case 6:
        Index = (ULONG64)Cdb->CDB6READWRITE.LogicalBlockLsb;
        Index |= (ULONG64)Cdb->CDB6READWRITE.LogicalBlockMsb0 << 8;
        Index |= (ULONG64)Cdb->CDB6READWRITE.LogicalBlockMsb1 << 16;
        break;

    case 10:
        Index = (ULONG64)Cdb->CDB10.LogicalBlockByte3;
        Index |= (ULONG64)Cdb->CDB10.LogicalBlockByte2 << 8;
        Index |= (ULONG64)Cdb->CDB10.LogicalBlockByte1 << 16;
        Index |= (ULONG64)Cdb->CDB10.LogicalBlockByte0 << 24;
        break;

    case 12: {
        ULONG Value;

        REVERSE_BYTES(&Value, &Cdb->CDB12.LogicalBlock);
        Index = (ULONG64)Value;
        break;
    }
    case 16:
        REVERSE_BYTES_QUAD(&Index, &Cdb->CDB16.LogicalBlock);
        break;

    default:
        XM_BUG();
        break;
    }

    return Index;
}

/* This gets called if either we run out of grant references in
   non-scsifilt mode, or a request manages to leak past scsifilt in
   scsifilt mode.  If we're in non-scsifilt mode, kick all the targets
   to get them going again; otherwise, poll the filters to see if
   they've got any non-filter requests which need completing. */
VOID
XenvbdTimerFunc(PHW_DEVICE_EXTENSION devExt)
{
    ULONG j;
    KIRQL irql;

    irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    for (j = 0; j < (ULONG)XENVBD_MAX_DISKS; j++) {
        PXHBD_TARGET_INFO ptargetInfo = XenvbdTargetInfo[j];

        if (ptargetInfo != NULL) {
            if (ptargetInfo->FilterTarget.scsifilt)
                XenvbdFilterPoll(ptargetInfo);
            else
                EvtchnRaiseLocally(ptargetInfo->evtchn_port);
        }
    }
    release_irqsafe_lock(XenvbdTargetInfoLock, irql);
}

#define BTOPR(_bytes)   (((_bytes) + PAGE_OFFSET) >> PAGE_SHIFT)

static VOID
PrepareSrb(PXHBD_TARGET_INFO ptargetInfo, PSCSI_REQUEST_BLOCK srb)
{
    PSRB_EXTENSION srb_extension = SrbExtension(srb);
    ULONG64 start_sector;
    ULONG nr_sectors;
    ULONG sectors_done;
    ULONG nr_segments;
    ULONG segments_done;
    UCHAR operation;
    GRANT_MODE mode;
    ULONG i;

    XM_ASSERT(!srb_extension->bounced);

    start_sector = GetStartLogicalBlock(srb);
    nr_sectors = srb->DataTransferLength / SECTOR_SIZE(ptargetInfo);

    nr_segments = (ULONG)BTOPR(((ULONG_PTR)srb->DataBuffer & PAGE_OFFSET) + srb->DataTransferLength);

    if (nr_segments > XENVBD_MAX_SEGMENTS_PER_SRB) {
        TraceError(("%s: target %d: OP too big (%d pages)\n", __FUNCTION__,
                    ptargetInfo->targetId,
                    nr_segments));
        srb->ScsiStatus = 0x40; /* SCSI ABORTED */
        srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;

        CompleteSrb(srb);
        return;
    }

    srb_extension->nr_requests = (nr_segments + XENVBD_MAX_SEGMENTS_PER_REQUEST - 1) /
                                 XENVBD_MAX_SEGMENTS_PER_REQUEST;

    if (srb->Cdb[0] == SCSIOP_READ6 ||
        srb->Cdb[0] == SCSIOP_READ ||
        srb->Cdb[0] == SCSIOP_READ12 ||
        srb->Cdb[0] == SCSIOP_READ16)
        operation = BLKIF_OP_READ;
    else
        operation = BLKIF_OP_WRITE;

    if (operation == BLKIF_OP_WRITE)
        mode = GRANT_MODE_RO;
    else
        mode = GRANT_MODE_RW;

    TraceDebug(("%s: target %d: SRB 0x%p %s [%016llx - %016llx) => %d request(s)\n", __FUNCTION__,
                ptargetInfo->targetId,
                srb,
                (operation == BLKIF_OP_READ) ? "READ" : "WRITE",
                start_sector,
                start_sector + nr_sectors,
                srb_extension->nr_requests));

    segments_done = 0;
    sectors_done = 0;
    for (i = 0; i < srb_extension->nr_requests; i++) {
        xenvbd_request_t *request;
        ULONG segments_this_time;
        ULONG j;

        request = &(srb_extension->request[i]);

        XM_ASSERT(((ULONG_PTR)srb & XENVBD_REQUEST_MASK) == 0);
        request->id = (ULONG_PTR)srb | i;

        request->operation = operation;
        request->handle = ptargetInfo->handle;
        request->first_sector = start_sector + sectors_done;

        segments_this_time = MIN(nr_segments - segments_done,
                                 XENVBD_MAX_SEGMENTS_PER_REQUEST);

        request->nr_segments = (UCHAR)segments_this_time;

        TraceDebug(("%s: target %d: REQ%d (%d segments)\n", __FUNCTION__,
                    ptargetInfo->targetId,
                    i,
                    segments_this_time));

        for (j = 0; j < segments_this_time; j++) {
            ULONG sectors_this_time;
            ULONG first_sect, last_sect;
            PUCHAR vaddr;
            PHYSICAL_ADDRESS paddr;
            ULONG Length;
            GRANT_REF gref;

            vaddr = (PUCHAR)srb->DataBuffer + (sectors_done * SECTOR_SIZE(ptargetInfo));
            paddr = ScsiPortGetPhysicalAddress(XenvbdDeviceExtension,
                                               srb,
                                               vaddr,
                                               &Length);

            first_sect = (ULONG)((paddr.QuadPart & PAGE_OFFSET) / SECTOR_SIZE(ptargetInfo));
            sectors_this_time = MIN(nr_sectors - sectors_done,
                                    NR_SECTORS_PER_PAGE(ptargetInfo) - first_sect);
            XM_ASSERT(Length >= sectors_this_time * SECTOR_SIZE(ptargetInfo));
            last_sect = first_sect + sectors_this_time - 1;

            gref = GnttabGrantForeignAccessCache(ptargetInfo->backendId,
                                                 PHYS_TO_PFN(paddr),
                                                 mode,
                                                 ptargetInfo->grant_cache);
            XM_ASSERT(!is_null_GRANT_REF(gref));

            request->seg[j].gref = gref;
            request->seg[j].first_sect = first_sect;
            request->seg[j].last_sect = last_sect;

            TraceDebug(("%s: target %d: SEG%d [%016llx - %016llx) [%02x - %02x]\n", __FUNCTION__,
                        ptargetInfo->targetId,
                        j,
                        start_sector + sectors_done,
                        start_sector + sectors_done + sectors_this_time,
                        first_sect,
                        last_sect));

            sectors_done += sectors_this_time;
        }
        segments_done += segments_this_time;

        request->last_sector = start_sector + sectors_done - 1;
    }
    XM_ASSERT(segments_done == nr_segments);
    XM_ASSERT(sectors_done == nr_sectors);

    ptargetInfo->granted_srbs++;
    QueueSrbRaw(srb, &ptargetInfo->PreparedSrbs);
}

static VOID
PrepareBouncedSrb(PXHBD_TARGET_INFO ptargetInfo, PSCSI_REQUEST_BLOCK srb)
{
    PSRB_EXTENSION srb_extension = SrbExtension(srb);
    ULONG64 start_sector;
    ULONG nr_sectors;
    ULONG sectors_done;
    ULONG nr_segments;
    ULONG segments_done;
    UCHAR operation;
    GRANT_MODE mode;
    ULONG i;

    XM_ASSERT(srb_extension->bounced);

    start_sector = GetStartLogicalBlock(srb);
    nr_sectors = srb->DataTransferLength / SECTOR_SIZE(ptargetInfo);

    nr_segments = BTOPR(srb->DataTransferLength);

    if (nr_segments > XENVBD_MAX_SEGMENTS_PER_SRB) {
        TraceError(("%s: target %d: OP too big (%d pages)\n", __FUNCTION__,
                    ptargetInfo->targetId,
                    nr_segments));
        srb->ScsiStatus = 0x40; /* SCSI ABORTED */
        srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;

        CompleteSrb(srb);
        return;
    }

    srb_extension->nr_requests = (nr_segments + XENVBD_MAX_SEGMENTS_PER_REQUEST - 1) /
                                 XENVBD_MAX_SEGMENTS_PER_REQUEST;

    if (srb->Cdb[0] == SCSIOP_READ6 ||
        srb->Cdb[0] == SCSIOP_READ ||
        srb->Cdb[0] == SCSIOP_READ12 ||
        srb->Cdb[0] == SCSIOP_READ16)
        operation = BLKIF_OP_READ;
    else
        operation = BLKIF_OP_WRITE;

    if (operation == BLKIF_OP_WRITE)
        mode = GRANT_MODE_RO;
    else
        mode = GRANT_MODE_RW;

    TraceDebug(("%s: target %d: SRB 0x%p %s [%016llx - %016llx) => %d request(s)\n", __FUNCTION__,
                ptargetInfo->targetId,
                srb,
                (operation == BLKIF_OP_READ) ? "READ" : "WRITE",
                start_sector,
                start_sector + nr_sectors,
                srb_extension->nr_requests));

    segments_done = 0;
    sectors_done = 0;
    for (i = 0; i < srb_extension->nr_requests; i++) {
        xenvbd_request_t *request;
        ULONG segments_this_time;
        ULONG j;

        request = &(srb_extension->request[i]);

        XM_ASSERT(((ULONG_PTR)srb & XENVBD_REQUEST_MASK) == 0);
        request->id = (ULONG_PTR)srb | i;

        request->operation = operation;
        request->handle = ptargetInfo->handle;
        request->first_sector = start_sector + sectors_done;

        segments_this_time = MIN(nr_segments - segments_done,
                                 XENVBD_MAX_SEGMENTS_PER_REQUEST);

        request->nr_segments = (UCHAR)segments_this_time;

        TraceDebug(("%s: target %d: REQ%d (%d segments)\n", __FUNCTION__,
                    ptargetInfo->targetId,
                    i,
                    segments_this_time));

        for (j = 0; j < segments_this_time; j++) {
            struct bounce_buffer *buffer;
            ULONG sectors_this_time;
            BUFFER_ID bid;
            GRANT_REF gref;
            ULONG offset;
            ULONG length;

            sectors_this_time = MIN(nr_sectors - sectors_done,
                                    NR_SECTORS_PER_PAGE(ptargetInfo));

            bid = AllocateBounceBuffer();
            if (bid < 0)
                goto cleanup;

            buffer = GetBounceBuffer(bid);
            offset = sectors_done * SECTOR_SIZE(ptargetInfo);
            length = sectors_this_time * SECTOR_SIZE(ptargetInfo);

            memcpy(buffer->vaddr,
                   (PUCHAR)srb->DataBuffer + offset,
                   length);

            gref = GnttabGrantForeignAccessCache(ptargetInfo->backendId,
                                                 PHYS_TO_PFN(buffer->paddr),
                                                 mode,
                                                 ptargetInfo->grant_cache);
            XM_ASSERT(!is_null_GRANT_REF(gref));

            request->seg[j].gref = gref;
            request->seg[j].first_sect = 0;
            request->seg[j].last_sect = sectors_this_time - 1;
            request->seg[j].bid = bid;
            request->seg[j].offset = offset;
            request->seg[j].length = length;

            TraceDebug(("%s: target %d: SEG%d [%016llx - %016llx) [%02x - %02x] (bid %d)\n", __FUNCTION__,
                        ptargetInfo->targetId,
                        j,
                        start_sector + sectors_done,
                        start_sector + sectors_done + sectors_this_time,
                        0,
                        sectors_this_time - 1,
                        bid));

            sectors_done += sectors_this_time;
        }
        segments_done += segments_this_time;

        request->last_sector = start_sector + sectors_done - 1;
    }
    XM_ASSERT(segments_done == nr_segments);
    XM_ASSERT(sectors_done == nr_sectors);

    ptargetInfo->bounced_srbs++;
    QueueSrbRaw(srb, &ptargetInfo->PreparedSrbs);
    return;

cleanup:
    TraceDebug(("%s: target %d: SRB 0x%p: out of bounce buffers\n", __FUNCTION__,
                ptargetInfo->targetId, srb));
    CleanupSrb(ptargetInfo, srb);

    ptargetInfo->NeedsWakeWhenBuffersAvail = TRUE;
    QueueSrbAtHeadRaw(srb, &ptargetInfo->FreshSrbs);
}

static VOID
copy_to_req(xenvbd_request_t *src, blkif_request_t *dst)
{
    ULONG j;

    dst->operation = (uint8_t)src->operation;
    dst->nr_segments = (uint8_t)src->nr_segments;
    dst->handle = (blkif_vdev_t)src->handle;
    dst->id = (uint64_t)src->id;
    dst->sector_number = (blkif_sector_t)src->first_sector;

    for (j = 0; j < src->nr_segments; j++) {
        dst->seg[j].gref = xen_GRANT_REF(src->seg[j].gref);
        dst->seg[j].first_sect = (uint8_t)src->seg[j].first_sect;
        dst->seg[j].last_sect = (uint8_t)src->seg[j].last_sect;
    }
}

/* Submit a prepared SRB to the backend. */
static BOOLEAN
SubmitSrb(PXHBD_TARGET_INFO ptargetInfo, PSCSI_REQUEST_BLOCK srb)
{
    SRB_EXTENSION *srb_ext = SrbExtension(srb);
    ULONG i;
    int notify;

    if (RING_PROD_SLOTS_AVAIL(&ptargetInfo->ring) < srb_ext->nr_requests)
        return FALSE;

    for (i = 0; i < srb_ext->nr_requests; i++) {
        blkif_request_t *req;

        req = RING_GET_REQUEST(&ptargetInfo->ring,
                               ptargetInfo->ring.req_prod_pvt);

        copy_to_req(&srb_ext->request[i], req);

        TraceDebug(("%s: target %d: SRB 0x%p REQ%d ID=%016llx", __FUNCTION__,
                    ptargetInfo->targetId, srb, i, req->id));

        ptargetInfo->ring.req_prod_pvt =
            RING_IDX_PLUS(ptargetInfo->ring.req_prod_pvt, 1);
    }

    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&ptargetInfo->ring, notify);
    if (notify)
        EvtchnNotifyRemote(ptargetInfo->evtchn_port);

    srb->SrbStatus = SRB_STATUS_SUCCESS;
    return TRUE;
}

static void
SubmitPreparedSrbs(PXHBD_TARGET_INFO ptargetInfo)
{
    PSCSI_REQUEST_BLOCK srb;

    while (1) {
        srb = PeekSrb(&ptargetInfo->PreparedSrbs);
        if (!srb)
            break;
        if (!SubmitSrb(ptargetInfo, srb))
            break;
        RemoveSrbFromQueueRaw(srb, &ptargetInfo->PreparedSrbs);
        QueueSrbRaw(srb, &ptargetInfo->SubmittedSrbs);
    }
}

/* Used to prepare and submit SRBs which don't need to go through the
   slow path thread. */
VOID
XenvbdStartFastSrb(PSCSI_REQUEST_BLOCK srb, PXHBD_TARGET_INFO ptargetInfo)
{
    PrepareSrb(ptargetInfo, srb);
    SubmitPreparedSrbs(ptargetInfo);
}

VOID
XenvbdEvtchnCallback(PVOID Context)
{
    PXHBD_TARGET_INFO ptargetInfo = Context;
    PSCSI_REQUEST_BLOCK srb, next;

    XenvbdCompleteRequests(ptargetInfo);

    if (ptargetInfo->FreshSrbs.head) {
        for (srb = ptargetInfo->FreshSrbs.head; srb; srb = next) {
            next = SrbExtension(srb)->next;
            RemoveSrbFromQueueRaw(srb, &ptargetInfo->FreshSrbs);
            if ( SrbExtension(srb)->bounced) {
                /* PrepareSrb will only ever requeue srbs to the
                 *head* of the fresh list, so we know we're not going
                 to see this one again before we hit the end of the
                 list, so won't deadlock. */
                PrepareBouncedSrb(ptargetInfo, srb);
            } else {
                PrepareSrb(ptargetInfo, srb);
            }
        }
    }

    SubmitPreparedSrbs(ptargetInfo);

    MaybeCompleteShutdownSrbs(ptargetInfo);
}

static VOID
XenvbdCompleteRequests(PXHBD_TARGET_INFO ptargetInfo)
{
    RING_IDX prod;
    ULONG not_done;
    PSRB_EXTENSION srb_ext;

again:
    prod = ptargetInfo->ring.sring->rsp_prod;
    XsMemoryBarrier();
    while (!RING_IDXS_EQ(ptargetInfo->ring.rsp_cons, prod)) {
        blkif_response_t *rsp;
        xenvbd_request_t *request;
        PSCSI_REQUEST_BLOCK srb;
        ULONG i;

        rsp = RING_GET_RESPONSE(&ptargetInfo->ring,
                                ptargetInfo->ring.rsp_cons);

        srb = (PSCSI_REQUEST_BLOCK)(ULONG_PTR)(rsp->id & ~XENVBD_REQUEST_MASK);
        i = (ULONG)(rsp->id & XENVBD_REQUEST_MASK);

        TraceDebug(("%s: target %d: ID=%016llx -> SRB 0x%p REQ%d ID=%016llx\n", __FUNCTION__,
                    ptargetInfo->targetId, rsp->id, srb, i));

        ptargetInfo->ring.rsp_cons = RING_IDX_PLUS(ptargetInfo->ring.rsp_cons, 1);

        srb_ext = SrbExtension(srb);
        request = &(srb_ext->request[i]);

        switch(rsp->operation) {
            case BLKIF_OP_READ:
            case BLKIF_OP_WRITE: {
                ULONG j;

                /* SRB defaults to successful completion */
                if (!AustereMode && rsp->status != BLKIF_RSP_OKAY)
                    srb->SrbStatus = SRB_STATUS_ERROR;

                for (j = 0; j < request->nr_segments; j++) {
                    GRANT_REF gref = request->seg[j].gref;

                    XM_ASSERT(!is_null_GRANT_REF(gref));
                    GnttabEndForeignAccessCache(gref, ptargetInfo->grant_cache);

                    if (srb_ext->bounced) {
                        BUFFER_ID bid = request->seg[j].bid;
                        ULONG offset = request->seg[j].offset;
                        ULONG length = request->seg[j].length;
                        struct bounce_buffer *buffer;

                        XM_ASSERT(bid >= 0);
                        buffer = GetBounceBuffer(bid);

                        memcpy((PUCHAR)srb->DataBuffer + offset,
                               buffer->vaddr,
                               length);

                        FreeBounceBuffer(bid);
                    }
                }
                memset(request, 0, sizeof (xenvbd_request_t));

                break;
            }
            default:
                TraceError(("%s: bogus request (SRB 0x%p REQ%d)\n", __FUNCTION__, srb, i));
                break;
        }

        XM_ASSERT(srb_ext->nr_requests != 0);
        if (--srb_ext->nr_requests == 0) {
            ptargetInfo->completed_srbs++;
            if (srb->SrbStatus == SRB_STATUS_SUCCESS) {
                srb->ScsiStatus = 0x00; /* SCSI GOOD */
            } else {
                srb->ScsiStatus = 0x40; /* SCSI ABORTED */
                ptargetInfo->aborted_srbs++;
            }

            RemoveSrbFromQueueRaw(srb, &ptargetInfo->SubmittedSrbs);

            CompleteSrb(srb);
        }
    }

    RING_FINAL_CHECK_FOR_RESPONSES(&ptargetInfo->ring, not_done);
    if (not_done) {
        DBGMSG(("XENVBD: CompleteRequests: FINAL_CHECK %d\n", 
            not_done));
        goto again;
    }
}

static VOID
XenvbdDebugTarget(PXHBD_TARGET_INFO ptargetInfo)
{
    unsigned j;
    blkif_front_ring_t *ring = &ptargetInfo->ring;
    blkif_request_t *req;
    blkif_response_t *resp;
    RING_IDX idx;

    if (ring->sring) {
        TraceInternal(("req_prod %x, req_prod_pvt %x, resp_prod %x, resp_cons %x.\n",
                   ring->sring->req_prod,
                   ring->req_prod_pvt,
                   ring->sring->rsp_prod,
                   ring->rsp_cons));
        TraceInternal(("Requests pending:\n"));
        for (idx = RING_IDX_PLUS(ring->sring->rsp_prod, 1);
             idx.__idx < ring->req_prod_pvt.__idx;
             idx = RING_IDX_PLUS(idx, 1)) {
            req = RING_GET_REQUEST(ring, idx);
            TraceInternal(("%x: op %d, n %d, handle %x, id %x:%x, sect %x:%x\n",
                       idx, req->operation, req->nr_segments,
                       req->handle, req->id, req->sector_number));
            for (j = 0;
                 j < req->nr_segments && j < BLKIF_MAX_SEGMENTS_PER_REQUEST;
                 j++)
                TraceInternal(("\t%d: gref %d [%d,%d]\n",
                           j,
                           req->seg[j].gref,
                           req->seg[j].first_sect,
                           req->seg[j].last_sect));
        }
        TraceInternal(("Responses pending:\n"));
        for (idx = ring->rsp_cons;
             idx.__idx < ring->sring->rsp_prod.__idx;
             idx = RING_IDX_PLUS(idx, 1)) {
            resp = RING_GET_RESPONSE(ring, idx);
            TraceInternal(("%x: id %I64x, operation %d, status %d.\n",
                       idx, resp->id, resp->operation, resp->status));
        }
    }

    if (XenvbdDeviceExtension->resetInProgress)
        TraceInternal(("Reset in progress.\n"));

    TraceInternal(("%d SRBs bounced, %d granted.\n",
                 ptargetInfo->bounced_srbs,
                 ptargetInfo->granted_srbs));
    ptargetInfo->bounced_srbs = 0;
    ptargetInfo->granted_srbs = 0;

    TraceInternal(("Fresh: %d cur, %d max, %d tot.\n",
                 ptargetInfo->FreshSrbs.srbs_cur,
                 ptargetInfo->FreshSrbs.srbs_max,
                 ptargetInfo->FreshSrbs.srbs_ever));
    ptargetInfo->FreshSrbs.srbs_ever = 0;
    ptargetInfo->FreshSrbs.srbs_max = ptargetInfo->FreshSrbs.srbs_cur;

    TraceInternal(("Prepared: %d cur, %d max, %d tot.\n",
                 ptargetInfo->PreparedSrbs.srbs_cur,
                 ptargetInfo->PreparedSrbs.srbs_max,
                 ptargetInfo->PreparedSrbs.srbs_ever));
    ptargetInfo->PreparedSrbs.srbs_ever = 0;
    ptargetInfo->PreparedSrbs.srbs_max = ptargetInfo->PreparedSrbs.srbs_cur;

    TraceInternal(("Submitted: %d cur, %d max, %d tot.\n",
                 ptargetInfo->SubmittedSrbs.srbs_cur,
                 ptargetInfo->SubmittedSrbs.srbs_max,
                 ptargetInfo->SubmittedSrbs.srbs_ever));
    ptargetInfo->SubmittedSrbs.srbs_ever = 0;
    ptargetInfo->SubmittedSrbs.srbs_max = ptargetInfo->SubmittedSrbs.srbs_cur;

    TraceInternal(("Completed: %d (%d aborted)\n",
                 ptargetInfo->completed_srbs,
                 ptargetInfo->aborted_srbs));
    ptargetInfo->completed_srbs = 0;
    ptargetInfo->aborted_srbs = 0;

    TraceInternal(("%d redirected srbs, of which %d still outstanding, %d pending.\n",
                 ptargetInfo->FilterTarget.total_redirected_srbs,
                 ptargetInfo->FilterTarget.outstanding_redirected_srbs,
                 ptargetInfo->FilterTarget.pending_redirect_complete.srbs_cur));
}

VOID
XenvbdDebugCallback(PVOID ctxt)
{
    PHW_DEVICE_EXTENSION ext = ctxt;
    int i;
    NTSTATUS stat;
    KIRQL irql;

    stat = try_acquire_irqsafe_lock(XenvbdTargetInfoLock, &irql);
    if (NT_SUCCESS(stat)) {
        for (i = 0; i < XENVBD_MAX_DISKS; i++) {
            PXHBD_TARGET_INFO targetInfo; 

            if ((targetInfo = XenvbdTargetInfo[i]) != NULL) {
                TraceInternal(("Target %d:\n", i));
                XenvbdDebugTarget(targetInfo);
            }
        }
        release_irqsafe_lock(XenvbdTargetInfoLock, irql);
    } else {
        TraceInternal(("Target lock is busy.\n"));
    }
    TraceInternal(("%d bounce buffers free, %d min.\n",
                 FreeBounceBuffers, MinFreeBounceBuffers));
    MinFreeBounceBuffers = FreeBounceBuffers;

    TraceInternal(("%d in xenvbd, %d max.\n", ext->totInFlight,
                 ext->maxTotInFlight));
    ext->maxTotInFlight = ext->totInFlight;
}

/* Disconnect from the backend.  This is only used when the driver is
   being unloaded, and so only during the HCTs. */
VOID 
XenbusDisconnectBackend(PXHBD_TARGET_INFO TargetInfo)
{
    BOOLEAN online;
    XENBUS_STATE state;
    SUSPEND_TOKEN token;
    CHAR *BackendPath;

    token = EvtchnAllocateSuspendToken("xenvbd disconnect");

    BackendPath = find_backend_path(TargetInfo, token);
    if (!BackendPath)
        goto done;

    xenbus_read_feature_flag(XBT_NIL, BackendPath, "online", &online);

    xenbus_change_state(XBT_NIL, TargetInfo->xenbusNodeName, "state",
                        XENBUS_STATE_CLOSED);

    state = XENBUS_STATE_CONNECTED;
    do {
        state = XenbusWaitForBackendStateChange(BackendPath, state, NULL,
                                                token);

    } while (same_XENBUS_STATE(state, XENBUS_STATE_CONNECTED) ||
             same_XENBUS_STATE(state, XENBUS_STATE_CLOSING));

    /* Careful: The driver is likely to reload quite soon, and it'll
       re-register the backend state watch.  If that ever sees the
       backend in state CLOSED, it'll conclude that the device has
       been surprise-removed and refuse to connect it up.  Push the
       backend back into state INITWAIT from here to prevent this from
       happening. */
    if (online) {
        xenbus_change_state(XBT_NIL, TargetInfo->xenbusNodeName, "state",
                            XENBUS_STATE_INITIALISING);

        while (!same_XENBUS_STATE(state, XENBUS_STATE_INITWAIT) &&
               !is_null_XENBUS_STATE(state)) {

            state = XenbusWaitForBackendStateChange(BackendPath, state, NULL,
                                                    token);
        }
    }

    XmFreeMemory(BackendPath);

done:
    EvtchnReleaseSuspendToken(token);
    return;
}
