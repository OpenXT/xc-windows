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

#include "ntddk.h"
#include "ntddstor.h"
#pragma warning (push, 3)
#include "srb.h"
#include "classpnp.h"
#pragma warning (pop)
#include "xsapi.h"
#include "scsiboot.h"
#include "scsifilt.h"
#include "scsifilt_ioctl.h"

#include "scsifilt_wpp.h"
#include "scsifilt.tmh"

static UNICODE_STRING
ScsifiltRegistryPath;

extern PULONG InitSafeBootMode;

static NTSTATUS _send_irp_and_wait(PDEVICE_OBJECT pdo, PIRP irp, PVOID ctxt);

struct scsifilt *
get_scsifilt(PDEVICE_OBJECT fdo)
{
    struct scsifilt *sf = (struct scsifilt *)fdo->DeviceExtension;
    XM_ASSERT3U(sf->magic, ==, SCSIFILT_MAGIC);
    return sf;
}

/* IoCallDriver() uses the fastcall calling convention, whereas
 * PoCallDriver() uses standard call.  Use a simple wrapper around
 * IoCallDriver() to massage the arguments to look the same, so that
 * we can call the appropriate function through a function pointer and
 * not worry about the difference in generic routines. */
static NTSTATUS
io_call_driver(PDEVICE_OBJECT dev, PIRP irp)
{
    return IoCallDriver(dev, irp);
}

/* Simple wrapper around KeWaitForSingleObject() which logs warnings
 * if we have to wait more than a second. */
static void
wait_for_single_object(PVOID object, const char *who, char *why)
{
    LARGE_INTEGER timeout;
    NTSTATUS status;

    for (;;) {
        timeout.QuadPart = -10000000;
        status = KeWaitForSingleObject(object, Executive, KernelMode,
                                       FALSE, &timeout);
        if (status == STATUS_SUCCESS)
            return;
        TraceWarning(("%s: waiting a long time for %s (%x)\n",
                      who, why, status));
    }
}

struct scsiport_ioctl_ctxt {
    struct scsifilt *sf;
    KEVENT *evt;
    void (*cb)(struct scsifilt *, SRB_IO_CONTROL *);
    SCSI_REQUEST_BLOCK srb;
    CHAR why[64];
};

static NTSTATUS
complete_scsiport_ioctl(PDEVICE_OBJECT pdo, PIRP irp, PVOID _ctxt)
{
    struct scsiport_ioctl_ctxt *ctxt = _ctxt;
    struct scsifilt *sf = ctxt->sf;
    SCSI_REQUEST_BLOCK *srb = &(ctxt->srb);

    UNREFERENCED_PARAMETER(pdo);

    TraceVerbose(("target %d: %s: %s\n", sf->target_id, __FUNCTION__, ctxt->why));

    if (ctxt->evt != NULL) {
        XM_ASSERT3P(ctxt->cb, ==, NULL);
        KeSetEvent(ctxt->evt, IO_NO_INCREMENT, FALSE);
    }

    IoReleaseRemoveLock(&ctxt->sf->remove_lock, ctxt);

    if (ctxt->cb != NULL) {
        XM_ASSERT3P(ctxt->evt, ==, NULL);
        ctxt->cb(sf, (SRB_IO_CONTROL *)srb->DataBuffer);
        IoFreeIrp(irp);
    }

    XmFreeMemory(ctxt);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static void
init_srb_for_ioctl(SCSI_REQUEST_BLOCK *srb, SRB_IO_CONTROL *header)
{
    memset(srb, 0, sizeof(*srb));
    srb->Function = SRB_FUNCTION_IO_CONTROL;
    srb->DataTransferLength = sizeof(*header) + header->Length;
    srb->DataBuffer = header;
    /* NO_QUEUE_FREEZE because we don't want to have to mess about
     * unfreezing it if this fails. */
    srb->SrbFlags =
        SRB_FLAGS_NO_QUEUE_FREEZE |
        SRB_FLAGS_BYPASS_LOCKED_QUEUE;
}

/* We expect the ioctl payload to be immediately after @header in
 * memory.  Both the header and the payload should already have been
 * completely initialised.  */
/* If @synchronous is false, we send the ioctl down but don't bother
 * waiting for it to complete.  This is a little bit dubious.  We use
 * a remove lock to protect against the device getting removed, but
 * there's no protection against driver unload after the remove lock
 * is dropped.  Fortunately scifilt, once loaded, will never be
 * unloaded, because it's needed to access C:. */
static NTSTATUS
send_scsiport_ioctl(struct scsifilt *sf, SRB_IO_CONTROL *header,
                    void (*cb)(struct scsifilt *, SRB_IO_CONTROL *), char *why)
{
    PIRP irp;
    PIO_STACK_LOCATION isl;
    KEVENT event;
    NTSTATUS status;
    struct scsiport_ioctl_ctxt *ctxt;
    BOOLEAN synchronous;
    BOOLEAN free_irp;

    ctxt = XmAllocateZeroedMemory(sizeof(*ctxt));
    if (!ctxt)
        return STATUS_INSUFFICIENT_RESOURCES;
    ctxt->sf = sf;

    strncpy(ctxt->why, why, sizeof (ctxt->why));
    ctxt->why[sizeof (ctxt->why) - 1] = '\0';

    init_srb_for_ioctl(&ctxt->srb, header);

    status = IoAcquireRemoveLock(&sf->remove_lock, ctxt);
    if (!NT_SUCCESS(status)) {
        XmFreeMemory(ctxt);
        return status;
    }

    irp = IoAllocateIrp(sf->lower_do->StackSize + 1, FALSE);
    if (irp == NULL) {
        IoReleaseRemoveLock(&sf->remove_lock, header);
        XmFreeMemory(ctxt);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    IoSetNextIrpStackLocation(irp);
    isl = IoGetNextIrpStackLocation(irp);
    isl->MajorFunction = IRP_MJ_SCSI;
    isl->Parameters.Scsi.Srb = &ctxt->srb;

    /* Send it down and wait for an answer. */
    if (cb == NULL) {
        KeInitializeEvent(&event, NotificationEvent, FALSE);
        ctxt->evt = &event;
        synchronous = TRUE;
        free_irp = TRUE;
    } else {
        ctxt->cb = cb;
        synchronous = FALSE;
        free_irp = FALSE;
    }
    IoSetCompletionRoutine(irp, complete_scsiport_ioctl, ctxt, TRUE, TRUE,
                           TRUE);

    TraceVerbose(("target %d: %s: %s (%s)\n", sf->target_id, __FUNCTION__, why,
                  (synchronous) ? "synchronous" : "asynchronous"));

    status = IoCallDriver(sf->lower_do, irp);
    if (synchronous && status == STATUS_PENDING) {
        wait_for_single_object(&event, __FUNCTION__, why);
        status = irp->IoStatus.Status;
    }

    if (free_irp)
        IoFreeIrp(irp);

    return status;
}

/* Returns either STATUS_SUCCESS for a normal attach, or
 * STATUS_INTERRUPT_VECTOR_ALREADY_CONNECTED if xenvbd gave us a
 * pre-bundled connection, or an error value if something goes
 * wrong. */
static NTSTATUS
attach_to_xenvbd(struct scsifilt *sf)
{
    struct xenvbd_ioctl_sniff sniff;
    NTSTATUS status;
    SUSPEND_TOKEN token;

    /* This isn't a good idea if we already have our own connection to
       the backend. */
    XM_ASSERT(is_null_EVTCHN_PORT(sf->evtchn_port));

    /* Send the sniff ioctl */
    memset(&sniff, 0, sizeof(sniff));
    sniff.header.HeaderLength = sizeof(sniff.header);
    memcpy(sniff.header.Signature, XENVBD_IOCTL_SIGNATURE,
           sizeof(XENVBD_IOCTL_SIGNATURE));
    sniff.header.Timeout = 120;
    sniff.header.ControlCode = XENVBD_IOCTL_SNIFF;
    sniff.header.ReturnCode = 0;
    sniff.header.Length = sizeof(sniff) - sizeof(sniff.header);
    status = send_scsiport_ioctl(sf, &sniff.header, NULL, "sniff");
    if (!NT_SUCCESS(status)) {
        /* Probably wasn't really a xenvbd disk. */
        TraceWarning(("Failed to attach %p to xenvbd (%x)!\n", sf,
                      status));
        return status;
    }

    if (sniff.version != XENVBD_IOCTL_SNIFF_VERSION) {
        TraceWarning(("Version mismatch: got version %d, expected %d\n",
                      sniff.version, XENVBD_IOCTL_SNIFF_VERSION));
        return STATUS_UNSUCCESSFUL;
    }

    /* Copy the xenvbd-provided pointers back into the scsifilt
     * structure. */
    sf->switch_from_filter = sniff.switch_from_filter;
    sf->set_target_info = sniff.set_target_info;
    sf->target_id = sniff.target_id;
    sf->frontend_path = sniff.frontend_path;
    sf->complete_redirected_srb = sniff.complete_redirected_srb;
    sf->target_start = sniff.target_start;
    sf->target_stop = sniff.target_stop;
    sf->target_resume = sniff.target_resume;

    TraceInfo(("Binding %p to target %d (%s)\n",
               sf, sf->target_id,
               sf->frontend_path));

    /* Bad things happen if you migrate while we're in the process of
       transferring a connection from xenvbd to scsifilt.  Make sure
       that doesn't happen. */
    token = EvtchnAllocateSuspendToken("attach_to_xenvbd");

    /* Get xenvbd to detach from the ring. */
    sniff.switch_to_filter(sf->target_id, sf, redirect_srb);

    TraceVerbose(("Done.\n"));

    EvtchnReleaseSuspendToken(token);

    sf->attached = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS
complete_irp(PIRP irp, NTSTATUS status)
{
    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

/* ignore_irp() -- pass an IRP down to the lower device object without
   taking any action. */
static NTSTATUS
_ignore_irp(PDEVICE_OBJECT fdo, PIRP irp, PVOID ctxt)
{
    struct scsifilt *const sf = ctxt;
    UNREFERENCED_PARAMETER(fdo);
    if (irp->PendingReturned)
        IoMarkIrpPending(irp);
    IoReleaseRemoveLock(&sf->remove_lock, irp);
    return STATUS_SUCCESS;
}
NTSTATUS
ignore_irp(struct scsifilt *sf, PIRP irp,
           NTSTATUS (*call_driver)(PDEVICE_OBJECT dev, PIRP irp))
{
    NTSTATUS status;

    status = IoAcquireRemoveLock(&sf->remove_lock, irp);
    if (!NT_SUCCESS(status))
        return complete_irp(irp, status);
    IoCopyCurrentIrpStackLocationToNext(irp);
    IoSetCompletionRoutine(irp, _ignore_irp, sf, TRUE, TRUE, TRUE);
    return call_driver(sf->lower_do, irp);
}

/* send_irp_and_wait() -- Send an IRP to the lower device and wait for
   it to complete it. */
static NTSTATUS
_send_irp_and_wait(PDEVICE_OBJECT pdo, PIRP irp, PVOID ctxt)
{
    PKEVENT evt = ctxt;

    UNREFERENCED_PARAMETER(pdo);
    UNREFERENCED_PARAMETER(irp);

    KeSetEvent(evt, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}
static NTSTATUS
send_irp_and_wait(PIRP irp, PDEVICE_OBJECT dev, char *why)
{
    NTSTATUS status;
    KEVENT event;

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    IoCopyCurrentIrpStackLocationToNext(irp);
    IoSetCompletionRoutine(irp, _send_irp_and_wait, &event, TRUE, TRUE, TRUE);
    status = IoCallDriver(dev, irp);
    if (status == STATUS_PENDING)
        wait_for_single_object(&event, "send_irp_and_wait", why);
    return irp->IoStatus.Status;
}

static void
complete_wakeup(struct scsifilt *sf, SRB_IO_CONTROL *ioctl)
{
    KIRQL Irql;

    XM_ASSERT(memcmp(ioctl->Signature, XENVBD_IOCTL_SIGNATURE,
                     sizeof(XENVBD_IOCTL_SIGNATURE)) == 0);

    TraceVerbose(("target %d: wakeup done\n", sf->target_id));

    KeAcquireSpinLock(&sf->wakeup_lock, &Irql);
    XM_ASSERT(sf->wakeup_pending);
    sf->wakeup_pending = FALSE;
    KeReleaseSpinLock(&sf->wakeup_lock, Irql);

    XmFreeMemory(ioctl);
}

static void
send_wakeup(struct scsifilt *sf)
{
    SRB_IO_CONTROL *ioctl;

    ioctl = XmAllocateZeroedMemory(sizeof (SRB_IO_CONTROL));
    if (ioctl == NULL) {
        TraceError(("target %d: failed to send wakeup\n", sf->target_id));
        return;
    }

    ioctl->HeaderLength = sizeof (SRB_IO_CONTROL);
    memcpy(ioctl->Signature, XENVBD_IOCTL_SIGNATURE,
           sizeof(XENVBD_IOCTL_SIGNATURE));
    ioctl->Timeout = 120;
    ioctl->ControlCode = XENVBD_IOCTL_WAKEUP;
    ioctl->ReturnCode = 0;
    ioctl->Length = 0;

    (void)send_scsiport_ioctl(sf, ioctl, complete_wakeup, "wakeup");
}

static NTSTATUS
restart_thread(struct xm_thread *thread, void *ctxt)
{
    struct scsifilt *const sf = ctxt;
    IRP *power_irp;
    KIRQL Irql;

    while (XmThreadWait(thread) >= 0) {
        power_irp = InterlockedExchangePointer(&sf->pending_power_up_irp,
                                               NULL);
        if (power_irp)
            finish_power_up_irp(sf, power_irp);

        power_irp = InterlockedExchangePointer(&sf->pending_power_irp,
                                               NULL);
        if (power_irp)
            handle_power_passive(sf, power_irp);

        KeAcquireSpinLock(&sf->wakeup_lock, &Irql);
        if (sf->need_wakeup) {
            sf->need_wakeup = FALSE;

            XM_ASSERT(!sf->wakeup_pending);
            sf->wakeup_pending = TRUE;

            KeReleaseSpinLock(&sf->wakeup_lock, Irql);

            send_wakeup(sf);
        } else {
            KeReleaseSpinLock(&sf->wakeup_lock, Irql);
        }
            
        complete_redirected_srbs(sf);
    }

    return STATUS_SUCCESS;
}

void
wakeup_scsiport(struct scsifilt *sf, const char *who)
{
    KIRQL Irql;

    KeAcquireSpinLock(&sf->wakeup_lock, &Irql);

    if (sf->need_wakeup || sf->wakeup_pending)
        goto done;

    sf->need_wakeup = TRUE;

    TraceVerbose(("target %d: %s: requesting wakeup\n", sf->target_id, who));
    KeSetEvent(&sf->restart_thread->event, IO_NO_INCREMENT, FALSE);

done:
    KeReleaseSpinLock(&sf->wakeup_lock, Irql);
}

/* Stop a scsi filter, unbind from xenvbd, and release all
 * resources. */
static void
stop_scsifilt(struct scsifilt *sf)
{
    close_scsifilt(sf);

    if (sf->attached) {
        sf->switch_from_filter(sf->target_id);
        sf->attached = FALSE;
    }

    sf->frontend_path = NULL;
}

static void
debug_cb(PVOID arg)
{
    struct scsifilt *sf = arg;
    unsigned nr_requests;
    unsigned nr_irps;

    XM_ASSERT3U(sf->magic, ==, SCSIFILT_MAGIC);
    TraceInternal(("%p has %d outstanding, max %d.\n",
                 sf,
                 sf->cur_outstanding,
                 sf->max_outstanding));
    sf->max_outstanding = sf->cur_outstanding;

    TraceInternal(("%d on ring, %d scheduled.\n",
                 sf->nr_inflight,
                 sf->schedule.nr_scheduled));

    /* Volatile discourages the compiler from loading it twice, which
       avoids potential division-by-zero errors. */
    nr_requests = *(volatile unsigned *)&sf->nr_requests;
    nr_irps = *(volatile unsigned *)&sf->nr_irps;
    TraceInternal(("%d requests ever, %d irps.\n", nr_requests, nr_irps));
    if (nr_requests != 0) {
        TraceInternal(("Arrive2submit %I64d, submit2return %I64d, return2complete %I64d\n",
                     sf->arrive2submit / nr_requests,
                     sf->submit2return / nr_requests,
                     sf->return2complete / nr_requests));
    }
    if (nr_irps != 0) {
        TraceInternal(("Arrive2complete %I64d\n",
                     sf->arrive2complete / nr_irps));
    }
    sf->nr_requests = 0;
    sf->nr_irps = 0;
    sf->arrive2submit = 0;
    sf->submit2return = 0;
    sf->return2complete = 0;
    sf->arrive2complete = 0;

    TraceInternal(("%d sectors transferred total, %d implied seeks\n",
                 sf->nr_sectors_transferred, sf->nr_seeks));
    sf->nr_sectors_transferred = 0;
    sf->nr_seeks = 0;

    TraceInternal(("%d bounces.\n", sf->nr_bounces));
    sf->nr_bounces = 0;

    TraceInternal(("Remove lock: count %d, removed %d.\n",
                 sf->remove_lock.Common.IoCount,
                 sf->remove_lock.Common.Removed));

    TraceInternal(("rsp_cons %d, prod_pvt %d\n", sf->ring.rsp_cons,
                 sf->ring.req_prod_pvt));
    if (sf->ring_shared)
        TraceInternal(("req_prod %d, req_event %d, rsp_prod %d, rsp_event %d\n",
                     sf->ring_shared->req_prod,
                     sf->ring_shared->req_event,
                     sf->ring_shared->rsp_prod,
                     sf->ring_shared->rsp_event));

    TraceInternal(("Last notified the remote when the request producer pointer was %d\n",
                 sf->last_notify_prod));

    TraceInternal(("%d requests need replay\n", sf->nr_replay_outstanding));
    TraceInternal(("Paused: %d\n", sf->pause_count));
    TraceInternal(("%d redirections ever.\n", sf->nr_redirected_srbs_ever));
    TraceInternal(("%d awaiting IRP, %d awaiting completion, %d underway.\n",
                 sf->redirect_srb_list_len, sf->redirect_complete_list_len,
                 sf->redirect_srbs_outstanding));

    if (sf->pending_power_irp)
        TraceInternal(("pending power IRP %p.\n", sf->pending_power_irp));
}

static NTSTATUS
advertise_filter(
    IN  DEVICE_OBJECT   *DeviceObject
    )
{
    KEVENT              Complete;
    IO_STATUS_BLOCK     StatusBlock;
    IRP                 *Irp;
    IO_STACK_LOCATION   *StackLocation;
    WCHAR               *InstanceID;
    ULONG               Length;
    WCHAR               *Target;
    UNICODE_STRING      String;
    ULONG               TargetID;
    CHAR                *Path;
    NTSTATUS            status;

    KeInitializeEvent(&Complete, NotificationEvent, FALSE);
    RtlZeroMemory(&StatusBlock, sizeof (IO_STATUS_BLOCK));

    status = STATUS_UNSUCCESSFUL;
    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP, DeviceObject, NULL, 0, NULL, &Complete, &StatusBlock);
    if (Irp == NULL)
        goto fail1;

    StackLocation = IoGetNextIrpStackLocation(Irp);
    StackLocation->MinorFunction = IRP_MN_QUERY_ID;
    StackLocation->Parameters.QueryId.IdType = BusQueryInstanceID;

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    status = IoCallDriver(DeviceObject, Irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&Complete, Executive, KernelMode, FALSE, NULL);
        status = StatusBlock.Status;
    }

    if (!NT_SUCCESS(status))
        goto fail2;

    InstanceID = (PWCHAR)StatusBlock.Information;

    status = STATUS_UNSUCCESSFUL;
    if (InstanceID == NULL)
        goto fail3;

    Length = (ULONG)wcslen(InstanceID);
    switch (Length) {
    case 3: // BTL
        Target = InstanceID + 1;
        Target[1] = UNICODE_NULL;
        break;

    case 6: // BBTTLL
        Target = InstanceID + 2;
        Target[2] = UNICODE_NULL;
        break;

    default:
        status = STATUS_INVALID_PARAMETER;
        goto fail4;
    }

    RtlInitUnicodeString(&String, Target);
    status = RtlUnicodeStringToInteger(&String, 16, &TargetID);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = STATUS_NO_MEMORY;
    Path = Xmasprintf("data/scsi/target/%d", TargetID);
    if (Path == NULL)
        goto fail6;

    status = xenbus_printf(XBT_NIL, Path, "filter", "present");
    if (!NT_SUCCESS(status))
        goto fail7;

    TraceVerbose(("%s/filter -> present\n", Path));

    XmFreeMemory(Path);
    return STATUS_SUCCESS;

fail7:
    TraceError(("%s: fail7\n", __FUNCTION__));

    XmFreeMemory(Path);

fail6:
    TraceError(("%s: fail6\n", __FUNCTION__));

fail5:
    TraceError(("%s: fail5\n", __FUNCTION__));

fail4:
    TraceError(("%s: fail4\n", __FUNCTION__));

    ExFreePool(InstanceID);

fail3:
    TraceError(("%s: fail3\n", __FUNCTION__));

fail2:
    TraceError(("%s: fail2\n", __FUNCTION__));

fail1:
    TraceError(("%s: fail1 (0x%08x)\n", __FUNCTION__, status));

    return status;
}

static NTSTATUS
handle_pnp(PDEVICE_OBJECT fdo, PIRP irp)
{
    struct scsifilt *const sf = get_scsifilt(fdo);
    IO_STACK_LOCATION *const isl = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status;

    switch (isl->MinorFunction) {
    case IRP_MN_START_DEVICE: {
        status = advertise_filter(fdo);
        if (!NT_SUCCESS(status))
           return complete_irp(irp, status);

        status = send_irp_and_wait(irp, sf->lower_do, "start");
        if (NT_SUCCESS(status)) {
            status = attach_to_xenvbd(sf);
            if (NT_SUCCESS(status)) {
                status = connect_scsifilt(sf);

                if (NT_SUCCESS(status)) {
                    sf->current_power_state = PowerDeviceD0;
                    unpause_datapath(sf);
                }
                return complete_irp(irp, status);
            } else if (status == STATUS_DEVICE_REMOVED) {
                /* Eject sequence started while we were attaching ->
                   fail the start request. */
                return complete_irp(irp, status);
            } else {
                /* Failed to attach scsifilt to xenvbd -> drop the
                   filter into pass-through mode.  i.e. return success
                   but don't actually do anything. */
                return complete_irp(irp, STATUS_SUCCESS);
            }
        } else {
            return complete_irp(irp, status);
        }
    }
    case IRP_MN_REMOVE_DEVICE:
        if (sf->frontend_path != NULL) {
            TraceNotice(("Remove %s with %d requests outstanding, of which %d on ring.\n",
                         sf->frontend_path,
                         sf->cur_outstanding,
                         sf->nr_inflight));
            IoAcquireRemoveLock(&sf->remove_lock, sf);
            abort_pending_requests(sf);
            IoReleaseRemoveLockAndWait(&sf->remove_lock, sf);

            if (sf->cur_outstanding != 0) {
                TraceWarning(("%s: %d requests left outstanding after we thought we'd stopped (%d on ring)!\n",
                              sf->frontend_path,
                              sf->cur_outstanding,
                              sf->nr_inflight));
            }
        }

        stop_scsifilt(sf);

        /* We're accessing lower_do without holding the remove lock.
           That's okay, because we know that Windows won't send us
           several REMOVE_DEVICE requests at the same time. */

        IoSkipCurrentIrpStackLocation(irp);
        status = IoCallDriver(sf->lower_do, irp);

        /* Note that we don't wait for the lower device to finish
           before tearing down the filter device. */

        /* Once this returns, it is guaranteed that no more IRPs will
           be started against this device, and we know that there are
           none outstanding because of the remove lock, so we can
           safely tear it all down. */
        IoDetachDevice(sf->lower_do);

        EvtchnReleaseDebugCallback(sf->debug_cb);

        if (sf->restart_thread)
            XmKillThread(sf->restart_thread);
        sf->restart_thread = NULL;

        ExDeleteNPagedLookasideList(&sf->sfri_lookaside_list);

        cleanup_xenvbd_bits(sf);

        IoDeleteDevice(fdo);
        return status;

    case IRP_MN_STOP_DEVICE:
        XM_ASSERT(sf->frontend_path != NULL);
        TraceNotice(("Stopping %s, %d outstanding, %d on ring.\n",
                     sf->frontend_path, sf->cur_outstanding,
                     sf->nr_inflight));

        pause_datapath(sf);
        stop_scsifilt(sf);

        break;
    }
    return ignore_irp(sf, irp, io_call_driver);
}

/* IRP_MJ_INTERNAL_DEVICE_CONTROL and IRP_MJ_SCSI are #define'd to the
   same constant, and you have to know what you're getting based on
   where you are in the device stack.  We're underneath disk.sys, and
   so we only ever get SCSI requests. */
static NTSTATUS
handle_scsi(PDEVICE_OBJECT fdo, PIRP irp)
{
    struct scsifilt *const sf = get_scsifilt(fdo);
    IO_STACK_LOCATION *const isl = IoGetCurrentIrpStackLocation(irp);
    SCSI_REQUEST_BLOCK *const srb = isl->Parameters.Scsi.Srb;
    CDB *const cdb = (CDB *)srb->Cdb;

    if (!sf->attached)
        return ignore_irp(sf, irp, io_call_driver);

    DoTraceMessage(FLAG_SCSI, "%s scsi function %d",
                   sf->frontend_path, srb->Function);

    switch (srb->Function) {
    default:
        TraceWarning(("Strange srb function %x.\n", srb->Function));
    case SRB_FUNCTION_CLAIM_DEVICE:
    case SRB_FUNCTION_IO_CONTROL:
    case SRB_FUNCTION_FLUSH:
    case SRB_FUNCTION_LOCK_QUEUE:
    case SRB_FUNCTION_UNLOCK_QUEUE:
        return ignore_irp(sf, irp, io_call_driver);
    case SRB_FUNCTION_SHUTDOWN:
        filter_wait_for_idle(sf);
        return ignore_irp(sf, irp, io_call_driver);
    case SRB_FUNCTION_EXECUTE_SCSI:
        break;
    }

    if ((srb->SrbFlags & SRB_FLAGS_QUEUE_ACTION_ENABLE) &&
        srb->QueueAction != SRB_SIMPLE_TAG_REQUEST) {
        TraceWarning(("Strange queue action %x!\n", srb->QueueAction));
    }

    DoTraceMessage(FLAG_SCSI, "%s scsi operation 0x%x length %d",
                   sf->frontend_path, srb->Cdb[0], srb->CdbLength);

    if (srb->Function == SRB_FUNCTION_EXECUTE_SCSI &&
        (srb->CdbLength == 6 &&
         (cdb->CDB6GENERIC.OperationCode == SCSIOP_READ6 ||
          cdb->CDB6GENERIC.OperationCode == SCSIOP_WRITE6)) ||
        (srb->CdbLength == 10 &&
         (cdb->CDB10.OperationCode == SCSIOP_READ ||
          cdb->CDB10.OperationCode == SCSIOP_WRITE)) ||
        (srb->CdbLength == 12 &&
         (cdb->CDB12.OperationCode == SCSIOP_READ12 ||
          cdb->CDB12.OperationCode == SCSIOP_WRITE12)) ||
        (srb->CdbLength == 16 &&
         (cdb->CDB16.OperationCode == SCSIOP_READ16 ||
          cdb->CDB16.OperationCode == SCSIOP_WRITE16))) {
        return filter_process_irp(sf, irp, srb);
    }

    if (srb->CdbLength == 10 &&
        cdb->CDB10.OperationCode == SCSIOP_READ_CAPACITY)
        return filter_process_capacity_irp(sf, irp, srb);
    if (srb->CdbLength == 16 &&
        cdb->CDB10.OperationCode == SCSIOP_READ_CAPACITY16)
        return filter_process_capacity_ex_irp(sf, irp, srb);

    return ignore_irp(sf, irp, io_call_driver);
}

static NTSTATUS
handle_get_xenbus_name(struct scsifilt *sf, PIRP irp)
{
    IO_STACK_LOCATION *const isl = IoGetCurrentIrpStackLocation(irp);
    char *const outbuf = irp->AssociatedIrp.SystemBuffer;
    const ULONG out_size = isl->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS res;
    SUSPEND_TOKEN token;
    char *path;
    char *name;

    irp->IoStatus.Information = 0;

    res = IoAcquireRemoveLock(&sf->remove_lock, irp);
    if (!NT_SUCCESS(res))
        return complete_irp(irp, res);

    token = EvtchnAllocateSuspendToken("handle_get_xenbus_name()");
    path = Xmasprintf("%s/dev", sf->backend_path);
    if (path == NULL) {
        res = STATUS_INSUFFICIENT_RESOURCES;
    } else {
        res = xenbus_read(XBT_NIL, path, &name);
        if (NT_SUCCESS(res)) {
            if (strlen(name) >= out_size) {
                res = STATUS_BUFFER_TOO_SMALL;
            } else {
                strcpy(outbuf, name);
                irp->IoStatus.Information = strlen(name) + 1;
            }
            XmFreeMemory(name);
        }
        XmFreeMemory(path);
    }
    EvtchnReleaseSuspendToken(token);
    IoReleaseRemoveLock(&sf->remove_lock, irp);
    return complete_irp(irp, res);
}

static NTSTATUS
_handle_storage_query_property(PDEVICE_OBJECT fdo, PIRP irp, PVOID ctxt)
{
    struct scsifilt *const sf = ctxt;
    IO_STACK_LOCATION *const isl = IoGetCurrentIrpStackLocation(irp);
    STORAGE_ADAPTER_DESCRIPTOR *const sad = irp->AssociatedIrp.SystemBuffer;

    UNREFERENCED_PARAMETER(fdo);

    XM_ASSERT3U(isl->Parameters.DeviceIoControl.OutputBufferLength, >=,
                FIELD_OFFSET(STORAGE_ADAPTER_DESCRIPTOR, AlignmentMask));

    if (irp->PendingReturned)
        IoMarkIrpPending(irp);
    IoReleaseRemoveLock(&sf->remove_lock, irp);

    /* Don't do anything if the scsiport failed the request. */
    if (irp->IoStatus.Status != STATUS_SUCCESS)
        return STATUS_SUCCESS;

    TraceVerbose(("Scsiport reported max length of %x, max pages of %x\n",
                  sad->MaximumTransferLength, sad->MaximumPhysicalPages));

    sad->MaximumTransferLength = MAX_PAGES_PER_REQUEST*PAGE_SIZE;
    sad->MaximumPhysicalPages = MAX_PAGES_PER_REQUEST;

    return STATUS_SUCCESS;
}

static const char *query_type_name(STORAGE_QUERY_TYPE type)
{
#define _QUERY_TYPE(_type)  \
    case _type:             \
        return #_type;

    switch (type) {
    _QUERY_TYPE(PropertyStandardQuery);
    _QUERY_TYPE(PropertyExistsQuery);
    _QUERY_TYPE(PropertyMaskQuery);
    _QUERY_TYPE(PropertyQueryMaxDefined);
    default:
        return "UNKNOWN";
    }

#undef  _QUERY_TYPE
}

static const char *property_id_name(STORAGE_PROPERTY_ID id)
{
#define _PROPERTY_ID(_id)   \
    case _id:               \
        return #_id;

    switch (id) {
    _PROPERTY_ID(StorageDeviceProperty);
    _PROPERTY_ID(StorageAdapterProperty);
    _PROPERTY_ID(StorageDeviceIdProperty);
    _PROPERTY_ID(StorageDeviceUniqueIdProperty);
    _PROPERTY_ID(StorageDeviceWriteCacheProperty);
    _PROPERTY_ID(StorageMiniportProperty);
    _PROPERTY_ID(StorageAccessAlignmentProperty);
    default:
        return "UNKNOWN";
    }

#undef  _PROPERTY_ID
}

static NTSTATUS
handle_storage_query_property(struct scsifilt *sf, PIRP irp)
{
    IO_STACK_LOCATION *const isl = IoGetCurrentIrpStackLocation(irp);
    STORAGE_PROPERTY_QUERY *const spq = irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status;

    /* Make sure it looks sane. */
    if (isl->Parameters.DeviceIoControl.InputBufferLength <
        sizeof(STORAGE_PROPERTY_QUERY)) {
        TraceWarning(("Storage property query was too small (%d < %d)\n",
                      isl->Parameters.DeviceIoControl.InputBufferLength,
                      sizeof(STORAGE_PROPERTY_QUERY)));
        return ignore_irp(sf, irp, io_call_driver);
    }

    TraceVerbose(("%s: %s %s\n", __FUNCTION__,
                  query_type_name(spq->QueryType),
                  property_id_name(spq->PropertyId)));

    if (spq->QueryType != PropertyStandardQuery ||
        spq->PropertyId != StorageAdapterProperty) {
        // Not interested
        return ignore_irp(sf, irp, io_call_driver);
    }

    /* Is it actually going to query enough to get the field we
     * want? */
    if (isl->Parameters.DeviceIoControl.OutputBufferLength <
        FIELD_OFFSET(STORAGE_ADAPTER_DESCRIPTOR, AlignmentMask)) {
        /* Nope. */
        return ignore_irp(sf, irp, io_call_driver);
    }

    /* This is the one we're interested in.  Send it down. */
    status = IoAcquireRemoveLock(&sf->remove_lock, irp);
    IoCopyCurrentIrpStackLocationToNext(irp);
    IoSetCompletionRoutine(irp, _handle_storage_query_property, sf, TRUE,
                           TRUE, TRUE);
    return IoCallDriver(sf->lower_do, irp);
}

static NTSTATUS
handle_device_control(PDEVICE_OBJECT fdo, PIRP irp)
{
    struct scsifilt *const sf = get_scsifilt(fdo);
    IO_STACK_LOCATION *const isl = IoGetCurrentIrpStackLocation(irp);

    DoTraceMessage(FLAG_CONTROL_INTERFACE, "%s ioctl %x",
                   sf->frontend_path,
                   isl->Parameters.DeviceIoControl.IoControlCode);
    switch (isl->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_SCSIFILT_GET_XENBUS_NAME:
        return handle_get_xenbus_name(sf, irp);
    case IOCTL_STORAGE_QUERY_PROPERTY:
        return handle_storage_query_property(sf, irp);
    default:
        TraceDebug(("IOCTL: DeviceType = %04x Access = %02x Function = %04x Method = %02x\n",
                    ((isl->Parameters.DeviceIoControl.IoControlCode) >> 16) & 0x0000ffff,
                    ((isl->Parameters.DeviceIoControl.IoControlCode) >> 14) & 0x00000003,
                    ((isl->Parameters.DeviceIoControl.IoControlCode) >> 2 ) & 0x00000fff,
                    ((isl->Parameters.DeviceIoControl.IoControlCode)      ) & 0x00000003));
        return ignore_irp(sf, irp, io_call_driver);
    }
}

static NTSTATUS
handle_uninteresting_irp(PDEVICE_OBJECT fdo, PIRP irp)
{
    struct scsifilt *const sf = get_scsifilt(fdo);
    return ignore_irp(sf, irp, io_call_driver);
}

static NTSTATUS
initialise_scsifilt_instance(PDEVICE_OBJECT fdo, PDEVICE_OBJECT pdo)
{
    struct scsifilt *sf;
    NTSTATUS status;

    sf = (struct scsifilt *)fdo->DeviceExtension;
    memset(sf, 0, sizeof(*sf));
    sf->magic = SCSIFILT_MAGIC;
    sf->fdo = fdo;
    sf->pdo = pdo;
    sf->current_power_state = PowerDeviceD3; /* i.e. switched off */
    sf->shutdown_type = PowerActionNone;
    sf->pause_count = 1; /* We're paused until we get an IRP_MN_START
                            request */
    init_redirection(sf);

    KeInitializeSpinLock(&sf->wakeup_lock);

    KeInitializeSpinLock(&sf->request_replay_lock);
    InitializeListHead(&sf->requests_needing_replay);

    IoInitializeRemoveLock(&sf->remove_lock, 'mrfs', 0, 0);

    status = initialise_xenvbd_bits(sf);
    if (!NT_SUCCESS(status)) {
        TraceError(("Failed to initialise scsifilt instance\n"));
        cleanup_xenvbd_bits(sf);
        return status;
    }

    ExInitializeNPagedLookasideList(&sf->sfri_lookaside_list,
                                    NULL,
                                    NULL,
                                    0,
                                    sizeof(struct scsifilt_request_internal),
                                    'irfs',
                                    0);

    sf->restart_thread = XmSpawnThread(restart_thread, sf);
    if (sf->restart_thread == NULL) {
        ExDeleteNPagedLookasideList(&sf->sfri_lookaside_list);
        cleanup_xenvbd_bits(sf);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Don't really care if this fails. */
    sf->debug_cb = EvtchnSetupDebugCallback(debug_cb, sf);

    return STATUS_SUCCESS;
}

static NTSTATUS
add_device(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT pdo)
{
    DECLARE_CONST_UNICODE_STRING(xenvbd_driver_name, L"\\Driver\\xenvbd");
    PDEVICE_OBJECT fdo;
    NTSTATUS status;
    struct scsifilt *sf;
    PDRIVER_OBJECT pdo_driver;

    /* We only want to attach to our own disks.  The original plan
       here was to create a DO for every disk, and then use an ioctl
       against the lower device to figure out whether it's a xenvbd
       device.  Unfortunately, if you issue an IRP_MJ_SCSI request
       against ATAPI it blue screens, so that doesn't work.  We still
       have the sniff ioctl, but it's now used to establish the
       direct-call interface, rather than to determine whether we want
       to use the filter. */
    /* (IRP_MJ_SCSI is numerically equal to
       IRP_MJ_INTERNAL_DEVICE_CONTROL, but they format their IRP
       parameters in a different way.  My suspicion is that atapi.sys
       is interpreting our SCSI ioctl as an INTERNAL_DEVICE_CONTROL
       ioctl and falling over when the IRP parameters don't make
       sense.  In any case, it's unlikely to be worthwhile to spend a
       lot of time investigating this, and this workaround is actually
       likely to be slightly more efficient than the old scheme
       anyway, even if it is a bit gross.) */
    pdo_driver = pdo->DriverObject;
    XM_ASSERT(pdo_driver != NULL);
    TraceVerbose(("Considering attaching to service %wZ\n",
                  &pdo_driver->DriverName));
    if (RtlCompareUnicodeString(&pdo_driver->DriverName,
                                &xenvbd_driver_name,
                                TRUE) != 0) {
        TraceNotice(("Not attaching to %wZ\n", &pdo_driver->DriverName));
        return STATUS_SUCCESS;
    }
    //
    // XC-4424
    //
    // When we are not the lowest filter driver, we cannot attach
    // to the disk device...or else we will eventually crash.
    //
    if (pdo->AttachedDevice)
    {
        if (RtlCompareUnicodeString(&pdo->AttachedDevice->DriverObject->DriverName,
                                    &xenvbd_driver_name,
                                    TRUE) != 0) {
            TraceNotice(("Not attaching to %wZ [caught in 2nd test]\n",
                &pdo->AttachedDevice->DriverObject->DriverName));
            return STATUS_SUCCESS;
        }
    }
    status = IoCreateDevice(DriverObject,
                            sizeof(*sf),
                            NULL,
                            pdo->DeviceType,
                            0,
                            FALSE,
                            &fdo);
    if (!NT_SUCCESS(status)) {
        TraceError(("Failed to create FDO (%x)!\n", status));
        return status;
    }
    status = initialise_scsifilt_instance(fdo, pdo);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(fdo);
        return status;
    }
    sf = get_scsifilt(fdo);
    sf->lower_do = IoAttachDeviceToDeviceStack(fdo, pdo);
    fdo->Characteristics = sf->lower_do->Characteristics;
    fdo->AlignmentRequirement = sf->lower_do->AlignmentRequirement;
    fdo->Flags = sf->lower_do->Flags;

    WPP_INIT_TRACING(fdo, &ScsifiltRegistryPath);

    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
    unsigned x;

    if (*InitSafeBootMode > 0) {
        TraceNotice(("loading in safe mode\n"));
        return STATUS_SUCCESS;
    }

    if (!XmCheckXenutilVersionString(TRUE, XENUTIL_CURRENT_VERSION))
        return STATUS_REVISION_MISMATCH;

    ScsifiltRegistryPath.Buffer =
        XmAllocateZeroedMemory(registry_path->MaximumLength);
    if (!ScsifiltRegistryPath.Buffer)
        return STATUS_NO_MEMORY;
    ScsifiltRegistryPath.MaximumLength = registry_path->MaximumLength;
    ScsifiltRegistryPath.Length = registry_path->Length;
    memcpy(ScsifiltRegistryPath.Buffer, registry_path->Buffer,
           registry_path->Length);
    WPP_SYSTEMCONTROL(driver_object);

    driver_object->DriverExtension->AddDevice = add_device;

    for (x = 0; x <= IRP_MJ_MAXIMUM_FUNCTION; x++)
        driver_object->MajorFunction[x] = handle_uninteresting_irp;
    driver_object->MajorFunction[IRP_MJ_POWER] = handle_power;

    driver_object->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] =
        handle_scsi;
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
        handle_device_control;
    driver_object->MajorFunction[IRP_MJ_PNP] = handle_pnp;

    return STATUS_SUCCESS;
}
