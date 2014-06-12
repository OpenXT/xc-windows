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

/* Stuff related to handling non-scsifilt datapath requests which come
   back up from xenvbd. */
#include "ntddk.h"
#include "ntddstor.h"
#pragma warning (push, 3)
#include "srb.h"
#include "classpnp.h"
#pragma warning (pop)
#include "xsapi.h"
#include "scsiboot.h"
#include "scsifilt.h"

struct scsifilt_srb_extension {
    LIST_ENTRY list;
    PSCSI_REQUEST_BLOCK srb;
};

/* The scsifilt srb extension must fit inside a xenvbd srb
   extension. */
CASSERT(sizeof(struct scsifilt_srb_extension) <= sizeof(PVOID)*3);

static struct scsifilt_srb_extension *
get_srb_extension(PSCSI_REQUEST_BLOCK srb)
{
    return srb->SrbExtension;
}

void
complete_redirected_srbs(struct scsifilt *sf)
{
    KIRQL irql;
    LIST_ENTRY requests;
    PLIST_ENTRY ple;
    PLIST_ENTRY next_ple;
    struct scsifilt_srb_extension *se;

    irql = acquire_irqsafe_lock(&sf->redirect_lock);
    sf->redirect_complete_list_len = 0;
    XmListTransplant(&requests, &sf->redirect_complete_list);
    release_irqsafe_lock(&sf->redirect_lock, irql);

    for (ple = requests.Flink; ple != &requests; ple = next_ple) {
        next_ple = ple->Flink;
        se = CONTAINING_RECORD(ple, struct scsifilt_srb_extension, list);
        sf->complete_redirected_srb(sf->target_id, se->srb);
    }
}

static void
queue_srb_for_completion(struct scsifilt *sf, PSCSI_REQUEST_BLOCK srb)
{
    struct scsifilt_srb_extension *se = srb->SrbExtension;
    KIRQL irql;

    XM_ASSERT3P(se->srb, ==, srb);
    irql = acquire_irqsafe_lock(&sf->redirect_lock);
    sf->redirect_srbs_outstanding--;
    sf->redirect_complete_list_len++;
    InsertTailList(&sf->redirect_complete_list, &se->list);
    release_irqsafe_lock(&sf->redirect_lock, irql);

    XM_ASSERT(sf->restart_thread != NULL);
    KeSetEvent(&sf->restart_thread->event, IO_NO_INCREMENT, FALSE);
}

static void
queue_srb_for_error(struct scsifilt *sf, PSCSI_REQUEST_BLOCK srb)
{
    srb->SrbStatus = SRB_STATUS_INTERNAL_ERROR;
    srb->ScsiStatus = 0x40;

    queue_srb_for_completion(sf, srb);
}

static NTSTATUS
redirect_irp_completion(PDEVICE_OBJECT dev_obj, PIRP irp, PVOID ctxt)
{
    IO_STACK_LOCATION *const isl = IoGetCurrentIrpStackLocation(irp);
    struct scsifilt *const sf = get_scsifilt(dev_obj);
    SCSI_REQUEST_BLOCK *const new_srb = isl->Parameters.Scsi.Srb;
    SCSI_REQUEST_BLOCK *const srb = new_srb->OriginalRequest;
    MDL *const mdl = irp->MdlAddress;
    void *const buf = new_srb->DataBuffer;

    UNREFERENCED_PARAMETER(ctxt);

    srb->SrbStatus = new_srb->SrbStatus;
    srb->ScsiStatus = new_srb->ScsiStatus;
    memcpy(srb->DataBuffer, buf, srb->DataTransferLength);

    IoFreeIrp(irp);
    IoFreeMdl(mdl);
    ExFreePool(buf);
    XmFreeMemory(new_srb);

    queue_srb_for_completion(sf, srb);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

/* srb is kind of half const here.  We never modify it directly, but
   it will obviously get modified when it completes. */
static void
allocate_irp_and_resubmit_srb(struct scsifilt *sf,
                              SCSI_REQUEST_BLOCK *srb_)
{
    const SCSI_REQUEST_BLOCK *const srb = srb_;
    PIRP irp;
    PIO_STACK_LOCATION isl;
    PVOID buf;
    PMDL mdl;
    PSCSI_REQUEST_BLOCK new_srb;

    irp = NULL;
    mdl = NULL;
    new_srb = NULL;

    buf = ExAllocatePoolWithTag(NonPagedPool, srb->DataTransferLength, 'ssrx');
    if (!buf)
        goto err;

    memcpy(buf, srb->DataBuffer, srb->DataTransferLength);

    new_srb = XmAllocateZeroedMemory(sizeof(*new_srb));
    if (!new_srb)
        goto err;

    new_srb->Length = sizeof(*new_srb);
    new_srb->Function = srb->Function;
    XM_ASSERT3U(new_srb->Function, ==, SRB_FUNCTION_EXECUTE_SCSI);
    new_srb->SrbFlags = srb->SrbFlags;
    new_srb->PathId = srb->PathId;
    new_srb->TargetId = srb->TargetId;
    new_srb->Lun = srb->Lun;
    new_srb->QueueTag = srb->QueueTag;
    new_srb->QueueAction = srb->QueueAction;
    new_srb->DataTransferLength = srb->DataTransferLength;
    new_srb->DataBuffer = buf;
    new_srb->OriginalRequest = (PVOID)srb;
    new_srb->CdbLength = srb->CdbLength;
    memcpy(new_srb->Cdb, srb->Cdb, srb->CdbLength);

    irp = IoAllocateIrp(2, FALSE);
    if (!irp)
        goto err;

    mdl = IoAllocateMdl(buf, new_srb->DataTransferLength, FALSE, FALSE, irp);
    if (!mdl)
        goto err;
    MmBuildMdlForNonPagedPool(mdl);

    IoSetNextIrpStackLocation(irp);
    isl = IoGetCurrentIrpStackLocation(irp);
    isl->Parameters.Scsi.Srb = new_srb;
    isl->DeviceObject = sf->fdo;
    IoSetCompletionRoutine(irp, redirect_irp_completion, NULL, TRUE, TRUE, TRUE);
    IoSetNextIrpStackLocation(irp);

    isl = IoGetCurrentIrpStackLocation(irp);
    isl->MajorFunction = IRP_MJ_SCSI;
    isl->MinorFunction = 0;
    isl->Parameters.Scsi.Srb = new_srb;
    isl->DeviceObject = sf->fdo;
    filter_process_irp(sf, irp, new_srb);

    return;

err:
    TraceWarning(("Failed to set up redirected SRB\n"));
    if (irp)
        IoFreeIrp(irp);
    if (mdl)
        IoFreeMdl(mdl);
    if (buf)
        ExFreePool(buf);
    if (new_srb)
        XmFreeMemory(new_srb);

    queue_srb_for_error(sf, (PSCSI_REQUEST_BLOCK)srb);
}

static void
redirect_srb_dpc(PKDPC dpc, PVOID deferred_ctxt, PVOID system_ctxt1,
                 PVOID system_ctxt2)
{
    struct scsifilt *const sf = deferred_ctxt;
    LIST_ENTRY requests;
    PLIST_ENTRY ple;
    PLIST_ENTRY next_ple;
    struct scsifilt_srb_extension *se;
    KIRQL irql;

    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(system_ctxt1);
    UNREFERENCED_PARAMETER(system_ctxt2);

    irql = acquire_irqsafe_lock(&sf->redirect_lock);
    sf->redirect_srbs_outstanding += sf->redirect_srb_list_len;
    sf->redirect_srb_list_len = 0;
    XmListTransplant(&requests, &sf->redirect_srb_list);
    release_irqsafe_lock(&sf->redirect_lock, irql);

    for (ple = requests.Flink; ple != &requests; ple = next_ple) {
        next_ple = ple->Flink;
        se = CONTAINING_RECORD(ple, struct scsifilt_srb_extension, list);
        allocate_irp_and_resubmit_srb(sf, se->srb);
    }
}

void
redirect_srb(struct scsifilt *sf, PSCSI_REQUEST_BLOCK srb)
{
    struct scsifilt_srb_extension *const se = get_srb_extension(srb);
    KIRQL irql;

    se->srb = srb;
    irql = acquire_irqsafe_lock(&sf->redirect_lock);
    sf->nr_redirected_srbs_ever++;
    sf->redirect_srb_list_len++;
    InsertTailList(&sf->redirect_srb_list, &se->list);
    release_irqsafe_lock(&sf->redirect_lock, irql);

    KeInsertQueueDpc(&sf->redirect_srb_dpc, NULL, NULL);
}

void
init_redirection(struct scsifilt *sf)
{
    InitializeListHead(&sf->redirect_srb_list);
    InitializeListHead(&sf->redirect_complete_list);
    KeInitializeDpc(&sf->redirect_srb_dpc, redirect_srb_dpc, sf);
}
