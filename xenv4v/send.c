/*
 * Copyright (c) 2011 Citrix Systems, Inc.
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
#include <csq.h>
#include <ntstrsafe.h>
#include "xenv4v.h"

static NTSTATUS
V4vInternalMsgCompletion(PDEVICE_OBJECT fdo, PIRP irp, PVOID ctx)
{
    XENV4V_CTRL_MSG  *cmsg = (XENV4V_CTRL_MSG*)ctx;
    XENV4V_EXTENSION *pde;
    FILE_OBJECT      *pfo;
    PMDL              mdl = NULL, nextMdl = NULL;

    UNREFERENCED_PARAMETER(fdo);

    // Determine message type and hold a pointers for use at the end
    if (cmsg->sh.flags == V4V_SHF_RST) {
        pde = ((XENV4V_RESET*)ctx)->pde;
        pfo = ((XENV4V_RESET*)ctx)->pfo;
    }
    else {
        pde = ((XENV4V_ACKNOWLEDGE*)ctx)->pde;
        pfo = ((XENV4V_ACKNOWLEDGE*)ctx)->pfo;
    }

    if (irp->IoStatus.Status == STATUS_CANCELLED) {
        TraceInfo(("IRP(%d) was cancelled.", cmsg->sh.flags));
    }
    else if (!NT_SUCCESS(irp->IoStatus.Status)) {
        TraceWarning(("IRP(%d) failed - status: 0x%x.", cmsg->sh.flags, irp->IoStatus.Status));
    }

    if ((irp->AssociatedIrp.SystemBuffer != NULL)&&(irp->Flags & IRP_DEALLOCATE_BUFFER)) {
        // For completeness in case we use buffered IO
        ExFreePoolWithTag(ctx, XENV4V_TAG);
    }
    else if (irp->MdlAddress != NULL) {
        // We use DIRECT_IO so we have to unlock things before we can free the buffer, this
        // is where we will come through. This is never a zero write so there is always an MDL.
        for (mdl = irp->MdlAddress; mdl != NULL; mdl = nextMdl) {
            nextMdl = mdl->Next;
            MmUnlockPages(mdl);
            IoFreeMdl(mdl); // This function will also unmap pages.
        }
        irp->MdlAddress = NULL;
        ExFreePoolWithTag(ctx, XENV4V_TAG);
    }

    IoReleaseRemoveLock(&pde->removeLock, irp);
    IoFreeIrp(irp);
    ObDereferenceObject(pfo);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static IO_WORKITEM_ROUTINE V4vSendWorkItem;
static VOID NTAPI
V4vSendWorkItem(PDEVICE_OBJECT fdo, PVOID ctx)
{
    XENV4V_CTRL_MSG       *cmsg = (XENV4V_CTRL_MSG*)ctx;
    XENV4V_EXTENSION      *pde;
    FILE_OBJECT           *pfo;
    IRP                   *irp = NULL;
    XENV4V_RESET          *rst;
    XENV4V_ACKNOWLEDGE    *ack;
    NTSTATUS               status;

    UNREFERENCED_PARAMETER(fdo);

    if (cmsg->sh.flags == V4V_SHF_RST) {
        rst = (XENV4V_RESET*)cmsg;
        pde = rst->pde;
        pfo = rst->pfo;
        IoFreeWorkItem(rst->pwi);
        rst->pwi = NULL;

        irp = IoBuildAsynchronousFsdRequest(IRP_MJ_WRITE, pde->fdo, rst, sizeof(XENV4V_RESET), NULL, NULL);
        if (irp == NULL) {
            TraceWarning(("Send RST failed - out of memory allocating IRP\n"));
            goto wi_err;
        }
        irp->Tail.Overlay.DriverContext[0] = (PVOID)(ULONG_PTR)(XENV4V_PEEK_RST);
        irp->Tail.Overlay.DriverContext[1] = (PVOID)(ULONG_PTR)(XENV4V_RST_MAGIC);

        IoSetCompletionRoutine(irp, V4vInternalMsgCompletion, rst, TRUE, TRUE, TRUE);
    }
    else {
        ack = (XENV4V_ACKNOWLEDGE*)cmsg;
        pde = ack->pde;
        pfo = ack->pfo;
        IoFreeWorkItem(ack->pwi);
        ack->pwi = NULL;

        irp = IoBuildAsynchronousFsdRequest(IRP_MJ_WRITE, pde->fdo, ack, sizeof(XENV4V_ACKNOWLEDGE), NULL, NULL);
        if (irp == NULL) {
            TraceWarning(("Send ACK failed - out of memory allocating IRP\n"));
            goto wi_err;
        }
        irp->Tail.Overlay.DriverContext[0] = (PVOID)(ULONG_PTR)(XENV4V_PEEK_ACK);
        irp->Tail.Overlay.DriverContext[1] = (PVOID)(ULONG_PTR)(XENV4V_ACK_MAGIC);

        IoSetCompletionRoutine(irp, V4vInternalMsgCompletion, ack, TRUE, TRUE, TRUE);
    }

    // Associate the file object with the target IOSL - ref count already bumped during work item queueing
    IoGetNextIrpStackLocation(irp)->FileObject = pfo;

    status = IoAcquireRemoveLock(&pde->removeLock, irp);
    if (!NT_SUCCESS(status)) {
        TraceWarning(("IoAcquireRemoveLock(%d) for send failed - status: 0x%x.", cmsg->sh.flags, status));
        goto wi_err;
    }

    status = IoCallDriver(pde->fdo, irp);
    if (!NT_SUCCESS(status)) {
        TraceWarning(("IoCallDriver(%d) for send failed - status: 0x%x.", cmsg->sh.flags, status));
        // Undo the lock here
        IoReleaseRemoveLock(&pde->removeLock, irp);
        goto wi_err;
    }

    return;

wi_err:
    if (irp != NULL) {
        IoFreeIrp(irp);
    }

    // Restore ref count on parent PFO
    ObDereferenceObject(pfo);

    // Normally freed in completion routine unless the driver call fails.
    ExFreePoolWithTag(cmsg, XENV4V_TAG);
}

VOID
V4vSendReset(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx, uint32_t connId, v4v_addr_t *dst, BOOLEAN noq)
{
    NTSTATUS      status;
    ULONG32       written = 0;
    V4V_STREAM    sh;
    XENV4V_RESET *rst = NULL;

    // Try to send it right here first
    sh.conid = connId;
    sh.flags = V4V_SHF_RST;
    status = V4vSend(&ctx->ringObject->ring->id.addr,
                     dst,
                     V4V_PROTO_STREAM,
                     &sh,
                     sizeof(V4V_STREAM),
                     &written);

    if (status == STATUS_RETRY) {
        if (noq) {
            return;
        }

        // Ring is full, send an IRP to ourselves to queue the RST
        rst = (XENV4V_RESET*)ExAllocatePoolWithTag(NonPagedPool, sizeof(XENV4V_RESET), XENV4V_TAG);
        if (rst == NULL) {
            TraceWarning(("send RST failed - out of memory\n"));
            goto reset_err;
        }

        // Allocated a work item to do this in another context to avoid re-entering our locks etc.
        rst->pwi = IoAllocateWorkItem(pde->fdo);
        if (rst->pwi == NULL) {
            TraceError(("Failed to allocate send RST work item - out of memory.\n"));
            goto reset_err;
        }

        // Setup RST, add a ref to the parent for the call back to ourselves.
        rst->dst = (*dst);
        rst->sh  = sh;
        rst->pde = pde;
        rst->pfo = ctx->pfoParent;
        ObReferenceObject(ctx->pfoParent);

        IoQueueWorkItem(rst->pwi, V4vSendWorkItem, DelayedWorkQueue, rst);
    }
    else if ((!NT_SUCCESS(status))&&(status != STATUS_VIRTUAL_CIRCUIT_CLOSED)) {
        TraceWarning(("Send RST failed - error: 0x%x\n", status));
    }

    return;

reset_err:
    if (rst != NULL) {
        ExFreePoolWithTag(rst, XENV4V_TAG);
    }
}

NTSTATUS
V4vSendAcknowledge(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx)
{
    NTSTATUS            status = STATUS_NO_MEMORY;
    XENV4V_ACKNOWLEDGE *ack = NULL;

    // For ACKs (from accepted contexts), always create and push a write IRP to the back of the queue.
    ack = (XENV4V_ACKNOWLEDGE*)ExAllocatePoolWithTag(NonPagedPool, sizeof(XENV4V_ACKNOWLEDGE), XENV4V_TAG);
    if (ack == NULL) {
        TraceWarning(("send ACK failed - out of memory\n"));
        goto acknowledge_err;
    }

    // Allocated a work item to do this in another context to avoid re-entering our locks etc.
    ack->pwi = IoAllocateWorkItem(pde->fdo);
    if (ack->pwi == NULL) {
        TraceError(("Failed to allocate send ACK work item - out of memory.\n"));
        goto acknowledge_err;
    }

    // Setup ACK, add a ref to the parent for the call back to ourselves.
    ack->sh.conid = (uint32_t)ctx->connId;
    ack->sh.flags = V4V_SHF_ACK;
    ack->pde      = pde;
    ack->pfo      = ctx->pfoParent;
    ObReferenceObject(ctx->pfoParent);

    IoQueueWorkItem(ack->pwi, V4vSendWorkItem, DelayedWorkQueue, ack);

    return STATUS_SUCCESS;

acknowledge_err:
    if (ack != NULL) {
        ExFreePoolWithTag(ack, XENV4V_TAG);
    }

    return status;
}
