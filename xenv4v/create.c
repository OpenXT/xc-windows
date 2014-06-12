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

static ULONG32
V4vReleaseContextInternal(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx, BOOLEAN lock)
{
    KLOCK_QUEUE_HANDLE  lqh = {0};
    ULONG32             count;
    FILE_OBJECT        *pfo;
    LONG                val;

    val = InterlockedExchangeAdd(&ctx->type, 0);

    if (lock) {
        KeAcquireInStackQueuedSpinLock(&pde->contextLock, &lqh);
    }
    ASSERT(ctx->refc != 0); // SNO, really bad
    count = --ctx->refc;

    // For listeners only, unlink the context here when there are no more contexts associated with it
    if ((val == XENV4V_TYPE_LISTENER)&&(count == 1)) {
        RemoveEntryList(&ctx->le);
        count = --ctx->refc;
        pde->contextCount--;
        ASSERT(pde->contextCount >= 0); // SNO, really bad
    }

    if (lock) {
        KeReleaseInStackQueuedSpinLock(&lqh);
    }

    // When the count goes to zero, clean it all up. We are out of the list so a lock is not needed.
    // N.B. if we end up doing any cleanup that cannot happen at DISPATCH, we will need a work item.
    if (count == 0) {
        // Type specific cleanup
        if (val == XENV4V_TYPE_ACCEPTER) {
            V4vFlushAccepterQueueData(ctx);
            ASSERT(ctx->u.accepter.listenerContext != NULL);
            V4vReleaseContextInternal(pde, ctx->u.accepter.listenerContext, lock);
        }
        else if (val == XENV4V_TYPE_LISTENER) {
            ASSERT(ctx->u.listener.synList != NULL);
            ExFreePoolWithTag(ctx->u.listener.synList, XENV4V_TAG);
        }

        pfo = ctx->pfoParent;
        // Cleanup the ring - if it is shared, this will just drop the ref count.
        if (ctx->ringObject != NULL) {
            V4vReleaseRing(pde, ctx->ringObject);
        }
        // Release the event
        if (ctx->kevReceive != NULL) {
            ObDereferenceObject(ctx->kevReceive);
        }
        // Free any that were requeued by the VIRQ handler at the last minute
        V4vCancelAllFileIrps(pde, pfo);
        // Free context itself...
        ExFreePoolWithTag(ctx, XENV4V_TAG);
        // Drop the reference the context held that prevents the final close
        ObDereferenceObject(pfo);
    }

    return count;
}

ULONG32
V4vReleaseContext(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx)
{
    return V4vReleaseContextInternal(pde, ctx, TRUE);
}

ULONG32
V4vAddRefContext(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx)
{
    KLOCK_QUEUE_HANDLE lqh;
    ULONG32            count;

    KeAcquireInStackQueuedSpinLock(&pde->contextLock, &lqh);
    count = ++ctx->refc;
    KeReleaseInStackQueuedSpinLock(&lqh);

    return count;
}

VOID
V4vPutAllContexts(XENV4V_EXTENSION *pde, XENV4V_CONTEXT** ctxList, ULONG count)
{
    KLOCK_QUEUE_HANDLE lqh;
    ULONG              i;

    if (ctxList == NULL) {
        return;
    }

    KeAcquireInStackQueuedSpinLock(&pde->contextLock, &lqh);
    for (i = 0; i < count; i++) {
        V4vReleaseContextInternal(pde, ctxList[i], FALSE);
    }
    KeReleaseInStackQueuedSpinLock(&lqh);
    ExFreePoolWithTag(ctxList, XENV4V_TAG);
}

XENV4V_CONTEXT**
V4vGetAllContexts(XENV4V_EXTENSION *pde, ULONG *countOut)
{
    KLOCK_QUEUE_HANDLE   lqh;
    XENV4V_CONTEXT      *ctx;
    XENV4V_CONTEXT     **ctxList;
    ULONG                i = 0;

    *countOut = 0;

    KeAcquireInStackQueuedSpinLock(&pde->contextLock, &lqh);
    if (IsListEmpty(&pde->contextList)) {
        KeReleaseInStackQueuedSpinLock(&lqh);
        return NULL;
    }
    ASSERT(pde->contextCount > 0);

    ctxList = (XENV4V_CONTEXT**)ExAllocatePoolWithTag(NonPagedPool,
                                                      pde->contextCount*sizeof(XENV4V_CONTEXT*),
                                                      XENV4V_TAG);
    if (ctxList == NULL) {
        KeReleaseInStackQueuedSpinLock(&lqh);
        TraceError(("failed to allocate context list - out of memory.\n"));
        return NULL;
    }

    ctx = (XENV4V_CONTEXT*)pde->contextList.Flink;
    while (ctx != (XENV4V_CONTEXT*)&pde->contextList) {
        ctx->refc++;
        ctxList[i++] = ctx;
        ctx = (XENV4V_CONTEXT*)ctx->le.Flink;
    }
    *countOut = pde->contextCount;
    KeReleaseInStackQueuedSpinLock(&lqh);

    return ctxList;
}

XENV4V_CONTEXT*
V4vGetContextByConnectionId(XENV4V_EXTENSION *pde, ULONG64 connId)
{
    KLOCK_QUEUE_HANDLE  lqh;
    XENV4V_CONTEXT     *ctx = NULL, *ctxOut = NULL;

    KeAcquireInStackQueuedSpinLock(&pde->contextLock, &lqh);
    if (IsListEmpty(&pde->contextList)) {
        KeReleaseInStackQueuedSpinLock(&lqh);
        return NULL;
    }
    ASSERT(pde->contextCount > 0);

    ctx = (XENV4V_CONTEXT*)pde->contextList.Flink;
    while (ctx != (XENV4V_CONTEXT*)&pde->contextList) {
        if ((ctx->state == XENV4V_STATE_ACCEPTED)&&(ctx->type == XENV4V_TYPE_ACCEPTER)&&
            (ctx->connId == connId)) {
            ctx->refc++;
            ctxOut = ctx;
            break;
        }
        ctx = (XENV4V_CONTEXT*)ctx->le.Flink;
    }

    KeReleaseInStackQueuedSpinLock(&lqh);

    return ctxOut;
}

static VOID
V4vLinkToContextList(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx)
{
    KLOCK_QUEUE_HANDLE lqh;

    KeAcquireInStackQueuedSpinLock(&pde->contextLock, &lqh);

    // Add a reference for the list and up the counter
    ctx->refc++;
    pde->contextCount++;

    // Link this context into the adapter list
    InsertHeadList(&pde->contextList, &(ctx->le));
    //TraceInfo(("added context %p to list.\n", ctx));

    KeReleaseInStackQueuedSpinLock(&lqh);
}

static VOID
V4vUnlinkFromContextList(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx)
{
    KLOCK_QUEUE_HANDLE lqh;

    KeAcquireInStackQueuedSpinLock(&pde->contextLock, &lqh);
    RemoveEntryList(&ctx->le);
    V4vReleaseContextInternal(pde, ctx, FALSE);
    // Drop the count when it gets removed from the list
    pde->contextCount--;
    ASSERT(pde->contextCount >= 0); // SNO, really bad
    KeReleaseInStackQueuedSpinLock(&lqh);
}

VOID
V4vCancelAllFileIrps(XENV4V_EXTENSION *pde, FILE_OBJECT *pfo)
{
    PIRP pendingIrp;
    XENV4V_QPEEK peek;

    peek.types = XENV4V_PEEK_ANY_TYPE; // process for any type
    peek.ops   = XENV4V_PEEK_WRITE;    // and any ops
    peek.pfo   = pfo;                  // for a specific file object

    pendingIrp = IoCsqRemoveNextIrp(&pde->csqObject, &peek);
    while (pendingIrp != NULL) {
        V4vSimpleCompleteIrp(pendingIrp, STATUS_CANCELLED);
        pendingIrp = IoCsqRemoveNextIrp(&pde->csqObject, &peek);
    }
}

NTSTATUS NTAPI
V4vDispatchCreate(PDEVICE_OBJECT fdo, PIRP irp)
{
    XENV4V_EXTENSION   *pde = V4vGetDeviceExtension(fdo);
    PIO_STACK_LOCATION  isl;
    FILE_OBJECT        *pfo;
    XENV4V_CONTEXT     *ctx;

    UNREFERENCED_PARAMETER(fdo);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    isl = IoGetCurrentIrpStackLocation(irp);
    isl->FileObject->FsContext = NULL;
    isl->FileObject->FsContext2 = NULL;
    pfo = isl->FileObject;

    if (pfo->FsContext != NULL) {
        TraceError(("context already associated with the file!\n"));
        return V4vSimpleCompleteIrp(irp, STATUS_INVALID_HANDLE);
    }

    ctx = (XENV4V_CONTEXT*)ExAllocatePoolWithTag(NonPagedPool, sizeof(XENV4V_CONTEXT), XENV4V_TAG);
    if (ctx == NULL) {
        return V4vSimpleCompleteIrp(irp, STATUS_NO_MEMORY);
    }
    RtlZeroMemory(ctx, sizeof(XENV4V_CONTEXT));

    InitializeListHead(&ctx->le);
    ctx->state = XENV4V_STATE_UNINITIALIZED;
    ctx->type = XENV4V_TYPE_UNSPECIFIED;
    ctx->sdst.port = V4V_PORT_NONE;
    ctx->sdst.domain = V4V_DOMID_NONE;
    ctx->connId = XENV4V_INVALID_CONNID;

    // Add one ref count for the handle file object/handle reference
    ctx->refc++;
    
    // Link it to the device extension list
    V4vLinkToContextList(pde, ctx);

    // Now it is ready for prime time, set it as the file contex
    // and set a back pointer. The reference on the file object by
    // the context prevents the final close until the ref count goes
    // to zero. Note, this can occur after the cleanup when all the
    // user mode handles are closed.
    isl->FileObject->FsContext = ctx;
    ctx->pfoParent = isl->FileObject;
    ObReferenceObject(ctx->pfoParent);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return V4vSimpleCompleteIrp(irp, STATUS_SUCCESS);
}

NTSTATUS NTAPI
V4vDispatchCleanup(PDEVICE_OBJECT fdo, PIRP irp)
{
    NTSTATUS            status = STATUS_SUCCESS;
    XENV4V_EXTENSION   *pde = V4vGetDeviceExtension(fdo);
    PIO_STACK_LOCATION  isl = IoGetCurrentIrpStackLocation(irp);
    FILE_OBJECT        *pfo;
    XENV4V_CONTEXT     *ctx;
    LONG                val;

    UNREFERENCED_PARAMETER(fdo);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    pfo = isl->FileObject;

    //TraceInfo(("cleanup file - FsContext: 0x%x.\n", pfo->FsContext));    

    ctx = (XENV4V_CONTEXT*)pfo->FsContext;
    if (ctx != NULL) {
        // First check if we are in the CONNECT states and send an immediate reset (no queueing).
        val = InterlockedExchangeAdd(&ctx->state, 0);
        if (val & (XENV4V_STATE_LISTENING|XENV4V_STATE_CONNECTING|XENV4V_STATE_WAITING|
                   XENV4V_STATE_CONNECTED|XENV4V_STATE_ACCEPTED)) {
            V4vSendReset(pde, ctx, (uint32_t)ctx->connId, &ctx->sdst, TRUE);
        }

        if (val == XENV4V_STATE_CONNECTING) {
            // Turn of the connection timer
            V4vStopConnectionTimer(pde, FALSE);
        }
        else if (val == XENV4V_STATE_ACCEPTED) {
            V4vFlushAccepterQueueData(ctx);
        }

        val = InterlockedExchangeAdd(&ctx->type, 0);
        if (val != XENV4V_TYPE_LISTENER) {        
            // Go to the closed state. If the VIRQ handler picks up an IRP before we cancel the
            // queue for this file, it will see it is closed and cancel it there.
            InterlockedExchange(&ctx->state, XENV4V_STATE_CLOSED);

            // Drop it out of the list
            V4vUnlinkFromContextList(pde, ctx);

            // Release our ref count - if zero then the release routine will do the final cleanup
            V4vReleaseContextInternal(pde, ctx, TRUE);
        }
        else {
            // For listeners with 1 or more accepters attached, keep the context in the list
            // to process incoming data for the accepters.
            InterlockedExchange(&ctx->state, XENV4V_STATE_PASSIVE);

            // Do not unlink the context from the list. The following release call will take
            // care of that for listeners when the ref count goes to 1.
            V4vReleaseContextInternal(pde, ctx, TRUE);
        }
    }
    else {
        // This SNO
        TraceError(("cleanup file - no context associated with the file?!?\n"));
        status = STATUS_UNSUCCESSFUL;
    }

    V4vSimpleCompleteIrp(irp, status);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return status;
}

NTSTATUS NTAPI
V4vDispatchClose(PDEVICE_OBJECT fdo, PIRP irp)
{
    PIO_STACK_LOCATION isl;

    UNREFERENCED_PARAMETER(fdo);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    isl = IoGetCurrentIrpStackLocation(irp);

    // By the time we reach close, the final release has been called and
    // dropped its ref count in the file object. All that is left is to
    // NULL the context for consistency.
    isl->FileObject->FsContext = NULL;

    V4vSimpleCompleteIrp(irp, STATUS_SUCCESS);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return STATUS_SUCCESS;
}
