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
#include <ntstrsafe.h>
#include "xenv4v.h"

// N.B. Do not put any code in here that calls the CSQ routines because
// this will require the inclusion of csq.h which causes many compile errors.
// Making CSQ calls w/o the header will implicitly link the DDI's exported
// from ntoskrnl - this is bad.

static __inline VOID
V4vCsqGetDestination(PIRP irp, v4v_addr_t **dstOut)
{
    XENV4V_CONTEXT *ctx;
    XENV4V_RESET   *rst;

    if ((ULONG_PTR)irp->Tail.Overlay.DriverContext[0] & XENV4V_PEEK_RST) {
        // Queued RST write IRPs use a special structure to hold the destination.
        rst = (XENV4V_RESET*)irp->MdlAddress->MappedSystemVa;
        *dstOut = &rst->dst;        
    }
    else if ((ULONG_PTR)irp->Tail.Overlay.DriverContext[0] & XENV4V_PEEK_STREAM) {
        // Streams have one dst for stream traffic stored at connect/accept time. This
        // includes ACKs that were sent internally for accepter contexts.
        ctx = (XENV4V_CONTEXT*)IoGetCurrentIrpStackLocation(irp)->FileObject->FsContext;
        *dstOut = &ctx->sdst;
    }
    else {
        // Datagrams, destination is in the message
        *dstOut = (v4v_addr_t*)irp->MdlAddress->MappedSystemVa;
    }
}

static BOOLEAN
V4vCsqPeekTest(PIRP irp, PVOID peekContext)
{
    XENV4V_QPEEK       *qp = (XENV4V_QPEEK*)peekContext;
    PIO_STACK_LOCATION  isl = IoGetCurrentIrpStackLocation(irp);
    XENV4V_DESTINATION *idst;
    ULONG_PTR           types = (ULONG_PTR)irp->Tail.Overlay.DriverContext[0] & XENV4V_PEEK_ANY_TYPE;
    ULONG_PTR           ops   = (ULONG_PTR)irp->Tail.Overlay.DriverContext[0] & XENV4V_PEEK_ANY_OP;

    // First, the types and ops always have to match
    if ((qp->types & types)&&(qp->ops & ops)) {
        // Next we are either searching by file object or destination
        if (qp->pfo == NULL) {
            // If no desitination was supplied, just match it
            if (qp->dst.domain == DOMID_INVALID) {
                return TRUE;
            }
            // Search by destination, safely use the stashed dest record.
            idst = (XENV4V_DESTINATION*)irp->Tail.Overlay.DriverContext[1];
            if (XENV4V_ADDR_COMPARE(qp->dst, idst->dst)) {
                return TRUE; // destination address match
            }
        }
        else if (isl->FileObject == qp->pfo) {
            return TRUE; // file object match
        }
    }

    return FALSE;
}

static VOID
V4vCsqChainIrp(XENV4V_DESTINATION *xdst, PIRP irp, BOOLEAN front)
{
    XENV4V_DESTINATION *idst;
    PIRP                nextIrp = NULL;

    // If we found a destination then there is at least one entry in the list
    // so chain this irp at the end unless front is specified. In this case
    // the IRP is being pushed up front on the list and the length is updated.
    nextIrp = xdst->nextIrp;
    ASSERT(nextIrp != NULL);

    if (!front) {
        while (nextIrp != NULL) {
            idst = (XENV4V_DESTINATION*)nextIrp->Tail.Overlay.DriverContext[1];

            if (idst->nextIrp == NULL) {
                idst->nextIrp = irp;
                break;
            }
            nextIrp = idst->nextIrp;
        }
    }
    else {
        xdst->nextIrp = irp;
        idst = (XENV4V_DESTINATION*)irp->Tail.Overlay.DriverContext[1];
        idst->nextIrp = nextIrp;
        XENV4V_PAYLOAD_DATA_LEN(xdst->nextIrp, xdst->nextLength);
    }
}

static VOID
V4vCsqUnchainIrp(XENV4V_DESTINATION *xdst, PIRP irp)
{
    XENV4V_DESTINATION *idst, *ldst;
    PIRP                irpLast = NULL;
    PIRP                irpCurr = xdst->nextIrp;

    // Has to be at least one present, just unchain it
    do {
        idst = (XENV4V_DESTINATION*)irpCurr->Tail.Overlay.DriverContext[1];
        if (irp == irpCurr) {            
            if (irpLast == NULL) {
                // Found up front, update next len too                
                xdst->nextIrp = idst->nextIrp;
                if (xdst->nextIrp != NULL) {
                    XENV4V_PAYLOAD_DATA_LEN(xdst->nextIrp, xdst->nextLength);
                }
            }
            else {
                ldst = (XENV4V_DESTINATION*)irpLast->Tail.Overlay.DriverContext[1];
                ldst->nextIrp = idst->nextIrp;
            }

            // Flag it with an invalid pointer - handy for debugging.
            idst->nextIrp = (PVOID)(ULONG_PTR)(-1);
            return;
        }

        irpLast = irpCurr;
        irpCurr = idst->nextIrp;
    } while (irpCurr != NULL);

    // We should have found it???
    ASSERT(irpCurr != NULL);
}

static BOOLEAN
V4vCsqLinkDestination(XENV4V_EXTENSION *pde, PIRP irp, BOOLEAN front)
{
    XENV4V_DESTINATION *xdst = NULL;
    XENV4V_DESTINATION *idst;
    v4v_addr_t         *dst = NULL;
    PLIST_ENTRY         head, next;    

    // Get the destination and init things we need
    V4vCsqGetDestination(irp, &dst);    
    head = &pde->destList;
    next = head->Flink;

    // Allocate a block to hold the destination information needed for unchaining
    // the IRP. During cancelation removal, the IRPs buffer can be freed so we 
    // cannot rely on reading the destination information out of the mapped
    // buffer at that point.
    irp->Tail.Overlay.DriverContext[1] = 
        ExAllocateFromNPagedLookasideList(&pde->destLookasideList);
    if (irp->Tail.Overlay.DriverContext[1] == NULL) {
        TraceError(("failed to allocate irp destinaion record - out of memory.\n"));
        return FALSE;
    }

    // Some of the fields are not used for the irp's destination record. Only the
    // nextIrp and dst fields.
    idst = (XENV4V_DESTINATION*)irp->Tail.Overlay.DriverContext[1];
    RtlZeroMemory(idst, sizeof(XENV4V_DESTINATION));
    idst->dst = *dst;

    while (next != head) {
        xdst = CONTAINING_RECORD(next, XENV4V_DESTINATION, le);
        if (XENV4V_ADDR_COMPARE(xdst->dst, (*dst))) {
            ASSERT(xdst->refc > 0);
            xdst->refc++;

            // Chain the IRP on this destination entry
            V4vCsqChainIrp(xdst, irp, front);
            return TRUE;
        }
        next = next->Flink;
    }

    // If we are still here, a destination entry was not found so create a new one
    xdst = (XENV4V_DESTINATION*)ExAllocateFromNPagedLookasideList(&pde->destLookasideList);
    if (xdst == NULL) {
        ExFreeToNPagedLookasideList(&pde->destLookasideList,
                                    irp->Tail.Overlay.DriverContext[1]);
        irp->Tail.Overlay.DriverContext[1] = NULL;
        TraceError(("failed to allocate destinaion record - out of memory.\n"));
        return FALSE;
    }
    InitializeListHead(&xdst->le);
    xdst->refc = 1;
    xdst->dst = *dst;
    xdst->nextIrp = irp;
    XENV4V_PAYLOAD_DATA_LEN(irp, xdst->nextLength);
    InsertTailList(&pde->destList, &xdst->le);
    pde->destCount++;

    return TRUE;
}

static VOID
V4vCsqUnlinkDestination(XENV4V_EXTENSION *pde, PIRP irp)
{
    XENV4V_DESTINATION *xdst;
    XENV4V_DESTINATION *idst;
    PLIST_ENTRY         head, next;

    ASSERT(pde->destCount > 0);

    // Get the destination record and init things we need
    idst = (XENV4V_DESTINATION*)irp->Tail.Overlay.DriverContext[1];
    ASSERT(idst != 0);
    head = &pde->destList;
    next = head->Flink;

    while (next != head) {
        xdst = CONTAINING_RECORD(next, XENV4V_DESTINATION, le);
        if (XENV4V_ADDR_COMPARE(xdst->dst, idst->dst)) {
            ASSERT(xdst->refc > 0);
            ASSERT(xdst->nextIrp != NULL);
            V4vCsqUnchainIrp(xdst, irp);
            ExFreeToNPagedLookasideList(&pde->destLookasideList,
                                        irp->Tail.Overlay.DriverContext[1]);
            irp->Tail.Overlay.DriverContext[1] = NULL;

            xdst->refc--;
            if (xdst->refc == 0) {
                ASSERT(xdst->nextIrp == NULL);
                RemoveEntryList(&xdst->le);
                ExFreeToNPagedLookasideList(&pde->destLookasideList, xdst);
                pde->destCount--;
            }
            break;
        }
        next = next->Flink;
    }
}

NTSTATUS NTAPI
V4vCsqInsertIrpEx(PIO_CSQ csq, PIRP irp, PVOID insertContext)
{
    XENV4V_EXTENSION *pde = V4vCsqGetDeviceExtension(csq);
    XENV4V_INSERT    *ins = (XENV4V_INSERT*)insertContext;

    ASSERT(((pde->pendingIrpCount != 0)||(pde->destCount == 0)));

    if (pde->pendingIrpCount == XENV4V_MAX_IRP_COUNT) {
        TraceError(("maximun pended IRP count reached!! max: %d.\n", pde->pendingIrpCount));
        return STATUS_QUOTA_EXCEEDED;
    }

    if ((ULONG_PTR)irp->Tail.Overlay.DriverContext[0] & XENV4V_PEEK_WRITE) {
        if (!V4vCsqLinkDestination(pde, irp, ins->insertHead)) {
            return STATUS_NO_MEMORY;
        }
    }

    // Do this here before we put it on the queue. Once queued we cannot touch the IRP
    // safely outside of CSQ calls.
    IoMarkIrpPending(irp);
    InitializeListHead(&irp->Tail.Overlay.ListEntry);

    // Normally the IRP is inserted at the tail in a queue or re-queue operation. The stream
    // processing may insert it at the head though.
    if (!ins->insertHead) {
        InsertTailList(&pde->pendingIrpQueue, &irp->Tail.Overlay.ListEntry);
    }
    else {
        InsertHeadList(&pde->pendingIrpQueue, &irp->Tail.Overlay.ListEntry);
    }

    // Bump count
    ASSERT(pde->pendingIrpCount >= 0);
    pde->pendingIrpCount++;

    return STATUS_SUCCESS;
}

VOID NTAPI
V4vCsqRemoveIrp(PIO_CSQ csq, PIRP irp)
{
    XENV4V_EXTENSION *pde = V4vCsqGetDeviceExtension(csq);

    if ((ULONG_PTR)irp->Tail.Overlay.DriverContext[0] & XENV4V_PEEK_WRITE) {
        V4vCsqUnlinkDestination(pde, irp);
    }

    RemoveEntryList(&irp->Tail.Overlay.ListEntry);

    // Clear out dangling list pointers and drop count
    InitializeListHead(&irp->Tail.Overlay.ListEntry);
    pde->pendingIrpCount--;
    ASSERT(pde->pendingIrpCount >= 0);
    ASSERT(((pde->pendingIrpCount != 0)||(pde->destCount == 0)));
}

PIRP NTAPI
V4vCsqPeekNextIrp(PIO_CSQ csq, PIRP irp, PVOID peekContext)
{
    XENV4V_EXTENSION *pde = V4vCsqGetDeviceExtension(csq);
    PIRP              nextIrp = NULL;
    PLIST_ENTRY       head, next;

    head = &pde->pendingIrpQueue;

    // If the IRP is NULL, we will start peeking from the head else
    // we will start from that IRP onwards (since irps are inserted
    // at the tail).
    next = ((irp == NULL) ? head->Flink : irp->Tail.Overlay.ListEntry.Flink);

    while (next != head) {
        nextIrp = CONTAINING_RECORD(next, IRP, Tail.Overlay.ListEntry);

        // A context is used during cleanup to remove all IRPs for a given
        // file that has all its handles closed. If there is a context, match it
        // first.
        if (peekContext == NULL) {
            break; // on first one
        }

        if (V4vCsqPeekTest(nextIrp, peekContext)) {
            break; // on first one that matches
        }
        
        // Onward
        nextIrp = NULL;
        next = next->Flink;
    }

    return nextIrp;
}

VOID NTAPI
V4vCsqAcquireLock(PIO_CSQ csq, PKIRQL irqlOut)
{
    XENV4V_EXTENSION *pde = V4vCsqGetDeviceExtension(csq);

    KeAcquireSpinLock(&pde->queueLock, irqlOut);
}

VOID NTAPI
V4vCsqReleaseLock(PIO_CSQ csq, KIRQL irql)
{
    XENV4V_EXTENSION *pde = V4vCsqGetDeviceExtension(csq);

    KeReleaseSpinLock(&pde->queueLock, irql);
}

VOID NTAPI
V4vCsqCompleteCanceledIrp(PIO_CSQ csq, PIRP irp)
{
    XENV4V_EXTENSION   *pde = V4vCsqGetDeviceExtension(csq);
    PIO_STACK_LOCATION  isl;
    ULONG               ioControlCode;
    XENV4V_CONTEXT     *ctx;
    XENV4V_CONTEXT     *actx;
    struct v4v_addr    *peer;
    V4V_ACCEPT_PRIVATE *priv;
    ULONG               size;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    TraceVerbose(("Cancelled-IRP %p\n", irp));

    do {
        isl = IoGetCurrentIrpStackLocation(irp);
        ctx = (XENV4V_CONTEXT*)isl->FileObject->FsContext;

        // First, if this is a context that is a connector durring in the connecting state, then
        // the connection timer should be decremented for it's cancelation.
        if ((InterlockedExchangeAdd(&ctx->type, 0) == XENV4V_TYPE_CONNECTOR)&&
            (InterlockedExchangeAdd(&ctx->state, 0) == XENV4V_STATE_CONNECTING)) {
            V4vStopConnectionTimer(pde, FALSE);
            break;
        }

        // Second, have to clean up the extra ref count on pended IOCTL IRPs in the
        // accepting state.      
        if (isl->MajorFunction != IRP_MJ_DEVICE_CONTROL) {
            break;
        }

        ioControlCode = isl->Parameters.DeviceIoControl.IoControlCode;
#if defined(_WIN64)
        if ((ioControlCode != V4V_IOCTL_ACCEPT_32)&&
            (ioControlCode != V4V_IOCTL_ACCEPT)) {
            break;
        }
#else
        if (ioControlCode != V4V_IOCTL_ACCEPT) {
            break;
        }
#endif

        // Gather the private accept information
        size = V4vGetAcceptPrivate(ioControlCode, irp->AssociatedIrp.SystemBuffer, &priv, &peer);
        ASSERT(size > 0);

        // Get the stashed referenced context pointer for the new accepter
#if defined(_WIN64)
        actx = (XENV4V_CONTEXT*)priv->q.a;
#else
        actx = (XENV4V_CONTEXT*)priv->d.a;
#endif

        if (InterlockedExchangeAdd(&actx->state, 0) != XENV4V_STATE_ACCEPTING) {
            break;
        }

        // Drop the ref count
        V4vReleaseContext(pde, actx);
    } while (FALSE);

    V4vSimpleCompleteIrp(irp, STATUS_CANCELLED);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
}

v4v_ring_data_t*
V4vCopyDestinationRingData(XENV4V_EXTENSION *pde)
{
    KIRQL               irql;
    v4v_ring_data_t    *ringData;
    XENV4V_DESTINATION *xdst;
    LONG                i;
    ULONG               size;
    PLIST_ENTRY         head, next;

    KeAcquireSpinLock(&pde->queueLock, &irql);

    size = sizeof(v4v_ring_data_t) + pde->destCount*sizeof(v4v_ring_data_ent_t);
    ringData = (v4v_ring_data_t*)ExAllocatePoolWithTag(NonPagedPool, size, XENV4V_TAG);
    if (ringData == NULL) {
        KeReleaseSpinLock(&pde->queueLock, irql);
        TraceError(("failed to allocate destination list - out of memory.\n"));
        return NULL;
    }

    RtlZeroMemory(ringData, sizeof(v4v_ring_data_t));
    ringData->magic = V4V_RING_DATA_MAGIC;
    ringData->nent = pde->destCount;

    head = &pde->destList;
    next = head->Flink;

    for (i = 0; i < pde->destCount; i++) {
        ASSERT(next != head);
        xdst = CONTAINING_RECORD(next, XENV4V_DESTINATION, le);
        ringData->data[i].ring = xdst->dst;
        ringData->data[i].space_required = xdst->nextLength;
        next = next->Flink;
    }

    KeReleaseSpinLock(&pde->queueLock, irql);

    return ringData;
}
