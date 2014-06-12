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

VOID
V4vFlushAccepterQueueData(XENV4V_CONTEXT *ctx)
{
    KLOCK_QUEUE_HANDLE  lqh;
    XENV4V_DATA        *pd, *pn;

    KeAcquireInStackQueuedSpinLock(&ctx->u.accepter.dataLock, &lqh);

    pd = ctx->u.accepter.dataList;
    while (pd != NULL) {
        pn = pd->next;
        ExFreePoolWithTag(pd, XENV4V_TAG);
        pd = pn;
    }
    ctx->u.accepter.dataList = NULL;
    ctx->u.accepter.dataTail = NULL;

    KeReleaseInStackQueuedSpinLock(&lqh);
}

VOID
V4vDisconnectStreamAndSignal(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx)
{
    LONG val;

    val = InterlockedExchangeAdd(&ctx->state, 0);
    if (val == XENV4V_STATE_CONNECTING) {
        // Turn of the connection timer (decrement the number of connectors using it).
        V4vStopConnectionTimer(pde, FALSE);
    }
    else if (val == XENV4V_STATE_ACCEPTED) {
        V4vFlushAccepterQueueData(ctx);
    }

    InterlockedExchange(&ctx->state, XENV4V_STATE_DISCONNECTED);
    V4vCancelAllFileIrps(pde, ctx->pfoParent);

    KeSetEvent(ctx->kevReceive, EVENT_INCREMENT, FALSE);
}

static __inline VOID
V4vRequeueIrps(XENV4V_EXTENSION *pde, LIST_ENTRY *irps)
{
    NTSTATUS    status;
    PIRP        nextIrp = NULL;
    PLIST_ENTRY   next = NULL;
    XENV4V_INSERT ins = {FALSE};

    // Put the IRPs back. They are returned in the order the were pulled off and
    // chained in the original queue. In the case of destination send processing
    // this could cause reordering in the main queue but this is mostly OK. The 
    // calling routines do this after their main processing loops so they don't 
    // keep picking up the same IRPs.
    //
    // Note that the tiny window where the file went to CLOSED but we put an IRP
    // back is handled by the second IRP cancellation call in V4vReleaseContextInternal().
    while (!IsListEmpty(irps)) {
        next = irps->Flink;
        nextIrp = CONTAINING_RECORD(next, IRP, Tail.Overlay.ListEntry);
        RemoveEntryList(&nextIrp->Tail.Overlay.ListEntry);
        InitializeListHead(&nextIrp->Tail.Overlay.ListEntry);
        status = IoCsqInsertIrpEx(&pde->csqObject, nextIrp, NULL, &ins);
        if (!NT_SUCCESS(status)) {
            V4vSimpleCompleteIrp(nextIrp, status);
        }
    }
}

// ---- WRITE ROUTINES ----

static ULONG32
V4vGetWriteIrpValues(XENV4V_CONTEXT *ctx, PIRP irp, v4v_addr_t **dstOut, uint8_t **msgOut, uint32_t *lenOut)
{
    PIO_STACK_LOCATION  isl = IoGetCurrentIrpStackLocation(irp);
    XENV4V_RESET       *rst;
    XENV4V_ACKNOWLEDGE *ack;

    if ((ULONG_PTR)irp->Tail.Overlay.DriverContext[0] & XENV4V_PEEK_SYN) {
        // SYN datagram packets are in IOCTL IRPs associated with stream contexts
        *dstOut = &ctx->sdst;
        *msgOut = (UCHAR*)irp->AssociatedIrp.SystemBuffer;
        *lenOut = sizeof(V4V_STREAM);
        return V4V_PROTO_STREAM;
    }
    else if ((ULONG_PTR)irp->Tail.Overlay.DriverContext[0] & XENV4V_PEEK_ACK) {
        // ACK datagram packets are in IOCTL IRPs associated with stream contexts
        // or sent internally as write IRPs
        if ((ULONG_PTR)irp->Tail.Overlay.DriverContext[0] & XENV4V_PEEK_IOCTL) {
            *dstOut = &ctx->sdst;
            *msgOut = (UCHAR*)irp->AssociatedIrp.SystemBuffer;
            *lenOut = sizeof(V4V_STREAM);
        }
        else {
            ack = (XENV4V_ACKNOWLEDGE*)irp->MdlAddress->MappedSystemVa;
            *dstOut = &ctx->sdst;
            *msgOut = (UCHAR*)&ack->sh;
            *lenOut = sizeof(V4V_STREAM);
        }
        return V4V_PROTO_STREAM;
    }
    else if ((ULONG_PTR)irp->Tail.Overlay.DriverContext[0] & XENV4V_PEEK_RST) {
        // Queued RST write IRPs use a special structure to hold the destination and dev ext.
        rst = (XENV4V_RESET*)irp->MdlAddress->MappedSystemVa;
        *dstOut = &rst->dst;
        *msgOut = (UCHAR*)&rst->sh;
        *lenOut = sizeof(V4V_STREAM);
        return V4V_PROTO_STREAM;
    }
    else if ((ULONG_PTR)irp->Tail.Overlay.DriverContext[0] & XENV4V_PEEK_STREAM) {
        // Streams have one dst for stream traffic stored at connect/accept time.
        *dstOut = &ctx->sdst;
        *msgOut = (isl->Parameters.Write.Length > 0) ? (UCHAR*)irp->MdlAddress->MappedSystemVa : &ctx->safe[0];
        *lenOut = isl->Parameters.Write.Length;
        return V4V_PROTO_STREAM;
    }
    else {
        // For datagrams, destination is in the message
        *dstOut = (v4v_addr_t*)irp->MdlAddress->MappedSystemVa;
        *msgOut = ((UCHAR*)irp->MdlAddress->MappedSystemVa) + sizeof(V4V_DATAGRAM);
        *lenOut = isl->Parameters.Write.Length - sizeof(V4V_DATAGRAM);
        return V4V_PROTO_DGRAM;
    }
}

static NTSTATUS
V4vDoWrite(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx, PIRP irp)
{
    NTSTATUS    status;
    v4v_addr_t *dst = NULL;
    uint8_t    *msg = NULL;
    uint32_t    len;
    ULONG32     written = 0;
    ULONG32     protocol;
    ULONG_PTR   flags;
    V4V_STREAM  sh;
    v4v_iov_t   iovs[2];

    // Already checked that the buffer is big enough for a v4v dgram header and not
    // an issue for streams. Also took care of 0 length drgam writes. Call helper to
    // get relevant values.
    protocol = V4vGetWriteIrpValues(ctx, irp, &dst, &msg, &len);
    flags = (ULONG_PTR)irp->Tail.Overlay.DriverContext[0];
    written = 0;

    if ((flags & XENV4V_PEEK_STREAM)&&((flags & XENV4V_PEEK_STREAM_FLAGS) == 0)) {
        // This is a stream send, we need to use the iov sendv function to cat the stream
        // header up front.
        sh.conid = (uint32_t)ctx->connId;
        sh.flags = 0;
        iovs[0].iov_len = sizeof(V4V_STREAM);
        iovs[0].iov_base = (ULONG64)(ULONG_PTR)(&sh);
        iovs[1].iov_len = len;
        iovs[1].iov_base = (ULONG64)(ULONG_PTR)(msg);

        status = V4vSendVec(&ctx->ringObject->ring->id.addr, dst, iovs, 2, protocol, &written);
        written -= sizeof(V4V_STREAM);
    }
    else {
        status = V4vSend(&ctx->ringObject->ring->id.addr, dst, protocol, msg, len, &written);
        if ((flags & XENV4V_PEEK_STREAM_FLAGS) == 0) {
            // Datagram write, add on the ammount send by caller
            written += sizeof(V4V_DATAGRAM);
        }
        else if (flags & XENV4V_PEEK_RST) {
            // for RST writes, report the entire structure as written (assuming is succeeded)
            written = sizeof(XENV4V_RESET);
        }
        else if ((flags & XENV4V_PEEK_ACK)&&((flags & XENV4V_PEEK_IOCTL) == 0)) {
            // If this was an ACK for an accepter, just complete it - already in ACCEPTED
            // state. Report the entire structure as written (assuming is succeeded).
            written = sizeof(XENV4V_ACKNOWLEDGE);
        }
        // Else for the other stream IOCTLs, just report the stream header amount written
    }
    if (status == STATUS_RETRY) {
        // Ring is full, just return retry
        return status;
    }
    else if (!NT_SUCCESS(status)) {
        // Failed SYN, go to the DISCONNECTED state and don't wait for an ACK. If the ACK
        // failed for a waiter or an accepter, fail the connection here and go to DISCONNECTED.
        if (flags & (XENV4V_PEEK_SYN|XENV4V_PEEK_ACK)) {
            V4vDisconnectStreamAndSignal(pde, ctx);
        }

        // If this a stream and we got a disconnected error back, transition to that state
        // and cancel all pending IO. Also set the event so clients will attempt to read
        // and realize it is disconnected.
        if ((status == STATUS_VIRTUAL_CIRCUIT_CLOSED)&&
            (InterlockedExchangeAdd(&(ctx->type), 0) & XENV4V_FILE_TYPE_STREAM)) {
            V4vDisconnectStreamAndSignal(pde, ctx);
        }

        // Actual error, dump it and try another one                             
        return V4vSimpleCompleteIrp(irp, status);
    }

    // SYN-ACK swizzle: if this is a connect SYN and it succeeded, then we want 
    // to requeue it as a read IOCTL IRP looking for an ACK.
    if (flags & XENV4V_PEEK_SYN) {
        // Update the flags
        flags &= ~(XENV4V_PEEK_WRITE|XENV4V_PEEK_SYN);
        flags |= (XENV4V_PEEK_READ|XENV4V_PEEK_ACK);
        irp->Tail.Overlay.DriverContext[0] = (PVOID)flags;
        return STATUS_PENDING;
    }

    // If this was an ACK for a waiter, transition to the connected 
    // state (and complete the IOCTL IRP).
    if ((flags & XENV4V_PEEK_ACK)&&(flags & XENV4V_PEEK_IOCTL)) {        
        InterlockedExchange(&ctx->state, XENV4V_STATE_CONNECTED);
        // There is no output buffer for the CONNECT-WAIT IOCTL so indicate 0 bytes written.
        written = 0;
    }

    // Complete it here with bytes written. Indicate that we consumed 
    // the appropriate size.
    irp->IoStatus.Information = written;
    irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

static VOID
V4vProcessDestinationWrites(XENV4V_EXTENSION *pde, v4v_ring_data_ent_t *entry)
{
    NTSTATUS            status;
    XENV4V_QPEEK        peek;
    PIRP                nextIrp = NULL;
    XENV4V_CONTEXT     *ctx = NULL;
    KLOCK_QUEUE_HANDLE  lqh;
    LIST_ENTRY          returnIrps;
    ULONG               counter = 0;

    peek.types = XENV4V_PEEK_ANY_TYPE; // process for any type
    peek.ops   = XENV4V_PEEK_WRITE;    // writes ops
    peek.pfo   = NULL;                 // not using file object search

    InitializeListHead(&returnIrps);

    do {
        // Grab an IRP by destination
        peek.dst = entry->ring; // using destination search
        nextIrp = IoCsqRemoveNextIrp(&pde->csqObject, &peek);
        if (nextIrp == NULL) {
            break;
        }

        // N.B. The assumption is that if the CSQ returned the IRP then the IRP is valid and
        // by extension the file object and all its state must still be intact so safe to access.
        ctx = (XENV4V_CONTEXT*)IoGetCurrentIrpStackLocation(nextIrp)->FileObject->FsContext;

        // Lock our ring to access it
        KeAcquireInStackQueuedSpinLock(&ctx->ringObject->lock, &lqh);

        // If this particular entry specifies the destination is closed then complete all the
        // IRPs indicating such.
        if ((entry->flags & V4V_RING_DATA_F_EXISTS) == 0) {
            KeReleaseInStackQueuedSpinLock(&lqh);

            // Complete the write with disconnected and for streams, go to disconnected state
            // and cancel all pending IO. Also set the event so clients will attempt to read
            // and realize it is disconnected.
            if (InterlockedExchangeAdd(&(ctx->type), 0) & XENV4V_FILE_TYPE_STREAM) {
                V4vDisconnectStreamAndSignal(pde, ctx);
            }

            V4vSimpleCompleteIrp(nextIrp, STATUS_VIRTUAL_CIRCUIT_CLOSED);
            continue;
        }

        // In the case of the first write, check the flag to see if the next size we reported will
        // fit at this point, if not then end here. If we get the first item in then we can just try
        // subsequent writes. If any fail with retry, we will get an interrupt later.
        if ((counter == 0)&&((entry->flags & V4V_RING_DATA_F_SUFFICIENT) == 0)) {
            KeReleaseInStackQueuedSpinLock(&lqh);
            InsertTailList(&returnIrps, &nextIrp->Tail.Overlay.ListEntry);
            break;
        }

        // Call the send helper to do the actual send of the data to the ring. For
        // all non retry/pending statuses, IRPs are completed internally.
        status = V4vDoWrite(pde, ctx, nextIrp);

        // Unlock the ring to lower contention before processing the final send status
        KeReleaseInStackQueuedSpinLock(&lqh);

        // Process the send status
        if (status == STATUS_RETRY) {
            // Ring is full, put the IRP back and try another. Since we got retry
            // we can just break and wait for the next interrupt.
            InsertTailList(&returnIrps, &nextIrp->Tail.Overlay.ListEntry);
            break;
        }
        else if (status == STATUS_PENDING) {
            // This was a connect SYN successfully written and swizzled. Requeue it, bump counter and
            // go on.
            InsertTailList(&returnIrps, &nextIrp->Tail.Overlay.ListEntry);
            counter++;
        }
        else if (NT_SUCCESS(status)) {
            // Send successful, update counter and just come around
            counter++;
        }
        // Else if it failed, V4vDoWrite() completed it internally.
    } while (TRUE);

    // Put the uncompleted ones back
    V4vRequeueIrps(pde, &returnIrps);
}

VOID
V4vProcessNotify(XENV4V_EXTENSION *pde)
{
    NTSTATUS         status;
    ULONG            i;
    v4v_ring_data_t *ringData;

    ringData = V4vCopyDestinationRingData(pde);
    if (ringData == NULL) {
        TraceError(("failed to allocate ring data - out of memory.\n"));
        return;
    }

    // Now do the actual notify
    status = V4vNotify(ringData);
    if (!NT_SUCCESS(status)) {
        // That ain't good
        ExFreePoolWithTag(ringData, XENV4V_TAG);
        return;
    }

    // Process each of the destinations
    for (i = 0; i < ringData->nent; i++) {
        V4vProcessDestinationWrites(pde, &ringData->data[i]);
    }

    ExFreePoolWithTag(ringData, XENV4V_TAG);
}

VOID
V4vProcessContextWrites(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx)
{
    NTSTATUS           status;
    KLOCK_QUEUE_HANDLE lqh;
    PIRP               nextIrp = NULL;
    XENV4V_QPEEK       peek;
    LIST_ENTRY         returnIrps;

    peek.types = XENV4V_PEEK_ANY_TYPE; // process for any type
    peek.ops   = XENV4V_PEEK_WRITE;    // writes ops
    peek.pfo   = ctx->pfoParent;       // for a specific file object

    InitializeListHead(&returnIrps);

    // For datagram writes, we always have a 1 to 1 file to ring relationship so we
    // lock the ring and start popping out pending IRPs either from the write dispatch
    // handler or the VIRQ DPC.
    KeAcquireInStackQueuedSpinLock(&ctx->ringObject->lock, &lqh);

    do {
        // Any IRPs to work with
        nextIrp = IoCsqRemoveNextIrp(&pde->csqObject, &peek);
        if (nextIrp == NULL) {
            // No more IRPs, we are done here.
            break;
        }

        // Call the send helper to do the actual send of the data to the ring. For
        // all non retry statuses, IRPs are completed internally.
        status = V4vDoWrite(pde, ctx, nextIrp);
        if (status == STATUS_RETRY) {
            // Ring is full, put the IRP back and try another. 
            InsertTailList(&returnIrps, &nextIrp->Tail.Overlay.ListEntry);
        }
        else if (status == STATUS_PENDING) {
            // This was a connect SYN successfully written. Requeue it and
            // go on.
            InsertTailList(&returnIrps, &nextIrp->Tail.Overlay.ListEntry);
        }
    } while (TRUE);

    KeReleaseInStackQueuedSpinLock(&lqh);

    // Put the uncompleted ones back
    V4vRequeueIrps(pde, &returnIrps);
}

NTSTATUS NTAPI
V4vDispatchWrite(PDEVICE_OBJECT fdo, PIRP irp)
{
    NTSTATUS            status = STATUS_SUCCESS;
    XENV4V_EXTENSION   *pde = V4vGetDeviceExtension(fdo);
    PIO_STACK_LOCATION  isl = IoGetCurrentIrpStackLocation(irp);
    XENV4V_CONTEXT     *ctx;
    LONG                val, ds;
    ULONG_PTR           flags = 0;
    ULONG_PTR           dcs[2] = {0, 0};
    XENV4V_INSERT       ins = {FALSE};

    TraceReadWrite(("====> '%s'.\n", __FUNCTION__));

    ctx = (XENV4V_CONTEXT*)isl->FileObject->FsContext;
    val = InterlockedExchangeAdd(&ctx->state, 0);
    ds  = InterlockedExchangeAdd(&pde->state, 0);
    
    // Store any context values passed down by internal writes
    dcs[0] = (ULONG_PTR)irp->Tail.Overlay.DriverContext[0];
    dcs[1] = (ULONG_PTR)irp->Tail.Overlay.DriverContext[1];    

    // Any IRPs that are queued are given a sanity initialization
    V4vInitializeIrp(irp);

    switch (val) {
    case XENV4V_STATE_BOUND:
        // Input check for datagram header
        if (isl->Parameters.Write.Length < sizeof(V4V_DATAGRAM)) {
            return V4vSimpleCompleteIrp(irp, STATUS_BUFFER_TOO_SMALL);
        }

        // N.B. zero length datagram writes are still dispatched through the hypercall since they 
        // can be used to test that the other end is still there.

        // Store the state we have for servicing this IRP
        irp->Tail.Overlay.DriverContext[0] = (PVOID)(ULONG_PTR)(XENV4V_PEEK_DGRAM|XENV4V_PEEK_WRITE);
        break;
    case XENV4V_STATE_CONNECTED:
    case XENV4V_STATE_ACCEPTED:
    case XENV4V_STATE_LISTENING:
    case XENV4V_STATE_PASSIVE:
        // When we transition to stream, there may be pended IRPs that are still set to be sent
        // as datagrams. This is fine since the state is set in the IRP. All new IRPs will be setup
        // as stream packets. For listeners, the only valid IRPs coming in here are RSTs so handle that.

        // First, check if this is one of our own RST or ACK IRPs coming down. This could be for contexts
        // in the listening or passive states so we test this first.
        if ((dcs[0] == XENV4V_PEEK_RST)&&(dcs[1] == XENV4V_RST_MAGIC)) {
            flags = XENV4V_PEEK_RST;
            // Push resets to the front of the queue to make them higher priority sends.
            ins.insertHead = TRUE;
        }
        else if ((dcs[0] == XENV4V_PEEK_ACK)&&(dcs[1] == XENV4V_ACK_MAGIC)) {
            flags = XENV4V_PEEK_ACK;
            // Acks go to the back of the queue.
        }
        else if ((val == XENV4V_STATE_LISTENING)||(val == XENV4V_STATE_PASSIVE)) {
            // Should not try to write on the actual listening file context. If it is in passive mode then there
            // is no user file handle so it will never be here.
            ASSERT(val != XENV4V_STATE_PASSIVE);
            TraceWarning(("cannot perform writes on the LISTENING file context %p, failing IRP request %p\n", ctx, irp));
            return V4vSimpleCompleteIrp(irp, STATUS_INVALID_DEVICE_REQUEST);
        }

        // Store the state we have for servicing this IRP.
        irp->Tail.Overlay.DriverContext[0] = (PVOID)(ULONG_PTR)(XENV4V_PEEK_STREAM|XENV4V_PEEK_WRITE|flags);
        break;
    case XENV4V_STATE_DISCONNECTED:
        // Indicate disconnected or reset to caller
        return V4vSimpleCompleteIrp(irp, STATUS_VIRTUAL_CIRCUIT_CLOSED);
    default:
        // N.B. we should not be in here in the CONNECTING/WAITING states 
        // or the state XENV4V_STATE_DISCONNECTED which is a dead connection.
        TraceWarning(("invalid state 0x%x for context %p write IRP request %p\n", val, ctx, irp));
        return V4vSimpleCompleteIrp(irp, STATUS_INVALID_DEVICE_REQUEST);
    }

    // The rest is common to both types

    // Map in the DIRECT IO locked MDL - do it once up front since we will access it
    // from the Q. If the length is zero, don't touch the MDL, it is NULL.
    if (isl->Parameters.Write.Length > 0) {
        if (MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority) == NULL) {
            return V4vSimpleCompleteIrp(irp, STATUS_NO_MEMORY);
        }

#if defined(XENV4V_WRITE_RO_PROTECT) && defined(DBG)
        status = MmProtectMdlSystemAddress(irp->MdlAddress, PAGE_READONLY);
        if (!NT_SUCCESS(status)) {
            return V4vSimpleCompleteIrp(irp, status);
        }
#endif

    }

    // Always queue it to the back and marks it pending (except RSTs)
    status = IoCsqInsertIrpEx(&pde->csqObject, irp, NULL, &ins);
    if (NT_SUCCESS(status)) {
        status = STATUS_PENDING;

        // Drive any write IO unless the device is stopped.
        if ((ds & XENV4V_DEV_STOPPED) == 0) {
            V4vProcessContextWrites(pde, ctx);
        }
    }
    else {
        // Fail it
        V4vSimpleCompleteIrp(irp, status);
    }

    TraceReadWrite(("<==== '%s'.\n", __FUNCTION__));

    return status;
}

// ---- READ ROUTINES ----

static VOID
V4vProcessDatagramReads(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx, BOOLEAN *pntfy)
{
    KLOCK_QUEUE_HANDLE  lqh;
    PIRP                nextIrp = NULL;
    PIO_STACK_LOCATION  isl;
    XENV4V_QPEEK        peek;
    v4v_addr_t         *src = NULL;
    uint8_t            *msg = NULL;
    uint32_t            len;
    uint32_t            protocol;
    ssize_t             ret;

    peek.types = XENV4V_PEEK_DGRAM; // process for dgram types
    peek.ops   = XENV4V_PEEK_READ;  // read ops
    peek.pfo   = ctx->pfoParent;    // for a specific file object

    // For datagram reads, we always have a 1 to 1 file to ring relationship so we
    // lock the ring and start popping out pending IRPs either from the read dispatch
    // handler or the VIRQ DPC.
    KeAcquireInStackQueuedSpinLock(&ctx->ringObject->lock, &lqh);

    do {
        if (ctx->ringObject->ring->rx_ptr == ctx->ringObject->ring->tx_ptr) {
            // No data so clear any events
            KeClearEvent(ctx->kevReceive);
            break; // no more to read
        }

        // Is data to read, anybody waiting?
        nextIrp = IoCsqRemoveNextIrp(&pde->csqObject, &peek);
        if (nextIrp == NULL) {
            // Nobody to accept it so set the data ready event for clients who use it.
            KeSetEvent(ctx->kevReceive, EVENT_INCREMENT, FALSE);
            break;
        }

        // Already checked there is room for the header in IRP buffer when it was queued
        isl = IoGetCurrentIrpStackLocation(nextIrp);
        src = (v4v_addr_t*)nextIrp->MdlAddress->MappedSystemVa;
        msg = ((UCHAR*)nextIrp->MdlAddress->MappedSystemVa) + sizeof(V4V_DATAGRAM);
        len = isl->Parameters.Read.Length - sizeof(V4V_DATAGRAM);
        ret = v4v_copy_out(ctx->ringObject->ring, src, &protocol, msg, len, 1);
        if (ret < 0) {
            TraceError(("failure reading data into IRP %p\n", nextIrp));
            V4vRecoverRing(ctx);
            // Fail this IRP - let caller know there is a mess
            V4vSimpleCompleteIrp(nextIrp, STATUS_INTERNAL_DB_CORRUPTION);
            continue;
        }

        // Ok, successfully read 0 or more bytes and consumed one message
        nextIrp->IoStatus.Information = ret + sizeof(V4V_DATAGRAM);
        nextIrp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(nextIrp, IO_NO_INCREMENT);

        // If we did a read, we need to notify the v4v backend (and process any writes
        // that are pending while we are at it).
        XENV4V_SET_BOOL_PTR(pntfy);
    } while (TRUE);

    KeReleaseInStackQueuedSpinLock(&lqh);
}

static BOOLEAN
V4vProcessPreConnectReads(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx, LONG state, BOOLEAN *pntfy)
{
    NTSTATUS            status;
    KLOCK_QUEUE_HANDLE  lqh;
    PIRP                nextIrp = NULL;
    PIO_STACK_LOCATION  isl;
    XENV4V_QPEEK        peek;
    v4v_addr_t          src = {0};
    uint32_t            protocol = 0;
    ssize_t             ret;
    ULONG_PTR           flags;
    BOOLEAN             rc = FALSE;
    V4V_STREAM          sh = {0};
    V4V_WAIT_VALUES    *wvs;
    XENV4V_INSERT       ins = {FALSE};

    if (state == XENV4V_STATE_CONNECTING) {
        peek.types = XENV4V_PEEK_STREAM;               // process for stream types
        peek.ops   = XENV4V_PEEK_READ|XENV4V_PEEK_ACK; // ACK read ops
        peek.pfo   = ctx->pfoParent;                   // for a specific file object
    }
    else {
        peek.types = XENV4V_PEEK_STREAM;               // process for stream types
        peek.ops   = XENV4V_PEEK_READ|XENV4V_PEEK_SYN; // SYN read ops
        peek.pfo   = ctx->pfoParent;                   // for a specific file object
    }

    // For stream connecting reads, we always have a 1 to 1 file to ring relationship so we
    // lock the ring and start popping out pending IRPs either from the read dispatch
    // handler or the VIRQ DPC. The connecting read is in the original connect IOCTL IRP
    // that has not been completed yet.
    // For listener connecting SYNs for now we will do a 1 to 1 file to ring allow a single
    // accept to happen. Then the listener file will become the accepted end. The listening
    // IOCTL IRP came in through V4vProcessContextReads(). Once we get a SYN, we will requeue
    // it as a write ACK.
    KeAcquireInStackQueuedSpinLock(&ctx->ringObject->lock, &lqh);

    do {
        if (ctx->ringObject->ring->rx_ptr == ctx->ringObject->ring->tx_ptr) {
            break; // no more to read
        }

        // Is data to read, anybody waiting?
        nextIrp = IoCsqRemoveNextIrp(&pde->csqObject, &peek);
        if (nextIrp == NULL) {
            // Nobody to accept it - for streams this is handled in a special way
            // depending on connect/listen/wait
            if (state == XENV4V_STATE_WAITING) {
                // This should never happen since we certainly queue the read first 
                // and wait (by definition as the listener).
                TraceError(("listener received data with no outstanding IRP ????\n"));
            }
            // For connectors, there is a small window where the ACK for the connector can 
            // come back but the connect IOCTL IRP has not been swizzled and returned to the 
            // queue. In this special case, we have a timer running to pick these up if needed.
            break;
        }

        // For connecting reads, we should only be getting ACKs from the other end so
        // the first read we see should be that ACK. For listening reads, we should be
        // waiting for the first SYN to come in. Already checked there is room for
        // the stream header in IRP buffer when it was queued.
        isl = IoGetCurrentIrpStackLocation(nextIrp);
        ret = v4v_copy_out(ctx->ringObject->ring, &src, &protocol, (VOID*)&sh, sizeof(V4V_STREAM), 1);
        if (ret < 0) {
            TraceError(("failure reading pre-stream data into IRP %p\n", nextIrp));
            V4vRecoverRing(ctx);

            // Fail this IRP and go to the DISCONNECTED state and let caller know
            // this connection is done and the ring is a mess.
            V4vDisconnectStreamAndSignal(pde, ctx);

            V4vSimpleCompleteIrp(nextIrp, STATUS_INTERNAL_DB_CORRUPTION);
            break;
        }

        // Whatever happens below, we did read data out of our ring
        XENV4V_SET_BOOL_PTR(pntfy);

        if (state == XENV4V_STATE_CONNECTING) {
            // Sanity check the ACK including only reads with a ACK set should be our
            // connect IOCTL IRP. This will cover RSTs from the other side too.
            if ((isl->MajorFunction != IRP_MJ_DEVICE_CONTROL)||(ret < sizeof(V4V_STREAM))||
                (sh.conid != (ULONG32)ctx->connId)||((sh.flags & V4V_SHF_ACK) == 0)||
                (ctx->sdst.domain != src.domain)||(!XENV4V_PROTOCOL_TEST(protocol, V4V_PROTO_STREAM))) {
                // Fail this IRP and go to the DISCONNECTED state and let caller know
                // this connection is done.
                V4vDisconnectStreamAndSignal(pde, ctx);

                V4vSimpleCompleteIrp(nextIrp, STATUS_DEVICE_PROTOCOL_ERROR);
                // Drop out here 
                break;
            }

            // Ok, successfully read 1 ACK so we can go to connected. There is no output
            // buffer for a CONNECT IOCTL so indicate 0 read.
            V4vStopConnectionTimer(pde, FALSE);
            InterlockedExchange(&ctx->state, XENV4V_STATE_CONNECTED);
            nextIrp->IoStatus.Information = 0;
            nextIrp->IoStatus.Status = STATUS_SUCCESS;
            IoCompleteRequest(nextIrp, IO_NO_INCREMENT);
            rc = TRUE;
            break;
        }

        if (state == XENV4V_STATE_WAITING) {
            // Sanity check the SYN including only reads with a SYN set should be our 
            // connect IOCTL IRP. This will cover RSTs from the other side too (not that
            // that makes much sense).
            if ((isl->MajorFunction != IRP_MJ_DEVICE_CONTROL)||(ret < sizeof(V4V_STREAM))||
                ((sh.flags & V4V_SHF_SYN) == 0)||(!XENV4V_PROTOCOL_TEST(protocol, V4V_PROTO_STREAM))) {
                // Fail this IRP and go to the DISCONNECTED state and let caller know 
                // this connection is done.
                V4vDisconnectStreamAndSignal(pde, ctx);

                V4vSimpleCompleteIrp(nextIrp, STATUS_DEVICE_PROTOCOL_ERROR);
                // Drop out here 
                break;
            }

            // We now have a connection ID and a stream destination address to save.
            ctx->sdst = src;
            ctx->connId = (ULONG64)sh.conid;

            // Update the stream header in the IRPs buffer. The lvs pointer points to the IRPs actual
            // in/out buffer the IOCTL is defined to have output.
            wvs = (V4V_WAIT_VALUES*)nextIrp->AssociatedIrp.SystemBuffer;
            wvs->sh.flags = V4V_SHF_ACK;
            wvs->sh.conid = (ULONG32)ctx->connId;

            // SYN-ACK swizzle: if this is a listen SYN that was read then we want 
            // to requeue it as a write IOCTL IRP ready to send the ACK.
            flags = (ULONG_PTR)nextIrp->Tail.Overlay.DriverContext[0];
            flags &= ~(XENV4V_PEEK_READ|XENV4V_PEEK_SYN);
            flags |= (XENV4V_PEEK_WRITE|XENV4V_PEEK_ACK);
            nextIrp->Tail.Overlay.DriverContext[0] = (PVOID)flags;
            // The ACK successfully read and swizzled, requeue it.
            status = IoCsqInsertIrpEx(&pde->csqObject, nextIrp, NULL, &ins);
            if (!NT_SUCCESS(status)) {
                // Fail this IRP and go to the DISCONNECTED state and let caller know 
                // this connection is done.
                V4vDisconnectStreamAndSignal(pde, ctx);

                V4vSimpleCompleteIrp(nextIrp, status);
            }

            // Leave rc == FALSE to prevent processing stream reads at this point since we
            // are still waiting to ACK.
            break;
        }

        // Whatever this IRP is, we better complete it and get rid of it (SNO) including 
        // XENV4V_STATE_LISTENING for now.
        TraceError(("invalid state 0x%x in V4vProcessPreConnectReads() for IRP %p\n", state, nextIrp));
        V4vSimpleCompleteIrp(nextIrp, STATUS_INTERNAL_ERROR);
    } while (FALSE);

    KeReleaseInStackQueuedSpinLock(&lqh);

    return rc;
}

static VOID
V4vProcessConnectorReads(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx, BOOLEAN *pntfy)
{
    NTSTATUS            status;
    KLOCK_QUEUE_HANDLE  lqh;
    PIRP                nextIrp = NULL;
    PIO_STACK_LOCATION  isl;
    XENV4V_QPEEK        peek;
    v4v_addr_t          src = {0};
    uint32_t            len;
    uint32_t            protocol = 0;
    ssize_t             ret;
    BOOLEAN             retain = FALSE;
    V4V_STREAM          sh;
    XENV4V_INSERT       ins = {TRUE}; // this one is inserted to the head

    peek.types = XENV4V_PEEK_STREAM; // process for stream types
    peek.ops   = XENV4V_PEEK_READ;   // read ops
    peek.pfo   = ctx->pfoParent;     // for a specific file object

    // For connector reads, we always have a 1 to 1 file to ring relationship so we
    // lock the ring and start popping out pending IRPs either from the read dispatch
    // handler or the VIRQ DPC. 
    KeAcquireInStackQueuedSpinLock(&ctx->ringObject->lock, &lqh);

    do {
        // If we retained any IRPs then we read data and dumped it so the ring 
        // changed and we need to notify.
        if (retain) {
            XENV4V_SET_BOOL_PTR(pntfy);
        }

        if (ctx->ringObject->ring->rx_ptr == ctx->ringObject->ring->tx_ptr) {
            // If the last IRP is being retained but there is no more to read so
            // return it to the front of the queue.
            if (retain) {
                status = IoCsqInsertIrpEx(&pde->csqObject, nextIrp, NULL, &ins);
                if (!NT_SUCCESS(status)) {
                    V4vSimpleCompleteIrp(nextIrp, status);
                }
            }

            // No data so clear any events
            KeClearEvent(ctx->kevReceive);

            break; // no more to read
        }

        // Last iteration dumped some data but did not complete the current IRP so try again.
        if (!retain) {
            // Is data to read, anybody waiting?
            nextIrp = IoCsqRemoveNextIrp(&pde->csqObject, &peek);
            if (nextIrp == NULL) {
                // Nobody to accept it so set the data ready event for clients who use it.
                KeSetEvent(ctx->kevReceive, EVENT_INCREMENT, FALSE);
                break;
            }
        }

        // There should never be any pre-stream IOCTL reads in the queue once this
        // context is connected.
        if ((ULONG_PTR)nextIrp->Tail.Overlay.DriverContext[0] & (XENV4V_PEEK_SYN|XENV4V_PEEK_ACK)) {
            TraceError(("invalid IOCTL found for CONNECTED context, IRP %p\n", nextIrp));
            V4vSimpleCompleteIrp(nextIrp, STATUS_INVALID_DEVICE_REQUEST);
            continue;
        }

        // For stream reads, there will be a stream header preceeding each chunk
        // we read. We want to peek the header and get the total size first.
        ret = v4v_copy_out(ctx->ringObject->ring, &src, &protocol, 
                           (VOID*)&sh, sizeof(V4V_STREAM), 0);
        if (ret < 0) {
            TraceError(("failure reading stream data into IRP %p\n", nextIrp));
            V4vRecoverRing(ctx); // emergency measures
            // Fail this IRP - let caller know there is a mess
            V4vSimpleCompleteIrp(nextIrp, STATUS_INTERNAL_DB_CORRUPTION);
            continue;
        }

        // Set our flag for the following checks
        retain = TRUE;

        // Check what we have gotten back
        if ((!XENV4V_PROTOCOL_TEST(protocol, V4V_PROTO_STREAM))||(ret < sizeof(V4V_STREAM))) {
            // Dump it in the bit bucket, not stream data. We do not want to deal with
            // bad data on our ring to prevent DoS etc. Retain current IRP and try again.
            (VOID)v4v_copy_out(ctx->ringObject->ring, NULL, NULL, NULL, 0, 1);
            continue;
        }

        if (sh.flags & V4V_SHF_SYN) {
            // Illegal at this point (we should never have a SYN on the connector either).
            // Dump it and RST the connection. Note we check for presence of a payload which
            // is a protocol violation in which case we ignore it/do not RST. Also never
            // send a RST if the sender set the RST flag.
            ret = v4v_copy_out(ctx->ringObject->ring, &src, &protocol, 
                               (VOID*)&sh, sizeof(V4V_STREAM), 1);
            if ((ret == sizeof(V4V_STREAM))&&((sh.flags & V4V_SHF_RST) == 0)) {
                V4vSendReset(pde, ctx, sh.conid, &src, FALSE);
            }
            continue;
        }

        if (sh.conid != (ULONG32)ctx->connId) {
            // This may occur when a connection disappears and reappears on the same port
            // (e.g. if a domain restarts) but the other end doesn't know about it. So it
            // tries to send traffic with the old conneection ID. These always get RST unless
            // they are a RST themselves (avoid endless loop of RSTs).
            (VOID)v4v_copy_out(ctx->ringObject->ring, NULL, NULL, NULL, 0, 1);
            if ((sh.flags & V4V_SHF_RST) == 0) {
                V4vSendReset(pde, ctx, sh.conid, &src, FALSE);
            }
            continue;
        }

        if (ctx->sdst.domain != src.domain) {
            // Only accept traffic from our peer domain on the connection at this point. Send a 
            // RST unless they are a RST themselves (avoid endless loop of RSTs).
            (VOID)v4v_copy_out(ctx->ringObject->ring, NULL, NULL, NULL, 0, 1);
            if ((sh.flags & V4V_SHF_RST) == 0) {
                V4vSendReset(pde, ctx, sh.conid, &src, FALSE);
            }
            continue;
        }

        if (sh.flags & V4V_SHF_ACK) {
            // Illegal at this point since we are connected already. Since the connId matches
            // we will deal with it - Dump it and RST the connection. Note we check for presence 
            // of a payload which is a protocol violation in which case we ignore it/do not RST.
            // Also never send a RST if the sender set the RST flag.
            ret = v4v_copy_out(ctx->ringObject->ring, &src, &protocol, 
                               (VOID*)&sh, sizeof(V4V_STREAM), 1);
            if ((ret == sizeof(V4V_STREAM))&&((sh.flags & V4V_SHF_RST) == 0)) {
                V4vSendReset(pde, ctx, sh.conid, &src, FALSE);
            }
            continue;
        }
 
        // End of checks, reset flag
        retain = FALSE;

        if (sh.flags & V4V_SHF_RST) {
            // The other side disconnected us, disconnect this end and fail the IRP. Also
            // dump all pending IRPs so we don't try to keep reading/writing.
            // Flush all pending IRPs so we don't try to keep reading/writing. Note a few 
            // could slip in after the flush but that is no big deal, they will be met with 
            // another RST from the other end.
            V4vDisconnectStreamAndSignal(pde, ctx);

            V4vSimpleCompleteIrp(nextIrp, STATUS_VIRTUAL_CIRCUIT_CLOSED);
            break;
        }

        isl = IoGetCurrentIrpStackLocation(nextIrp);
        len = isl->Parameters.Read.Length;

        // TODO for now, we will fail the read and force the caller to use a bigger
        // buffer. In the future we can read into an intermediate buffer and get
        // closer to stream semantics.
        if (len < (ret - sizeof(V4V_STREAM))) {
            // Leave the data in the ring, fail the IRP and go on.
            V4vSimpleCompleteIrp(nextIrp, STATUS_BUFFER_OVERFLOW);
            continue;
        }

        ret = v4v_copy_out_offset(ctx->ringObject->ring, &src, &protocol,
                                  nextIrp->MdlAddress->MappedSystemVa, len + sizeof(V4V_STREAM), 1, sizeof(V4V_STREAM));
        if (ret < 0) {
            TraceError(("failure reading stream data into IRP %p\n", nextIrp));
            V4vRecoverRing(ctx); // emergency measures
            // Fail this IRP - let caller know there is a mess
            V4vSimpleCompleteIrp(nextIrp, STATUS_INTERNAL_DB_CORRUPTION);
            continue;
        }

        // Ok, successfully read some stream data (maybe 0 bytes).
        nextIrp->IoStatus.Information = ret - sizeof(V4V_STREAM);
        nextIrp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(nextIrp, IO_NO_INCREMENT);
        XENV4V_SET_BOOL_PTR(pntfy);
    } while (TRUE);

    KeReleaseInStackQueuedSpinLock(&lqh);
}

static VOID
V4vProcessPreAcceptReads(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx, V4V_STREAM *psh, v4v_addr_t *psrc)
{
    KLOCK_QUEUE_HANDLE  lqh;
    XENV4V_SYN         *sptr;
    LONG                i;

    // Lock the SYN list state
    KeAcquireInStackQueuedSpinLock(&ctx->u.listener.synLock, &lqh);
    ASSERT(((ctx->u.listener.synCount >= 0)&&(ctx->u.listener.synCount <= ctx->u.listener.backlog)));
    if (ctx->u.listener.synCount == ctx->u.listener.backlog) {
        // Reached the max SYN backlog limit, send a RST and dump the SYN.
        KeReleaseInStackQueuedSpinLock(&lqh);
        V4vSendReset(pde, ctx, psh->conid, psrc, FALSE);
        TraceVerbose(("SYN backlog limit %d reached, RST connection attempt\n", ctx->u.listener.backlog));
        return;
    }

    // Locate the next free SYN record.
    sptr = ctx->u.listener.synList;
    for (i = 0; i < ctx->u.listener.backlog; i++, sptr++) {
        if (!sptr->pending) {
            break;
        }
    }
    // Better have found one!
    ASSERT(sptr < (ctx->u.listener.synList + ctx->u.listener.backlog));

    // Set it up and chain it in.
    sptr->next = NULL;
    sptr->last = NULL;
    sptr->pending = TRUE;
    sptr->sdst = (*psrc);
    sptr->connId = (ULONG64)psh->conid;
    if (ctx->u.listener.synTail != NULL) {
        ctx->u.listener.synTail->next = sptr;
        sptr->last = ctx->u.listener.synTail;
        ctx->u.listener.synTail = sptr;
    }
    else {
        ctx->u.listener.synHead = sptr;
        ctx->u.listener.synTail = sptr;
    }
    ctx->u.listener.synCount++;

    KeReleaseInStackQueuedSpinLock(&lqh);

    // Drive accepts
    V4vDoAccepts(pde, ctx);
}

static BOOLEAN
V4vProcessAccepterReads(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx, BOOLEAN notify, BOOLEAN *pntfy)
{
    KLOCK_QUEUE_HANDLE  lqh;
    PIRP                nextIrp = NULL;
    PIO_STACK_LOCATION  isl;
    uint32_t            len;
    XENV4V_DATA        *pd;
    XENV4V_QPEEK        peek;
    BOOLEAN             signaled = FALSE;

    peek.types = XENV4V_PEEK_STREAM; // process for stream types
    peek.ops   = XENV4V_PEEK_READ;   // read ops
    peek.pfo   = ctx->pfoParent;     // for a specific file object

    // For accepter reads, the data is being read out of the accepter's queue. This
    // may be driven by a user read, the VIRQ DPC or V4vProcessAccepterBufferedReads().
    // Since we share the listener's ring, it is the listener context that actually drives
    // the fetching of data from the ring. In here we will satisfy as many IRPs with as
    // much of the queued data as possible. 
    KeAcquireInStackQueuedSpinLock(&ctx->u.accepter.dataLock, &lqh);

    do {
        // Anything queued?
        if (ctx->u.accepter.dataList == NULL) {
            // No data so clear any events
            if (!notify) {
                KeClearEvent(ctx->kevReceive);
            }

            break; // no more to read
        }

        // Is data to read, anybody waiting?
        nextIrp = IoCsqRemoveNextIrp(&pde->csqObject, &peek);
        if (nextIrp == NULL) {
            // Nobody to accept it so set the data ready event for clients who use it.
            KeSetEvent(ctx->kevReceive, EVENT_INCREMENT, FALSE);
            signaled = TRUE;
            break;
        }

        // There should never be any pre-stream IOCTL reads in the queue once this
        // context is accepted.
        if ((ULONG_PTR)nextIrp->Tail.Overlay.DriverContext[0] & (XENV4V_PEEK_SYN|XENV4V_PEEK_ACK)) {
            TraceError(("invalid IOCTL found for ACCEPTED context, IRP %p\n", nextIrp));
            V4vSimpleCompleteIrp(nextIrp, STATUS_INVALID_DEVICE_REQUEST);
            continue;
        }

        pd = ctx->u.accepter.dataList;
        isl = IoGetCurrentIrpStackLocation(nextIrp);
        len = isl->Parameters.Read.Length;

        // TODO for now, we will fail the read and force the caller to use a bigger
        // buffer. To fix this we can read part of the dataList entry and put the rest
        // back in the same location.
        if (len < pd->length) {
            // Leave the data in the queue, fail the IRP and go on.
            V4vSimpleCompleteIrp(nextIrp, STATUS_BUFFER_OVERFLOW);
            continue;
        }

        // Data was checked before it was queued. Copy it to the IPR, pop it
        // out and coplete the IO.
        RtlCopyMemory(nextIrp->MdlAddress->MappedSystemVa, pd->data, pd->length);

        // Ok, successfully read some stream data (maybe 0 bytes).
        nextIrp->IoStatus.Information = pd->length;
        nextIrp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(nextIrp, IO_NO_INCREMENT);
        XENV4V_SET_BOOL_PTR(pntfy);

        ctx->u.accepter.dataList = pd->next;
        ExFreePoolWithTag(pd, XENV4V_TAG);
    } while (TRUE);

    KeReleaseInStackQueuedSpinLock(&lqh);

    return signaled;
}

static VOID
V4vProcessAccepterBufferedReads(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx, ssize_t dlen)
{
    KLOCK_QUEUE_HANDLE  lqh;
    PIRP                nextIrp;
    XENV4V_DATA        *pd;
    XENV4V_QPEEK        peek;
    v4v_addr_t          src = {0};
    uint32_t            protocol = 0;
    uint32_t            len = 0;
    ssize_t             ret;
    BOOLEAN             signaled;

    peek.types = XENV4V_PEEK_STREAM; // process for stream types
    peek.ops   = XENV4V_PEEK_READ;   // read ops
    peek.pfo   = ctx->pfoParent;     // for a specific file object

    // Already have the ring locked, drive any accepter reads to from the internal queue.
    signaled = V4vProcessAccepterReads(pde, ctx, TRUE, NULL);

    // Now we have satisfied any reads from the queue (though there may still be some left). Grab an IRP
    // if there are any more, if not the data will be queued.
    nextIrp = IoCsqRemoveNextIrp(&pde->csqObject, &peek);
    if (nextIrp != NULL) {
        // TODO For now we are failing this. To fix it later, read a chunk here 
        // and buffer the remainder (and not fail the IRP).
        len = IoGetCurrentIrpStackLocation(nextIrp)->Parameters.Read.Length;
        if (len < (dlen - sizeof(V4V_STREAM))) {
            // Queue it and fail the IRP
            V4vSimpleCompleteIrp(nextIrp, STATUS_BUFFER_OVERFLOW);
            nextIrp = NULL;
        }
    }

    if (nextIrp == NULL) {
        // Nobody to accept it or buffer too small so we have to queue the data and set the data 
        // ready event for clients who use it.
        pd = (XENV4V_DATA*)ExAllocatePoolWithTag(NonPagedPool, sizeof(XENV4V_DATA) + dlen, XENV4V_TAG);
        if (pd == NULL) {
            TraceError(("failed to allocate data queue entry - out of memory.\n"));
            return;
        }
        pd->next = NULL;
        pd->data = (UCHAR*)pd + sizeof(XENV4V_DATA);
        pd->length = (ULONG)dlen - sizeof(V4V_STREAM);

        // Read it out of the listener's ring - dlen already has the size of the stream header in it
        ret = v4v_copy_out_offset(ctx->ringObject->ring, &src, &protocol, pd->data, dlen, 1, sizeof(V4V_STREAM));
        if (ret < 0) {
            TraceError(("failure reading stream data into queue buffer\n"));
            V4vRecoverRing(ctx); // emergency measures
            ExFreePoolWithTag(pd, XENV4V_TAG);
            return;
        }

        // Chain it at the end
        KeAcquireInStackQueuedSpinLock(&ctx->u.accepter.dataLock, &lqh);
        if (ctx->u.accepter.dataList == NULL) {
            ctx->u.accepter.dataList = pd;
            ctx->u.accepter.dataTail = pd;
        }
        else {
            ctx->u.accepter.dataTail->next = pd;
            ctx->u.accepter.dataTail = pd;
        }
        KeReleaseInStackQueuedSpinLock(&lqh);

        if (!signaled) {
            KeSetEvent(ctx->kevReceive, EVENT_INCREMENT, FALSE);
        }
        return;
    }

    // Final case, we have an IRP to put the read in and the queue should be empty.
    ASSERT(ctx->u.accepter.dataList == NULL);

    ret = v4v_copy_out_offset(ctx->ringObject->ring, &src, &protocol,
                              nextIrp->MdlAddress->MappedSystemVa, dlen + sizeof(V4V_STREAM), 1, sizeof(V4V_STREAM));
    if (ret < 0) {
        TraceError(("failure reading stream data into IRP %p\n", nextIrp));
        V4vRecoverRing(ctx); // emergency measures
        // Fail this IRP - let caller know there is a mess
        V4vSimpleCompleteIrp(nextIrp, STATUS_INTERNAL_DB_CORRUPTION);
        return;
    }

    // Ok, successfully read some stream data (maybe 0 bytes).
    nextIrp->IoStatus.Information = ret - sizeof(V4V_STREAM);
    nextIrp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(nextIrp, IO_NO_INCREMENT);
}

static VOID
V4vProcessListenerReads(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx, LONG state)
{
    KLOCK_QUEUE_HANDLE  lqh;
    v4v_addr_t          src = {0};
    uint32_t            protocol = 0;
    ssize_t             ret;
    V4V_STREAM          sh;
    XENV4V_CONTEXT     *actx;

    // For stream listener reads, we always have a 1 to 1 file to ring relationship so we
    // lock the ring and start peeking at the stream traffic. If it is a SYN, we queue it
    // and alert user land that it can try to accept. All other traffic gets passed to a
    // routine to process accept stream data. Note that the listener processing is entirely
    // internal and only the VIRQ DPC calls it.
    KeAcquireInStackQueuedSpinLock(&ctx->ringObject->lock, &lqh);

    do {
        // Note the listener processing code always drains the ring putting it in a state
        // where it will be notified by the interrupt when more data comes.
        if (ctx->ringObject->ring->rx_ptr == ctx->ringObject->ring->tx_ptr) {
            break; // no more to read
        }

        // For stream reads, there will be a stream header preceeding each chunk
        // we read. We want to peek the header and get the total size first.
        ret = v4v_copy_out(ctx->ringObject->ring, &src, &protocol, 
                           (VOID*)&sh, sizeof(V4V_STREAM), 0);
        if (ret < 0) {
            TraceError(("failure reading listener stream data\n"));
            V4vRecoverRing(ctx); // emergency measures
            continue;
        }

        // Check what we have gotten back
        if ((!XENV4V_PROTOCOL_TEST(protocol, V4V_PROTO_STREAM))||(ret < sizeof(V4V_STREAM))) {
            // Dump it in the bit bucket, not stream data. We do not want to deal with
            // bad data on our ring to prevent DoS etc. Retain current IRP and try again.
            (VOID)v4v_copy_out(ctx->ringObject->ring, NULL, NULL, NULL, 0, 1);
            continue;
        }

        if (sh.flags & V4V_SHF_SYN) {
            // SYN procesing code
            ret = v4v_copy_out(ctx->ringObject->ring, &src, &protocol, (VOID*)&sh, sizeof(V4V_STREAM), 1);
            if (ret < 0) {
                TraceError(("failure reading SYN listener data\n"));
                V4vRecoverRing(ctx); // emergency measures
                continue;
            }

            if (state == XENV4V_STATE_LISTENING) {
                V4vProcessPreAcceptReads(pde, ctx, &sh, &src);
            }
            else {
                // Else in the passive state so dump it, no more accepts
                (VOID)v4v_copy_out(ctx->ringObject->ring, NULL, NULL, NULL, 0, 1);
                if ((sh.flags & V4V_SHF_RST) == 0) {
                    V4vSendReset(pde, ctx, sh.conid, &src, FALSE);
                }
            }
            continue;
        }

        actx = V4vGetContextByConnectionId(pde, sh.conid);
        if (actx == NULL) {
            // The accepter is gone - may be that it is in the process of closing or
            // it is just a bum packet. Dump the data and reset this one.
            (VOID)v4v_copy_out(ctx->ringObject->ring, NULL, NULL, NULL, 0, 1);
            if ((sh.flags & V4V_SHF_RST) == 0) {
                V4vSendReset(pde, ctx, sh.conid, &src, FALSE);
            }
            continue;
        }

        if (XENV4V_ADDR_COMPARE(&actx->sdst, &src)) {
            // Only accept traffic from our peer domain and port on the connection at this point. Send a 
            // RST on the accepter context unless it is a RST itself (avoid endless loop of RSTs).
            (VOID)v4v_copy_out(ctx->ringObject->ring, NULL, NULL, NULL, 0, 1);
            if ((sh.flags & V4V_SHF_RST) == 0) {
                V4vSendReset(pde, actx, sh.conid, &src, FALSE);
            }
            V4vReleaseContext(pde, actx);
            continue;
        }

        if (sh.flags & V4V_SHF_RST) {
            // The other side disconnected us, disconnect this end and dump any existing
            // data in the accepter queue.
            // Flush all pending IRPs so we don't try to keep reading/writing. Note a few 
            // could slip in after the flush but that is no big deal, they will be met with 
            // another RST from the other end.
            V4vDisconnectStreamAndSignal(pde, actx);
            V4vReleaseContext(pde, actx);
            break;
        }
    
        // Call the helper to process incoming data for this accepted stream. If it can't read it
        // or queue it, it will have to dump it.
        V4vProcessAccepterBufferedReads(pde, actx, ret);
        V4vReleaseContext(pde, actx);
    } while (TRUE);

    KeReleaseInStackQueuedSpinLock(&lqh);
}

VOID
V4vProcessContextReads(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx)
{
    LONG val;

    // Reads can be processed by the current state of the context because it
    // it is during reads that the context can progress to the next state. It
    // is possible to use a ring for datagrams and later switch it to a stream
    // ring but there is no way back to the bound datagram state so we treat it
    // as a one way street.
    val = InterlockedExchangeAdd(&ctx->state, 0);
    switch (val) {
    case XENV4V_STATE_CLOSED:
        // Must have just closed - the cleanup dispatch routine will cancel any
        // IRPs for it so just ignore it.
        return;
    case XENV4V_STATE_DISCONNECTED:
        // Caller will find out next time it tries to do IO
        return;
    case XENV4V_STATE_BOUND:
        V4vProcessDatagramReads(pde, ctx, NULL);
        break;
    case XENV4V_STATE_CONNECTING:
    case XENV4V_STATE_WAITING:
        if (!V4vProcessPreConnectReads(pde, ctx, val, NULL)) {
            break;
        }
        // fall through
    case XENV4V_STATE_CONNECTED:
        V4vProcessConnectorReads(pde, ctx, NULL);
        break;
    case XENV4V_STATE_LISTENING:
    case XENV4V_STATE_PASSIVE:
        V4vProcessListenerReads(pde, ctx, val);
        break;
    case XENV4V_STATE_ACCEPTED:
        V4vProcessAccepterReads(pde, ctx, FALSE, NULL);
        break;
    default:
        // May be freshly opened file that has not been bound, just ignore.
        break;
    };
}

NTSTATUS NTAPI
V4vDispatchRead(PDEVICE_OBJECT fdo, PIRP irp)
{
    NTSTATUS            status = STATUS_SUCCESS;
    PIO_STACK_LOCATION  isl = IoGetCurrentIrpStackLocation(irp);
    XENV4V_EXTENSION   *pde = V4vGetDeviceExtension(fdo);
    XENV4V_CONTEXT     *ctx;
    LONG                val, ds;
    XENV4V_INSERT       ins = {FALSE};
    BOOLEAN             notify = FALSE;

    TraceReadWrite(("====> '%s'.\n", __FUNCTION__));

    ctx = (XENV4V_CONTEXT*)isl->FileObject->FsContext;
    val = InterlockedExchangeAdd(&ctx->state, 0);
    ds  = InterlockedExchangeAdd(&pde->state, 0);

    // Any IRPs that are queued are given a sanity initialization
    V4vInitializeIrp(irp);

    // Map in the DIRECT IO locked MDL - do it once up front since we will access it
    // from the Q. We can do this up front since we are only dealing with READ IRPs.
    // Don't touch the MDL if the read length is zero.
    if (isl->Parameters.Read.Length > 0) {
        if (MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority) == NULL) {
            return V4vSimpleCompleteIrp(irp, STATUS_NO_MEMORY);
        }
    }

    switch (val) {
    case XENV4V_STATE_BOUND:
        // Input check for datagram header - this weeds out zero length reads too.
        if (isl->Parameters.Read.Length < sizeof(V4V_DATAGRAM)) {
            status = V4vSimpleCompleteIrp(irp, STATUS_BUFFER_TOO_SMALL);
            break;
        }

        // Store the state we have for servicing this IRP
        irp->Tail.Overlay.DriverContext[0] = (PVOID)(ULONG_PTR)(XENV4V_PEEK_DGRAM|XENV4V_PEEK_READ);
        // Always queues it to the back and marks it pending
        status = IoCsqInsertIrpEx(&pde->csqObject, irp, NULL, &ins);
        if (!NT_SUCCESS(status)) {
            V4vSimpleCompleteIrp(irp, status);
            break;
        }
        status = STATUS_PENDING;

        // If device is stopped, just leave it pended
        if (ds & XENV4V_DEV_STOPPED) {
            break;
        }

        // Drive any read IO
        V4vProcessDatagramReads(pde, ctx, &notify);
        break;
    case XENV4V_STATE_CONNECTING:
    case XENV4V_STATE_WAITING:
    case XENV4V_STATE_CONNECTED:
    case XENV4V_STATE_ACCEPTED:
        // For streams, a zero length read doesn't make much sense. We will just complete it here.
        if (isl->Parameters.Read.Length == 0) {
            V4vSimpleCompleteIrp(irp, STATUS_SUCCESS);
            break;
        }
        // Store the state we have for servicing this IRP - this a stream read that would happen after
        // we transition our of the connecting/listening state.
        irp->Tail.Overlay.DriverContext[0] = (PVOID)(ULONG_PTR)(XENV4V_PEEK_STREAM|XENV4V_PEEK_READ);
        // Always queues it to the back and marks it pending
        status = IoCsqInsertIrpEx(&pde->csqObject, irp, NULL, &ins);
        if (!NT_SUCCESS(status)) {
            // Fail the IRP
            V4vSimpleCompleteIrp(irp, status);
            break;
        }
        status = STATUS_PENDING;

        // If device is stopped, just leave it pended
        if (ds & XENV4V_DEV_STOPPED) {
            break;
        }

        if ((val == XENV4V_STATE_CONNECTING)||(val == XENV4V_STATE_WAITING)) {
            // Drive any read IO. If we process a single ACK/SYN succesfully, we will be connected
            // or accepted and then can try reading stream bits.
            if (V4vProcessPreConnectReads(pde, ctx, val, &notify)) {
                V4vProcessConnectorReads(pde, ctx, &notify);
            }
        }
        else if (val == XENV4V_STATE_CONNECTED){
            V4vProcessConnectorReads(pde, ctx, &notify);
        }
        else {
            V4vProcessAccepterReads(pde, ctx, FALSE, &notify);
        }
        break;
    case XENV4V_STATE_DISCONNECTED:
        // Indicate disconnected or reset to caller
        status = V4vSimpleCompleteIrp(irp, STATUS_VIRTUAL_CIRCUIT_CLOSED);
        break;
    case XENV4V_STATE_LISTENING:
        // Should not try to read on the actual listening file context.
        TraceWarning(("cannot perform reads on the LISTENING file context %p, failing IRP request %p\n", ctx, irp));
        status = V4vSimpleCompleteIrp(irp, STATUS_INVALID_DEVICE_REQUEST);
        break;
    default:      
        TraceWarning(("invalid state 0x%x for context %p read IRP request %p\n", val, ctx, irp));
        status = V4vSimpleCompleteIrp(irp, STATUS_INVALID_DEVICE_REQUEST);
    }

    // If we did a read, we need to notify the v4v backend (and process any writes
    // that are pending while we are at it).
    if (notify) {
        V4vProcessNotify(pde);
    }

    TraceReadWrite(("<==== '%s'.\n", __FUNCTION__));

    return status;
}
