/*
 * Copyright (c) 2012 Citrix Systems, Inc.
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

#include <ntifs.h>
#include <csq.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include "xenv4v.h"

static NTSTATUS
V4vCtrlInitializeFile(XENV4V_CONTEXT *ctx, V4V_INIT_VALUES *invs, PIRP irp);

ULONG
V4vGetAcceptPrivate(ULONG code, VOID *buffer, V4V_ACCEPT_PRIVATE **ppriv, struct v4v_addr **ppeer)
{
    ULONG size = 0;

    UNREFERENCED_PARAMETER(code);

#if defined(_WIN64)
    if (code == V4V_IOCTL_ACCEPT_32)
    {
        V4V_ACCEPT_VALUES_32 *avs32 = (V4V_ACCEPT_VALUES_32*)buffer;

        *ppeer = &avs32->peerAddr;       
        *ppriv = (V4V_ACCEPT_PRIVATE*)((UCHAR*)avs32 + FIELD_OFFSET(V4V_ACCEPT_VALUES_32, priv));
        size = sizeof(V4V_ACCEPT_VALUES_32);
    }
    else
#endif
    {
        V4V_ACCEPT_VALUES *avs = (V4V_ACCEPT_VALUES*)buffer;

        *ppeer = &avs->peerAddr;        
        *ppriv = (V4V_ACCEPT_PRIVATE*)((UCHAR*)avs + FIELD_OFFSET(V4V_ACCEPT_VALUES, priv));
        size = sizeof(V4V_ACCEPT_VALUES);
    }

    return size;
}

VOID
V4vDoAccepts(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx)
{
    NTSTATUS            status;
    KLOCK_QUEUE_HANDLE  lqh;
    PIO_STACK_LOCATION  isl;
    PIRP                nextIrp = NULL;
    XENV4V_QPEEK        peek;
    ULONG               ioControlCode;
    PVOID               ioBuffer;
    struct v4v_addr    *peer;
    ULONG               size;
    XENV4V_CONTEXT     *actx;
    XENV4V_SYN         *sptr;
    V4V_ACCEPT_PRIVATE *priv;

    peek.types = XENV4V_PEEK_STREAM; // process for stream types
    peek.ops   = XENV4V_PEEK_ACCEPT; // accept ops
    peek.pfo   = ctx->pfoParent;     // for a specific file object

    // Lock the SYN list state and process SYN entries. For each,
    // try to locate an accept IRP in the queue for this listener.
    KeAcquireInStackQueuedSpinLock(&ctx->u.listener.synLock, &lqh);

    do {
        if (ctx->u.listener.synCount == 0) {
            // No data so clear any events indicating pending accepts.
            KeClearEvent(ctx->kevReceive);
            break; // no more to read
        }

        // SYNs, any pending accepts?
        nextIrp = IoCsqRemoveNextIrp(&pde->csqObject, &peek);
        if (nextIrp == NULL) {
            // Nobody to accept it so tell the listener there are SYNs waiting.
            // Set the data ready event for clients who use it.
            KeSetEvent(ctx->kevReceive, EVENT_INCREMENT, FALSE);
            break;
        }

        // Now there is a SYN and an accept IRP to take it.
        isl           = IoGetCurrentIrpStackLocation(nextIrp);
        ioControlCode = isl->Parameters.DeviceIoControl.IoControlCode;
        ioBuffer      = nextIrp->AssociatedIrp.SystemBuffer;

        // Gather the private accept information
        size = V4vGetAcceptPrivate(ioControlCode, ioBuffer, &priv, &peer);

        // Get the stashed referenced context pointer for the new accepter
#if defined(_WIN64)
        actx = (XENV4V_CONTEXT*)priv->q.a;
#else
        actx = (XENV4V_CONTEXT*)priv->d.a;
#endif

        // Pop the next in order from the head of the list
        ASSERT(ctx->u.listener.synHead != NULL);
        ASSERT(ctx->u.listener.synTail != NULL);
        sptr = ctx->u.listener.synHead;
        if (ctx->u.listener.synHead != ctx->u.listener.synTail) {
            // More than one on the list
            ctx->u.listener.synHead = sptr->next;
        }
        else {
            // Only one on the list, reset pointers
            ctx->u.listener.synHead = NULL;
            ctx->u.listener.synTail = NULL;
        }

        ctx->u.listener.synCount--;
        ASSERT(ctx->u.listener.synCount >= 0);

        // Finish the accept, clear the SYN entry and drop the ref count on the context
        actx->sdst   = sptr->sdst;
        actx->connId = sptr->connId;
        (*peer)      = sptr->sdst;
        RtlZeroMemory(sptr, sizeof(XENV4V_SYN));
        V4vReleaseContext(pde, actx);
        InterlockedExchange(&actx->state, XENV4V_STATE_ACCEPTED);

        // Send the ACK to our peer
        status = V4vSendAcknowledge(pde, actx);
        if (!NT_SUCCESS(status)) {
            // Fail the IRP and go to the disconnected state for the new context
            V4vSimpleCompleteIrp(nextIrp, status);
            InterlockedExchange(&actx->state, XENV4V_STATE_DISCONNECTED);
            continue;
        }

        // Complete the IRP - this will finish the accept call. Set the IOCTL output
        // buffer to the size appropriate for the user mode caller (32b vs 64b).
        nextIrp->IoStatus.Information = size;
        nextIrp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(nextIrp, IO_NO_INCREMENT);
    } while (TRUE);

    KeReleaseInStackQueuedSpinLock(&lqh);
}

static NTSTATUS
V4vCtrlDumpRing(XENV4V_CONTEXT *ctx)
{
    NTSTATUS           status = STATUS_INVALID_DEVICE_REQUEST;
    LONG               val;
    KLOCK_QUEUE_HANDLE lqh;

    val = InterlockedExchangeAdd(&ctx->state, 0);

    if (val & (XENV4V_STATE_BOUND|XENV4V_STATE_LISTENING|XENV4V_STATE_WAITING|
               XENV4V_STATE_CONNECTING|XENV4V_STATE_CONNECTED|
               XENV4V_STATE_ACCEPTED)) {
        KeAcquireInStackQueuedSpinLock(&ctx->ringObject->lock, &lqh);
        V4vDumpRing(ctx->ringObject->ring);
        KeReleaseInStackQueuedSpinLock(&lqh);
        status = STATUS_SUCCESS;
    }
    
    return status;
}

static NTSTATUS
V4vCtrlGetInfo(XENV4V_CONTEXT *ctx, V4V_GETINFO_VALUES *gi)
{
    NTSTATUS           status = STATUS_INVALID_DEVICE_REQUEST;
    LONG               val;
    KLOCK_QUEUE_HANDLE lqh;

    val = InterlockedExchangeAdd(&ctx->state, 0);

    if (gi->type == V4vGetPeerInfo) {
        if (val & (XENV4V_STATE_CONNECTING|XENV4V_STATE_CONNECTED|XENV4V_STATE_ACCEPTED)) {
            RtlMoveMemory(&gi->ringInfo.addr, &ctx->sdst, sizeof(v4v_addr_t));
            gi->ringInfo.partner = V4V_DOMID_NONE;
            status = STATUS_SUCCESS;
        }
    }
    else if (gi->type == V4vGetLocalInfo) {
        if (val & (XENV4V_STATE_BOUND|XENV4V_STATE_LISTENING|XENV4V_STATE_WAITING|
                   XENV4V_STATE_CONNECTING|XENV4V_STATE_CONNECTED|
                   XENV4V_STATE_ACCEPTED)) {
            KeAcquireInStackQueuedSpinLock(&ctx->ringObject->lock, &lqh);
            RtlMoveMemory(&gi->ringInfo, &ctx->ringObject->ring->id, sizeof(v4v_ring_id_t));
            KeReleaseInStackQueuedSpinLock(&lqh);
            status = STATUS_SUCCESS;
        }
    }
    
    return status;
}

static NTSTATUS
V4vCtrlDisconnect(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx)
{
    LONG val;

    val = InterlockedExchangeAdd(&ctx->state, 0);
    if ((val & (XENV4V_STATE_CONNECTED|XENV4V_STATE_ACCEPTED)) == 0) {
        // Drop the warning - it is fine if a client calls disconnect event though it did not connect.
        TraceVerbose(("state not CONNECTED or ACCEPTED, cannot complete disconnect request\n"));
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    // Send a RST write. This may go out immediately or get queued.
    V4vSendReset(pde, ctx, (uint32_t)ctx->connId, &ctx->sdst, FALSE);

    // Flush any queued inbound data
    if (val == XENV4V_STATE_ACCEPTED) {
        V4vFlushAccepterQueueData(ctx);
    }
    
    // Disconnect our side. Note that if the client is doing an orderly shutdown
    // then it does not need to be signaled and presumably has canceled all its
    // IO to. Worst case any IO will be cleaned up in the final release of the 
    // context so just transition the state.
    InterlockedExchange(&ctx->state, XENV4V_STATE_DISCONNECTED);

    return STATUS_SUCCESS;
}

static NTSTATUS
V4vCtrlConnectWait(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx, V4V_WAIT_VALUES *wvs, PIRP irp)
{
    NTSTATUS      status = STATUS_SUCCESS;
    LONG          val;
    XENV4V_INSERT ins = {FALSE};

    // This is the connect wait functionality that allows a single end to end
    // stream connection. This part serves as the "listening" end.
    val = InterlockedExchangeAdd(&ctx->state, 0);
    if (val != XENV4V_STATE_BOUND) {
        TraceWarning(("state not BOUND, cannot complete connect wait request\n"));
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    // Any IRPs that are queued are given a sanity initialization
    V4vInitializeIrp(irp);

    // Update the stream header in the IRPs buffer. Just clear if now, later it will
    // be used for the ACK.
    wvs->sh.flags = 0;
    wvs->sh.conid = 0;

    // Now it becomes a connector type for ever more
    InterlockedExchange(&ctx->type, XENV4V_TYPE_CONNECTOR);

    // After this transition, we will wait to get a SYN and send back the ACK
    InterlockedExchange(&ctx->state, XENV4V_STATE_WAITING);

    // Flag it
    irp->Tail.Overlay.DriverContext[0] = 
        (PVOID)(ULONG_PTR)(XENV4V_PEEK_STREAM|XENV4V_PEEK_READ|XENV4V_PEEK_SYN|XENV4V_PEEK_IOCTL);

    // Always queue it to the back and marks it pending
    status = IoCsqInsertIrpEx(&pde->csqObject, irp, NULL, &ins);
    if (NT_SUCCESS(status)) {        
        status = STATUS_PENDING;
        // Drive any read IO
        V4vProcessContextReads(pde, ctx);
    }
    else {
        // Fail it in IOCTL routine and return go to disconnected state
        InterlockedExchange(&ctx->state, XENV4V_STATE_DISCONNECTED);
    }

    return status;
}

static NTSTATUS
V4vCtrlConnect(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx, V4V_CONNECT_VALUES *cvs, PIRP irp)
{
    NTSTATUS      status = STATUS_SUCCESS;
    LONG          val;
    XENV4V_INSERT ins = {FALSE};

    val = InterlockedExchangeAdd(&ctx->state, 0);
    if (val != XENV4V_STATE_BOUND) {
        TraceWarning(("state not BOUND, cannot complete connect request\n"));
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    // Any IRPs that are queued are given a sanity initialization
    V4vInitializeIrp(irp);

    // These stream related values are only set once during a single phase of transitioning
    // to a stream type.
    ctx->sdst = cvs->ringAddr;
    ctx->connId = (ULONG64)(RtlRandomEx(&pde->seed) & 0xffffffff);

    // Update the stream header in the IRPs buffer. The cvs pointer points to the IRPs actual
    // in/out buffer the IOCTL is defined to have output.
    cvs->sh.flags = V4V_SHF_SYN;
    cvs->sh.conid = (ULONG32)ctx->connId;

    // Now it becomes a connector type for ever more
    InterlockedExchange(&ctx->type, XENV4V_TYPE_CONNECTOR);

    // After this transition, we will still send a SYN datagram and get the ACK
    InterlockedExchange(&ctx->state, XENV4V_STATE_CONNECTING);

    // Start the connecting timer each time a context goes into this state.
    V4vStartConnectionTimer(pde);

    // Flag it
    irp->Tail.Overlay.DriverContext[0] = 
        (PVOID)(ULONG_PTR)(XENV4V_PEEK_STREAM|XENV4V_PEEK_WRITE|XENV4V_PEEK_SYN|XENV4V_PEEK_IOCTL);

    // Always queue it to the back and marks it pending
    status = IoCsqInsertIrpEx(&pde->csqObject, irp, NULL, &ins);
    if (NT_SUCCESS(status)) {        
        status = STATUS_PENDING;
        // Drive any write IO
        V4vProcessContextWrites(pde, ctx);
    }
    else {
        // Fail it in IOCTL routine and return go to disconnected state
        V4vStopConnectionTimer(pde, FALSE);
        InterlockedExchange(&ctx->state, XENV4V_STATE_DISCONNECTED);
    }

    return status;
}

static NTSTATUS
V4vCtrlAccept(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx, ULONG ioc, VOID *iob, ULONG iol, PIRP irp)
{
    NTSTATUS            status = STATUS_SUCCESS;
    LONG                val;
    V4V_INIT_VALUES     init;
    FILE_OBJECT        *pfo = NULL;
    XENV4V_CONTEXT     *actx;
    XENV4V_INSERT       ins = {FALSE};
    HANDLE              fh;
    HANDLE              rxe;
    V4V_ACCEPT_PRIVATE *priv;

    val = InterlockedExchangeAdd(&ctx->state, 0);
    if (val != XENV4V_STATE_LISTENING) {
        TraceWarning(("state not LISTENING, cannot complete accept request\n"));
        return STATUS_INVALID_DEVICE_REQUEST;
    }    

    // Handle 32b/64b thunk sructures here and test input
#if defined(_WIN64)
    if (ioc == V4V_IOCTL_ACCEPT_32)
    {
        V4V_ACCEPT_VALUES_32 *avs32 = (V4V_ACCEPT_VALUES_32*)iob;

        if (iol != sizeof(V4V_ACCEPT_VALUES_32)) {
            TraceError(("invalid accept values.\n"));
            return STATUS_INVALID_PARAMETER;
        }        
        fh  = avs32->fileHandle;
        rxe = avs32->rxEvent;
        priv = (V4V_ACCEPT_PRIVATE*)((UCHAR*)avs32 + FIELD_OFFSET(V4V_ACCEPT_VALUES_32, priv));
    }
    else
#endif
    {
        V4V_ACCEPT_VALUES *avs = (V4V_ACCEPT_VALUES*)iob;

        UNREFERENCED_PARAMETER(ioc);

        if (iol != sizeof(V4V_ACCEPT_VALUES)) {
            TraceError(("invalid accept values.\n"));
            return STATUS_INVALID_PARAMETER;
        }        
        fh  = avs->fileHandle;
        rxe = avs->rxEvent;
        priv = (V4V_ACCEPT_PRIVATE*)((UCHAR*)avs + FIELD_OFFSET(V4V_ACCEPT_VALUES, priv));
    }

    // Any IRPs that are queued are given a sanity initialization
    V4vInitializeIrp(irp);

    // Get a reference to the file object for the handle
    status = ObReferenceObjectByHandle(fh,
                                       0,
                                       *IoFileObjectType,
                                       irp->RequestorMode,
                                       &pfo,
                                       NULL);
    if (!NT_SUCCESS(status)) {
        TraceError(("failed to get a reference to the accepter file object - error: 0x%x\n", status));
        return status;
    }
    actx = (XENV4V_CONTEXT*)pfo->FsContext;
    ObDereferenceObject(pfo);

    // Store the referenced acceptor context in the IOCTL buffer so we can access it at > PASSIVE later.
    V4vAddRefContext(pde, actx);
#if defined(_WIN64)
    priv->q.a = (ULONG64)actx;
#else
    priv->d.a = (ULONG32)actx;
#endif

    // Do the base initialization of the file object context
    init.rxEvent = rxe;
    init.ringLength = ctx->ringLength; // shared ring length
    status = V4vCtrlInitializeFile(actx, &init, irp);
    if (!NT_SUCCESS(status)) {
        V4vReleaseContext(pde, actx);
        TraceError(("failed to initialize the accepter file object - error: 0x%x\n", status));
        return status;
    }

    // Now initialize the accepter specific state and associate the accepter
    // with the listener context and ring.
    KeInitializeSpinLock(&actx->u.accepter.dataLock);
    actx->u.accepter.dataList = NULL;
    actx->u.accepter.dataTail = NULL;
    V4vAddRefContext(pde, ctx);
    V4vAddRefRing(pde, ctx->ringObject);
    actx->u.accepter.listenerContext = ctx;
    actx->ringObject = ctx->ringObject;

    // Now it becomes an accepter type for ever more
    InterlockedExchange(&actx->type, XENV4V_TYPE_ACCEPTER);

    // After this transition, we will wait for a SYN (may be one in the queue already).
    InterlockedExchange(&actx->state, XENV4V_STATE_ACCEPTING);

    // Flag it
    irp->Tail.Overlay.DriverContext[0] = 
        (PVOID)(ULONG_PTR)(XENV4V_PEEK_STREAM|XENV4V_PEEK_ACCEPT|XENV4V_PEEK_IOCTL);

    // Always queue it to the back and marks it pending. If it fails to be queued then
    // the user mode call will close the new handle.
    status = IoCsqInsertIrpEx(&pde->csqObject, irp, NULL, &ins);
    if (NT_SUCCESS(status)) {
        status = STATUS_PENDING;
        // Drive any accepts
        V4vDoAccepts(pde, ctx);
    }

    return status;
}

static NTSTATUS
V4vCtrlListen(XENV4V_CONTEXT *ctx, V4V_LISTEN_VALUES *lvs)
{
    LONG    val;
    ULONG32 size;

    val = InterlockedExchangeAdd(&ctx->state, 0);
    if (val != XENV4V_STATE_BOUND) {
        TraceWarning(("state not BOUND, cannot complete connect listen\n"));
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (lvs->backlog > V4V_SOMAXCONN) {
        TraceWarning(("backlog cannot be larger than V4V_SOMAXCONN: %d\n", V4V_SOMAXCONN));
        return STATUS_INVALID_PARAMETER;
    }

    // Initialize the listener specific pieces of the context
    KeInitializeSpinLock(&ctx->u.listener.synLock);
    ctx->u.listener.synHead = NULL;
    ctx->u.listener.synTail = NULL;
    ctx->u.listener.synCount = 0;
    if (lvs->backlog == 0) {
        ctx->u.listener.backlog = V4V_SOMAXCONN;
    }
    else {
        ctx->u.listener.backlog = (LONG)lvs->backlog;
    }
    size = ctx->u.listener.backlog*sizeof(XENV4V_SYN);

    ctx->u.listener.synList = (XENV4V_SYN*)ExAllocatePoolWithTag(NonPagedPool, size, XENV4V_TAG);
    if (ctx->u.listener.synList == NULL) {
        TraceWarning(("listen failed, out of memory\n"));
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(ctx->u.listener.synList, size);

    // Now it becomes a listener type for ever more
    InterlockedExchange(&ctx->type, XENV4V_TYPE_LISTENER);

    // After this transition the ring is ready to receive SYNs for new connections
    InterlockedExchange(&ctx->state, XENV4V_STATE_LISTENING);
    
    return STATUS_SUCCESS;
}

static NTSTATUS
V4vCtrlBind(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx, V4V_BIND_VALUES *bvs)
{
    NTSTATUS            status = STATUS_SUCCESS;
    LONG                val;
    KLOCK_QUEUE_HANDLE  lqh;
    XENV4V_RING        *robj;
    uint32_t            port;

    // Use a simple guard variable to enforce the state transition order
    val = InterlockedExchangeAdd(&ctx->state, 0);
    if (val != XENV4V_STATE_IDLE) {
        TraceWarning(("state not IDLE, cannot complete bind request\n"));
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    ASSERT(ctx->ringObject == NULL);

    do {
        if ((bvs->ringId.addr.domain != V4V_DOMID_NONE)&&
            (bvs->ringId.addr.domain != DOMID_INVALID_COMPAT)) {
            TraceWarning(("failure - ring ID domain must be V4V_DOMID_NONE - value: 0x%x\n",
                         bvs->ringId.addr.domain));
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        robj = V4vAllocateRing(ctx->ringLength);
        if (robj == NULL) {    
            TraceError(("failed to allocate the ring\n"));
            status = STATUS_NO_MEMORY;
            break;
        }
        robj->ring->id = bvs->ringId;

        // Have to grab this outside of lock at IRQL PASSIVE    
        port = V4vRandomPort(pde);

        // Lock this section since we access the list
        KeAcquireInStackQueuedSpinLock(&pde->ringLock, &lqh);

        if (robj->ring->id.addr.port == V4V_PORT_NONE) {
            robj->ring->id.addr.port = V4vSparePortNumber(pde, port);
        }
        else if (V4vRingIdInUse(pde, &robj->ring->id)) {
            KeReleaseInStackQueuedSpinLock(&lqh);
            TraceWarning(("ring ID already in use, cannot bind\n"));
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
        
        // Now register the ring.
        status = V4vRegisterRing(robj);
        if (!NT_SUCCESS(status)) {
            KeReleaseInStackQueuedSpinLock(&lqh);
            TraceError(("failed in register ring hypercall - error: 0x%x\n", status));
            break;
        }
        robj->registered = TRUE;

        // Link it to the main list and set our pointer to it
        V4vLinkToRingList(pde, robj);
        ctx->ringObject = robj;

        KeReleaseInStackQueuedSpinLock(&lqh);

        InterlockedExchange(&ctx->type, XENV4V_TYPE_DATAGRAM);
        InterlockedExchange(&ctx->state, XENV4V_STATE_BOUND);        
    } while (FALSE);

    if (!NT_SUCCESS(status)) {
        // If it failed, undo everything - this will remove it from the list
        if (ctx->ringObject != NULL) {
            V4vReleaseRing(pde, ctx->ringObject);
        }
    }

    return status;
}

static NTSTATUS
V4vCtrlInitializeFile(XENV4V_CONTEXT *ctx, V4V_INIT_VALUES *invs, PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (ctx == NULL) {
        TraceError(("no file context!\n"));
        return STATUS_INVALID_HANDLE;
    }

    if (invs->rxEvent == NULL) {
        TraceError(("no event handle!\n"));
        return STATUS_INVALID_HANDLE;
    }

    do {       
        // Reference the event objects
        status = ObReferenceObjectByHandle(invs->rxEvent,
                                           EVENT_MODIFY_STATE,
                                           *ExEventObjectType,
                                           irp->RequestorMode,
                                           (void **)&ctx->kevReceive,
                                           NULL);

        if (!NT_SUCCESS(status)) {
            TraceError(("failed to get a reference to the receive event - error: 0x%x\n", status));
            break;
        }        
        
        ctx->ringLength = invs->ringLength;

        // Straighten out the ring
        if (ctx->ringLength > PAGE_SIZE) {         
            ctx->ringLength = (ctx->ringLength + XENV4V_RING_MULT - 1) & ~(XENV4V_RING_MULT - 1);
        }
        else {
            ctx->ringLength = PAGE_SIZE; // minimum to guarantee page alignment
        }

        InterlockedExchange(&ctx->state, XENV4V_STATE_IDLE);
    } while (FALSE);

    if (!NT_SUCCESS(status)) {
        // If it failed, undo everything
        if (ctx->kevReceive != NULL) {
            ObDereferenceObject(ctx->kevReceive);
            ctx->kevReceive = NULL;
        }        
    }

    return status;
}

NTSTATUS NTAPI
V4vDispatchDeviceControl(PDEVICE_OBJECT fdo, PIRP irp)
{
    NTSTATUS            status = STATUS_SUCCESS;
    PIO_STACK_LOCATION  isl;
    ULONG               ioControlCode;
    PVOID               ioBuffer;
    ULONG               ioInLen;
    ULONG               ioOutLen;
    XENV4V_EXTENSION   *pde = V4vGetDeviceExtension(fdo);
    XENV4V_CONTEXT     *ctx;
    LONG                ds;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    isl           = IoGetCurrentIrpStackLocation(irp);
    ioControlCode = isl->Parameters.DeviceIoControl.IoControlCode;
    ioBuffer      = irp->AssociatedIrp.SystemBuffer;
    ioInLen       = isl->Parameters.DeviceIoControl.InputBufferLength;
    ioOutLen      = isl->Parameters.DeviceIoControl.OutputBufferLength;
    ctx           = (XENV4V_CONTEXT*)isl->FileObject->FsContext;

    TraceVerbose((" =IOCTL= 0x%x\n", ioControlCode));

    irp->IoStatus.Information = 0;

    ds = InterlockedExchangeAdd(&pde->state, 0);
    if (ds & XENV4V_DEV_STOPPED) {
        TraceVerbose(("aborting IOCTL IRP, device is in the stopped state.\n"));
        irp->IoStatus.Status = STATUS_INVALID_DEVICE_STATE;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
        return STATUS_INVALID_DEVICE_STATE;
    }

    switch (ioControlCode) {
#if defined(_WIN64)
    case V4V_IOCTL_INITIALIZE_32:
    {
        V4V_INIT_VALUES_32 *invs32 = (V4V_INIT_VALUES_32*)ioBuffer;
        if (ioInLen == sizeof(V4V_INIT_VALUES_32)) {
            V4V_INIT_VALUES init;
            init.rxEvent = invs32->rxEvent;
            init.ringLength = invs32->ringLength;
            status = V4vCtrlInitializeFile(ctx, &init, irp);
        }
        else {
            TraceError(("invalid initialization values.\n"));
            status = STATUS_INVALID_PARAMETER;
        }

        break;
    }
#endif
    case V4V_IOCTL_INITIALIZE:
    {
        V4V_INIT_VALUES *invs = (V4V_INIT_VALUES*)ioBuffer;
        if (ioInLen == sizeof(V4V_INIT_VALUES)) {
            status = V4vCtrlInitializeFile(ctx, invs, irp);
        }
        else {
            TraceError(("invalid initialization values.\n"));
            status = STATUS_INVALID_PARAMETER;
        }

        break;
    }
    case V4V_IOCTL_BIND:
    {
        V4V_BIND_VALUES *bvs = (V4V_BIND_VALUES*)ioBuffer;
        if (ioInLen == sizeof(V4V_BIND_VALUES)) {
            status = V4vCtrlBind(pde, ctx, bvs);
        }
        else {
            TraceError(("invalid bind values.\n"));
            status = STATUS_INVALID_PARAMETER;
        }

        break;
    }
    case V4V_IOCTL_LISTEN:
    {
        V4V_LISTEN_VALUES *lvs = (V4V_LISTEN_VALUES*)ioBuffer;
        if (ioInLen == sizeof(V4V_LISTEN_VALUES)) {
            status = V4vCtrlListen(ctx, lvs);
        }
        else {
            TraceError(("invalid listen values.\n"));
            status = STATUS_INVALID_PARAMETER;
        }

        break;
    }
#if defined(_WIN64)
    case V4V_IOCTL_ACCEPT_32: // Fall through
#endif
    case V4V_IOCTL_ACCEPT:
    {
        status = V4vCtrlAccept(pde, ctx, ioControlCode, ioBuffer, ioInLen, irp);
        break;
    }
    case V4V_IOCTL_CONNECT:
    {
        V4V_CONNECT_VALUES *cvs = (V4V_CONNECT_VALUES*)ioBuffer;
        if (ioInLen == sizeof(V4V_CONNECT_VALUES)) {
            status = V4vCtrlConnect(pde, ctx, cvs, irp);
        }
        else {
            TraceError(("invalid connect values.\n"));
            status = STATUS_INVALID_PARAMETER;
        }
      
        break;
    }
    case V4V_IOCTL_WAIT:
    {
        V4V_WAIT_VALUES *wvs = (V4V_WAIT_VALUES*)ioBuffer;
        if (ioInLen == sizeof(V4V_WAIT_VALUES)) {
            status = V4vCtrlConnectWait(pde, ctx, wvs, irp);
        }
        else {
            TraceError(("invalid connect wait values.\n"));
            status = STATUS_INVALID_PARAMETER;
        }

        break;
    }
    case V4V_IOCTL_DISCONNECT:
    {
        status = V4vCtrlDisconnect(pde, ctx);      
        break;
    }
    case V4V_IOCTL_GETINFO:
    {
        V4V_GETINFO_VALUES *gi = (V4V_GETINFO_VALUES*)ioBuffer;
        if (ioInLen == sizeof(V4V_GETINFO_VALUES)) {
            status = V4vCtrlGetInfo(ctx, gi);
        }
        else {
            TraceError(("invalid get info values.\n"));
	        status = STATUS_INVALID_PARAMETER;
        }

        if (NT_SUCCESS(status)) {
            irp->IoStatus.Information = sizeof(V4V_GETINFO_VALUES);
        }

        break;
    }
    case V4V_IOCTL_DUMPRING:
    {
        status = V4vCtrlDumpRing(ctx);
        break;
    }
    default:
        status = STATUS_INVALID_PARAMETER;		
    }

    if (status != STATUS_PENDING) {
        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return status;
}
