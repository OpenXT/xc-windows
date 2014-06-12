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

#include <ntddk.h>
#include <ntstrsafe.h>
#include "v2vk.h"
#include "v2vdrv.h"

/* Connector and Listener:
 * The operations of the roles for the samples are analogous to the 
 * syncrhonous case with the consumer driving the exchanges. See these
 * comments for more information.
 *
 * Asynchonous Operation:
 * Both the async and sync samples show the same basic operations or
 * perhaps more precisely they show certain protocols of data exchange
 * that dictate those operations. Close inspection will show the analogous
 * portions of sync vs. async.
 *
 * Locking:
 * The first thing to note is that, as with the synchronous cases, there is 
 * no locking between the local and remote side. E.g. side A will manage its 
 * local state (updating it) and publish the updates to its shared local state.
 * The remote side B will treat this shared state in turn as the read only 
 * remote state for side A. And this is done in mirror fashion from B to A.
 * In addition, the state associated with each of the 2 rings is managed 
 * separately with the roles for producer/consumer reversed for A and B.
 *
 * For the sample, this manifests itself as two separate locks for send and 
 * recieve. Each lock prevents concurrent access to the local ring state for
 * either send or receive operations. So within the locked critical sections
 * for send or receive, the operations are analogous to the synchronous
 * version.
 *
 * Note that the transmit lock is used to protect the external sample 
 * connector/listener state. This is due to the fact that in the examples,
 * the sending of data is driving the external state machine.
 */

/************************* CONNECTOR *************************/

static void
V2vTransmitWorkItem(PDEVICE_OBJECT pdo, void *ctx)
{
    NTSTATUS status;
    
    UNREFERENCED_PARAMETER(pdo);
    status = ((V2VK_BASE_CONTEXT*)ctx)->s.async.txFunction(ctx);
    if (!NT_SUCCESS(status)) {
        ((V2VK_BASE_CONTEXT*)ctx)->s.async.termStatus = V2VK_TERM_TX_ERROR;
        KeSetEvent(&((V2VK_BASE_CONTEXT*)ctx)->s.async.termEvent, IO_NO_INCREMENT, FALSE);
    }
}

static NTSTATUS
V2vkConnectorProcessInternalAsyncRx(V2VK_CONNECTOR_CONTEXT *vcc)
{
    NTSTATUS status;
    KIRQL irql;
    volatile UCHAR *msg;
    size_t size;
    unsigned type;
    unsigned flags;
    ULONG rxCounter = 0;
    V2V_FRAME_HEADER *header;
    V2V_RESP_INTERNAL lvri;
    GUID *pguid;
    UCHAR sum;
    BOOLEAN last = FALSE;

    do {
        /* Critical section where we access the rings - have to lock this area */
        KeAcquireSpinLock(&vcc->s.async.rxLock, &irql);

        status = v2v_nc2_get_message(vcc->channel, &msg, &size, &type, &flags);
        if (status != STATUS_SUCCESS) {
            KeReleaseSpinLock(&vcc->s.async.rxLock, irql);
            break;
        }
        
        header = (V2V_FRAME_HEADER*)msg;
        if (!V2vkMessageHeaderCheck("connector", "internal", header, size, sizeof(V2V_RESP_INTERNAL))) {
            v2v_nc2_finish_message(vcc->channel);
            KeReleaseSpinLock(&vcc->s.async.rxLock, irql);
            status = STATUS_DATA_ERROR;
            break;
        }

        /* Make a local copy of the message header and run a checksum over the message */
        RtlCopyMemory(&lvri, (void*)msg, sizeof(V2V_RESP_INTERNAL));
        sum = V2vChecksum((const UCHAR*)msg, header->length);

        v2v_nc2_finish_message(vcc->channel);
        KeReleaseSpinLock(&vcc->s.async.rxLock, irql);

        /* Critical section to test counter state */
        KeAcquireSpinLock(&vcc->s.async.txLock, &irql);
        
        /* Update counter tracking state, we just sent one */
        rxCounter = ++vcc->rxCounter;

        /* See if we are done sending and receiving and set the completion event */
        if ((vcc->txCounter == vcc->u.xferInternal.count)&&(vcc->rxCounter == vcc->txCounter)) {
            vcc->s.async.termStatus = V2VK_TERM_COMPLETE;
            KeSetEvent(&vcc->s.async.termEvent, IO_NO_INCREMENT, FALSE);
            KeReleaseSpinLock(&vcc->s.async.txLock, irql);
            last = TRUE;
        }
        KeReleaseSpinLock(&vcc->s.async.txLock, irql);

        /* Out of critical section and the buffer in the ring has been released,
           back; can't touch the msg any longer - do some testing and tracing */
        DbgPrint("------ message status=%d\n", lvri.status);
        pguid = &lvri.guid;
        DbgPrint("------ GUID={%8.8x-%4.4x-%4.4x-%2.2x%2.2x-%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x}\n",
                 pguid->Data1, pguid->Data2, pguid->Data3, pguid->Data4[0], pguid->Data4[1], pguid->Data4[2],
                 pguid->Data4[3], pguid->Data4[4], pguid->Data4[5], pguid->Data4[6], pguid->Data4[7]);
        if (sum != 0)
            DbgPrint("%s connector(%p) bad checksumm on response #%d!!!\n", V2VDRV_LOGTAG, vcc, rxCounter);
        if (last) {
            status = STATUS_SUCCESS;
            break;
        }

    } while (TRUE);

    /* If we ended the receive handler with this code, there are no more message right
       now so we wait for an rx interrupt. If the status is success then it was the last
       message. */
    if (status == STATUS_NO_MORE_ENTRIES) {
        /* No more messages */
        DbgPrint("%s connector(%p) no more messages, returning\n", V2VDRV_LOGTAG, vcc);
        return STATUS_SUCCESS;
    }
    else if (status == STATUS_SUCCESS) {
        /* No more messages */
        DbgPrint("%s connector(%p) last message sent, returning\n", V2VDRV_LOGTAG, vcc);
        return STATUS_SUCCESS;
    }

    DbgPrint("%s connector(%p) receive internal receive data failure; abort processing - error: 0x%x\n",
             V2VDRV_LOGTAG, vcc, status);
    return status; /* failure */
}

static NTSTATUS
V2vkConnectorProcessInternalAsyncTx(V2VK_CONNECTOR_CONTEXT *vcc)
{
    NTSTATUS status;
    KIRQL irql;
    unsigned available;
    ULONG txCounter = 0;
    volatile UCHAR *msg;
    V2V_FRAME_HEADER *header;
    V2V_POST_INTERNAL *vpi;
    GUID guid;
    LARGE_INTEGER timeout;

    /* Loop and send as many messages as possible. The internal message connector does not wait for
       responses before posting more messages. */
    do {
        /* Make a GUID for the next message we send if any */
        status = ExUuidCreate(&guid);
        if (!NT_SUCCESS(status)) {
            DbgPrint("%s connector(%p) ExUuidCreate() failed - error: 0x%x; using NULL GUID\n",
                     V2VDRV_LOGTAG, vcc, status);
            memset((void*)(&guid), 0, sizeof(GUID));
        }

        /* Critical section where we access the rings - have to lock this area */
        KeAcquireSpinLock(&vcc->s.async.txLock, &irql);
        
        /* See if we are done sending, if so set a timer and exit */
        if (vcc->txCounter == vcc->u.xferInternal.count) {
            KeReleaseSpinLock(&vcc->s.async.txLock, irql);
            /* Set the expiry for waiting for responses now that all messages have been sent. If
               the timer is already in the queue the old one will be canceled and the new one
               queued. */
            timeout.QuadPart = LargeIntRelDelay(vcc->xferTimeout);
            KeSetTimer(&vcc->s.async.toTimer, timeout, NULL);            
            DbgPrint("%s connector(%p) finished sending message, setting timer and exiting\n", V2VDRV_LOGTAG, vcc);
            status = STATUS_SUCCESS;
            break;
        }

        available = v2v_nc2_producer_bytes_available(vcc->channel);
        status = v2v_nc2_prep_message(vcc->channel, vcc->xferSize, V2V_MESSAGE_TYPE_INTERNAL, 0, &msg);
        if (!NT_SUCCESS(status)) {
            KeReleaseSpinLock(&vcc->s.async.txLock, irql);
            if (status == STATUS_RETRY) {
                /* No room right now, return and try again later. We will get an interrupt
                   when room is available */
                DbgPrint("%s connector(%p) not enough buffer space to send message #%d; retry\n",
                         V2VDRV_LOGTAG, vcc, vcc->txCounter + 1);
                status = STATUS_SUCCESS;
            }
            else
                DbgPrint("%s connector(%p) transmit internal message failure; abort processing - error: 0x%x\n",
                          V2VDRV_LOGTAG, vcc, status);
            break;           
        }

        txCounter = ++vcc->txCounter; /* next message */
        header = (V2V_FRAME_HEADER*)msg;
        header->id = (USHORT)vcc->txCounter;
        header->type = V2V_MESSAGE_TYPE_INTERNAL;
        header->cs = 0;
        header->length = vcc->xferSize;
        vpi = (V2V_POST_INTERNAL*)msg;
        RtlCopyMemory(&vpi->guid, &guid, sizeof(GUID));

        /* Fill it up with some data and send it */
        memset((void*)(msg + sizeof(V2V_POST_INTERNAL)),
               'X',
               (vcc->xferSize - sizeof(V2V_POST_INTERNAL)));
        header->cs = V2vChecksum((const UCHAR*)msg, vcc->xferSize);

        v2v_nc2_send_messages(vcc->channel);
        KeReleaseSpinLock(&vcc->s.async.txLock, irql);

        DbgPrint("%s connector(%p) sent internal message #%d\n", V2VDRV_LOGTAG, vcc, txCounter);

    } while (TRUE);
    
    /* We are either exiting because there is no more space so we will get an interrupt when
       more is available or there was an error which will cause the connector to shutdown */
    return status;
}

static void
V2vReadFileWorkItem(PDEVICE_OBJECT pdo, void *ctx)
{
    V2VK_CONNECTOR_CONTEXT *vcc = (V2VK_CONNECTOR_CONTEXT*)ctx;
    KIRQL irql;
    NTSTATUS status;
    unsigned available;
    ULONG txCounter = 0, seqnum = 0;
    ULONG remainder, send;
    BOOLEAN last = FALSE;
    void *fdata;
    volatile UCHAR *msg;
    V2V_FRAME_HEADER *header;
    V2V_POST_FILE *vpf;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER timeout;

    UNREFERENCED_PARAMETER(pdo);

    /* This part is highly contrived for the sample. All the buffer copies and
       reading a file in this manner would make this a very poor solution. It is simply 
       demonstrative - a file is just a good place to get arbitrary data and show the 
       transfer was successfull. More may be read than can be sent but this will be dealt
       with when the file offset is updated. Also note we are in a work item so it is OK
       to use Zw functions. */
    fdata = ExAllocatePoolWithTag(NonPagedPool, vcc->xferSize, V2VDRV_TAG);
    if (fdata == NULL) {
        DbgPrint("%s connector(%p) cannot allocate file data buffer; out of memory\n", V2VDRV_LOGTAG, vcc);
        vcc->s.async.termStatus = V2VK_TERM_TX_ERROR;
        KeSetEvent(&vcc->s.async.termEvent, IO_NO_INCREMENT, FALSE);
        return;
    }
    
    /* read the file data */
    status = ZwReadFile(vcc->u.xferFile.hf, NULL, NULL, NULL, &iosb, fdata,
                        vcc->xferSize, &vcc->u.xferFile.offset, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("%s connector(%p) failed to read file; aborting - error: 0x%x\n", V2VDRV_LOGTAG, vcc, status);        
        vcc->s.async.termStatus = V2VK_TERM_TX_ERROR;
        KeSetEvent(&vcc->s.async.termEvent, IO_NO_INCREMENT, FALSE);
        ExFreePoolWithTag(fdata, V2VDRV_TAG);
        return;
    }                   

    /* Critical section where we access the rings - have to lock this area */
    KeAcquireSpinLock(&vcc->s.async.txLock, &irql);

    /* The flow is to send one file segment at a time then wait for the ack so when
       the sequence number is the same as the sequence received number, send more. Also
       drop out if done sending. */
    if ((vcc->u.xferFile.seqnum != vcc->u.xferFile.seqrx)||(vcc->u.xferFile.done)) {
        KeReleaseSpinLock(&vcc->s.async.txLock, irql);
        ExFreePoolWithTag(fdata, V2VDRV_TAG);
        return;
    }

    available = v2v_nc2_producer_bytes_available(vcc->channel);    
    remainder = (ULONG)(vcc->u.xferFile.length.QuadPart - vcc->u.xferFile.offset.QuadPart);
    send = MIN(available, vcc->xferSize) - sizeof(V2V_POST_FILE);
    if (send >= remainder) {
        send = remainder;
        last = TRUE;
    }

    status = v2v_nc2_prep_message(vcc->channel, send + sizeof(V2V_POST_FILE), V2V_MESSAGE_TYPE_FILE, 0, &msg);
    if (!NT_SUCCESS(status)) {
        KeReleaseSpinLock(&vcc->s.async.txLock, irql);
        if (status != STATUS_RETRY) {
            DbgPrint("%s connector(%p) transmit file message failure; abort processing - error: 0x%x\n",
                      V2VDRV_LOGTAG, vcc, status);
            vcc->s.async.termStatus = V2VK_TERM_TX_ERROR;
            KeSetEvent(&vcc->s.async.termEvent, IO_NO_INCREMENT, FALSE);
        }
        else {
            /* No room right now, return and try again later. We will get an interrupt
               when room is available */
            DbgPrint("%s connector(%p) not enough buffer space to send message; retry\n", V2VDRV_LOGTAG, vcc);
            status = STATUS_SUCCESS;
        }
        ExFreePoolWithTag(fdata, V2VDRV_TAG);
        return;
    }

    txCounter = ++vcc->txCounter; /* next message */
    header = (V2V_FRAME_HEADER*)msg;
    header->id = (USHORT)vcc->txCounter;
    header->type = V2V_MESSAGE_TYPE_FILE;
    header->cs = 0;
    header->length = send + sizeof(V2V_POST_FILE);
    vpf = (V2V_POST_FILE*)msg;
    vpf->status = (last ? V2V_MESSAGE_STATUS_EOF : V2V_MESSAGE_STATUS_MORE);
    vpf->seqnum = vcc->u.xferFile.seqnum;
    RtlCopyMemory((void*)(msg + sizeof(V2V_POST_FILE)), fdata, send);
    header->cs = V2vChecksum((const UCHAR*)msg, send + sizeof(V2V_POST_FILE));

    v2v_nc2_send_messages(vcc->channel);

    /* Update for next file chunk to send */
    seqnum = vcc->u.xferFile.seqnum;
    vcc->u.xferFile.seqnum++;
    vcc->u.xferFile.offset.QuadPart += send;
    if (last)
        vcc->u.xferFile.done = TRUE;

    KeReleaseSpinLock(&vcc->s.async.txLock, irql);

    /* Set a timer to wait for the next ack. */
    timeout.QuadPart = LargeIntRelDelay(vcc->xferTimeout);
    KeSetTimer(&vcc->s.async.toTimer, timeout, NULL);
    
    DbgPrint("%s connector(%p) sent file data message #%d seqnum=%d done=%d\n",
             V2VDRV_LOGTAG, vcc, txCounter, seqnum, last);
    ExFreePoolWithTag(fdata, V2VDRV_TAG);
}

static NTSTATUS
V2vkConnectorProcessFileAsyncRx(V2VK_CONNECTOR_CONTEXT *vcc)
{
    NTSTATUS status;    
    KIRQL irql;
    volatile UCHAR *msg;
    size_t size;
    unsigned type;
    unsigned flags;
    ULONG rxCounter = 0;
    V2V_FRAME_HEADER *header;
    UCHAR sum;
    V2V_RESP_FILE lvrf;
    BOOLEAN done = FALSE;

    /* Critical section where we access the rings - have to lock this area */
    KeAcquireSpinLock(&vcc->s.async.rxLock, &irql);

    status = v2v_nc2_get_message(vcc->channel, &msg, &size, &type, &flags);
    if (status != STATUS_SUCCESS) {
        KeReleaseSpinLock(&vcc->s.async.rxLock, irql);
        if (status == STATUS_NO_MORE_ENTRIES) {
            /* No more messages */
            DbgPrint("%s connector(%p) no file message during DPC!!!; failure, exiting\n", V2VDRV_LOGTAG, vcc);
            status = STATUS_UNSUCCESSFUL;
        }
        else
            DbgPrint("%s connector(%p) receive internal receive data failure; abort processing - error: 0x%x\n",
                      V2VDRV_LOGTAG, vcc, status);
        return status;
    }

    header = (V2V_FRAME_HEADER*)msg;
    if (!V2vkMessageHeaderCheck("connector", "file", header, size, sizeof(V2V_RESP_FILE))) {
        v2v_nc2_finish_message(vcc->channel);
        KeReleaseSpinLock(&vcc->s.async.rxLock, irql);
        return STATUS_DATA_ERROR;
    }

    /* Copy the response locally and free it */
    rxCounter = ++vcc->rxCounter;
    lvrf = *(V2V_RESP_FILE*)msg;
    v2v_nc2_finish_message(vcc->channel);

    /* Test to make sure there are no more messages, there should not be */
    status = v2v_nc2_get_message(vcc->channel, &msg, &size, &type, &flags);
    if (status != STATUS_NO_MORE_ENTRIES) {
        KeReleaseSpinLock(&vcc->s.async.rxLock, irql);
        DbgPrint("%s connector(%p) more than one message in the ring during rx DPC!!!; failure, exiting\n",
                 V2VDRV_LOGTAG, vcc);
        return STATUS_UNSUCCESSFUL;
    }

    KeReleaseSpinLock(&vcc->s.async.rxLock, irql);

    /* Test the response, any failure then abort. The listener should be acking the most
       recent seqnum. */
    sum = V2vChecksum((const UCHAR*)(&lvrf), sizeof(V2V_RESP_FILE));
    if (sum != 0) {
        DbgPrint("%s connector(%p) bad checksumm file response #%d - seqnum: %d\n",
                  V2VDRV_LOGTAG, vcc, vcc->rxCounter, lvrf.seqnum);
        return STATUS_DATA_ERROR;
    }
    if (lvrf.status != V2V_MESSAGE_STATUS_OK) {
        DbgPrint("%s connector(%p) failure status number in file response #%d - seqnum: %d status: 0x%x\n",
                  V2VDRV_LOGTAG, vcc, rxCounter, lvrf.seqnum, lvrf.status);
        return STATUS_DATA_ERROR;
    }
    
    /* Critical section where we update the state machine and counters */
    KeAcquireSpinLock(&vcc->s.async.txLock, &irql);

    if ((lvrf.seqnum != vcc->u.xferFile.seqnum - 1)||(lvrf.seqnum != vcc->u.xferFile.seqrx)) {
        KeReleaseSpinLock(&vcc->s.async.txLock, irql);
        DbgPrint("%s connector(%p) invalid sequence number in file response #%d - seqnum: %d\n",
                  V2VDRV_LOGTAG, vcc, rxCounter, lvrf.seqnum);
        return STATUS_DATA_ERROR;
    }
    
    /* If all checks pass then move the seqrx counter forward and test the state. We should now
       be ready to send the next file segment. */    
    vcc->u.xferFile.seqrx++;
    ASSERT(vcc->u.xferFile.seqnum == vcc->u.xferFile.seqrx);

    /* If the tx side said we are done, we can set the event and exit */
    if (vcc->u.xferFile.done)
        done = TRUE;

    KeReleaseSpinLock(&vcc->s.async.txLock, irql);

    /* All is clear, turn off the timer and proceed */
    KeCancelTimer(&vcc->s.async.toTimer);
    if (done) {
        vcc->s.async.termStatus = V2VK_TERM_COMPLETE;
        KeSetEvent(&vcc->s.async.termEvent, IO_NO_INCREMENT, FALSE);
    }
    else {
        /* Queue a send for the next segment */
        IoQueueWorkItem(vcc->s.async.pwi,
                        V2vReadFileWorkItem,
                        DelayedWorkQueue,
                        vcc); 
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
V2vkConnectorProcessFileAsyncTx(V2VK_CONNECTOR_CONTEXT *vcc)
{
    /* When we get an interrupt, there is space in the producer ring to send more
       file data. Presumably we are here because we tried to send data and there was
       no room. Start another work item to try again. */
    IoQueueWorkItem(vcc->s.async.pwi,
                    V2vReadFileWorkItem,
                    DelayedWorkQueue,
                    vcc); 
    return STATUS_SUCCESS;
}

NTSTATUS
V2vkConnectorProcessMessagesAsync(V2VK_CONNECTOR_CONTEXT *vcc)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID kobjarr[3];    

    DbgPrint("%s connector(%p) started ASYNC processing loop for transfer type: %d\n", V2VDRV_LOGTAG, vcc, vcc->xfer);

    /* A transfer count of 0 is used to just test connecting and disconnecting
       w/o sending any data */
    if ((vcc->xfer == XferTypeInternal)&&(vcc->u.xferInternal.count == 0)) {
        DbgPrint("%s connector(%p) tranfer count set to 0; disconnecting.\n", V2VDRV_LOGTAG, vcc);
        return STATUS_SUCCESS;
    }

    InterlockedIncrement(&vcc->s.async.running);

    kobjarr[0] = v2v_get_control_event(vcc->channel);
    kobjarr[1] = &vcc->s.async.termEvent;
    kobjarr[2] = &vcc->s.async.toTimer;    
    
    /* Send our first file chunk to the listener to start things off in an async fashion */
    IoQueueWorkItem(vcc->s.async.pwi,
                    (vcc->xfer == XferTypeInternal) ? V2vTransmitWorkItem : V2vReadFileWorkItem,
                    DelayedWorkQueue,
                    vcc);   

    /* Start out processing loop, wait for a response and send more file chunks */
    do {
        status = KeWaitForMultipleObjects(3, kobjarr, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
        if (status == STATUS_WAIT_0) {
            status = V2vStatusCheck((V2VK_BASE_CONTEXT*)vcc, "connector");
            if (!NT_SUCCESS(status)||(status == STATUS_SUCCESS))
                break;
            /* else STATUS_PENDING indicates further operation */
        }
        else if (status == STATUS_WAIT_1) {
            /* The terminate event may indicate an error or normal completion */
            if (vcc->s.async.termStatus == V2VK_TERM_COMPLETE) {
                DbgPrint("%s connector(%p) async handlers signalled a terminate for completion; exiting.\n",
                         V2VDRV_LOGTAG, vcc);
                status = STATUS_SUCCESS;
            }
            else {
                DbgPrint("%s connector(%p) async handlers signalled a terminate with error status=0x%x; exiting.\n",
                         V2VDRV_LOGTAG, vcc, vcc->s.async.termStatus);
                status = STATUS_UNSUCCESSFUL;
            }
            break;
        }
        else if (status == STATUS_WAIT_2) {
            /* Timeout notification timer was set indicating we finished sending messages but did not get all 
               the remaining responses in the alloted time. */
            DbgPrint("%s connector(%p) timeout waiting for responses from listener; exiting.\n", V2VDRV_LOGTAG);
            status = STATUS_UNSUCCESSFUL;
            break;
        }
        else {
            /* sno */
            DbgPrint("%s connector(%p) wait critical failure - unexpected wait value; exiting.\n",
                     V2VDRV_LOGTAG, vcc);
            status = STATUS_UNSUCCESSFUL;
            break;
        }     
    } while (TRUE);

    InterlockedDecrement(&vcc->s.async.running);

    /* Cancel our timer on the way out. It is ok to cancel it even if it is not in the
       queue. This will cover all cases (set or not). */
    KeCancelTimer(&vcc->s.async.toTimer);

    return status;
}

/************************* LISTENER *************************/

static NTSTATUS
V2vkListenerProcessInternalAsyncRx(V2VK_LISTENER_CONTEXT *vlc)
{
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL irql;
    volatile UCHAR *msg;
    size_t size;
    unsigned type;
    unsigned flags;
    ULONG rxCounter = 0;
    V2V_FRAME_HEADER *header;
    V2V_POST_INTERNAL *vpi;
    V2V_LISTENER_RESP_ITEM *vlri;
    GUID *pguid;
    UCHAR sum;

    do {
        /* Create one up front, drop out if we can't */
        vlri = (V2V_LISTENER_RESP_ITEM*)
            ExAllocatePoolWithTag(NonPagedPool, sizeof(V2V_LISTENER_RESP_ITEM), V2VDRV_TAG);
        if (vlri == NULL) {
            DbgPrint("%s listener(%p) cannot allocate response item; out of memory\n", V2VDRV_LOGTAG, vlc);
            status = STATUS_NO_MEMORY;
            break;
        }

        /* Critical section where we access the rings - have to lock this area */
        KeAcquireSpinLock(&vlc->s.async.rxLock, &irql);

        status = v2v_nc2_get_message(vlc->channel, &msg, &size, &type, &flags);
        if (status != STATUS_SUCCESS) {
            KeReleaseSpinLock(&vlc->s.async.rxLock, irql);
            ExFreePoolWithTag(vlri, V2VDRV_TAG);
            break;
        }

        rxCounter = ++vlc->rxCounter;
        header = (V2V_FRAME_HEADER*)msg;
        if (!V2vkMessageHeaderCheck("listener", "internal", header, size, sizeof(V2V_POST_INTERNAL))) {
            v2v_nc2_finish_message(vlc->channel);            
            KeReleaseSpinLock(&vlc->s.async.rxLock, irql);
            status = STATUS_DATA_ERROR;
            ExFreePoolWithTag(vlri, V2VDRV_TAG);
            break;
        }
        
        vpi = (V2V_POST_INTERNAL*)msg;
        pguid = &vpi->guid;

        /* Save the GUID and checksum and exit the critical section */
        vlri->resp.header.id = header->id;
        RtlCopyMemory(&vlri->resp.guid, pguid, sizeof(GUID));
        sum = V2vChecksum((const UCHAR*)msg, header->length);        

        v2v_nc2_finish_message(vlc->channel);
        KeReleaseSpinLock(&vlc->s.async.rxLock, irql);

        /* Out of critical section and the buffer in the ring has been released,
         * back; can't touch the msg any longer - do some testing and tracing */
        pguid = &vlri->resp.guid;
        DbgPrint("------ GUID={%8.8x-%4.4x-%4.4x-%2.2x%2.2x-%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x}\n",
                 pguid->Data1, pguid->Data2, pguid->Data3, pguid->Data4[0], pguid->Data4[1], pguid->Data4[2],
                 pguid->Data4[3], pguid->Data4[4], pguid->Data4[5], pguid->Data4[6], pguid->Data4[7]);
        if (sum != 0)
            DbgPrint("%s listener(%p) bad checksumm on message #%d!!!\n", V2VDRV_LOGTAG, vlc, rxCounter);

        vlri->next = NULL;        
        vlri->resp.header.type = V2V_MESSAGE_TYPE_INTERNAL;
        vlri->resp.header.cs = 0;
        vlri->resp.header.length = sizeof(V2V_RESP_INTERNAL); /* header + resp data */
        vlri->resp.status = (sum == 0 ? V2V_MESSAGE_STATUS_OK : V2V_MESSAGE_STATUS_BADCS);
        vlri->resp.header.cs = V2vChecksum((const UCHAR*)vlri, sizeof(V2V_RESP_INTERNAL));

        /* Lock the transmit side to add to queue a response */
        KeAcquireSpinLock(&vlc->s.async.txLock, &irql);
        if (vlc->u.xferInternal.respList) {
            vlc->u.xferInternal.respTail->next = vlri;
            vlc->u.xferInternal.respTail = vlri;
        }
        else {
            vlc->u.xferInternal.respList = vlri;
            vlc->u.xferInternal.respTail = vlri;
        }
        KeReleaseSpinLock(&vlc->s.async.txLock, irql);
    } while (TRUE);

    /* If we ended the receive handler with this code, there are no more message right
       now. At this point we can send out any queued responses we might have queued */
    if (status == STATUS_NO_MORE_ENTRIES) {
        /* No more messages */
        DbgPrint("%s listener(%p) no more messages, calling TX processor\n", V2VDRV_LOGTAG, vlc);
        return vlc->s.async.txFunction(vlc);
    }

    DbgPrint("%s listener(%p) receive internal receive data failure; abort processing - error: 0x%x\n",
             V2VDRV_LOGTAG, vlc, status);
    return status; /* failure */
}

static NTSTATUS
V2vkListenerProcessInternalAsyncTx(V2VK_LISTENER_CONTEXT *vlc)
{
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL irql;
    unsigned available;
    ULONG txCounter = 0;
    volatile UCHAR *msg;
    V2V_LISTENER_RESP_ITEM *vlri;    

    /* Loop and send any queued response */
    do {
        /* Critical section where we access the rings - have to lock this area */
        KeAcquireSpinLock(&vlc->s.async.txLock, &irql);

        if (vlc->u.xferInternal.respList == NULL) {
            KeReleaseSpinLock(&vlc->s.async.txLock, irql);
            DbgPrint("%s listener(%p) no responses to send in internal TX handler; exiting\n", V2VDRV_LOGTAG, vlc);            
            status = STATUS_SUCCESS;
            break;
        }
      
        available = v2v_nc2_producer_bytes_available(vlc->channel);
        status = v2v_nc2_prep_message(vlc->channel, sizeof(V2V_RESP_INTERNAL), V2V_MESSAGE_TYPE_INTERNAL, 0, &msg);
        if (!NT_SUCCESS(status)) {
            KeReleaseSpinLock(&vlc->s.async.txLock, irql);
            if (status == STATUS_RETRY) {
                /* No room right now, return and try again later. We will get an interrupt
                   when room is available */
                DbgPrint("%s listener(%p) not enough buffer space to send response #%d; retry\n",
                         V2VDRV_LOGTAG, vlc, vlc->txCounter + 1);
                status = STATUS_SUCCESS;
            }
            else
                DbgPrint("%s listener(%p) transmit internal response failure; abort processing - error: 0x%x\n",
                          V2VDRV_LOGTAG, vlc, status);
            break;           
        }
        txCounter = ++vlc->txCounter; /* next message */
        vlri = vlc->u.xferInternal.respList;
        vlc->u.xferInternal.respList = vlri->next;
        if (!vlc->u.xferInternal.respList)
            vlc->u.xferInternal.respTail = NULL;
        /* Response already formed, just copy it in */
        RtlCopyMemory((void*)msg, vlri, sizeof(V2V_RESP_INTERNAL));
        ExFreePoolWithTag(vlri, V2VDRV_TAG);

        v2v_nc2_send_messages(vlc->channel);
        KeReleaseSpinLock(&vlc->s.async.txLock, irql);

        DbgPrint("%s listener(%p) sent internal response #%d\n", V2VDRV_LOGTAG, vlc, txCounter);
    } while (TRUE);

    return status;
}

typedef struct _V2VK_WRITE_FILE_BLOCK {
    V2VK_LISTENER_CONTEXT *vlc;
    V2V_POST_FILE pfheader;
    UCHAR sum;
    UCHAR *data;
} V2VK_WRITE_FILE_BLOCK, *PV2VK_WRITE_FILE_BLOCK;

static void V2vWriteFileWorkItem(PDEVICE_OBJECT pdo, void *ctx);

static NTSTATUS
V2vkListenerProcessFileAsyncRx(V2VK_LISTENER_CONTEXT *vlc)
{
    NTSTATUS status;
    KIRQL irql;
    volatile UCHAR *msg;
    size_t size, write;
    unsigned type;
    unsigned flags;
    V2V_FRAME_HEADER *header;
    V2VK_WRITE_FILE_BLOCK *vwfb;

    /* Critical section where we access the rings - have to lock this area */
    KeAcquireSpinLock(&vlc->s.async.rxLock, &irql);

    status = v2v_nc2_get_message(vlc->channel, &msg, &size, &type, &flags);
    if (status != STATUS_SUCCESS) {
        KeReleaseSpinLock(&vlc->s.async.rxLock, irql);
        if (status == STATUS_NO_MORE_ENTRIES) {
            /* No more messages */
            DbgPrint("%s listener(%p) no file message during DPC!!!; failure, exiting\n", V2VDRV_LOGTAG, vlc);
            status = STATUS_UNSUCCESSFUL;
        }
        else
            DbgPrint("%s listener(%p) receive internal receive data failure; abort processing - error: 0x%x\n",
                      V2VDRV_LOGTAG, vlc, status);
        return status;
    }

    header = (V2V_FRAME_HEADER*)msg;
    if (!V2vkMessageHeaderCheck("listener", "file", header, size, sizeof(V2V_RESP_FILE))) {
        v2v_nc2_finish_message(vlc->channel);
        KeReleaseSpinLock(&vlc->s.async.rxLock, irql);
        return STATUS_DATA_ERROR;
    }

    /* Copy the response and free it */    
    write = header->length - sizeof(V2V_POST_FILE);

    vwfb = (V2VK_WRITE_FILE_BLOCK*)
        ExAllocatePoolWithTag(NonPagedPool, write + sizeof(V2VK_WRITE_FILE_BLOCK), V2VDRV_TAG);
    if (vwfb == NULL) {
        v2v_nc2_finish_message(vlc->channel);
        KeReleaseSpinLock(&vlc->s.async.rxLock, irql);
        DbgPrint("%s listener(%p) cannot allocate file data block; out of memory\n", V2VDRV_LOGTAG, vlc);
        return STATUS_NO_MEMORY;
    }
    vwfb->vlc = vlc;
    vwfb->pfheader = *(V2V_POST_FILE*)msg;
    vwfb->data = ((UCHAR*)vwfb) + sizeof(V2VK_WRITE_FILE_BLOCK);

    RtlCopyMemory(vwfb->data, (void*)(msg + sizeof(V2V_POST_FILE)), write);
    vwfb->sum = V2vChecksum((const UCHAR*)msg, header->length);

    v2v_nc2_finish_message(vlc->channel);

    /* Test to make sure there are no more messages, there should not be */
    status = v2v_nc2_get_message(vlc->channel, &msg, &size, &type, &flags);
    if (status != STATUS_NO_MORE_ENTRIES) {
        KeReleaseSpinLock(&vlc->s.async.rxLock, irql);
        DbgPrint("%s connector(%p) more than one message in the ring during rx DPC!!!; failure, exiting\n",
                 V2VDRV_LOGTAG, vlc);
        ExFreePoolWithTag(vwfb, V2VDRV_TAG);
        return STATUS_UNSUCCESSFUL;
    }

    KeReleaseSpinLock(&vlc->s.async.rxLock, irql);

    /* Now that the data is copied, we will queue a work item to write it and respond. Again
       this is not the most efficient way to do things but it is a sample. */
    IoQueueWorkItem(vlc->s.async.pwi,
                    V2vWriteFileWorkItem,
                    DelayedWorkQueue,
                    vwfb); 

    return STATUS_SUCCESS;
}

static NTSTATUS
V2vkListenerProcessFileAsyncTx(V2VK_LISTENER_CONTEXT *vlc)
{
    NTSTATUS status;
    KIRQL irql;
    unsigned available;
    ULONG txCounter;
    volatile UCHAR *msg;
    V2V_FRAME_HEADER *header;
    V2V_RESP_FILE *vrf;

    /* The routine runs either from the context of a work item queue by the
       the receive routine or when an interrupt signals there is room to transmit
       (in the case of v2v_nc2_prep_message() returing STATUS_RETRY. */

    /* Critical section where we access the rings - have to lock this area */
    KeAcquireSpinLock(&vlc->s.async.txLock, &irql);

    if (!vlc->u.xferFile.ack) {
        KeReleaseSpinLock(&vlc->s.async.txLock, irql);
        DbgPrint("%s listener(%p) no file ack to send in TX handler; exiting\n", V2VDRV_LOGTAG, vlc);            
        return STATUS_SUCCESS;
    }

    available = v2v_nc2_producer_bytes_available(vlc->channel);
    status = v2v_nc2_prep_message(vlc->channel, sizeof(V2V_RESP_FILE), V2V_MESSAGE_TYPE_FILE, 0, &msg);
    if (!NT_SUCCESS(status)) {
        KeReleaseSpinLock(&vlc->s.async.txLock, irql);
        if (status == STATUS_RETRY) {
            /* No room right now, return and try again later. We will get an interrupt
               when room is available */
            DbgPrint("%s listener(%p) not enough buffer space to send file response #%d; retry\n",
                     V2VDRV_LOGTAG, vlc, vlc->txCounter + 1);
            status = STATUS_SUCCESS;
        }
        else
            DbgPrint("%s listener(%p) transmit file response failure; abort processing - error: 0x%x\n",
                      V2VDRV_LOGTAG, vlc, status);
        return status;
    }
    
    txCounter = ++vlc->txCounter; /* next message */
    header = (V2V_FRAME_HEADER*)msg;
    header->id = (USHORT)vlc->txCounter;
    header->type = V2V_MESSAGE_TYPE_FILE;
    header->cs = 0;
    header->length = sizeof(V2V_RESP_FILE);
    vrf = (V2V_RESP_FILE*)msg;
    vrf->status = vlc->u.xferFile.status;
    vrf->seqnum = vlc->u.xferFile.seqnum;
    header->cs = V2vChecksum((const UCHAR*)vrf, sizeof(V2V_RESP_FILE));

    v2v_nc2_send_messages(vlc->channel);

    /* Wait for more inbound file segments */
    vlc->u.xferFile.ack = FALSE;

    KeReleaseSpinLock(&vlc->s.async.txLock, irql);

    DbgPrint("%s listener(%p) sent file response #%d\n", V2VDRV_LOGTAG, vlc, txCounter);

    return STATUS_SUCCESS;
}

static void
V2vWriteFileWorkItem(PDEVICE_OBJECT pdo, void *ctx)
{
    NTSTATUS status;
    KIRQL irql;
    V2VK_WRITE_FILE_BLOCK *vwfb = (V2VK_WRITE_FILE_BLOCK*)ctx;
    V2VK_LISTENER_CONTEXT *vlc;
    V2V_FRAME_HEADER *header;
    IO_STATUS_BLOCK iosb;
    ULONG rxCounter, mstat;
    size_t write;
    
    UNREFERENCED_PARAMETER(pdo);
    vlc = vwfb->vlc;
    header = (V2V_FRAME_HEADER*)&(vwfb->pfheader);

    /* Critical section where we change the state machine and counters */
    KeAcquireSpinLock(&vlc->s.async.txLock, &irql);

    rxCounter = ++vlc->rxCounter; /* update the rx counter since we just received a file segment */

    /* Check payload and seqnums, write file, return failure status to connector if anything is wrong */
    if (vwfb->sum != 0) {
        vlc->u.xferFile.status = V2V_MESSAGE_STATUS_BADCS;
        goto status_done;
    }
    if (vlc->u.xferFile.seqnum + 1 != vwfb->pfheader.seqnum) {            
        vlc->u.xferFile.status = V2V_MESSAGE_STATUS_BADSEQ;
        goto status_done;
    }
    write = header->length - sizeof(V2V_POST_FILE);
    if (write == 0) {            
        vlc->u.xferFile.status = V2V_MESSAGE_STATUS_NODATA;
        goto status_done;
    }

    /* Have to leave the critical section to write the file. This is OK since file segment exchanges are
       serialized by the logic of the file connector. */
    KeReleaseSpinLock(&vlc->s.async.txLock, irql);
    status = ZwWriteFile(vlc->u.xferFile.hf, NULL, NULL, NULL, &iosb, (void*)vwfb->data,
                         (ULONG)write, NULL, NULL);
    KeAcquireSpinLock(&vlc->s.async.txLock, &irql);

    if (!NT_SUCCESS(status)) {            
        vlc->u.xferFile.status = V2V_MESSAGE_STATUS_WRITE_ERR;
        goto status_done;
    }
    vlc->u.xferFile.status = V2V_MESSAGE_STATUS_OK;

status_done:

    /* Finish setting up ack, for failure statuses the ack will cause the other end to disconnect
       and the listener will close down also */
    mstat = vlc->u.xferFile.status;
    vlc->u.xferFile.ack = TRUE;
    vlc->u.xferFile.seqnum++;

    KeReleaseSpinLock(&vlc->s.async.txLock, irql);

    DbgPrint("%s listener(%p) final status for received file message #%d - status: %d\n",
                     V2VDRV_LOGTAG, vlc, rxCounter, mstat);

    /* Free the work item and call the transmit routine */   
    ExFreePoolWithTag(vwfb, V2VDRV_TAG);

    status = V2vkListenerProcessFileAsyncTx(vlc);
    if (!NT_SUCCESS(status)) {
        vlc->s.async.termStatus = V2VK_TERM_TX_ERROR;
        KeSetEvent(&vlc->s.async.termEvent, IO_NO_INCREMENT, FALSE);
    }
}

NTSTATUS
V2vkListenerProcessMessagesAsync(V2VK_LISTENER_CONTEXT *vlc)
{
    NTSTATUS status = STATUS_SUCCESS;
    PKEVENT kevarr[2];    

    DbgPrint("%s listener(%p) started ASYNC processing loop for transfer type: %d\n", V2VDRV_LOGTAG, vlc, vlc->xfer);

    InterlockedIncrement(&vlc->s.async.running);

    kevarr[0] = v2v_get_control_event(vlc->channel);
    kevarr[1] = &vlc->s.async.termEvent;    

    /* Start out processing loop, wait for control message */
    do {
        status = KeWaitForMultipleObjects(2, kevarr, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
        if (status == STATUS_WAIT_0) {
            status = V2vStatusCheck((V2VK_BASE_CONTEXT*)vlc, "listener");
            if (!NT_SUCCESS(status)||(status == STATUS_SUCCESS))
                break;
            /* else STATUS_PENDING indicates further operation */
        }
        else if (status == STATUS_WAIT_1) {
            /* The terminate event should only convey errors for the listener */
            DbgPrint("%s listener(%p) async handlers signalled a terminate with error status=0x%x; exiting.\n",
                     V2VDRV_LOGTAG, vlc, vlc->s.async.termStatus);
            status = STATUS_UNSUCCESSFUL;
            break;
        }
        else {
            /* sno */
            DbgPrint("%s listener(%p) wait critical failure - unexpected wait value; exiting.\n",
                     V2VDRV_LOGTAG, vlc);
            status = STATUS_UNSUCCESSFUL;
            break;
        }
    } while (TRUE);

    InterlockedDecrement(&vlc->s.async.running);
    return status;
}

/************************* COMMON *************************/

void
V2vkReceiveDpc(void *ctx)
{
    V2VK_BASE_CONTEXT *vbc = (V2VK_BASE_CONTEXT*)ctx;
    NTSTATUS status;
    LONG running;

    /* Avoid spurious interrupts before initialization is complete */
    running = InterlockedExchangeAdd(&vbc->s.async.running, 0);
    if (running == 0)
        return;

    status = vbc->s.async.rxFunction(ctx);
    if (!NT_SUCCESS(status)) {
        vbc->s.async.termStatus = V2VK_TERM_RX_ERROR;
        KeSetEvent(&vbc->s.async.termEvent, IO_NO_INCREMENT, FALSE);
    }     
}

void
V2vkSendDpc(void *ctx)
{
    V2VK_BASE_CONTEXT *vbc = (V2VK_BASE_CONTEXT*)ctx;
    NTSTATUS status;
    LONG running;

    /* Avoid spurious interrupts before initialization is complete */
    running = InterlockedExchangeAdd(&vbc->s.async.running, 0);
    if (running == 0)
        return;
    
    status = vbc->s.async.txFunction(ctx);
    if (!NT_SUCCESS(status)) {
        vbc->s.async.termStatus = V2VK_TERM_TX_ERROR;
        KeSetEvent(&vbc->s.async.termEvent, IO_NO_INCREMENT, FALSE);
    }
}

void
V2vkControlCb(void *ctx)
{
    V2VK_BASE_CONTEXT *vbc = (V2VK_BASE_CONTEXT*)ctx;
    LONG running;

    /* Avoid xenstore events before initialization is complete */
    running = InterlockedExchangeAdd(&vbc->s.async.running, 0);
    if (running == 0)
        return;

    /* The async V2V functionality provides a way to register an
     * async callback for control message processing as an alternative
     * to waiting on the control event. For purposes of the sample,
     * we will use the control event to keep the processing thread
     * busy waiting for events.
     */    
    V2vStatusCheck(vbc, "ctrlcb");    
}


BOOLEAN V2vkInitializeAsync(V2VK_BASE_CONTEXT *vbc)
{
    /* Setup the processor functions */
    if (vbc->role == RoleTypeConnector) {
        if (vbc->xfer == XferTypeInternal) {
            vbc->s.async.rxFunction = V2vkConnectorProcessInternalAsyncRx;
            vbc->s.async.txFunction = V2vkConnectorProcessInternalAsyncTx;
        }
        else {
            vbc->s.async.rxFunction = V2vkConnectorProcessFileAsyncRx;
            vbc->s.async.txFunction = V2vkConnectorProcessFileAsyncTx;
        }
    }
    else {
        if (vbc->xfer == XferTypeInternal) {
            vbc->s.async.rxFunction = V2vkListenerProcessInternalAsyncRx;
            vbc->s.async.txFunction = V2vkListenerProcessInternalAsyncTx;
        }
        else {
            vbc->s.async.rxFunction = V2vkListenerProcessFileAsyncRx;
            vbc->s.async.txFunction = V2vkListenerProcessFileAsyncTx;
        }
    }
    KeInitializeSpinLock(&vbc->s.async.rxLock);
    KeInitializeSpinLock(&vbc->s.async.txLock);
    KeInitializeEvent(&vbc->s.async.termEvent, SynchronizationEvent, FALSE);
    KeInitializeTimer(&vbc->s.async.toTimer);
    vbc->s.async.running = 0;
    vbc->s.async.termStatus = V2VK_TERM_UNKNOWN;

    vbc->s.async.asv.receive_dpc = V2vkReceiveDpc;
    vbc->s.async.asv.receive_ctx = vbc;
    vbc->s.async.asv.send_dpc = V2vkSendDpc;
    vbc->s.async.asv.send_ctx = vbc;
    vbc->s.async.asv.control_cb = V2vkControlCb;
    vbc->s.async.asv.control_ctx = vbc;
    vbc->asvp = &vbc->s.async.asv;

    vbc->s.async.pwi = IoAllocateWorkItem(vbc->pfo->DeviceObject);
    if (vbc->s.async.pwi == NULL)
        return FALSE;

    return TRUE;
}

void
V2vkCleanupAsync(V2VK_BASE_CONTEXT *vbc)
{
    IoFreeWorkItem(vbc->s.async.pwi);
    vbc->s.async.pwi = NULL;
}
