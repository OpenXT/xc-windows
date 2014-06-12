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
 * The terms connector and listener are arbitrary with the first denoting
 * the agent that connects and sends data and the other accepting the
 * connection and processing received data.
 *
 * In both of the sample connector/listener pairs below, the consumer drives 
 * the operations via initiating data sends to the listener. The listener 
 * responds (acks) the receipt of data. The connector is also responsible
 * for waiting for remaining responses and disconnecting the channel in a
 * normal fashion.
 *
 * For internal data message, the connector is not waiting for responses
 * from the listener before sending another message. It drives the messages
 * until it runs out of room. The listener queues responses to inbound 
 * messages and sends them out when it can. The only check that all traffic
 * was sent and received is done after disconnect.
 *
 * For file messages, the connector and listener synchonize by performing
 * sendig a single file data segment and acking that segment before
 * continuing. The connector drives the operations but it also waits
 * after each send for an ack with status from the listener.
 *
 * Notice:
 * The samples are rather contrived (being samples and all). The are mainly
 * meant to demonstrate various uses of the v2v library. In addition the
 * only touch on the many types of protocols that could be setup over
 * v2v.
 */


/************************* CONNECTOR *************************/

static NTSTATUS
V2vkConnectorProcessInternalSyncRx(V2VK_CONNECTOR_CONTEXT *vcc)
{
    NTSTATUS status;
    volatile UCHAR *msg;
    size_t size;
    unsigned type;
    unsigned flags;
    V2V_FRAME_HEADER *header;
    V2V_RESP_INTERNAL *vri;
    GUID *pguid;
    UCHAR sum;

    if (vcc->flags & V2V_KERNEL_FASTRX)
        v2v_nc2_request_fast_receive(vcc->channel);

    while ((status = v2v_nc2_get_message(vcc->channel, &msg, &size, &type, &flags))
            == STATUS_SUCCESS) {
        vcc->rxCounter++;   
        header = (V2V_FRAME_HEADER*)msg;
        if (!V2vkMessageHeaderCheck("connector", "internal", header, size, sizeof(V2V_RESP_INTERNAL))) {
            DbgPrint("%s connector(%p) message header check failed for message #%d!!!\n", V2VDRV_LOGTAG, vcc, vcc->rxCounter);
            v2v_nc2_finish_message(vcc->channel);
            return STATUS_DATA_ERROR;
        }

        vri = (V2V_RESP_INTERNAL*)msg;
        DbgPrint("------ message status=%d\n", vri->status);
        pguid = &vri->guid;
        DbgPrint("------ GUID={%8.8x-%4.4x-%4.4x-%2.2x%2.2x-%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x}\n",
                 pguid->Data1, pguid->Data2, pguid->Data3, pguid->Data4[0], pguid->Data4[1], pguid->Data4[2],
                 pguid->Data4[3], pguid->Data4[4], pguid->Data4[5], pguid->Data4[6], pguid->Data4[7]);
        sum = V2vChecksum((const UCHAR*)msg, header->length);
        if (sum != 0)
            DbgPrint("%s connector(%p) bad checksumm on response #%d!!!\n", V2VDRV_LOGTAG, vcc, vcc->rxCounter);
        v2v_nc2_finish_message(vcc->channel);
    }
    if (vcc->flags & V2V_KERNEL_FASTRX)
        v2v_nc2_cancel_fast_receive(vcc->channel);    

    if (status == STATUS_NO_MORE_ENTRIES) {
        /* No more messages */
        DbgPrint("%s connector(%p) no more messages, returning\n", V2VDRV_LOGTAG, vcc);
        return STATUS_SUCCESS;
    }

    DbgPrint("%s connector(%p) receive internal data failure; abort processing - error: 0x%x\n",
             V2VDRV_LOGTAG, vcc, status);
    return status; /* failure */
}

static NTSTATUS
V2vkConnectorProcessInternalSyncTx(V2VK_CONNECTOR_CONTEXT *vcc)
{
    NTSTATUS status;
    unsigned available;
    volatile UCHAR *msg;
    size_t msize;
    V2V_FRAME_HEADER *header;
    V2V_POST_INTERNAL *vpi;

    DbgPrint("%s connector(%p) sending internal message #%d\n", V2VDRV_LOGTAG, vcc, vcc->txCounter + 1);
    available = v2v_nc2_producer_bytes_available(vcc->channel);
    DbgPrint("%s connector(%p) channel indicates minimum bytes available: 0x%x\n", V2VDRV_LOGTAG, vcc, available);

    if ((vcc->flags & V2V_KERNEL_FASTRX) && v2v_nc2_remote_requested_fast_wakeup(vcc->channel))
        msize = MIN(vcc->xferSize, vcc->xferMaxFastRx);
    else
        msize = vcc->xferSize;

    status = v2v_nc2_prep_message(vcc->channel, msize, V2V_MESSAGE_TYPE_INTERNAL, 0, &msg);
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_RETRY) {
            /* No room right now, return and try again later */
            DbgPrint("%s connector(%p) not enough buffer space to send message #%d; retry\n",
                     V2VDRV_LOGTAG, vcc, vcc->txCounter + 1);
            return STATUS_RETRY;
        }
        DbgPrint("%s connector(%p) transmit internal data failure; abort processing - error: 0x%x\n",
                 V2VDRV_LOGTAG, vcc, status);
        return status; /* failure */
    }
    vcc->txCounter++; /* next message */
    header = (V2V_FRAME_HEADER*)msg;
    header->id = (USHORT)vcc->txCounter;
    header->type = V2V_MESSAGE_TYPE_INTERNAL;
    header->cs = 0;
    header->length = vcc->xferSize;
    vpi = (V2V_POST_INTERNAL*)msg;
    status = ExUuidCreate(&vpi->guid);
    if (!NT_SUCCESS(status)) {
        DbgPrint("%s connector(%p) ExUuidCreate() failed - error: 0x%x; using NULL GUID\n",
                 V2VDRV_LOGTAG, vcc, status);
        memset((void*)(msg + sizeof(V2V_FRAME_HEADER)), 0, sizeof(GUID));
    }
    /* Fill it up with some data and send it */
    memset((void*)(msg + sizeof(V2V_POST_INTERNAL)),
           'X',
           (vcc->xferSize - sizeof(V2V_POST_INTERNAL)));
    header->cs = V2vChecksum((const UCHAR*)msg, vcc->xferSize);
    v2v_nc2_send_messages(vcc->channel);

    /* Keep the send loop going by setting the event. If there is no more room, the prep message call
       will return ERROR_RETRY and just land us back in the wait. */
    KeSetEvent(v2v_get_send_event(vcc->channel), IO_NO_INCREMENT, FALSE);
    
    return STATUS_SUCCESS;
}

static NTSTATUS
V2vkConnectorProcessFileSyncRx(V2VK_CONNECTOR_CONTEXT *vcc)
{
    NTSTATUS status;
    volatile UCHAR *msg;
    size_t size;
    unsigned type;
    unsigned flags;
    V2V_FRAME_HEADER *header;
    V2V_RESP_FILE *vrf;
    UCHAR sum;
    V2V_RESP_FILE lvrf;

    if (vcc->flags & V2V_KERNEL_FASTRX)
        v2v_nc2_request_fast_receive(vcc->channel);

    while ((status = v2v_nc2_get_message(vcc->channel, &msg, &size, &type, &flags))
            == STATUS_SUCCESS) {
        vcc->rxCounter++;
        header = (V2V_FRAME_HEADER*)msg;
        if (!V2vkMessageHeaderCheck("connector", "file", header, size, sizeof(V2V_RESP_FILE))) {
            DbgPrint("%s connector(%p) message header check failed for message #%d!!!\n", V2VDRV_LOGTAG, vcc, vcc->rxCounter);
            v2v_nc2_finish_message(vcc->channel);
            return STATUS_DATA_ERROR;
        }

        vrf = (V2V_RESP_FILE*)msg;
        DbgPrint("------ message status=%d seqnum=%d\n", vrf->status, vrf->seqnum);

        /* Copy the response locally and free it */
        lvrf = *vrf;
        v2v_nc2_finish_message(vcc->channel);
        
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
                      V2VDRV_LOGTAG, vcc, vcc->rxCounter, lvrf.seqnum, lvrf.status);
            return STATUS_DATA_ERROR;
        }
        if ((lvrf.seqnum != vcc->u.xferFile.seqnum - 1)||(lvrf.seqnum != vcc->u.xferFile.seqrx)) {
            DbgPrint("%s connector(%p) invalid sequence number in file response #%d - seqnum: %d\n",
                      V2VDRV_LOGTAG, vcc, vcc->rxCounter, lvrf.seqnum);
            return STATUS_DATA_ERROR;
        }

        /* Else move the seqrx tracker forward - it should now match the seqnum which indicats we should send */
        vcc->u.xferFile.seqrx++;
        ASSERT(vcc->u.xferFile.seqnum == vcc->u.xferFile.seqrx);
    }
    if (vcc->flags & V2V_KERNEL_FASTRX)
        v2v_nc2_cancel_fast_receive(vcc->channel);

    if (status == STATUS_NO_MORE_ENTRIES) {
        /* No more messages */
        DbgPrint("%s connector(%p) no more messages, returning\n", V2VDRV_LOGTAG, vcc);
        return STATUS_SUCCESS;
    }
 
    DbgPrint("%s connector(%p) receive file data failure; abort processing - error: 0x%x\n",
             V2VDRV_LOGTAG, vcc, status);
    return status; /* failure */
}

static NTSTATUS
V2vkConnectorProcessFileSyncTx(V2VK_CONNECTOR_CONTEXT *vcc)
{
    NTSTATUS status;
    unsigned available;
    ULONG remainder, send, seqnum = 0;
    BOOLEAN last = FALSE;
    size_t msize;
    volatile UCHAR *msg;
    V2V_FRAME_HEADER *header;
    V2V_POST_FILE *vpf;
    IO_STATUS_BLOCK iosb;

    DbgPrint("%s connector(%p) sending file message #%d\n", V2VDRV_LOGTAG, vcc, vcc->txCounter + 1);
    available = v2v_nc2_producer_bytes_available(vcc->channel);
    DbgPrint("%s connector(%p) channel indicates minimum bytes available: 0x%x\n", V2VDRV_LOGTAG, vcc, available);

    if ((vcc->flags & V2V_KERNEL_FASTRX) && v2v_nc2_remote_requested_fast_wakeup(vcc->channel))
        msize = MIN(vcc->xferSize, vcc->xferMaxFastRx);
    else
        msize = vcc->xferSize;
    
    remainder = (ULONG)(vcc->u.xferFile.length.QuadPart - vcc->u.xferFile.offset.QuadPart);
    send = MIN(available, (ULONG)msize) - sizeof(V2V_POST_FILE);
    if (send >= remainder) {
        send = remainder;
        last = TRUE;
    }

    status = v2v_nc2_prep_message(vcc->channel, send + sizeof(V2V_POST_FILE), V2V_MESSAGE_TYPE_FILE, 0, &msg);
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_RETRY) {
            /* No room right now, return and try again later */
            DbgPrint("%s connector(%p) not enough buffer space to send file data, sequence number %d; retry\n",
                     V2VDRV_LOGTAG, vcc, vcc->u.xferFile.seqnum);
            return STATUS_RETRY;
        }
        DbgPrint("%s connector(%p) transmit file data failure; abort processing - error: 0x%x\n",
                 V2VDRV_LOGTAG, vcc, status);
        return status; /* failure */
    }
    vcc->txCounter++; /* next message */
    header = (V2V_FRAME_HEADER*)msg;
    header->id = (USHORT)vcc->txCounter;
    header->type = V2V_MESSAGE_TYPE_FILE;
    header->cs = 0;
    header->length = send + sizeof(V2V_POST_FILE);
    vpf = (V2V_POST_FILE*)msg;
    vpf->status = (last ? V2V_MESSAGE_STATUS_EOF : V2V_MESSAGE_STATUS_MORE);
    vpf->seqnum = vcc->u.xferFile.seqnum;

    /* read the file data */
    status = ZwReadFile(vcc->u.xferFile.hf, NULL, NULL, NULL, &iosb, (void*)(msg + sizeof(V2V_POST_FILE)),
                        send, &vcc->u.xferFile.offset, NULL);
    if (!NT_SUCCESS(status)) {
        /* Since the call to v2v_nc2_send_messages() actually flushes or sends the messages, nothing has been updated
           yet by calling v2v_nc2_prep_message() so nothing needs to be released. */
        DbgPrint("%s connector(%p) failed to read file; aborting - error: 0x%x\n", V2VDRV_LOGTAG, vcc, status);
        return status;
    }
    header->cs = V2vChecksum((const UCHAR*)msg, send + sizeof(V2V_POST_FILE));
    v2v_nc2_send_messages(vcc->channel);    

    /* Update for next file chunk to send */
    seqnum = vcc->u.xferFile.seqnum;
    if (!last) {
        vcc->u.xferFile.offset.QuadPart += send;
        vcc->u.xferFile.seqnum++;
    }
    else
        vcc->u.xferFile.done = TRUE;

    DbgPrint("%s connector(%p) sent file data seqnum=%d done=%d\n", V2VDRV_LOGTAG, vcc, seqnum, vcc->u.xferFile.done);

    return STATUS_SUCCESS;
}

NTSTATUS
V2vkConnectorProcessMessagesSync(V2VK_CONNECTOR_CONTEXT *vcc)
{
    NTSTATUS status = STATUS_SUCCESS;
    PKEVENT kevarr[3];
    ULONG hc = 3;
    PLARGE_INTEGER delay = NULL;
    LARGE_INTEGER timeout, ts;
    ULONG to, td;

    DbgPrint("%s connector(%p) started SYNC processing loop for transfer type: %d fastrx: %d\n",
             V2VDRV_LOGTAG, vcc, vcc->xfer, (vcc->flags & V2V_KERNEL_FASTRX));

    /* A transfer count of 0 is used to just test connecting and disconnecting
       w/o sending any data */
    if ((vcc->xfer == XferTypeInternal)&&(vcc->u.xferInternal.count == 0)) {      
        DbgPrint("%s connector(%p) tranfer count set to 0; disconnecting.\n", V2VDRV_LOGTAG, vcc);
        return STATUS_SUCCESS;
    }    

    ts.QuadPart = 0;
    kevarr[0] = v2v_get_receive_event(vcc->channel);    
    kevarr[1] = v2v_get_control_event(vcc->channel);
    kevarr[2] = v2v_get_send_event(vcc->channel);
    to = vcc->xferTimeout;

    /* Send our first file chunk to the listener to start things off */
    status = vcc->s.sync.txFunction(vcc);
    if (status != STATUS_SUCCESS) {
        ASSERT(status != STATUS_RETRY); /* SNO on first message */
        return (status != STATUS_RETRY ? status : STATUS_UNSUCCESSFUL);
    }

    /* Start out processing loop, wait for a response and send more file chunks */
    do {
        if (vcc->xfer == XferTypeInternal) {
            /* When the tx counter reaches the transfer count value, stop sending and wait for 
               the rest of the responses */
            if (vcc->txCounter == vcc->u.xferInternal.count) {
                /* First see if we are done */
                if (vcc->rxCounter == vcc->txCounter) {
                    DbgPrint("%s connector(%p) received all remaing responses from listener; disconnecting.\n", V2VDRV_LOGTAG, vcc);
                    status = STATUS_SUCCESS;
                    break;
                }

                if (ts.QuadPart != 0) {
                    /* rundown timer */
                    td = V2vTimeDeltaMs(&ts);
                    if (td < to)
                        timeout.QuadPart = LargeIntRelDelay(to - td);
                    else
                        timeout.QuadPart = 0;
                }
                else {
                    hc = 2;
                    timeout.QuadPart = LargeIntRelDelay(to);
                    KeQuerySystemTime(&ts);
                }
                
                delay = &timeout;
            }
        }
        else { /* XferTypeFile */
            if ((vcc->u.xferFile.done)&&
                (vcc->u.xferFile.seqrx == vcc->u.xferFile.seqnum)) {
                DbgPrint("%s connector(%p) file send, recieved all ack responses from listener; disconnecting\n",
                         V2VDRV_LOGTAG, vcc);
                status = STATUS_SUCCESS;
                break;
            }
            if (vcc->u.xferFile.seqrx == vcc->u.xferFile.seqnum) {
                /* Ready to send more */                
                status = vcc->s.sync.txFunction(vcc);
                if (status == STATUS_RETRY) {
                    /* If we cannot send at this point, we go to the wait for room in the
                       tx ring to open up */
                    hc = 3;
                    delay = NULL;
                }
                else if (status != STATUS_SUCCESS)
                    return status;
            }
            else {
                /* Waiting for an ack on the last chunk */             
                if (ts.QuadPart != 0) {
                    /* rundown timer */
                    td = V2vTimeDeltaMs(&ts);
                    if (td < to)
                        timeout.QuadPart = LargeIntRelDelay(to - td);
                    else
                        timeout.QuadPart = 0;
                }
                else {
                    hc = 2;
                    timeout.QuadPart = LargeIntRelDelay(to);
                    KeQuerySystemTime(&ts);
                }

                delay = &timeout;
            }
        }

        status = KeWaitForMultipleObjects(hc, kevarr, WaitAny, Executive, KernelMode, FALSE, delay, NULL);
        if (status == STATUS_WAIT_0) {
            status = vcc->s.sync.rxFunction(vcc);
            if (!NT_SUCCESS(status))
                break;
        }        
        else if (status == STATUS_WAIT_1) {
            status = V2vStatusCheck((V2VK_BASE_CONTEXT*)vcc, "connector");
            if (!NT_SUCCESS(status)||(status == STATUS_SUCCESS))
                break;
            /* else STATUS_PENDING indicates further operation */
        }
        else if (status == STATUS_WAIT_2) {
            status = vcc->s.sync.txFunction(vcc);
            if ((status != STATUS_SUCCESS)&&(status != STATUS_RETRY))
                break;
        }
        else if (status == STATUS_TIMEOUT ) {
            DbgPrint("%s connector(%p) timed out waiting for ack responses from listener; disconnecting\n",
                     V2VDRV_LOGTAG, vcc);
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

    return status;
}

/************************* LISTENER *************************/

static NTSTATUS
V2vkListenerProcessInternalSyncRx(V2VK_LISTENER_CONTEXT *vlc)
{
    NTSTATUS status;
    volatile UCHAR *msg;
    size_t size;
    unsigned type;
    unsigned flags;
    V2V_FRAME_HEADER *header;
    V2V_POST_INTERNAL *vpi;
    V2V_LISTENER_RESP_ITEM *vlri;
    GUID *pguid;
    UCHAR sum;

    if (vlc->flags & V2V_KERNEL_FASTRX)
        v2v_nc2_request_fast_receive(vlc->channel);

    while ((status = v2v_nc2_get_message(vlc->channel, &msg, &size, &type, &flags))
            == STATUS_SUCCESS) {
        vlc->rxCounter++;   
        header = (V2V_FRAME_HEADER*)msg;
        if (!V2vkMessageHeaderCheck("listener", "internal", header, size, sizeof(V2V_POST_INTERNAL))) {
            DbgPrint("%s listener(%p) message header check failed for message #%d!!!\n", V2VDRV_LOGTAG, vlc, vlc->rxCounter);
            v2v_nc2_finish_message(vlc->channel);
            return STATUS_DATA_ERROR;
        }        

        vpi = (V2V_POST_INTERNAL*)msg;
        pguid = &vpi->guid;
        DbgPrint("------ GUID={%8.8x-%4.4x-%4.4x-%2.2x%2.2x-%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x}\n",
                 pguid->Data1, pguid->Data2, pguid->Data3, pguid->Data4[0], pguid->Data4[1], pguid->Data4[2],
                 pguid->Data4[3], pguid->Data4[4], pguid->Data4[5], pguid->Data4[6], pguid->Data4[7]);

        sum = V2vChecksum((const UCHAR*)msg, header->length);
        if (sum != 0)
            DbgPrint("%s listener(%p) bad checksumm on message #%d!!!\n", V2VDRV_LOGTAG, vlc, vlc->rxCounter);

        /* Queue a response */
        vlri = (V2V_LISTENER_RESP_ITEM*)
            ExAllocatePoolWithTag(NonPagedPool, sizeof(V2V_LISTENER_RESP_ITEM), V2VDRV_TAG);
        if (vlri) {
            vlri->next = NULL;
            vlri->resp.header.id = header->id;
            vlri->resp.header.type = V2V_MESSAGE_TYPE_INTERNAL;
            vlri->resp.header.cs = 0;
            vlri->resp.header.length = sizeof(V2V_RESP_INTERNAL); /* header + resp data */
            vlri->resp.status = (sum == 0 ? V2V_MESSAGE_STATUS_OK : V2V_MESSAGE_STATUS_BADCS);
            RtlCopyMemory(&vlri->resp.guid, pguid, sizeof(GUID));
            vlri->resp.header.cs = V2vChecksum((const UCHAR*)vlri, sizeof(V2V_RESP_INTERNAL));
            if (vlc->u.xferInternal.respList) {
                vlc->u.xferInternal.respTail->next = vlri;
                vlc->u.xferInternal.respTail = vlri;
            }
            else {
                vlc->u.xferInternal.respList = vlri;
                vlc->u.xferInternal.respTail = vlri;
            }
        }
        else
            DbgPrint("%s listener(%p) cannot queue response; out of memory\n", V2VDRV_LOGTAG, vlc);

        v2v_nc2_finish_message(vlc->channel);
    }
    if (vlc->flags & V2V_KERNEL_FASTRX)
        v2v_nc2_cancel_fast_receive(vlc->channel);

    if (status == STATUS_NO_MORE_ENTRIES) {
        /* No more messages */
        DbgPrint("%s listener(%p) no more messages, returning success\n", V2VDRV_LOGTAG, vlc);
        return STATUS_SUCCESS;
    }

    DbgPrint("%s listener(%p) receive internal data failure; abort processing - error: 0x%x\n",
             V2VDRV_LOGTAG, vlc, status);
    return status; /* failure */
}

static NTSTATUS
V2vkListenerProcessInternalSyncTx(V2VK_LISTENER_CONTEXT *vlc)
{
    NTSTATUS status;
    unsigned available;
    volatile UCHAR *msg;
    V2V_LISTENER_RESP_ITEM *vlri; 

    DbgPrint("%s listener(%p) sending internal response #%d\n", V2VDRV_LOGTAG, vlc, vlc->txCounter + 1);
    available = v2v_nc2_producer_bytes_available(vlc->channel);
    DbgPrint("%s listener(%p) channel indicates minimum bytes available: 0x%x\n", V2VDRV_LOGTAG, vlc, available);
    ASSERT(vlc->u.xferInternal.respList);

    /* No resizing fixed responses for fastrx */

    status = v2v_nc2_prep_message(vlc->channel, sizeof(V2V_RESP_INTERNAL), V2V_MESSAGE_TYPE_INTERNAL, 0, &msg);
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_RETRY) {
            /* No room right now, return and try again later */
            DbgPrint("%s listener(%p) not enough buffer space to send response #%d; retry\n",
                     V2VDRV_LOGTAG, vlc, vlc->txCounter + 1);
            return STATUS_RETRY;
        }
        DbgPrint("%s listener(%p) transmit internal response failure; abort processing - error: 0x%x\n",
                 V2VDRV_LOGTAG, vlc, status);
        return status; /* failure */
    }
    vlc->txCounter++; /* next message */
    vlri = vlc->u.xferInternal.respList;
    vlc->u.xferInternal.respList = vlri->next;
    if (!vlc->u.xferInternal.respList)
        vlc->u.xferInternal.respTail = NULL;
    /* Response already formed, just copy it in */
    RtlCopyMemory((void*)msg, vlri, sizeof(V2V_RESP_INTERNAL));
    ExFreePoolWithTag(vlri, V2VDRV_TAG);

    v2v_nc2_send_messages(vlc->channel);

    /* Keep the send loop going by setting the event. If there is no more room, the prep message call
       will return ERROR_RETRY and just land us back in the wait. */
    KeSetEvent(v2v_get_send_event(vlc->channel), IO_NO_INCREMENT, FALSE);
    
    return STATUS_SUCCESS;
}

static NTSTATUS
V2vkListenerProcessFileSyncRx(V2VK_LISTENER_CONTEXT *vlc)
{
    NTSTATUS status;
    volatile UCHAR *msg;
    size_t size, write;
    unsigned type;
    unsigned flags;
    V2V_FRAME_HEADER *header;
    V2V_POST_FILE *vpf;
    UCHAR sum;
    const UCHAR *data;
    IO_STATUS_BLOCK iosb;

    if (vlc->flags & V2V_KERNEL_FASTRX)
        v2v_nc2_request_fast_receive(vlc->channel);

    while ((status = v2v_nc2_get_message(vlc->channel, &msg, &size, &type, &flags))
            == STATUS_SUCCESS) {
        vlc->rxCounter++;   
        header = (V2V_FRAME_HEADER*)msg;
        if (!V2vkMessageHeaderCheck("listener", "file", header, size, sizeof(V2V_POST_FILE))) {
            DbgPrint("%s listener(%p) message header check failed for message #%d!!!\n", V2VDRV_LOGTAG, vlc, vlc->rxCounter);
            v2v_nc2_finish_message(vlc->channel);
            return STATUS_DATA_ERROR;
        }

        vpf = (V2V_POST_FILE*)msg;
        
        /* Check payload and seqnums, return failure status to connector if anything is wrong */
        do {
            sum = V2vChecksum((const UCHAR*)msg, header->length);
            if (sum != 0) {
                DbgPrint("%s listener(%p) bad checksumm on file data message #%d!!!\n",
                         V2VDRV_LOGTAG, vlc, vlc->rxCounter);
                vlc->u.xferFile.status = V2V_MESSAGE_STATUS_BADCS;
                break;
            }
            if (vlc->u.xferFile.seqnum + 1 != vpf->seqnum) {
                DbgPrint("%s listener(%p) invalid sequence number in file data seqnum: %d expecting: %d\n",
                         V2VDRV_LOGTAG, vlc, vpf->seqnum, vlc->u.xferFile.seqnum + 1);
                vlc->u.xferFile.status = V2V_MESSAGE_STATUS_BADSEQ;
                break;
            }
            write = header->length - sizeof(V2V_POST_FILE);
            if (write == 0) {
                DbgPrint("%s listener(%p) no file data in message #%d\n",
                         V2VDRV_LOGTAG, vlc, vlc->rxCounter);
                vlc->u.xferFile.status = V2V_MESSAGE_STATUS_NODATA;
                break;
            }
            data = (const UCHAR*)(msg + sizeof(V2V_POST_FILE));
            status = ZwWriteFile(vlc->u.xferFile.hf, NULL, NULL, NULL, &iosb, (void*)data,
                                 (ULONG)write, NULL, NULL);
            if (!NT_SUCCESS(status)) {
                DbgPrint("%s listener(%p) failed to write file data in message #%d - error: 0x%x\n",
                         V2VDRV_LOGTAG, vlc, vlc->rxCounter, status);
                vlc->u.xferFile.status = V2V_MESSAGE_STATUS_WRITE_ERR;
                break;
            }
            vlc->u.xferFile.status = V2V_MESSAGE_STATUS_OK;
        } while (FALSE);

        /* Finish setting up ack, for failure statuses the ack will cause the other end to disconnect
           and the listener will close down also */
        vlc->u.xferFile.ack = TRUE;
        vlc->u.xferFile.seqnum++;

        v2v_nc2_finish_message(vlc->channel);
    }
    if (vlc->flags & V2V_KERNEL_FASTRX)
        v2v_nc2_cancel_fast_receive(vlc->channel);

    if (status == STATUS_NO_MORE_ENTRIES) {
        /* No more messages */
        return STATUS_SUCCESS;
    }
 
    DbgPrint("%s listener(%p) receive file data failure; abort processing - error: 0x%x\n",
             V2VDRV_LOGTAG, vlc, status);
    return status; /* failure */
}

static NTSTATUS
V2vkListenerProcessFileSyncTx(V2VK_LISTENER_CONTEXT *vlc)
{
    NTSTATUS status;
    unsigned available;
    volatile UCHAR *msg;
    V2V_FRAME_HEADER *header;
    V2V_RESP_FILE *vrf;

    DbgPrint("%s listener(%p) sending file response #%d for seqnum: %d\n", V2VDRV_LOGTAG, vlc, 
             vlc->txCounter + 1, vlc->u.xferFile.seqnum);
    available = v2v_nc2_producer_bytes_available(vlc->channel);
    DbgPrint("%s listener(%p) channel indicates minimum bytes available: 0x%x\n", V2VDRV_LOGTAG, vlc, available);
    ASSERT(vlc->u.xferFile.ack);

    /* No resizing fixed responses for fastrx */   

    status = v2v_nc2_prep_message(vlc->channel, sizeof(V2V_RESP_FILE), V2V_MESSAGE_TYPE_FILE, 0, &msg);
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_RETRY) {
            /* No room right now, return and try again later */
            DbgPrint("%s listener(%p) not enough buffer space to send file response, sequence number %d; retry\n",
                     V2VDRV_LOGTAG, vlc, vlc->u.xferFile.seqnum);
            return STATUS_RETRY;
        }
        DbgPrint("%s listener(%p) transmit file data failure; abort processing - error: 0x%x\n",
                 V2VDRV_LOGTAG, vlc, status);
        return status; /* failure */
    }
    vlc->txCounter++; /* next message */
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
    vlc->u.xferFile.ack = FALSE;
    
    return STATUS_SUCCESS;
}

NTSTATUS
V2vkListenerProcessMessagesSync(V2VK_LISTENER_CONTEXT *vlc)
{
    NTSTATUS status = STATUS_SUCCESS;
    PKEVENT kevarr[3];
    ULONG hc = 2;

    DbgPrint("%s listener(%p) started SYNC processing loop for transfer type: %d fastrx: %d\n",
             V2VDRV_LOGTAG, vlc, vlc->xfer, (vlc->flags & V2V_KERNEL_FASTRX));

    kevarr[0] = v2v_get_receive_event(vlc->channel);    
    kevarr[1] = v2v_get_control_event(vlc->channel);
    kevarr[2] = v2v_get_send_event(vlc->channel);   

    /* Start out processing loop, wait for message */
    do {
        if (vlc->xfer == XferTypeInternal) {
            if (vlc->u.xferInternal.respList)
                hc = 3;
            else
                hc = 2;
        }
        else { /* XferTypeFile */
            /* Ready to send ack */
            if (vlc->u.xferFile.ack) {
                status = vlc->s.sync.txFunction(vlc);
                if (status == STATUS_RETRY)
                    hc = 3; /* wait to send ack below */
                else if (status != STATUS_SUCCESS)
                    return status;
            }
            else
                hc = 2; /* no ack to send, don't wait for tx */
        }

        status = KeWaitForMultipleObjects(hc, kevarr, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
        if (status == STATUS_WAIT_0) {
            status = vlc->s.sync.rxFunction(vlc);
            if (!NT_SUCCESS(status))
                break;
        }        
        else if (status == STATUS_WAIT_1) {
            status = V2vStatusCheck((V2VK_BASE_CONTEXT*)vlc, "listener");
            if (!NT_SUCCESS(status)||(status == STATUS_SUCCESS))
                break;
            /* else STATUS_PENDING indicates further operation */            
        }
        else if (status == STATUS_WAIT_2) {
            status = vlc->s.sync.txFunction(vlc);
            if ((status != STATUS_SUCCESS)&&(status != STATUS_RETRY))
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

    return status;
}

/************************* COMMON *************************/

BOOLEAN V2vkInitializeSync(V2VK_BASE_CONTEXT *vbc)
{
    /* Setup the processor functions */
    if (vbc->role == RoleTypeConnector) {
        if (vbc->xfer == XferTypeInternal) {
            vbc->s.sync.rxFunction = V2vkConnectorProcessInternalSyncRx;
            vbc->s.sync.txFunction = V2vkConnectorProcessInternalSyncTx;
        }
        else {
            vbc->s.sync.rxFunction = V2vkConnectorProcessFileSyncRx;
            vbc->s.sync.txFunction = V2vkConnectorProcessFileSyncTx;
        }
    }
    else {
        if (vbc->xfer == XferTypeInternal) {
            vbc->s.sync.rxFunction = V2vkListenerProcessInternalSyncRx;
            vbc->s.sync.txFunction = V2vkListenerProcessInternalSyncTx;
        }
        else {
            vbc->s.sync.rxFunction = V2vkListenerProcessFileSyncRx;
            vbc->s.sync.txFunction = V2vkListenerProcessFileSyncTx;
        }
    }
    vbc->asvp = NULL;

    return TRUE;
}
