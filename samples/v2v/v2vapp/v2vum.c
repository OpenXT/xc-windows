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

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include <rpc.h>
#include <assert.h>
#include <sys/stat.h>
#include "v2vapp.h"
#include "xs2.h"
#include "v2v.h"

/************************** GENERAL **************************/
typedef struct _V2V_CANCEL_STATE {
    HANDLE cancelEvent;
    struct xs2_handle *xs2;
    struct xs2_watch *cancelWatch;
    char watchPath[MAX_PATH + 1];
} V2V_CANCEL_STATE, *PV2V_CANCEL_STATE;

typedef ULONG (*V2vDataProcessingFunction_t)(void *ctx);

static BOOL
V2vInputSanityCheck(V2V_APP_CONFIG *vac)
{
    ULONG xferSize;

    if (vac->role == RoleTypeListener) {
        /* listener always sends fixed sized messages and doesn use xfer_size */
        return TRUE;
    }

    if (vac->xferSize == 0) {
        /* Special value indicates connect, send nothing and just wait idle */
        printf("V2VAPP connector transfer size of 0 indicates send nothing and do an idle connect\n");
        return TRUE;
    }

    xferSize = (vac->xfer == XferTypeInternal) ? sizeof(V2V_POST_INTERNAL) : sizeof(V2V_POST_FILE);
    if (vac->xferSize <= xferSize) {
        printf("V2VAPP connector transfer size %d (0x%x) too small; %d (0x%x) required\n",
                vac->xferSize, vac->xferSize, xferSize + 1, xferSize + 1);
        return FALSE;
    }

    return TRUE;
}

static BOOL
V2vMessageHeaderCheck(V2V_APP_CONFIG *vac,
                      V2V_FRAME_HEADER *header,
                      size_t messsageSize,
                      size_t minSize,
                      ULONG rxCounter)
{
    const char *rstr = (vac->role == RoleTypeConnector ? "connector" : "listener");
    const char *xstr = (vac->xfer == XferTypeInternal ? "internal" : "file");

    if ((messsageSize < sizeof(V2V_FRAME_HEADER))||(messsageSize < minSize)) {
        printf("V2VAPP (%s - %s) response #%d is too small!!!\n", rstr, xstr, rxCounter);
        return FALSE;
    }
    if (header->length < messsageSize) {
        printf("V2VAPP (%s - %s) response #%d header length incorrect!!!\n", rstr, xstr, rxCounter);
        return FALSE;
    }       
    
    printf("V2VAPP (%s - %s) received message #%d\n", rstr, xstr, rxCounter);
    printf("------ id=%d type=%d length=0x%x\n", header->id, header->type, header->length);

    return TRUE;
}

static BOOL
V2vInitCancelState(V2V_CANCEL_STATE *cs, const char *prefix)
{
    memset(cs, 0, sizeof(V2V_CANCEL_STATE));

    cs->xs2 = xs2_open();
    if (cs->xs2 == NULL) {       
        printf("V2VAPP-CANCEL failed to open xs2 library\n");
        return FALSE;
    }

    cs->cancelEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (cs->cancelEvent == NULL) {
        printf("V2VAPP-CANCEL failed to create cancel event\n");
        xs2_close(cs->xs2);
        return FALSE;
    }

    strcpy(cs->watchPath, prefix);
    strcat(cs->watchPath, "/cancel");
    cs->cancelWatch = xs2_watch(cs->xs2, cs->watchPath, cs->cancelEvent);
    if (cs->cancelWatch == NULL) {       
        printf("V2VAPP-CANCEL failed to register cancel watch\n");
        CloseHandle(cs->cancelEvent);
        xs2_close(cs->xs2);
        return FALSE;
    }

    return TRUE;
}

static void
V2vFreeCancelState(V2V_CANCEL_STATE *cs)
{
    if (cs->cancelWatch != NULL)
        xs2_unwatch(cs->cancelWatch);
    if (cs->cancelEvent != NULL)
        CloseHandle(cs->cancelEvent);
    if (cs->xs2 != NULL)
        xs2_close(cs->xs2);
}

static BOOL
V2vTestCancelState(V2V_CANCEL_STATE *cs)
{
    char *val;
    BOOL rc = TRUE;

    val = xs2_read(cs->xs2, cs->watchPath, NULL);
    if (val == NULL) {
        printf("V2VAPP-CANCEL failed to read cancel value; returning cancel now.\n");
        return TRUE;
    }
    if (strcmp(val, "0") == 0)
        rc = FALSE;

    xs2_free(val);
    return rc;
}

/************************* CONNECTOR *************************/
typedef struct _V2V_CONNECTOR_STATE {
    V2V_APP_CONFIG *vac;
    struct v2v_channel *channel;
    ULONG txCounter;
    ULONG rxCounter;
    V2V_CANCEL_STATE cs;

    V2vDataProcessingFunction_t rxFunction;
    V2vDataProcessingFunction_t txFunction;

    union {
        struct {
            ULONG reserved;
        } xferInternal;
        struct {
            FILE *fh;
            struct _stat finfo;
            ULONG offset;
            ULONG seqnum;
            ULONG seqrx;
            BOOL done;
        } xferFile;
    } u;
} V2V_CONNECTOR_STATE, *PV2V_CONNECTOR_STATE;

static ULONG
V2vConnect(V2V_CONNECTOR_STATE *vcs)
{
    BOOL rc;
    DWORD status, ms = INFINITE, tc = 0, to = vcs->vac->xferTimeout << 2, td;
    ULONG error = ERROR_SUCCESS;
    HANDLE hce;
    enum v2v_endpoint_state state;

    /* Connect to the listener, get back a channel handle */
    rc = v2v_connect(vcs->vac->localPrefix, &vcs->channel);
    if (!rc) {
        error = GetLastError();
        printf("V2VAPP-CONNECTOR failure in v2v_connect() - error: 0x%x\n", error);
        return error;
    }
    assert(vcs->channel != NULL);

    printf("V2VAPP-CONNECTOR Connector connected to listener; wait for listenter to indicate it has accepted the connection...\n");

    hce = v2v_get_control_event(vcs->channel);
    
    do {
        if (tc != 0) {
            /* rundown timer */ 
            td = GetTickCount() - tc;
            if (td < to)
                ms = to - td;
            else
                ms = 0;
        }
        else {
            ms = to;
            tc = GetTickCount();
        }

        status = WaitForSingleObject(hce, ms);
        if (status == WAIT_FAILED) {
            /* this is bad */
            error = GetLastError();
            printf("V2VAPP-CONNECTOR wait failure; abort waiting for accept - error: 0x%x\n", error);
            break;
        }    
        else if (status == WAIT_OBJECT_0) {
            state = v2v_get_remote_state(vcs->channel);
            printf("V2VAPP-CONNECTOR state changed for other end - new state: %s\n", 
                    v2v_endpoint_state_name(state));
            if (state == v2v_state_connected) {
                printf("V2VAPP-CONNECTOR listener reports connected; begin processing messages\n");
                error = ERROR_SUCCESS;
                break;
            }
        }     
        else if (status == WAIT_TIMEOUT) {
            printf("V2VAPP-CONNECTOR timed out waiting for accept from listener; disconnecting\n");
            error = ERROR_GEN_FAILURE;
            break;
        }
        else {
            /* sno */
            printf("V2VAPP-CONNECTOR wait critical failure - unexpected wait value; exiting.\n");
            exit(-1);
        }
    } while (TRUE);

    if (error != ERROR_SUCCESS)
        v2v_disconnect(vcs->channel);

    return error;
}

static ULONG
V2vConnectorProcessInternalRx(V2V_CONNECTOR_STATE *vcs)
{
    volatile UCHAR *msg;
    size_t size;
    unsigned type;
    unsigned flags;
    ULONG error;
    V2V_FRAME_HEADER *header;
    V2V_RESP_INTERNAL *vri;
    GUID *pguid;
    UCHAR sum;

    if (vcs->vac->fastrx)
        v2v_nc2_request_fast_receive(vcs->channel);

    while (v2v_nc2_get_message(vcs->channel, &msg, &size, &type, &flags)) {
        vcs->rxCounter++;   
        header = (V2V_FRAME_HEADER*)msg;
        if (!V2vMessageHeaderCheck(vcs->vac, header, size, sizeof(V2V_RESP_INTERNAL), vcs->rxCounter)) {
            v2v_nc2_finish_message(vcs->channel);
            return ERROR_INVALID_DATA;
        }

        vri = (V2V_RESP_INTERNAL*)msg;
        printf("------ message status=%d\n", vri->status);
        pguid = &vri->guid;
        printf("------ GUID={%8.8x-%4.4x-%4.4x-%2.2x%2.2x-%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x}\n",
               pguid->Data1, pguid->Data2, pguid->Data3, pguid->Data4[0], pguid->Data4[1], pguid->Data4[2],
               pguid->Data4[3], pguid->Data4[4], pguid->Data4[5], pguid->Data4[6], pguid->Data4[7]);
        sum = V2vChecksum((const UCHAR*)msg, header->length);
        if (sum != 0)
            printf("V2VAPP-CONNECTOR bad checksumm on response #%d!!!\n", vcs->rxCounter);
        v2v_nc2_finish_message(vcs->channel);
    }
    error = GetLastError();
    if (vcs->vac->fastrx)
        v2v_nc2_cancel_fast_receive(vcs->channel);

    if (error == ERROR_NO_MORE_ITEMS) {
        /* No more messages */
        printf("V2VAPP-CONNECTOR no more messages, returning\n");
        return ERROR_SUCCESS;
    }

    printf("V2VAPP-CONNECTOR receive internal data failure; abort processing - error: 0x%x\n", error);
    return error; /* failure */
}

static ULONG
V2vConnectorProcessInternalTx(V2V_CONNECTOR_STATE *vcs)
{
    unsigned available;
    volatile UCHAR *msg;
    ULONG error;
    V2V_FRAME_HEADER *header;
    V2V_POST_INTERNAL *vpi;
    RPC_STATUS rpcstat;
    size_t msize;

    printf("V2VAPP-CONNECTOR sending internal message #%d\n", vcs->txCounter + 1);
    available = v2v_nc2_producer_bytes_available(vcs->channel);
    printf("V2VAPP-CONNECTOR channel indicates minimum bytes available: 0x%x\n", available);

    if (vcs->vac->xferSize == 0) {
        printf("V2VAPP-CONNECTOR transer size 0, send nothing\n");
        return ERROR_SUCCESS;
    }
    
    if (vcs->vac->fastrx && v2v_nc2_remote_requested_fast_wakeup(vcs->channel))
        msize = MIN(vcs->vac->xferSize, vcs->vac->xferMaxFastRx);
    else
        msize = vcs->vac->xferSize;

    if (!v2v_nc2_prep_message(vcs->channel, msize, V2V_MESSAGE_TYPE_INTERNAL, 0, &msg)) {
        error = GetLastError();
        if (error == ERROR_RETRY) {
            /* No room right now, return and try again later */
            printf("V2VAPP-CONNECTOR not enough buffer space to send message #%d; retry\n", vcs->txCounter + 1);
            return ERROR_RETRY;
        }
        printf("V2VAPP-CONNECTOR transmit internal data failure; abort processing - error: 0x%x\n", error);
        return error; /* failure */
    }
    vcs->txCounter++; /* next message */
    header = (V2V_FRAME_HEADER*)msg;
    header->id = (USHORT)vcs->txCounter;
    header->type = V2V_MESSAGE_TYPE_INTERNAL;
    header->cs = 0;
    header->length = vcs->vac->xferSize;
    vpi = (V2V_POST_INTERNAL*)msg;
    rpcstat = UuidCreate(&vpi->guid);
    if (rpcstat != RPC_S_OK) {
        printf("V2VAPP-CONNECTOR UuidCreate() failed - error: 0x%x; using NULL GUID\n", rpcstat);
        memset((void*)(msg + sizeof(V2V_FRAME_HEADER)), 0, sizeof(GUID));
    }
    /* Fill it up with some data and send it */
    memset((void*)(msg + sizeof(V2V_POST_INTERNAL)),
           'X',
           (vcs->vac->xferSize - sizeof(V2V_POST_INTERNAL)));
    header->cs = V2vChecksum((const UCHAR*)msg, vcs->vac->xferSize);
    v2v_nc2_send_messages(vcs->channel);

    /* Keep the send loop going by setting the event. If there is no more room, the prep message call
       will return ERROR_RETRY and just land us back in the wait. */
    SetEvent(v2v_get_send_event(vcs->channel));

    return ERROR_SUCCESS;
}

static ULONG
V2vConnectorProcessFileRx(V2V_CONNECTOR_STATE *vcs)
{
    volatile UCHAR *msg;
    size_t size;
    unsigned type;
    unsigned flags;
    ULONG error;
    V2V_FRAME_HEADER *header;
    V2V_RESP_FILE *vrf;
    UCHAR sum;
    V2V_RESP_FILE lvrf;

    if (vcs->vac->fastrx)
        v2v_nc2_request_fast_receive(vcs->channel);

    while (v2v_nc2_get_message(vcs->channel, &msg, &size, &type, &flags)) {
        vcs->rxCounter++;
        header = (V2V_FRAME_HEADER*)msg;
        if (!V2vMessageHeaderCheck(vcs->vac, header, size, sizeof(V2V_RESP_FILE), vcs->rxCounter)) {
            v2v_nc2_finish_message(vcs->channel);
            return ERROR_INVALID_DATA;
        }

        vrf = (V2V_RESP_FILE*)msg;
        printf("------ message status=%d seqnum=%d\n", vrf->status, vrf->seqnum);
        /* Copy the response locally and free it */
        lvrf = *vrf;
        v2v_nc2_finish_message(vcs->channel);
        
        /* Test the response, any failure then abort. The listener should be acking the most
           recent seqnum. */
        sum = V2vChecksum((const UCHAR*)(&lvrf), sizeof(V2V_RESP_FILE));
        if (sum != 0) {
            printf("V2VAPP-CONNECTOR bad checksumm file response #%d - seqnum: %d\n", vcs->rxCounter, lvrf.seqnum);
            return ERROR_INVALID_DATA;
        }
        if (lvrf.status != V2V_MESSAGE_STATUS_OK) {
            printf("V2VAPP-CONNECTOR failure status number in file response #%d - seqnum: %d status: 0x%x\n",
                    vcs->rxCounter, lvrf.seqnum, lvrf.status);
            return ERROR_INVALID_DATA;
        }
        if ((lvrf.seqnum != vcs->u.xferFile.seqnum - 1)||(lvrf.seqnum != vcs->u.xferFile.seqrx)) {
            printf("V2VAPP-CONNECTOR invalid sequence number in file response #%d - seqnum: %d\n", vcs->rxCounter, lvrf.seqnum);
            return ERROR_INVALID_DATA;
        }        
        /* Else move the seqrx tracker forward - it should now match the seqnum which indicats we should send */
        vcs->u.xferFile.seqrx++;
        assert(vcs->u.xferFile.seqnum == vcs->u.xferFile.seqrx);
    }
    error = GetLastError();
    if (vcs->vac->fastrx)
        v2v_nc2_cancel_fast_receive(vcs->channel);

    if (error == ERROR_NO_MORE_ITEMS) {
        /* No more messages */
        return ERROR_SUCCESS;
    }

    printf("V2VAPP-CONNECTOR receive file data failure; abort processing - error: 0x%x\n", error);
    return error; /* failure */
}

static ULONG
V2vConnectorProcessFileTx(V2V_CONNECTOR_STATE *vcs)
{
    unsigned available;
    ULONG remainder, send;
    BOOL last = FALSE;
    size_t msize;
    volatile UCHAR *msg;
    ULONG error;
    V2V_FRAME_HEADER *header;
    V2V_POST_FILE *vpf;
    int ret;

    printf("V2VAPP-CONNECTOR sending file message #%d\n", vcs->txCounter + 1);
    available = v2v_nc2_producer_bytes_available(vcs->channel);
    printf("V2VAPP-CONNECTOR channel indicates minimum bytes available: 0x%x\n", available);

    if (vcs->vac->xferSize == 0) {
        printf("V2VAPP-CONNECTOR transer size 0, send nothing\n");
        return ERROR_SUCCESS;
    }

    if (vcs->vac->fastrx && v2v_nc2_remote_requested_fast_wakeup(vcs->channel))
        msize = MIN(vcs->vac->xferSize, vcs->vac->xferMaxFastRx);
    else
        msize = vcs->vac->xferSize;
    
    remainder = vcs->u.xferFile.finfo.st_size - vcs->u.xferFile.offset;
    send = MIN(available, (ULONG)msize) - sizeof(V2V_POST_FILE);
    if (send >= remainder) {
        send = remainder;
        last = TRUE;
    }

    if (!v2v_nc2_prep_message(vcs->channel, send + sizeof(V2V_POST_FILE), V2V_MESSAGE_TYPE_FILE, 0, &msg)) {
        error = GetLastError();
        if (error == ERROR_RETRY) {
            /* No room right now, return and try again later */
            printf("V2VAPP-CONNECTOR not enough buffer space to send file data, sequence number %d; retry\n", vcs->u.xferFile.seqnum);
            return ERROR_RETRY;
        }
        printf("V2VAPP-CONNECTOR transmit file data failure; abort processing - error: 0x%x\n", error);
        return error; /* failure */
    }
    vcs->txCounter++; /* next message */
    header = (V2V_FRAME_HEADER*)msg;
    header->id = (USHORT)vcs->txCounter;
    header->type = V2V_MESSAGE_TYPE_FILE;
    header->cs = 0;
    header->length = send + sizeof(V2V_POST_FILE);
    vpf = (V2V_POST_FILE*)msg;
    vpf->status = (last ? V2V_MESSAGE_STATUS_EOF : V2V_MESSAGE_STATUS_MORE);
    vpf->seqnum = vcs->u.xferFile.seqnum;
    /* read the file data */
    ret = fseek(vcs->u.xferFile.fh, vcs->u.xferFile.offset, SEEK_SET);
    if (ret) {
        printf("V2VAPP-CONNECTOR failed to seek file; aborting - errno: %d\n", errno);
        return ERROR_INVALID_DATA;
    }
    ret = (int)fread((void*)(msg + sizeof(V2V_POST_FILE)), send, 1, vcs->u.xferFile.fh);
    if (ret < (int)send) {
        if (ferror(vcs->u.xferFile.fh) != 0) {
            printf("V2VAPP-CONNECTOR failed to read file; aborting - errno: %d\n", errno);
            return ERROR_INVALID_DATA;
        }
        else if (ret == 0) {
            /* EOF, exit */
            printf("V2VAPP-CONNECTOR EOF received.\n", errno);
            return ERROR_INVALID_DATA; /* not really an error */
        }
        /* Else it is just the last chunk - we will get EOF next time*/
    }

    header->cs = V2vChecksum((const UCHAR*)msg, send + sizeof(V2V_POST_FILE));
    v2v_nc2_send_messages(vcs->channel);

    printf("V2VAPP-CONNECTOR sent file data seqnum=%d done=%d\n", vcs->u.xferFile.seqnum, vcs->u.xferFile.done);

    /* Update for next file chunk to send */
    if (!last) {
        vcs->u.xferFile.offset += send;
        vcs->u.xferFile.seqnum++;
    }
    else
        vcs->u.xferFile.done = TRUE;    

    return ERROR_SUCCESS;
}

static void
V2vConnectorProcessMessages(V2V_CONNECTOR_STATE *vcs)
{
    HANDLE harr[4];
    DWORD status, hc = 4, ms = INFINITE, tc = 0, to, td;
    ULONG error = ERROR_SUCCESS;
    enum v2v_endpoint_state state;

    printf("V2VAPP-CONNECTOR started processing loop for transfer type: %d fastrx: %d\n", 
           vcs->vac->xfer, vcs->vac->fastrx);

    /* A transfer count of 0 is used to just test connecting and disconnecting
       w/o sending any data */
    if ((vcs->vac->xfer == XferTypeInternal)&&(vcs->vac->xferCount == 0)) {
        printf("V2VAPP-CONNECTOR tranfer count set to 0; disconnecting.\n");
        return;
    }

    harr[0] = vcs->cs.cancelEvent;
    harr[1] = v2v_get_receive_event(vcs->channel);    
    harr[2] = v2v_get_control_event(vcs->channel);
    harr[3] = v2v_get_send_event(vcs->channel);
    to = vcs->vac->xferTimeout;

    /* Send our first file chunk to the listener to start things off */
    error = vcs->txFunction(vcs);
    if (error != ERROR_SUCCESS) {
        assert(error != ERROR_RETRY); /* SNO on first message */
        return;
    }

    /* Start our processing loop, wait for a response and send more file chunks */
    do {
        if (vcs->vac->xfer == XferTypeInternal) {
            /* When the tx counter reaches the transfer count value, stop sending and wait for 
               the rest of the responses */
            if (vcs->txCounter == vcs->vac->xferCount) {
                /* First see if we are done */
                if (vcs->rxCounter == vcs->txCounter) {
                    printf("V2VAPP-CONNECTOR received all remaing responses from listener; disconnecting\n");
                    break;
                }

                if (tc != 0) {
                    /* rundown timer */ 
                    td = GetTickCount() - tc;
                    if (td < to)
                        ms = to - td;
                    else
                        ms = 0;
                }
                else {
                    hc = 2;
                    ms = to;
                    tc = GetTickCount();
                }
            }
        }
        else { /* XferTypeFile */
            if ((vcs->u.xferFile.done)&&
                (vcs->u.xferFile.seqrx == vcs->u.xferFile.seqnum)) {
                 printf("V2VAPP-CONNECTOR file send, recieved all ack responses from listener; disconnecting\n");
                 break;
            }
            if (vcs->u.xferFile.seqrx == vcs->u.xferFile.seqnum) {
                /* Ready to send more */                  
                error = vcs->txFunction(vcs);
                if (error == ERROR_RETRY) {
                    /* If we cannot send at this point, we go to the wait for room in the
                       tx ring to open up */
                    hc = 3;
                    ms = INFINITE;
                }
                else if (error != ERROR_SUCCESS)
                    return;
            }
            else {
                /* Waiting for an ack on the last chunk */
                if (tc != 0) {
                    /* rundown timer */ 
                    td = GetTickCount() - tc;
                    if (td < to)
                        ms = to - td;
                    else
                        ms = 0;
                }
                else {
                    hc = 2;
                    ms = to;
                    tc = GetTickCount();
                }
            }
        }

        status = WaitForMultipleObjects(hc, harr, FALSE, ms);
        if (status == WAIT_FAILED) {
            /* this is bad */
            error = GetLastError();
            printf("V2VAPP-CONNECTOR wait failure; abort processing - error: 0x%x\n", error);
            break;
        }
        else if (status == WAIT_OBJECT_0) {
            printf("V2VAPP-CONNECTOR cancel event signaled\n");
            /* Test the cancel state to see if we should end the loop */
            if (V2vTestCancelState(&vcs->cs)) {
                printf("V2VAPP-CONNECTOR main processing loop ending for cancel event...\n"); 
                break;
            }
        }
        else if (status == WAIT_OBJECT_0 + 1) {
            error = vcs->rxFunction(vcs);
            if (error != ERROR_SUCCESS)
                break;           
        }        
        else if (status == WAIT_OBJECT_0 + 2) {
            state = v2v_get_remote_state(vcs->channel);
            printf("V2VAPP-CONNECTOR state changed for other end - new state: %s\n", 
                    v2v_endpoint_state_name(state));
            if (v2v_state_requests_disconnect(state)) {
                printf("V2VAPP-CONNECTOR main processing loop ending for disconnect request...\n"); 
                break;
            }
        }
        else if (status == WAIT_OBJECT_0 + 3) {
            error = vcs->txFunction(vcs);
            if ((error != ERROR_SUCCESS)&&(error != ERROR_RETRY))
                break;
        }
        else if (status == WAIT_TIMEOUT) {
            printf("V2VAPP-CONNECTOR timed out waiting for ack responses from listener; disconnecting\n");
            break;
        }
        else {
            /* sno */
            printf("V2VAPP-CONNECTOR wait critical failure - unexpected wait value; exiting.\n");
            exit(-1);
        }
    } while (TRUE);
}

static void
V2vConnectorDisconnect(V2V_CONNECTOR_STATE *vcs)
{
    printf("V2VAPP-CONNECTOR Disconnecting...\n");
    v2v_disconnect(vcs->channel);
    printf("V2VAPP-CONNECTOR Disconnected.\n");

    printf("V2VAPP-CONNECTOR Sent message counter: %d\n", vcs->txCounter);
    printf("V2VAPP-CONNECTOR Received response counter: %d\n", vcs->rxCounter);
    if (vcs->txCounter != vcs->rxCounter)
        printf("V2VAPP-CONNECTOR WARNING Response count does not match the send count\n");
}

static void
V2vConnectorCleanup(V2V_CONNECTOR_STATE *vcs)
{
    if ((vcs->vac->xfer == XferTypeFile)&&(vcs->u.xferFile.fh))
        fclose(vcs->u.xferFile.fh);
    V2vFreeCancelState(&vcs->cs);
    free(vcs);
}

static void
V2vRunUserModeConnector(V2V_APP_CONFIG *vac)
{
    V2V_CONNECTOR_STATE *vcs = NULL;
    ULONG error;
    int ret;

    printf("V2VAPP-CONNECTOR starting for transfer type: %s\n", (vac->xfer == XferTypeInternal) ? "Internal" : "File");

    vcs = (V2V_CONNECTOR_STATE*)malloc(sizeof(V2V_CONNECTOR_STATE));
    if (vcs == NULL) {
        printf("V2VAPP-CONNECTOR out of memory\n");
        return;
    }
    memset(vcs, 0, sizeof(V2V_CONNECTOR_STATE));
    vcs->vac = vac;
    
    if (!V2vInitCancelState(&vcs->cs, vac->localPrefix)) {
        printf("V2VAPP-CONNECTOR failed to init cancel state\n");
        V2vConnectorCleanup(vcs);
        return;
    }

    if (vac->xfer == XferTypeFile) {
        /* First open the file to send and get some information about it */
        vcs->u.xferFile.fh = fopen(vcs->vac->xferFilePath, "rb");
        if (!vcs->u.xferFile.fh) {
            printf("V2VAPP-CONNECTOR failed to open file %s; aborting - errno: %d\n", vcs->vac->xferFilePath, errno);
            V2vConnectorCleanup(vcs);
            return;
        }
        ret = _stat(vcs->vac->xferFilePath, &vcs->u.xferFile.finfo);
        if (ret) {
            printf("V2VAPP-CONNECTOR failed to get file information %s; aborting - errno: %d\n", vcs->vac->xferFilePath, errno);
            V2vConnectorCleanup(vcs);
            return;
        }
        vcs->u.xferFile.seqnum = 1;
        vcs->u.xferFile.seqrx = 1;

        vcs->rxFunction = V2vConnectorProcessFileRx;
        vcs->txFunction = V2vConnectorProcessFileTx;
    }
    else {
        vcs->rxFunction = V2vConnectorProcessInternalRx;
        vcs->txFunction = V2vConnectorProcessInternalTx;
    }

    if (!V2vInputSanityCheck(vcs->vac)) {
        V2vConnectorCleanup(vcs);
        return;
    }

    error = V2vConnect(vcs);
    if (error != ERROR_SUCCESS) {
        V2vConnectorCleanup(vcs);
        return;
    }
	
    /* This runs the main processing loop, when it is done we disconnect
       and cleanup regardless of what may have occured */
    V2vConnectorProcessMessages(vcs);

    V2vConnectorDisconnect(vcs);

    V2vConnectorCleanup(vcs);
}

/************************* LISTENER **************************/
typedef struct _V2V_LISTENER_STATE {
    V2V_APP_CONFIG *vac;
    struct v2v_channel *channel;
    ULONG rxCounter;
    ULONG txCounter;
    V2V_CANCEL_STATE cs;

    V2vDataProcessingFunction_t rxFunction;
    V2vDataProcessingFunction_t txFunction;
   
    union {
        struct {
            struct _V2V_LISTENER_RESP_ITEM *respList;
            struct _V2V_LISTENER_RESP_ITEM *respTail;
        } xferInternal;
        struct {
            FILE *fh;
            ULONG seqnum;
            ULONG status;
            BOOL ack;
        } xferFile;
    } u;
} V2V_LISTENER_STATE, *PV2V_LISTENER_STATE;

static ULONG
V2vListenAccept(V2V_LISTENER_STATE *vls)
{
    BOOL rc;
    ULONG error = ERROR_SUCCESS;

    /* Start the listener, get back a channel handle */
    rc = v2v_listen(vls->vac->localPrefix, &vls->channel, 0, 0);
    if (!rc) {
        error = GetLastError();
        printf("V2VAPP-LISTENER failure in v2v_listen() - error: 0x%x\n", error);
        return error;
    }
    assert(vls->channel != NULL);
    printf("V2VAPP-LISTENER Listener started, wait to accept...\n");
    
    /* Wait to accept the connection from the connector end */
    rc = v2v_accept(vls->channel);
    if (!rc) {
        error = GetLastError();
        if (error != ERROR_VC_DISCONNECTED)
            printf("V2VAPP-LISTENER failure in v2v_accept() - error: 0x%x\n", error);
        else
            printf("V2VAPP-LISTENER remote end disconnected while waiting to accept\n");      
        
        rc = v2v_disconnect(vls->channel);
        if (!rc)
            printf("V2VAPP-LISTENER secondary failure in v2v_disconnect() after accept failed - error: 0x%x\n", GetLastError());
        return error;
    }
    
    printf("V2VAPP-LISTENER Accepted connection, ready to process incoming data.\n");
    return ERROR_SUCCESS;
}

static ULONG
V2vListenerProcessInternalRx(V2V_LISTENER_STATE *vls)
{
    volatile UCHAR *msg;
    size_t size;
    unsigned type;
    unsigned flags;
    ULONG error;
    V2V_FRAME_HEADER *header;
    V2V_POST_INTERNAL *vpi;
    V2V_LISTENER_RESP_ITEM *vlri;
    GUID *pguid;
    UCHAR sum;

    if (vls->vac->fastrx)
        v2v_nc2_request_fast_receive(vls->channel);

    while (v2v_nc2_get_message(vls->channel, &msg, &size, &type, &flags)) {
        vls->rxCounter++;
        header = (V2V_FRAME_HEADER*)msg;
        if (!V2vMessageHeaderCheck(vls->vac, header, size, sizeof(V2V_POST_INTERNAL), vls->rxCounter)) {
            v2v_nc2_finish_message(vls->channel);
            return ERROR_INVALID_DATA;
        }

        vpi = (V2V_POST_INTERNAL*)msg;
        pguid = &vpi->guid;
        printf("------ GUID={%8.8x-%4.4x-%4.4x-%2.2x%2.2x-%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x}\n",
               pguid->Data1, pguid->Data2, pguid->Data3, pguid->Data4[0], pguid->Data4[1], pguid->Data4[2],
               pguid->Data4[3], pguid->Data4[4], pguid->Data4[5], pguid->Data4[6], pguid->Data4[7]);
        sum = V2vChecksum((const UCHAR*)msg, header->length);
        if (sum != 0)
            printf("V2VAPP-LISTENER bad checksumm on message #%d!!!\n", vls->rxCounter);

        /* Queue a response */
        vlri = (V2V_LISTENER_RESP_ITEM*)malloc(sizeof(V2V_LISTENER_RESP_ITEM));
        if (vlri) {
            vlri->next = NULL;
            vlri->resp.header.id = header->id;
            vlri->resp.header.type = V2V_MESSAGE_TYPE_INTERNAL;
            vlri->resp.header.cs = 0;
            vlri->resp.header.length = sizeof(V2V_RESP_INTERNAL); /* header + resp data */
            vlri->resp.status = (sum == 0 ? V2V_MESSAGE_STATUS_OK : V2V_MESSAGE_STATUS_BADCS);
            memcpy(&vlri->resp.guid, pguid, sizeof(GUID));
            vlri->resp.header.cs = V2vChecksum((const UCHAR*)vlri, sizeof(V2V_RESP_INTERNAL));
            if (vls->u.xferInternal.respList) {
                vls->u.xferInternal.respTail->next = vlri;
                vls->u.xferInternal.respTail = vlri;
            }
            else {
                vls->u.xferInternal.respList = vlri;
                vls->u.xferInternal.respTail = vlri;
            }
        }
        else
            printf("V2VAPP-LISTENER cannot queue response; out of memory\n");

        v2v_nc2_finish_message(vls->channel);
    }
    error = GetLastError();
    if (vls->vac->fastrx)
        v2v_nc2_cancel_fast_receive(vls->channel);

    if (error == ERROR_NO_MORE_ITEMS) {
        /* No more messages */
        printf("V2VAPP-LISTENER no more messages, returning\n");
        return ERROR_SUCCESS;
    }

    printf("V2VAPP-LISTENER receive internal data failure; abort processing - error: 0x%x\n", error);
    return error; /* failure */
}

static ULONG
V2vListenerProcessInternalTx(V2V_LISTENER_STATE *vls)
{
    unsigned available;
    volatile UCHAR *msg;
    ULONG error;
    size_t msize;
    V2V_LISTENER_RESP_ITEM *vlri; 

    printf("V2VAPP-LISTENER sending internal response #%d\n", vls->txCounter + 1);
    available = v2v_nc2_producer_bytes_available(vls->channel);
    printf("V2VAPP-LISTENER channel indicates minimum bytes available: 0x%x\n", available);
    assert(vls->u.xferInternal.respList);

    if (vls->vac->fastrx && v2v_nc2_remote_requested_fast_wakeup(vls->channel))
        msize = MIN(sizeof(V2V_RESP_INTERNAL), vls->vac->xferMaxFastRx);
    else
        msize = sizeof(V2V_RESP_INTERNAL);

    if (!v2v_nc2_prep_message(vls->channel, msize, V2V_MESSAGE_TYPE_INTERNAL, 0, &msg)) {
        error = GetLastError();
        if (error == ERROR_RETRY) {
            /* No room right now, return and try again later */
            printf("V2VAPP-LISTENER not enough buffer space to send response #%d; retry\n", vls->txCounter + 1);
            return ERROR_RETRY;
        }
        printf("V2VAPP-LISTENER transmit internal response failure; abort processing - error: 0x%x\n", error);
        return error; /* failure */
    }
    vls->txCounter++;
    vlri = vls->u.xferInternal.respList;
    vls->u.xferInternal.respList = vlri->next;
    if (!vls->u.xferInternal.respList)
        vls->u.xferInternal.respTail = NULL;
    /* Response already formed, just copy it in */
    memcpy((void*)msg, vlri, sizeof(V2V_RESP_INTERNAL));
    free(vlri);

    v2v_nc2_send_messages(vls->channel);

    /* Keep the send loop going by setting the event. If there is no more room, the prep message call
       will return ERROR_RETRY and just land us back in the wait. */
    SetEvent(v2v_get_send_event(vls->channel));
    
    return ERROR_SUCCESS;
}

static ULONG
V2vListenerProcessFileRx(V2V_LISTENER_STATE *vls)
{
    volatile UCHAR *msg;
    size_t size, write, written;
    unsigned type;
    unsigned flags;
    ULONG error;
    V2V_FRAME_HEADER *header;
    V2V_POST_FILE *vpf;
    UCHAR sum;
    const UCHAR *data;

    if (vls->vac->fastrx)
        v2v_nc2_request_fast_receive(vls->channel);

    while (v2v_nc2_get_message(vls->channel, &msg, &size, &type, &flags)) {
        vls->rxCounter++;
        header = (V2V_FRAME_HEADER*)msg;
        if (!V2vMessageHeaderCheck(vls->vac, header, size, sizeof(V2V_POST_FILE), vls->rxCounter)) {
            v2v_nc2_finish_message(vls->channel);
            return ERROR_INVALID_DATA;
        }

        vpf = (V2V_POST_FILE*)msg;
        
        /* Check payload and seqnums, return failure status to connector if anything is wrong */
        do {
            sum = V2vChecksum((const UCHAR*)msg, header->length);
            if (sum != 0) {
                printf("V2VAPP-LISTENER bad checksumm on file data message #%d!!!\n", vls->rxCounter);
                vls->u.xferFile.status = V2V_MESSAGE_STATUS_BADCS;
                break;
            }
            if (vls->u.xferFile.seqnum + 1 != vpf->seqnum) {
                printf("V2VAPP-LISTENER invalid sequence number in file data seqnum: %d expecting: %d\n",
                       vpf->seqnum, vls->u.xferFile.seqnum + 1);
                vls->u.xferFile.status = V2V_MESSAGE_STATUS_BADSEQ;
                break;
            }
            write = header->length - sizeof(V2V_POST_FILE);
            if (write == 0) {
                printf("V2VAPP-LISTENER no file data in message #%d!!!\n", vls->rxCounter);
                vls->u.xferFile.status = V2V_MESSAGE_STATUS_NODATA;
                break;
            }
            data = (const UCHAR*)(msg + sizeof(V2V_POST_FILE));
            written = fwrite(data, write, 1, vls->u.xferFile.fh);
            if (written != 1) {
                printf("V2VAPP-LISTENER failed to write file data in message #%d - errno: %d\n",
                       vls->rxCounter, errno);
                vls->u.xferFile.status = V2V_MESSAGE_STATUS_WRITE_ERR;
                break;
            }
            vls->u.xferFile.status = V2V_MESSAGE_STATUS_OK;
        } while (FALSE);

        /* Finish setting up ack, for failure statuses the ack will cause the other end to disconnect
           and the listener will close down also */
        vls->u.xferFile.ack = TRUE;
        vls->u.xferFile.seqnum++;

        v2v_nc2_finish_message(vls->channel);
    }
    error = GetLastError();
    if (vls->vac->fastrx)
        v2v_nc2_cancel_fast_receive(vls->channel);

    if (error == ERROR_NO_MORE_ITEMS) {
        /* No more messages */
        return ERROR_SUCCESS;
    }

    printf("V2VAPP-LISTENER receive file data failure; abort processing - error: 0x%x\n", error);
    return error; /* failure */
}

static ULONG
V2vListenerProcessFileTx(V2V_LISTENER_STATE *vls)
{
    unsigned available;
    volatile UCHAR *msg;
    ULONG error;
    size_t msize;
    V2V_FRAME_HEADER *header;
    V2V_RESP_FILE *vrf;

    printf("V2VAPP-LISTENER sending file response #%d for seqnum: %d\n",
           vls->txCounter + 1, vls->u.xferFile.seqnum);
    available = v2v_nc2_producer_bytes_available(vls->channel);
    printf("V2VAPP-LISTENER channel indicates minimum bytes available: 0x%x\n", available);
    assert(vls->u.xferFile.ack);

    if (vls->vac->fastrx && v2v_nc2_remote_requested_fast_wakeup(vls->channel))
        msize = MIN(sizeof(V2V_RESP_FILE), vls->vac->xferMaxFastRx);
    else
        msize = sizeof(V2V_RESP_FILE);

    if (!v2v_nc2_prep_message(vls->channel, msize, V2V_MESSAGE_TYPE_FILE, 0, &msg)) {
        error = GetLastError();
        if (error == ERROR_RETRY) {
            /* No room right now, return and try again later */
            printf("V2VAPP-LISTENER not enough buffer space to send response #%d; retry\n", vls->txCounter + 1);
            return ERROR_RETRY;
        }
        printf("V2VAPP-LISTENER transmit internal response failure; abort processing - error: 0x%x\n", error);
        return error; /* failure */
    }
    vls->txCounter++; /* next message */
    header = (V2V_FRAME_HEADER*)msg;
    header->id = (USHORT)vls->txCounter;
    header->type = V2V_MESSAGE_TYPE_FILE;
    header->cs = 0;
    header->length = sizeof(V2V_RESP_FILE);
    vrf = (V2V_RESP_FILE*)msg;
    vrf->status = vls->u.xferFile.status;
    vrf->seqnum = vls->u.xferFile.seqnum;
    header->cs = V2vChecksum((const UCHAR*)vrf, sizeof(V2V_RESP_FILE));

    v2v_nc2_send_messages(vls->channel);
    vls->u.xferFile.ack = FALSE;
    
    return ERROR_SUCCESS;
}

static void
V2vListenerProcessMessages(V2V_LISTENER_STATE *vls)
{
    HANDLE harr[4];
    DWORD status, hc = 3;
    ULONG error = ERROR_SUCCESS;
    enum v2v_endpoint_state state;

    printf("V2VAPP-LISTENER started processing loop for transfer type: %d fastrx: %d\n", 
           vls->vac->xfer, vls->vac->fastrx);

    harr[0] = vls->cs.cancelEvent;
    harr[1] = v2v_get_receive_event(vls->channel);   
    harr[2] = v2v_get_control_event(vls->channel);
    harr[3] = v2v_get_send_event(vls->channel);    

    /* Start out processing loop, wait for message */
    do {
        if (vls->vac->xfer == XferTypeInternal) {
            if (vls->u.xferInternal.respList)
                hc = 4;
            else
                hc = 3;
        }
        else { /* XferTypeFile */
            /* Ready to send ack */
            if (vls->u.xferFile.ack) {
                error = vls->txFunction(vls);
                if (error == ERROR_RETRY)
                    hc = 3; /* wait to send ack below */
                else if (error != ERROR_SUCCESS)
                    return;
            }
            else
                hc = 2; /* no ack to send, don't wait for tx */
        }

        status = WaitForMultipleObjects(hc, harr, FALSE, INFINITE);
        if (status == WAIT_FAILED) {
            /* this is bad */
            error = GetLastError();
            printf("V2VAPP-LISTENER wait failure; abort processing - error: 0x%x\n", error);
            break;
        }
        else if (status == WAIT_OBJECT_0) {
            printf("V2VAPP-LISTENER cancel event signaled\n");
            /* Test the cancel state to see if we should end the loop */
            if (V2vTestCancelState(&vls->cs)) {
                printf("V2VAPP-LISTENER main processing loop ending for cancel event...\n"); 
                break;
            }
        }  
        else if (status == WAIT_OBJECT_0 + 1) {
            error = vls->rxFunction(vls);
            if (error != ERROR_SUCCESS)
                break;
        }        
        else if (status == WAIT_OBJECT_0 + 2) {
            state = v2v_get_remote_state(vls->channel);
            printf("V2VAPP-LISTENER state changed for other end - new state: %s\n", 
                    v2v_endpoint_state_name(state));
            if (v2v_state_requests_disconnect(state)) {
                printf("V2VAPP-LISTENER main processing loop ending for disconnect request...\n"); 
                break;
            }
        }
        else if (status == WAIT_OBJECT_0 + 3) {
            error = vls->txFunction(vls);
            if ((error != ERROR_SUCCESS)&&(error != ERROR_RETRY))
                break;
        }
        else {
            /* sno */
            printf("V2VAPP-LISTENER wait critical failure; unexpected wait value - exiting.\n");
            exit(-1);
        }
    } while (TRUE);
}

static void
V2vListenerDisconnect(V2V_LISTENER_STATE *vls)
{
    ULONG i = 0;
    struct _V2V_LISTENER_RESP_ITEM *resp;

    printf("V2VAPP-LISTENER Disconnecting...\n");
    v2v_disconnect(vls->channel);
    printf("V2VAPP-LISTENER Disconnected.\n");

    printf("V2VAPP-LISTENER Received message counter: %d\n", vls->rxCounter);
    printf("V2VAPP-LISTENER Sent response counter: %d\n", vls->txCounter);
    if (vls->txCounter != vls->rxCounter)
        printf("V2VAPP-CONNECTOR WARNING Receive count does not match the response count\n", i);

    if (vls->vac->xfer == XferTypeInternal) {
        while (vls->u.xferInternal.respList) {
            resp = vls->u.xferInternal.respList;
            vls->u.xferInternal.respList = resp->next;
            free(resp);
            i++;
        }
        if (i > 0)
            printf("V2VAPP-LISTENER WARNING Found %d unsent responses\n", i);
    }
}

static void
V2vListenerCleanup(V2V_LISTENER_STATE *vls)
{
    if ((vls->vac->xfer == XferTypeFile)&&(vls->u.xferFile.fh))
        fclose(vls->u.xferFile.fh);
    V2vFreeCancelState(&vls->cs);
    free(vls);
}

static void
V2vRunUserModeListener(V2V_APP_CONFIG *vac)
{
    V2V_LISTENER_STATE *vls = NULL;
    ULONG error;

    printf("V2VAPP-LISTENER starting for transfer type: %s\n", (vac->xfer == XferTypeInternal) ? "Internal" : "File");

    vls = (V2V_LISTENER_STATE*)malloc(sizeof(V2V_LISTENER_STATE));
    if (vls == NULL) {
        printf("V2VAPP-LISTENER out of memory\n");
        return;
    }
    memset(vls, 0, sizeof(V2V_LISTENER_STATE));
    vls->vac = vac;

    if (!V2vInitCancelState(&vls->cs, vac->localPrefix)) {
        printf("V2VAPP-CONNECTOR failed to init cancel state\n");
        V2vListenerCleanup(vls);
        return;
    }

    if (vac->xfer == XferTypeFile) {
        /* First open the file to write */
        vls->u.xferFile.fh = fopen(vls->vac->xferFilePath, "wb");
        if (!vls->u.xferFile.fh) {
            printf("V2VAPP-LISTENER failed to open file %s; aborting - errno: %d\n", vls->vac->xferFilePath, errno);
            V2vListenerCleanup(vls);
            return;
        }
        vls->rxFunction = V2vListenerProcessFileRx;
        vls->txFunction = V2vListenerProcessFileTx;
    }
    else {
        vls->rxFunction = V2vListenerProcessInternalRx;
        vls->txFunction = V2vListenerProcessInternalTx;
    }

    if (!V2vInputSanityCheck(vls->vac)) {
        V2vListenerCleanup(vls);
        return;
    }

    error = V2vListenAccept(vls);
    if (error != ERROR_SUCCESS) {
        V2vListenerCleanup(vls);
        return;
    }

    /* This runs the main processing loop, when it is done we disconnect
       and cleanup regardless of what may have occured */
    V2vListenerProcessMessages(vls);  

    V2vListenerDisconnect(vls);

    V2vListenerCleanup(vls);
}

/*************************** MAIN ****************************/
void
V2vRunUserMode(V2V_APP_CONFIG *vac)
{
    /* TODO enhancements:
       - console input control
       - like local shutdown of connector/listner at any point
       - keep app running and start another round.
    */
    if (vac->role == RoleTypeConnector)
        V2vRunUserModeConnector(vac);
    else
        V2vRunUserModeListener(vac);
}
