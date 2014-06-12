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

#include <windows.h>
#pragma warning(push)
#pragma warning(disable: 4201)
#include <winioctl.h>
#pragma warning(pop)
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include <sys/stat.h>
#include <assert.h>
#include <rpc.h>
#include "v4v_common.h"
#include "v4vapi.h"
#include "v4vapp.h"

#define V4V_MESSAGE_FTYPE_DATA       0x11
#define V4V_MESSAGE_FTYPE_ACK        0x22

#define V4V_MESSAGE_STATUS_OK        0
#define V4V_MESSAGE_STATUS_EOF       1
#define V4V_MESSAGE_STATUS_MORE      2
#define V4V_MESSAGE_STATUS_BADCS     0xFFFFF100
#define V4V_MESSAGE_STATUS_BADSEQ    0xFFFFF101
#define V4V_MESSAGE_STATUS_NODATA    0xFFFFF102
#define V4V_MESSAGE_STATUS_WRITE_ERR 0xFFFFF103
#define V4V_MESSAGE_STATUS_BADLEN    0xFFFFF103

#pragma pack(push, 1)
typedef struct _V4V_DFILE_HEADER {  
    UCHAR   type;
    UCHAR   cs;
    USHORT  pad1;
    ULONG32 length; 
    ULONG32 offset;
    ULONG32 status;
    ULONG32 seqnum;
    ULONG32 pad2;
    // file data starts here
} V4V_DFILE_HEADER, *PV4V_DFILE_HEADER;
#pragma pack(pop)

#define V4V_DFILE_HEADERS_SIZE (sizeof(V4V_DATAGRAM) + sizeof(V4V_DFILE_HEADER))
#define V4V_DFILE_MIN_DATA_SIZE (128)
#define V4V_DFILE_MIN_BUFFER_SIZE (V4V_DFILE_HEADERS_SIZE + V4V_DFILE_MIN_DATA_SIZE)

static BOOL
V4vDatagramSenderPrepareSend(V4V_CONFIG *cfg, ULONG *toSend)
{
    ULONG remainder, send;
    BOOL last = FALSE;
    V4V_DFILE_HEADER *header;
    UCHAR *p;
    int ret;

    *toSend = 0;
    
    remainder = cfg->r.dfile.finfo.st_size - cfg->r.dfile.offset;
    send = cfg->r.dfile.dataSize;
    if (send >= remainder) {
        send = remainder;
        last = TRUE;
    }

    // Dgram header already formatted for send, format the file header
    header = (V4V_DFILE_HEADER*)(cfg->txBuf + sizeof(V4V_DATAGRAM));
    header->type = V4V_MESSAGE_FTYPE_DATA;
    header->cs = 0;
    header->length = send + sizeof(V4V_DFILE_HEADER);
    header->status = (last ? V4V_MESSAGE_STATUS_EOF : V4V_MESSAGE_STATUS_MORE);
    header->seqnum = cfg->r.dfile.seqnum;
    p = cfg->txBuf + V4V_DFILE_HEADERS_SIZE;

    // Read the file data
    ret = fseek(cfg->r.dfile.fh, cfg->r.dfile.offset, SEEK_SET);
    if (ret) {
        printf("V4VDF failed to seek file; aborting - errno: %d\n", errno);
        return FALSE;
    }
    ret = (int)fread((void*)p, send, 1, cfg->r.dfile.fh);
    if (ret < (int)send) {
        if (ferror(cfg->r.dfile.fh) != 0) {
            printf("V4VDF failed to read file; aborting - errno: %d\n", errno);
            return FALSE;
        }
        else if (ret == 0) {
            // EOF, exit
            printf("V4VDF EOF received.\n");
            return FALSE;
        }
        // Else it is just the last chunk - we will get EOF next time
    }

    header->cs = V4vChecksum((const UCHAR*)header, send + sizeof(V4V_DFILE_HEADER));

    // The total send length is the file data, the file header, and the dgram header
    *toSend = send + sizeof(V4V_DFILE_HEADER) + sizeof(V4V_DATAGRAM);

    printf("V4VDF sent file data sending=%d seqnum=%d done=%d\n", *toSend, cfg->r.dfile.seqnum, cfg->r.dfile.done);

    // Update for next file chunk to send
    if (!last) {
        cfg->r.dfile.offset += send;
        cfg->r.dfile.seqnum++;
    }
    else
        cfg->r.dfile.done = TRUE;    

    return TRUE;
}

static BOOL
V4vDatagramReceiverPrepareSend(V4V_CONFIG *cfg, ULONG *toSend)
{
    V4V_DFILE_HEADER *header;

    assert(cfg->r.dfile.ack);
    *toSend = sizeof(V4V_DFILE_HEADER) + sizeof(V4V_DATAGRAM);

    // Dgram header already formatted for send, format the file header
    header = (V4V_DFILE_HEADER*)(cfg->txBuf + sizeof(V4V_DATAGRAM));
    header->type = V4V_MESSAGE_FTYPE_ACK;
    header->cs = 0;
    header->length = sizeof(V4V_DFILE_HEADER);
    header->status = cfg->r.dfile.status;
    header->seqnum = cfg->r.dfile.seqnum;
    header->cs = V4vChecksum((const UCHAR*)header, sizeof(V4V_DFILE_HEADER));
    
    return TRUE;
}

static BOOL
V4vDatagramSenderProcessRecv(V4V_CONFIG *cfg, ULONG recv)
{
    UCHAR sum;
    V4V_DFILE_HEADER *header;

    header = (V4V_DFILE_HEADER*)(cfg->rxBuf + sizeof(V4V_DATAGRAM));
    
    // Test the response, any failure then abort. The listener should be acking the most recent seqnum.
    if ((header->length + sizeof(V4V_DATAGRAM)) != recv) {
        printf("V4VDF data receive length: %d does not match what was read: %d\n",
               (header->length + sizeof(V4V_DATAGRAM)), recv);
        return FALSE;
    }
    sum = V4vChecksum((const UCHAR*)header, sizeof(V4V_DFILE_HEADER));
    if (sum != 0) {
        printf("V4VDF bad checksumm file response - seqnum: %d\n", header->seqnum);
        return FALSE;
    }
    if (header->status != V4V_MESSAGE_STATUS_OK) {
        printf("V4VDF failure status number in file response - seqnum: %d status: 0x%x\n",
                header->seqnum, header->status);
        return FALSE;
    }
    if ((header->seqnum != cfg->r.dfile.seqnum - 1)||(header->seqnum != cfg->r.dfile.seqrx)) {
        printf("V4VDF invalid sequence number in file response - seqnum: %d\n", header->seqnum);
        return FALSE;
    }

    // Else move the seqrx tracker forward - it should now match the seqnum which indicats we should send 
    cfg->r.dfile.seqrx++;
    assert(cfg->r.dfile.seqnum == cfg->r.dfile.seqrx);

    return TRUE;
}

static BOOL
V4vDatagramReceiverProcessRecv(V4V_CONFIG *cfg, ULONG recv)
{
    size_t write, written;
    UCHAR sum;
    V4V_DFILE_HEADER *header;
    UCHAR *p;    
    
    header = (V4V_DFILE_HEADER*)(cfg->rxBuf + sizeof(V4V_DATAGRAM));
    
    // Check payload and seqnums, return failure status to connector if anything is wrong
    do {
        if ((header->length + sizeof(V4V_DATAGRAM)) != recv) {
            printf("V4VDF data receive length: %d does not match what was read: %d\n",
                   (header->length + sizeof(V4V_DATAGRAM)), recv);
            cfg->r.dfile.status = V4V_MESSAGE_STATUS_BADLEN;
            break;
        }
        sum = V4vChecksum((const UCHAR*)header, header->length);
        if (sum != 0) {
            printf("V4VDF bad checksumm on file data message - seqnum %d!!!\n", cfg->r.dfile.seqnum);
            cfg->r.dfile.status = V4V_MESSAGE_STATUS_BADCS;
            break;
        }
        if ((cfg->r.dfile.seqnum + 1) != header->seqnum) {
            printf("V4VDF invalid sequence number in file data seqnum: %d expecting: %d\n",
                   header->seqnum, cfg->r.dfile.seqnum + 1);
            cfg->r.dfile.status = V4V_MESSAGE_STATUS_BADSEQ;
            break;
        }
        write = header->length - sizeof(V4V_DFILE_HEADER);
        if (write == 0) {
            printf("V4VDF no file data in message - seqnum %d!!!\n", cfg->r.dfile.seqnum);
            cfg->r.dfile.status = V4V_MESSAGE_STATUS_NODATA;
            break;
        }
        p = (UCHAR*)header + sizeof(V4V_DFILE_HEADER);
        written = fwrite(p, write, 1, cfg->r.dfile.fh);
        if (written != 1) {
            printf("V4VDF failed to write file data in - seqnum %d - errno: %d\n",
                   cfg->r.dfile.seqnum, errno);
            cfg->r.dfile.status = V4V_MESSAGE_STATUS_WRITE_ERR;
            break;
        }
        cfg->r.dfile.status = V4V_MESSAGE_STATUS_OK;
    } while (FALSE);

    // Finish setting up ack, for failure statuses the ack will cause the other end to disconnect
    // and the receiver will close down also
    cfg->r.dfile.ack = TRUE;
    cfg->r.dfile.seqnum++;

    return TRUE;
}

#define V4V_IS_SENDER(c)    (c->role == RoleTypeSender)
#define V4V_IS_RECEIVER(c)  (c->role == RoleTypeReceiver)
#define V4V_ROLE_STR(c)     (V4V_IS_SENDER(cfg) ? "sender" : "receiver")
#define V4V_TXIDX           0
#define V4V_RXIDX           1
#define V4V_RESET_AFLAGS(a)    { a[V4V_TXIDX] = FALSE; a[V4V_RXIDX] = FALSE; }

static DWORD WINAPI
V4vRunDatagramFileProcessor(VOID *ctx)
{
    V4V_CONFIG *cfg = (V4V_CONFIG*)ctx;
    HANDLE harr[4];
    DWORD status, error;
    V4V_DATAGRAM *dg;
    ULONG send = 0, sent = 0, recv = 0;
    BOOL rc;
    OVERLAPPED ovs[2] = {{0}, {0}};
    BOOLEAN    afs[2] = {FALSE, FALSE};

    printf("V4VDF START datagram file %s thread...\n", V4V_ROLE_STR(c));

    harr[V4V_TXIDX] = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (harr[V4V_TXIDX] == NULL) {
        printf("V4VDF failed to create overlapped send event - error: %d\n", GetLastError());       
        return 0xfffffffe;
    }
    harr[V4V_RXIDX] = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (harr[V4V_RXIDX] == NULL) {
        CloseHandle(harr[V4V_TXIDX]);
        printf("V4VDF failed to create overlapped read event - error: %d\n", GetLastError());       
        return 0xfffffffd;
    }
    harr[2] = cfg->v4vctx.recvEvent;
    harr[3] = cfg->shutdownEvent1;

    dg = (V4V_DATAGRAM*)cfg->txBuf;
    dg->addr.domain = cfg->dst.domain;
    dg->addr.port = cfg->dst.port;

    if (V4V_IS_SENDER(cfg)) {
        // Start by sending the first chunk
        SetEvent(harr[V4V_TXIDX]);
    }
    else {
        // Start by waiting to read the first chunk
        SetEvent(harr[V4V_RXIDX]);
    }

    do {
        if (cfg->r.dfile.done) {
            printf("V4VDF file transfer done, breaking out.\n");
            break;
        }

        status = WaitForMultipleObjects(4, harr, FALSE, INFINITE);
        if (status == WAIT_FAILED) {
            printf("V4VDF async wait failure; abort processing - error: %d\n", GetLastError());
            break;
        }
        else if (status == WAIT_OBJECT_0) {
            if (afs[V4V_TXIDX]) {
                if (!HasOverlappedIoCompleted(&ovs[V4V_TXIDX])) {
                    printf("V4VDF async write completions signaled but HasOverlappedIoCompleted reports otherwise????; aborting\n");
                    break;
                }
                if (!GetOverlappedResult(cfg->v4vctx.v4vHandle, &ovs[V4V_TXIDX], &sent, FALSE)) {
                    printf("V4VDF GetOverlappedResult() for write failed with error: %d\n", GetLastError());
                }
                if (send != sent) {
                    printf("V4VDF WARNING send %d less than sent %d\n", send, sent);    
                }

                // Sender: wake up reader for ACK
                // Receiver: wake up reader for next chunk
                V4V_RESET_AFLAGS(afs);
                SetEvent(harr[V4V_RXIDX]);
            }

            if (V4V_IS_SENDER(cfg)) {
                if (!V4vDatagramSenderPrepareSend(cfg, &send))
                    break;
            }
            else {
                if (!V4vDatagramReceiverPrepareSend(cfg, &send))
                    break;
            }            

            V4V_RESET_OVERLAPPED(&ovs[V4V_TXIDX], harr[V4V_TXIDX]);
            rc = WriteFile(cfg->v4vctx.v4vHandle, cfg->txBuf, send, &sent, &ovs[V4V_TXIDX]);
            if (!rc) {
                error = GetLastError();
                if (error != ERROR_IO_PENDING) {
                    printf("V4VDF WriteFile() failure - error: %d\n", error);
                    break;
                }
                afs[V4V_TXIDX] = TRUE;
            }
            else {
                printf("V4VDF WriteFile() completed synchronously\n");
                if (send != sent) {
                    printf("V4VDF WARNING send %d less than sent %d\n", send, sent);
                }

                // Sender: wake up reader for ACK
                // Receiver: wake up reader for next chunk
                V4V_RESET_AFLAGS(afs);
                SetEvent(harr[V4V_RXIDX]);
            }
        }
        else if (status == WAIT_OBJECT_0 + 1) {
            if (afs[V4V_RXIDX]) {
                if (!HasOverlappedIoCompleted(&ovs[V4V_RXIDX])) {
                    printf("V4VDF async read completions signaled but HasOverlappedIoCompleted reports otherwise????; aborting\n");
                    break;
                }
                if (!GetOverlappedResult(cfg->v4vctx.v4vHandle, &ovs[V4V_RXIDX], &recv, FALSE)) {
                    printf("V4VDF GetOverlappedResult() for read failed with error: %d\n", GetLastError());                    
                }

                if (V4V_IS_SENDER(cfg)) {
                    if (!V4vDatagramSenderProcessRecv(cfg, recv))
                        break;
                }
                else {
                    if (!V4vDatagramReceiverProcessRecv(cfg, recv))
                        break;
                }

                // Sender: ACK processed, wake up send for next chunk.
                // Receiver: file data processed, wake up send for next ACK.
                V4V_RESET_AFLAGS(afs);
                SetEvent(harr[V4V_TXIDX]);
            }

            V4V_RESET_OVERLAPPED(&ovs[V4V_RXIDX], harr[V4V_RXIDX]);
            rc = ReadFile(cfg->v4vctx.v4vHandle, cfg->rxBuf, cfg->rxSize, &recv, &ovs[V4V_RXIDX]);
            if (!rc) {
                error = GetLastError();
                if (error != ERROR_IO_PENDING) {
                    printf("V4VDF WriteFile() ReadFile - error: %d\n", error);
                    break;
                }
                afs[V4V_RXIDX] = TRUE;
            }
            else {
                if (V4V_IS_SENDER(cfg)) {
                    if (!V4vDatagramSenderProcessRecv(cfg, recv))
                        break;
                }
                else {
                    if (!V4vDatagramReceiverProcessRecv(cfg, recv))
                        break;
                }

                // Sender: ACK processed, wake up send for next chunk.
                // Receiver: file data processed, wake up send for next ACK.
                V4V_RESET_AFLAGS(afs);
                SetEvent(harr[V4V_TXIDX]);
            }
        }
        else if (status == WAIT_OBJECT_0 + 2) {
            printf("V4VDF data arrival event signaled\n");
        }
        else if (status == WAIT_OBJECT_0 + 3) {
            printf("V4VDF shutdown signaled, exiting\n");
            break;
        }
        else {
            printf("V4VDF send critical failure - unexpected wait value; exiting.\n");
            exit(-1);
        }
    } while (TRUE);

    V4vCancelIoEx(cfg, cfg->v4vctx.v4vHandle, NULL);
    CloseHandle(harr[V4V_RXIDX]);
    CloseHandle(harr[V4V_TXIDX]);

    printf("V4VDF datagram file %s thread exit\n", V4V_ROLE_STR(c));

    return 0;
}

VOID
V4vStartDatagramFile(V4V_CONFIG *cfg)
{
    BOOL rc;
    v4v_ring_id_t id;
    HANDLE ht = NULL;
    char buf[256];
    int ret;
    HANDLE ev = NULL;
    OVERLAPPED ov;
    DWORD status, bytes;

    if ((cfg->txSize < V4V_DFILE_MIN_BUFFER_SIZE)||(cfg->rxSize < V4V_DFILE_MIN_BUFFER_SIZE)) {
        printf("V4VDF transmit/receive size too small for datagram file transfer - tx: %d rx: %d needed: %d\n",
               cfg->txSize, cfg->rxSize, V4V_DFILE_MIN_BUFFER_SIZE);
        return;
    }

    // Set some values and open the file
    if (cfg->role == RoleTypeSender) {
        cfg->r.dfile.dataSize = cfg->txSize - V4V_DFILE_HEADERS_SIZE;
        // First open the file to send and get some information about it 
        cfg->r.dfile.fh = fopen(cfg->xferFilePath, "rb");
        if (cfg->r.dfile.fh == NULL) {
            printf("V4VDF failed to open file %s for sending; aborting - errno: %d\n", cfg->xferFilePath, errno);
            return;
        }
        ret = _stat(cfg->xferFilePath, &cfg->r.dfile.finfo);
        if (ret) {
            printf("V4VDFR failed to get file information %s; aborting - errno: %d\n", cfg->xferFilePath, errno);
            fclose(cfg->r.dfile.fh);
            return;
        }
        cfg->r.dfile.seqnum = 1;
        cfg->r.dfile.seqrx = 1;        
    }
    else {
        cfg->r.dfile.dataSize = cfg->rxSize - V4V_DFILE_HEADERS_SIZE;
        // First open the file to write
        cfg->r.dfile.fh = fopen(cfg->xferFilePath, "wb");
        if (cfg->r.dfile.fh == NULL) {
            printf("V4VDFR failed to open file %s for receiving; aborting - errno: %d\n", cfg->xferFilePath, errno);
            return;
        }
        cfg->r.dfile.seqnum = 0;
        cfg->r.dfile.seqrx = 0;
    }
    cfg->r.dfile.done = FALSE;
    cfg->r.dfile.ack = FALSE;
    cfg->r.dfile.status = V4V_MESSAGE_STATUS_OK;

    cfg->v4vctx.flags = V4V_FLAG_OVERLAPPED;
    ev = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (ev == NULL) {
        printf("V4VDF failed to create overlapped open event - error: %d\n", GetLastError());
        fclose(cfg->r.dfile.fh);
        return;
    }
    V4V_RESET_OVERLAPPED(&ov, ev);

    printf("V4VDF starting datagram test - running in async mode only\n");

    do {
        rc = V4vOpen(&cfg->v4vctx, cfg->ringSize, &ov);
        if (!rc) {
            printf("V4VDF V4vOpen() failed error: %d\n", GetLastError());
            break;
        }

        status = WaitForSingleObject(ev, INFINITE);
        if (status != WAIT_OBJECT_0) {
            printf("V4VDF V4vOpen() wait warning, unexpected status: %d\n", status);
        }

        if (!GetOverlappedResult(cfg->v4vctx.v4vHandle, &ov, &bytes, FALSE)) {
            printf("V4VDF GetOverlappedResult() for open failed with error: %d\n", GetLastError());
            break;
        }
        V4V_RESET_OVERLAPPED(&ov, ev);

        assert(cfg->v4vctx.v4vHandle != NULL);
        assert(cfg->v4vctx.v4vHandle != INVALID_HANDLE_VALUE);
        assert(cfg->v4vctx.recvEvent != NULL);

        id.partner = cfg->dst.domain;
        id.addr.domain = V4V_DOMID_NONE;
        id.addr.port = cfg->src.port;

        rc = V4vBind(&cfg->v4vctx, &id, &ov);
        if (!rc) {
            printf("V4VDF V4vBind() failed error: %d\n", GetLastError());
            break;
        }

        status = WaitForSingleObject(ev, INFINITE);
        if (status != WAIT_OBJECT_0) {
            printf("V4VDF V4vBind() wait warning, unexpected status: %d\n", status);
        }

        if (!GetOverlappedResult(cfg->v4vctx.v4vHandle, &ov, &bytes, FALSE)) {
            printf("V4VDF GetOverlappedResult() for bind failed with error: %d\n", GetLastError());
            break;
        }
        CloseHandle(ev);
        ev = NULL;

        if (cfg->connectOnly) {
            printf("V4VDF Connect only test not supported, ignorning..\n");
        }

        ht = CreateThread(NULL, 0,
                          V4vRunDatagramFileProcessor,
                          cfg, 0, NULL);
        if (ht == NULL) {
            printf("V4VDF create thread failed error: %d\n", GetLastError());
            break;
        }
    
        printf("Starting datagram file processing...\n");
        printf("Type \'q\' to quit.\n");
        
        while (TRUE) {
            scanf("%s", buf);
            if (_stricmp(buf, "q") == 0) {
                printf("Stopping datagram file processing...\n");
                V4vCancelIoEx(cfg, cfg->v4vctx.v4vHandle, NULL);
                SetEvent(cfg->shutdownEvent1);
                WaitForSingleObject(ht, INFINITE);
                break;
            }
        }

    } while (FALSE);

    if (ev != NULL)
        CloseHandle(ev);

    if (ht != NULL)
        CloseHandle(ht);

    rc = V4vClose(&cfg->v4vctx);
    if (!rc)
        printf("V4VDF V4vClose() failed error: %d\n", GetLastError());

    fclose(cfg->r.dfile.fh);
}
