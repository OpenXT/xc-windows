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

#define V4V_MESSAGE_DATAGRAM        0xAA

#pragma pack(push, 1)
typedef struct _V4V_DATAGRAM_HEADER {
    USHORT id;
    UCHAR  type;
    UCHAR  cs;
    ULONG  length;
    GUID   guid;
} V4V_DATAGRAM_HEADER, *PV4V_DATAGRAM_HEADER;
#pragma pack(pop)

#define V4V_DATAGRAM_MIN_SIZE (sizeof(V4V_DATAGRAM) + sizeof(V4V_DATAGRAM_HEADER))

static VOID
V4vFormatDatagramSend(V4V_CONFIG *cfg)
{
    UCHAR *p;
    ULONG dlen;
    RPC_STATUS rpcstat;
    V4V_DATAGRAM *dg;
    V4V_DATAGRAM_HEADER *dgh;
    GUID *pguid;

    p = cfg->txBuf + sizeof(V4V_DATAGRAM);
    dlen = cfg->txSize - sizeof(V4V_DATAGRAM);    
    dgh = (V4V_DATAGRAM_HEADER*)p;
    dgh->id = cfg->r.dgram.counter++;
    dgh->type = V4V_MESSAGE_DATAGRAM;
    dgh->cs = 0;
    dgh->length = dlen;
    rpcstat = UuidCreate(&dgh->guid);
    if (rpcstat != RPC_S_OK) {
        printf("V4VDG UuidCreate() failed - error: 0x%x; using Y GUID\n", rpcstat);
        memset((VOID*)(&dgh->guid), 'Y', sizeof(GUID));
    }
    p += sizeof(V4V_DATAGRAM_HEADER);
    dlen -= sizeof(V4V_DATAGRAM_HEADER);
    memset(p, 'X', dlen);
    dgh->cs = V4vChecksum((const UCHAR*)dgh, dgh->length);

    dg = (V4V_DATAGRAM*)cfg->txBuf;
    printf("V4VDG +++SENDING+++ to: %d port: %d id: %d length: %d (0x%x)\n",
           dg->addr.domain, dg->addr.port, dgh->id, dgh->length, dgh->length);
    pguid = &dgh->guid;
    printf("------ GUID={%8.8x-%4.4x-%4.4x-%2.2x%2.2x-%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x}\n",
           pguid->Data1, pguid->Data2, pguid->Data3, pguid->Data4[0], pguid->Data4[1], pguid->Data4[2],
           pguid->Data4[3], pguid->Data4[4], pguid->Data4[5], pguid->Data4[6], pguid->Data4[7]);
    printf("V4VDG +++SENDING+++ END\n");
}

static VOID
V4vValidateDatagramRecv(V4V_CONFIG *cfg, ULONG recv)
{
    UCHAR *p;
    V4V_DATAGRAM *dg;
    V4V_DATAGRAM_HEADER *dgh;
    GUID *pguid;
    UCHAR sum;

    if (recv < V4V_DATAGRAM_MIN_SIZE) {
        printf("V4VDG ERROR recv size %d less than needed for headers!\n", recv);
        return;
    }
    dg = (V4V_DATAGRAM*)cfg->rxBuf;
    p = cfg->rxBuf + sizeof(V4V_DATAGRAM);
    dgh = (V4V_DATAGRAM_HEADER*)p;
    printf("V4VDG +++RECEIVED+++ to: %d port: %d id: %d length: %d (0x%x)\n",
           dg->addr.domain, dg->addr.port, dgh->id, dgh->length, dgh->length);
    if (dgh->type != V4V_MESSAGE_DATAGRAM)
        printf("V4VDG ERROR invalid type: %d\n", dgh->type);
    if (recv != (dgh->length + sizeof(V4V_DATAGRAM)))
        printf("V4VDG ERROR reveive length %d (0x%x) does not match reported length\n", recv, recv);
    pguid = &dgh->guid;
    printf("------ GUID={%8.8x-%4.4x-%4.4x-%2.2x%2.2x-%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x}\n",
           pguid->Data1, pguid->Data2, pguid->Data3, pguid->Data4[0], pguid->Data4[1], pguid->Data4[2],
           pguid->Data4[3], pguid->Data4[4], pguid->Data4[5], pguid->Data4[6], pguid->Data4[7]);
    sum = V4vChecksum((const UCHAR*)dgh, dgh->length);
    if (sum != 0)
        printf("V4VDG ERROR bad checksumm on message\n");
    printf("V4VDG +++RECEIVED+++ END\n");
}

static DWORD WINAPI
V4vRunAsyncDatagram(VOID *ctx)
{
    V4V_CONFIG *cfg = (V4V_CONFIG*)ctx;
    HANDLE harr[4];
    DWORD status, error;
    V4V_DATAGRAM *dg;
    ULONG sent = 0, recv = 0;
    BOOL rc;
    OVERLAPPED ovw = {0}, ovr = {0};
    BOOLEAN asw = FALSE, asr = FALSE;

    printf("V4VDG START asynchronous datagram thread...\n");

    harr[0] = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (harr[0] == NULL) {
        printf("V4VDG failed to create overlapped send event - error: %d\n", GetLastError());       
        return 0xfffffffe;
    }
    harr[1] = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (harr[1] == NULL) {
        CloseHandle(harr[0]);
        printf("V4VDG failed to create overlapped read event - error: %d\n", GetLastError());       
        return 0xfffffffd;
    }
    harr[2] = cfg->v4vctx.recvEvent;
    harr[3] = cfg->shutdownEvent1;

    dg = (V4V_DATAGRAM*)cfg->txBuf;
    dg->addr.domain = cfg->dst.domain;
    dg->addr.port = cfg->dst.port;

    SetEvent(harr[0]);
    SetEvent(harr[1]);

    do {
        status = WaitForMultipleObjects(4, harr, FALSE, INFINITE);
        if (status == WAIT_FAILED) {
            printf("V4VDG async wait failure; abort processing - error: %d\n", GetLastError());
            break;
        }
        else if (status == WAIT_OBJECT_0) {
            if (asw) {
                if (!HasOverlappedIoCompleted(&ovw)) {
                    printf("V4VDG async write completions signaled but HasOverlappedIoCompleted reports otherwise????; aborting\n");
                    break;
                }
                if (!GetOverlappedResult(cfg->v4vctx.v4vHandle, &ovw, &sent, FALSE)) {
                    printf("V4VDG GetOverlappedResult() for write failed with error: %d\n", GetLastError());
                }
                if (cfg->txSize != sent)
                    printf("V4VDG WARNING send %d less than sent %d\n", cfg->txSize, sent);
            }
            
            V4vFormatDatagramSend(cfg);
            V4V_RESET_OVERLAPPED(&ovw, harr[0]);
            rc = WriteFile(cfg->v4vctx.v4vHandle, cfg->txBuf, cfg->txSize, &sent, &ovw);
            if (!rc) {
                error = GetLastError();
                if (error != ERROR_IO_PENDING) {
                    printf("V4VDG WriteFile() failure - error: %d\n", error);
                }
                asw = TRUE;
            }
            else {
                printf("V4VDG WriteFile() completed synchronously\n");
                if (cfg->txSize != sent)
                    printf("V4VDG WARNING send %d less than sent %d\n", cfg->txSize, sent);
                asw = FALSE;
                SetEvent(harr[0]);
            }
        }
        else if (status == WAIT_OBJECT_0 + 1) {
            if (asr) {
                if (!HasOverlappedIoCompleted(&ovr)) {
                    printf("V4VDG async read completions signaled but HasOverlappedIoCompleted reports otherwise????; aborting\n");
                    break;
                }
                if (!GetOverlappedResult(cfg->v4vctx.v4vHandle, &ovr, &recv, FALSE)) {
                    printf("V4VDG GetOverlappedResult() for read failed with error: %d\n", GetLastError());                    
                }
                V4vValidateDatagramRecv(cfg, recv);
            }

            V4V_RESET_OVERLAPPED(&ovr, harr[1]);
            rc = ReadFile(cfg->v4vctx.v4vHandle, cfg->rxBuf, cfg->rxSize, &recv, &ovr);
            if (!rc) {
                error = GetLastError();
                if (error != ERROR_IO_PENDING) {
                    printf("V4VDG WriteFile() ReadFile - error: %d\n", error);
                }
                asr = TRUE;
            }
            else {
                printf("V4VDG ReadFile() completed synchronously\n");
                V4vValidateDatagramRecv(cfg, recv);
                asr = FALSE;
                SetEvent(harr[1]);
            }
        }
        else if (status == WAIT_OBJECT_0 + 2) {
            printf("V4VDG data arrival event signaled\n"); 
        }
        else if (status == WAIT_OBJECT_0 + 3) {
            printf("V4VDG shutdown signaled, exiting\n");
            break;
        }
        else {
            printf("V4VDG async critical failure - unexpected wait value; exiting.\n");
            exit(-1);
        }
    } while (TRUE);

    V4vCancelIoEx(cfg, cfg->v4vctx.v4vHandle, NULL);
    CloseHandle(harr[1]);
    CloseHandle(harr[0]);

    printf("V4VDG asynchronous datagram thread exit.\n");

    return 0;
}

static DWORD WINAPI
V4vRunSyncDatagramSends(VOID *ctx)
{
    V4V_CONFIG *cfg = (V4V_CONFIG*)ctx;
    DWORD status;
    V4V_DATAGRAM *dg;
    ULONG sent = 0;
    BOOL rc;

    printf("V4VDG START synchronous datagram send thread...\n");

    dg = (V4V_DATAGRAM*)cfg->txBuf;
    dg->addr.domain = cfg->dst.domain;
    dg->addr.port = cfg->dst.port;

    V4vFormatDatagramSend(cfg);
    rc = WriteFile(cfg->v4vctx.v4vHandle, cfg->txBuf, cfg->txSize, &sent, NULL);
    if (!rc)
        printf("V4VDG initial WriteFile failure - error: %d\n", GetLastError());
    if (cfg->txSize != sent)
        printf("V4VDG WARNING send %d less than sent %d\n", cfg->txSize, sent);

    do {
        status = WaitForSingleObject(cfg->shutdownEvent2, cfg->xferTimeout);
        if (status == WAIT_FAILED) {
            printf("V4VDG send wait failure; abort processing - error: %d\n", GetLastError());
            break;
        }        
        else if (status == WAIT_OBJECT_0) {
            printf("V4VDG send shutdown signaled, exiting\n"); 
            break;
        }
        else if (status == WAIT_TIMEOUT) {
            V4vFormatDatagramSend(cfg);
            rc = WriteFile(cfg->v4vctx.v4vHandle, cfg->txBuf, cfg->txSize, &sent, NULL);
            if (!rc) {
                printf("V4VDG WriteFile failure - error: %d\n", GetLastError());
            }
            if (cfg->txSize != sent) {
                printf("V4VDG send %d less than sent %d\n", cfg->txSize, sent);
            }
        }
        else {
            printf("V4VDG send wait critical failure - unexpected wait value; exiting.\n");
            exit(-1);
        }
    } while (TRUE);

    return 0;
}

static DWORD WINAPI
V4vRunSyncDatagram(VOID *ctx)
{
    V4V_CONFIG *cfg = (V4V_CONFIG*)ctx;
    HANDLE harr[2];
    DWORD status;
    ULONG recv;
    BOOL rc;
    HANDLE ht;

    printf("V4VDG START synchronous datagram main thread...\n");

    harr[0] = cfg->v4vctx.recvEvent;
    harr[1] = cfg->shutdownEvent1;  

    ht = CreateThread(NULL, 0, V4vRunSyncDatagramSends, cfg, 0, NULL);
    if (ht == NULL) {
        printf("V4VDG create send thread failed error: %d; aborting\n", GetLastError());
        return 0xfffffffe;
    }

    do {
        status = WaitForMultipleObjects(2, harr, FALSE, INFINITE);
        if (status == WAIT_FAILED) {
            printf("V4VDG main wait failure; abort processing - error: %d\n", GetLastError());
            break;
        }
        else if (status == WAIT_OBJECT_0) {
            rc = ReadFile(cfg->v4vctx.v4vHandle, cfg->rxBuf, cfg->rxSize, &recv, NULL);
            if (rc)
                V4vValidateDatagramRecv(cfg, recv);
            else
                printf("V4VDG ReadFile failure - error: %d\n", GetLastError());
        }
        else if (status == WAIT_OBJECT_0 + 1) {
            printf("V4VDG main shutdown signaled, exit\n");
            V4vCancelSynchronousIo(cfg, ht);
            SetEvent(cfg->shutdownEvent2);
            break;
        }
        else {
            printf("V4VDG main wait critical failure - unexpected wait value; exiting.\n");
            exit(-1);
        }
    } while (TRUE);

    printf("V4VDG synchronous datagram wait for send thread...\n");
    WaitForSingleObject(ht, INFINITE);

    printf("V4VDG synchronous datagram main thread exit.\n");

    return 0;
}

VOID
V4vStartDatagram(V4V_CONFIG *cfg)
{
    BOOL rc;
    v4v_ring_id_t id;
    HANDLE ht = NULL;
    char buf[256];
    HANDLE ev = NULL;
    OVERLAPPED ov;
    DWORD status, bytes;

    if ((cfg->txSize < V4V_DATAGRAM_MIN_SIZE)||(cfg->rxSize < V4V_DATAGRAM_MIN_SIZE)) {
        printf("V4VDG transmit/receive size smaller for datagrams - tx: %d rx: %d needed: %d\n",
               cfg->txSize, cfg->rxSize, V4V_DATAGRAM_MIN_SIZE);
        return;
    }

    if (cfg->async) {
        cfg->v4vctx.flags = V4V_FLAG_OVERLAPPED;
        ev = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (ev == NULL) {
            printf("V4VDG failed to create overlapped open event - error: %d\n", GetLastError());       
            return;
        }
        V4V_RESET_OVERLAPPED(&ov, ev);
    }
    else {
        cfg->v4vctx.flags = V4V_FLAG_NONE;
    }

    printf("V4VDG starting datagram test - using async: %s\n", ((cfg->async) ?  "TRUE" : "FALSE"));

    do {
        rc = V4vOpen(&cfg->v4vctx, cfg->ringSize, ((cfg->async) ? &ov : NULL));
        if (!rc) {
            printf("V4VDG V4vOpen() failed error: %d\n", GetLastError());
            break;
        }

        if (cfg->async) {
            status = WaitForSingleObject(ev, INFINITE);
            if (status != WAIT_OBJECT_0) {
                printf("V4VDG V4vOpen() wait warning, unexpected status: %d\n", status);
            }

            if (!GetOverlappedResult(cfg->v4vctx.v4vHandle, &ov, &bytes, FALSE)) {
                printf("V4VDG GetOverlappedResult() for open failed with error: %d\n", GetLastError());
                break;
            }
            V4V_RESET_OVERLAPPED(&ov, ev);
        }

        assert(cfg->v4vctx.v4vHandle != NULL);
        assert(cfg->v4vctx.v4vHandle != INVALID_HANDLE_VALUE);
        assert(cfg->v4vctx.recvEvent != NULL);

        id.partner = cfg->dst.domain;
        id.addr.domain = V4V_DOMID_NONE;
        id.addr.port = cfg->src.port;

        rc = V4vBind(&cfg->v4vctx, &id, ((cfg->async) ? &ov : NULL));
        if (!rc) {
            printf("V4VDG V4vBind() failed error: %d\n", GetLastError());
            break;
        }

        if (cfg->async) {
            status = WaitForSingleObject(ev, INFINITE);
            if (status != WAIT_OBJECT_0) {
                printf("V4VDG V4vBind() wait warning, unexpected status: %d\n", status);
            }

            if (!GetOverlappedResult(cfg->v4vctx.v4vHandle, &ov, &bytes, FALSE)) {
                printf("V4VDG GetOverlappedResult() for bind failed with error: %d\n", GetLastError());
                break;
            }
            CloseHandle(ev);
            ev = NULL;
        }

        // For a datagram, this means just bind
        if (cfg->connectOnly) {
            printf("Connect only test...\n");
            printf("Type \'q\' to quit.\n");

            while (TRUE) {
                scanf("%s", buf);
                if (_stricmp(buf, "q") == 0) {
                    printf("Stopping connect test.\n");
                    break;
                }
            }
            break;
        }

        ht = CreateThread(NULL, 0,
                          (cfg->async) ? V4vRunAsyncDatagram : V4vRunSyncDatagram,
                          cfg, 0, NULL);
        if (ht == NULL) {
            printf("V4VDG create thread failed error: %d\n", GetLastError());
            break;
        }
    
        printf("Starting datagram processing...\n");
        printf("Type \'q\' to quit.\n");
        
        while (TRUE) {
            scanf("%s", buf);
            if (_stricmp(buf, "q") == 0) {
                printf("Stopping datagram processing...\n");
                if (cfg->async)
                    V4vCancelIoEx(cfg, cfg->v4vctx.v4vHandle, NULL);
                else
                    V4vCancelSynchronousIo(cfg, ht);
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
        printf("V4VDG V4vClose() failed error: %d\n", GetLastError());
}
