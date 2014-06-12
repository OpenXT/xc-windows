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
#include "v4v_common.h"
#include "v4vapi.h"
#include "v4vapp.h"

#define WM_V4V_QUIT    (WM_USER + 101)
#define WM_V4V_DUMP    (WM_USER + 102)
#define WM_V4V_NOTHING (WM_USER + 103)
#define WM_V4V_TEXT    (WM_USER + 104)

#define V4V_LCA_MAX_THREADS   128
#define V4V_LCA_INVALID_INDEX 0xffffffff
#define V4V_LCA_READBUF_SIZE  512

typedef struct _V4V_LCA_THREAD_INFO {
    HANDLE ht;
    DWORD  tid;
} V4V_LCA_THREAD_INFO;

typedef struct _V4V_LCA_THREAD_CONTEXT {
    V4V_CONTEXT ctx;
    V4V_LCA_THREAD_INFO ti;
} V4V_LCA_THREAD_CONTEXT;

static V4V_LCA_THREAD_INFO g_tlist[V4V_LCA_MAX_THREADS];
static HANDLE g_tlmutex = NULL;
static HANDLE g_lthread = NULL;
static DWORD g_ltid = 0;

static ULONG
V4vAddConnectedThread(V4V_LCA_THREAD_INFO *pti)
{
    ULONG i, index = V4V_LCA_INVALID_INDEX;

    (VOID)WaitForSingleObject(g_tlmutex, INFINITE);

    for (i = 0; i < V4V_LCA_MAX_THREADS; i++) {
        if (g_tlist[i].ht == NULL) {
            g_tlist[i].ht = pti->ht;
            g_tlist[i].tid = pti->tid;
            index = i + 1;
            break;
        }
    }

    (VOID)ReleaseMutex(g_tlmutex);

    return index;
}

static VOID
V4vRemoveConnectedThread(ULONG index)
{
    index--;
    (VOID)WaitForSingleObject(g_tlmutex, INFINITE);
    g_tlist[index].ht = NULL;
    g_tlist[index].tid = 0;
    (VOID)ReleaseMutex(g_tlmutex);
}

static BOOL
V4vLCAAccepterWrite(V4V_LCA_THREAD_CONTEXT *tctx, MSG *pmsg)
{
    static const char empty[] = "";
    BOOL rc = TRUE;
    ULONG val, error, len;
    const char *buf = (const char*)pmsg->lParam;

    if (pmsg->message != WM_V4V_NOTHING) {
        if (buf == NULL) {
            printf("V4VLCA accepter thread %p WriteFile() invalid data buffer!!!\n", tctx->ti.ht);
            return TRUE; // let the user try again
        }
        len = (ULONG)strlen(buf);
    }
    else {
        buf = empty;
        len = 0;
    }

    rc = WriteFile(tctx->ctx.v4vHandle, buf, len, &val, NULL);
    if (!rc) {
        error = GetLastError();
        if (error == ERROR_VC_DISCONNECTED) {
            printf("V4VLCA accepter thread %p WriteFile() returned ERROR_VC_DISCONNECTED - other side disconnected\n", tctx->ti.ht);
        }
        else {
            printf("V4VLCA accepter thread %p WriteFile() failed error: 0x%x\n", tctx->ti.ht, error);
        }
        return FALSE; // terminate accepter on disconnects or other errors
    }
    if (val != len) {
        printf("V4VLCA accepter thread %p write=%d not equal to written=%d\n", tctx->ti.ht, len, val);
        return FALSE; // terminate accepter on bad writes
    }

    return TRUE;
}

static DWORD WINAPI
V4vLCAAccepterThread(VOID *c)
{
    V4V_LCA_THREAD_CONTEXT *tctx = (V4V_LCA_THREAD_CONTEXT*)c;
    ULONG index, val, status, error;
    BOOL rc;
    MSG msg;
    UCHAR rbuf[V4V_LCA_READBUF_SIZE];

    // Put myself into the list
    index = V4vAddConnectedThread(&tctx->ti);
    if (index == V4V_LCA_INVALID_INDEX) {
        printf("V4VLCA accepter thread no more slots! Exiting\n");
        return 0xfffffffe;
    }

    printf("V4VLCA accepter connection started - index: %d thread: %p\n", index, tctx->ti.ht);

    while (1) {
        status = MsgWaitForMultipleObjects(1, &tctx->ctx.recvEvent, FALSE, INFINITE, QS_POSTMESSAGE);
        if (status == WAIT_OBJECT_0) {
            // Something is ready for us
            rc = ReadFile(tctx->ctx.v4vHandle, rbuf, V4V_LCA_READBUF_SIZE, &val, NULL);
            if (!rc) {
                error = GetLastError();
                if (error == ERROR_VC_DISCONNECTED) {
                    printf("V4VLCA accepter thread %p ReadFile() returned ERROR_VC_DISCONNECTED - other side disconnected\n", tctx->ti.ht);
                }
                else {
                    printf("V4VLCA accepter thread %p ReadFile() failed error: 0x%x\n", tctx->ti.ht, error);
                }
                break;
            }

            // Process it a bit
            rbuf[val] = '\0';
            printf("V4VLCA accepter thread %p received %d bytes of message\n", tctx->ti.ht, val);        
            printf("V4VLCA msg: %s\n", rbuf);
            if (_stricmp((const char*)rbuf, "resetme") == 0) {
                printf("V4VLCA accepter thread %p RST requested, breaking out and disconnecting\n", tctx->ti.ht);
                V4vDisconnect(&tctx->ctx, NULL);
                break;
            }
        }
        else if (status == (WAIT_OBJECT_0 + 1)) {
            // PeekMessage use hwnd == -1, forget about translate and dispatch - process it here.
            rc = PeekMessage(&msg, (HWND)-1, WM_V4V_QUIT, WM_V4V_TEXT, PM_REMOVE);
            if (!rc) {
                printf("V4VLCA accepter thread %p woken up but there is no message?\n", tctx->ti.ht);
                continue;
            }
            if (msg.message == WM_V4V_QUIT) {
                // Shutdown listener here and end thread
                printf("V4VLCA accepter thread %p at index: %d quiting\n", tctx->ti.ht, index);
                break;
            }
            else if (msg.message == WM_V4V_DUMP) {
                rc = V4vDumpRing(&tctx->ctx, NULL);
                if (!rc) {
                    printf("V4VLCA accepter thread %p V4vDumpRing() failed error: 0x%x\n", tctx->ti.ht, GetLastError());
                }
            }
            else if ((msg.message == WM_V4V_NOTHING)||(msg.message == WM_V4V_TEXT)) {
                if (!V4vLCAAccepterWrite(tctx, &msg)) {
                    break;
                }
            }
            else {
                printf("V4VLCA accepter thread %p invalid message ID %d\n", tctx->ti.ht, msg.message);
            }
        }
        else {
            printf("V4VLCA accepter thread %p unexpected wait value: 0x%x error: %d\n", tctx->ti.ht, status, GetLastError());
        }
    }

    // Remove myself from list
    V4vRemoveConnectedThread(index);

    // Close the connection and cleanup
    V4vClose(&tctx->ctx);
    free(tctx);
    return 0;
}

static DWORD WINAPI
V4vLCAListenerThread(VOID *c)
{
    V4V_CONTEXT *pctx = (V4V_CONTEXT*)c;
    V4V_LCA_THREAD_CONTEXT *tctx = NULL;
    V4V_ACCEPT_VALUES acc;
    BOOL rc;
    MSG msg;
    ULONG status;

    // Force thread to create message queue
    PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE);

    rc = V4vListen(pctx, V4V_SOMAXCONN, NULL);
    if (!rc) {
        printf("V4VLCA listener V4vListen() failed error: 0x%x\n", GetLastError());
        printf("V4VLCA listener thread exiting!\n");
        return 0xfffffffe;
    }

    while (1) {
        status = MsgWaitForMultipleObjects(1, &pctx->recvEvent, FALSE, INFINITE, QS_POSTMESSAGE);
        if (status == WAIT_OBJECT_0) {
            // Accept the connection and pass it off to a new thread for handling
            tctx = (V4V_LCA_THREAD_CONTEXT*)malloc(sizeof(V4V_LCA_THREAD_CONTEXT));
            if (tctx == NULL) {
                printf("V4VLCA listener thread out of memory for thread new context.\n");
                continue;
            }

            rc = V4vAccept(pctx, &tctx->ctx, &acc, NULL);
            if (!rc) {
                printf("V4VLCA listener thread V4vAccept() failed error: 0x%x\n", GetLastError());
                free(tctx);
                continue;
            }

            tctx->ti.ht = CreateThread(NULL, 0, V4vLCAAccepterThread, tctx, 0, &tctx->ti.tid);
            if (tctx->ti.ht == NULL) {
                printf("V4VLCA create accepter thread failed error: %d\n", GetLastError());
                V4vClose(&tctx->ctx);
                free(tctx);
            }
        }
        else if (status == (WAIT_OBJECT_0 + 1)) {
            // PeekMessage use hwnd == -1, forget about translate and dispatch - process it here.
            rc = PeekMessage(&msg, (HWND)-1, WM_V4V_QUIT, WM_V4V_DUMP, PM_REMOVE);
            if (!rc) {
                printf("V4VLCA listener thread woken up but there is no message?\n");
                continue;
            }
            if (msg.message == WM_V4V_QUIT) {
                // Shutdown listener here and end thread
                printf("V4VLCA listener thread quiting...\n");
                V4vClose(pctx);
                pctx->v4vHandle = NULL;
                pctx->recvEvent = NULL;
                break;
            }
            else if (msg.message == WM_V4V_DUMP) {
                rc = V4vDumpRing(pctx, NULL);
                if (!rc) {
                    printf("V4VLCA listener thread V4vDumpRing() failed error: 0x%x\n", GetLastError());
                }
            }
            else {
                printf("V4VLCA listener thread invalid message ID %d\n", msg.message);
            }
        }
        else {
            printf("V4VLCA listener thread unexpected wait value: 0x%x error: %d\n", status, GetLastError());
        }
    }

    return 0;
}

static char *
V4vParseInput(char *pb, ULONG *pidx)
{
    ULONG len, i;
    char *ptr = pb;

    if (pb == NULL) {
        return NULL;
    }

    len = (ULONG)strlen(pb);
    if (len < 3) {
        return NULL;
    }

    for (i = 0; i < len; i++, ptr++) {
        if (*ptr == ':') {
            if (ptr == pb) {
                return NULL;
            }
            if ((i + 1) == len) {
                return NULL;
            }
            *ptr = '\0';
            *pidx = (ULONG)strtol(pb, NULL, 10);
            return ++ptr;
        }
    }
    
    return NULL;
}

static VOID
V4vTraceConnectionIndices(VOID)
{
    ULONG i;

    (VOID)WaitForSingleObject(g_tlmutex, INFINITE);

    printf("V4VLCA list of valid connection indices in (1 - 128):\n");
    for (i = 0; i < V4V_LCA_MAX_THREADS; i++) {
        if (g_tlist[i].ht != NULL) {
            printf("%d ", i + 1);
        }
    }
    printf("\n");

    (VOID)ReleaseMutex(g_tlmutex);
}

static VOID
V4vLCARunListenAccept(USHORT partner, ULONG32 port)
{
    BOOL rc;
    V4V_CONTEXT ctx = {0};
    v4v_ring_id_t id;
    char buf[V4V_LCA_READBUF_SIZE];
    char *umsg;
    ULONG idx, len;
    HANDLE ht;
    DWORD tid;
    UINT mid;
    char *lp = 0;
    
    printf("V4VLCA char listener starting\n");

    memset(g_tlist, 0, sizeof(V4V_LCA_THREAD_INFO)*V4V_LCA_MAX_THREADS);    

    ctx.flags = V4V_FLAG_NONE;
    rc = V4vOpen(&ctx, 8192, NULL);
    if (!rc) {
        printf("V4VLCA listener V4vOpen() failed error: 0x%x\n", GetLastError());
        return;
    }

    g_tlmutex = CreateMutex(NULL, FALSE, NULL);
    if (g_tlmutex == NULL) {
        printf("V4VLCA listener CreateMutex error: %d\n", GetLastError());
        goto listdone;
    }    

    id.partner = partner;
    id.addr.domain = V4V_DOMID_NONE;
    id.addr.port = port;
    rc = V4vBind(&ctx, &id, NULL);
    if (!rc) {
        printf("V4VLCA listener V4vBind() failed error: 0x%x\n", GetLastError());
        goto listdone;
    }

    printf("V4VLCA local ring bound - begin listening\n");

    g_lthread = CreateThread(NULL, 0, V4vLCAListenerThread, &ctx, 0, &g_ltid);
    if (g_lthread == NULL) {
        printf("V4VLCA listener thread failed error: %d\n", GetLastError());
        goto listdone;
    }

    printf(" - type some characters then enter to send.\n");
    printf(" - prefix your string with a connection number to target a specific connetion.\n");
    printf(" - valid connections 1 - 128 for example: 5:testmessge\n");
    printf(" - type \"n:quit\" to disconnect (prefix 0 shuts down listener).\n");
    printf(" - type \"n:dump\" to dump the ring to debug output (prefix 0 dumps listener).\n");
    printf(" - type \"n:resetme\" to have the other end send a disconnect (prefix 0 invalid).\n");
    printf(" - type \"n:nothing\" to send an empty message (prefix 0 invalid).\n");
    printf(" - type \"0:indices\" to trace valid connection indices.\n");
    printf(" - type \"0:shutdown\" to shutdown the application.\n");

    while (1) {
        scanf("%s", buf);
        umsg = V4vParseInput(buf, &idx);

        if (umsg == NULL) {
            printf("invalid input - use a valid prefix and try again...\n");
            continue;
        }

        if ((idx == 0)&&(_stricmp(umsg, "shutdown") == 0)) {
            break;
        }

        if ((idx == 0)&&(_stricmp(umsg, "indices") == 0)) {
            V4vTraceConnectionIndices();
            continue;
        }

        (VOID)WaitForSingleObject(g_tlmutex, INFINITE);
        if (idx != 0) {
            ht = g_tlist[idx - 1].ht;
            tid = g_tlist[idx - 1].tid;
        }
        else {
            ht = g_lthread;
            tid = g_ltid;
        }
        (VOID)ReleaseMutex(g_tlmutex);

        if (ht == NULL) {
            printf("invalid input index %d - use a valid prefix and try again...\n", idx);
            continue;
        }

        // We have a message to post to one of the threads
        if (_stricmp(umsg, "quit") == 0) {
            mid = WM_V4V_QUIT;
        }
        else if (_stricmp(umsg, "dump") == 0) {
            mid = WM_V4V_DUMP;
        }
        else if (_stricmp(umsg, "nothing") == 0) {
            if (idx == 0) {
                printf("nothing invalid for listener index 0\n");
                continue;
            }
            mid = WM_V4V_NOTHING;
        }        
        else {
            if (idx == 0) {
                printf("text messages invalid for listener index 0\n");
                continue;
            }
            // Note, "resetme" goes as a text message to the peer
            mid = WM_V4V_TEXT;
        }

        lp = NULL;
        if (mid == WM_V4V_TEXT) {
            len = (ULONG)strlen(umsg);
            lp = (char*)malloc(len*sizeof(char) + 1);
            if (lp == NULL) {
                printf("V4VLCA listener out of memory for message to index %d\n", idx);
                continue;
            }
            strncpy(lp, umsg, len);
            lp[len] = '\0';
        }

        rc = PostThreadMessage(tid, mid, 0, (LPARAM)lp);
        if (!rc) {
            printf("V4VLCA listener PostThreadMessage() failed for index %d error: %d\n", idx, GetLastError());
            if (lp != NULL) {
                free(lp);
            }
            continue;
        }
    }

listdone:

    if (g_lthread != NULL) {
        CloseHandle(g_lthread);
    }

    if (g_tlmutex != NULL) {
        CloseHandle(g_tlmutex);
    }

    V4vClose(&ctx);
}

static HANDLE g_crshutdown = NULL;
static BOOLEAN g_crreset = FALSE;
static HANDLE g_rthread = NULL;

static DWORD WINAPI
V4vLCAConnectorReadThread(VOID *c)
{
    V4V_CONTEXT *pctx = (V4V_CONTEXT*)c;
    ULONG val, error;
    BOOL rc;    
    UCHAR rbuf[V4V_LCA_READBUF_SIZE];

    printf("V4VLCA Start connector reader thread\n");

    do {
        error = WaitForSingleObject(pctx->recvEvent, INFINITE);
        if (error != WAIT_OBJECT_0) {
            printf("V4VLCA WaitForSingleObject() failed error: 0x%x\n", error);
            break;
        }

        // Something is ready for us
        rc = ReadFile(pctx->v4vHandle, rbuf, V4V_LCA_READBUF_SIZE, &val, NULL);
        if (!rc) {
            error = GetLastError();
            if (error == ERROR_VC_DISCONNECTED) {
                printf("V4VLCA connector ReadFile() returned ERROR_VC_DISCONNECTED - other side disconnected\n");
            }
            else {
                printf("V4VLCA connector ReadFile() failed error: 0x%x\n", error);
            }
            break;
        }

        // Process it a bit
        rbuf[val] = '\0';
        printf("V4VLCA connector received %d bytes of message\n", val);        
        printf("V4VLCA msg: %s\n", rbuf);
        if (_stricmp((const char*)rbuf, "resetme") == 0) {
            printf("V4VLCA RST requested, breaking out and disconnecting\n");
            V4vDisconnect(pctx, NULL);
            g_crreset = TRUE;
            break;
        }

        if (WaitForSingleObject(g_crshutdown, 0) == WAIT_OBJECT_0) {
            printf("V4VLCA connector reader thread shutdown requested, ending\n");
            break;
        }
    } while (TRUE);

    return 0;
}

static VOID
V4vLCARunConnect(USHORT partner, ULONG32 port)
{
    BOOL rc;
    V4V_CONTEXT ctx = {0};
    v4v_ring_id_t id;
    v4v_addr_t addr;
    char buf[512];
    ULONG val, len, error;

    printf("V4VLCA char connnector starting\n");

    ctx.flags = V4V_FLAG_NONE;
    rc = V4vOpen(&ctx, 8192, NULL);
    if (!rc) {
        printf("V4VLCA connector V4vOpen() failed error: 0x%x\n", GetLastError());
        return;
    } 

    id.partner = partner;
    id.addr.domain = V4V_DOMID_NONE;
    id.addr.port = V4V_PORT_NONE;
    rc = V4vBind(&ctx, &id, NULL);
    if (!rc) {
        printf("V4VLCA connector V4vBind() failed error: 0x%x\n", GetLastError());
        goto conndone;
    }

    printf("V4VLCA local ring bound - begin connecting\n");

    addr.domain = partner;
    addr.port = port;
    rc = V4vConnect(&ctx, &addr, NULL);
    if (!rc) {
        printf("V4VLCA V4vConnect() failed error: 0x%x\n", GetLastError());        
        goto conndone;
    }
    printf("V4VLCA connected to port: 0x%x in domain: 0x%x\n", port, partner);

    g_crshutdown = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (g_crshutdown == NULL) {
        printf("V4VLCA connector CreateEvent() failed error: 0x%x\n", GetLastError());
        goto conndone;
    }

    g_rthread = CreateThread(NULL, 0, V4vLCAConnectorReadThread, &ctx, 0, NULL);
    if (g_rthread == NULL) {
        printf("V4VLCA connector reader thread failed error: %d\n", GetLastError());
        goto conndone;
    }

    printf(" - type some characters then enter to send.\n");
    printf(" - type \"dump\" to dump the ring to debug output.\n");
    printf(" - type \"quit\" to disconnect.\n");
    printf(" - type \"resetme\" to have the other end send a disconnect.\n");
    printf(" - type \"nothing\" to send an empty message.\n");

    while (1) {
        scanf("%s", buf);

        if (g_crreset) {
            printf("V4VLCA reader thread reset and closed the connection, exiting\n");
            break;
        }

        if (_stricmp(buf, "quit") == 0) {
            break;
        }

        if (_stricmp(buf, "dump") == 0) {
            rc = V4vDumpRing(&ctx, NULL);
            if (!rc) {
                printf("V4VLCA connector V4vDumpRing() failed error: 0x%x\n", GetLastError());
            }
            continue;
        }

        if (_stricmp(buf, "nothing") == 0) {
            len = 0;
        }
        else {
            len = (ULONG)strlen(buf);
        }

        rc = WriteFile(ctx.v4vHandle, buf, len, &val, NULL);
        if (!rc) {
            error = GetLastError();
            if (error == ERROR_VC_DISCONNECTED) {
                printf("V4VLCA connector WriteFile() returned ERROR_VC_DISCONNECTED - other side disconnected\n");
            }
            else {
                printf("V4VLCA connector WriteFile() failed error: 0x%x\n", error);
            }
            break;
        }
        if (val != len) {
            printf("V4VLCA connector write=%d not equal to written=%d\n", len, val);
            break;
        }
    }

    printf("V4VLCA connector set event and wait for reader thread\n");
    SetEvent(g_crshutdown);
    WaitForSingleObject(g_rthread, INFINITE);

    printf("V4VLCA connector reader thread shutdown, cleaning up\n");

conndone:

    if (!g_crreset) {
        V4vDisconnect(&ctx, NULL);
    }

    if (g_rthread != NULL) {
        CloseHandle(g_rthread);
    }

    if (g_crshutdown != NULL) {
        CloseHandle(g_crshutdown);
        g_crshutdown = NULL;
    }

    V4vClose(&ctx);
}

VOID
V4vRunConnectorAccepterTest(USHORT partner, ULONG32 port, BOOL conn)
{
    if (conn) {
        V4vLCARunConnect(partner, port);
    }
    else {
        V4vLCARunListenAccept(partner, port);
    }
}
