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

VOID
V4vCancelTest(USHORT partner)
{
    v4v_ring_id_t id;
    V4V_CONTEXT ctx1 = {0};
    V4V_CONTEXT ctx2 = {0};
    V4V_DATAGRAM *dg;
    HMODULE hm = NULL;
    HANDLE ev = NULL;
    OVERLAPPED ov;
    HANDLE ev2 = NULL;
    OVERLAPPED ov2;
    DWORD status, bytes, error;
    BOOL rc;
    char *p;
    char buf[64];
    CancelIoEx_t CancelIoExFn;

    printf("V4VCT Start cancel test\n");

    hm = LoadLibraryA("kernel32.dll");
    CancelIoExFn = (CancelIoEx_t)GetProcAddress(hm, "CancelIoEx");
    if (CancelIoExFn == NULL) {
        printf("V4VAPP could not locate CancelIoEx, error: %d\n", GetLastError());
        goto out0;
    }
    printf("V4VCT found CancelIoEx function: %p\n", CancelIoExFn);

    ev = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (ev == NULL) {
        printf("V4VCT failed to create overlapped open event - error: %d\n", GetLastError());
        goto out0;
    }
    V4V_RESET_OVERLAPPED(&ov, ev);

    ev2 = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (ev2 == NULL) {
        printf("V4VCT failed to create overlapped open event - error: %d\n", GetLastError());
        goto out0;
    }
    V4V_RESET_OVERLAPPED(&ov2, ev2);

    ctx1.flags = V4V_FLAG_NONE;
    rc = V4vOpen(&ctx1, 1024, NULL);
    if (!rc) {
        printf("V4VCT V4vOpen(ctx1) failed error: 0x%x\n", GetLastError());
        goto out1;
    }

    id.partner = V4V_DOMID_NONE;
    id.addr.port = 9907;
    id.addr.domain = V4V_DOMID_NONE;
    rc = V4vBind(&ctx1, &id, NULL);
    if (!rc) {
        printf("V4VCT V4vBind(ctx1) failed error: 0x%x\n", GetLastError());        
        goto out2;
    }

    ctx2.flags = V4V_FLAG_OVERLAPPED;
    rc = V4vOpen(&ctx2, 1024, &ov);
    if (!rc) {
        printf("V4VCT V4vOpen(ctx2) failed error: 0x%x\n", GetLastError());
        goto out2;
    }

    status = WaitForSingleObject(ev, INFINITE);
    if (status != WAIT_OBJECT_0) {
        printf("V4VCT V4vOpen(ctx2) wait warning, unexpected status: %d\n", status);
    }

    if (!GetOverlappedResult(ctx2.v4vHandle, &ov, &bytes, FALSE)) {
        printf("V4VCT GetOverlappedResult() for open failed with error: %d\n", GetLastError());
        goto out2;
    }
    V4V_RESET_OVERLAPPED(&ov, ev);

    id.partner = V4V_DOMID_NONE;
    id.addr.port = 9908;
    id.addr.domain = V4V_DOMID_NONE;
    rc = V4vBind(&ctx2, &id, &ov);
    if (!rc) {
        printf("V4VCT V4vBind(ctx2) failed error: 0x%x\n", GetLastError());        
        goto out3;
    }

    status = WaitForSingleObject(ev, INFINITE);
    if (status != WAIT_OBJECT_0) {
        printf("V4VCT V4vBind(ctx2) wait warning, unexpected status: %d\n", status);
    }

    if (!GetOverlappedResult(ctx2.v4vHandle, &ov, &bytes, FALSE)) {
        printf("V4VCT GetOverlappedResult() for bind failed with error: %d\n", GetLastError());
        goto out3;
    }
    V4V_RESET_OVERLAPPED(&ov, ev);

    dg = (V4V_DATAGRAM*)buf;
    dg->addr.domain = partner;
    dg->addr.port = 9907;
    p = buf + sizeof(V4V_DATAGRAM);
    memset(p, 'X', 64 - sizeof(V4V_DATAGRAM));

    // Pend 2 reads and then cancel it
    rc = ReadFile(ctx2.v4vHandle, buf, 64, &bytes, &ov);
    if (!rc) {
        error = GetLastError();
        if (error != ERROR_IO_PENDING) {
            printf("V4VCT WriteFile(ctx2-1) ReadFile - error: %d\n", error);
            goto out3;
        }        
    }
    else {
        printf("V4VCT ReadFile(ctx2-1) completed synchronously???? Should not happen!\n");
        goto out3;
    }

    rc = ReadFile(ctx2.v4vHandle, buf, 64, &bytes, &ov2);
    if (!rc) {
        error = GetLastError();
        if (error != ERROR_IO_PENDING) {
            printf("V4VCT WriteFile(ctx2-2) ReadFile - error: %d\n", error);
            goto out3;
        }        
    }
    else {
        printf("V4VCT ReadFile(ctx2-2) completed synchronously???? Should not happen!\n");
        goto out3;
    }

    printf("V4VCT read pended, sleep a bit and then cancel the IO\n");
    Sleep(3000);
    CancelIoExFn(ctx2.v4vHandle, NULL);
    printf("V4VCT CancelIoExFn returned\n");

    rc = GetOverlappedResult(ctx2.v4vHandle, &ov, &bytes, FALSE);
    if (!rc) {
        error = GetLastError();
        if (error == ERROR_OPERATION_ABORTED) {
            printf("V4VCT GetOverlappedResult returned ERROR_OPERATION_ABORTED as expected.\n");
        }
        else {
            printf("V4VCT GetOverlappedResult unexpected error: %d\n", error);
        }        
    }
    else
        printf("V4VCT GetOverlappedResult should have returned an error???\n");
    
out3:
    V4vClose(&ctx2);
out2:
    V4vClose(&ctx1);
out1:
    if (ev2 != NULL)
        CloseHandle(ev2);
    if (ev != NULL)
        CloseHandle(ev);
out0:
    if (hm != NULL)
        FreeLibrary(hm);   
}

VOID
V4vRunListenAcceptImmediate(USHORT partner, ULONG32 port)
{
    BOOL rc;
    V4V_CONTEXT ctx = {0}, actx = {0};
    v4v_ring_id_t id;
    HANDLE ev = NULL;
    HMODULE hm = NULL;
    CancelIoEx_t CancelIoExFn;
    OVERLAPPED ov;
    DWORD status, bytes, error;
    V4V_ACCEPT_VALUES acc;

    printf("V4VLA listen-accept immediate test starting\n");

    hm = LoadLibraryA("kernel32.dll");
    CancelIoExFn = (CancelIoEx_t)GetProcAddress(hm, "CancelIoEx");
    if (CancelIoExFn == NULL) {
        printf("V4VLA could not locate CancelIoEx, error: %d\n", GetLastError());
        goto ladone0;
    }
    printf("V4VLA found CancelIoEx function: %p\n", CancelIoExFn);
    
    ev = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (ev == NULL) {
        printf("V4VLA failed to create overlapped open event - error: %d\n", GetLastError());       
        goto ladone0;
    }
    V4V_RESET_OVERLAPPED(&ov, ev);  

    ctx.flags = V4V_FLAG_OVERLAPPED;
    rc = V4vOpen(&ctx, 8192, &ov);
    if (!rc) {
        printf("V4VLA listener V4vOpen() failed error: 0x%x\n", GetLastError());
        goto ladone1;
    }
    status = WaitForSingleObject(ev, INFINITE);
    if (status != WAIT_OBJECT_0) {
        printf("V4VLA V4vOpen() wait hosed, unexpected status: %d\n", status);
        goto ladone1;
    }

    if (!GetOverlappedResult(ctx.v4vHandle, &ov, &bytes, FALSE)) {
        printf("V4VLA GetOverlappedResult() for open failed with error: %d\n", GetLastError());
        goto ladone1;
    }
    V4V_RESET_OVERLAPPED(&ov, ev);

    id.partner = partner;
    id.addr.domain = V4V_DOMID_NONE;
    id.addr.port = port;
    rc = V4vBind(&ctx, &id, &ov);
    if (!rc) {
        printf("V4VLA listener V4vBind() failed error: 0x%x\n", GetLastError());
        goto ladone2;
    }
    status = WaitForSingleObject(ev, INFINITE);
    if (status != WAIT_OBJECT_0) {
        printf("V4VLA V4vBind() wait hosed, unexpected status: %d\n", status);
        goto ladone2;
    }

    if (!GetOverlappedResult(ctx.v4vHandle, &ov, &bytes, FALSE)) {
        printf("V4VLA GetOverlappedResult() for bind failed with error: %d\n", GetLastError());
        goto ladone2;
    }
    V4V_RESET_OVERLAPPED(&ov, ev);

    printf("V4VLA local ring bound - begin listening\n");

    rc = V4vListen(&ctx, V4V_SOMAXCONN, &ov);
    if (!rc) {
        printf("V4VLA listener V4vListen() failed error: 0x%x\n", GetLastError());
        goto ladone2;
    }
    status = WaitForSingleObject(ev, INFINITE);
    if (status != WAIT_OBJECT_0) {
        printf("V4VLA V4vListen() wait hosed, unexpected status: %d\n", status);
        goto ladone2;
    }

    if (!GetOverlappedResult(ctx.v4vHandle, &ov, &bytes, FALSE)) {
        printf("V4VLA GetOverlappedResult() for listen failed with error: %d\n", GetLastError());
        goto ladone2;
    }
    V4V_RESET_OVERLAPPED(&ov, ev);

    rc = V4vAccept(&ctx, &actx, &acc, &ov);
    if (!rc) {
        printf("V4VLA V4vAccept() failed, should have pended the accept error: 0x%x\n", GetLastError());
        goto ladone2;
    }

    printf("V4VLA accept pended, sleep a bit and then cancel the IO\n");
    Sleep(3000);
    CancelIoExFn(ctx.v4vHandle, NULL);
    printf("V4VLA CancelIoExFn returned\n");

    rc = GetOverlappedResult(ctx.v4vHandle, &ov, &bytes, FALSE);
    if (!rc) {
        error = GetLastError();
        if (error == ERROR_OPERATION_ABORTED) {
            printf("V4VLA GetOverlappedResult returned ERROR_OPERATION_ABORTED as expected.\n");
        }
        else {
            printf("V4VLA GetOverlappedResult unexpected error: %d\n", error);
        }        
    }
    else
        printf("V4VLA GetOverlappedResult should have returned an error???\n");

    V4vClose(&actx);
ladone2:
    V4vClose(&ctx);
ladone1:
    if (ev != NULL)
        CloseHandle(ev);
ladone0:
    if (hm != NULL)
        FreeLibrary(hm);
}

#define V4VAPP_BUFFER_SIZE 512
#define V4VAPP_MSG_SIZE (V4VAPP_BUFFER_SIZE + sizeof(V4V_DATAGRAM))

static UCHAR g_buffer[V4VAPP_MSG_SIZE];

VOID
V4vRunDatagramTest(USHORT partner, ULONG32 sport, ULONG32 dport)
{
    v4v_ring_id_t id;
    V4V_CONTEXT ctx = {0};
    V4V_DATAGRAM *dg;
    UCHAR *p;
    BOOL rc;
    ULONG val;
    char buf[256];

    printf("V4VDG Start datagram test with partner: 0x%x\n", partner);

    ctx.flags = V4V_FLAG_NONE;
    rc = V4vOpen(&ctx, 4096, NULL);
    if (!rc) {
        printf("V4VDG V4vOpen() failed error: 0x%x\n", GetLastError());
        return;
    }

    id.partner = V4V_DOMID_NONE;
    id.addr.port = sport;
    id.addr.domain = V4V_DOMID_NONE;
    rc = V4vBind(&ctx, &id, NULL);
    if (!rc) {
        printf("V4VDG V4vBind() failed error: 0x%x\n", GetLastError());
        V4vClose(&ctx);
        return;
    }

    printf("V4VDG local ring bound on port: 0x%x\n", sport);
    printf("type \"c\" to continue when ready.\n");

    while (TRUE) {
        scanf("%s", buf);
        if (_stricmp(buf, "c") == 0)
            break;
    }

    dg = (V4V_DATAGRAM*)g_buffer;
    dg->addr.domain = partner;
    dg->addr.port = dport;
    p = g_buffer + sizeof(V4V_DATAGRAM);
    memset(p, 'X', V4VAPP_BUFFER_SIZE);

    rc = WriteFile(ctx.v4vHandle, g_buffer, V4VAPP_MSG_SIZE, &val, NULL);
    if (!rc) {
        printf("V4VDG WriteFile() failed error: 0x%x\n", GetLastError());
        V4vClose(&ctx);
        return;
    }
    if (val == V4VAPP_MSG_SIZE) {
        printf("V4VDG Sent datagram to partner: 0x%x\n", partner);
    }
    else {
        printf("V4VDG WriteFile() tried to send: %d actually sent: %d ?????\n", V4VAPP_MSG_SIZE, val);
    }    

    WaitForSingleObject(ctx.recvEvent, INFINITE);
    printf("V4VDG Received datagram notification from partner: 0x%x\n", partner);

    rc = ReadFile(ctx.v4vHandle, g_buffer, V4VAPP_MSG_SIZE, &val, NULL);
    if (!rc) {
        printf("V4VDG ReadFile() failed error: 0x%x\n", GetLastError());
        V4vClose(&ctx);
        return;
    }
    if (val == V4VAPP_MSG_SIZE) {
        printf("V4VDG Read datagram from partner: 0x%x\n", partner);
        printf("  -- destination domain: 0x%x port: 0x%x\n", dg->addr.domain, dg->addr.port);
        printf("  -- first 8 bytes:\n");
        printf("  -- %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n",
               p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
    }
    else {
        printf("V4VDG ReadFile() tried to read: %d actually read: %d ?????\n", V4VAPP_MSG_SIZE, val);
    }

    V4vClose(&ctx);
}

#define V4VAPP_MOCK_CTRLMSG_SIZE (sizeof(V4V_DATAGRAM) + sizeof(V4V_STREAM))
#define V4VAPP_BIG_BUFFER_SIZE (2048 + V4VAPP_MOCK_CTRLMSG_SIZE)

static UCHAR g_bigBuffer[V4VAPP_BIG_BUFFER_SIZE];

VOID
V4vRunMockListerTest(USHORT partner, ULONG32 sport, ULONG32 dport)
{
    v4v_ring_id_t id;
    V4V_CONTEXT ctx = {0};
    V4V_DATAGRAM *dg;
    BOOL rc;
    ULONG val;
    V4V_STREAM *psh;
    uint32_t conid;
    BOOL doreset = FALSE;
    char *ptr;

    printf("V4VML Start mock listener test with partner: 0x%x\n", partner);

    ctx.flags = V4V_FLAG_NONE;
    rc = V4vOpen(&ctx, 8192, NULL);
    if (!rc) {
        printf("V4VML V4vOpen() failed error: 0x%x\n", GetLastError());
        return;
    }

    id.partner = V4V_DOMID_NONE;
    id.addr.port = sport;
    id.addr.domain = V4V_DOMID_NONE;
    rc = V4vBind(&ctx, &id, NULL);
    if (!rc) {
        printf("V4VML V4vBind() failed error: 0x%x\n", GetLastError());
        V4vClose(&ctx);
        return;
    }

    printf("V4VML local ring bound on port: 0x%x - begin listening\n", sport);

    // Wait for a SYN
    rc = ReadFile(ctx.v4vHandle, g_buffer, V4VAPP_MOCK_CTRLMSG_SIZE, &val, NULL);
    if (!rc) {
        printf("V4VML ReadFile() failed error: 0x%x\n", GetLastError());
        V4vClose(&ctx);
        return;
    }
    if (val != V4VAPP_MOCK_CTRLMSG_SIZE) {
        printf("V4VML wait for SYN failed, wrong size????\n");
        V4vClose(&ctx);
        return;
    }
    dg = (V4V_DATAGRAM*)g_buffer;
    psh = (V4V_STREAM*)(g_buffer + sizeof(V4V_DATAGRAM));
    if ((psh->flags & V4V_SHF_SYN) == 0) {
        printf("V4VML wait for SYN failed, not a SYN - flags: 0x%x\n", psh->flags);
        V4vClose(&ctx);
        return;
    }
    // Looks good, save the conid and send the ACK
    conid = psh->conid;
    printf("V4VML SYN succeeded - new conid: %d\n", conid);

    printf("V4VML send ACK...\n");
    dg = (V4V_DATAGRAM*)g_buffer;
    dg->addr.domain = partner;
    dg->addr.port = dport;
    psh = (V4V_STREAM*)(g_buffer + sizeof(V4V_DATAGRAM));
    psh->flags = V4V_SHF_ACK;
    psh->conid = conid;

    rc = WriteFile(ctx.v4vHandle, g_buffer, V4VAPP_MOCK_CTRLMSG_SIZE, &val, NULL);
    if (!rc) {
        printf("V4VML WriteFile() failed error: 0x%x\n", GetLastError());
        V4vClose(&ctx);
        return;
    }
    if (val != V4VAPP_MOCK_CTRLMSG_SIZE) {
        printf("V4VML send ACK to partner: 0x%x failed, wrote wrong size ????\n", partner);
        V4vClose(&ctx);
        return;
    }
    printf("V4VML send ACK succeeded\n");

    ptr = (char*)g_bigBuffer + V4VAPP_MOCK_CTRLMSG_SIZE;
    do {
        rc = ReadFile(ctx.v4vHandle, g_bigBuffer, V4VAPP_BIG_BUFFER_SIZE, &val, NULL);
        if (!rc) {
            printf("V4VML ReadFile() failed error: 0x%x\n", GetLastError());
            doreset = TRUE;
            break;
        }

        // Test the message
        if (val < V4VAPP_MOCK_CTRLMSG_SIZE) {
            printf("V4VML message too small from partner, size: %d\n", val);
            doreset = TRUE;
            break;
        }

        dg = (V4V_DATAGRAM*)g_bigBuffer;
        psh = (V4V_STREAM*)(g_bigBuffer + sizeof(V4V_DATAGRAM));
        if ((psh->flags & V4V_SHF_RST)&&(psh->conid == conid)) {
            printf("V4VML other side RST us, breaking out\n");
            break;
        }

        if ((psh->flags != 0)||(psh->conid != conid)) {
            printf("V4VML stream recv failed, bad flags or conid: 0x%x\n", psh->flags);
            doreset = TRUE;
            break;
        }

        // Process it a bit
        val -= V4VAPP_MOCK_CTRLMSG_SIZE;
        ptr[val] = '\0';        
        printf("V4VML received %d bytes of message\n", val);        
        printf("V4VML msg: %s\n", ptr);
        if (_stricmp(ptr, "resetme") == 0) {
            printf("V4VML RST requested, breaking out\n");
            doreset = TRUE;
            break;
        }
    } while (TRUE);

    if (doreset) {
        dg->addr.domain = partner;
        dg->addr.port = dport;
        psh = (V4V_STREAM*)(g_buffer + sizeof(V4V_DATAGRAM));
        psh->flags = V4V_SHF_RST;
        psh->conid = conid;

        rc = WriteFile(ctx.v4vHandle, g_buffer, V4VAPP_MOCK_CTRLMSG_SIZE, &val, NULL);
        if (!rc) {
            printf("V4VML WriteFile() RST failed error: 0x%x\n", GetLastError());
        }
        if (val != V4VAPP_MOCK_CTRLMSG_SIZE) {
            printf("V4VML send RST to partner: 0x%x failed, write too small\n", partner);
        }
    }
    
    rc = V4vClose(&ctx);
    if (!rc)
        printf("V4VML V4vClose() failed error: %d\n", GetLastError());
}

VOID
V4vRunConnectorMockTest(USHORT partner, ULONG32 sport, ULONG32 dport)
{
    BOOL rc;
    V4V_CONTEXT ctx = {0};
    v4v_ring_id_t id;
    v4v_addr_t addr;
    char buf[512];
    ULONG val, len, error;

    printf("V4VCM char connnector test\n");

    ctx.flags = V4V_FLAG_NONE;
    rc = V4vOpen(&ctx, 8192, NULL);
    if (!rc) {
        printf("V4VCM V4vOpen() failed error: 0x%x\n", GetLastError());
        return;
    }

    id.partner = partner;
    id.addr.domain = V4V_DOMID_NONE;
    id.addr.port = sport;
    rc = V4vBind(&ctx, &id, NULL);
    if (!rc) {
        printf("V4VCM V4vBind() failed error: 0x%x\n", GetLastError());
        V4vClose(&ctx);
        return;
    }

    printf("V4VCM local ring bound on port: 0x%x - begin connecting\n", sport);

    addr.domain = partner;
    addr.port = dport;
    rc = V4vConnect(&ctx, &addr, NULL);
    if (!rc) {
        printf("V4VCM V4vConnect() failed error: 0x%x\n", GetLastError());
        V4vClose(&ctx);
        return;
    }
    
    printf("V4VCM connected to port: 0x%x domain: 0x%x\n", dport, partner);
    printf(" - type some characters then enter to send.\n");
    printf(" - type \"quit\" to disconnect.\n");
    printf(" - type \"resetme\" to have the other end send a disconnect.\n");

    while (1) {
        scanf("%s", buf);
        if (_stricmp(buf, "quit") == 0)
            break;
        len = (ULONG)strlen(buf);
        rc = WriteFile(ctx.v4vHandle, buf, len, &val, NULL);
        if (!rc) {
            error = GetLastError();
            if (error == ERROR_VC_DISCONNECTED) {
                printf("V4VCM WriteFile() returned ERROR_VC_DISCONNECTED - other side disconnected\n");
            }
            else {
                printf("V4VCM WriteFile() failed error: 0x%x\n", error);
            }
            break;
        }
        if (val != len) {
            printf("V4VCM write=%d not equal to written=%d\n", len, val);
            break;
        }
    }

    rc = V4vClose(&ctx);
    if (!rc)
        printf("V4VCM V4vClose() failed error: %d\n", GetLastError());
}

VOID
V4vRunCharReceiverTest(USHORT partner, ULONG32 sport)
{
    v4v_ring_id_t id;
    V4V_CONTEXT ctx = {0};
    V4V_DATAGRAM *dg;
    BOOL rc;
    ULONG val;
    char *ptr;

    printf("V4VRX Start char receiver test with partner: 0x%x\n", partner);

    ctx.flags = V4V_FLAG_NONE;
    rc = V4vOpen(&ctx, 8192, NULL);
    if (!rc) {
        printf("V4VRX V4vOpen() failed error: 0x%x\n", GetLastError());
        return;
    }

    id.partner = partner;
    id.addr.port = sport;
    id.addr.domain = V4V_DOMID_NONE;
    rc = V4vBind(&ctx, &id, NULL);
    if (!rc) {
        printf("V4VRX V4vBind() failed error: 0x%x\n", GetLastError());
        V4vClose(&ctx);
        return;
    }

    printf("V4VRX local ring bound on port: 0x%x - begin waiting for messages\n", sport);

    ptr = (char*)g_bigBuffer + sizeof(V4V_DATAGRAM);    
    do {
        rc = ReadFile(ctx.v4vHandle, g_bigBuffer, V4VAPP_BIG_BUFFER_SIZE, &val, NULL);
        if (!rc) {
            printf("V4VRX ReadFile() failed error: 0x%x\n", GetLastError());
            break;
        }

        // Test the message
        if (val < sizeof(V4V_DATAGRAM)) {
            printf("V4VRX message too small from partner, size: %d\n", val);
            break;
        }        

        // Process it a bit
        dg = (V4V_DATAGRAM*)g_bigBuffer;
        val -= sizeof(V4V_DATAGRAM);
        ptr[val] = '\0';
        printf("V4VRX received %d bytes of message from 0x%x on 0x%x\n", val, dg->addr.domain, dg->addr.port);        
        printf("V4VRX msg: %s\n", ptr);
        if (_stricmp(ptr, "shutdown") == 0) {
            printf("V4VRX shutdown requested, breaking out\n");
            break;
        }
        if (_stricmp(ptr, "dump") == 0) {
            printf("V4VRX ring dump requested...\n");
            rc = V4vDumpRing(&ctx, NULL);            
            if (!rc) {
                printf("V4VRX V4vDumpRing() failed error: 0x%x\n", GetLastError());
            }            
        }
    } while (TRUE);
    
    rc = V4vClose(&ctx);
    if (!rc)
        printf("V4VRX V4vClose() failed error: %d\n", GetLastError());
}

VOID
V4vRunCharSenderTest(USHORT partner, ULONG32 dport)
{
    v4v_ring_id_t id;
    V4V_CONTEXT ctx = {0};
    V4V_DATAGRAM *dg;
    BOOL rc;
    ULONG val, len, mlen, error;
    char buf[512];
    char *ptr;

    printf("V4VTX Start char sender test with partner: 0x%x\n", partner);

    ctx.flags = V4V_FLAG_NONE;
    rc = V4vOpen(&ctx, 8192, NULL);
    if (!rc) {
        printf("V4VTX V4vOpen() failed error: 0x%x\n", GetLastError());
        return;
    }

    id.partner = partner;
    id.addr.port = V4V_PORT_NONE;
    id.addr.domain = V4V_DOMID_NONE;
    rc = V4vBind(&ctx, &id, NULL);
    if (!rc) {
        printf("V4VTX V4vBind() failed error: 0x%x\n", GetLastError());
        V4vClose(&ctx);
        return;
    }

    printf("V4VTX local ring bound - sending to port: 0x%x domain: 0x%x - begin sending messages\n", dport, partner);
    printf(" - type some characters then enter to send.\n");
    printf(" - type \"quit\" to disconnect.\n");
    printf(" - type \"shutdown\" to have the other end shutdown.\n");
    printf(" - type \"nothing\" to send a zero length message.\n");
    printf(" - type \"dump\" to dump the remote ring to debug output.\n");

    dg = (V4V_DATAGRAM*)buf;
    dg->addr.domain = partner;
    dg->addr.port = dport;
    ptr = (char*)buf + sizeof(V4V_DATAGRAM);
    do {
        scanf("%s", ptr);
        if (_stricmp(ptr, "quit") == 0)
            break;        
        if (_stricmp(ptr, "nothing") == 0)
            len = 0;
        else
            len = (ULONG)strlen(ptr);
        mlen = len + sizeof(V4V_DATAGRAM);      
        rc = WriteFile(ctx.v4vHandle, buf, mlen, &val, NULL);
        if (!rc) {
            error = GetLastError();
            if (error == ERROR_VC_DISCONNECTED) {
                printf("V4VTX WriteFile() returned ERROR_VC_DISCONNECTED - other side shutdown\n");
            }
            else {
                printf("V4VTX WriteFile() failed error: 0x%x\n", error);
            }
            break;
        }
        if (val != mlen) {
            printf("V4VTX write=%d not equal to written=%d\n", mlen, val);
            break;
        }
    } while (TRUE);
    
    rc = V4vClose(&ctx);
    if (!rc)
        printf("V4VTX V4vClose() failed error: %d\n", GetLastError());
}

#define V4VAPP_CCBUFFER_SIZE 1024
static UCHAR g_ccbuffer[V4VAPP_CCBUFFER_SIZE];
static HANDLE g_ccshutdown = NULL;
static BOOLEAN g_ccreset = FALSE;
static CancelSynchronousIo_t g_CancelSynchronousIoFn;
static HMODULE g_k32 = NULL;
static HANDLE g_hthread = NULL;
static HANDLE g_htmain = NULL;

static DWORD WINAPI
V4vConnectorConnectorReadThread(VOID *c)
{
    V4V_CONTEXT *pctx = (V4V_CONTEXT*)c;
    BOOL rc;
    ULONG val;
    ULONG error;

    printf("V4VCC Start reader thread\n");

    do {
        error = WaitForSingleObject(pctx->recvEvent, INFINITE);
        if (error != WAIT_OBJECT_0) {
            printf("V4VCC WaitForSingleObject() failed error: 0x%x\n", error);
            break;
        }

        // Something is ready for us
        rc = ReadFile(pctx->v4vHandle, g_ccbuffer, V4VAPP_CCBUFFER_SIZE, &val, NULL);
        if (!rc) {
            error = GetLastError();
            if (error == ERROR_VC_DISCONNECTED) {
                printf("V4VCC ReadFile() returned ERROR_VC_DISCONNECTED - other side disconnected\n");
            }
            else {
                printf("V4VCC ReadFile() failed error: 0x%x\n", error);
            }
            break;
        }

        // Process it a bit
        g_ccbuffer[val] = '\0';
        printf("V4VCC received %d bytes of message\n", val);        
        printf("V4VCC msg: %s\n", g_ccbuffer);
        if (_stricmp((const char*)g_ccbuffer, "resetme") == 0) {
            printf("V4VCC RST requested, breaking out and closing connection\n");
            g_ccreset = TRUE;
            break;
        }

        if (WaitForSingleObject(g_ccshutdown, 0) == WAIT_OBJECT_0) {
            printf("V4VCC reader thread shutdown requested, ending\n");
            break;
        }
    } while (TRUE);

    if (g_ccreset) {
        V4vDisconnect(pctx, NULL);
    }

    return 0;
}

VOID
V4vRunConnectorConnectorTest(USHORT partner, ULONG32 port, BOOL conn)
{
    BOOL rc;
    V4V_CONTEXT ctx = {0};
    v4v_ring_id_t id;
    v4v_addr_t addr;
    char buf[512];
    ULONG val, len, error;

    printf("V4VCC char connnector test\n");

    ctx.flags = V4V_FLAG_NONE;
    rc = V4vOpen(&ctx, 8192, NULL);
    if (!rc) {
        printf("V4VCC V4vOpen() failed error: 0x%x\n", GetLastError());
        return;
    }

    g_k32 = LoadLibraryA("kernel32.dll");
    g_CancelSynchronousIoFn = (CancelSynchronousIo_t)GetProcAddress(g_k32, "CancelIoEx");
    if (g_CancelSynchronousIoFn != NULL) {
        printf("V4VCC found CancelSynchronousIo function: %p\n", g_CancelSynchronousIoFn);
    }
    else {
        printf("V4VAPP could not locate CancelSynchronousIo error: %d\n", GetLastError());
    }    

    id.partner = partner;
    id.addr.domain = V4V_DOMID_NONE;
    id.addr.port = (conn ? V4V_PORT_NONE : port); // port is the listening port in this case
    rc = V4vBind(&ctx, &id, NULL);
    if (!rc) {
        printf("V4VCC V4vBind() failed error: 0x%x\n", GetLastError());
        goto ccdone;
    }

    if (conn) {
        printf("V4VCC local ring bound - begin connecting\n");

        addr.domain = partner;
        addr.port = port;
        rc = V4vConnect(&ctx, &addr, NULL);
        if (!rc) {
            printf("V4VCC V4vConnect() failed error: 0x%x\n", GetLastError());        
            goto ccdone;
        }
        printf("V4VCC connected to port: 0x%x in domain: 0x%x\n", port, partner);
    }
    else {
        printf("V4VCC local ring bound on port: 0x%x - begin waiting\n", port);
        rc = V4vConnectWait(&ctx, NULL);
        if (!rc) {
            printf("V4VCC V4vConnectWait() failed error: 0x%x\n", GetLastError());
            goto ccdone;
        }
        printf("V4VCC waiting on port: 0x%x for domain: 0x%x\n", port, partner);
    }

    g_ccshutdown = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (g_ccshutdown == NULL) {
        printf("V4VCC CreateEvent() failed error: 0x%x\n", GetLastError());
        goto ccdone;
    }

    g_htmain = GetCurrentThread();

    g_hthread = CreateThread(NULL, 0, V4vConnectorConnectorReadThread, &ctx, 0, NULL);
    if (g_hthread == NULL) {
        printf("V4VCC create reader thread failed error: %d\n", GetLastError());
        goto ccdone;
    }

    printf(" - type some characters then enter to send.\n");
    printf(" - type \"quit\" to disconnect.\n");
    printf(" - type \"resetme\" to have the other end send a disconnect.\n");
    printf(" - type \"nothing\" to send an empty message.\n");
    printf(" - type \"dump\" to dump the ring to debug output.\n");

    while (1) {
        scanf("%s", buf);

        if (g_ccreset) {
            printf("V4VCC reader thread reset and closed the connection, exiting\n");
            break;
        }

        if (_stricmp(buf, "quit") == 0)
            break;

        if (_stricmp(buf, "dump") == 0) {
            rc = V4vDumpRing(&ctx, NULL);
            if (!rc) {
                printf("V4VCC V4vDumpRing() failed error: 0x%x\n", GetLastError());
            }
            continue;
        }

        if (_stricmp(buf, "nothing") == 0)
            len = 0;
        else
            len = (ULONG)strlen(buf);

        rc = WriteFile(ctx.v4vHandle, buf, len, &val, NULL);
        if (!rc) {
            error = GetLastError();
            if (error == ERROR_VC_DISCONNECTED) {
                printf("V4VCC WriteFile() returned ERROR_VC_DISCONNECTED - other side disconnected\n");
            }
            else {
                printf("V4VCC WriteFile() failed error: 0x%x\n", error);
            }
            break;
        }
        if (val != len) {
            printf("V4VCC write=%d not equal to written=%d\n", len, val);
            break;
        }        
    }

    printf("V4VCC set event and wait for reader thread\n");
    SetEvent(g_ccshutdown);
    WaitForSingleObject(g_hthread, INFINITE);

    printf("V4VCC reader thread shutdown, cleaning up\n");

ccdone:

    if (!g_ccreset) {
        V4vDisconnect(&ctx, NULL);
    }

    if (g_hthread != NULL)
        CloseHandle(g_hthread);

    if (g_ccshutdown != NULL) {
        CloseHandle(g_ccshutdown);
        g_ccshutdown = NULL;
    }

    if (g_k32 != NULL) {
        FreeLibrary(g_k32);
        g_k32 = NULL;
        g_CancelSynchronousIoFn = NULL;
    }

    V4vClose(&ctx);
}
