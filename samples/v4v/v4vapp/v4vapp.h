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

#if !defined(_V4VAPP_H_)
#define _V4VAPP_H_

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define V4V_TRANSFER_TIMEOUT      2000
#define V4V_DEFAULT_RING_SIZE     2*PAGE_SIZE
#define V4V_DEFAULT_BUFFER_SIZE   512

typedef enum _V4V_ROLE_TYPE {
    RoleTypeNone = 0,
    RoleTypeSender,
    RoleTypeReceiver,
    RoleTypeConnector,
    RoleTypeListener
} V4V_ROLE_TYPE;

typedef enum _V4V_XFER_TYPE {
    XferTypeUnknown = 0,
    XferTypeInternal,
    XferTypeFile
} V4V_XFER_TYPE;

typedef BOOL (WINAPI* CancelSynchronousIo_t)(__in HANDLE hThread);

typedef BOOL (WINAPI* CancelIoEx_t)(__in HANDLE hFile, __in_opt LPOVERLAPPED lpOverlapped);

/* V4V App */
typedef struct _V4V_CONFIG {
    V4V_ROLE_TYPE role;
    V4V_XFER_TYPE xfer;
    BOOL async;
    BOOL connectOnly;

    char xferFilePath[_MAX_PATH + 1];
    ULONG xferTimeout;

    ULONG txSize;
    ULONG rxSize;
    UCHAR *txBuf;
    UCHAR *rxBuf;

    ULONG ringSize;
    v4v_addr_t src;
    v4v_addr_t dst;
    ULONG protocol;

    V4V_CONTEXT v4vctx;
    HANDLE heap;
    HANDLE shutdownEvent1;
    HANDLE shutdownEvent2;

    HMODULE k32;
    CancelSynchronousIo_t CancelSynchronousIoFn;
    CancelIoEx_t CancelIoExFn;

    union {
        struct {            
            USHORT counter;
        } dgram;
        struct {
            ULONG dataSize;
            FILE *fh;
            struct _stat finfo;
            ULONG offset;
            ULONG seqnum;
            ULONG seqrx;
            ULONG status;
            BOOL ack;
            BOOL done;
        } dfile;
    } r;    
} V4V_CONFIG, *PV4V_CONFIG;

#define V4V_RESET_OVERLAPPED(o, h) { \
        ZeroMemory((o), sizeof(OVERLAPPED)); \
        (o)->hEvent = h; \
    }

/* Tests */
VOID V4vCancelTest(USHORT partner);
VOID V4vRunListenAcceptImmediate(USHORT partner, ULONG32 port);
VOID V4vRunDatagramTest(USHORT partner, ULONG32 sport, ULONG32 dport);
VOID V4vRunMockListerTest(USHORT partner, ULONG32 sport, ULONG32 dport);
VOID V4vRunConnectorMockTest(USHORT partner, ULONG32 sport, ULONG32 dport);
VOID V4vRunCharReceiverTest(USHORT partner, ULONG32 sport);
VOID V4vRunCharSenderTest(USHORT partner, ULONG32 dport);
VOID V4vRunConnectorConnectorTest(USHORT partner, ULONG32 port, BOOL conn);
VOID V4vRunConnectorAccepterTest(USHORT partner, ULONG32 port, BOOL conn);

VOID V4vStartDatagram(V4V_CONFIG *cfg);
VOID V4vStartDatagramFile(V4V_CONFIG *cfg);

VOID V4vStartListener(V4V_CONFIG *cfg);
VOID V4vStartConnector(V4V_CONFIG *cfg);

/* Driver/Device Control */
ULONG V4vDcInstallDriver(const wchar_t *driverName, const wchar_t *serviceExe, BOOL systemStart);
ULONG V4vDcStartDriver(const wchar_t *driverName);
ULONG V4vDcOpenDeviceFile(const wchar_t *fileName, HANDLE *deviceOut);
ULONG V4vDcStopDriver(const wchar_t *driverName);
ULONG V4vDcRemoveDriver(const wchar_t *driverName);

/* Cancel */
static __inline BOOL V4vCancelSynchronousIo(V4V_CONFIG *cfg, HANDLE hThread)
{
    if (cfg->CancelSynchronousIoFn != NULL) {
        return cfg->CancelSynchronousIoFn(hThread);
    }
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

static __inline BOOL V4vCancelIoEx(V4V_CONFIG *cfg, HANDLE hFile, LPOVERLAPPED lpOverlapped)
{
    if (cfg->CancelIoExFn != NULL) {
        return cfg->CancelIoExFn(hFile, lpOverlapped);
    }
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

#endif /*_V4VAPP_H_*/
