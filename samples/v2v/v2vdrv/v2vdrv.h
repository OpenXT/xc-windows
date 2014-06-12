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

#if !defined(_V2VDRV_H_)
#define _V2VDRV_H_

#pragma warning(disable: 4127) // conditional expression is constant

#include "v2v_common.h"
#include "v2v_ioctl.h"

/* Core driver definitions */

#pragma warning(disable: 4201)

#define V2VDRV_TAG 'kv2v'
#define V2VDRV_LOGTAG "V2VDRV"

extern PDRIVER_OBJECT g_driverObject;
extern PDEVICE_OBJECT g_deviceObject;

extern ULONG g_osMajorVersion;
extern ULONG g_osMinorVersion;

/* V2V Ops definitions */
typedef NTSTATUS (*V2vkProcessingFunction_t)(void *ctx);

#define V2VK_TERM_UNKNOWN  (ULONG)-1
#define V2VK_TERM_COMPLETE       0x0
#define V2VK_TERM_GENERAL_ERROR  0x1
#define V2VK_TERM_RX_ERROR       0x2
#define V2VK_TERM_TX_ERROR       0x3

typedef struct _V2VK_BASE_CONTEXT {
    PFILE_OBJECT pfo;
    V2V_ROLE_TYPE role;
    V2V_XFER_TYPE xfer;
    ULONG flags;
    ULONG xferMaxFastRx;
    char *localPrefix;  /* XenStore local path prefix */
    BOOLEAN hasFilePath;

    struct v2v_channel *channel;
    struct v2v_async *asvp;

    volatile ULONG txCounter;
    volatile ULONG rxCounter;

    union {
        struct {
            V2vkProcessingFunction_t rxFunction;
            V2vkProcessingFunction_t txFunction;
        } sync;
        struct {
            V2vkProcessingFunction_t rxFunction;
            V2vkProcessingFunction_t txFunction;
            KSPIN_LOCK rxLock;
            KSPIN_LOCK txLock;
            KEVENT termEvent;
            KTIMER toTimer;
            PIO_WORKITEM pwi;
            struct v2v_async asv;
            LONG running;
            ULONG termStatus;
        } async;
    } s;
} V2VK_BASE_CONTEXT, *PV2VK_BASE_CONTEXT;

typedef struct _V2VK_CONNECTOR_CONTEXT {
    V2VK_BASE_CONTEXT;
    ULONG xferSize;
    ULONG xferTimeout;

    union {
        struct {
            ULONG count;
        } xferInternal;
        struct {
            UNICODE_STRING fileName;
            HANDLE hf;
            LARGE_INTEGER length;
            LARGE_INTEGER offset;
            ULONG seqnum;
            ULONG seqrx;
            BOOLEAN done;
        } xferFile;
    } u;
} V2VK_CONNECTOR_CONTEXT, *PV2VK_CONNECTOR_CONTEXT;

typedef struct _V2VK_LISTENER_CONTEXT {
    V2VK_BASE_CONTEXT;
	
    union {
        struct {
            struct _V2V_LISTENER_RESP_ITEM *respList;
            struct _V2V_LISTENER_RESP_ITEM *respTail;
        } xferInternal;
        struct {
            UNICODE_STRING fileName;
            HANDLE hf;
            ULONG seqnum;
            ULONG status;
            BOOLEAN ack;
        } xferFile;
    } u;
} V2VK_LISTENER_CONTEXT, *PV2VK_LISTENER_CONTEXT;

NTSTATUS V2vkCreateContext(FILE_OBJECT *pfo);
NTSTATUS V2vkDestroyContext(FILE_OBJECT *pfo);
NTSTATUS V2vkInitInternalXfer(FILE_OBJECT *pfo, V2VK_IOCD_INIT_INTERNAL_XFER *iixfer);
NTSTATUS V2vkInitFileXfer(FILE_OBJECT *pfo, V2VK_IOCD_INIT_FILE_XFER *ifxfer);
NTSTATUS V2vkRunConnector(FILE_OBJECT *pfo);
NTSTATUS V2vkRunListener(FILE_OBJECT *pfo);

BOOLEAN V2vkMessageHeaderCheck(const char *rstr,
                               const char *xstr,
                               V2V_FRAME_HEADER *header,
                               size_t messsageSize,
                               size_t minSize);
NTSTATUS V2vStatusCheck(V2VK_BASE_CONTEXT *vbc, const char *rstr);

NTSTATUS V2vkConnectorProcessMessagesSync(V2VK_CONNECTOR_CONTEXT *vcc);
NTSTATUS V2vkListenerProcessMessagesSync(V2VK_LISTENER_CONTEXT *vlc);
BOOLEAN V2vkInitializeSync(V2VK_BASE_CONTEXT *vbc);
#define V2vkCleanupSync(x)

NTSTATUS V2vkConnectorProcessMessagesAsync(V2VK_CONNECTOR_CONTEXT *vcc);
NTSTATUS V2vkListenerProcessMessagesAsync(V2VK_LISTENER_CONTEXT *vlc);
BOOLEAN V2vkInitializeAsync(V2VK_BASE_CONTEXT *vbc);
void V2vkCleanupAsync(V2VK_BASE_CONTEXT *vbc);

/* Driver utility definitions */

#define LargeIntRelDelay(ms) (ULONG64) -(10000 * ((LONG32) (ms)))

ULONG V2vTimeDeltaMs(PLARGE_INTEGER start);

#define V2V_FILE_OPEN_READ      1
#define V2V_FILE_OPEN_WRITE     2
#define V2V_FILE_OPEN_APPEND    3

NTSTATUS V2vkCreateFilePath(const char *pathIn, PUNICODE_STRING pathOut);

NTSTATUS V2vkCreateFile(PUNICODE_STRING fileName,
                        ULONG32 readWrite,
                        HANDLE *hfOut,
                        LARGE_INTEGER *lengthOut,
                        LARGE_INTEGER *posOut);

#endif /*_V2VDRV_H_*/
