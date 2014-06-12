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

/************************** COMMON **************************/

ULONG
V2vTimeDeltaMs(PLARGE_INTEGER start)
{
    LARGE_INTEGER now;

    KeQuerySystemTime(&now);

    return (ULONG)((now.QuadPart - start->QuadPart)/10000);
}

NTSTATUS
V2vkCreateFilePath(const char *pathIn, PUNICODE_STRING pathOut)
{
    NTSTATUS status = STATUS_SUCCESS;
    size_t len;
    char *path = NULL;
    ANSI_STRING as;

    if (!pathIn || !pathOut)
        return STATUS_INVALID_PARAMETER;

    status = RtlStringCchLengthA(pathIn, V2V_MAX_IOCTL_STRING, &len);
    if (!NT_SUCCESS(status))
        return status;

    path = ExAllocatePoolWithTag(NonPagedPool, len + 5, V2VDRV_TAG);
    if (!path)
        return STATUS_NO_MEMORY;

    do {
        status = RtlStringCchCopyNA(path, len + 5, "\\??\\", 4);
        if (!NT_SUCCESS(status))
            break;

        status = RtlStringCchCatNA(path, len + 5, pathIn, len);
        if (!NT_SUCCESS(status))
            break;

        RtlInitAnsiString(&as, path);

        status = RtlAnsiStringToUnicodeString(pathOut, &as, TRUE);
    } while (FALSE);

    ExFreePoolWithTag(path, V2VDRV_TAG);    

    return status;
}

/* Create file routine. Arg readWrite can be use:
 * V2V_FILE_OPEN_READ
 * V2V_FILE_OPEN_WRITE
 * V2V_FILE_OPEN_APPEND
 */
NTSTATUS
V2vkCreateFile(PUNICODE_STRING fileName, 
               ULONG32 readWrite,
               HANDLE *hfOut,
               LARGE_INTEGER *lengthOut,
               LARGE_INTEGER *posOut)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE hf = 0;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    ULONG share;
    ULONG disp;
    ACCESS_MASK am;
    ULONG createOptions;
    LARGE_INTEGER liStartingPos;
    FILE_STANDARD_INFORMATION fsi;

    liStartingPos.QuadPart = 0;

    switch(readWrite)
    {
    case V2V_FILE_OPEN_READ:
        am    = GENERIC_READ;
        share = FILE_SHARE_READ;
        disp  = FILE_OPEN;
        createOptions = FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT;
        break;
    case V2V_FILE_OPEN_WRITE:
        am    = GENERIC_WRITE;
        share = FILE_SHARE_READ;
        disp  = FILE_OVERWRITE_IF;
        createOptions = FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT;
        break;
    case V2V_FILE_OPEN_APPEND:
        am    = GENERIC_WRITE;
        share = FILE_SHARE_READ;
        disp  = FILE_OPEN;
        createOptions = FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT;
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    InitializeObjectAttributes(&oa, fileName, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, 0, 0);

    do {
        status = 
            ZwCreateFile(&hf, am, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                         share, disp, createOptions, NULL, 0);
        if (!NT_SUCCESS(status))
    	    break;

        status =
            ZwQueryInformationFile(hf, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
        if (!NT_SUCCESS(status))
            break;

        if (iosb.Information < sizeof(fsi)) {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        if (readWrite == V2V_FILE_OPEN_APPEND)
            liStartingPos = fsi.EndOfFile;

        *hfOut = hf;
        *lengthOut = fsi.EndOfFile;
        *posOut = liStartingPos;        
    } while (FALSE);

    if (!NT_SUCCESS(status)) {
        if (hf)
            ZwClose(hf);
        *hfOut  = 0;
        lengthOut->QuadPart = 0;
        posOut->QuadPart = 0;
    }
    return status;
}

static BOOLEAN
V2vkInputSanityCheck(V2VK_BASE_CONTEXT *vbc)
{
    V2VK_CONNECTOR_CONTEXT *vcc;
    ULONG xferSize;

    if (vbc->role == RoleTypeListener) {
        /* listener always sends fixed sized messages and doesn use xfer_size */
        return TRUE;
    }

    vcc = (V2VK_CONNECTOR_CONTEXT*)vbc;
    xferSize = (vcc->xfer == XferTypeInternal) ? sizeof(V2V_POST_INTERNAL) : sizeof(V2V_POST_FILE);
    if (vcc->xferSize <= xferSize) {
        DbgPrint("%s connector(%p) transfer size %d (0x%x) too small; %d (0x%x) required\n",
                 V2VDRV_LOGTAG, vbc, vcc->xferSize, vcc->xferSize, xferSize + 1, xferSize + 1);
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
V2vkMessageHeaderCheck(const char *rstr,
                       const char *xstr,
                       V2V_FRAME_HEADER *header,
                       size_t messsageSize,
                       size_t minSize)
{
    if ((messsageSize < sizeof(V2V_FRAME_HEADER))||(messsageSize < minSize)) {
        DbgPrint("%s (%s - %s) response is too small!!!\n", V2VDRV_LOGTAG, rstr, xstr);
        return FALSE;
    }
    if (header->length < messsageSize) {
        DbgPrint("%s (%s - %s) response header length incorrect!!!\n", V2VDRV_LOGTAG, rstr, xstr);
        return FALSE;
    }       
    
    DbgPrint("%s (%s - %s) received message\n", V2VDRV_LOGTAG, rstr, xstr);
    DbgPrint("------ id=%d type=%d length=0x%x\n", header->id, header->type, header->length);

    return TRUE;
}

NTSTATUS
V2vStatusCheck(V2VK_BASE_CONTEXT *vbc, const char *rstr)
{
    NTSTATUS status;
    enum v2v_endpoint_state state;

    status = v2v_get_remote_state(vbc->channel, &state);
    if (!NT_SUCCESS(status)) {
        DbgPrint("%s %s(%p) failure in v2v_get_remote_state(); aborting - error: 0x%x\n",
                 V2VDRV_LOGTAG, rstr, vbc, status);
        return status;
    }
    DbgPrint("%s %s(%p) state changed for other end - new state: %s\n",
             V2VDRV_LOGTAG, rstr, vbc, v2v_endpoint_state_name(state));
    if (v2v_state_requests_disconnect(state)) {
        DbgPrint("%s %s(%p) main processing loop ending for disconnect request...\n",
                 V2VDRV_LOGTAG, rstr, vbc);
        /* requesting disconnect */
        return STATUS_SUCCESS;
    }

    /* more work pending, remote still connected */
    return STATUS_PENDING;
}

/************************* CONNECTOR *************************/

static NTSTATUS
V2vkConnect(V2VK_CONNECTOR_CONTEXT *vcc, struct v2v_async *asv)
{
    NTSTATUS status = STATUS_SUCCESS;
    PKEVENT kev;
    LARGE_INTEGER timeout, ts;
    ULONG to, td;
    enum v2v_endpoint_state state;

    /* Connect to the listener, get back a channel handle */
    status = v2v_connect(vcc->localPrefix, &vcc->channel, asv);
    if (!NT_SUCCESS(status)) {
        DbgPrint("%s connector(%p) failure in v2v_connect() - error: 0x%x\n", V2VDRV_LOGTAG, vcc, status);
        return status;
    }

    ASSERT(vcc->channel != NULL);

    DbgPrint("%s connector(%p) connected to listener; wait for listenter to indicate it has accepted the connection...\n", V2VDRV_LOGTAG, vcc);    

    ts.QuadPart = 0;
    to = vcc->xferTimeout << 2; /* in ms x4*/
    kev = v2v_get_control_event(vcc->channel);
    
    do {
        if (ts.QuadPart != 0) {
            /* rundown timer */
            td = V2vTimeDeltaMs(&ts);
            if (td < to)
                timeout.QuadPart = LargeIntRelDelay(to - td);
            else
                timeout.QuadPart = 0;
        }
        else {
            timeout.QuadPart = LargeIntRelDelay(to);
            KeQuerySystemTime(&ts);
        }

        status = KeWaitForSingleObject(kev, Executive, KernelMode, FALSE, &timeout);
        if (status == STATUS_WAIT_0) {
            status = v2v_get_remote_state(vcc->channel, &state);
            if (!NT_SUCCESS(status)) {
                DbgPrint("%s connector(%p) failure in v2v_get_remote_state(); aborting - error: 0x%x\n",
                         V2VDRV_LOGTAG, vcc, status);
                break;
            }
            DbgPrint("%s connector(%p) state changed for other end - new state: %s\n",
                     V2VDRV_LOGTAG, vcc, v2v_endpoint_state_name(state));
            if (state == v2v_state_connected) {
                DbgPrint("%s connector(%p) listener reports connected; begin processing messages.\n",
                         V2VDRV_LOGTAG, vcc);
                status = STATUS_SUCCESS;
                break;
            }
        }
        else if (status == STATUS_TIMEOUT ) {
            DbgPrint("%s connector(%p) timed out waiting for accept from listener; disconnecting\n",
                     V2VDRV_LOGTAG, vcc);
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

    if (!NT_SUCCESS(status))
        v2v_disconnect(vcc->channel);

    return status;
}

static void
V2vkConnectorDisconnect(V2VK_CONNECTOR_CONTEXT *vcc)
{
    NTSTATUS status;

    DbgPrint("%s connector(%p) Disconnecting...\n", V2VDRV_LOGTAG, vcc);
    status = v2v_disconnect(vcc->channel);
    DbgPrint("%s connector(%p) Disconnected - status: 0x%x\n", V2VDRV_LOGTAG, vcc, status);

    DbgPrint("%s connector(%p) Sent message counter: %d\n", V2VDRV_LOGTAG, vcc, vcc->txCounter);
    DbgPrint("%s connector(%p) Received response counter: %d\n", V2VDRV_LOGTAG, vcc, vcc->rxCounter);

    if (vcc->txCounter != vcc->rxCounter)
        DbgPrint("%s connector(%p) WARNING Response count does not match the send count\n", V2VDRV_LOGTAG, vcc);
}

static void
V2vkConnectorCleanup(V2VK_CONNECTOR_CONTEXT *vcc)
{
    if ((vcc->xfer == XferTypeFile)&&(vcc->u.xferFile.hf))
        ZwClose(vcc->u.xferFile.hf);
}

NTSTATUS
V2vkRunConnector(FILE_OBJECT *pfo)
{
    NTSTATUS status = STATUS_SUCCESS;
    V2VK_CONNECTOR_CONTEXT *vcc = (V2VK_CONNECTOR_CONTEXT*)pfo->FsContext;

    ASSERT(vcc != NULL);
    DbgPrint("%s connector(%p) starting %s for transfer type: %s\n", V2VDRV_LOGTAG, vcc,
             (vcc->flags & V2V_KERNEL_ASYNC) ? "ASYNC" : "SYNC",
             (vcc->xfer == XferTypeInternal) ? "Internal" : "File");
    
    if (vcc->xfer == XferTypeFile) {
        status = V2vkCreateFile(&vcc->u.xferFile.fileName,
                                V2V_FILE_OPEN_READ,
                                &vcc->u.xferFile.hf,
                                &vcc->u.xferFile.length,
                                &vcc->u.xferFile.offset);
        if (!NT_SUCCESS(status)) {
            DbgPrint("%s connector(%p) failed to open file %.*ws\n", V2VDRV_LOGTAG, vcc,
                vcc->u.xferFile.fileName.Length >> 1, vcc->u.xferFile.fileName.Buffer);
            return status;
        }      
        vcc->u.xferFile.seqnum = 1;
        vcc->u.xferFile.seqrx = 1;
    }

    if (!V2vkInputSanityCheck((V2VK_BASE_CONTEXT*)vcc)) {
        V2vkConnectorCleanup(vcc);
        return STATUS_UNSUCCESSFUL;
    }

    status = V2vkConnect(vcc, vcc->asvp);
    if (!NT_SUCCESS(status)) {
        V2vkConnectorCleanup(vcc);
        return status;
    }

    /* This runs the main processing loop, when it is done we disconnect
       and cleanup regardless of what may have occured */
    if (vcc->flags & V2V_KERNEL_ASYNC)
        status = V2vkConnectorProcessMessagesAsync(vcc);
    else
        status = V2vkConnectorProcessMessagesSync(vcc);

    V2vkConnectorDisconnect(vcc);

    V2vkConnectorCleanup(vcc);

    return status;
}

/************************* LISTENER **************************/

static NTSTATUS
V2vListenAccept(V2VK_LISTENER_CONTEXT *vlc, struct v2v_async *asv)
{
    NTSTATUS status, status2;

    /* Start the listener, get back a channel handle */
    status = v2v_listen(vlc->localPrefix, &vlc->channel, 0, 0, asv);
    if (!NT_SUCCESS(status)) {
        DbgPrint("%s listener(%p) failure in v2v_listen() - error: 0x%x\n", V2VDRV_LOGTAG, vlc, status);
        return status;
    }

    ASSERT(vlc->channel != NULL);
    DbgPrint("%s listener(%p) listener started, wait to accept...\n", V2VDRV_LOGTAG, vlc);
    
    /* Wait to accept the connection from the connector end */
    status = v2v_accept(vlc->channel);
    if (!NT_SUCCESS(status)) {
        if (status != STATUS_VIRTUAL_CIRCUIT_CLOSED)
            DbgPrint("%s listener(%p) failure in v2v_accept() - error: 0x%x\n", V2VDRV_LOGTAG, vlc, status);
        else
            DbgPrint("%s listener(%p) remote end disconnected while waiting to accept\n", V2VDRV_LOGTAG, vlc);
        
        status2 = v2v_disconnect(vlc->channel);
        if (!NT_SUCCESS(status2)) {
            DbgPrint("%s listener(%p) secondary failure in v2v_disconnect() after accept failed - error: 0x%x\n",
                     V2VDRV_LOGTAG, vlc, status2);
        }
        return status;
    }
   
    DbgPrint("%s listener(%p) accepted connection, ready to process incoming data.\n", V2VDRV_LOGTAG, vlc);
    return STATUS_SUCCESS;
}

static void
V2vkListenerDisconnect(V2VK_LISTENER_CONTEXT *vlc)
{
    NTSTATUS status;
    ULONG i = 0;
    struct _V2V_LISTENER_RESP_ITEM *resp;

    DbgPrint("%s listener(%p) Disconnecting...\n", V2VDRV_LOGTAG, vlc);
    status = v2v_disconnect(vlc->channel);
    DbgPrint("%s listener(%p) Disconnected - status: 0x%x\n", V2VDRV_LOGTAG, vlc, status);

    DbgPrint("%s listener(%p) Sent message counter: %d\n", V2VDRV_LOGTAG, vlc, vlc->txCounter);
    DbgPrint("%s listener(%p) Received response counter: %d\n", V2VDRV_LOGTAG, vlc, vlc->rxCounter);
    if (vlc->txCounter != vlc->rxCounter)
        DbgPrint("%s listener(%p) WARNING Response count does not match the send count\n", V2VDRV_LOGTAG, vlc);

    if (vlc->xfer == XferTypeInternal) {
        while (vlc->u.xferInternal.respList) {
            resp = vlc->u.xferInternal.respList;
            vlc->u.xferInternal.respList = resp->next;
            ExFreePoolWithTag(resp, V2VDRV_TAG);
            i++;
        }
        if (i > 0)
            DbgPrint("%s listener(%p) WARNING Found %d unsent responses\n", V2VDRV_LOGTAG, vlc, i);
    }
}

static void
V2vkListenerCleanup(V2VK_LISTENER_CONTEXT *vlc)
{
    if ((vlc->xfer == XferTypeFile)&&(vlc->u.xferFile.hf))
        ZwClose(vlc->u.xferFile.hf);
}

NTSTATUS
V2vkRunListener(FILE_OBJECT *pfo)
{
    NTSTATUS status = STATUS_SUCCESS;
    LARGE_INTEGER length, offset;
    V2VK_LISTENER_CONTEXT *vlc = (V2VK_LISTENER_CONTEXT*)pfo->FsContext;    

    ASSERT(vlc != NULL);
    DbgPrint("%s listener(%p) starting %s for transfer type: %s\n", V2VDRV_LOGTAG, vlc,
             (vlc->flags & V2V_KERNEL_ASYNC) ? "ASYNC" : "SYNC",
             (vlc->xfer == XferTypeInternal) ? "Internal" : "File");
    
    if (vlc->xfer == XferTypeFile) {
        status = V2vkCreateFile(&vlc->u.xferFile.fileName,
                                V2V_FILE_OPEN_WRITE,
                                &vlc->u.xferFile.hf,
                                &length,
                                &offset);
        if (!NT_SUCCESS(status)) {
            DbgPrint("%s listener(%p) failed to open file %.*ws\n", V2VDRV_LOGTAG, vlc,
                vlc->u.xferFile.fileName.Length >> 1, vlc->u.xferFile.fileName.Buffer);
            return status;
        }
    }

    if (!V2vkInputSanityCheck((V2VK_BASE_CONTEXT*)vlc)) {
        V2vkListenerCleanup(vlc);
        return STATUS_UNSUCCESSFUL;
    }

    status = V2vListenAccept(vlc, vlc->asvp);
    if (!NT_SUCCESS(status)) {
        V2vkListenerCleanup(vlc);
        return status;
    }

    /* This runs the main processing loop, when it is done we disconnect
       and cleanup regardless of what may have occured */
    if (vlc->flags & V2V_KERNEL_ASYNC)
        status = V2vkListenerProcessMessagesAsync(vlc);
    else
        status = V2vkListenerProcessMessagesSync(vlc);

    V2vkListenerDisconnect(vlc);

    V2vkListenerCleanup(vlc);

    return status;
}

/*************************** MAIN ****************************/

NTSTATUS
V2vkCreateContext(FILE_OBJECT *pfo)
{
    V2V_ROLE_TYPE role = RoleTypeUnknown;
    V2V_XFER_TYPE xfer = XferTypeUnknown;    
    UNICODE_STRING path;
    V2VK_BASE_CONTEXT *vbc;
    ULONG size;

    do {
        RtlInitUnicodeString(&path, L"\\connector\\internal");
        if (RtlCompareUnicodeString(&pfo->FileName, &path, FALSE) == 0) {
            role = RoleTypeConnector;
            xfer = XferTypeInternal;            
            break;
        }
        RtlInitUnicodeString(&path, L"\\connector\\file");
        if (RtlCompareUnicodeString(&pfo->FileName, &path, FALSE) == 0) {
            role = RoleTypeConnector;
            xfer = XferTypeFile;            
            break;
        }
        RtlInitUnicodeString(&path, L"\\listener\\internal");
        if (RtlCompareUnicodeString(&pfo->FileName, &path, FALSE) == 0) {
            role = RoleTypeListener;
            xfer = XferTypeInternal;            
            break;
        }
        RtlInitUnicodeString(&path, L"\\listener\\file");
        if (RtlCompareUnicodeString(&pfo->FileName, &path, FALSE) == 0) {
            role = RoleTypeListener;
            xfer = XferTypeFile;
        }
    } while (FALSE);
    
    if (role == RoleTypeUnknown)
        return STATUS_NO_SUCH_FILE;

    if (role == RoleTypeConnector)
        size = sizeof(V2VK_CONNECTOR_CONTEXT);
    else
        size = sizeof(V2VK_LISTENER_CONTEXT);

    pfo->FsContext = ExAllocatePoolWithTag(NonPagedPool, size, V2VDRV_TAG);
    memset(pfo->FsContext, 0, size);
    if (!pfo->FsContext)
        return STATUS_NO_MEMORY;

    vbc = (V2VK_BASE_CONTEXT*)pfo->FsContext;
    vbc->pfo = pfo;
    vbc->role = role;
    vbc->xfer = xfer;

    DbgPrint("%s Created context %p for v2v file %.*ws\n", V2VDRV_LOGTAG, vbc,
             pfo->FileName.Length >> 1, pfo->FileName.Buffer);
    return STATUS_SUCCESS;
}

NTSTATUS
V2vkDestroyContext(FILE_OBJECT *pfo)
{
    V2VK_BASE_CONTEXT *vbc = (V2VK_BASE_CONTEXT*)pfo->FsContext;

    ASSERT(vbc != NULL);

    if (vbc->flags & V2V_KERNEL_ASYNC)
        V2vkCleanupAsync(vbc);
    else
        V2vkCleanupSync(vbc);

    if (vbc->hasFilePath) {
        RtlFreeUnicodeString(((vbc->role == RoleTypeConnector) ? 
                &((V2VK_CONNECTOR_CONTEXT*)vbc)->u.xferFile.fileName :
                &((V2VK_LISTENER_CONTEXT*)vbc)->u.xferFile.fileName));
    }
    
    if (vbc->localPrefix)
         ExFreePoolWithTag(vbc->localPrefix, V2VDRV_TAG);

    ExFreePoolWithTag(pfo->FsContext, V2VDRV_TAG);
    pfo->FsContext = NULL;

    DbgPrint("%s Destroyed context %p\n", V2VDRV_LOGTAG, vbc);
    return STATUS_SUCCESS;
}

static NTSTATUS
V2vkCopyLocalPrefix(const char *localPrefix, V2VK_BASE_CONTEXT *vbc)
{
    NTSTATUS status;
    size_t len;
    char *prefix;

    status = RtlStringCchLengthA(localPrefix, V2V_MAX_IOCTL_STRING, &len);
    if (!NT_SUCCESS(status))
        return status;

    prefix = ExAllocatePoolWithTag(NonPagedPool, len + 1, V2VDRV_TAG);
    if (!prefix)
        return STATUS_NO_MEMORY;

    status = RtlStringCchCopyNA(prefix, len + 1, localPrefix, len);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(prefix, V2VDRV_TAG);
        return status;
    }
    vbc->localPrefix = prefix;

    return STATUS_SUCCESS;
}

NTSTATUS
V2vkInitInternalXfer(FILE_OBJECT *pfo, V2VK_IOCD_INIT_INTERNAL_XFER *iixfer)
{
    NTSTATUS status;
    V2VK_BASE_CONTEXT *vbc = (V2VK_BASE_CONTEXT*)pfo->FsContext;
    V2VK_CONNECTOR_CONTEXT *vcc;

    ASSERT(vbc != NULL);
    if (vbc->xfer != XferTypeInternal)
        return STATUS_INVALID_PARAMETER;

    vbc->flags = iixfer->flags;

    status = V2vkCopyLocalPrefix(iixfer->localPrefix, vbc);
    if (!NT_SUCCESS(status))
        return status;

    if (vbc->role == RoleTypeConnector) {
        vcc = (V2VK_CONNECTOR_CONTEXT*)vbc;
        vcc->xferTimeout = iixfer->xferTimeout;
        vcc->xferSize = iixfer->xferSize;
        vcc->u.xferInternal.count = iixfer->xferCount;
    }

    if (vbc->flags & V2V_KERNEL_FASTRX)
        vbc->xferMaxFastRx = iixfer->xferMaxFastRx;

    if (vbc->flags & V2V_KERNEL_ASYNC)
        V2vkInitializeAsync(vbc);
    else
        V2vkInitializeSync(vbc);

    DbgPrint("%s Initialized context %p for internal transfer.\n", V2VDRV_LOGTAG, vbc);
    return STATUS_SUCCESS;
}

NTSTATUS
V2vkInitFileXfer(FILE_OBJECT *pfo, V2VK_IOCD_INIT_FILE_XFER *ifxfer)
{
    NTSTATUS status;
    V2VK_BASE_CONTEXT *vbc = (V2VK_BASE_CONTEXT*)pfo->FsContext;
    V2VK_CONNECTOR_CONTEXT *vcc;

    ASSERT(vbc != NULL);
    if (vbc->xfer != XferTypeFile)
        return STATUS_INVALID_PARAMETER;

    vbc->flags = ifxfer->flags;

    status = V2vkCopyLocalPrefix(ifxfer->localPrefix, vbc);
    if (!NT_SUCCESS(status))
        return status;

    if (vbc->role == RoleTypeConnector) {
        vcc = (V2VK_CONNECTOR_CONTEXT*)vbc;
        vcc->xferTimeout = ifxfer->xferTimeout;
        vcc->xferSize = ifxfer->xferSize;
    }

    status = V2vkCreateFilePath(ifxfer->filePath,
        ((vbc->role == RoleTypeConnector) ? 
            &((V2VK_CONNECTOR_CONTEXT*)vbc)->u.xferFile.fileName :
            &((V2VK_LISTENER_CONTEXT*)vbc)->u.xferFile.fileName));
    if (NT_SUCCESS(status))
        vbc->hasFilePath = TRUE;

    if (vbc->flags & V2V_KERNEL_FASTRX)
        vbc->xferMaxFastRx = ifxfer->xferMaxFastRx;

    if (vbc->flags & V2V_KERNEL_ASYNC)
        V2vkInitializeAsync(vbc);
    else
        V2vkInitializeSync(vbc);

    DbgPrint("%s Initialized context %p for file transfer.\n", V2VDRV_LOGTAG, vbc);
    return status;
}
