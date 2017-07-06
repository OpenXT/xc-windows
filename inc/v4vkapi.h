#ifdef USE_V4V
//
// v4vkm.h - Xen Windows XenGfx v4v
//
// Copyright (c) 2010 Citrix, Inc.
//

/*
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

/*
 *  This the kernel version of v4vapi. See the documentation in v4vapi.h for usage.
*/
#pragma  once
#define V4V_EXCLUDE_INTERNAL
#define XENV4V_DRIVER
#include <ntddk.h>
#include <windef.h>
#include "v4vapi.h"
#include <xen.h>
#include "xsapi.h"

// A pool tag
#define XENV4V_TAG              'V4VX'
#define V4V_EVENT_NAME          L"\\KernelObjects\\xenv4vEvent"
#define _XENGFX_V4V_RING_PORT   4700
#define XENWNET_V4V_RING_PORT   3062

/* Typedef for internal stream header structure */
typedef struct v4v_stream_header V4V_STREAM, *PV4V_STREAM;

typedef struct _V4V_CONTEXT
{
    HANDLE v4vHandle; /* handle for open V4V file */
    PKEVENT recvEvent; /* data arrival, new connection for accept */
    HANDLE recvEventHandle; /* data arrival, new connection for accept */
    ULONG  flags;     /* configuration flags set by caller */
} V4V_CONTEXT, *PV4V_CONTEXT;

typedef enum _V4V_STATUS_TYPE {
    V4vUnintialized = 1,
    V4vOpen,
    V4vClosed,
    V4vBound,
    V4vConnected,
    V4vDisconnected,
    V4vError
}V4V_STATUS_TYPE, *pV4V_STATUS_TYPE;

typedef struct  _XEN_V4V {
    V4V_CONTEXT             ctx;
    PFILE_OBJECT            pFileObject;
    PDEVICE_OBJECT          pDevObject;
    V4V_STATUS_TYPE         state;
}XEN_V4V, *PXEN_V4V;

HANDLE  __inline NTAPI V4VHandle(PXEN_V4V xenV4v) {return xenV4v->ctx.v4vHandle;}
void    __inline NTAPI V4VSetFlag (PXEN_V4V xenV4v, ULONG flags) {xenV4v->ctx.flags = flags;}
ULONG   __inline NTAPI V4VFlag (PXEN_V4V xenV4v) {return xenV4v->ctx.flags;}
void    __inline NTAPI V4VSetState (PXEN_V4V xenV4v, V4V_STATUS_TYPE state) {xenV4v->state = state;}
V4V_STATUS_TYPE __inline NTAPI  V4VState(PXEN_V4V xenV4v) {return xenV4v->state;}

static __inline  NTSTATUS
XenV4vDevObject(PXEN_V4V pV4v)
{
    NTSTATUS        status;
    UNICODE_STRING  devName;

    RtlInitUnicodeString(&devName, V4V_DEVICE_NAME);
    status = IoGetDeviceObjectPointer (&devName, 
        FILE_READ_DATA,
        &pV4v->pFileObject,
        &pV4v->pDevObject);
    if (status != STATUS_SUCCESS) {
        TraceError (( "%s IoGetDeviceObjectPointer with %d\n", __FUNCTION__, status));
    }
    return status;
};

static __inline PIRP
XenV4VBuildIOCTL(PXEN_V4V pV4v, ULONG ioctl, PKEVENT hIOCTL,
                PVOID InputBuffer, ULONG InputBufferLength, 
                PVOID OutputBuffer, ULONG OutputBufferLength
                )
{
    PIRP    pIrp;
    IO_STATUS_BLOCK status;

    pIrp = IoBuildDeviceIoControlRequest(ioctl, 
        pV4v->pDevObject, InputBuffer, InputBufferLength,
        OutputBuffer, OutputBufferLength, FALSE, hIOCTL,
        &status);
    if (!pIrp ) {
        TraceError (( "%s IoBuildDeviceIoControlRequest failed\n", __FUNCTION__));
    }
    return pIrp;
}

static __inline  PIO_STACK_LOCATION 
XenV4VIRPStack(PXEN_V4V pV4v, PIRP pIrp)
{
    PIO_STACK_LOCATION  stack;

    stack = IoGetNextIrpStackLocation(pIrp);  
    stack->MajorFunction = IRP_MJ_DEVICE_CONTROL;
    stack->DeviceObject = pV4v->pDevObject;
    stack->FileObject = pV4v->pFileObject;
    return stack;
}

extern  NTSTATUS ZwCreateEvent( PHANDLE EventHandle, ACCESS_MASK DesiredAccess, 
    POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState);

static __inline  HANDLE 
XenV4VCreateEvent(PXEN_V4V pV4v, PUNICODE_STRING drvName)
{
    NTSTATUS        status;
    ULONG           attributes;
    HANDLE          hIOCTL = 0;
    OBJECT_ATTRIBUTES   oa;
    BOOLEAN state = TRUE;

    UNREFERENCED_PARAMETER (pV4v);

    attributes = OBJ_OPENIF;
    InitializeObjectAttributes(&oa, drvName, attributes, NULL, NULL);
    status = ZwCreateEvent (&hIOCTL, EVENT_ALL_ACCESS, &oa, SynchronizationEvent, state );
    if (!NT_SUCCESS(status))
        hIOCTL = (HANDLE)0;
    return hIOCTL;
}

static __inline  PKEVENT
XenV4VCreateKEvent(PHANDLE pHIOCTL)
{
    UNICODE_STRING  eventName;
    ULONG           attributes;
    PKEVENT         pKEvent;
    OBJECT_ATTRIBUTES   oa;

    RtlInitUnicodeString(&eventName, L"");
    attributes = OBJ_OPENIF | OBJ_KERNEL_HANDLE;
    InitializeObjectAttributes(&oa, &eventName, attributes, NULL, NULL);
    pKEvent = IoCreateSynchronizationEvent(&eventName, pHIOCTL);
    if (!pKEvent) {
        pKEvent = IoCreateSynchronizationEvent(&eventName, pHIOCTL);
        TraceError (( "%s IoCreateSynchronizationEvent failed\n", __FUNCTION__));
        pKEvent =  NULL;
    }
    return pKEvent;
}

static __inline  NTSTATUS
XenV4VInitDev(PXEN_V4V pV4v, size_t ringSize)
{
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    V4V_INIT_VALUES     init = {0};
    HANDLE              hIOCTL = 0;
    HANDLE              hEvent = 0;
    PIO_STACK_LOCATION  stack;
    UNICODE_STRING      drvName;
    PKEVENT             pkIOCTL;
    PIRP                pIrp;

    do {

        //Event for V4v
        RtlInitUnicodeString(&drvName, V4V_EVENT_NAME);
        hEvent = XenV4VCreateEvent(pV4v, &drvName); //IoCreateSynchronizationEvent(&drvName, &hIOCTL);
        init.ringLength = (ULONG32)ringSize;
        init.rxEvent = hEvent;
        if (init.rxEvent == NULL) {
            TraceError (( "%s IoCreateSynchronizationEvent failed\n", __FUNCTION__));
            break;
        }
        //KEvent for ioctl call
        pkIOCTL = XenV4VCreateKEvent(&hIOCTL);
        if (!pkIOCTL)
            break;
        pIrp = XenV4VBuildIOCTL(pV4v, V4V_IOCTL_INITIALIZE, pkIOCTL, &init, sizeof(init), NULL, 0);
        if (!pIrp) break;

        stack = XenV4VIRPStack(pV4v, pIrp);
        status = IoCallDriver(pV4v->pDevObject, pIrp);
        if (status != STATUS_SUCCESS && status != STATUS_PENDING) {
            TraceError( ("%s IoCallDriver failed with %d\n", __FUNCTION__, status));
            status = STATUS_UNSUCCESSFUL;
            break;
        }else {
            status = ObReferenceObjectByHandle(init.rxEvent,
                                           EVENT_MODIFY_STATE,
                                           *ExEventObjectType,
                                           KernelMode,
                                           (void **)&pV4v->ctx.recvEvent,
                                           NULL);
            pV4v->ctx.recvEventHandle = init.rxEvent;
        }
    }while (FALSE);

    if (!NT_SUCCESS(status)) {
        if (init.rxEvent) ZwClose(init.rxEvent);
    } else
        pV4v->state = V4vOpen;

    if (hIOCTL) 
        ZwClose(hIOCTL);
    return status;
}

static __inline  NTSTATUS
XenV4VConnectWait(PXEN_V4V pV4v)
{
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    V4V_WAIT_VALUES     connect;
    PIRP                pIrp;
    HANDLE              hIOCTL = 0;
    PKEVENT             pKEvent;
    PIO_STACK_LOCATION  pStack;

    do {
        RtlZeroMemory(&connect, sizeof(V4V_WAIT_VALUES));

        pKEvent = XenV4VCreateKEvent(&hIOCTL);
        pIrp = XenV4VBuildIOCTL(pV4v, V4V_IOCTL_WAIT, pKEvent,
            &connect, sizeof(V4V_WAIT_VALUES),
            NULL, 0);

        pStack = XenV4VIRPStack(pV4v, pIrp);
        status = IoCallDriver(pV4v->pDevObject, pIrp);

        if (status != STATUS_SUCCESS) {
            TraceError( ("%s IoCallDriver failed with %d\n", __FUNCTION__, status));
            break;
        }
    }while (FALSE);

    ZwClose(hIOCTL);
    return status;
}

__inline  NTSTATUS
XenV4VConnect(PXEN_V4V pV4v, domid_t toDomain, uint32_t port)
{
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    V4V_CONNECT_VALUES  connect;
    PIRP                pIrp;
    HANDLE              hIOCTL = 0;
    PKEVENT             pKEvent;
    PIO_STACK_LOCATION  pStack;

    do {
        RtlZeroMemory(&connect, sizeof(V4V_CONNECT_VALUES));
        connect.ringAddr.domain = toDomain;
        connect.ringAddr.port = port;
        pKEvent = XenV4VCreateKEvent(&hIOCTL);
        pIrp = XenV4VBuildIOCTL(pV4v, V4V_IOCTL_CONNECT, pKEvent,
            &connect, sizeof(V4V_CONNECT_VALUES),
            NULL, 0);

        pStack = XenV4VIRPStack(pV4v, pIrp);
        status = IoCallDriver(pV4v->pDevObject, pIrp);
        if (status == STATUS_PENDING) {
            status = KeWaitForSingleObject(pKEvent, Executive, KernelMode, FALSE, NULL);
        }
        if (status != STATUS_SUCCESS) {
            TraceError( ("%s IoCallDriver failed with %d\n", __FUNCTION__, status));
            break;
        }
    }while (FALSE);

    pV4v->state = V4vConnected;
    ZwClose(hIOCTL);
    return status;
}

__inline  NTSTATUS
XenV4VDisconnect(PXEN_V4V  pV4v)
{
    PIO_STACK_LOCATION  pStack;
    PKEVENT             pKEvent;
    PIRP                pIrp;
    HANDLE              hIOCTL = 0;
    NTSTATUS            status = STATUS_UNSUCCESSFUL;

    do {
        pKEvent = XenV4VCreateKEvent(&hIOCTL);
        pIrp = XenV4VBuildIOCTL(pV4v, V4V_IOCTL_DISCONNECT, 
            pKEvent, NULL, 0, NULL, 0);
        pStack = XenV4VIRPStack(pV4v, pIrp);
        status = IoCallDriver(pV4v->pDevObject, pIrp);
        if (status == STATUS_PENDING) {
            status = KeWaitForSingleObject(pKEvent, Executive, KernelMode, FALSE, NULL);
        }
        if (!NT_SUCCESS(status)) {
            TraceError(("%s IoCallDriver failed with %d\n", __FUNCTION__, status));
            break;
        }
    }while (FALSE);

    if (NT_SUCCESS(status))
        pV4v->state = V4vDisconnected;
    else
        pV4v->state = V4vError;
    ZwClose(hIOCTL);
    return status;
}

__inline  NTSTATUS
XenV4VClose(PXEN_V4V pV4v)
{
    NTSTATUS status;

    ObDereferenceObject(pV4v->ctx.recvEvent);

    do {
        status = ZwClose(pV4v->ctx.recvEventHandle);
        if (!NT_SUCCESS(status)) break;

        status = ZwClose(pV4v->ctx.v4vHandle);
        if (!NT_SUCCESS(status)) break;
    } while(FALSE);

    if (!NT_SUCCESS(status))
        pV4v->state = V4vError;
    else
        pV4v->state = V4vClosed;

    return status;
}

__inline  NTSTATUS
XenV4VWrite(PXEN_V4V pV4v, PVOID buf, UINT len, PIO_STATUS_BLOCK iosb)
{
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    PIRP                pIrp;
    HANDLE              hIOCTL = 0;
    PKEVENT             pKEvent;
    PIO_STACK_LOCATION  stack;

    do {
        pKEvent = XenV4VCreateKEvent(&hIOCTL);
        pIrp = IoBuildSynchronousFsdRequest(IRP_MJ_WRITE, 
            pV4v->pDevObject, buf, len,
            NULL, pKEvent,
            iosb);
        if (!pIrp ) {
            TraceError (( "%s IoBuildSynchronousFsdRequest failed\n", __FUNCTION__));
            break;
        }

        stack = IoGetNextIrpStackLocation(pIrp);
        stack->DeviceObject = pV4v->pDevObject;
        stack->FileObject = pV4v->pFileObject;
        status = IoCallDriver(pV4v->pDevObject, pIrp);

        if (status == STATUS_PENDING) {
            status = KeWaitForSingleObject(pKEvent, Executive, KernelMode, FALSE, NULL);
        }

        if (status != STATUS_SUCCESS) {
            TraceError( ("%s IoCallDriver failed with %d\n", __FUNCTION__, status));
            break;
        }
    }while (FALSE);

    ZwClose(hIOCTL);
    return status;
}

__inline  NTSTATUS
XenV4VRead(PXEN_V4V pV4v, PVOID buf, UINT len, PIO_STATUS_BLOCK iosb)
{
    NTSTATUS            status = STATUS_UNSUCCESSFUL;
    PIRP                pIrp;
    HANDLE              hIOCTL = 0;
    PKEVENT             pKEvent;
    PIO_STACK_LOCATION  stack;

    do {
        pKEvent = XenV4VCreateKEvent(&hIOCTL);
        pIrp = IoBuildSynchronousFsdRequest(IRP_MJ_READ,
            pV4v->pDevObject, buf, len,
            NULL, pKEvent,
            iosb);
        if (!pIrp ) {
            TraceError (( "%s IoBuildSynchronousFsdRequest failed\n", __FUNCTION__));
            break;
        }

        stack = IoGetNextIrpStackLocation(pIrp);
        stack->DeviceObject = pV4v->pDevObject;
        stack->FileObject = pV4v->pFileObject;
        status = IoCallDriver(pV4v->pDevObject, pIrp);

        if (status == STATUS_PENDING) {
            status = KeWaitForSingleObject(pKEvent, Executive, KernelMode, FALSE, NULL);
        }

        if (status != STATUS_SUCCESS) {
            TraceError( ("%s IoCallDriver failed with %d\n", __FUNCTION__, status));
            break;
        }
    }while (FALSE);

    ZwClose(hIOCTL);
    return status;
}

__inline  NTSTATUS
XenV4VBind(PXEN_V4V pV4v, domid_t toDomain, uint32_t port)
{
    NTSTATUS            status = STATUS_SUCCESS;
    v4v_ring_id_t       v4vid;
    V4V_BIND_VALUES     bind;
    PIRP                pIrp;
    HANDLE              hIOCTL = 0;
    PKEVENT             pkIOCTL;
    PIO_STACK_LOCATION  pStack;

    do {


        //Format Bind IOCTL
        v4vid.addr.domain = V4V_DOMID_NONE;
        v4vid.addr.port = port;
        v4vid.partner = toDomain;
        RtlCopyMemory(&bind.ringId, &v4vid, sizeof(v4v_ring_id_t));

        pkIOCTL= XenV4VCreateKEvent(&hIOCTL);
        pIrp = XenV4VBuildIOCTL(pV4v, V4V_IOCTL_BIND, pkIOCTL, &bind, sizeof(V4V_BIND_VALUES), 
            NULL, 0);
        if (!pIrp)break;

        //Call Bind IOCTL
        pStack = XenV4VIRPStack(pV4v, pIrp);
        status = IoCallDriver(pV4v->pDevObject, pIrp);
        if (status != STATUS_SUCCESS && status != STATUS_PENDING ) {
            TraceError (( "%s IoCallDriver failed with %d\n", __FUNCTION__, status));
            status = STATUS_UNSUCCESSFUL;
            break;
        }
    }while (FALSE);

    if (hIOCTL) ZwClose(hIOCTL);
    return status;
}

__inline  NTSTATUS
XenV4VOpenDgramPort (PXEN_V4V pV4v, size_t ringSize, domid_t domain, uint32_t port)
{
    NTSTATUS            status;
    OBJECT_ATTRIBUTES   oa;
    HANDLE              hd = 0;
    ULONG               attributes;
    IO_STATUS_BLOCK     ioStatus;
    UNICODE_STRING      devName;

    RtlInitUnicodeString(&devName, V4V_DEVICE_NAME);
    attributes = OBJ_OPENIF | OBJ_KERNEL_HANDLE;
    InitializeObjectAttributes( &oa, 
        &devName,
        attributes,
        NULL, NULL);

    do {

        status = ZwCreateFile(&hd,  GENERIC_READ|GENERIC_WRITE, &oa, &ioStatus, NULL,
            FILE_ATTRIBUTE_NORMAL, 
            FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_NO_INTERMEDIATE_BUFFERING |FILE_SYNCHRONOUS_IO_ALERT,
            NULL, 0);

        if(!NT_SUCCESS(status)){
            TraceError (("%s unable to open v4v with error 0x%x\n", __FUNCTION__, status));
            break;

        } else {
            OBJECT_HANDLE_INFORMATION hdInfo;
            status = ObReferenceObjectByHandle(hd, EVENT_ALL_ACCESS, *IoFileObjectType, KernelMode,
                (PVOID *)&pV4v->pFileObject, &hdInfo);
            pV4v->pDevObject = pV4v->pFileObject->DeviceObject;
        }

        status = XenV4VInitDev(pV4v, ringSize);
        if (status != STATUS_SUCCESS) 
            break;

        status = XenV4VBind(pV4v, domain, port);
        if (status != STATUS_SUCCESS)
            break;

    }while (FALSE);

    if (status != STATUS_SUCCESS) {
        if (hd) ZwClose(hd);
        if (pV4v->ctx.recvEventHandle) ZwClose(pV4v->ctx.recvEventHandle);
    } else {
        pV4v->ctx.v4vHandle = hd;
    }
    return status;
}

__inline  NTSTATUS
XenV4VOpenDevice(PXEN_V4V pV4v, size_t ringSize, domid_t domain, uint32_t port)
{
    NTSTATUS            status;
    OBJECT_ATTRIBUTES   oa;
    HANDLE              hd = 0;
    ULONG               attributes;
    IO_STATUS_BLOCK     ioStatus;
    UNICODE_STRING      devName;

    RtlInitUnicodeString(&devName, V4V_DEVICE_NAME);
    attributes = OBJ_OPENIF | OBJ_KERNEL_HANDLE;
    InitializeObjectAttributes( &oa, 
        &devName,
        attributes,
        NULL, NULL);

    do {

        status = ZwCreateFile(&hd,  GENERIC_READ|GENERIC_WRITE, &oa, &ioStatus, NULL,
            FILE_ATTRIBUTE_NORMAL, 
            FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_NO_INTERMEDIATE_BUFFERING |FILE_SYNCHRONOUS_IO_ALERT,
            NULL, 0);

        if(!NT_SUCCESS(status)){
            TraceError (("%s unable to open v4v with error 0X%x\n", __FUNCTION__, status));
            break;

        } else {
            OBJECT_HANDLE_INFORMATION hdInfo;
            status = ObReferenceObjectByHandle(hd, EVENT_ALL_ACCESS, *IoFileObjectType, KernelMode,
                (PVOID *)&pV4v->pFileObject, &hdInfo);
            pV4v->pDevObject = pV4v->pFileObject->DeviceObject;
        }

        status = XenV4VInitDev(pV4v, ringSize);
        if (status != STATUS_SUCCESS) 
            break;

        status = XenV4VBind(pV4v, domain, port);
        if (status != STATUS_SUCCESS)
            break;

        status = XenV4VConnect(pV4v, domain, port);
        if (status != STATUS_SUCCESS)
            break;

    }while (FALSE);

    if (status != STATUS_SUCCESS) {
        if (hd) ZwClose(hd);
        if (pV4v->ctx.recvEventHandle) ZwClose(pV4v->ctx.recvEventHandle);
    } else {
        pV4v->ctx.v4vHandle = hd;
    }
    return status;
}

__inline  void
XenV4VDestroy(PXEN_V4V pV4v)
{
    if (pV4v) {
        ExFreePoolWithTag(pV4v, XENV4V_TAG );
    }
}
#endif
