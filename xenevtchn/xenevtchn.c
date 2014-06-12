//
// xenevtchn.c - Xen event channel driver.
//
// Copyright (c) 2006 XenSource, Inc. - All rights reserved.
//

/*
 * Copyright (c) 2014 Citrix Systems, Inc.
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


#include "ntifs.h"
#include "xenevtchn.h"
#include "pnp.h"
#include "xs_ioctl.h"
#include "scsiboot.h"

// These should not be here. Code requiring them will eventually
// move into xenutil
#include "../xenutil/hvm.h"
#include "../xenutil/hypercall.h"
#include "../xenutil/debug.h"
#include "../xenutil/balloon.h"
#include "../xenutil/xenutl.h"
#include "../xenutil/evtchn.h"

#include <hvm_params.h>

#include "xenevtchn_wpp.h"
#include "xenevtchn.tmh"

#define MIN(a,b) ((a)<(b)?(a):(b))

//
// Dont care about unreferenced formal parameters here
//
#pragma warning( disable : 4100 )

#define XEVC_TAG 'CVEX'

PDRIVER_OBJECT XenevtchnDriver;

//
// Function prototypes
//
NTSTATUS
DriverEntry(
    IN PVOID DriverObject,
    IN PVOID Argument2
);

DRIVER_ADD_DEVICE XenevtchnAddDevice;
DRIVER_DISPATCH XenevtchnDispatchPnp;
DRIVER_DISPATCH XenevtchnDispatchWmi;
DRIVER_DISPATCH XenevtchnDispatchPower;

extern PULONG InitSafeBootMode;

static VOID
XenevtchnProcessNotifyHandler (
    IN HANDLE  ParentId,
    IN HANDLE  ProcessId,
    IN BOOLEAN  Create
    )
{
    KAPC_STATE apcState;
    static int have_process_create = 1;
    PKPROCESS process;
    NTSTATUS status;
    xen_hvm_xentrace_t trace;
    ULONG_PTR cr3;

    /* 2 -> Have new process destroy, 1 -> have old process destroy,
       0 -> don't have any process destroy */
    /* Xen 4.1: No longer has process destory HVM_op
    static int have_process_destroy = 0;*/

    if (Create != TRUE) {
        /* Xen 4.1: No process destroy HVM op any longer
        if (have_process_destroy) {
            p.cr3 = _readcr3();
            if (have_process_destroy == 2) {
                if ((int)HYPERVISOR_hvm_op(HVMOP_process_destroy, &p) < 0)
                    have_process_destroy = 1;
            }
            if (have_process_destroy == 1) {
                if ((int)HYPERVISOR_hvm_op(HVMOP_process_destroy_compat, &p) < 0)
                    have_process_destroy = 0;
            }
        }*/

        XevtchnProcessCleanup();

        goto exit;
    }

    //
    // Handle process create.
    //

    if (!XenPVFeatureEnabled(DEBUG_TRACE_PROCESS_CREATE)) {
        goto exit;
    }

    if (!have_process_create) {
        goto exit;
    }

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        TraceError(("Failed (0x%08x) to get pointer to KPROCESS.\n", status)); 
        goto exit;
    }

    KeStackAttachProcess(process, &apcState);
    cr3 = _readcr3();
    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);
    trace.event = HVM_EVENT_PROCESS_CREATE;
    trace.extra_bytes = sizeof(ProcessId) + sizeof(cr3);
    memcpy(&trace.extra[0], &ProcessId, sizeof(ProcessId));
    memcpy(&trace.extra[sizeof(ProcessId)], &cr3, sizeof(cr3));
    if ((int)HYPERVISOR_hvm_op(HVMOP_xentrace, &trace) < 0) {
        have_process_create = 0;
    }

exit:
    return;
}

static VOID
XenevtchnImageNotifyHandler (
    IN PUNICODE_STRING  FullImageName,
    IN HANDLE           ProcessId,
    IN PIMAGE_INFO      ImageInfo
    )
{
    ANSI_STRING ansiString;
    static int have_image_load = 1;
    ULONG length;
    CHAR *p;
    NTSTATUS status;
    xen_hvm_xentrace_t trace;

    if (!XenPVFeatureEnabled(DEBUG_TRACE_IMAGE_LOAD)) {
        //
        // Tracing disabled by user.
        //
        goto exit;
    }

    if (!have_image_load) {
        //
        // Xen does not support trace hypercall.
        //
        goto exit;
    }

    if (!wcsstr(FullImageName->Buffer, L".exe")) {
        //
        // Skip non-executables.
        //
        goto exit;
    }

    status = RtlUnicodeStringToAnsiString(&ansiString, FullImageName, TRUE);
    if (NT_SUCCESS(status)) {
        p = strrchr(ansiString.Buffer, '\\');
        if (p) {
            length = ansiString.Length - (ULONG)(p - ansiString.Buffer);
            p++;
            trace.event = HVM_EVENT_IMAGE_LOAD;
            trace.extra_bytes = (uint16_t)MIN(sizeof(trace.extra), 
                                              length + sizeof(ProcessId));

            memcpy(&trace.extra[0], &ProcessId, sizeof(ProcessId));
            memcpy(&trace.extra[sizeof(ProcessId)], 
                   p, 
                   MIN(length, sizeof(trace.extra) - sizeof(ProcessId)));

            if ((int)HYPERVISOR_hvm_op(HVMOP_xentrace, &trace) < 0) {
                have_image_load = 0;
            }
        }

        RtlFreeAnsiString(&ansiString);
    }

exit:
    return;
}

UNICODE_STRING XenevtchnRegistryPath;

static VOID
XenevtchnUnload(
    IN PDRIVER_OBJECT DriverObject
    )
{
    TraceBugCheck(("%s\n", __FUNCTION__));
}

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath
    )
{
    PVOID PathBuffer;
    USHORT PathLength;

    TraceInfo(("%s: IRQL = %d\n", __FUNCTION__, KeGetCurrentIrql()));

    XenevtchnDriver = DriverObject;

    if (!XmCheckXenutilVersionString(TRUE, XENUTIL_CURRENT_VERSION))
        return STATUS_REVISION_MISMATCH;

    if ((*InitSafeBootMode > 0) &&
        (!XenPVFeatureEnabled(DEBUG_HA_SAFEMODE)))
    {
        return STATUS_SUCCESS;
    }

    TraceDebug (("==>\n"));

    WPP_SYSTEMCONTROL(DriverObject); // Needed for win2k

    PathLength = RegistryPath->Length;
    if ((PathBuffer = ExAllocatePoolWithTag(NonPagedPool,
                                            PathLength,
                                            XEVC_TAG)) == NULL) {
        return STATUS_NO_MEMORY;
    }

    XenevtchnRegistryPath.Buffer = PathBuffer;
    XenevtchnRegistryPath.Length = PathLength;
    XenevtchnRegistryPath.MaximumLength = PathLength;

    RtlCopyUnicodeString(&XenevtchnRegistryPath, RegistryPath);

    InitUsermodeInterfaceEarly();

    SuspendPreInit();

    //
    // Cant unload becuase the binary patching engine uses 
    // PsSetLoadImageNotifyRoutine and it doesnt allow for unloading.
    //

    // DriverObject->DriverUnload = XenevtchnUnload;

    //
    // Define the driver's standard entry routines. 
    //

    DriverObject->DriverExtension->AddDevice = XenevtchnAddDevice;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = XenevtchnCreate;
    DriverObject->MajorFunction[IRP_MJ_PNP] = XenevtchnDispatchPnp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = XenevtchnDispatchPower;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = 
        XenevtchnDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = 
        XenevtchnDispatchWmi;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = XenevtchnClose;
    DriverObject->DriverUnload = XenevtchnUnload;

    (VOID) InstallDumpDeviceCallback();

    if (XenPVEnabled()) {
        PsSetCreateProcessNotifyRoutine(XenevtchnProcessNotifyHandler, FALSE);
        if (XenPVFeatureEnabled(DEBUG_TRACE_IMAGE_LOAD)) {
            PsSetLoadImageNotifyRoutine(XenevtchnImageNotifyHandler);
        }
    }

    TraceDebug (("<==\n"));

    return( STATUS_SUCCESS );
}

static VOID
XenEvtchnWppTrace(
    IN  XEN_TRACE_LEVEL Level,
    IN  CHAR            *Message
    )
{
    // Unfortunately DoTraceMessage is a macro and we don't necessarily know
    // what magic is being applied to the FLAG_ argument, so safest to use
    // a switch statement to map from Level to FLAG_ even though it is
    // somewhat inelegant.

    switch (Level) {
    case XenTraceLevelDebug:
        DoTraceMessage(FLAG_DEBUG, "%s", Message);
        break;

    case XenTraceLevelVerbose:
        DoTraceMessage(FLAG_VERBOSE, "%s", Message);
        break;

    case XenTraceLevelInfo:
        DoTraceMessage(FLAG_INFO, "%s", Message);
        break;

    case XenTraceLevelNotice:
        DoTraceMessage(FLAG_NOTICE, "%s", Message);
        break;

    case XenTraceLevelWarning:
        DoTraceMessage(FLAG_WARNING, "%s", Message);
        break;

    case XenTraceLevelError:
        DoTraceMessage(FLAG_ERROR, "%s", Message);
        break;

    case XenTraceLevelCritical:
        DoTraceMessage(FLAG_CRITICAL, "%s", Message);
        break;

    case XenTraceLevelBugCheck:
        DoTraceMessage(FLAG_CRITICAL, "%s", Message);
        break;

    case XenTraceLevelProfile:
        DoTraceMessage(FLAG_PROFILE, "%s", Message);
        break;
    }
}

static DEVICE_OBJECT    *XenevtchnFdo;

static const CHAR *
DeviceUsageName(
    IN  DEVICE_USAGE_NOTIFICATION_TYPE  Type
    )
{
#define _TYPE_NAME(_Type)               \
        case DeviceUsageType ## _Type:  \
            return #_Type;

    switch (Type) {
    _TYPE_NAME(Undefined);
    _TYPE_NAME(Paging);
    _TYPE_NAME(Hibernation);
    _TYPE_NAME(DumpFile);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _TYPE_NAME
}

VOID
XenevtchnSetDeviceUsage(
    IN  DEVICE_USAGE_NOTIFICATION_TYPE  Type,
    IN  BOOLEAN                         On
    )
{
    IO_STACK_LOCATION   *StackLocation;
    IRP                 *Irp;
    KEVENT              Event;
    IO_STATUS_BLOCK     IoStatus;
    NTSTATUS            status;

    XM_ASSERT3U(KeGetCurrentIrql(), <, DISPATCH_LEVEL);

    if (XenevtchnFdo == NULL)
        return;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP, XenevtchnFdo, NULL, 0, NULL, &Event, &IoStatus);

    StackLocation = IoGetNextIrpStackLocation(Irp);
    StackLocation->MinorFunction = IRP_MN_DEVICE_USAGE_NOTIFICATION;
    StackLocation->Parameters.UsageNotification.Type = Type;
    StackLocation->Parameters.UsageNotification.InPath = On;

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    TraceInfo(("%s: issuing IRP (%s,%s)\n", __FUNCTION__, 
               DeviceUsageName(Type),
               (On) ? "ON" : "OFF"));

    status = IoCallDriver(XenevtchnFdo, Irp);
    if (status == STATUS_PENDING)
        KeWaitForSingleObject(&Event,
                              Executive,
                              KernelMode,
                              FALSE,
                              NULL);

    TraceInfo(("%s: completed IRP (%08x)\n", __FUNCTION__,
               IoStatus.Status));
}

NTSTATUS
XenevtchnAddDevice(
    IN PDRIVER_OBJECT DriverObject,
    IN PDEVICE_OBJECT pdo
)
{
    PDEVICE_OBJECT fdo;
    NTSTATUS status;
    UNICODE_STRING name, linkName;
    PXENEVTCHN_DEVICE_EXTENSION pXendx;

    RtlInitUnicodeString(&name, XENEVTCHN_DEVICE_NAME);

    status = IoCreateDevice(DriverObject,
                sizeof(XENEVTCHN_DEVICE_EXTENSION),
                &name, FILE_DEVICE_UNKNOWN,
                FILE_DEVICE_SECURE_OPEN,
                FALSE,
                &fdo);
    if (status != STATUS_SUCCESS) {
        TraceError (("IoCreateDevice failed %d\n", status));
        return status;
    }

    ObReferenceObject(fdo); // We don't want this to go away
    XenevtchnFdo = fdo;

    TraceNotice(("%s: FDO = 0x%p\n", __FUNCTION__, XenevtchnFdo));

    RtlInitUnicodeString( &linkName, XENEVTCHN_FILE_NAME );
    status = IoCreateSymbolicLink( &linkName, &name );
    if ( !NT_SUCCESS( status )) {
        TraceError (("IoCreateSymbolicLink failed %d\n", status));
        IoDeleteDevice( fdo );
        return status;
    }

    pXendx = (PXENEVTCHN_DEVICE_EXTENSION)fdo->DeviceExtension;
    memset(pXendx, 0, sizeof(*pXendx));
    pXendx->DriverObject = DriverObject;
    pXendx->DeviceObject = fdo;
    pXendx->PhysicalDeviceObject = pdo;
    pXendx->LowerDeviceObject = IoAttachDeviceToDeviceStack(fdo, pdo);
    pXendx->Header.Signature = XENEVTCHN_FDO_SIGNATURE;
    InitializeListHead(&pXendx->xenbus_device_classes);
    InitializeListHead(&pXendx->devices);
    InitializeListHead(&pXendx->ActiveHandles);
    ExInitializeFastMutex(&pXendx->xenbus_lock);
    KeInitializeTimer(&pXendx->xenbus_timer);
    KeInitializeDpc(&pXendx->xenbus_dpc, XsRequestInvalidateBus,
                    pXendx);
    KeInitializeSpinLock(&pXendx->ActiveHandleLock);

    // Must start out disabled
    pXendx->UninstEnabled = FALSE;

    InitUsermodeInterfaceLate(pXendx);

    WPP_INIT_TRACING(fdo, &XenevtchnRegistryPath); // fdo ignored in XP or above
    SetWppTrace(XenEvtchnWppTrace);
    TraceNotice(("Initialized tracing provider\n"));

    fdo->Flags &= ~DO_DEVICE_INITIALIZING;

    return ( status );
}

//
// General dispatch point for Windows Plug and Play
// Irps.
//
NTSTATUS 
XenevtchnDispatchPnp(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx = 
        (PXENEVTCHN_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PEVTCHN_PNP_HANDLER handler = NULL;
    PCHAR name = NULL;
    NTSTATUS status;

    TraceDebug (("==> enter minor %d\n", stack->MinorFunction));
    if (pXevtdx->Header.Signature == XENEVTCHN_PDO_SIGNATURE) {
        TraceDebug (("(%d) - PDO\n", stack->MinorFunction));
        if (stack->MinorFunction >
            IRP_MN_QUERY_LEGACY_BUS_INFORMATION) {
            name = "???";
            handler = IgnoreRequest;
        } else {
            name = pnpInfo[stack->MinorFunction].name;
            handler = pnpInfo[stack->MinorFunction].pdoHandler;
        }
    } else if (pXevtdx->Header.Signature == XENEVTCHN_FDO_SIGNATURE) {
        TraceDebug (("(%d) - FDO\n", stack->MinorFunction));
        if (stack->MinorFunction >
            IRP_MN_QUERY_LEGACY_BUS_INFORMATION) {
            name = "???";
            handler = DefaultPnpHandler;
        } else {
            name = pnpInfo[stack->MinorFunction].name;
            handler = pnpInfo[stack->MinorFunction].fdoHandler;
        }
    } else {
        TraceBugCheck(("Bad signature %x\n", pXevtdx->Header.Signature));
    }

    status = handler(DeviceObject, Irp);
    TraceDebug (("<== (%s) = %d\n", name, status));

    return status;

}

NTSTATUS
XenevtchnDispatchWmi(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
)
{
    /* We don't support WMI, so just pass it on down the stack. */
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx =
        (PXENEVTCHN_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    TraceDebug (("DispatchWmi.\n"));
    if (pXevtdx->Header.Signature == XENEVTCHN_PDO_SIGNATURE) {
        TraceDebug (("DispatchWmi PDO.\n"));
        Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_NOT_SUPPORTED;
    } else {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(pXevtdx->LowerDeviceObject, Irp);
    }
}

NTSTATUS
DllInitialize(PUNICODE_STRING RegistryPath)
{
    TraceInfo(("%s\n", __FUNCTION__));

    return STATUS_SUCCESS;
}
