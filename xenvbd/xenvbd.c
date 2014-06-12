//
// xenvbd.c - Xen virtual SCSI Miniport driver.
//
// Copyright (c) 2006 XenSource, Inc.
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


#pragma warning (push, 3)

#include "xenvbd.h"
#include "scsiboot.h"
#include "vbd_special.h"
#include "stdio.h"
#include "xenvbd_ioctl.h"

#include "../xenutil/gnttab.h"
#include "../xenutil/xenbus.h"
#include "../xenutil/evtchn.h"
#include "../xenutil/iohole.h"
#include "../xenutil/debug.h"
#include "../xenutil/hvm.h"
#include "../xenutil/xenutl.h"
#include "../xenutil/reexport.h"
#include "../xenutil/austere.h"

#pragma warning (pop)

//
// Dont care about unreferenced formal parameters here
//
//#pragma warning( disable : 4100 )

PDEVICE_OBJECT XenvbdFdo;

PHW_DEVICE_EXTENSION XenvbdDeviceExtension;
PXHBD_TARGET_INFO *XenvbdTargetInfo;
struct irqsafe_lock __XenvbdTargetInfoLock;
struct irqsafe_lock *XenvbdTargetInfoLock = &__XenvbdTargetInfoLock;

PORT_CONFIGURATION_INFORMATION XenvbdConfigInfo;
struct xenbus_watch_handler *device_area_watch;

//
// Cause the emergency heap to be allocated in its own section with
// read/write/execute attributes, default is with no execute. On crash
// hibernate, the hypercall page is allocated from this heap and needs
// to be executable.
//

#pragma section("emergencyHeap",read,write,execute,nopage)
#pragma comment(linker, "/section:emergencyHeap,rwe")
__declspec(allocate("emergencyHeap"))
static unsigned char emergency_heap[(AUSTERE_HEAP_PAGES + 1) * PAGE_SIZE];

void InitBounceBuffers(void);

static BOOLEAN EvtchnInitialized = FALSE;
BOOLEAN XenvbdUnloading;

static EVTCHN_PORT  XenvbdKickPort;

static struct xm_thread *XenvbdRescanThread;

//
// Function prototyes.
//
NTSTATUS
DriverEntry(
    IN PVOID DriverObject,
    IN PVOID Argument2
);

static VOID
XenvbdUnload (
    IN  PDRIVER_OBJECT  DriverObject
    );

static ULONG
XenvbdFindAdapter(
    IN PVOID HwDeviceExtension,
    IN PVOID Context,
    IN PVOID BusInformation,
    IN PCHAR ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    OUT PBOOLEAN Again
);

static BOOLEAN srb_valid_for_target(PSCSI_REQUEST_BLOCK srb,
                                    PXHBD_TARGET_INFO targetInfo);
static VOID XenvbdCapacity16(PXHBD_TARGET_INFO ptargetInfo,
                             PSCSI_REQUEST_BLOCK Srb,
                             PVOID DataBuffer);
static VOID XenvbdCapacity(PXHBD_TARGET_INFO ptargetInfo,
                           PSCSI_REQUEST_BLOCK srb,
                           PVOID DataBuffer);
static void XenvbdReportLuns(PSCSI_REQUEST_BLOCK srb,
                             PVOID DataBuffer);

static BOOLEAN XenvbdHwInitialize(
    IN PVOID HwDeviceExtension
);

static BOOLEAN XenvbdStartIO(
    IN PVOID HwDeviceExtension,
    IN PSCSI_REQUEST_BLOCK Srb
);

static BOOLEAN XenvbdInterrupt(
    IN PVOID HwDeviceExtension
);

static BOOLEAN XenvbdResetBusHoldingLock(VOID);

static BOOLEAN XenvbdResetBus(
    IN PVOID HwDeviceExtension,
    IN ULONG PathId
    );

SCSI_ADAPTER_CONTROL_STATUS
XenvbdAdapterControl(
    IN PVOID HwDeviceExtension,
    IN SCSI_ADAPTER_CONTROL_TYPE ControlType,
    IN PVOID Parameters
);

/* SCSIPort-supplied driver object callbacks. */
static PDRIVER_ADD_DEVICE ScsiportAddDevice;
static PDRIVER_DISPATCH ScsiportDispatchPnp;
static PDRIVER_UNLOAD ScsiportDriverUnload;

extern PDEVICE_OBJECT   IoGetAttachedDevice(PDEVICE_OBJECT  DeviceObject);

extern PDEVICE_OBJECT   IoGetAttachedDevice(PDEVICE_OBJECT  DeviceObject);

NTSTATUS
XenvbdAddDevice(
    IN  PDRIVER_OBJECT  DriverObject,
    IN  PDEVICE_OBJECT  Pdo
    )
{
    NTSTATUS            status;

    status = ScsiportAddDevice(DriverObject, Pdo);
    if (!NT_SUCCESS(status))
        goto fail1;

    XenvbdFdo = IoGetAttachedDevice(Pdo);
    TraceNotice(("%s: FDO = 0x%p\n", __FUNCTION__, XenvbdFdo));

    return STATUS_SUCCESS;

fail1:
    TraceError(("%s: fail1 (0x%08x)\n", __FUNCTION__, status));

    return status;
}

//
// This function attempts to map a DEVICE_OBJECT to a target ID.
//
// It does this by sending IRP_MN_QUERY_ID-BusInstanceId to the stack
// and parsing the returned string.
//

static VOID
XenvbdMapDeviceObjectToTargetId(
    IN  PDEVICE_OBJECT  DeviceObject
    )
{
    KEVENT              event;
    PWCHAR              instanceId;
    PIRP                irp;
    PIO_STACK_LOCATION  irpStack;
    size_t              length;
    IO_STATUS_BLOCK     statusBlock;
    PWCHAR              target;
    ULONG               targetId;
    UNICODE_STRING      unicodeString;
    XHBD_TARGET_INFO    *TargetInfo;
    KIRQL               Irql;
    NTSTATUS            status;

    instanceId = NULL;

    //
    // Build IRP_MJ_PNP and query BusQueryInstanceID.
    //

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    RtlZeroMemory(&statusBlock, sizeof(statusBlock));

    irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP, DeviceObject, NULL, 0, NULL, &event, &statusBlock);

    status = STATUS_UNSUCCESSFUL;
    if (irp == NULL)
        goto fail1;

    irpStack = IoGetNextIrpStackLocation(irp);
    irpStack->MinorFunction = IRP_MN_QUERY_ID;
    irpStack->Parameters.QueryId.IdType = BusQueryInstanceID;
    irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    status = IoCallDriver(DeviceObject, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = statusBlock.Status;
    }

    if (!NT_SUCCESS(status))
        goto fail2;

    instanceId = (PWCHAR)statusBlock.Information;

    status = STATUS_NO_SUCH_DEVICE;
    if (instanceId == NULL)
        goto fail3;

    //
    // SCSIPORT instance ID is in the following format: btl (<= WXP)
    // bbttll (>= W2K3) where (b = bus, t = target, l = LUN).
    //

    length = wcslen(instanceId);

    status = STATUS_NO_SUCH_DEVICE;
    if ((length != 3) && (length != 6))
        goto fail4;

    //
    // Map taget id to target info from the adapter extension.
    //

    if (length == 3) {
        target = instanceId + 1;
        target[1] = UNICODE_NULL;
    } else {
        target = instanceId + 2;
        target[2] = UNICODE_NULL;
    }

    RtlInitUnicodeString(&unicodeString, target);
    status = RtlUnicodeStringToInteger(&unicodeString, 16, &targetId);
    if (!NT_SUCCESS(status))
        goto fail5;

    Irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    TargetInfo = XenvbdTargetInfo[targetId];

    status = STATUS_NO_SUCH_DEVICE;
    if (TargetInfo == NULL)
        goto fail6;

    TraceNotice(("Mapped PDO 0x%p to target %d.\n", 
                 DeviceObject, targetId));

    XM_ASSERT(TargetInfo->DeviceObject == NULL);
    TargetInfo->DeviceObject = DeviceObject;

    release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

    ExFreePool(instanceId);

    return;

fail6:
    TraceError(("%s: fail6\n", __FUNCTION__));
    release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

fail5:
    TraceError(("%s: fail5\n", __FUNCTION__));

fail4:
    TraceError(("%s: fail4\n", __FUNCTION__));

    ExFreePool(instanceId);

fail3:
    TraceError(("%s: fail3\n", __FUNCTION__));

fail2:
    TraceError(("%s: fail2\n", __FUNCTION__));

fail1:
    TraceError(("%s: fail1 (0x%08x)\n", __FUNCTION__, status));
}

static const CHAR *
PnpIrpName(
    IN  ULONG   MinorFunction
    )
{
#define _IRP_NAME(_Code)    \
    case IRP_MN_ ## _Code : \
        return #_Code;

    switch (MinorFunction) {
    _IRP_NAME(START_DEVICE);
    _IRP_NAME(QUERY_REMOVE_DEVICE);
    _IRP_NAME(REMOVE_DEVICE);
    _IRP_NAME(CANCEL_REMOVE_DEVICE);
    _IRP_NAME(STOP_DEVICE);
    _IRP_NAME(QUERY_STOP_DEVICE);
    _IRP_NAME(CANCEL_STOP_DEVICE);
    _IRP_NAME(QUERY_DEVICE_RELATIONS);
    _IRP_NAME(QUERY_INTERFACE);
    _IRP_NAME(QUERY_CAPABILITIES);
    _IRP_NAME(QUERY_RESOURCES);
    _IRP_NAME(QUERY_RESOURCE_REQUIREMENTS);
    _IRP_NAME(QUERY_DEVICE_TEXT);
    _IRP_NAME(FILTER_RESOURCE_REQUIREMENTS);
    _IRP_NAME(READ_CONFIG);
    _IRP_NAME(WRITE_CONFIG);
    _IRP_NAME(EJECT);
    _IRP_NAME(SET_LOCK);
    _IRP_NAME(QUERY_ID);
    _IRP_NAME(QUERY_PNP_DEVICE_STATE);
    _IRP_NAME(QUERY_BUS_INFORMATION);
    _IRP_NAME(DEVICE_USAGE_NOTIFICATION);
    _IRP_NAME(SURPRISE_REMOVAL);
    default:
        return "UNKNOWN";
    }

#undef  _IRP_NAME
}

static BOOLEAN
FilterPresent(
    IN  ULONG   TargetID
    )
{
    CHAR        *Path;
    CHAR        *Result;
    size_t      Length;
    BOOLEAN     Present;
    NTSTATUS    status;

    Path = Xmasprintf("data/scsi/target/%d", TargetID);
    if (Path == NULL)
        goto fail1;

    status = xenbus_read_bin(XBT_NIL, Path, "filter", &Result, &Length);
    if (!NT_SUCCESS(status))
        goto fail2;

    Present = (strncmp(Result, "present", Length) == 0) ? TRUE : FALSE;

    XmFreeMemory(Result);
    XmFreeMemory(Path);
    return Present;

fail2:
    XmFreeMemory(Path);

fail1:
    return FALSE;
}

static NTSTATUS
StartPdo(
    IN  XHBD_TARGET_INFO    *Target,
    IN  DEVICE_OBJECT       *DeviceObject,
    IN  IRP                 *Irp
    )
{
    SUSPEND_TOKEN           Token;
    CHAR                    *BackendPath;
    NTSTATUS                ScsiportStatus;
    NTSTATUS                status;

    XM_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    TraceVerbose(("%s(%d): ====>\n", __FUNCTION__, Target->targetId));

    status = ScsiportStatus = ScsiportDispatchPnp(DeviceObject, Irp);
    if (!NT_SUCCESS(ScsiportStatus))
        goto fail1;

    XM_ASSERT(ScsiportStatus != STATUS_PENDING);

    Token = EvtchnAllocateSuspendToken("xenvbd");

    BackendPath = find_backend_path(Target, Token);

    status = STATUS_NO_MEMORY;
    if (BackendPath == NULL)
        goto fail2;

    ExAcquireFastMutex(&Target->StateLock);

    XM_ASSERT(!Target->Started);

    status = PrepareBackendForReconnect(Target, BackendPath, Token);
    if (!NT_SUCCESS(status))
        goto fail3;

    Target->Started = TRUE;

    if (!FilterPresent(Target->targetId)) {
        TraceWarning(("target %d filter not present\n", Target->targetId));

        status = XenvbdConnectTarget(Target, BackendPath, Token);
        if (!NT_SUCCESS(status))
            goto fail4;

        Target->Connected = TRUE;
    }

    ExReleaseFastMutex(&Target->StateLock);

    XmFreeMemory(BackendPath);
    EvtchnReleaseSuspendToken(Token);

    TraceVerbose(("%s(%d): <====\n", __FUNCTION__, Target->targetId));
    return ScsiportStatus;

fail4:
    TraceError(("%s: fail4\n", __FUNCTION__));

    Target->Started = FALSE;

fail3:
    TraceError(("%s: fail3\n", __FUNCTION__));

    ExReleaseFastMutex(&Target->StateLock);

    XmFreeMemory(BackendPath);

fail2:
    TraceError(("%s: fail2\n", __FUNCTION__));

    EvtchnReleaseSuspendToken(Token);

fail1:
    TraceError(("%s: fail1 (0x%08x)\n", __FUNCTION__, status));

    XM_ASSERT(!Target->Started);
    
    TraceVerbose(("%s(%d): <====\n", __FUNCTION__, Target->targetId));
    return ScsiportStatus;
}

static NTSTATUS
StopPdo(
    IN  XHBD_TARGET_INFO    *Target,
    IN  DEVICE_OBJECT       *DeviceObject,
    IN  IRP                 *Irp
    )
{
    SUSPEND_TOKEN           Token;
    CHAR                    *BackendPath;
    NTSTATUS                ScsiportStatus;

    XM_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    TraceVerbose(("%s(%d): ====>\n", __FUNCTION__, Target->targetId));

    Token = EvtchnAllocateSuspendToken("xenvbd");

    BackendPath = find_backend_path(Target, Token);

    ExAcquireFastMutex(&Target->StateLock);

    if (BackendPath == NULL)
        goto done;  // We are not allowed to fail this IRP

    if (Target->Connected) {
        CloseFrontend(Target, BackendPath, Token);
        XenvbdDisconnectTarget(Target, BackendPath, Token);

        Target->Connected = FALSE;
    }

    XmFreeMemory(BackendPath);

done:
    Target->Started = FALSE;
    ExReleaseFastMutex(&Target->StateLock);

    EvtchnReleaseSuspendToken(Token);

    ScsiportStatus = ScsiportDispatchPnp(DeviceObject, Irp);

    TraceVerbose(("%s(%d): <====\n", __FUNCTION__, Target->targetId));
    return ScsiportStatus;
}

static NTSTATUS
CancelRemovePdo(
    IN  XHBD_TARGET_INFO    *Target,
    IN  DEVICE_OBJECT       *DeviceObject,
    IN  IRP                 *Irp
    )
{
    BOOLEAN                 EjectFailed;
    KIRQL                   Irql;
    NTSTATUS                ScsiportStatus;

    TraceVerbose(("%s(%d): ====>\n", __FUNCTION__, Target->targetId));

    EjectFailed = FALSE;

    KeAcquireSpinLock(&Target->EjectLock, &Irql);
    if (Target->EjectRequested) {
        Target->EjectRequested = FALSE;
        EjectFailed = TRUE;
    }
    KeReleaseSpinLock(&Target->EjectLock, Irql);

    if (EjectFailed) {
        CHAR    *ErrorPath;

        TraceError(("Failed to eject target %d.\n", Target->targetId));

        ErrorPath = Xmasprintf("error/%s/error", Target->xenbusNodeName);
        if (ErrorPath != NULL) {
            xenbus_write(XBT_NIL, ErrorPath, "Unplug failed due to open handle(s)!");
            XmFreeMemory(ErrorPath);
        }
    }

    ScsiportStatus = ScsiportDispatchPnp(DeviceObject, Irp);

    TraceVerbose(("%s(%d): <====\n", __FUNCTION__, Target->targetId));
    return ScsiportStatus;
}

static NTSTATUS
QueryCapabilitiesPdo(
    IN  XHBD_TARGET_INFO    *Target,
    IN  DEVICE_OBJECT       *DeviceObject,
    IN  IRP                 *Irp
    )
{
    IO_STACK_LOCATION       *StackLocation;
    DEVICE_CAPABILITIES     *Capabilities;
    NTSTATUS                ScsiportStatus;

    TraceVerbose(("%s(%d): ====>\n", __FUNCTION__, Target->targetId));

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Capabilities = StackLocation->Parameters.DeviceCapabilities.Capabilities;

    if (Target->removable) {
        TraceNotice(("target %d is ejectable.\n",
                     Target->targetId));

        Capabilities->Removable = 1;
        Capabilities->EjectSupported = 1;
    } else {
        TraceNotice(("target %d is not ejectable.\n",
                     Target->targetId));
    }

    if (Target->info & VDISK_REMOVABLE) {
        TraceNotice(("target %d is surprise-removable.\n",
                     Target->targetId));

        Capabilities->SurpriseRemovalOK = 1;
    } else {
        TraceNotice(("target %d is not surprise-removable.\n",
                     Target->targetId));
    }

    Capabilities->UniqueID = 1;

    ScsiportStatus = ScsiportDispatchPnp(DeviceObject, Irp);

    TraceVerbose(("%s(%d): <====\n", __FUNCTION__, Target->targetId));
    return ScsiportStatus;
}

static NTSTATUS
EjectPdo(
    IN  XHBD_TARGET_INFO    *Target,
    IN  DEVICE_OBJECT       *DeviceObject,
    IN  IRP                 *Irp
    )
{
    NTSTATUS                ScsiportStatus;

    TraceVerbose(("%s(%d): ====>\n", __FUNCTION__, Target->targetId));

    XenbusEjectTarget(Target);
    XenvbdRequestInvalidate();

    ScsiportStatus = ScsiportDispatchPnp(DeviceObject, Irp);

    TraceVerbose(("%s(%d): <====\n", __FUNCTION__, Target->targetId));
    return ScsiportStatus;
}

static NTSTATUS
SurpriseRemovalPdo(
    IN  XHBD_TARGET_INFO    *Target,
    IN  DEVICE_OBJECT       *DeviceObject,
    IN  IRP                 *Irp
    )
{
    NTSTATUS                ScsiportStatus;

    TraceVerbose(("%s(%d): ====>\n", __FUNCTION__, Target->targetId));

    XM_ASSERT(Target->Disappeared);
    Target->SurpriseRemoved = TRUE;
    XenvbdRequestInvalidate();

    ScsiportStatus = ScsiportDispatchPnp(DeviceObject, Irp);

    TraceVerbose(("%s(%d): <====\n", __FUNCTION__, Target->targetId));
    return ScsiportStatus;
}


static NTSTATUS
DeviceUsagePdo(
    IN  XHBD_TARGET_INFO    *Target,
    IN  DEVICE_OBJECT       *DeviceObject,
    IN  IRP                 *Irp
    )
{
    IO_STACK_LOCATION       *StackLocation;
    NTSTATUS                ScsiportStatus;

    TraceVerbose(("%s(%d): ====>\n", __FUNCTION__, Target->targetId));

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    switch (StackLocation->Parameters.UsageNotification.Type) {
    case DeviceUsageTypePaging:
        Target->Paging = StackLocation->Parameters.UsageNotification.InPath;
        break;

    case DeviceUsageTypeHibernation:
        Target->Hibernation = StackLocation->Parameters.UsageNotification.InPath;
        break;

    case DeviceUsageTypeDumpFile:
        Target->DumpFile = StackLocation->Parameters.UsageNotification.InPath;
        break;

    case DeviceUsageTypeUndefined:
    default:
        goto done;
    }

    XenbusUpdateTargetUsage(Target);

done:
    ScsiportStatus = ScsiportDispatchPnp(DeviceObject, Irp);

    TraceVerbose(("%s(%d): <====\n", __FUNCTION__, Target->targetId));
    return ScsiportStatus;
}

static NTSTATUS
XenvbdProcessPdoPnpIrp(
    IN  DEVICE_OBJECT   *DeviceObject,
    IN  IRP             *Irp
    )
{
    ULONG               TargetId;
    XHBD_TARGET_INFO    *Target;
    KIRQL               Irql;
    BOOLEAN             DoEject;
    IO_STACK_LOCATION   *StackLocation;
    NTSTATUS            status;

    XM_ASSERT(DeviceObject != XenvbdFdo);
    XM_ASSERT(XenvbdDeviceExtension != NULL);

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    TraceDebug(("%s: (%p) %02x:%s\n", __FUNCTION__, DeviceObject,
                StackLocation->MinorFunction,
                PnpIrpName(StackLocation->MinorFunction)));

    switch (StackLocation->MinorFunction) {
    case IRP_MN_QUERY_ID:
    case IRP_MN_QUERY_CAPABILITIES:
    case IRP_MN_START_DEVICE:
    case IRP_MN_STOP_DEVICE:
    case IRP_MN_REMOVE_DEVICE:
    case IRP_MN_CANCEL_REMOVE_DEVICE:
    case IRP_MN_EJECT:
    case IRP_MN_SURPRISE_REMOVAL:
    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        break;

    default:
        status = ScsiportDispatchPnp(DeviceObject, Irp);
        return status;
    }

    TargetId = 0;
    Target = NULL;

    Irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    while (TargetId < (ULONG)XENVBD_MAX_DISKS) {
        Target = XenvbdTargetInfo[TargetId];
        if (Target != NULL && Target->DeviceObject == DeviceObject) {
            Target->References++;
            break;
        }

        TargetId++;
    }
    release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

    if (Target == NULL) {
        switch (StackLocation->MinorFunction) {
        case IRP_MN_QUERY_ID:
            switch (StackLocation->Parameters.QueryId.IdType) {
            case BusQueryDeviceID:
                // The first IRP sent after creation of the PDO, by observation, is a
                // IRP_MN_QUERY_ID:BusQueryDeviceID. This will clearly not find a cached
                // PDO pointer in any target structure so in this case we send our own
                // IRP_MN_QUERY_ID:BusQueryInstanceID to associate the PDO and the target.
                //
                // NOTE: It is important to only to this in response to the first IRP
                //       after PDO creation to avoid some nasty races between target
                //       creation/destruction and the PnP state machine.
                //
                XenvbdMapDeviceObjectToTargetId(DeviceObject);
                break;

            default:
                break;
            }
            break;

        case IRP_MN_REMOVE_DEVICE:
            // For some reason, after sending down an EJECT IRP (which causes us to delete
            // the target) Windows then sends a QUERY_DEVICE_RELATIONS followed by another
            // REMOVE_DEVICE (the original one coming directly before the EJECT).
            // Avoid the warning in this case.
            break;

        case IRP_MN_SURPRISE_REMOVAL:
            // If we failed during processing of START_DEVICE then we may end up destroying
            // the target before the PnP manager manages to send a SURPRISE_REMOVAL IRP.
            // This is not a problem so avoid the warning in this case.
            break;

        default:
            TraceWarning(("%s: %02x:%s failed to map PDO %p to target\n", __FUNCTION__,
                        StackLocation->MinorFunction,
                        PnpIrpName(StackLocation->MinorFunction),
                        DeviceObject));
            break;
        }

        status = ScsiportDispatchPnp(DeviceObject, Irp);
        return status;
    }

    XM_ASSERT(Target->References != 0);

    // Check for a pending eject request
    DoEject = FALSE;
    KeAcquireSpinLock(&Target->EjectLock, &Irql);
    if (Target->EjectPending) {
        Target->EjectPending = FALSE;

        DoEject = TRUE;
        Target->EjectRequested = TRUE;
    }
    KeReleaseSpinLock(&Target->EjectLock, Irql);

    if (DoEject) {
        TraceNotice(("%s: Issuing eject request for target %d\n",
                     __FUNCTION__, TargetId));
        IoRequestDeviceEject(Target->DeviceObject);
    }

    switch (StackLocation->MinorFunction) {
    case IRP_MN_QUERY_ID:
        status = ScsiportDispatchPnp(DeviceObject, Irp);
        break;

    case IRP_MN_QUERY_CAPABILITIES:
        status = QueryCapabilitiesPdo(Target, DeviceObject, Irp);
        break;

    case IRP_MN_START_DEVICE:
        status = StartPdo(Target, DeviceObject, Irp);
        break;

    case IRP_MN_STOP_DEVICE:
        status = StopPdo(Target, DeviceObject, Irp);
        break;

    case IRP_MN_REMOVE_DEVICE:
        status = StopPdo(Target, DeviceObject, Irp);
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        status = CancelRemovePdo(Target, DeviceObject, Irp);
        break;

    case IRP_MN_EJECT:
        status = EjectPdo(Target, DeviceObject, Irp);
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        status = SurpriseRemovalPdo(Target, DeviceObject, Irp);
        break;

    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        status = DeviceUsagePdo(Target, DeviceObject, Irp);
        break;

    default:
        XM_ASSERT(FALSE);
        break;
    }

    Irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    Target->References--;
    release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

    return status;
}

static NTSTATUS
DeviceRelationsFdo(
    IN  DEVICE_OBJECT   *DeviceObject,
    IN  IRP             *Irp
    )
{
    IO_STACK_LOCATION   *StackLocation;
    NTSTATUS            ScsiportStatus;

    TraceVerbose(("%s: ====>\n", __FUNCTION__));

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    if (StackLocation->Parameters.QueryDeviceRelations.Type == BusRelations)
        XenvbdScanTargets();

    ScsiportStatus = ScsiportDispatchPnp(DeviceObject, Irp);

    TraceVerbose(("%s: <====\n", __FUNCTION__));
    return ScsiportStatus;
}

static NTSTATUS
DeviceUsageFdo(
    IN  DEVICE_OBJECT   *DeviceObject,
    IN  IRP             *Irp
    )
{
    IO_STACK_LOCATION   *StackLocation;
    NTSTATUS            ScsiportStatus;

    TraceVerbose(("%s: ====>\n", __FUNCTION__));

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    if (StackLocation->Parameters.UsageNotification.Type == DeviceUsageTypePaging) {
        BOOLEAN On = StackLocation->Parameters.UsageNotification.InPath;

        XenevtchnSetDeviceUsage(DeviceUsageTypePaging, On);
    }

    ScsiportStatus = ScsiportDispatchPnp(DeviceObject, Irp);

    TraceVerbose(("%s: <====\n", __FUNCTION__));
    return ScsiportStatus;
}

static NTSTATUS
XenvbdProcessFdoPnpIrp(
    IN  DEVICE_OBJECT   *DeviceObject,
    IN  IRP             *Irp
    )
{
    IO_STACK_LOCATION   *StackLocation;
    NTSTATUS            status;

    XM_ASSERT(DeviceObject == XenvbdFdo);

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    TraceDebug(("%s: (%p) %02x:%s\n", __FUNCTION__, DeviceObject,
                StackLocation->MinorFunction,
                PnpIrpName(StackLocation->MinorFunction)));

    switch (StackLocation->MinorFunction) {
    case IRP_MN_QUERY_DEVICE_RELATIONS:
        status = DeviceRelationsFdo(DeviceObject, Irp);
        break;

    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        status = DeviceUsageFdo(DeviceObject, Irp);
        break;

    default:
        status = ScsiportDispatchPnp(DeviceObject, Irp);
        break;
    }

    return status;
}

static NTSTATUS
XenvbdProcessPnpIrp(
    IN  DEVICE_OBJECT   *DeviceObject,
    IN  IRP             *Irp)
{
    NTSTATUS            status;

    if (DeviceObject == XenvbdFdo) {
        status = XenvbdProcessFdoPnpIrp(DeviceObject, Irp);
    } else {
        status = XenvbdProcessPdoPnpIrp(DeviceObject, Irp);
    }

    return status;
}

static void
DeviceAreaChanged(void *ignore)
{
    UNREFERENCED_PARAMETER(ignore);

    XenvbdRequestRescan();
}

typedef
VOID
DRIVER_REINITIALIZE (
    __in        DRIVER_OBJECT *DriverObject,
    __in_opt    PVOID Context,
    __in        ULONG Count
    );

typedef DRIVER_REINITIALIZE *PDRIVER_REINITIALIZE;

extern NTKERNELAPI
VOID
IoRegisterBootDriverReinitialization(
    __in PDRIVER_OBJECT DriverObject,
    __in PDRIVER_REINITIALIZE DriverReinitializationRoutine,
    __in_opt PVOID Context
    );

static VOID
XenvbdReinitialize(
    __in        DRIVER_OBJECT   *DriverObject,
    __in_opt    VOID            *Context,
    __in        ULONG           Count
    )
{
    XM_ASSERT(!AustereMode);

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Count);

    if (!device_area_watch)
        device_area_watch = xenbus_watch_path("device/vbd",
                                              DeviceAreaChanged,
                                              NULL);
}

#pragma warning(disable : 28138)
#define CRASH_PORT  ((PVOID)(ULONG_PTR)0xED)

//
// DriverEntry - Perform driver initialization, create FDO and
//               setup device enumeration. For now we install this
//               device as a non-PnP device so that it will be 
//               explicitly enumerated by the root bus. Once the
//               xenbus is in place, this device should be enumerated
//               via PnP.

extern PULONG InitSafeBootMode;

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING Argument2
)
{
	HW_INITIALIZATION_DATA *hwInitializationData;
	char buf[sizeof(HW_INITIALIZATION_DATA) + sizeof(PVOID)];
    ULONG Status;
    ULONG i;

	hwInitializationData = (HW_INITIALIZATION_DATA *)buf;

    if (*InitSafeBootMode > 0) {
        TraceNotice(("loading in safe mode\n"));
        return STATUS_SUCCESS;
    }

    if (!XmCheckXenutilVersionString(TRUE, XENUTIL_CURRENT_VERSION))
        return STATUS_REVISION_MISMATCH;

    TraceDebug(("==>\n"));

    if (!XenPVEnabled() ||
        XenPVFeatureEnabled(DEBUG_HA_SAFEMODE))
    {
        TraceInfo (("PV disabled?\n"));
        return STATUS_SUCCESS;
    }

    XM_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL || AustereMode);

    switch (GetOperatingMode()) {
    case NORMAL_MODE:
        TraceNotice(("XENVBD in NORMAL mode.\n"));
        ExInitializeFastMutex(&XenvbdEnumLock);
        break;

    case HIBER_MODE:
        TraceNotice(("XENVBD in HIBER mode.\n"));
        break;

    case DUMP_MODE:
        TraceNotice(("XENVBD in DUMP mode.\n"));

        // Give a hint to Xen that we're crashing
        WRITE_PORT_ULONG(CRASH_PORT, 'PLEH');

        break;

    default:
        XM_BUG();
        break;
    }

    for (i = 0; i < sizeof(HW_INITIALIZATION_DATA) + sizeof(PVOID); i++) {
        ((PUCHAR) & buf)[i] = 0;
	}

    hwInitializationData->HwInitializationDataSize = 
        sizeof(HW_INITIALIZATION_DATA);

    hwInitializationData->HwInitialize = XenvbdHwInitialize;
    hwInitializationData->HwResetBus = XenvbdResetBus;
    hwInitializationData->HwStartIo = XenvbdStartIO;

    hwInitializationData->HwInterrupt =  XenvbdInterrupt;

    hwInitializationData->HwFindAdapter = XenvbdFindAdapter;
    hwInitializationData->HwAdapterControl = XenvbdAdapterControl;

    hwInitializationData->MapBuffers = TRUE;
    hwInitializationData->NeedPhysicalAddresses = TRUE;
    hwInitializationData->AutoRequestSense = TRUE;

    hwInitializationData->TaggedQueuing = FALSE;
    hwInitializationData->MultipleRequestPerLu = FALSE;

    hwInitializationData->DeviceExtensionSize = sizeof(HW_DEVICE_EXTENSION);

    hwInitializationData->SpecificLuExtensionSize = 0;

    hwInitializationData->AdapterInterfaceType = PCIBus;

    hwInitializationData->NumberOfAccessRanges = 2;

    hwInitializationData->SrbExtensionSize = sizeof(SRB_EXTENSION);

    if (AustereMode) {

		XEN_WINDOWS_VERSION WinVer;
		XenutilGetOsVersionDuringAustere(&WinVer);

		TraceNotice(("Windows Version Info: %d.%d SP %d.%d\n",
			WinVer.dwMajorVersion,
			WinVer.dwMinorVersion,
			WinVer.wServicePackMajor,
			WinVer.wServicePackMinor));

		//
		// XC-4394
		//
		// If we are running Windows 7 with SP1 or later, we need
		// to avoid a bug in SCSIPORT that will not accept a
		// HW_INITIALIZATION_DATA struct that is from SCSIPORT. It checks
		// the size field and only allows StorPort or stream structs.
		// To get around this, we just adjust the size by sizeof(PVOID) bytes.
		//
		// NB: This is only valid when in crash dump or hibernate mode!!
		//
		if ((WinVer.dwMajorVersion >= 6) &&
			(WinVer.dwMinorVersion >= 1) &&
			(WinVer.wServicePackMajor >= 1))
		{
			TraceWarning(("Windows 7 SP1 (or later) detected!\n"));
			TraceWarning(("Increaing HwInitializationDataSize to %d\n",
					sizeof(HW_INITIALIZATION_DATA) + sizeof(PVOID)));
			hwInitializationData->HwInitializationDataSize = 
					sizeof(HW_INITIALIZATION_DATA) + sizeof(PVOID);
		}

        /* We're not a PNP device when run in SCSIBOOT mode, and so
           have to specify the PCI device id ourselves. */
        hwInitializationData->VendorId = "5853";
        hwInitializationData->VendorIdLength = 4;
        hwInitializationData->DeviceId = "0001";
        hwInitializationData->DeviceIdLength = 4;
    }

    Status = ScsiPortInitialize(DriverObject, Argument2,
                 hwInitializationData, NULL);

    /* Try the old PCI ids if those ones didn't work. */
    if (AustereMode && Status != 0) {
        TraceWarning(("Trying old device ids...\n"));
        hwInitializationData->VendorId = "fffd";
        hwInitializationData->VendorIdLength = 4;
        hwInitializationData->DeviceId = "0101";
        hwInitializationData->DeviceIdLength = 4;
        Status = ScsiPortInitialize(DriverObject, Argument2,
                     hwInitializationData, NULL);
    }

    if (AustereMode) {
        TraceNotice(("Scsiport initialized: %x\n", Status));
    } else {
        ScsiportAddDevice = DriverObject->DriverExtension->AddDevice;
        DriverObject->DriverExtension->AddDevice = XenvbdAddDevice;

        ScsiportDispatchPnp = DriverObject->MajorFunction[IRP_MJ_PNP];
        DriverObject->MajorFunction[IRP_MJ_PNP] = XenvbdProcessPnpIrp;

        ScsiportDriverUnload = DriverObject->DriverUnload;
        DriverObject->DriverUnload = XenvbdUnload;

        IoRegisterBootDriverReinitialization(DriverObject, XenvbdReinitialize, NULL);
    }

    TraceDebug(("XENVBD: DriverEntry return %x\n", Status));

    return( Status );
}

void
RemoveSrbFromQueueRaw(PSCSI_REQUEST_BLOCK srb, PSRB_QUEUE_RAW queue)
{
    PSRB_EXTENSION se = SrbExtension(srb);

    if (se->queued != queue)
        KeBugCheckEx(0xf7deb0,
                     (ULONG_PTR)queue,
                     (ULONG_PTR)se->queued,
                     (ULONG_PTR)se->next,
                     (ULONG_PTR)se->prev);

    if (se->next) {
        SrbExtension(se->next)->prev = se->prev;
    } else {
        if (queue->tail != srb)
            KeBugCheckEx(0xf7deaf,
                         (ULONG_PTR)queue->tail,
                         (ULONG_PTR)queue->head,
                         (ULONG_PTR)srb,
                         (ULONG_PTR)se->prev);
        queue->tail = se->prev;
    }
    if (se->prev) {
        SrbExtension(se->prev)->next = se->next;
    } else {
        XM_ASSERT(queue->head == srb);
        queue->head = se->next;
    }

    XM_ASSERT(queue->srbs_cur != 0);
    queue->srbs_cur--;

    se->queued = NULL;
}

void
QueueSrbRaw(PSCSI_REQUEST_BLOCK srb, PSRB_QUEUE_RAW queue)
{
    PSRB_EXTENSION se = SrbExtension(srb);

    if (se->queued != NULL)
        KeBugCheckEx(0xf7deb1,
                     (ULONG_PTR)queue,
                     (ULONG_PTR)se->queued,
                     (ULONG_PTR)se->next,
                     (ULONG_PTR)se->prev);

    se->next = NULL;
    se->prev = queue->tail;
    if (queue->tail)
        SrbExtension(queue->tail)->next = srb;
    queue->tail = srb;
    if (!queue->head)
        queue->head = srb;
    queue->srbs_cur++;
    queue->srbs_ever++;
    if (queue->srbs_cur >= queue->srbs_max)
        queue->srbs_max = queue->srbs_cur;

    se->queued = queue;
}

void
QueueSrbAtHeadRaw(PSCSI_REQUEST_BLOCK srb, PSRB_QUEUE_RAW queue)
{
    PSRB_EXTENSION se = SrbExtension(srb);

    if (se->queued != NULL)
        KeBugCheckEx(0xf7deb1,
                     (ULONG_PTR)queue,
                     (ULONG_PTR)se->queued,
                     (ULONG_PTR)se->next,
                     (ULONG_PTR)se->prev);

    se->prev = NULL;
    se->next = queue->head;
    if (queue->head)
        SrbExtension(queue->head)->prev = srb;
    queue->head = srb;
    if (!queue->tail)
        queue->tail = srb;
    queue->srbs_cur++;
    queue->srbs_ever++;
    if (queue->srbs_cur >= queue->srbs_max)
        queue->srbs_max = queue->srbs_cur;

    se->queued = queue;
}

PSCSI_REQUEST_BLOCK
PeekSrb(PSRB_QUEUE_RAW queue)
{
    return queue->head;
}

PSCSI_REQUEST_BLOCK
DequeueSrbRaw(PSRB_QUEUE_RAW queue)
{
    PSCSI_REQUEST_BLOCK srb;

    srb = PeekSrb(queue);
    if (srb)
        RemoveSrbFromQueueRaw(srb, queue);
    return srb;
}

#define MAXARG 16

/* strictly base 10 conversion of NUL terminated string */
static LONG
_strtol(const char *buf, __inout int *err)
{
    LONG acc = 0;
    unsigned digit;
    unsigned off;
    LONG neg = 1;

    *err = 0;

    off = 0;
    if (buf[off] == '\0') {
        *err = 1;
        return 0;
    }
    if (buf[off] == '-') {
        neg = -1;
        off++;
    }
    while (buf[off] != '\0') {
        if (buf[off] >= '0' && buf[off] <= '9') {
            digit = buf[off] - '0';
        } else {
            *err = 1;
            return 0;
        }
        acc = (acc * 10) + digit;
        off++;
    }

    return neg * acc;
}

static VOID
ParseArgumentString(
    IN PCHAR                ArgumentString
    )
{
    PCHAR                   key[MAXARG];
    PCHAR                   value[MAXARG];
    ULONG                   offset;
    ULONG                   count;
    ULONG                   index;

    TraceInfo(("%s: %s\n", __FUNCTION__, ArgumentString));

    /*
     * The argument string format is expected to be a space separated
     * list of key value pairs, e.g. a=tom b=dick c=harry
     */
    offset = 0;
    count = 0;

    while (count < MAXARG) {
        key[count] = NULL;
        value[count] = NULL;

        while (ArgumentString[offset] == ' ')
            offset++;

        key[count] = &ArgumentString[offset];

        while (ArgumentString[offset] != '=') {
            if (ArgumentString[offset] == '\0')
                goto done;

            offset++;
        }

        ArgumentString[offset++] = '\0';
        value[count] = &ArgumentString[offset];

        if (ArgumentString[offset] == '\0')
            goto done;

        while (ArgumentString[offset] != ' ' &&
               ArgumentString[offset] != '\0')
            offset++;
        
        ArgumentString[offset++] = '\0';
        count++;
    }

done:
    for (index = 0; index < count; index++) {
        TraceNotice(("%s: KEY: %s VALUE: %s\n", __FUNCTION__, key[index], value[index]));

        if (!strcmp(key[index], "max-ring-page-order")) {
            LONG order;
            int err;

            order = _strtol(value[index], &err);
            if (!err)
                XenvbdDeviceExtension->MaxRingPageOrder = order;
        }

        if (!strcmp(key[index], "vendor-id")) {
            size_t len = strlen(value[index]);

            if (len > sizeof (XenvbdDeviceExtension->VendorId))
                len = sizeof (XenvbdDeviceExtension->VendorId);

            memset(XenvbdDeviceExtension->VendorId, ' ', 
                   sizeof (XenvbdDeviceExtension->VendorId));
            memcpy(XenvbdDeviceExtension->VendorId, value[index], len);
            XenvbdDeviceExtension->OverrideVendorId = TRUE;
        }

        if (!strcmp(key[index], "product-id")) {
            size_t len = strlen(value[index]);

            if (len > sizeof (XenvbdDeviceExtension->ProductId))
                len = sizeof (XenvbdDeviceExtension->ProductId);

            memset(XenvbdDeviceExtension->ProductId, ' ', 
                   sizeof (XenvbdDeviceExtension->ProductId));
            memcpy(XenvbdDeviceExtension->ProductId, value[index], len);
            XenvbdDeviceExtension->OverrideProductId = TRUE;
        }

        if (!strcmp(key[index], "product-revision-level")) {
            size_t len = strlen(value[index]);

            if (len > sizeof (XenvbdDeviceExtension->ProductRevisionLevel))
                len = sizeof (XenvbdDeviceExtension->ProductRevisionLevel);

            memset(XenvbdDeviceExtension->ProductRevisionLevel, ' ', 
                   sizeof (XenvbdDeviceExtension->ProductRevisionLevel));
            memcpy(XenvbdDeviceExtension->ProductRevisionLevel, value[index], len);
            XenvbdDeviceExtension->OverrideProductRevisionLevel = TRUE;
        }
    }
}

static VOID
DoInvalidate(VOID *Context)
{
    KIRQL Irql;

    UNREFERENCED_PARAMETER(Context);

    Irql = acquire_irqsafe_lock(&XenvbdDeviceExtension->InvalidateLock);
    if (!XenvbdDeviceExtension->NeedInvalidate) {
        release_irqsafe_lock(&XenvbdDeviceExtension->InvalidateLock, Irql);
        return;
    }

    TraceNotice(("invalidating bus relations\n"));

    XenvbdDeviceExtension->NeedInvalidate = FALSE;
    release_irqsafe_lock(&XenvbdDeviceExtension->InvalidateLock, Irql);

    ScsiPortNotification(BusChangeDetected,
                         XenvbdDeviceExtension,
                         0);
}

 VOID
__XenvbdRequestInvalidate(const char *caller)
{
    KIRQL Irql;

    if (is_null_EVTCHN_PORT(XenvbdKickPort)) {
        TraceWarning(("%s: missing invalidation of bus relations\n", caller));
        return;
    } else {
        TraceNotice(("%s: requesting invalidation of bus relations\n", caller));
    }

    Irql = acquire_irqsafe_lock(&XenvbdDeviceExtension->InvalidateLock);
    XenvbdDeviceExtension->NeedInvalidate = TRUE;
    release_irqsafe_lock(&XenvbdDeviceExtension->InvalidateLock, Irql);

    EvtchnRaiseLocally(XenvbdKickPort);
}

static NTSTATUS
RescanThread(
    IN  struct xm_thread    *Self,
    IN  VOID                *Context)
{
    LARGE_INTEGER           Interval;

    UNREFERENCED_PARAMETER(Context);

    TraceNotice(("%s: starting\n", __FUNCTION__));

    Interval.QuadPart = -10 * 1000 * 100; // 100ms

    while (XmThreadWait(Self) >= 0) {
        KIRQL   Irql;
        BOOLEAN NeedRescan;

        Irql = acquire_irqsafe_lock(&XenvbdDeviceExtension->RescanLock);
        NeedRescan = XenvbdDeviceExtension->NeedRescan;
        XenvbdDeviceExtension->NeedRescan = FALSE;
        release_irqsafe_lock(&XenvbdDeviceExtension->RescanLock, Irql);

        if (NeedRescan)
            XenvbdScanTargets();

        // Rate limit the thread a little
        KeDelayExecutionThread(KernelMode, FALSE, &Interval);
    }

    TraceNotice(("%s: exiting\n", __FUNCTION__));

    return STATUS_SUCCESS;
}

VOID
__XenvbdRequestRescan(const char *caller)
{
    KIRQL Irql;

    TraceNotice(("%s: requesting rescan of targets\n", caller));

    Irql = acquire_irqsafe_lock(&XenvbdDeviceExtension->RescanLock);
    XenvbdDeviceExtension->NeedRescan = TRUE;
    release_irqsafe_lock(&XenvbdDeviceExtension->RescanLock, Irql);

    KeSetEvent(&XenvbdRescanThread->event, IO_NO_INCREMENT, FALSE);
}

VOID
LaunchRescanThread(
    IN  VOID *Context
    )
{
    UNREFERENCED_PARAMETER(Context);

    if (XenvbdRescanThread != NULL)
        return;

    XenvbdRescanThread = XmSpawnThread(RescanThread, NULL);
    XM_ASSERT(XenvbdRescanThread);
}

static VOID
ResumeAllTargets(
    VOID                *Argument
    )
{
    SUSPEND_TOKEN       Token;
    XHBD_TARGET_INFO    *List = NULL;
    ULONG               TargetId;
    KIRQL               Irql;

    UNREFERENCED_PARAMETER(Argument);

    XM_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    TraceVerbose(("%s: ====>\n", __FUNCTION__));

    Token = EvtchnAllocateSuspendToken("xenvbd");

    Irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    for (TargetId = 0; TargetId < (ULONG)XENVBD_MAX_DISKS; TargetId++) {
        XHBD_TARGET_INFO *Target = XenvbdTargetInfo[TargetId];

        if (Target == NULL)
            continue;

        if (Target->Suspended) {
            // Clear the suspended flag and set the resuming flag so
            // that the target does not get resumed again.
            Target->Suspended = FALSE;
            Target->Resuming = TRUE;

            // Add it to the suspended list
            XM_ASSERT(Target->Next == NULL);
            Target->Next = List;
            List = Target;

            continue;
        }
    }
    release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

    // Resume any suspended targets
    while (List != NULL) {
        XHBD_TARGET_INFO *Target = List;

        List = Target->Next;
        Target->Next = NULL;

        ResumeTarget(Target, Token);
    }

    EvtchnReleaseSuspendToken(Token);

    TraceVerbose(("%s: <====\n", __FUNCTION__));
}

static KIRQL XenvbdIrql;

//
// XenvbdFindAdapter - Called by the SCSI port driver to allow us to
//                     locate and initialize the host adapter.
//
// NOTE: The ArgumentString parameter is sourced by SCSIport from
//       the REG_SZ registry key:
//
// HKLM\system\currentcontrolset\services\xenvbd\DeviceN\DriverParameter
//
static ULONG
XenvbdFindAdapter(
    IN PVOID HwDeviceExtension,
    IN PVOID Context,
    IN PVOID BusInformation,
    IN PCHAR ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    OUT PBOOLEAN Again
)
{
    PHW_DEVICE_EXTENSION deviceExtension = HwDeviceExtension;
    ULONG i;
    NTSTATUS Status;
    PVOID heap = NULL;
    PVOID MemBaseVa;
    SCSI_PHYSICAL_ADDRESS IoPortBase;
    ULONG NPorts;
    SCSI_PHYSICAL_ADDRESS MemBase;
    ULONG NBytes;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(BusInformation);
    UNREFERENCED_PARAMETER(Again);

    if (AustereMode)
        TraceNotice(("%s: ====>\n", __FUNCTION__));
    else
        TraceVerbose(("%s: ====> (%d)\n", __FUNCTION__, KeGetCurrentIrql()));

    TraceVerbose(("FindAdapter: AdapterInterfaceType: %x\n",
                  ConfigInfo->AdapterInterfaceType));
    TraceVerbose(("FindAdapter: BusInterruptLevel: %x\n",
                  ConfigInfo->BusInterruptLevel));
    TraceVerbose(("FindAdapter: BusInterruptVector: %x\n",
                  ConfigInfo->BusInterruptVector));
    TraceVerbose(("FindAdapter: InterruptMode: %x\n",
                  ConfigInfo->InterruptMode));
    TraceVerbose(("FindAdapter: NumberOfBuses: %x\n",
                  ConfigInfo->NumberOfBuses));
    TraceVerbose(("FindAdapter: NumberOfAccessRanges: %x\n",
                  ConfigInfo->NumberOfAccessRanges));


    for (i=0;i<ConfigInfo->NumberOfAccessRanges;i++) {
        TraceVerbose(("FindAdapter: Range[%d] (%x, %x, %x)\n", i,
                      (*ConfigInfo->AccessRanges)[i].RangeStart,
                      (*ConfigInfo->AccessRanges)[i].RangeLength,
                      (*ConfigInfo->AccessRanges)[i].RangeInMemory));
    }

    IoPortBase = (*ConfigInfo->AccessRanges)[0].RangeStart;
    NPorts = (*ConfigInfo->AccessRanges)[0].RangeLength;
    MemBase = (*ConfigInfo->AccessRanges)[1].RangeStart;
    NBytes = (*ConfigInfo->AccessRanges)[1].RangeLength;

    if (!AustereMode)
        XenvbdIrql = (KIRQL)ConfigInfo->BusInterruptLevel;
    else
        XenvbdIrql = 0;

    //
    // No Wmi for now.
    //
    ConfigInfo->WmiDataProvider = FALSE;

    //
    // Hardware found, let's contrive the hardware config info.
    //
    ConfigInfo->NumberOfBuses = 1;
    ConfigInfo->InitiatorBusId[0] = XENVBD_MAX_DISKS;
    ConfigInfo->Master = TRUE;

    if (AustereMode) {
        ConfigInfo->NumberOfPhysicalBreaks = 0;
        ConfigInfo->MaximumTransferLength = PAGE_SIZE;
        ConfigInfo->ScatterGather = FALSE;
    } else {
        ConfigInfo->NumberOfPhysicalBreaks = XENVBD_MAX_SEGMENTS_PER_SRB - 1;
        ConfigInfo->MaximumTransferLength = (XENVBD_MAX_SEGMENTS_PER_SRB - 1) * PAGE_SIZE;
        ConfigInfo->ScatterGather = TRUE;
    }

    ConfigInfo->Dma32BitAddresses = TRUE;

    ConfigInfo->TaggedQueuing = TRUE;
    ConfigInfo->MultipleRequestPerLu = TRUE;

    ConfigInfo->AlignmentMask = 0x0;

    ConfigInfo->MaximumNumberOfTargets = XENVBD_MAX_DISKS;
    ConfigInfo->MaximumNumberOfLogicalUnits = 1;

    if (AustereMode) {
        SCSI_PHYSICAL_ADDRESS paddr;
        int nr_pages;

        TraceNotice(("Setting up the austere heap.\n"));
        heap = emergency_heap;
        nr_pages = AUSTERE_HEAP_PAGES;
        if ( ((ULONG_PTR)heap & (PAGE_SIZE - 1)) )
            heap = (void *)(((ULONG_PTR)heap + PAGE_SIZE - 1) &
                                        PAGE_MASK);
        TraceVerbose(("Heap at %lx.\n", heap));

        paddr = XenGetPhysicalAddress(heap);
        TraceNotice(("Get heap physaddr %lx\n", paddr.LowPart));

        XmInitMemory(heap, nr_pages, paddr);
        TraceNotice(("Austere heap ready.\n"));
    }

    XenvbdConfigInfo = *ConfigInfo;

    if (deviceExtension->Magic != _HW_DEVICE_EXTENSION_MAGIC) {
        TraceVerbose(("new device extension at 0x%p\n", deviceExtension));

        deviceExtension->Magic = _HW_DEVICE_EXTENSION_MAGIC;
        XenvbdDeviceExtension = deviceExtension;
    } else {
        XM_ASSERT(XenvbdDeviceExtension == deviceExtension);
    }

    if (XenPVFeatureEnabled(DEBUG_HCT_DP_HACKS))
        memset(XenvbdDeviceExtension, 0, sizeof (HW_DEVICE_EXTENSION));

    if (XenvbdTargetInfo == NULL) {
        PXHBD_TARGET_INFO *targetInfo;

        targetInfo = XmAllocateZeroedMemory(sizeof(PVOID) *
                                            ConfigInfo->MaximumNumberOfTargets);
        if (targetInfo == NULL) {
            TraceError(("XENVBD: Cannot allocate target array\n"));
            return(SP_RETURN_NOT_FOUND);
        }

        TraceVerbose(("allocated target array at 0x%p\n", targetInfo));
        XenvbdTargetInfo = targetInfo;
    }

    XenvbdDeviceExtension->MaxRingPageOrder = -1;

    // Arguments are passed to the driver by adding a registry parameter as
    // follows:
    //
    // Under HKLM\SYSTEM\CurrentControlSet\Services\xenvbd\parameters\Device0
    // add a REG_SZ called DriverParameter. This can be up to 512 characters
    // in length.
    if (ArgumentString != NULL)
        ParseArgumentString(ArgumentString);

    if (AustereMode)
        TraceNotice(("Phase 1 init done.\n"));

    /* If we can't map the whole 1MB area, try to map the
       beginning of it, since we very rarely need more than about
       half a dozen pages. */
    do {
        MemBaseVa = ScsiPortGetDeviceBase(XenvbdDeviceExtension,
                                          PCIBus,
                                          ConfigInfo->SystemIoBusNumber,
                                          MemBase,
                                          NBytes,
                                          FALSE);
        if (MemBaseVa)
            break;
        NBytes /= 2;
    } while (NBytes >= PAGE_SIZE * 8);
    if (!MemBaseVa) {
        /* We leak memory here, but (a) it should never happen, and
           (b) if it does we're going to bluescreen, so it doesn't
           matter. */
        TraceError(("Can't map iomem area.\n"));
        return SP_RETURN_NOT_FOUND;
    }

    /* The HCTs occasionally play silly buggers with driver load
       order, and arrange for xenvbd to load before xevtchn.  In that
       case, we need a working IO hole before xevtchn comes up.  We
       can use the PCI device's space for that.  Unfortunately, we
       can't just change the load order so that xenvbd always loads
       before xevtchn, because that breaks Ardence.  We therefore
       allocate a hole in *both* drivers, and just use whichever one
       gets in first.  Grr. */
    XenevtchnInitIoHole(MemBase, MemBaseVa, NBytes);

    InitOldUnplugProtocol(IoPortBase, NPorts);

    RegisterBugcheckCallbacks();
    InitDebugHelpers();

    TraceVerbose (("Starting event channel.\n"));
    Status = EvtchnStart();
    if (Status == STATUS_SUCCESS) {
        EvtchnInitialized = TRUE;
    } else {
        TraceError(("FindAdapter: EvtchnStart failed %x\n",
                    Status));
        return( SP_RETURN_NOT_FOUND );
    }

    TraceVerbose (("Starting grant table.\n"));
    status = GnttabInit();
    if (!NT_SUCCESS(status)) {
        TraceError(("FindAdapter: GnttabInit failed %x\n",
                    Status));
        EvtchnStop();
        CleanupDebugHelpers();
        DeregisterBugcheckCallbacks();
        return( SP_RETURN_NOT_FOUND );
    }

    TraceVerbose (("Starting xenbus.\n"));
    status = XenevtchnInitXenbus();
    if (!NT_SUCCESS(status)) {
        TraceError(("FindAdapter: XenevtchnInitXenbus failed %x\n",
                    Status));
        GnttabCleanup();
        EvtchnStop();
        CleanupDebugHelpers();
        DeregisterBugcheckCallbacks();
        return( SP_RETURN_NOT_FOUND );
    }

    if (AustereMode)
        TraceNotice(("Phase 2 init done.\n"));

    xenbus_write(XBT_NIL, "drivers/xenvbd", XENVBD_VERSION);

    InitBounceBuffers();

    XenvbdKickPort = EvtchnAllocUnbound(DOMAIN_ID_0(), DoInvalidate, NULL);
    if (is_null_EVTCHN_PORT(XenvbdKickPort)) {
        TraceError(("XENVBD: Cannot allocate event channel.\n"));
        return(SP_RETURN_NOT_FOUND);
    }

    if (AustereMode)
        TraceNotice(("Phase 3 init done.\n"));

    if (AustereMode)
        XenvbdSetupAustereTarget();

    if (!AustereMode) {
        // Why do we do this here?
        EvtchnLaunchSuspendThread();

        (VOID) XenQueueWork(LaunchRescanThread, NULL);
    }

    if (is_null_EVTCHN_DEBUG_CALLBACK(XenvbdDeviceExtension->DebugCallbackHandle))
        XenvbdDeviceExtension->DebugCallbackHandle =
            EvtchnSetupDebugCallback(XenvbdDebugCallback, XenvbdDeviceExtension);

    if (!AustereMode)
        XenQueueWork(ResumeAllTargets, NULL);

    if (AustereMode)
        TraceNotice(("%s: <====\n", __FUNCTION__));
    else
        TraceVerbose(("%s: <====\n", __FUNCTION__));

    return( SP_RETURN_FOUND );
}

//
// XenvbdHwInitialize - Callback routine used to initialize the
//                      HBA.
//
// This is invoked at interrupt irql, so can't do very much.
BOOLEAN XenvbdHwInitialize(
    IN PVOID HwDeviceExtension
)
{
    UNREFERENCED_PARAMETER(HwDeviceExtension);
    //
    // Configure device interrupt. The raw interrupt vector was
    // obtained from the plug-and-play subsystem earlier.
    //
    HvmSetCallbackIrq(XenvbdIrql);
    return( TRUE );
}

static VOID
XenvbdCapacity16(PXHBD_TARGET_INFO ptargetInfo,
                 PSCSI_REQUEST_BLOCK srb,
                 PVOID DataBuffer)
{
    READ_CAPACITY_DATA_EX *rcapp = DataBuffer;
    ULONG64 FixBlockEnd;
    ULONG FixBlockSize;

    TraceInfo(("target %d: READ_CAPACITY16\n", srb->TargetId));

    FixBlockEnd = ptargetInfo->sectors - 1;
    FixBlockSize = ptargetInfo->sector_size;

    // Endian conversion.
    REVERSE_BYTES_QUAD(&rcapp->LogicalBlockAddress, &FixBlockEnd);
    REVERSE_BYTES(&rcapp->BytesPerBlock, &FixBlockSize);

    srb->SrbStatus = SRB_STATUS_SUCCESS;
}

//
// XenvbdCapacity - Handle a SCSI Read Capacity request. We need
//                  to byte swap the values to make Windows happy.
//
static VOID
XenvbdCapacity(
    PXHBD_TARGET_INFO ptargetInfo,
    PSCSI_REQUEST_BLOCK srb,
    PVOID DataBuffer
)
{
    READ_CAPACITY_DATA *rcapp = DataBuffer;
    ULONG FixBlockEnd;
    ULONG FixBlockSize;

    TraceInfo(("target %d: READ_CAPACITY\n", srb->TargetId));

    if (ptargetInfo->sectors > (1ull << 32))
        FixBlockEnd = ~0ul;
    else
        FixBlockEnd = (ULONG)(ptargetInfo->sectors - 1);

    FixBlockSize = ptargetInfo->sector_size;

    // Endian conversion.
    REVERSE_BYTES(&rcapp->LogicalBlockAddress, &FixBlockEnd);
    REVERSE_BYTES(&rcapp->BytesPerBlock, &FixBlockSize);

    srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static VOID
XenvbdVerify(
    PXHBD_TARGET_INFO targetInfo,
    IN OUT PSCSI_REQUEST_BLOCK srb
    )
{
    PCDB cdb = (PCDB)srb->Cdb;
    ULONG BlockSize = targetInfo->sector_size;
    USHORT SectorCount = (cdb->CDB10.TransferBlocksMsb << 8) +
        cdb->CDB10.TransferBlocksLsb;

    TraceInfo(("VERIFY (%d)\n", srb->TargetId));

    srb->DataTransferLength = SectorCount * BlockSize;
    srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static VOID
XenvbdStartStop(
    PXHBD_TARGET_INFO targetInfo,
    IN OUT PSCSI_REQUEST_BLOCK srb
    )
{
    PCDB cdb = (PCDB)srb->Cdb;

    UNREFERENCED_PARAMETER(targetInfo);

    TraceInfo(("START_STOP (%d): %s%s (LOEJ=%d) (CONTROL=%x)\n", srb->TargetId,
               (cdb->START_STOP.Immediate) ? "IMMEDIATE " : "",
               (cdb->START_STOP.Start) ? "START" : "STOP",
               cdb->START_STOP.LoadEject,
               cdb->START_STOP.Control));

    srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static void
XenvbdReportLuns(
    IN  PSCSI_REQUEST_BLOCK     Srb,
    IN  PVOID                   DataBuffer)
{
    PCDB                        Cdb = (PCDB)Srb->Cdb;
    ULONG                       AllocationLength;
    PUCHAR                      Buffer;
    ULONG                       Offset;
    ULONG                       Length;

    if (Srb->DataTransferLength < sizeof (struct _REPORT_LUNS)) {
        TraceWarning(("target %d: invalid REPORT_LUNS SRB\n", Srb->TargetId));
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        return;
    }

    REVERSE_BYTES(&AllocationLength, &Cdb->REPORT_LUNS.AllocationLength);
    if (AllocationLength < 16) {
        TraceWarning(("target %d: invalid REPORT_LUNS SRB\n", Srb->TargetId));
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        return;
    }

    TraceInfo(("target %d: REPORT_LUNS (%02x)\n", Srb->TargetId, &Cdb->REPORT_LUNS.Control));

    Buffer = DataBuffer;
    RtlZeroMemory(Buffer, AllocationLength);

    Length = 0;

    /* Leave space for the byte count at the beginning */
    Offset = 8;

    /* Target LUN */
    if (Offset + 8 <= AllocationLength) {
        Buffer[Offset] = 0;
        Offset += 8;
        Length += 8;
    }

    /* Initiator LUN */
    if (Offset + 8 <= AllocationLength) {
        Buffer[Offset] = XENVBD_MAX_DISKS;
        Offset += 8;
        Length += 8;
    }

    REVERSE_BYTES(Buffer, &Length);

    Srb->DataTransferLength = MIN(Length, AllocationLength);
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static BOOLEAN
srb_valid_for_target(PSCSI_REQUEST_BLOCK srb, PXHBD_TARGET_INFO targetInfo)
{
    if (srb->PathId != 0) {
        TraceDebug(("SRB for invalid path (%d)\n", srb->PathId));
        return FALSE;
    }

    if (targetInfo == NULL) {
        TraceDebug(("SRB for invalid target (%d)\n", srb->TargetId));
        return FALSE;
    }

    if (srb->Lun != 0) {
        TraceDebug(("SRB for invalid LUN (%d)\n", srb->Lun));
        return FALSE;
    }

    if (targetInfo->Ejected) {
        TraceDebug(("SRB for ejected target (%d)\n", targetInfo->targetId));
        return FALSE;
    }

    if (targetInfo->Disappeared) {
        TraceDebug(("SRB for missing target (%d)\n", targetInfo->targetId));
        return FALSE;
    }
    
    return TRUE;
}

static BOOLEAN
SrbNeedsBounceBuffer(PSCSI_REQUEST_BLOCK srb, PXHBD_TARGET_INFO info)
{
    PHYSICAL_ADDRESS pa;
    ULONG length;

    pa = ScsiPortGetPhysicalAddress(XenvbdDeviceExtension,
                                    srb,
                                    srb->DataBuffer,
                                    &length);

    if (pa.LowPart & (info->sector_size - 1))
        return TRUE;
    else
        return FALSE;
}

static void
HandleScsiIoctl(PSCSI_REQUEST_BLOCK srb, PXHBD_TARGET_INFO targetInfo)
{
    struct xenvbd_ioctl_sniff *sniff;
    PSRB_IO_CONTROL header;

    srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;

    if ( srb->DataTransferLength < sizeof(*header) ) {
        TraceWarning(("Short ioctl: only %d bytes, need %d header.\n",
                      srb->DataTransferLength,
                      sizeof(*header)));
        return;
    }
    header = srb->DataBuffer;

    if ( memcmp(header->Signature, XENVBD_IOCTL_SIGNATURE,
                sizeof(XENVBD_IOCTL_SIGNATURE)) != 0 )
        return;

    /* Looks broadly sane.  Parse it up. */

    if (srb->DataTransferLength == sizeof(*header) &&
        header->ControlCode == XENVBD_IOCTL_WAKEUP) {
        TraceVerbose(("%s: WAKEUP\n", __FUNCTION__));
    
        srb->SrbStatus = SRB_STATUS_SUCCESS;
        return;
    }

    if ( srb->DataTransferLength == sizeof(*sniff) &&
         header->ControlCode == XENVBD_IOCTL_SNIFF ) {
        NTSTATUS status;

        TraceVerbose(("%s: SNIFF\n", __FUNCTION__));

        XM_ASSERT(!AustereMode);

        if (!targetInfo->Started)
            return;

        sniff = srb->DataBuffer;

        status = XenvbdFilterSniff(targetInfo, sniff);
        if (NT_SUCCESS(status))
            srb->SrbStatus = SRB_STATUS_SUCCESS;

        return;
    }

    TraceWarning(("Bad scsifilt ioctl %x (%d, %d, %d)!\n",
                  header->ControlCode, srb->DataTransferLength,
                  sizeof(*sniff), sizeof(*header)));
    return;
}

void
MaybeCompleteShutdownSrbs(PXHBD_TARGET_INFO targetInfo)
{
    PSCSI_REQUEST_BLOCK srb;

    if (targetInfo->ShutdownSrbs.srbs_cur == 0)
        return;

    if (targetInfo->PreparedSrbs.srbs_cur != 0 ||
        targetInfo->FreshSrbs.srbs_cur != 0 ||
        targetInfo->SubmittedSrbs.srbs_cur != 0) {
        TraceNotice(("target %d: defering shutdown\n", targetInfo->targetId));
        return;
    }

    TraceNotice(("target %d: completing shutdown\n", targetInfo->targetId));
    while ((srb = DequeueSrbRaw(&targetInfo->ShutdownSrbs)) != NULL) {
        srb->SrbStatus = SRB_STATUS_SUCCESS;
        CompleteSrb(srb);
    }

    XM_ASSERT(XenvbdDeviceExtension->totInFlight == 0);

    TraceNotice(("target %d: %llu SRBs processed\n", targetInfo->targetId,
                 targetInfo->totSrb));;

//    if (AustereMode)
//        _asm { int 3 };
}

//
// XenvbdStartIO - Crack the I/O request provided by the SCSI
//                 port device and handle it as appropritate.
//

BOOLEAN
XenvbdStartIO(
    IN PVOID HwDeviceExtension,
    IN PSCSI_REQUEST_BLOCK srb
)
{
    PXHBD_TARGET_INFO targetInfo;
    PSRB_EXTENSION srbExt = SrbExtension(srb);
    BOOLEAN CompleteRequest;
    KIRQL old_irql;

    memset(srbExt, 0, sizeof(*srbExt));

    XenvbdDeviceExtension->totInFlight++;
    if (XenvbdDeviceExtension->totInFlight > XenvbdDeviceExtension->maxTotInFlight)
        XenvbdDeviceExtension->maxTotInFlight = XenvbdDeviceExtension->totInFlight;

    if (srb->SrbFlags & SRB_FLAGS_QUEUE_ACTION_ENABLE &&
        srb->QueueAction != SRB_SIMPLE_TAG_REQUEST)
        TraceWarning (("Ignoring barrier request.\n"));

    srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
    CompleteRequest = TRUE;

    old_irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    targetInfo = XenvbdTargetInfo[srb->TargetId];

    if (!srb_valid_for_target(srb, targetInfo)) {
        srb->SrbStatus = SRB_STATUS_INVALID_TARGET_ID;
        goto out;
    }

    targetInfo->totSrb++;

    switch (srb->Function) {
    case SRB_FUNCTION_ABORT_COMMAND:
        TraceWarning(("target %d: ABORT_COMMAND\n", targetInfo->targetId));
        /* We can never abort requests: once they hit the
           ring, the backend can start them at any time, and
           we only get notified when they complete.  */
        srb->SrbStatus = SRB_STATUS_ABORT_FAILED;
        break;
    case SRB_FUNCTION_RESET_BUS:
        TraceNotice(("target %d: RESET_BUS\n", targetInfo->targetId));
        XenvbdResetBusHoldingLock();
        srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;
    case SRB_FUNCTION_EXECUTE_SCSI:
        switch (srb->Cdb[0]) {
        case SCSIOP_INQUIRY:
            XenvbdInquiry(targetInfo, srb, srb->DataBuffer);
            break;
        case SCSIOP_REPORT_LUNS:
            XenvbdReportLuns(srb, srb->DataBuffer);
            break;
        case SCSIOP_MODE_SENSE:
            XenvbdModeSense(targetInfo, srb, srb->DataBuffer);
            break;
        case SCSIOP_READ_CAPACITY:
            XenvbdCapacity(targetInfo, srb, srb->DataBuffer);
            break;
        case SCSIOP_READ_CAPACITY16:
            XenvbdCapacity16(targetInfo, srb, srb->DataBuffer);
            break;
        case SCSIOP_READ:
        case SCSIOP_WRITE:
        case SCSIOP_READ16:
        case SCSIOP_WRITE16: {
            if (targetInfo->FilterTarget.scsifilt) {
                XenvbdRedirectSrbThroughScsifilt(targetInfo, srb);
            } else {
                if (!targetInfo->Connected) {
                   TraceWarning(("target %d: aborting SRB\n", targetInfo->targetId));
                   srb->ScsiStatus = 0x40; /* SCSI_ABORTED */
                   targetInfo->aborted_srbs++;
                   break;
                }

                SrbExtension(srb)->bounced = SrbNeedsBounceBuffer(srb, targetInfo);

                if (SrbExtension(srb)->bounced) {
                    QueueSrbRaw(srb, &targetInfo->FreshSrbs);
                    EvtchnRaiseLocally(targetInfo->evtchn_port);
                } else {
                    XenvbdStartFastSrb(srb, targetInfo);
                }
            }
            CompleteRequest = FALSE;
            break;
        }
        case SCSIOP_VERIFY:
            XenvbdVerify(targetInfo, srb);
            break;
        case SCSIOP_START_STOP_UNIT:
            XenvbdStartStop(targetInfo, srb);
            break;
        case SCSIOP_SYNCHRONIZE_CACHE: /* We don't have a write cache,
                                          so this is a no-op. */
            TraceInfo(("target %d: SYNCHRONIZE_CACHE\n", targetInfo->targetId));
            srb->SrbStatus = SRB_STATUS_SUCCESS;
            break;
        case SCSIOP_MEDIUM_REMOVAL:
            TraceInfo(("target %d: MEDIUM_REMOVAL\n", targetInfo->targetId));
            srb->SrbStatus = SRB_STATUS_SUCCESS;
            break;
        case SCSIOP_TEST_UNIT_READY:
            TraceInfo(("target %d: TEST_UNIT_READY\n", targetInfo->targetId));
            srb->SrbStatus = SRB_STATUS_SUCCESS;
            break;
        default:
            TraceWarning(("target %d: unknown SRB SCSI OP: %d\n", targetInfo->targetId,
                          srb->Cdb[0]));
            break;
        }
        break;

    case SRB_FUNCTION_SHUTDOWN:
        TraceNotice(("target %d: SHUTDOWN\n", targetInfo->targetId));
        QueueSrbRaw(srb, &targetInfo->ShutdownSrbs);
        EvtchnRaiseLocally(targetInfo->evtchn_port);
        CompleteRequest = FALSE;
        break;

    case SRB_FUNCTION_IO_CONTROL:
        TraceVerbose(("target %d: IO_CONTROL\n", targetInfo->targetId));
        HandleScsiIoctl(srb, targetInfo);
        break;

    default:
        TraceWarning(("target %d: unknown SRB function: %d\n", targetInfo->targetId,
                       srb->Function));
        srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        break;
    }

out:
    release_irqsafe_lock(XenvbdTargetInfoLock, old_irql);

    if (CompleteRequest)
        CompleteSrb(srb);
    ScsiPortNotification(NextRequest, HwDeviceExtension);

    return TRUE;
}

//
// XenvbdAdapterControl - Handle the adapter control operations 
//                        as appropriate.
//
SCSI_ADAPTER_CONTROL_STATUS
XenvbdAdapterControl(
    IN PVOID HwDeviceExtension,
    IN SCSI_ADAPTER_CONTROL_TYPE ControlType,
    IN PVOID Parameters
)
{
    PSCSI_SUPPORTED_CONTROL_TYPE_LIST pControlTypeList;

    UNREFERENCED_PARAMETER(HwDeviceExtension);

    switch(ControlType) {
    case ScsiQuerySupportedControlTypes: {
        BOOLEAN supportedTypes[ScsiAdapterControlMax] = {
        TRUE,       // ScsiQuerySupportedControlTypes
        TRUE,       // ScsiStopAdapter
        FALSE,      // ScsiRestartAdapter
        FALSE,      // ScsiSetBootConfig
        FALSE       // ScsiSetRunningConfig
        };

        ULONG max = ScsiAdapterControlMax;
        ULONG i;

        TraceVerbose (("%s: ScsiQuerySupportedControlTypes\n", __FUNCTION__));

        pControlTypeList = (PSCSI_SUPPORTED_CONTROL_TYPE_LIST) Parameters;

        if(pControlTypeList->MaxControlType < max) {
            max = pControlTypeList->MaxControlType;
        }

        for(i = 0; i < max; i++) {
            pControlTypeList->SupportedTypeList[i] = supportedTypes[i];
        }

        break;

    }

    case ScsiStopAdapter: {
        ULONG TargetID;
        KIRQL Irql;

        TraceNotice(("%s(ScsiStopAdapter) ====> (IRQL==0x%02x)\n", __FUNCTION__, KeGetCurrentIrql()));

        TraceVerbose(("Closing kick port...\n"));
        EvtchnClose(XenvbdKickPort);
        XenvbdKickPort = null_EVTCHN_PORT();

        if (XenGetSystemPowerState() != PowerSystemSleeping3) {
            TraceVerbose(("Shutting down xenbus...\n"));
            CleanupXenbus();
            TraceVerbose(("Shutting down grant tables...\n"));
            GnttabCleanup();
            TraceVerbose(("Stopping event channels...\n"));
            EvtchnStop();

            CleanupDebugHelpers();

            XenevtchnShutdownIoHole();

            DeregisterBugcheckCallbacks();
        } else {
            // We're still unloading, even if we're going into S3, so change the via
            // to avoid locking up event channels.
            ULONG vector = EvtchnGetVector();

            HvmSetCallbackIrq(vector);
        }

        Irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
        for (TargetID = 0; TargetID < (ULONG)XENVBD_MAX_DISKS; TargetID++) {
            XHBD_TARGET_INFO *Target = XenvbdTargetInfo[TargetID];

            if (Target != NULL)
                SuspendTarget(Target);
        }
        release_irqsafe_lock(XenvbdTargetInfoLock, Irql);

        TraceNotice(("%s(ScsiStopAdapter) <====\n", __FUNCTION__));
        break;
    }

    default: {
        TraceVerbose (("%s: unhandled control type %d\n", __FUNCTION__,
                       ControlType));

        return ScsiAdapterControlUnsuccessful;
    }
    }

    return ScsiAdapterControlSuccess;
}

//
// XenvbdResetBus - Handle a request to reset the SCSI bus(es)
//                  attached to the controller.
//
static BOOLEAN
XenvbdResetBusHoldingLock(VOID)
{
    int i;
    int cntr = 0;
    PSCSI_REQUEST_BLOCK srb;

    XenvbdDeviceExtension->resetInProgress = TRUE;

    /* Abort on each target */
    for (i = 0; i < XENVBD_MAX_DISKS; i++) {
        PXHBD_TARGET_INFO targetInfo = XenvbdTargetInfo[i];

        if (targetInfo != NULL && targetInfo->Connected) {
            /* Fresh SRBs are easy. */
            while ((srb = DequeueSrbRaw(&targetInfo->FreshSrbs)) != NULL) {
                srb->ScsiStatus = 0x40; /* SCSI_ABORTED */
                CompleteSrb(srb);
            }

            /* For prepared and submitted SRBs we just wait until they
               complete normally.  We need to keep calling the event
               channel callback directly, since scsiport won't run the
               callback itself until we finish this SRB (which is also
               why we don't need to worry about races). */
            while (targetInfo->PreparedSrbs.head || targetInfo->SubmittedSrbs.head) {
                XenvbdEvtchnCallback(targetInfo);
                cntr++;
                if (targetInfo->PreparedSrbs.head || targetInfo->SubmittedSrbs.head)
                    ScsiPortStallExecution(1000);
            }
            TraceVerbose(("Unstall for reset.\n"));

            /* Clear out any pending completions. */
            XM_ASSERT(targetInfo->ring.sring != NULL);
            XenvbdEvtchnCallback(targetInfo);
        }
    }

    XenvbdDeviceExtension->resetInProgress = FALSE;

    TraceNotice(("Scsi reset took %d loops.\n", cntr));
    return TRUE;
}

BOOLEAN
XenvbdResetBus(
    IN PVOID HwDeviceExtension,
    IN ULONG PathId
)
{
    BOOLEAN res;
    KIRQL old_irql;

    UNREFERENCED_PARAMETER(HwDeviceExtension);

    XM_ASSERT(PathId == 0);

    if (AustereMode) {
        TraceNotice (("%s\n", __FUNCTION__));
    } else {
        TraceWarning (("%s: invoking debug callback...\n", __FUNCTION__));
        XenvbdDebugCallback(XenvbdDeviceExtension);
    }

    old_irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    res = XenvbdResetBusHoldingLock();
    release_irqsafe_lock(XenvbdTargetInfoLock, old_irql);
    return res;
}

BOOLEAN
XenvbdInterrupt(
    IN PVOID HwDeviceExtension
)
{
    UNREFERENCED_PARAMETER(HwDeviceExtension);

    if (EvtchnInitialized == TRUE) {
        //
        // Call back to evtchn to let it schedule its
        // DPCs.
        //
        return EvtchnHandleInterrupt(NULL, NULL);
    } else {
        TraceWarning(("XENVBD: Interrupt: evtchn !initialized\n"));
        return FALSE;
    }
}

/* Try to clean up a bit when the driver unloads.  This is a real
   hack; we should be doing this kind of cleanup at
   IRP_MN_REMOVE_DEVICE time, since that's the last chance we get to
   touch the device extension.  It doesn't really matter, though,
   because this during normal operation it's impossible to unload the
   driver.  It's only necessary during the HCTs, and, for them,
   anything which works is good enough. */
static VOID
XenvbdUnload (
    IN  PDRIVER_OBJECT  DriverObject
    )
{
    ULONG i;

    TraceVerbose(("%s", __FUNCTION__));

    //
    // Indicate unload so asynchronous callbacks\threads can just exit if 
    // executed during cleanup.
    //
    XenvbdUnloading = TRUE;

    //
    // Cleanup all resources.
    //
    if (device_area_watch) {
        xenbus_unregister_watch(device_area_watch);
        device_area_watch = NULL;
    }

    XmKillThread(XenvbdRescanThread);

    EvtchnClose(XenvbdKickPort);

    if (XenvbdTargetInfo) {
        for (i = 0; i < (ULONG)XENVBD_MAX_DISKS; i++) {
            if (XenvbdTargetInfo[i])
                XenbusDestroyTarget(XenvbdTargetInfo[i]);
        }
    }
    XmFreeMemory(XenvbdTargetInfo);

    if (ScsiportDriverUnload) {
        ScsiportDriverUnload(DriverObject);
    }

    return;
}
