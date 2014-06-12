/*
 * Copyright (c) 2013 Citrix Systems, Inc.
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
#include <csq.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
#include <sddl.h>
#include "xenv4v.h"
// Need to include this for XmFreeMemory - not sure why it is in here??
#include "scsiboot.h"

typedef struct _XENV4V_MARKER {
	ULONG marker;
	ULONG winver;
	const char *date;
	const char *time;
	ULONG build;
	ULONG hw;
} XENV4V_MARKER;

#if defined(DBG)||defined(_DEBUG)
#define XENV4V_BUILD_TYPE ' GBD'
#else
#define XENV4V_BUILD_TYPE ' LER'
#endif

#if defined(_WIN64)
#define XENV4V_HW_TYPE ' 46x'
#else
#define XENV4V_HW_TYPE ' 68x'
#endif

__declspec(dllexport) XENV4V_MARKER __xenv4v = {
    0x800000B9, WINVER, __DATE__, __TIME__, XENV4V_BUILD_TYPE, XENV4V_HW_TYPE
};

static ULONG g_osMajorVersion = 0;
static ULONG g_osMinorVersion = 0;
static LONG g_deviceCreated = 0;

//
// Initialize a security descriptor string. Refer to SDDL docs in the SDK
// for more info.
//
// System:          All access
// LocalService:    All access
// Administrators:  All access
//
static WCHAR g_win5Sddl[] = 
{
    SDDL_DACL SDDL_DELIMINATOR SDDL_PROTECTED

    SDDL_ACE_BEGIN
    SDDL_ACCESS_ALLOWED
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_GENERIC_ALL
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_LOCAL_SYSTEM
    SDDL_ACE_END

    SDDL_ACE_BEGIN
    SDDL_ACCESS_ALLOWED
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_GENERIC_ALL
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_LOCAL_SERVICE
    SDDL_ACE_END

    SDDL_ACE_BEGIN
    SDDL_ACCESS_ALLOWED
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_GENERIC_ALL
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_SEPERATOR
    SDDL_BUILTIN_ADMINISTRATORS
    SDDL_ACE_END
};

// {3a523e0a-9b28-46c9-9046-5aaaaf20e51d}
static const GUID GUID_SD_XENV4V_CONTROL_OBJECT = 
    { 0x3a523e0a, 0x9b28, 0x46c9, { 0x90, 0x46, 0x5a, 0xaa, 0xaf, 0x20, 0xe5, 0x1d } };

// ---- EVENT CHANNEL ROUTINES ----

static VOID
V4vVirqNotifyDpc(KDPC *dpc, VOID *dctx, PVOID sarg1, PVOID sarg2)
{
    XENV4V_EXTENSION  *pde = V4vGetDeviceExtension((DEVICE_OBJECT*)dctx);
    XENV4V_CONTEXT   **ctxList;
    ULONG              count = 0, i;
    KLOCK_QUEUE_HANDLE lqh;

    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(sarg1);
    UNREFERENCED_PARAMETER(sarg2);

    // In MP guests when not using VIRQs, have to lock the DPC processing
    KeAcquireInStackQueuedSpinLockAtDpcLevel(&pde->dpcLock, &lqh);

    // Get a list of active contexts and their rings
    ctxList = V4vGetAllContexts(pde, &count);

    // Loop over the contexts and process read IO for each.
    for (i = 0; ((ctxList != NULL)&&(i < count)); i++) {
        V4vProcessContextReads(pde, ctxList[i]);        
    }

    // Return the context list and drop the ref count
    V4vPutAllContexts(pde, ctxList, count);

    // Now process the notify and satisfy writes that are queued
    V4vProcessNotify(pde);

    KeReleaseInStackQueuedSpinLockFromDpcLevel(&lqh);
}

static VOID
V4vVirqNotifyIsr(VOID *ctx)
{
    XENV4V_EXTENSION *pde = V4vGetDeviceExtension((DEVICE_OBJECT*)ctx);

    // Just drop out of ISR context
    KeInsertQueueDpc(&pde->virqDpc, NULL, NULL);
}

static NTSTATUS
V4vInitializeEventChannel(PDEVICE_OBJECT fdo)
{
    XENV4V_EXTENSION   *pde = V4vGetDeviceExtension(fdo);
    KLOCK_QUEUE_HANDLE  lqh;

    KeAcquireInStackQueuedSpinLock(&pde->virqLock, &lqh);

    if (!is_null_EVTCHN_PORT(pde->virqPort)) {
        KeReleaseInStackQueuedSpinLock(&lqh);
        TraceWarning(("V4V VIRQ already bound?\n"));
	    return STATUS_SUCCESS;
    }

    pde->virqPort = EvtchnBindVirq(VIRQ_V4V, V4vVirqNotifyIsr, fdo);
    if (is_null_EVTCHN_PORT(pde->virqPort)) {
        KeReleaseInStackQueuedSpinLock(&lqh);
        TraceError(("failed to bind V4V VIRQ\n"));
	    return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeReleaseInStackQueuedSpinLock(&lqh);

    TraceNotice(("V4V VIRQ connected.\n"));

    return STATUS_SUCCESS;
}

static VOID
V4vUninitializeEventChannel(PDEVICE_OBJECT fdo)
{
    XENV4V_EXTENSION   *pde = V4vGetDeviceExtension(fdo);
    KLOCK_QUEUE_HANDLE  lqh;

    KeAcquireInStackQueuedSpinLock(&pde->virqLock, &lqh);

    if (is_null_EVTCHN_PORT(pde->virqPort)) {
        // This is ok, e.g. getting a stop and remove PnP call
        KeReleaseInStackQueuedSpinLock(&lqh);
	    return;
    }

    EvtchnClose(pde->virqPort);
    pde->virqPort = null_EVTCHN_PORT();

    KeReleaseInStackQueuedSpinLock(&lqh);

    TraceNotice(("V4V VIRQ disconnected.\n"));
}

// ---- TIMER ROUTINES ----

static VOID
V4vConnectTimerDpc(KDPC *dpc, VOID *dctx, PVOID sarg1, PVOID sarg2)
{
    XENV4V_EXTENSION  *pde = V4vGetDeviceExtension((DEVICE_OBJECT*)dctx);
    XENV4V_CONTEXT   **ctxList;
    ULONG              count = 0, i;

    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(sarg1);
    UNREFERENCED_PARAMETER(sarg2);

    // The periodic timer is used to driver the connector SYN/ACK state machine.
    // Ultimately it simply drives the receive logic just as the the notify
    // DPC does. It should only be active when there are contexts in the 
    // CONNECTING state present.

    // Get a list of active contexts and their rings
    ctxList = V4vGetAllContexts(pde, &count);

    // Loop over the contexts and process read IO for each.
    for (i = 0; ((ctxList != NULL)&&(i < count)); i++) {
        V4vProcessContextReads(pde, ctxList[i]);
    }

    // Return the context list and drop the ref count
    V4vPutAllContexts(pde, ctxList, count);
}

VOID
V4vStartConnectionTimer(XENV4V_EXTENSION *pde)
{
    KLOCK_QUEUE_HANDLE lqh;
    ULONG              count;
    LARGE_INTEGER      due;

    KeAcquireInStackQueuedSpinLock(&pde->timerLock, &lqh);    
    count = ++pde->timerCounter;
    KeReleaseInStackQueuedSpinLock(&lqh);

    // Just transitioned from 1
    if (count == 1) {
        due.QuadPart = XENV4V_LARGEINT_DELAY(XENV4V_TIMER_INTERVAL/2);
        KeSetTimerEx(&pde->timer, due, XENV4V_TIMER_INTERVAL, &pde->timerDpc);
    }
}

VOID
V4vStopConnectionTimer(XENV4V_EXTENSION *pde, BOOLEAN immediate)
{
    KLOCK_QUEUE_HANDLE lqh;
    ULONG              count = (ULONG)-1;

    KeAcquireInStackQueuedSpinLock(&pde->timerLock, &lqh);
    if (immediate) {
        count = pde->timerCounter = 0;
    }
    else if (pde->timerCounter > 0) {
        count = --pde->timerCounter;
    }
    KeReleaseInStackQueuedSpinLock(&lqh);

    // Dropped back to 0, turn off the timer
    if (count == 0) {
        KeCancelTimer(&pde->timer);
    }
}

// ---- START WORK ROUTINES ----

static IO_WORKITEM_ROUTINE V4vDehibernateWorkItem;
static VOID NTAPI
V4vDehibernateWorkItem(PDEVICE_OBJECT fdo, PVOID ctx)
{
    PIO_WORKITEM wi  = (PIO_WORKITEM)ctx;

    if (xenbus_await_initialisation()) {        
        (VOID)V4vInitializeEventChannel(fdo);
        TraceNotice(("dehibrination work item initialized VIRQ.\n"));
    }
    else {
        TraceError(("wait for XENBUS initialization failed, cannot connect VIRQ.\n"));
    }

    IoFreeWorkItem(wi);
}

static VOID
V4vStartDehibernateWorkItem(PDEVICE_OBJECT fdo)
{
    PIO_WORKITEM wi;

    TraceNotice(("starting dehibrination work item.\n"));

    wi = IoAllocateWorkItem(fdo);
    if (wi == NULL) {   
        TraceError(("failed to allocate dehibernate work item - out of memory.\n"));
        return;
    }

    IoQueueWorkItem(wi, V4vDehibernateWorkItem, DelayedWorkQueue, wi);
}

// ---- BASE DRIVER ROUTINES ----

NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath);
static DRIVER_UNLOAD V4vDriverUnload;
static VOID NTAPI V4vDriverUnload(PDRIVER_OBJECT driverObject);

static VOID
V4vDisconnectAllStreams(XENV4V_EXTENSION *pde)
{
    XENV4V_CONTEXT **ctxList;
    ULONG            count = 0, i;

    // Get a list of active contexts and their rings
    ctxList = V4vGetAllContexts(pde, &count);

    // Loop over the contexts and disconnect any stream file objects
    for (i = 0; ((ctxList != NULL)&&(i < count)); i++) {
        if (InterlockedExchangeAdd(&(ctxList[i]->type), 0) & XENV4V_FILE_TYPE_STREAM) {
            V4vDisconnectStreamAndSignal(pde, ctxList[i]);            
        }
    }

    // Return the context list and drop the ref count
    V4vPutAllContexts(pde, ctxList, count);
}


static VOID
V4vStopDevice(PDEVICE_OBJECT fdo, PXENV4V_EXTENSION pde)
{
    PIRP pendingIrp;
    XENV4V_QPEEK peek;

    // Go to the stopped state to prevent IO, stop the timer and
    // interrupt (ec).
    InterlockedExchange(&pde->state, XENV4V_DEV_STOPPED);
    V4vUninitializeEventChannel(fdo);
    KeCancelTimer(&pde->timer);

    peek.types = XENV4V_PEEK_STREAM;              // process for stream types
    peek.ops   = XENV4V_PEEK_SYN|XENV4V_PEEK_ACK; // all SYN/ACK ops
    peek.pfo   = NULL;                            // not using file object search
    peek.dst.domain = DOMID_INVALID;              // not using destination search
    peek.dst.port   = V4V_PORT_NONE;

    pendingIrp = IoCsqRemoveNextIrp(&pde->csqObject, &peek);
    while (pendingIrp != NULL) {
        V4vSimpleCompleteIrp(pendingIrp, STATUS_CANCELLED);
        pendingIrp = IoCsqRemoveNextIrp(&pde->csqObject, &peek);
    }
}

static IO_COMPLETION_ROUTINE V4vStartDeviceIoCompletion;
static NTSTATUS
V4vStartDeviceIoCompletion(PDEVICE_OBJECT fdo, PIRP irp, PVOID context)
{
    UNREFERENCED_PARAMETER(fdo);
    UNREFERENCED_PARAMETER(irp);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));
    KeSetEvent((PKEVENT)context, IO_NO_INCREMENT, FALSE);
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static DRIVER_DISPATCH V4vDispatchPnP;
static NTSTATUS NTAPI
V4vDispatchPnP(PDEVICE_OBJECT fdo, PIRP irp)
{
    NTSTATUS           status = STATUS_SUCCESS;
    PIO_STACK_LOCATION isl = IoGetCurrentIrpStackLocation(irp);
    PXENV4V_EXTENSION  pde = V4vGetDeviceExtension(fdo);
    KEVENT             kev;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    TraceVerbose((" =PnP= 0x%x\n", isl->MinorFunction));

    status = IoAcquireRemoveLock(&pde->removeLock, irp);
    if (!NT_SUCCESS(status)) {
        TraceError(("failed to acquire IO lock - error: 0x%x\n", status));
        return V4vSimpleCompleteIrp(irp, status);
    }

    switch (isl->MinorFunction) {
    case IRP_MN_START_DEVICE:
        KeInitializeEvent(&kev, NotificationEvent, FALSE);
        // Send the start down and wait for it to complete
        IoCopyCurrentIrpStackLocationToNext(irp);
        IoSetCompletionRoutine(irp, V4vStartDeviceIoCompletion, &kev, TRUE, TRUE, TRUE);
        status = IoCallDriver(pde->ldo, irp);
        if (status == STATUS_PENDING) {
            // Wait for everything underneath us to complete
            TraceVerbose(("Device start waiting for lower device.\n"));
            KeWaitForSingleObject(&kev, Executive, KernelMode, FALSE, NULL);
            TraceVerbose(("Device start wait finished.\n"));
        }

        status = irp->IoStatus.Status;
        if (!NT_SUCCESS(status)) {
            TraceError(("Failed to start lower drivers: %x.\n", status));
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            break;
        }

        status = STATUS_SUCCESS;

        // Connect our interrupt (ec).
        status = V4vInitializeEventChannel(fdo);
        if (NT_SUCCESS(status)) {
            InterlockedExchange(&pde->state, XENV4V_DEV_STARTED);
        }
        else {
            TraceError(("failed to initialize event channel - error: 0x%x\n", status));
        }

        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        break;
    case IRP_MN_STOP_DEVICE:
        // Stop our device's IO processing
        V4vStopDevice(fdo, pde);

        // Pass it down
        irp->IoStatus.Status = STATUS_SUCCESS;
        IoSkipCurrentIrpStackLocation(irp);
        status = IoCallDriver(pde->ldo, irp);
        break;        
    case IRP_MN_REMOVE_DEVICE:
        // Stop our device's IO processing
        V4vStopDevice(fdo, pde);

        // Cleanup anything here that locks for IO
        IoReleaseRemoveLockAndWait(&pde->removeLock, irp);

        // Pass it down first
        IoSkipCurrentIrpStackLocation(irp);
        status = IoCallDriver(pde->ldo, irp);

        // Then detach and cleanup our device
        xenbus_change_state(XBT_NIL, pde->frontendPath, "state", XENBUS_STATE_CLOSED);
        IoDetachDevice(pde->ldo);
        ExDeleteNPagedLookasideList(&pde->destLookasideList);
        XmFreeMemory(pde->frontendPath);
        IoDeleteSymbolicLink(&pde->symbolicLink);
        IoDeleteDevice(fdo);
        InterlockedAnd(&g_deviceCreated, 0);
        return status;
    default:
        // Pass it down
        TraceVerbose(("IRP_MJ_PNP MinorFunction %d passed down\n", isl->MinorFunction));
        IoSkipCurrentIrpStackLocation(irp);
        status = IoCallDriver(pde->ldo, irp);
    };

    // Everybody but REMOVE
    IoReleaseRemoveLock(&pde->removeLock, irp); 

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return status;
}

static DRIVER_DISPATCH V4vDispatchWmi;
static NTSTATUS NTAPI
V4vDispatchWmi(PDEVICE_OBJECT fdo, PIRP irp)
{
    NTSTATUS          status;
    PXENV4V_EXTENSION pde = V4vGetDeviceExtension(fdo);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    // We don't support WMI, so just pass it on down the stack

    status = IoAcquireRemoveLock(&pde->removeLock, irp);
    if (!NT_SUCCESS(status)) {
        TraceError(("failed to acquire IO lock - error: 0x%x\n", status));        
        return V4vSimpleCompleteIrp(irp, status);
    }

    IoSkipCurrentIrpStackLocation(irp);
    status = IoCallDriver(pde->ldo, irp);

    IoReleaseRemoveLock(&pde->removeLock, irp);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
 
    return status;
}

static DRIVER_DISPATCH V4vDispatchPower;
static NTSTATUS NTAPI
V4vDispatchPower(PDEVICE_OBJECT fdo, PIRP irp)
{
    NTSTATUS           status;
    PXENV4V_EXTENSION  pde = V4vGetDeviceExtension(fdo);
    PIO_STACK_LOCATION isl = IoGetCurrentIrpStackLocation(irp);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    switch (isl->MinorFunction) {
    case IRP_MN_SET_POWER:
        if (isl->Parameters.Power.Type == SystemPowerState) {
            TraceNotice(("SET system power: %d %d\n",
                          isl->Parameters.Power.State.SystemState,
                          isl->Parameters.Power.ShutdownType));

            // If we are transitioning from the working (S0) power state to a lower state,
            // disconnect the VIRQ. If we are resuming to the working power state, re-connect.           
            if (isl->Parameters.Power.State.SystemState == PowerSystemWorking) {
                // When resuming from hibernation w/ multi-vCPUs, the pv drivers
                // may be initialized in parallel causing problems with xenbus being
                // initialized before we try to bind our VIRQ. Kick the job off to a 
                // work item and wait for initialization there.
                if (pde->lastPoState == PowerSystemHibernate) {
                    V4vStartDehibernateWorkItem(fdo);
                }
                else {
                    (VOID)V4vInitializeEventChannel(fdo);
                }
            }
            else if (isl->Parameters.Power.State.SystemState >= PowerSystemSleeping1) {
                V4vUninitializeEventChannel(fdo);               
            }

            // If the last state was S4, flush all connections
            if (pde->lastPoState == PowerSystemHibernate) {
                V4vDisconnectAllStreams(pde);
            }

            // Reset the last state to what we just saw
            pde->lastPoState = isl->Parameters.Power.State.SystemState;
        }
        else if (isl->Parameters.Power.Type == DevicePowerState) {
            TraceNotice(("SET device power: %d %d\n",
                         isl->Parameters.Power.State.SystemState,
                         isl->Parameters.Power.ShutdownType));
        }
        break;
    case IRP_MN_QUERY_POWER:
        if (isl->Parameters.Power.Type == SystemPowerState) {
            TraceNotice(("QUERY system power: %d %d\n",
                          isl->Parameters.Power.State.SystemState,
                          isl->Parameters.Power.ShutdownType));
        }
        else if (isl->Parameters.Power.Type == DevicePowerState) {
            TraceNotice(("QUERY device power: %d %d\n",
                         isl->Parameters.Power.State.SystemState,
                         isl->Parameters.Power.ShutdownType));
        }
        break;
    };    

    status = IoAcquireRemoveLock(&pde->removeLock, irp);
    if (!NT_SUCCESS(status)) {
        TraceError(("failed to acquire IO lock - error: 0x%x\n", status));
        PoStartNextPowerIrp(irp); // for xp and 2k3
        return V4vSimpleCompleteIrp(irp, status);
    }

    PoStartNextPowerIrp(irp); // for xp and 2k3
    IoSkipCurrentIrpStackLocation(irp);
    status = PoCallDriver(pde->ldo, irp);

    IoReleaseRemoveLock(&pde->removeLock, irp);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return status;
}

static DRIVER_ADD_DEVICE V4vAddDevice;
static NTSTATUS
V4vAddDevice(PDRIVER_OBJECT driverObject, PDEVICE_OBJECT pdo)
{
    NTSTATUS          status = STATUS_SUCCESS;
    UNICODE_STRING    deviceName;
    PDEVICE_OBJECT    fdo = NULL;
    PXENV4V_EXTENSION pde = NULL;
    LONG              val;
    BOOLEAN           symlink = FALSE;
    LARGE_INTEGER     seed;
    WCHAR            *szSddl = NULL;
    UNICODE_STRING    sddlString;
    CHAR             *szFpath = NULL;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    // We only allow one instance of this device type. If more than on pdo is created we need
    val = InterlockedCompareExchange(&g_deviceCreated, 1, 0);
    if (val != 0) {
        TraceWarning(("cannot instantiate more that one v4v device node.\n"));
        return STATUS_UNSUCCESSFUL;
    }

    do {
        // Create our device
        RtlInitUnicodeString(&deviceName, V4V_DEVICE_NAME);
        szSddl = g_win5Sddl;
        RtlInitUnicodeString(&sddlString, szSddl);

        status = 
            IoCreateDeviceSecure(driverObject,
                                 sizeof(XENV4V_EXTENSION),
                                 &deviceName,
                                 FILE_DEVICE_UNKNOWN,
                                 FILE_DEVICE_SECURE_OPEN,
                                 FALSE,
                                 &sddlString,
                                 (LPCGUID)&GUID_SD_XENV4V_CONTROL_OBJECT,
                                 &fdo);
        if (!NT_SUCCESS(status)) {
            TraceError(("failed to create device object - error: 0x%x\n", status));
            fdo = NULL;
            break;
        }

        pde = (PXENV4V_EXTENSION)fdo->DeviceExtension;
        RtlZeroMemory(pde, sizeof(XENV4V_EXTENSION));
        RtlStringCchCopyW(pde->symbolicLinkText, XENV4V_SYM_NAME_LEN, V4V_SYMBOLIC_NAME);
        RtlInitUnicodeString(&pde->symbolicLink, pde->symbolicLinkText);

        // Create our symbolic link
        status = IoCreateSymbolicLink(&pde->symbolicLink, &deviceName);
        if (!NT_SUCCESS(status)) {
            TraceError(("failed to create symbolic - error: 0x%x\n", status));
            break;
        }
        symlink = TRUE;       

        // Get our xenstore path
        szFpath = xenbus_find_frontend(pdo);
        if (szFpath == NULL) {
            status = STATUS_NO_SUCH_DEVICE;
            TraceError(("failed to locate XenStore front end path\n"));
            break;
        }

        // Setup the extension
        pde->magic = XENV4V_MAGIC;
        pde->pdo = pdo;
        pde->fdo = fdo;
        IoInitializeRemoveLock(&pde->removeLock, 'v4vx', 0, 0);
        pde->frontendPath = szFpath;
        szFpath = NULL;
        pde->state = XENV4V_DEV_STOPPED; // wait for start
        pde->lastPoState = PowerSystemWorking;
        pde->virqPort = null_EVTCHN_PORT();
        KeInitializeDpc(&pde->virqDpc, V4vVirqNotifyDpc, fdo);
        KeInitializeSpinLock(&pde->virqLock);
        KeInitializeSpinLock(&pde->dpcLock);
        KeInitializeTimerEx(&pde->timer, NotificationTimer);
        KeInitializeDpc(&pde->timerDpc,
                        V4vConnectTimerDpc,
                        fdo);
        KeInitializeSpinLock(&pde->timerLock);
        pde->timerCounter = 0;
        InitializeListHead(&pde->contextList);
        KeInitializeSpinLock(&pde->contextLock);
        pde->contextCount = 0;
        InitializeListHead(&pde->ringList);
        KeInitializeSpinLock(&pde->ringLock);
        InitializeListHead(&pde->pendingIrpQueue);
        pde->pendingIrpCount = 0;
        KeInitializeSpinLock(&pde->queueLock);
        IoCsqInitializeEx(&pde->csqObject,
                          V4vCsqInsertIrpEx,
                          V4vCsqRemoveIrp,
                          V4vCsqPeekNextIrp,
                          V4vCsqAcquireLock,
                          V4vCsqReleaseLock,
                          V4vCsqCompleteCanceledIrp);
        InitializeListHead(&pde->destList);
        pde->destCount = 0;
        ExInitializeNPagedLookasideList(&pde->destLookasideList,
                                        NULL,
                                        NULL,
                                        0,
                                        sizeof(XENV4V_DESTINATION),
                                        XENV4V_TAG,
                                        0);
        KeQueryTickCount(&seed);
        pde->seed = seed.u.LowPart;

        // Now attach us to the stack
        pde->ldo = IoAttachDeviceToDeviceStack(fdo, pdo);
        if (pde->ldo == NULL) {
            TraceError(("failed to attach device to stack - error: 0x%x\n", status));
            status = STATUS_NO_SUCH_DEVICE;
            break;
        }

        // Use direct IO and let the IO manager directly map user buffers; clear the init flag
        fdo->Flags |= DO_DIRECT_IO;
        fdo->Flags &= ~DO_DEVICE_INITIALIZING;        

        // Made it here, go to connected state to be consistent
        xenbus_change_state(XBT_NIL, pde->frontendPath, "state", XENBUS_STATE_CONNECTED);
    } while (FALSE);

    if (!NT_SUCCESS(status)) {
        if (fdo != NULL) {         
            if ((pde != NULL)&&(pde->ldo != NULL)) {
                IoDetachDevice(pde->ldo);
            }
            if (szFpath != NULL) {
                XmFreeMemory(szFpath);
            }
            if (symlink) {
                IoDeleteSymbolicLink(&pde->symbolicLink);
            }
            IoDeleteDevice(fdo);
        }
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return status;
}

#pragma alloc_text(INIT, DriverEntry)
NTSTATUS NTAPI
DriverEntry(PDRIVER_OBJECT driverObject,
			PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);	

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    PsGetVersion(&g_osMajorVersion, &g_osMinorVersion, NULL, NULL);

    if ((g_osMajorVersion < 5)||((g_osMajorVersion == 5)&&(g_osMinorVersion < 1))) {
        TraceWarning(("Windows XP or later operating systems supported!\n"));
        return STATUS_UNSUCCESSFUL;
    }

    TraceInfo(("Starting driver...\n"));

    driverObject->DriverUnload = V4vDriverUnload;
    driverObject->DriverExtension->AddDevice = V4vAddDevice;
	
    driverObject->MajorFunction[IRP_MJ_CREATE]         = V4vDispatchCreate;
    driverObject->MajorFunction[IRP_MJ_CLEANUP]        = V4vDispatchCleanup;
    driverObject->MajorFunction[IRP_MJ_CLOSE]          = V4vDispatchClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = V4vDispatchDeviceControl;
    driverObject->MajorFunction[IRP_MJ_READ]           = V4vDispatchRead;
    driverObject->MajorFunction[IRP_MJ_WRITE]          = V4vDispatchWrite;
    driverObject->MajorFunction[IRP_MJ_PNP]            = V4vDispatchPnP;
    driverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = V4vDispatchWmi;
    driverObject->MajorFunction[IRP_MJ_POWER]          = V4vDispatchPower;
    // The rest can be handled by the system not supported routine

    TraceVerbose(("DriverEntry returning successfully\n"));

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return STATUS_SUCCESS;
}

static VOID NTAPI
V4vDriverUnload(PDRIVER_OBJECT driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);
	
    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
}
