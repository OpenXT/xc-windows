/*
 * Copyright (c) 2012 Citrix Systems, Inc.
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

// Xen Windows PV M2B Bus Driver

#include <ntddk.h>
#include <ntstrsafe.h>
#include <hidport.h>
#include <sddl.h>
#include <wdmsec.h>
#include "input.h"
#include "xmou.h"
#include "xenm2b.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);

static DRIVER_ADD_DEVICE XenM2BAddDevice;

static IO_COMPLETION_ROUTINE XenM2BComplete;

static DRIVER_DISPATCH XenM2BPnP;

static DRIVER_DISPATCH XenM2BPower;

static DRIVER_DISPATCH XenM2BIoctl;

static DRIVER_DISPATCH XenM2BCreate;

static DRIVER_DISPATCH XenM2BClose;

static DRIVER_UNLOAD XenM2BUnload;

static VOID
XenM2BCleanupResources(PXENM2B_FDO_EXTENSION pFdoExt);

static NTSTATUS
XenM2BConfigureResources(PXENM2B_FDO_EXTENSION pFdoExt,
                         PCM_RESOURCE_LIST pResourceList);

static VOID
XenM2BHwEnable(PXENM2B_FDO_EXTENSION pFdoExt, ULONG MASK);

static VOID
XenM2BHwDisable(PXENM2B_FDO_EXTENSION pFdoExt, ULONG MASK);

static NTSTATUS
XenM2BStartDevice(PXENM2B_FDO_EXTENSION pFdoExt,
                  PIO_STACK_LOCATION pIrpStack,
                  PIRP pIrp);

static NTSTATUS
XenM2BQueryDeviceRelations(PXENM2B_FDO_EXTENSION pFdoExt,
                           PIO_STACK_LOCATION pIrpStack,
                           PIRP pIrp);

// TODO find other pageable code
#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, XenM2BAddDevice)
#pragma alloc_text(PAGE, XenM2BCreate)
#pragma alloc_text(PAGE, XenM2BClose)
#pragma alloc_text(PAGE, XenM2BIoctl)
#pragma alloc_text(PAGE, XenM2BPower)
#pragma alloc_text(PAGE, XenM2BUnload)
#pragma alloc_text(PAGE, XenM2BHwEnable)
#pragma alloc_text(PAGE, XenM2BHwDisable)
#pragma alloc_text(PAGE, XenM2BCleanupResources)
#pragma alloc_text(PAGE, XenM2BConfigureResources)
#pragma alloc_text(PAGE, XenM2BStartDevice)
//#pragma alloc_text(PAGE, XenM2BPnP)
//#pragma alloc_text(PAGE, XenM2BQueryDeviceRelations)
#endif

//
// Initialize a security descriptor string. Refer to SDDL docs in the SDK
// for more info.
//
// System:          All access
// LocalService:    All access
// Administrators:  All access
//
static WCHAR g_XenM2BSddl[] =
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

// {30FE3FC0-307E-4bd8-BA3B-E452181FA7BE}
static const GUID GUID_SD_XENM2B_CONTROL_OBJECT =
{ 0x30fe3fc0, 0x307e, 0x4bd8, { 0xba, 0x3b, 0xe4, 0x52, 0x18, 0x1f, 0xa7, 0xbe } };

static NTSTATUS
XenM2BSimpleCompleteIrp(PIRP pIrp, NTSTATUS Status)
{
    pIrp->IoStatus.Information = 0;
    pIrp->IoStatus.Status = Status;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return Status;
}

// Generic completion routine that allows the driver to send the irp down the
// stack, catch it on the way up, and do more processing at the original IRQL.
static NTSTATUS
XenM2BComplete(PDEVICE_OBJECT pDeviceObject, PIRP pIrp, PVOID pContext)
{
    PKEVENT pEvent = (PKEVENT)pContext;

    UNREFERENCED_PARAMETER(pDeviceObject);
    UNREFERENCED_PARAMETER(pIrp);

    // We could switch on the major and minor functions of the IRP to perform
    // different functions, but we know that Context is an event that needs
    // to be set.
    KeSetEvent(pEvent, 0, FALSE);

    // Allows the caller to use the IRP after it is completed
    return STATUS_MORE_PROCESSING_REQUIRED;
}

BOOLEAN
XenM2BInterruptService(PKINTERRUPT pInterrupt, PDEVICE_OBJECT pDeviceObject)
{
    PXENM2B_FDO_EXTENSION pFdoExt = (PXENM2B_FDO_EXTENSION)pDeviceObject->DeviceExtension;
    ULONG StatusReg;

    StatusReg = READ_REGISTER_ULONG((PULONG)(pFdoExt->pGlobalRegs + XMOU_ISR));
    if (StatusReg & XMOU_ISR_INT) {
        // Dismiss the interrupt
        WRITE_REGISTER_ULONG((PULONG)(pFdoExt->pGlobalRegs + XMOU_ISR), StatusReg);
        KeInsertQueueDpc(&pFdoExt->EventDpc, NULL, NULL);
        return TRUE;
    }
    return FALSE;
}

VOID
XenM2BDeleteDevice(PXENM2B_FDO_EXTENSION pFdoExt)
{
    PDEVICE_OBJECT pDevice = pFdoExt->pDevice;

    TraceDebug(("%s: Entry\n", __FUNCTION__));

    ASSERT(pFdoExt->References == 0);
    IoDetachDevice(pFdoExt->pTopOfStack);
    IoDeleteSymbolicLink(&pFdoExt->SymbolicLink);
    IoDeleteDevice(pDevice);

    TraceDebug(("%s: Exit\n", __FUNCTION__));
}

static NTSTATUS
XenM2BAddDevice(PDRIVER_OBJECT pDriver, PDEVICE_OBJECT pPdo)
{
    PXENM2B_FDO_EXTENSION pFdoExt;
    PDEVICE_OBJECT        pDevice;
    NTSTATUS              Status = STATUS_SUCCESS;
    UNICODE_STRING        DeviceString;
    UNICODE_STRING        SddlString;

    PAGED_CODE();

    TraceDebug(("%s: Entry\n", __FUNCTION__));

    RtlInitUnicodeString(&DeviceString, XENM2B_DEVICE_NAME);
    RtlInitUnicodeString(&SddlString, g_XenM2BSddl);

    Status = IoCreateDeviceSecure(pDriver,
                                  sizeof(XENM2B_FDO_EXTENSION),
                                  &DeviceString,
                                  FILE_DEVICE_MOUSE,
                                  FILE_DEVICE_SECURE_OPEN,
                                  FALSE,
                                  &SddlString,
                                  (LPCGUID)&GUID_SD_XENM2B_CONTROL_OBJECT,
                                  &pDevice);

    if (!NT_SUCCESS(Status))
        return Status;

    RtlZeroMemory(pDevice->DeviceExtension, sizeof(XENM2B_FDO_EXTENSION));
    pFdoExt = (PXENM2B_FDO_EXTENSION)pDevice->DeviceExtension;

    RtlStringCchCopyW(pFdoExt->SymbolicLinkText,
                      XENM2B_SYM_NAME_LENGTH,
                      XENM2B_SYMBOLIC_NAME);
    RtlInitUnicodeString(&pFdoExt->SymbolicLink,
                         pFdoExt->SymbolicLinkText);

    // Create our symbolic link
    Status = IoCreateSymbolicLink(&pFdoExt->SymbolicLink, &DeviceString);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(pDevice);
        return Status;
    }

    pFdoExt->pTopOfStack = IoAttachDeviceToDeviceStack(pDevice, pPdo);
    if (pFdoExt->pTopOfStack == NULL) {
        IoDeleteSymbolicLink(&pFdoExt->SymbolicLink);
        IoDeleteDevice(pDevice);
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    TraceDebug(("%s: Created device:%wZ Sym:%wZ\n", __FUNCTION__, &DeviceString, &pFdoExt->SymbolicLink));

    ASSERT(pFdoExt->pTopOfStack != NULL);

    pFdoExt->pDevice = pDevice;
    pFdoExt->pBusPdo = pPdo;
    pFdoExt->pDriver = pDriver;

    pDevice->Flags |= (DO_BUFFERED_IO | DO_POWER_PAGABLE);
    pDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    ExInitializeFastMutex(&pFdoExt->DevicePnPState.PnPStateMutex);
    XenM2BSetPnPState(&pFdoExt->DevicePnPState, PnPStateAdded);

    pFdoExt->SystemPowerState = PowerSystemWorking;
    pFdoExt->DevicePowerState = PowerDeviceD3;

    KeInitializeSpinLock(&pFdoExt->InterruptSpinLock);
    KeInitializeSpinLock(&pFdoExt->DpcSpinLock);
    KeInitializeDpc(&pFdoExt->EventDpc, XenM2BEventDpc, pDevice);

    InitializeListHead(&pFdoExt->PdoList);
    KeInitializeSpinLock(&pFdoExt->PdoListLock);
    pFdoExt->References = 1; // For the FDO reference

    TraceDebug(("%s: Exit Status:%x\n", __FUNCTION__, Status));
    return Status;
}

static NTSTATUS
XenM2BConfigureResources(PXENM2B_FDO_EXTENSION pFdoExt,
                         PCM_RESOURCE_LIST pResourceList)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR pPRList;
    ULONG c, i;
    NTSTATUS Status;
    KINTERRUPT_MODE InterruptMode;
    BOOLEAN ShareVector;
    ULONG MagicReg;

    PAGED_CODE();

    TraceDebug(("%s: Entry\n", __FUNCTION__));

    c = pResourceList->List[0].PartialResourceList.Count;
    pPRList = &pResourceList->List[0].PartialResourceList.PartialDescriptors[0];
    for (i = 0; i < c; i++, pPRList++) {
        if (pPRList->Type >= CmResourceTypeMaximum)
            continue;

        else if (pPRList->Type == CmResourceTypeMemory) {
            // The xenmou MMIO registers region in BAR0.
            RtlMoveMemory(&pFdoExt->XenM2BRegistersDescriptor,
                          pPRList,
                          sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
            TraceDebug(("MMIO BAR base == %x:%x size == 0x%x\n",
                        pFdoExt->XenM2BRegistersDescriptor.u.Memory.Start.HighPart,
                        pFdoExt->XenM2BRegistersDescriptor.u.Memory.Start.LowPart,
                        pFdoExt->XenM2BRegistersDescriptor.u.Memory.Length));
        }
        else if (pPRList->Type == CmResourceTypeInterrupt) {
            // The interrupt is hooked up below.
            RtlMoveMemory(&pFdoExt->InterruptDescriptor,
                          pPRList,
                          sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));

            TraceDebug(("IRQ level == %d vector == %d\n",
                        pFdoExt->InterruptDescriptor.u.Interrupt.Level,
                        pFdoExt->InterruptDescriptor.u.Interrupt.Vector));
        }
        else {
            // Not expecting this.
            TraceWarning(("Unknown resource at %d\n", i));
        }
    }

    // Map in MMIO registers
    pFdoExt->pXenM2BRegs =
        (PUCHAR)MmMapIoSpace(pFdoExt->XenM2BRegistersDescriptor.u.Memory.Start,
                             pFdoExt->XenM2BRegistersDescriptor.u.Memory.Length,
                             MmNonCached);
    if (pFdoExt->pXenM2BRegs == NULL) {
        TraceError(("MmMapIoSpace(MMIO register range) failed!\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    pFdoExt->pGlobalRegs = pFdoExt->pXenM2BRegs;
    pFdoExt->pEventRegs = pFdoExt->pXenM2BRegs + PAGE_SIZE;

    // Sanity check
    MagicReg = READ_REGISTER_ULONG((PULONG)(pFdoExt->pGlobalRegs + XMOU_MAGIC));
    if (MagicReg != XMOU_MAGIC_VALUE) {
        TraceError(("Start device detected unknown magic value: 0x%x\n", MagicReg));
        XenM2BCleanupResources(pFdoExt);
        return STATUS_UNSUCCESSFUL;
    }
    TraceDebug(("Read magic == 0x%x\n", MagicReg));

    // Get the event structure size and number of event pages
    pFdoExt->EventSize = READ_REGISTER_ULONG((PULONG)(pFdoExt->pGlobalRegs + XMOU_EVENT_SIZE));
    TraceDebug(("Read event structure size == 0x%x\n", pFdoExt->EventSize));
    pFdoExt->EventRegsPages = READ_REGISTER_ULONG((PULONG)(pFdoExt->pGlobalRegs + XMOU_EVENT_NPAGES));
    TraceDebug(("Read event regs pages == 0x%x\n", pFdoExt->EventRegsPages));
    pFdoExt->EventCount = ((pFdoExt->EventRegsPages*PAGE_SIZE)/pFdoExt->EventSize) - 1; //First event cell has read/write pointers
    pFdoExt->RWRegSize = pFdoExt->EventSize; // for clarity - the RW ptr regs reside in an event sized area

    // Locate the config size and config page
    pFdoExt->ConfigSize = READ_REGISTER_ULONG((PULONG)(pFdoExt->pGlobalRegs + XMOU_CONFIG_SIZE));
    TraceDebug(("Read config structure size == 0x%x\n", pFdoExt->ConfigSize));
    pFdoExt->pConfigRegs = pFdoExt->pEventRegs + (pFdoExt->EventRegsPages * PAGE_SIZE);

    // Interrupt values
    InterruptMode = (pFdoExt->InterruptDescriptor.Flags == CM_RESOURCE_INTERRUPT_LATCHED) ? Latched : LevelSensitive;
    ShareVector = (pFdoExt->InterruptDescriptor.ShareDisposition == CmResourceShareShared) ? TRUE : FALSE;

    // Connect the interrupt
    Status = IoConnectInterrupt(&(pFdoExt->pInterruptObject),
                                (PKSERVICE_ROUTINE)XenM2BInterruptService,
                                pFdoExt->pDevice,
                                &pFdoExt->InterruptSpinLock,
                                pFdoExt->InterruptDescriptor.u.Interrupt.Vector,
                                (KIRQL)pFdoExt->InterruptDescriptor.u.Interrupt.Level,
                                (KIRQL)pFdoExt->InterruptDescriptor.u.Interrupt.Level,
                                InterruptMode,
                                ShareVector,
                                pFdoExt->InterruptDescriptor.u.Interrupt.Affinity,
                                FALSE);
    if (!NT_SUCCESS(Status)) {
        TraceError(("IoConnectInterrupt failed! - status: 0x%x\n", Status));
        XenM2BCleanupResources(pFdoExt);
        return Status;
    }

    TraceDebug(("%s: Exit Status:%x\n", __FUNCTION__, STATUS_SUCCESS));
    return STATUS_SUCCESS;
}

static VOID
XenM2BCleanupResources(PXENM2B_FDO_EXTENSION pFdoExt)
{
    PAGED_CODE();

    if (pFdoExt->pInterruptObject != NULL) {
        IoDisconnectInterrupt(pFdoExt->pInterruptObject);
        pFdoExt->pInterruptObject = NULL;
    }

    if (pFdoExt->pXenM2BRegs != NULL) {
        MmUnmapIoSpace(pFdoExt->pXenM2BRegs,
                       pFdoExt->XenM2BRegistersDescriptor.u.Memory.Length);
        pFdoExt->pGlobalRegs = NULL;
        pFdoExt->pXenM2BRegs = NULL;
        pFdoExt->pEventRegs = NULL;
        pFdoExt->EventRegsPages = 0;
        pFdoExt->EventSize = 0;
        pFdoExt->RWRegSize = 0;
        pFdoExt->ConfigSize = 0;
    }
}

static VOID
XenM2BHwEnable(PXENM2B_FDO_EXTENSION pFdoExt, ULONG Mask)
{
	// Called during PnP start
    ULONG ControlReg;
    ULONG RevisionReg;

    PAGED_CODE();

    if (pFdoExt->pGlobalRegs != NULL) {
        // Write and read the revision register and make sure it reports a supported revision
        WRITE_REGISTER_ULONG((PULONG)(pFdoExt->pGlobalRegs + XMOU_CLIENT_REV), XMOU2_CLIENT_REV);

        RevisionReg = READ_REGISTER_ULONG((PULONG)(pFdoExt->pGlobalRegs + XMOU_CLIENT_REV));
        if (RevisionReg != XMOU2_CLIENT_REV) {
            TraceError(("%s Unsupported XMOU rev:%d Read:%d\n", __FUNCTION__, XMOU2_CLIENT_REV, RevisionReg));
            XenM2BHwDisable(pFdoExt, XMOU_CONTROL_XMOU_EN|XMOU_CONTROL_INT_EN);
        }
        else {
            TraceDebug(("%s: XMOU REV: %d\n", __FUNCTION__, XMOU2_CLIENT_REV));

            ControlReg = READ_REGISTER_ULONG((PULONG)(pFdoExt->pGlobalRegs + XMOU_CONTROL));
            TraceDebug(("%s: Read control register == 0x%x\n", __FUNCTION__, ControlReg));
            ControlReg |= Mask;
            WRITE_REGISTER_ULONG((PULONG)(pFdoExt->pGlobalRegs + XMOU_CONTROL), ControlReg);
            TraceDebug(("%s: Wrote control register == 0x%x\n", __FUNCTION__, ControlReg));
        }
    }
}

static VOID
XenM2BHwDisable(PXENM2B_FDO_EXTENSION pFdoExt, ULONG Mask)
{
    // Called during PnP remove
    ULONG ControlReg;

    PAGED_CODE();

    if (pFdoExt->pGlobalRegs != NULL) {
	    ControlReg = READ_REGISTER_ULONG((PULONG)(pFdoExt->pGlobalRegs + XMOU_CONTROL));
        TraceDebug(("%s: Read control register == 0x%x\n", __FUNCTION__, ControlReg));
        ControlReg &= ~Mask;
        WRITE_REGISTER_ULONG((PULONG)(pFdoExt->pGlobalRegs + XMOU_CONTROL), ControlReg);
        TraceDebug(("%s: Wrote control register == 0x%x\n", __FUNCTION__, ControlReg));
    }
}

static NTSTATUS
XenM2BStartDevice(PXENM2B_FDO_EXTENSION pFdoExt,
                  PIO_STACK_LOCATION pIrpStack,
                  PIRP pIrp)
{
    NTSTATUS    Status = STATUS_SUCCESS;
    KEVENT      Event;
    POWER_STATE PowerState;

    PAGED_CODE();

    TraceDebug(("%s: Entry\n", __FUNCTION__));

    // The device is starting.
    //
    // We cannot touch the device (send it any non pnp irps) until a
    // start device has been passed down to the lower drivers.
    IoCopyCurrentIrpStackLocationToNext(pIrp);
    KeInitializeEvent(&Event,
                      NotificationEvent,
                      FALSE);

    IoSetCompletionRoutine(pIrp,
                           (PIO_COMPLETION_ROUTINE)XenM2BComplete,
                           &Event,
                           TRUE,
                           TRUE,
                           TRUE); // No need for Cancel

    Status = IoCallDriver(pFdoExt->pTopOfStack, pIrp);

    if (STATUS_PENDING == Status) {
        KeWaitForSingleObject(&Event,
                              Executive, // Waiting for reason of a driver
                              KernelMode, // Waiting in kernel mode
                              FALSE, // No allert
                              NULL); // No timeout

        Status = pIrp->IoStatus.Status;
    }

    if (NT_SUCCESS(Status)) {
        // As we are successfully now back from our start device
        // we can do work. Setup IRQ and MMIO resources
        Status = XenM2BConfigureResources(pFdoExt,
                                          pIrpStack->Parameters.StartDevice.AllocatedResourcesTranslated);
        if (NT_SUCCESS(Status)) {
	        XenM2BHwEnable(pFdoExt, XMOU_CONTROL_XMOU_EN | XMOU_CONTROL_INT_EN);
        }
		else {
            TraceError(("Start device, failed to configure device resoruces. Error: 0x%x\n", Status));
		}
    }

    // Inidcate device state D0
    pFdoExt->DevicePowerState = PowerDeviceD0;
    PowerState.DeviceState = PowerDeviceD0;
    PoSetPowerState(pFdoExt->pDevice, DevicePowerState, PowerState);

    // Switch to started PnP state
    XenM2BSetPnPState(&pFdoExt->DevicePnPState, PnPStateStarted);

    // We must now complete the IRP, since we stopped it in the
    // completion routine with MORE_PROCESSING_REQUIRED.
    pIrp->IoStatus.Status = Status;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    TraceDebug(("%s: Exit Status:%x\n", __FUNCTION__, Status));
    return Status;
}

static NTSTATUS
XenM2BQueryDeviceRelations(PXENM2B_FDO_EXTENSION pFdoExt,
                           PIO_STACK_LOCATION pIrpStack,
                           PIRP pIrp)
{
    PXENM2B_PDO_EXTENSION pPdoExt = NULL;
    PXENM2B_PDO_EXTENSION pPdoExtCurr = NULL;
    PXENM2B_PDO_EXTENSION pPdoExtList = NULL;
    PLIST_ENTRY           pEntry;
    PDEVICE_RELATIONS     pRelations;
    NTSTATUS              Status = STATUS_SUCCESS;
    ULONG                 Count, i, Length;
    KIRQL                 Irql;

    if (pIrpStack->Parameters.QueryDeviceRelations.Type != BusRelations) {
        pIrp->IoStatus.Status = STATUS_SUCCESS;
        IoSkipCurrentIrpStackLocation(pIrp);
        return IoCallDriver(pFdoExt->pTopOfStack, pIrp);
    }

    KeAcquireSpinLock(&pFdoExt->PdoListLock, &Irql);

    Count = 0;
    ListForEach(pEntry, &pFdoExt->PdoList) {
        pPdoExt = CONTAINING_RECORD(pEntry, XENM2B_PDO_EXTENSION, ListEntry);

        if (pPdoExt->Missing)
            continue;

        if (XenM2BGetPnPState(&pPdoExt->DevicePnPState) == PnPStatePresent)
            XenM2BSetPnPState(&pPdoExt->DevicePnPState, PnPStateEnumerated);

        ObReferenceObject(pPdoExt->pDevice);

        // Chain the ones to report for relationships on the bus together.
        ASSERT(pPdoExt->pNextExt == NULL);

        if (pPdoExtList != NULL) {
            pPdoExtCurr->pNextExt = pPdoExt;
            pPdoExtCurr = pPdoExt;
        }
        else {
            pPdoExtCurr = pPdoExt;
            pPdoExtList = pPdoExt;
        }

        Count++;
    }

    KeReleaseSpinLock(&pFdoExt->PdoListLock, Irql);

    Length = FIELD_OFFSET(DEVICE_RELATIONS, Objects) +
             (sizeof(PDEVICE_OBJECT) * Count);

    pRelations = ExAllocatePoolWithTag(PagedPool,
                                       Length,
                                       XENM2B_POOL_TAG);
    if (pRelations == NULL) {
        TraceError(("%s: Failed to allocate relations structure\n", __FUNCTION__));
        pIrp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(pRelations, Length);

    pRelations->Count = Count;
    for (i = 0; i < Count; i++) {
        ASSERT(pPdoExtList != NULL);
        pRelations->Objects[i] = pPdoExtList->pDevice;
        pPdoExtCurr = pPdoExtList;
        pPdoExtList = pPdoExtList->pNextExt;
        pPdoExtCurr->pNextExt = NULL;
    }

    pIrp->IoStatus.Information = (ULONG_PTR)pRelations;
    pIrp->IoStatus.Status = STATUS_SUCCESS;

    IoSkipCurrentIrpStackLocation(pIrp);
    Status = IoCallDriver(pFdoExt->pTopOfStack, pIrp);

    TraceDebug(("%s: Exit %d PDO(s) Status:%x\n", __FUNCTION__, Count, Status));
    return Status;
}

// This routine is the dispatch routine for plug and play IRPs
static NTSTATUS
XenM2BPnP(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    PXENM2B_FDO_EXTENSION pFdoExt = (PXENM2B_FDO_EXTENSION)pDeviceObject->DeviceExtension;
    PXENM2B_PDO_EXTENSION pPdoExt;
    PIO_STACK_LOCATION    pIrpStack;
    PLIST_ENTRY           pEntry;
    NTSTATUS              Status = STATUS_SUCCESS;
    ULONG                 Count;
    BOOLEAN               CallNext = TRUE;
    KIRQL                 Irql;

    pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

    if (XenM2BDeviceType(pDeviceObject->DeviceExtension) == XenM2BPdo)
        return XenM2BPdoPnP(pDeviceObject, pIrp);

    switch (pIrpStack->MinorFunction) {
    case IRP_MN_START_DEVICE:
    {
        TraceDebug(("%s: IRP_MN_START_DEVICE\n", __FUNCTION__));

        // Call subroutine, this one is big. IRP completed in call.
        Status = XenM2BStartDevice(pFdoExt, pIrpStack, pIrp);
        CallNext = FALSE;
        break;
    }

    case IRP_MN_STOP_DEVICE:
        TraceDebug(("%s: IRP_MN_STOP_DEVICE\n", __FUNCTION__));

        // Disable interrupt and leave xenmou mode if not already done.
        if (XenM2BGetPnPState(&pFdoExt->DevicePnPState) == PnPStateStopPending)
            XenM2BHwDisable(pFdoExt, XMOU_CONTROL_XMOU_EN | XMOU_CONTROL_INT_EN);

        XenM2BCleanupResources(pFdoExt);

        XenM2BSetPnPState(&pFdoExt->DevicePnPState, PnPStateStopped);
        pIrp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        TraceDebug(("%s: IRP_MN_SURPRISE_REMOVAL\n", __FUNCTION__));

        // Disable interrupt and leave xenmou mode.
        XenM2BHwDisable(pFdoExt, XMOU_CONTROL_XMOU_EN | XMOU_CONTROL_INT_EN);

        XenM2BCleanupResources(pFdoExt);

        XenM2BSetPnPState(&pFdoExt->DevicePnPState, PnPStateSurpriseRemoval);

        // Mark all PDO devices as missing
        KeAcquireSpinLock(&pFdoExt->PdoListLock, &Irql);

        ListForEach(pEntry, &pFdoExt->PdoList) {
            pPdoExt = CONTAINING_RECORD(pEntry, XENM2B_PDO_EXTENSION, ListEntry);
            pPdoExt->Missing = TRUE;
        }

        KeReleaseSpinLock(&pFdoExt->PdoListLock, Irql);

        // Same as a remove device, but don't call IoDetach or IoDeleteDevice
        pIrp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_REMOVE_DEVICE:
        TraceDebug(("%s: IRP_MN_REMOVE_DEVICE\n", __FUNCTION__));

        // Disable interrupt and leave xenmou mode if not already done.
        if (XenM2BGetPnPState(&pFdoExt->DevicePnPState) == PnPStateRemovePending)
            XenM2BHwDisable(pFdoExt, XMOU_CONTROL_XMOU_EN | XMOU_CONTROL_INT_EN);

        XenM2BCleanupResources(pFdoExt);

        // Removal code here, clean up child PDO devices.
        KeAcquireSpinLock(&pFdoExt->PdoListLock, &Irql);

        pEntry = RemoveHeadList(&pFdoExt->PdoList);
        while (pEntry != &pFdoExt->PdoList) {
            pPdoExt = CONTAINING_RECORD(pEntry, XENM2B_PDO_EXTENSION, ListEntry);

            if (XenM2BGetPnPState(&pPdoExt->DevicePnPState) == PnPStateSurpriseRemoval) {
                // Pdo Cleanup
                XenM2BPdoUnlink(pPdoExt, TRUE);
                XenM2BPdoDeleteDevice(pPdoExt->pDevice);
            }
        }

        // Drop one reference for the FDO itself
        ASSERT(pFdoExt->References > 0);
        Count = --pFdoExt->References;

        KeReleaseSpinLock(&pFdoExt->PdoListLock, Irql);

        XenM2BSetPnPState(&pFdoExt->DevicePnPState, PnPStateDeleted);

        CallNext = FALSE;
        pIrp->IoStatus.Status = STATUS_SUCCESS;
        IoSkipCurrentIrpStackLocation(pIrp);
        Status = IoCallDriver(pFdoExt->pTopOfStack, pIrp);

        if (Count == 0)
            XenM2BDeleteDevice(pFdoExt);

        break;

    case IRP_MN_QUERY_DEVICE_RELATIONS:
        TraceDebug(("%s: IRP_MN_QUERY_DEVICE_RELATIONS\n", __FUNCTION__));

        // Bunch of work for the bus to do in this one.
        Status = XenM2BQueryDeviceRelations(pFdoExt, pIrpStack, pIrp);
        CallNext = FALSE;
        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
        TraceDebug(("%s: IRP_MN_QUERY_REMOVE_DEVICE\n", __FUNCTION__));

        XenM2BSetPnPState(&pFdoExt->DevicePnPState, PnPStateRemovePending);
        // Disable interrupt and leave xenmou mode early since a remove is coming.
        XenM2BHwDisable(pFdoExt, XMOU_CONTROL_INT_EN);
        pIrp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_QUERY_STOP_DEVICE:
        TraceDebug(("%s: IRP_MN_QUERY_STOP_DEVICE\n", __FUNCTION__));

        XenM2BSetPnPState(&pFdoExt->DevicePnPState, PnPStateStopPending);
        // Disable interrupt and leave xenmou mode early since a stop is coming.
        XenM2BHwDisable(pFdoExt, XMOU_CONTROL_XMOU_EN|XMOU_CONTROL_INT_EN);
        pIrp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        TraceDebug(("%s: IRP_MN_CANCEL_REMOVE_DEVICE\n", __FUNCTION__));

        if (XenM2BRestorePnPState(&pFdoExt->DevicePnPState, PnPStateRemovePending))
            XenM2BHwEnable(pFdoExt, XMOU_CONTROL_INT_EN); // Remove canceled, re-enable
        pIrp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        TraceDebug(("%s: IRP_MN_CANCEL_STOP_DEVICE\n", __FUNCTION__));

        if (XenM2BRestorePnPState(&pFdoExt->DevicePnPState, PnPStateStopPending))
            XenM2BHwEnable(pFdoExt, XMOU_CONTROL_INT_EN); // Stop canceled, re-enable
        pIrp->IoStatus.Status = STATUS_SUCCESS;
        break;

    case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
    case IRP_MN_QUERY_INTERFACE:
    case IRP_MN_QUERY_CAPABILITIES:
    case IRP_MN_QUERY_DEVICE_TEXT:
    case IRP_MN_QUERY_RESOURCES:
    case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
    case IRP_MN_READ_CONFIG:
    case IRP_MN_WRITE_CONFIG:
    case IRP_MN_EJECT:
    case IRP_MN_SET_LOCK:
    case IRP_MN_QUERY_ID:
    case IRP_MN_QUERY_PNP_DEVICE_STATE:
    default:
        break;
    }

    if (CallNext) {
        IoSkipCurrentIrpStackLocation(pIrp);
        Status = IoCallDriver(pFdoExt->pTopOfStack, pIrp);
    }

    return Status;
}

static NTSTATUS
XenM2BPower(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    PIO_STACK_LOCATION    pIrpStack;
    PXENM2B_FDO_EXTENSION pFdoExt;
    POWER_STATE           PowerState;
    POWER_STATE_TYPE      PowerType;

    PAGED_CODE();

    if (XenM2BDeviceType(pDeviceObject->DeviceExtension) == XenM2BPdo)
        return XenM2BPdoPower(pDeviceObject, pIrp);

    pFdoExt = (PXENM2B_FDO_EXTENSION)pDeviceObject->DeviceExtension;
    pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

    PowerType = pIrpStack->Parameters.Power.Type;
    PowerState = pIrpStack->Parameters.Power.State;

    switch (pIrpStack->MinorFunction) {
    case IRP_MN_SET_POWER:      
        TraceDebug(("%s: IRP_MN_SET_POWER Type:%d\n", __FUNCTION__, PowerType));
        if (PowerType == DevicePowerState) {
            TraceDebug(("%s: IRP_MN_SET_POWER DevicePowerState:%d\n", __FUNCTION__, PowerState.DeviceState));
            pFdoExt->DevicePowerState = PowerState.DeviceState;
        }
        else {
            // Else a system power state
            TraceDebug(("%s: IRP_MN_SET_POWER SystemPowerState:%d\n", __FUNCTION__, PowerState.SystemState));
            pFdoExt->SystemPowerState = PowerState.SystemState;

            // For sleep/hibernate we seem to get System power states only.
            // Disable XENMOU2 interupts on sleep/hibernate, re-enable on wakeup. Don't completely disable XENMOU2
            // as it will reset all the devices on wakeup if we do.
            //
            if (PowerSystemWorking == PowerState.SystemState) {
                XenM2BHwEnable(pFdoExt, XMOU_CONTROL_INT_EN);
            }
            else  {
                XenM2BHwDisable(pFdoExt, XMOU_CONTROL_INT_EN);
            }
        }
        break;

    case IRP_MN_QUERY_POWER:
        TraceDebug(("%s: IRP_MN_QUERY_POWER Type:%d\n", __FUNCTION__, PowerType));
        break;

    case IRP_MN_WAIT_WAKE:
    case IRP_MN_POWER_SEQUENCE:
    default:
        break;
    }

    PoStartNextPowerIrp(pIrp);
    IoSkipCurrentIrpStackLocation(pIrp);
    return PoCallDriver(pFdoExt->pTopOfStack, pIrp);
}

static NTSTATUS
XenM2BWmi(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    PXENM2B_FDO_EXTENSION pFdoExt;
    NTSTATUS              Status = STATUS_NOT_SUPPORTED;

    TraceDebug(("%s: Entry\n", __FUNCTION__));

    if (XenM2BDeviceType(pDeviceObject->DeviceExtension) == XenM2BPdo) {
        pIrp->IoStatus.Status = Status;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    }
    else if (XenM2BDeviceType(pDeviceObject->DeviceExtension) == XenM2BFdo) {
        pFdoExt = pDeviceObject->DeviceExtension;

        IoSkipCurrentIrpStackLocation(pIrp);
        Status = IoCallDriver(pFdoExt->pTopOfStack, pIrp);
    }
    else {
        ASSERT(FALSE);
    }

    TraceDebug(("%s: Exit Status:%x\n", __FUNCTION__, Status));
    return Status;
}

// This routine is the dispatch routine for internal device control requests.
static NTSTATUS
XenM2BIoctl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    PIO_STACK_LOCATION    pIrpStack;
    PXENM2B_FDO_EXTENSION pFdoExt = (PXENM2B_FDO_EXTENSION)pDeviceObject->DeviceExtension;
    NTSTATUS              Status = STATUS_SUCCESS;
    PVOID                 pIoBuffer;
    ULONG                 IoInLen;

    PAGED_CODE();

    TraceDebug(("%s: Entry\n", __FUNCTION__));

    pIrp->IoStatus.Information = 0;
    pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
    pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
    IoInLen = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;

    switch (pIrpStack->Parameters.DeviceIoControl.IoControlCode) {
    case XENINP_IOCTL_ACCELERATION:
    {
        XENINP_ACCELERATION *pAccel = (XENINP_ACCELERATION*)pIoBuffer;

        if (IoInLen == sizeof(XENINP_ACCELERATION)) {
			WRITE_REGISTER_ULONG((PULONG)(pFdoExt->pGlobalRegs + XMOU_ACCELERATION),
                                 pAccel->Acceleration);
        }
        else {
            Status = STATUS_INVALID_PARAMETER;
        }

        break;
    }
    default:
		Status = STATUS_INVALID_PARAMETER;
        break;
    }

    TraceDebug(("%s: Exit Status:%x\n", __FUNCTION__, Status));

    return XenM2BSimpleCompleteIrp(pIrp, Status);
}

// Maintain a simple count of the creates sent against this device
static NTSTATUS
XenM2BCreate(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(pDeviceObject);

    TraceDebug(("%s: Entry\n", __FUNCTION__));

    return XenM2BSimpleCompleteIrp(pIrp, STATUS_SUCCESS);
}

// Maintain a simple count of the closes sent against this device
static NTSTATUS
XenM2BClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(pDeviceObject);

    TraceDebug(("%s: Entry\n", __FUNCTION__));

    return XenM2BSimpleCompleteIrp(pIrp, STATUS_SUCCESS);
}

// Free all the allocated resources associated with this driver.
static VOID
XenM2BUnload(PDRIVER_OBJECT pDriver)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(pDriver);

    ASSERT(NULL == pDriver->DeviceObject);
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT  pDriverObject,
            PUNICODE_STRING pRegistryPath)
{
    UNREFERENCED_PARAMETER(pRegistryPath);

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = XenM2BCreate;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE]  = XenM2BClose;
    pDriverObject->MajorFunction[IRP_MJ_PNP]    = XenM2BPnP;
    pDriverObject->MajorFunction[IRP_MJ_POWER]  = XenM2BPower;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = XenM2BIoctl;
    pDriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = XenM2BWmi;

    // The rest can be handled by the system not supported routine

    pDriverObject->DriverUnload = XenM2BUnload;
    pDriverObject->DriverExtension->AddDevice = XenM2BAddDevice;

    return STATUS_SUCCESS;
}
