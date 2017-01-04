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

#include <ntddk.h>
#include <ntstrsafe.h>
#include <kbdmou.h>
#include <ntddmou.h>
#include <sddl.h>
#include <wdmsec.h>
#include "input.h"
#include "xmou.h"
#include "xeninp.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);

static DRIVER_ADD_DEVICE XenInpAddDevice;

static DRIVER_DISPATCH XenInpCreate;

static DRIVER_DISPATCH XenInpClose;

static IO_COMPLETION_ROUTINE XenInpComplete;

static DRIVER_DISPATCH XenInpIoCtl;

static DRIVER_DISPATCH XenInpDispatchPassThrough;

static DRIVER_DISPATCH XenInpInternIoCtl;

static DRIVER_DISPATCH XenInpPnP;

static DRIVER_DISPATCH XenInpPower;

static DRIVER_UNLOAD XenInpUnload;

static VOID
XenInpCleanupResources(PXENINP_DEVICE_EXTENSION pDevExt);

static NTSTATUS
XenInpConfigureResources(PXENINP_DEVICE_EXTENSION pDevExt,
                         PCM_RESOURCE_LIST pResourceList);

static VOID
XenInpEnable(PXENINP_DEVICE_EXTENSION pDevExt);

static VOID
XenInpDisable(PXENINP_DEVICE_EXTENSION pDevExt);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, XenInpAddDevice)
#pragma alloc_text (PAGE, XenInpCreate)
#pragma alloc_text (PAGE, XenInpClose)
#pragma alloc_text (PAGE, XenInpIoCtl)
#pragma alloc_text (PAGE, XenInpDispatchPassThrough)
#pragma alloc_text (PAGE, XenInpInternIoCtl)
#pragma alloc_text (PAGE, XenInpPnP)
#pragma alloc_text (PAGE, XenInpPower)
#pragma alloc_text (PAGE, XenInpUnload)
#pragma alloc_text (PAGE, XenInpEnable)
#pragma alloc_text (PAGE, XenInpDisable)
#pragma alloc_text (PAGE, XenInpCleanupResources)
#pragma alloc_text (PAGE, XenInpConfigureResources)
#endif

//
// Initialize a security descriptor string. Refer to SDDL docs in the SDK
// for more info.
//
// System:          All access
// LocalService:    All access
// Administrators:  All access
//
static WCHAR g_XinpSddl[] = 
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

// {DB947B7F-1DEF-4f4f-B63C-67F56B87EE17}
static const GUID GUID_SD_XENINP_CONTROL_OBJECT = 
{ 0xdb947b7f, 0x1def, 0x4f4f, { 0xb6, 0x3c, 0x67, 0xf5, 0x6b, 0x87, 0xee, 0x17 } };

static __inline NTSTATUS
XenInpSimpleCompleteIrp(PIRP pIrp, NTSTATUS Status)
{
    pIrp->IoStatus.Information = 0;
    pIrp->IoStatus.Status = Status;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return Status;
}

static BOOLEAN
XenInpEventConvert(PMOUSE_INPUT_DATA pMouInpData, PXENMOU_EVENT pMouEvent)
{
    if (XENMOU_GET_REVISION(pMouEvent->RevFlags) != 1)
        return FALSE;
    else if (XENMOU_TEST_FLAG(pMouEvent->RevFlags, XMOU_FLAG_FENCE))
        return FALSE;

    RtlZeroMemory(pMouInpData, sizeof(MOUSE_INPUT_DATA));

    if (XENMOU_TEST_FLAG(pMouEvent->RevFlags, XMOU_FLAG_ABSOLUTE))
    {
        pMouInpData->Flags = MOUSE_MOVE_ABSOLUTE | MOUSE_VIRTUAL_DESKTOP;
        pMouInpData->LastX = XENMOU_GET_ABS_XDATA(pMouEvent->Data);
        pMouInpData->LastY = XENMOU_GET_ABS_YDATA(pMouEvent->Data);
        //DbgPrint("XENINP: XenInpEventConvert: Absolute LastX=%x LastY=%x\n", pMouInpData->LastX, pMouInpData->LastY);
    }
    else if (XENMOU_TEST_FLAG(pMouEvent->RevFlags, XMOU_FLAG_RELATIVE))
    {
        pMouInpData->Flags = MOUSE_MOVE_RELATIVE;
        pMouInpData->LastX = XENMOU_GET_REL_XDATA(pMouEvent->Data);
        pMouInpData->LastY = XENMOU_GET_REL_YDATA(pMouEvent->Data);
        //DbgPrint("XENINP: XenInpEventConvert: Relative LastX=%x LastY=%x\n", pMouInpData->LastX, pMouInpData->LastY);
    }
    else if (XENMOU_TEST_FLAG(pMouEvent->RevFlags, XMOU_FLAG_LEFT_BUTTON_DOWN))
    {
        pMouInpData->ButtonFlags = MOUSE_LEFT_BUTTON_DOWN;
    }
    else if (XENMOU_TEST_FLAG(pMouEvent->RevFlags, XMOU_FLAG_LEFT_BUTTON_UP))
    {
        pMouInpData->ButtonFlags = MOUSE_LEFT_BUTTON_UP;
    }
    else if (XENMOU_TEST_FLAG(pMouEvent->RevFlags, XMOU_FLAG_RIGHT_BUTTON_DOWN))
    {
        pMouInpData->ButtonFlags = MOUSE_RIGHT_BUTTON_DOWN;
    }
    else if (XENMOU_TEST_FLAG(pMouEvent->RevFlags, XMOU_FLAG_RIGHT_BUTTON_UP))
    {
        pMouInpData->ButtonFlags = MOUSE_RIGHT_BUTTON_UP;
    }
    else if (XENMOU_TEST_FLAG(pMouEvent->RevFlags, XMOU_FLAG_MIDDLE_BUTTON_DOWN))
    {
        pMouInpData->ButtonFlags = MOUSE_MIDDLE_BUTTON_DOWN;
    }
    else if (XENMOU_TEST_FLAG(pMouEvent->RevFlags, XMOU_FLAG_MIDDLE_BUTTON_UP))
    {
        pMouInpData->ButtonFlags = MOUSE_MIDDLE_BUTTON_UP;
    }
    else if (XENMOU_TEST_FLAG(pMouEvent->RevFlags, XMOU_FLAG_HWHEEL))
    {
        pMouInpData->ButtonFlags = MOUSE_HWHEEL;
        pMouInpData->ButtonData = XENMOU_GET_WDATA(pMouEvent->Data) * WHEEL_DELTA;
    }
    else if (XENMOU_TEST_FLAG(pMouEvent->RevFlags, XMOU_FLAG_VWHEEL))
    {
        pMouInpData->ButtonFlags = MOUSE_WHEEL;
        pMouInpData->ButtonData = XENMOU_GET_WDATA(pMouEvent->Data) * WHEEL_DELTA;
    }
    else
        return FALSE;

    return TRUE;
}


static VOID NTAPI
XenInpEventCallback(PVOID pDevCtx, XENMOU_EVENT *pEventArray, ULONG Count)
{
    PXENINP_DEVICE_EXTENSION         pDevExt;
    ULONG                            i,InputDataConsumed;
    LONG                             j;

    pDevExt = (PXENINP_DEVICE_EXTENSION) pDevCtx;

    i = 0;
    while (i < Count) {
        for (j = 0; j < XENMOU_DIC && i < Count; j++, i++) {
            if (!XenInpEventConvert(&pDevExt->InputArray[j], &pEventArray[i]))
                j--;
        }

        //
        // UpperConnectData must be called at DISPATCH
        //
        if (j > 0) { // In case we get an array full of fences
            (*(PSERVICE_CALLBACK_ROUTINE) pDevExt->UpperConnectData.ClassService)(
                pDevExt->UpperConnectData.ClassDeviceObject,
                &pDevExt->InputArray[0],
                &pDevExt->InputArray[j],
                &InputDataConsumed
                );
        }
    }
}

// ISR and DPC
static VOID
XenInpIsrDpc(PKDPC pDpc, PDEVICE_OBJECT pDeviceObject, PIRP pIrp, PVOID pContext)
{
#define XenInpGetEventRevFlags(p, r) (p->pEventRegs + p->RWStructSize + (r*p->EventStructSize))
#define XenInpGetEventData(p, r) (p->pEventRegs + p->RWStructSize + (r*p->EventStructSize) + sizeof(ULONG))

    PXENINP_DEVICE_EXTENSION pDevExt = (PXENINP_DEVICE_EXTENSION)pDeviceObject->DeviceExtension;
    ULONG ReadPointer, WritePointer, EventCount, i;   

    UNREFERENCED_PARAMETER(pDpc);
    UNREFERENCED_PARAMETER(pIrp);
    UNREFERENCED_PARAMETER(pContext);

    KeAcquireSpinLockAtDpcLevel(&pDevExt->EventLock);

    EventCount = pDevExt->EventCount;

    do {
        // Auto alloc a block of events for each pass
        XENMOU_EVENT pEvents[XENINP_EVENT_ARRAY_SIZE];

        ReadPointer = READ_REGISTER_ULONG((PULONG)(pDevExt->pEventRegs + XMOU_READ_PTR));
        WritePointer = READ_REGISTER_ULONG((PULONG)(pDevExt->pEventRegs + XMOU_WRITE_PTR));
        i = 0;

        if (ReadPointer == WritePointer)
            break;

        while ((ReadPointer != WritePointer)&&(i != XENINP_EVENT_ARRAY_SIZE)) {
            pEvents[i].RevFlags = READ_REGISTER_ULONG((PULONG)XenInpGetEventRevFlags(pDevExt, ReadPointer));
            pEvents[i].Data = READ_REGISTER_ULONG((PULONG)XenInpGetEventData(pDevExt, ReadPointer));

            i++;
            ReadPointer++;
            ReadPointer %= EventCount;
        }

        WRITE_REGISTER_ULONG((PULONG)(pDevExt->pEventRegs + XMOU_READ_PTR), ReadPointer);
        XenInpEventCallback(pDevExt, pEvents, i);
    } while (TRUE);

    KeReleaseSpinLockFromDpcLevel(&pDevExt->EventLock);
}

BOOLEAN
XenInpInterruptService(PKINTERRUPT pInterrupt, PDEVICE_OBJECT pDeviceObject)
{
    PXENINP_DEVICE_EXTENSION pDevExt = (PXENINP_DEVICE_EXTENSION)pDeviceObject->DeviceExtension;    
    ULONG StatusReg;

    StatusReg = READ_REGISTER_ULONG((PULONG)(pDevExt->pGlobalRegs + XMOU_ISR));
    if (StatusReg & XMOU_ISR_INT) {
        // Dismiss the interrupt
        WRITE_REGISTER_ULONG((PULONG)(pDevExt->pGlobalRegs + XMOU_ISR), StatusReg);    
        IoRequestDpc(pDeviceObject, NULL, NULL);
        return TRUE;
    }

    return FALSE;
}

static NTSTATUS
XenInpAddDevice(PDRIVER_OBJECT pDriver, PDEVICE_OBJECT pPDO)
{
    PXENINP_DEVICE_EXTENSION pDevExt;
    PDEVICE_OBJECT           pDevice;
    NTSTATUS                 Status = STATUS_SUCCESS;
    UNICODE_STRING           DeviceString;
    UNICODE_STRING           SddlString;

    PAGED_CODE();

    RtlInitUnicodeString(&DeviceString, XENINP_DEVICE_NAME);
    RtlInitUnicodeString(&SddlString, g_XinpSddl);

    Status = IoCreateDeviceSecure(pDriver,
                                  sizeof(XENINP_DEVICE_EXTENSION),
                                  &DeviceString,
                                  FILE_DEVICE_MOUSE,
                                  FILE_DEVICE_SECURE_OPEN,
                                  FALSE,
                                  &SddlString,
                                  (LPCGUID)&GUID_SD_XENINP_CONTROL_OBJECT,
                                  &pDevice);

    if (!NT_SUCCESS(Status))
        return Status;

    RtlZeroMemory(pDevice->DeviceExtension, sizeof(XENINP_DEVICE_EXTENSION));
    pDevExt = (PXENINP_DEVICE_EXTENSION)pDevice->DeviceExtension;

    RtlStringCchCopyW(pDevExt->SymbolicLinkText, XENINP_SYM_NAME_LEN, XENINP_SYMBOLIC_NAME);
    RtlInitUnicodeString(&pDevExt->SymbolicLink, pDevExt->SymbolicLinkText);

    // Create our symbolic link
    Status = IoCreateSymbolicLink(&pDevExt->SymbolicLink, &DeviceString);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(pDevice);
        return Status;
    }

    pDevExt->pTopOfStack = IoAttachDeviceToDeviceStack(pDevice, pPDO);
    if (pDevExt->pTopOfStack == NULL) {
        IoDeleteSymbolicLink(&pDevExt->SymbolicLink);
        IoDeleteDevice(pDevice);
        return STATUS_DEVICE_NOT_CONNECTED; 
    }

    ASSERT(pDevExt->pTopOfStack != NULL);

    pDevExt->pSelf =         pDevice;
    pDevExt->pPDO =          pPDO;
    pDevExt->DeviceState =   PowerDeviceD0;

    pDevExt->SurpriseRemoved = FALSE;
    pDevExt->Removed =         FALSE;
    pDevExt->Started =         FALSE;
    pDevExt->RemovePending =   FALSE;

    pDevice->Flags |= (DO_BUFFERED_IO | DO_POWER_PAGABLE);
    pDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    KeInitializeSpinLock(&pDevExt->InterruptSpinLock);
    KeInitializeSpinLock(&pDevExt->EventLock);

    IoInitializeDpcRequest(pDevExt->pSelf, XenInpIsrDpc);

    return Status;
}

// Generic completion routine that allows the driver to send the irp down the 
// stack, catch it on the way up, and do more processing at the original IRQL.
static NTSTATUS
XenInpComplete(PDEVICE_OBJECT pDeviceObject, PIRP pIrp, PVOID pContext)
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
// Called when there are mouse packets to report to the RIT.  You can do 
// anything you like to the packets.  For instance:   
//    o Drop a packet altogether
//    o Mutate the contents of a packet 
//    o Insert packets into the stream 
//                    
// Arguments:
//    DeviceObject - Context passed during the connect IOCTL
//    InputDataStart - First packet to be reported   
//    InputDataEnd - One past the last packet to be reported.  Total number of
//                   packets is equal to InputDataEnd - InputDataStart
//    InputDataConsumed - Set to the total number of packets consumed by the RIT
//                        (via the function pointer we replaced in the connect
//                        IOCTL)
VOID
XenInpServiceCallback(PDEVICE_OBJECT pDeviceObject,
                       PMOUSE_INPUT_DATA pInputDataStart,
                       PMOUSE_INPUT_DATA pInputDataEnd,
                       PULONG pInputDataConsumed)
{
    PXENINP_DEVICE_EXTENSION   pDevExt;

    pDevExt = (PXENINP_DEVICE_EXTENSION) pDeviceObject->DeviceExtension;

    //
    // UpperConnectData must be called at DISPATCH
    //
    if (!pDevExt->UpperConnectData.ClassService) return;

    (*(PSERVICE_CALLBACK_ROUTINE) pDevExt->UpperConnectData.ClassService)(
        pDevExt->UpperConnectData.ClassDeviceObject,
        pInputDataStart,
        pInputDataEnd,
        pInputDataConsumed
        );
}
// This routine is the dispatch routine for internal device control requests.
//    
//    IOCTL_INTERNAL_MOUSE_CONNECT:
//        Store the old context and function pointer and replace it with our own.
//        This makes life much simpler than intercepting IRPs sent by the RIT and
//        modifying them on the way back up.                                   
//                                         
// Arguments:
//    DeviceObject - Pointer to the device object.
//    Irp - Pointer to the request packet.
NTSTATUS
XenInpInternIoCtl(PDEVICE_OBJECT pDeviceObject,
                   PIRP pIrp)
{
    PIO_STACK_LOCATION          pIrpStack;
    PXENINP_DEVICE_EXTENSION    pDevExt;
    PCONNECT_DATA               pConnectData;
    NTSTATUS                    Status = STATUS_SUCCESS;

    PAGED_CODE();

    pDevExt = (PXENINP_DEVICE_EXTENSION) pDeviceObject->DeviceExtension;
    pIrp->IoStatus.Information = 0;
    pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

    switch (pIrpStack->Parameters.DeviceIoControl.IoControlCode) {

    //
    // Connect a mouse class device driver to the port driver.
    //
    case IOCTL_INTERNAL_MOUSE_CONNECT:
        //
        // Only allow one connection.
        //
        if (pDevExt->UpperConnectData.ClassService != NULL) {
            Status = STATUS_SHARING_VIOLATION;
            break;
        }
        else if (pIrpStack->Parameters.DeviceIoControl.InputBufferLength <
                sizeof(CONNECT_DATA)) {
            //
            // invalid buffer
            //
            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        //
        // Copy the connection parameters to the device extension.
        //
        pConnectData = ((PCONNECT_DATA)
            (pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer));

        pDevExt->UpperConnectData = *pConnectData;

        //
        // Hook into the report chain.  Everytime a mouse packet is reported to
        // the system, XenInpServiceCallback will be called
        //
        pConnectData->ClassDeviceObject = pDevExt->pSelf;
        pConnectData->ClassService = XenInpServiceCallback;
        break;
    //
    // Disconnect a mouse class device driver from the port driver.
    //
    case IOCTL_INTERNAL_MOUSE_DISCONNECT:

        //
        // Clear the connection parameters in the device extension.
        //
         pDevExt->UpperConnectData.ClassDeviceObject = NULL;
         pDevExt->UpperConnectData.ClassService = NULL;
        break;

    //
    // These internal ioctls are not supported by the new PnP model.
    //
#if 0       // obsolete
    case IOCTL_INTERNAL_MOUSE_ENABLE:
    case IOCTL_INTERNAL_MOUSE_DISABLE:
        Status = STATUS_NOT_SUPPORTED;
        break;
#endif  // obsolete

    //
    // Might want to capture this in the future.  For now, then pass it down
    // the stack.  These queries must be successful for the RIT to communicate
    // with the mouse.
    //
    case IOCTL_MOUSE_QUERY_ATTRIBUTES:
    default:
        break;
    }

    pIrp->IoStatus.Status = Status;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS
XenInpDispatchPassThrough(__in PDEVICE_OBJECT pDeviceObject,
                          __in PIRP pIrp)
{
    // Pass the IRP to the target
    IoSkipCurrentIrpStackLocation(pIrp);

    return IoCallDriver(((PXENINP_DEVICE_EXTENSION)pDeviceObject->DeviceExtension)->pTopOfStack, pIrp);
}


// This routine is the dispatch routine for internal device control requests.
static NTSTATUS
XenInpIoCtl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    PIO_STACK_LOCATION       pIrpStack;
    PXENINP_DEVICE_EXTENSION pDevExt = (PXENINP_DEVICE_EXTENSION)pDeviceObject->DeviceExtension;
    KEVENT                   Event;
    NTSTATUS                 Status = STATUS_SUCCESS;
    ULONG                    IoControlCode;
    PVOID                    pIoBuffer;
    ULONG                    IoInLen;
    ULONG                    IoOutLen;
    KIRQL                    Irql;
    PCONNECT_DATA            pConnectData;

    PAGED_CODE();

    pIrp->IoStatus.Information = 0;
    pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

    IoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
    pIoBuffer     = pIrp->AssociatedIrp.SystemBuffer;
    IoInLen       = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
    IoOutLen      = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (IoControlCode) {

    case XENINP_IOCTL_ACCELERATION:
    {
        XENINP_ACCELERATION *Accel = (XENINP_ACCELERATION*)pIoBuffer;

        if (IoInLen == sizeof(XENINP_ACCELERATION)) {
			KeAcquireSpinLock(&pDevExt->EventLock, &Irql);

			WRITE_REGISTER_ULONG((PULONG)(pDevExt->pGlobalRegs + XMOU_ACCELERATION),Accel->Acceleration);

			KeReleaseSpinLock(&pDevExt->EventLock, Irql);
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

    return XenInpSimpleCompleteIrp(pIrp, Status);
}

static VOID
XenInpCleanupResources(PXENINP_DEVICE_EXTENSION pDevExt)
{   
    if (pDevExt->pInterruptObject != NULL) {
        IoDisconnectInterrupt(pDevExt->pInterruptObject);
        pDevExt->pInterruptObject = NULL;
    }

    if (pDevExt->pXenInpRegs != NULL) {
        MmUnmapIoSpace(pDevExt->pXenInpRegs,
                       pDevExt->XenInpRegistersDescriptor.u.Memory.Length);
        pDevExt->pGlobalRegs = NULL;
        pDevExt->pXenInpRegs = NULL;
        pDevExt->pEventRegs = NULL;
        pDevExt->EventRegsPages = 0;
        pDevExt->EventStructSize = 0;
        pDevExt->RWStructSize = 0;
    }
}

static NTSTATUS
XenInpConfigureResources(PXENINP_DEVICE_EXTENSION pDevExt,
                         PCM_RESOURCE_LIST pResourceList)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR pPRList;
    ULONG c, i;
    NTSTATUS Status;
    KINTERRUPT_MODE InterruptMode;
    BOOLEAN ShareVector;
    ULONG MagicReg;

    c = pResourceList->List[0].PartialResourceList.Count;
    pPRList = &pResourceList->List[0].PartialResourceList.PartialDescriptors[0];
    for (i = 0; i < c; i++, pPRList++) {
        if (pPRList->Type >= CmResourceTypeMaximum)
            continue;

        else if (pPRList->Type == CmResourceTypeMemory) {
            // The xenmou MMIO registers region in BAR0.
            RtlMoveMemory(&pDevExt->XenInpRegistersDescriptor,
                          pPRList,
                          sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
            DbgPrint("XENINP: MMIO BAR base == %x:%x size == 0x%x\n",
                     pDevExt->XenInpRegistersDescriptor.u.Memory.Start.HighPart,
                     pDevExt->XenInpRegistersDescriptor.u.Memory.Start.LowPart,
                     pDevExt->XenInpRegistersDescriptor.u.Memory.Length);
        }
        else if (pPRList->Type == CmResourceTypeInterrupt) {
            // The interrupt is hooked up below.
            RtlMoveMemory(&pDevExt->InterruptDescriptor,
                          pPRList,
                          sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));

            DbgPrint("XENINP: IRQ level == %d vector == %d\n",
                     pDevExt->InterruptDescriptor.u.Interrupt.Level,
                     pDevExt->InterruptDescriptor.u.Interrupt.Vector);
        }
        else {
            // Not expecting this.
            DbgPrint("XENINP: Unknown resource at %d\n", i);
        }
    }

    // Map in MMIO registers
    pDevExt->pXenInpRegs = 
        (PUCHAR)MmMapIoSpace(pDevExt->XenInpRegistersDescriptor.u.Memory.Start,
                             pDevExt->XenInpRegistersDescriptor.u.Memory.Length,
                             MmNonCached);
    if (pDevExt->pXenInpRegs == NULL) {
        DbgPrint("XENINP: MmMapIoSpace(MMIO register range) failed!\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    pDevExt->pGlobalRegs = pDevExt->pXenInpRegs;
    pDevExt->pEventRegs = pDevExt->pXenInpRegs + PAGE_SIZE;

    // Sanity check
    MagicReg = READ_REGISTER_ULONG((PULONG)(pDevExt->pGlobalRegs + XMOU_MAGIC));
    if (MagicReg != XMOU_MAGIC_VALUE) {
        DbgPrint("Start device detected unknown magic value: 0x%x\n", MagicReg);
        XenInpCleanupResources(pDevExt);
        return STATUS_UNSUCCESSFUL;
    }
    DbgPrint("XENINP: Read magic == 0x%x\n", MagicReg);

    // Get the event structure size and number of event pages
    pDevExt->EventStructSize = READ_REGISTER_ULONG((PULONG)(pDevExt->pGlobalRegs + XMOU_EVENT_SIZE));//0x00000008;
    DbgPrint("XENINP: Read event structure size == 0x%x\n", pDevExt->EventStructSize);
    pDevExt->EventRegsPages = READ_REGISTER_ULONG((PULONG)(pDevExt->pGlobalRegs + XMOU_EVENT_NPAGES));//0x00000002;
    DbgPrint("XENINP: Read event regs pages == 0x%x\n", pDevExt->EventRegsPages);
    pDevExt->EventCount = ((pDevExt->EventRegsPages*PAGE_SIZE)/pDevExt->EventStructSize) - 1; //First event cell has read/write pointers
    pDevExt->RWStructSize = pDevExt->EventStructSize; // just for clarity

    // Interrupt values
    InterruptMode = (pDevExt->InterruptDescriptor.Flags == CM_RESOURCE_INTERRUPT_LATCHED) ? Latched : LevelSensitive;
    ShareVector = (pDevExt->InterruptDescriptor.ShareDisposition == CmResourceShareShared) ? TRUE : FALSE;

    // Connect interrupt
    Status = 
        IoConnectInterrupt(&(pDevExt->pInterruptObject),
                           (PKSERVICE_ROUTINE)XenInpInterruptService,
                           pDevExt->pSelf,
                           &pDevExt->InterruptSpinLock,
                           pDevExt->InterruptDescriptor.u.Interrupt.Vector,       
                           (KIRQL)pDevExt->InterruptDescriptor.u.Interrupt.Level,
                           (KIRQL)pDevExt->InterruptDescriptor.u.Interrupt.Level, 
                           InterruptMode,
                           ShareVector,
                           pDevExt->InterruptDescriptor.u.Interrupt.Affinity,       
                           FALSE);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("XENINP: IoConnectInterrupt failed! - status: 0x%x\n", Status);
        XenInpCleanupResources(pDevExt);
        return Status;
    }
    return STATUS_SUCCESS;
}

static VOID
XenInpEnable(PXENINP_DEVICE_EXTENSION pDevExt)
{
	// Called during PnP start 
    ULONG ControlReg;
	
    if (pDevExt->pGlobalRegs != NULL) {
        ControlReg = READ_REGISTER_ULONG((PULONG)(pDevExt->pGlobalRegs + XMOU_CONTROL));
        DbgPrint("XENINP: XenInpEnable: Read control register == 0x%x\n", ControlReg);
        ControlReg |= XMOU_CONTROL_XMOU_EN|XMOU_CONTROL_INT_EN;

        WRITE_REGISTER_ULONG((PULONG)(pDevExt->pGlobalRegs + XMOU_CONTROL), ControlReg);
        DbgPrint("XENINP: XenInpEnable: Wrote control register == 0x%x\n", ControlReg);
    }
}

static VOID
XenInpDisable(PXENINP_DEVICE_EXTENSION pDevExt)
{
	// Called during PnP remove
    ULONG ControlReg;

    if (pDevExt->pGlobalRegs != NULL) {
	    ControlReg = READ_REGISTER_ULONG((PULONG)(pDevExt->pGlobalRegs + XMOU_CONTROL));
        DbgPrint("XENINP: XenInpDisable: Read control register == 0x%x\n", ControlReg);
        ControlReg &= ~(XMOU_CONTROL_XMOU_EN|XMOU_CONTROL_INT_EN);

        WRITE_REGISTER_ULONG((PULONG)(pDevExt->pGlobalRegs + XMOU_CONTROL), ControlReg);
        DbgPrint("XENINP: XenInpDisable: Wrote control register == 0x%x\n", ControlReg);
    }
}

// This routine is the dispatch routine for plug and play IRPs
static NTSTATUS
XenInpPnP(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    PXENINP_DEVICE_EXTENSION pDevExt = (PXENINP_DEVICE_EXTENSION)pDeviceObject->DeviceExtension;
    PIO_STACK_LOCATION       pIrpStack;
    NTSTATUS                 Status = STATUS_SUCCESS;
    KIRQL                    OldIrql;
    KEVENT                   Event;

    PAGED_CODE();

    pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

    switch (pIrpStack->MinorFunction) {
    case IRP_MN_START_DEVICE:
    {

        // The device is starting.
        //
        // We cannot touch the device (send it any non pnp irps) until a
        // start device has been passed down to the lower drivers.
        IoCopyCurrentIrpStackLocationToNext(pIrp);
        KeInitializeEvent(&Event,
                          NotificationEvent,
                          FALSE);

        IoSetCompletionRoutine(pIrp,
                               (PIO_COMPLETION_ROUTINE)XenInpComplete, 
                               &Event,
                               TRUE,
                               TRUE,
                               TRUE); // No need for Cancel

        Status = IoCallDriver(pDevExt->pTopOfStack, pIrp);

        if (STATUS_PENDING == Status) {
            KeWaitForSingleObject(&Event,
                                  Executive, // Waiting for reason of a driver
                                  KernelMode, // Waiting in kernel mode
                                  FALSE, // No allert
                                  NULL); // No timeout

            Status = pIrp->IoStatus.Status;
        }

        while (NT_SUCCESS(Status)) {
            // As we are successfully now back from our start device
            // we can do work.
            pDevExt->Started = TRUE;
            pDevExt->Removed = FALSE;
            pDevExt->SurpriseRemoved = FALSE;
            pDevExt->RemovePending = FALSE;

            // Setup IRQ and MMIO resources
            Status = XenInpConfigureResources(pDevExt,
                                              pIrpStack->Parameters.StartDevice.AllocatedResourcesTranslated);
            if (!NT_SUCCESS(Status)) {
                //trace something
                break;
            }
            XenInpEnable(pDevExt);
            break;
        }

        // We must now complete the IRP, since we stopped it in the
        // completion routine with MORE_PROCESSING_REQUIRED.
        pIrp->IoStatus.Status = Status;
        pIrp->IoStatus.Information = 0;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);

        break;
    }

    case IRP_MN_STOP_DEVICE:
        // Disable interrupt and leave xenmou mode.
        XenInpDisable(pDevExt);

        XenInpCleanupResources(pDevExt);

        IoSkipCurrentIrpStackLocation(pIrp);
        Status = IoCallDriver(pDevExt->pTopOfStack, pIrp);
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        // Disable interrupt and leave xenmou mode.
        XenInpDisable(pDevExt);

        XenInpCleanupResources(pDevExt);

        // Same as a remove device, but don't call IoDetach or IoDeleteDevice
        pDevExt->SurpriseRemoved = TRUE;

        // Remove code here
        IoSkipCurrentIrpStackLocation(pIrp);
        Status = IoCallDriver(pDevExt->pTopOfStack, pIrp);
        break;

    case IRP_MN_REMOVE_DEVICE:
        // Disable interrupt and leave xenmou mode.
        XenInpDisable(pDevExt);
        
        XenInpCleanupResources(pDevExt);
        pDevExt->RemovePending = FALSE;
        pDevExt->Removed = TRUE;

        // remove code here
        pIrp->IoStatus.Status = STATUS_SUCCESS;

        IoSkipCurrentIrpStackLocation(pIrp);
        Status = IoCallDriver(pDevExt->pTopOfStack, pIrp);
		
        IoDetachDevice(pDevExt->pTopOfStack);
        IoDeleteSymbolicLink(&pDevExt->SymbolicLink);
        IoDeleteDevice(pDeviceObject);

        break;
    
    case IRP_MN_QUERY_DEVICE_RELATIONS:
        if (pIrpStack->Parameters.QueryDeviceRelations.Type == RemovalRelations) {
            // This is fine when there is just one physical device.
            DEVICE_RELATIONS *pDevRel;
            pDevRel = (DEVICE_RELATIONS*)ExAllocatePoolWithTag(PagedPool, 
                          sizeof(DEVICE_RELATIONS), 'PNIX');
            pDevRel->Count = 1;
            pDevRel->Objects[0] = pDevExt->pPDO;
            ObReferenceObject(pDevExt->pPDO);
            pIrp->IoStatus.Information = (ULONG_PTR)pDevRel;
            pIrp->IoStatus.Status = Status;
            IoSkipCurrentIrpStackLocation(pIrp);
            Status = IoCallDriver(pDevExt->pTopOfStack, pIrp);
            pDevExt->RemovePending = TRUE;
            break;
        }

    case IRP_MN_QUERY_REMOVE_DEVICE:
    case IRP_MN_QUERY_STOP_DEVICE:
    case IRP_MN_CANCEL_REMOVE_DEVICE:
    case IRP_MN_CANCEL_STOP_DEVICE:
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
        // Here the filter driver might modify the behavior of these IRPS
        // Please see PlugPlay documentation for use of these IRPs.        
        IoSkipCurrentIrpStackLocation(pIrp);
        Status = IoCallDriver(pDevExt->pTopOfStack, pIrp);
        break;
    }

    return Status;
}

// This routine is the dispatch routine for power IRPs   Does nothing except
// record the state of the device.
static NTSTATUS
XenInpPower(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    PIO_STACK_LOCATION       pIrpStack;
    PXENINP_DEVICE_EXTENSION pDevExt = (PXENINP_DEVICE_EXTENSION)pDeviceObject->DeviceExtension;
    POWER_STATE              PowerState;
    POWER_STATE_TYPE         PowerType;

    PAGED_CODE();

    pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

    PowerType = pIrpStack->Parameters.Power.Type;
    PowerState = pIrpStack->Parameters.Power.State;

    switch (pIrpStack->MinorFunction) {
    case IRP_MN_SET_POWER:
        // It should be sufficient to disable/enable the device using the D
        // states alone. For both S3/S4 a D3 is sent down which will disable the
        // device. On resume in both cases a D0 is sent.
        if (PowerType == DevicePowerState) {
            DbgPrint("XENINP: IRP_MN_SET_POWER DevicePowerState State: %d\n",
                     PowerState.DeviceState);
            pDevExt->DeviceState = PowerState.DeviceState;
            if (PowerState.DeviceState == PowerDeviceD0)
                XenInpEnable(pDevExt);
            else
                XenInpDisable(pDevExt);
            break;
        }

        // Else a system power state

    case IRP_MN_QUERY_POWER:
    case IRP_MN_WAIT_WAKE:
    case IRP_MN_POWER_SEQUENCE:
    default:
        break;
    }

    PoStartNextPowerIrp(pIrp);
    IoSkipCurrentIrpStackLocation(pIrp);
    return PoCallDriver(pDevExt->pTopOfStack, pIrp);
}

// Free all the allocated resources associated with this driver.
static VOID
XenInpUnload(PDRIVER_OBJECT pDriver)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(pDriver);

    ASSERT(NULL == pDriver->DeviceObject);
}

// Maintain a simple count of the creates sent against this device
static NTSTATUS
XenInpCreate(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    PXENINP_DEVICE_EXTENSION pDevExt = (PXENINP_DEVICE_EXTENSION)pDeviceObject->DeviceExtension;

    PAGED_CODE();

    // Not really used but OK for debugging
    InterlockedIncrement(&pDevExt->EnableCount);

    return XenInpSimpleCompleteIrp(pIrp, STATUS_SUCCESS);
}

// Maintain a simple count of the closes sent against this device
static NTSTATUS
XenInpClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    PXENINP_DEVICE_EXTENSION pDevExt = (PXENINP_DEVICE_EXTENSION)pDeviceObject->DeviceExtension;

    PAGED_CODE();

    ASSERT(0 < pDevExt->EnableCount);

    InterlockedDecrement(&pDevExt->EnableCount);          

    return XenInpSimpleCompleteIrp(pIrp, STATUS_SUCCESS);
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT  pDriverObject,
            PUNICODE_STRING pRegistryPath)
{
    ULONG i;

    UNREFERENCED_PARAMETER(pRegistryPath);

    // Fill in all the dispatch entry points with the pass through function
    // and the explicitly fill in the functions we are going to intercept
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        pDriverObject->MajorFunction[i] = XenInpDispatchPassThrough;
    }

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = XenInpCreate;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE]  = XenInpClose;
    pDriverObject->MajorFunction[IRP_MJ_PNP]    = XenInpPnP;
    pDriverObject->MajorFunction[IRP_MJ_POWER]  = XenInpPower;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = XenInpIoCtl;
    pDriverObject->MajorFunction [IRP_MJ_INTERNAL_DEVICE_CONTROL] = XenInpInternIoCtl;

    // The rest can be handled by the system not supported routine

    pDriverObject->DriverUnload = XenInpUnload;
    pDriverObject->DriverExtension->AddDevice = XenInpAddDevice;

    return STATUS_SUCCESS;
}
