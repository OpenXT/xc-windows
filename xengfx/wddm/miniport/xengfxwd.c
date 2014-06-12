//
// xengfxwd.c - Xen Windows PV WDDM Miniport Driver
//
// Copyright (c) 2010 Citrix, Inc. - All rights reserved.
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


#include "xengfxwd.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE,XenGfxAddDevice)
#pragma alloc_text(PAGE,XenGfxStartDevice)
#pragma alloc_text(PAGE,XenGfxStopDevice)
#pragma alloc_text(PAGE,XenGfxRemoveDevice)
#pragma alloc_text(PAGE,XenGfxDispatchIoRequest)
#pragma alloc_text(PAGE,XenGfxQueryChildRelations)
#pragma alloc_text(PAGE,XenGfxQueryChildStatus)
#pragma alloc_text(PAGE,XenGfxQueryDeviceDescriptor)
#pragma alloc_text(PAGE,XenGfxSetPowerState)
#pragma alloc_text(PAGE,XenGfxUnload)
#pragma alloc_text(PAGE,XenGfxQueryInterface)
#pragma alloc_text(INIT,DriverEntry)
#endif

NTSTATUS APIENTRY
XenGfxAddDevice(CONST PDEVICE_OBJECT pPhysicalDeviceObject, PVOID *ppMiniportDeviceContext)
{
    PAGED_CODE();
    // T & S Level 3
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(pPhysicalDeviceObject)||!ARGUMENT_PRESENT(ppMiniportDeviceContext))
        return STATUS_INVALID_PARAMETER;

    *ppMiniportDeviceContext = 
        (XENGFX_DEVICE_EXTENSION*)ExAllocatePoolWithTag(NonPagedPool,
                                                        sizeof(XENGFX_DEVICE_EXTENSION),
                                                        XENGFX_TAG);

    if (*ppMiniportDeviceContext == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(*ppMiniportDeviceContext, sizeof(XENGFX_DEVICE_EXTENSION));

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxStartDevice(CONST PVOID pMiniportDeviceContext,
                  PDXGK_START_INFO pDxgkStartInfo,
                  PDXGKRNL_INTERFACE pDxgkInterface,
                  PULONG pNumberOfVideoPresentSources,
                  PULONG pNumberOfChildren)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)pMiniportDeviceContext;
    DXGK_DEVICE_INFO DeviceInfo;
    NTSTATUS Status;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR pPRList;
    ULONG c, i, Magic, Rev;
    PAGED_CODE();

    // T & S Level 3
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(pMiniportDeviceContext)||!ARGUMENT_PRESENT(pDxgkStartInfo)||
        !ARGUMENT_PRESENT(pDxgkInterface)||!ARGUMENT_PRESENT(pNumberOfVideoPresentSources)||
        !ARGUMENT_PRESENT(pNumberOfChildren)) {
        return STATUS_INVALID_PARAMETER;
    }

    pXenGfxExtension->hDxgkHandle = pDxgkInterface->DeviceHandle;
    RtlCopyMemory(&pXenGfxExtension->DxgkStartInfo, pDxgkStartInfo, sizeof(DXGK_START_INFO));
    RtlCopyMemory(&pXenGfxExtension->DxgkInterface, pDxgkInterface, sizeof(DXGKRNL_INTERFACE));

    Status = pXenGfxExtension->DxgkInterface.DxgkCbGetDeviceInformation(pXenGfxExtension->hDxgkHandle, &DeviceInfo);
    if (!NT_SUCCESS(Status)) {
        TraceError(("DlGetDeviceInformation() failed - error: 0x%x\n", Status));
        return Status;
    }
    pXenGfxExtension->pPhysicalDeviceObject = DeviceInfo.PhysicalDeviceObject;

    // Read any device specific registry values
    XenGfxReadRegistryValues(pXenGfxExtension, &DeviceInfo.DeviceRegistryPath);

    // If any debug tracing is requested then open the log file
    if (pXenGfxExtension->VidPnTracing)
        XenGfxOpenDebugLog(pXenGfxExtension);

    // Get the translated hardware resources. There should be one full resource list entry
    // for the PCI bus where xgfx is located.
    if (DeviceInfo.TranslatedResourceList->Count != 1) {
        TraceError(("TranslatedResourceList->Count == %d, expected 1??\n",
                    DeviceInfo.TranslatedResourceList->Count));
        XenGfxFreeResources(pXenGfxExtension);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    if (DeviceInfo.TranslatedResourceList->List[0].PartialResourceList.Count == 0) {
        TraceError(("TranslatedResourceList->List[0].PartialResourceList.Count == 0, expected > 0??\n"));
        XenGfxFreeResources(pXenGfxExtension);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    c = DeviceInfo.TranslatedResourceList->List[0].PartialResourceList.Count;
    pPRList = &DeviceInfo.TranslatedResourceList->List[0].PartialResourceList.PartialDescriptors[0];
    for (i = 0; i < c; i++, pPRList++) {
        if (pPRList->Type >= CmResourceTypeMaximum)
            continue;
        if (pPRList->Type == CmResourceTypeMemory) {
            // Is this the graphics aperture in BAR0.
            if (pPRList->u.Memory.Length > XENGFX_XGFXREG_MAX_SIZE) {
                RtlMoveMemory(&pXenGfxExtension->GraphicsApertureDescriptor,
                              pPRList,
                              sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
                continue;
            }

            if (pXenGfxExtension->XgfxRegistersDescriptor.u.Memory.Start.QuadPart != 0) {
                TraceWarning(("MMIO register range already set??? Ignore this resource == %x:%x\n",
                              pPRList->u.Memory.Start.HighPart, pPRList->u.Memory.Start.LowPart));
                continue;
            }

            // This BAR should be the XGFX registers
            RtlMoveMemory(&pXenGfxExtension->XgfxRegistersDescriptor,
                          pPRList,
                          sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
        }
        else if (pPRList->Type == CmResourceTypeInterrupt) {
            // The interrupt is hooked up by the DirectX framework for us.
            TraceVerbose(("IRQ level == %d vector == %d\n",
                         pPRList->u.Interrupt.Level,
                         pPRList->u.Interrupt.Vector));
        }
        else if (pPRList->Type == CmResourceTypePort) {
            // This is a Port I/O resource for accessing the MMIO registers via PIO.
            TraceVerbose(("PIO resource == %x:%x\n",
                         pPRList->u.Port.Start.HighPart,
                         pPRList->u.Port.Start.LowPart));
        }
    }
    
    // Map the XGFX registers and find the various register sections
    if ((pXenGfxExtension->XgfxRegistersDescriptor.u.Memory.Start.QuadPart == 0)||
        (pXenGfxExtension->XgfxRegistersDescriptor.u.Memory.Length < XENGFX_XGFXREG_SIZE)) {
        TraceError(("Incorrect MMIO XGFX registers resource - resource == %x:%x, length = 0x%x??\n",
                    pXenGfxExtension->XgfxRegistersDescriptor.u.Memory.Start.HighPart,
                    pXenGfxExtension->XgfxRegistersDescriptor.u.Memory.Start.LowPart,
                    pXenGfxExtension->XgfxRegistersDescriptor.u.Memory.Length));
        XenGfxFreeResources(pXenGfxExtension);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pXenGfxExtension->pXgfxRegs = 
        (PUCHAR)MmMapIoSpace(pXenGfxExtension->XgfxRegistersDescriptor.u.Memory.Start,
                             pXenGfxExtension->XgfxRegistersDescriptor.u.Memory.Length,
                             MmNonCached);
    if (pXenGfxExtension->pXgfxRegs == NULL) {
        TraceError(("MmMapIoSpace(MMIO register range) failed!\n"));
        XenGfxFreeResources(pXenGfxExtension);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Set pointer to Global regs, VCRTC0 banks and GART
    pXenGfxExtension->pGlobalRegs = pXenGfxExtension->pXgfxRegs + XGFX_GLOBAL_OFFSET;
    pXenGfxExtension->pVCrtcsRegs = pXenGfxExtension->pXgfxRegs + XGFX_VCRTC_OFFSET;
    pXenGfxExtension->pGartRegs = pXenGfxExtension->pXgfxRegs + XGFX_GART_OFFSET;

    // Mapping register pointers
    pXenGfxExtension->pGartBaseReg = (PULONG32)pXenGfxExtension->pGartRegs;

    // Reset the XGFX virtual adapter to a known state.
    READ_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_RESET));

    // Sanity check the magic value and the current rev.
    Magic = READ_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_MAGIC));
    Rev = READ_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_REV));
    if ((Magic != XGFX_MAGIC_VALUE)||(Rev != XGFX_CURRENT_REV)) {
        TraceError(("%s Invalid XGFX Magic or Rev. Magic (expected 0x%x): 0x%x Rev (expected 0x%x): 0x%x\n",
                    __FUNCTION__, XGFX_MAGIC_VALUE, Magic, XGFX_CURRENT_REV, Rev));
        XenGfxFreeResources(pXenGfxExtension);
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate a VCRTC banks for each
    KeInitializeSpinLock(&pXenGfxExtension->VCrtcLock);
    if (!XenGfxAllocateVCrtcBanks(pXenGfxExtension)) {
        // Errors traced in call
        XenGfxFreeResources(pXenGfxExtension);
        return STATUS_NO_MEMORY;
    }

    // This sets up the set of VidPN sources which will later be identified by 0..(N-1) where N = pXenGfxExtension->VCrtcCount
    *pNumberOfVideoPresentSources = pXenGfxExtension->VCrtcCount;
    *pNumberOfChildren = pXenGfxExtension->VCrtcCount;
    pXenGfxExtension->pSources =
        (XENGFX_SOURCE*)ExAllocatePoolWithTag(NonPagedPool,
                                              pXenGfxExtension->VCrtcCount*sizeof(XENGFX_SOURCE),
                                              XENGFX_TAG);
    if (pXenGfxExtension->pSources == NULL) {
        TraceError(("%s Failed to allocate Sources array!\n", __FUNCTION__));
        XenGfxFreeResources(pXenGfxExtension);
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(pXenGfxExtension->pSources, pXenGfxExtension->VCrtcCount*sizeof(XENGFX_SOURCE));
    KeInitializeSpinLock(&pXenGfxExtension->SourcesLock);

    // Enable the VCTRCs
    if (!XenGfxEnableVCrtcs(pXenGfxExtension)) {
        TraceError(("%s Failed to enable VCRTCs!\n", __FUNCTION__));
        XenGfxFreeResources(pXenGfxExtension);
        return STATUS_UNSUCCESSFUL;
    }
    KeInitializeDpc(&pXenGfxExtension->ChildStatusDpc,
                    XenGfxChildStatusChangeDpc,
                    pXenGfxExtension);   

    // Some GART bits
    KeInitializeSpinLock(&pXenGfxExtension->GartLock);    
    if (!XenGfxGartInitialize(pXenGfxExtension)) {
        TraceError(("%s Failed to initialize GART!\n", __FUNCTION__));
        XenGfxFreeResources(pXenGfxExtension);
        return STATUS_UNSUCCESSFUL;
    }
    XenGfxGartInitializeCursorSegment(pXenGfxExtension);

    // Read the private data information that is shared with the user mode display driver.
    XenGfxGetPrivateData(pXenGfxExtension);

    // Device is up, switch to initialized
    InterlockedExchange(&pXenGfxExtension->Initialized, 1);

    // Enable interrupts and switch to hires mode
    XenGfxChangeXgfxMode(pXenGfxExtension, TRUE);

    // Configure all the child devices once up front.
    XenGfxDetectChildStatusChanges(pXenGfxExtension);

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxStopDevice(CONST PVOID pMiniportDeviceContext)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)pMiniportDeviceContext;
    PAGED_CODE();

    // T & S Level 3
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(pMiniportDeviceContext))
        return STATUS_INVALID_PARAMETER;

    // Device stopped, switch to uninitialized
    InterlockedExchange(&pXenGfxExtension->Initialized, 0);

    // Disable the interrupt and turn off hires mode
    XenGfxChangeXgfxMode(pXenGfxExtension, FALSE);

    // Reset the GART to startup state
    XenGfxGartReset(pXenGfxExtension);

    // Reset the XGFX virtual adapter to a known state.
    READ_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_RESET));

    // Free all resources allocated in start routine
    XenGfxFreeResources(pXenGfxExtension);

    // Close any open debug log file
    XenGfxCloseDebugLog(pXenGfxExtension);

    // Clear any remaining state
    RtlZeroMemory(pXenGfxExtension, sizeof(XENGFX_DEVICE_EXTENSION));   

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxRemoveDevice(CONST PVOID pMiniportDeviceContext)
{
    PAGED_CODE();
    // T & S Level 3
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(pMiniportDeviceContext))
        return STATUS_INVALID_PARAMETER;

    ExFreePoolWithTag(pMiniportDeviceContext, XENGFX_TAG);

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxDispatchIoRequest(CONST PVOID pMiniportDeviceContext,
                        ULONG ViewIndex,
                        PVIDEO_REQUEST_PACKET pVideoRequestPacket)
{
    PAGED_CODE();
    // T & S Level 2
    XenGfxEnter(__FUNCTION__, 3);

    if (!ARGUMENT_PRESENT(pMiniportDeviceContext)||!ARGUMENT_PRESENT(pVideoRequestPacket)||
        (ViewIndex > 0)) {
        return STATUS_INVALID_PARAMETER;
    }

    pVideoRequestPacket->StatusBlock->Status = ERROR_INVALID_FUNCTION;

    // Only IOCTL_VIDEO_QUERY_COLOR_CAPABILITIES and IOCTL_VIDEO_HANDLE_VIDEOPARAMETERS 
    // are used - no support for either.

    XenGfxLeave(__FUNCTION__);

    return STATUS_UNSUCCESSFUL;
}

BOOLEAN APIENTRY
XenGfxInterruptRoutine(CONST PVOID pMiniportDeviceContext, ULONG MessageNumber)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)pMiniportDeviceContext;
    ULONG StatusReg;
    BOOLEAN IsHotplug = FALSE;
    ULONG i;
    DXGKARGCB_NOTIFY_INTERRUPT_DATA NotifyInt = {0};
    XENGFX_VCRTC *pVCrtc;

    UNREFERENCED_PARAMETER(MessageNumber); // line-based IRQ

    if (!ARGUMENT_PRESENT(pMiniportDeviceContext))
        return FALSE;
    
    if (InterlockedExchangeAdd(&pXenGfxExtension->Initialized, 0) == 0)
        return FALSE;

    StatusReg = READ_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_ISR));
    if (StatusReg & XGFX_ISR_INT) {
        // Dismiss the interrupt
        WRITE_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_ISR), StatusReg);

        // Determined which VCRTC banks generated interrupts and handle them accordingly.
        for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) {

            pVCrtc = pXenGfxExtension->ppVCrtcBanks[i];

            StatusReg = READ_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_STATUS));
            if (!StatusReg) continue;

            StatusReg = READ_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_STATUS_CHANGE));

            // Not getting DMA interrupts

            // DXGK_INTERRUPT_CRTC_VSYNC was enabled via the interrupt control callback
            // which enabled verticle retrace interrupts for the VCRTCs.
            if (StatusReg & XGFX_VCRTC_STATUS_CHANGE_D_RETRACE) {
                NotifyInt.InterruptType = DXGK_INTERRUPT_CRTC_VSYNC;
                NotifyInt.CrtcVsync.VidPnTargetId = pVCrtc->VidPnTargetId;
                NotifyInt.CrtcVsync.PhysicalAddress = pXenGfxExtension->GraphicsApertureDescriptor.u.Memory.Start;
                NotifyInt.CrtcVsync.PhysicalAddress.QuadPart += pVCrtc->PrimaryAddress.QuadPart;
                NotifyInt.CrtcVsync.PhysicalAdapterMask = 0;
                pXenGfxExtension->DxgkInterface.DxgkCbNotifyInterrupt(pXenGfxExtension->hDxgkHandle, &NotifyInt);
                pXenGfxExtension->DxgkInterface.DxgkCbQueueDpc(pXenGfxExtension->hDxgkHandle);
            }

            // Set bits to indicate which VCRTCs changed hotplug state
            if (StatusReg & XGFX_VCRTC_STATUS_CHANGE_D_HOTPLUG)
                IsHotplug = TRUE;

            // Clear status
            WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_STATUS_CHANGE), StatusReg);
        }

        // Queue a Custom DPC to re-enumerate the VCRTCn states.
        if (IsHotplug)
            KeInsertQueueDpc(&pXenGfxExtension->ChildStatusDpc, NULL, NULL);
        
        return TRUE;
    }

    return FALSE;
}

VOID APIENTRY
XenGfxDpcRoutine(CONST PVOID pMiniportDeviceContext)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)pMiniportDeviceContext;

    // The DDI DPC is used to ACK DMA and V-Sync interrupts are fully serviced.
    pXenGfxExtension->DxgkInterface.DxgkCbNotifyDpc(pXenGfxExtension->hDxgkHandle);
}

NTSTATUS APIENTRY
XenGfxQueryChildRelations(CONST PVOID pMiniportDeviceContext,
                          PDXGK_CHILD_DESCRIPTOR pChildRelations,
                          ULONG ChildRelationsSize)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)pMiniportDeviceContext;
    ULONG i;
    PAGED_CODE();

    // T & S Level 3
    XenGfxEnter(__FUNCTION__, 1);

    if (ChildRelationsSize <= (pXenGfxExtension->VCrtcCount*sizeof(PDXGK_CHILD_DESCRIPTOR)))
        return STATUS_BUFFER_TOO_SMALL;

    // This sets up the set of VidPN targets which will later be identified by the ChildUid. Since
    // there will be a 1 - 1 mapping of source->vCRTC->target, the target and source IDs used in 
    // the VidPN will range from 0 to pXenGfxExtension->VCrtcCount also.
    // N.B. hopefully specifying VGA will not make the directx kernel think we do not generate hotplug interrupts.
    for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) {
        pChildRelations[i].AcpiUid = 0;
        pChildRelations[i].ChildUid = i;
        pChildRelations[i].ChildDeviceType = TypeVideoOutput;
        pChildRelations[i].ChildCapabilities.HpdAwareness = HpdAwarenessInterruptible;
        pChildRelations[i].ChildCapabilities.Type.VideoOutput.InterfaceTechnology = D3DKMDT_VOT_HD15;
        pChildRelations[i].ChildCapabilities.Type.VideoOutput.MonitorOrientationAwareness = D3DKMDT_MOA_NONE;
        pChildRelations[i].ChildCapabilities.Type.VideoOutput.SupportsSdtvModes = FALSE;
    }

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxQueryChildStatus(CONST PVOID pMiniportDeviceContext,
                       PDXGK_CHILD_STATUS pChildStatus,
                       BOOLEAN NonDestructiveOnly)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)pMiniportDeviceContext;
    XENGFX_VCRTC *pVCrtc;
    PAGED_CODE();

    // T & S Level 1 (Child)
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(pMiniportDeviceContext)||!ARGUMENT_PRESENT(pChildStatus))
        return STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(NonDestructiveOnly); // We cause no destruction

    if (pChildStatus->ChildUid > XenGfxChildMaxUid(pXenGfxExtension)) {
        TraceError(("Invalid ChildUid specified: %d\n", pChildStatus->ChildUid));
        return STATUS_INVALID_PARAMETER;
    }

    switch (pChildStatus->Type) {
    case StatusConnection:
        pVCrtc = pXenGfxExtension->ppVCrtcBanks[pChildStatus->ChildUid];     
        pChildStatus->HotPlug.Connected = XenGfxMonitorConnected(pVCrtc);
        break;
    case StatusRotation:
        pChildStatus->Rotation.Angle = 0;
        break;
    default:
        TraceWarning(("Invalid ChildStatus type: %d\n", pChildStatus->Type));
        break;
    };

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}
static NTSTATUS
XenGfxCopyVcrtc(PXENGFX_DEVICE_EXTENSION pXenGfxExtension, PXENGFX_VCRTC pVCrtc, 
                PDXGK_DEVICE_DESCRIPTOR pDeviceDescriptor)
{
    KIRQL       Irql;
    NTSTATUS    Status;
    ULONG       ToCopy;

    KeAcquireSpinLock(&pXenGfxExtension->VCrtcLock, &Irql);

    do {
        Status = STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA;

        if (pDeviceDescriptor->DescriptorOffset >= pVCrtc->EdidSize)
            break;

        if (pDeviceDescriptor->DescriptorLength == 0)
            break;

        ToCopy = pVCrtc->EdidSize - pDeviceDescriptor->DescriptorOffset;
        if (ToCopy > pDeviceDescriptor->DescriptorLength)
            ToCopy = pDeviceDescriptor->DescriptorLength;

        // Valid hunk of descriptor requested
        RtlMoveMemory(pDeviceDescriptor->DescriptorBuffer,
            ((UCHAR*)pVCrtc->pEdid) + pDeviceDescriptor->DescriptorOffset,
            ToCopy);

        Status = STATUS_SUCCESS;
    } while (FALSE);

    KeReleaseSpinLock(&pXenGfxExtension->VCrtcLock, Irql);
    return Status;
}
NTSTATUS APIENTRY
XenGfxQueryDeviceDescriptor(CONST PVOID pMiniportDeviceContext,
                            ULONG ChildUid,
                            PDXGK_DEVICE_DESCRIPTOR pDeviceDescriptor)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)pMiniportDeviceContext;
    XENGFX_VCRTC *pVCrtc;
    NTSTATUS Status;
    PAGED_CODE();

    // T & S Level 1 (Child)
    XenGfxEnter(__FUNCTION__, 1);

    // These failures should not occur
    if (!ARGUMENT_PRESENT(pMiniportDeviceContext)||!ARGUMENT_PRESENT(pDeviceDescriptor))
        return STATUS_INVALID_PARAMETER;

    if (ChildUid > XenGfxChildMaxUid(pXenGfxExtension)) {
        TraceError(("Invalid ChildUid specified: %d\n", ChildUid));
        return STATUS_INVALID_PARAMETER;
    }

    pVCrtc = pXenGfxExtension->ppVCrtcBanks[ChildUid];
    Status = XenGfxCopyVcrtc(pXenGfxExtension, pVCrtc, pDeviceDescriptor);

    XenGfxLeave(__FUNCTION__);

    return Status;
}

NTSTATUS APIENTRY
XenGfxSetPowerState(CONST PVOID pMiniportDeviceContext,
                    ULONG HardwareUid,
                    DEVICE_POWER_STATE DevicePowerState,
                    POWER_ACTION ActionType)
{

    UNREFERENCED_PARAMETER(pMiniportDeviceContext);
    PAGED_CODE();

    // T & S Level 3
    XenGfxEnter(__FUNCTION__, 1);

    TraceVerbose(("HW UID: %d DEVICE_POWER_STATE: %d POWER_ACTION: %d\n",
                  HardwareUid, DevicePowerState, ActionType));

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

VOID APIENTRY
XenGfxResetDevice(CONST PVOID pMiniportDeviceContext)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)pMiniportDeviceContext;

    XenGfxEnter(__FUNCTION__, 1);

    // Disable XGFX mode
    XenGfxChangeXgfxMode(pXenGfxExtension, FALSE);

    // Return to VGA text mode 3 for hibernation, bug checks, and the like.
    if (!XenGfxVgaResetMode3((PUCHAR)XENGFX_SHADOW_PORT_BASE,
                             (PUCHAR)XENGFX_VBE_PORT_BASE)) {
        TraceError(("%s XenGfxVgaResetMode3() failed.\n", __FUNCTION__));
    }

    XenGfxLeave(__FUNCTION__);
}

VOID APIENTRY
XenGfxUnload(VOID)
{
    PAGED_CODE();

    // T & S Level 3
    XenGfxEnter(__FUNCTION__, 3);

    // Nothing to do

    XenGfxLeave(__FUNCTION__);
}

NTSTATUS APIENTRY
XenGfxQueryInterface(CONST PVOID pMiniportDeviceContext,
                     PQUERY_INTERFACE pQueryInterface)
{
    UNREFERENCED_PARAMETER(pMiniportDeviceContext);
    UNREFERENCED_PARAMETER(pQueryInterface);
    PAGED_CODE();

    // T & S Level 2
    XenGfxEnter(__FUNCTION__, 3);

    XenGfxLeave(__FUNCTION__);

    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    DRIVER_INITIALIZATION_DATA DriverInitializationData = {0};

    XenGfxEnter(__FUNCTION__, 3);

    DriverInitializationData.Version                                = DXGKDDI_INTERFACE_VERSION;

    // Miniport
    DriverInitializationData.DxgkDdiAddDevice                       = XenGfxAddDevice;
    DriverInitializationData.DxgkDdiStartDevice                     = XenGfxStartDevice;
    DriverInitializationData.DxgkDdiStopDevice                      = XenGfxStopDevice;
    DriverInitializationData.DxgkDdiRemoveDevice                    = XenGfxRemoveDevice;
    DriverInitializationData.DxgkDdiDispatchIoRequest               = XenGfxDispatchIoRequest;
    DriverInitializationData.DxgkDdiInterruptRoutine                = XenGfxInterruptRoutine;
    DriverInitializationData.DxgkDdiDpcRoutine                      = XenGfxDpcRoutine;
    DriverInitializationData.DxgkDdiQueryChildRelations             = XenGfxQueryChildRelations;
    DriverInitializationData.DxgkDdiQueryChildStatus                = XenGfxQueryChildStatus;
    DriverInitializationData.DxgkDdiQueryDeviceDescriptor           = XenGfxQueryDeviceDescriptor;
    DriverInitializationData.DxgkDdiSetPowerState                   = XenGfxSetPowerState;
    DriverInitializationData.DxgkDdiNotifyAcpiEvent                 = NULL; // optional, not currently used
    DriverInitializationData.DxgkDdiResetDevice                     = XenGfxResetDevice;
    DriverInitializationData.DxgkDdiUnload                          = XenGfxUnload;
    DriverInitializationData.DxgkDdiQueryInterface                  = XenGfxQueryInterface;
    // DDI
    DriverInitializationData.DxgkDdiControlEtwLogging               = XenGfxControlEtwLogging;
    DriverInitializationData.DxgkDdiQueryAdapterInfo                = XenGfxQueryAdapterInfo;
    DriverInitializationData.DxgkDdiCreateDevice                    = XenGfxCreateDevice;
    DriverInitializationData.DxgkDdiCreateAllocation                = XenGfxCreateAllocation;
    DriverInitializationData.DxgkDdiDestroyAllocation               = XenGfxDestroyAllocation;
    DriverInitializationData.DxgkDdiDescribeAllocation              = XenGfxDescribeAllocation;
    DriverInitializationData.DxgkDdiGetStandardAllocationDriverData = XenGfxGetStandardAllocationDriverData;
    DriverInitializationData.DxgkDdiAcquireSwizzlingRange           = XenGfxAcquireSwizzlingRange;
    DriverInitializationData.DxgkDdiReleaseSwizzlingRange           = XenGfxReleaseSwizzlingRange;
    DriverInitializationData.DxgkDdiPatch                           = XenGfxPatch;
    DriverInitializationData.DxgkDdiSubmitCommand                   = XenGfxSubmitCommand;
    DriverInitializationData.DxgkDdiPreemptCommand                  = XenGfxPreemptCommand;
    DriverInitializationData.DxgkDdiBuildPagingBuffer               = XenGfxBuildPagingBuffer;
    DriverInitializationData.DxgkDdiSetPalette                      = XenGfxSetPalette;
    DriverInitializationData.DxgkDdiSetPointerPosition              = XenGfxSetPointerPosition;
    DriverInitializationData.DxgkDdiSetPointerShape                 = XenGfxSetPointerShape;
    DriverInitializationData.DxgkDdiResetFromTimeout                = XenGfxResetFromTimeout;
    DriverInitializationData.DxgkDdiRestartFromTimeout              = XenGfxRestartFromTimeout;
    DriverInitializationData.DxgkDdiEscape                          = XenGfxEscape;
    DriverInitializationData.DxgkDdiCollectDbgInfo                  = XenGfxCollectDbgInfo;
    DriverInitializationData.DxgkDdiQueryCurrentFence               = XenGfxQueryCurrentFence;
    // VidPn
    DriverInitializationData.DxgkDdiIsSupportedVidPn                = XenGfxIsSupportedVidPn;
    DriverInitializationData.DxgkDdiRecommendFunctionalVidPn        = XenGfxRecommendFunctionalVidPn;
    DriverInitializationData.DxgkDdiEnumVidPnCofuncModality         = XenGfxEnumVidPnCofuncModality;
    DriverInitializationData.DxgkDdiSetVidPnSourceAddress           = XenGfxSetVidPnSourceAddress;
    DriverInitializationData.DxgkDdiSetVidPnSourceVisibility        = XenGfxSetVidPnSourceVisibility;
    DriverInitializationData.DxgkDdiCommitVidPn                     = XenGfxCommitVidPn;
    DriverInitializationData.DxgkDdiUpdateActiveVidPnPresentPath    = XenGfxUpdateActiveVidPnPresentPath;
    DriverInitializationData.DxgkDdiRecommendMonitorModes           = XenGfxRecommendMonitorModes;
    DriverInitializationData.DxgkDdiRecommendVidPnTopology          = XenGfxRecommendVidPnTopology;
    DriverInitializationData.DxgkDdiGetScanLine                     = XenGfxGetScanLine;
    // DDI
    DriverInitializationData.DxgkDdiStopCapture                     = XenGfxStopCapture;
    DriverInitializationData.DxgkDdiControlInterrupt                = XenGfxControlInterrupt;
    DriverInitializationData.DxgkDdiCreateOverlay                   = NULL; // not supported
    DriverInitializationData.DxgkDdiDestroyDevice                   = XenGfxDestroyDevice;
    DriverInitializationData.DxgkDdiOpenAllocation                  = XenGfxOpenAllocation;
    DriverInitializationData.DxgkDdiCloseAllocation                 = XenGfxCloseAllocation;
    DriverInitializationData.DxgkDdiRender                          = XenGfxRender;
    DriverInitializationData.DxgkDdiPresent                         = XenGfxPresent;
    DriverInitializationData.DxgkDdiUpdateOverlay                   = NULL; // not supported
    DriverInitializationData.DxgkDdiFlipOverlay                     = NULL; // not supported
    DriverInitializationData.DxgkDdiDestroyOverlay                  = NULL; // not supported
    DriverInitializationData.DxgkDdiCreateContext                   = XenGfxCreateContext;
    DriverInitializationData.DxgkDdiDestroyContext                  = XenGfxDestroyContext;
    DriverInitializationData.DxgkDdiLinkDevice                      = NULL; // not supported
    DriverInitializationData.DxgkDdiSetDisplayPrivateDriverFormat   = NULL; // not supported

    XenGfxLeave(__FUNCTION__);

    return DxgkInitialize(pDriverObject, pRegistryPath, &DriverInitializationData);
}
