//
// xengfxmp.c - Xen Windows PV XDDM Miniport Driver
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


#include "xengfxmp.h"

static VP_STATUS NTAPI
XenGfxRegistryCallback(PVOID pHwDeviceExtension,
                       PVOID pContext,
                       PWSTR pValueName,
                       PVOID pValueData,
                       ULONG ValueLength)
{
    if (pContext == NULL)
        return ERROR_INVALID_PARAMETER;
    if (ValueLength > 0) {
        *(PULONG)pContext = *(PULONG)pValueData;
        return NO_ERROR;
    }
    return ERROR_INVALID_PARAMETER;
}

static VOID NTAPI
XenGfxGetModeInfo(PXENGFX_MODE pXenGfxMode,
                  PVIDEO_MODE_INFORMATION pModeInfo,
                  ULONG Index)
{    
    pModeInfo->ModeIndex = Index;
    pModeInfo->Length = sizeof(VIDEO_MODE_INFORMATION);

    // Subtract the below by offscreen info if necessary.
    pModeInfo->VisScreenWidth = pXenGfxMode->XResolution; 
    pModeInfo->VisScreenHeight = pXenGfxMode->YResolution;
    pModeInfo->ScreenStride = pXenGfxMode->ScreenStride;
    pModeInfo->NumberOfPlanes = 1;
    pModeInfo->BitsPerPlane = pXenGfxMode->BitsPerPixel;
    pModeInfo->Frequency = 75;
 
    // 960 DPI appears to be common.
    pModeInfo->XMillimeter = pXenGfxMode->XResolution * 254 / 960;
    pModeInfo->YMillimeter = pXenGfxMode->YResolution * 254 / 960;
    pModeInfo->VideoMemoryBitmapHeight = pXenGfxMode->YResolution;
    pModeInfo->VideoMemoryBitmapWidth = pXenGfxMode->XResolution;            
    pModeInfo->AttributeFlags = VIDEO_MODE_GRAPHICS | VIDEO_MODE_COLOR | VIDEO_MODE_NO_OFF_SCREEN;

    // All mode are MemoryModel == VBE_MEMORYMODEL_DIRECT_COLOR and the RGB values are constant for the mode.
    pModeInfo->NumberRedBits   = 8;
    pModeInfo->NumberGreenBits = 8;
    pModeInfo->NumberBlueBits  = 8;
    pModeInfo->RedMask         = ((1 << 8) - 1) << 16;
    pModeInfo->GreenMask       = ((1 << 8) - 1) << 8;
    pModeInfo->BlueMask        = ((1 << 8) - 1) << 0;
}

static VOID NTAPI
XenGfxChangeXgfxMode(PXENGFX_DEVICE_EXTENSION pXenGfxExtension, BOOLEAN Enable)
{
    ULONG ControlReg;

    if ((Enable)&&(!pXenGfxExtension->XgfxMode)) {
        ControlReg = VideoPortReadRegisterUlong((PULONG)(pXenGfxExtension->pGlobal + XGFX_CONTROL));

        // Enable XGFX mode (note the interrupt is not enabled currently).
        ControlReg |= XGFX_CONTROL_HIRES_EN;

        VideoPortWriteRegisterUlong((PULONG)(pXenGfxExtension->pGlobal + XGFX_CONTROL), ControlReg);

        pXenGfxExtension->XgfxMode = TRUE;
    }
    else if ((!Enable)&&(pXenGfxExtension->XgfxMode)) {
        ControlReg = VideoPortReadRegisterUlong((PULONG)(pXenGfxExtension->pGlobal + XGFX_CONTROL));

        // Disable XGFX mode
        ControlReg &= ~(XGFX_CONTROL_HIRES_EN);

        VideoPortWriteRegisterUlong((PULONG)(pXenGfxExtension->pGlobal + XGFX_CONTROL), ControlReg);

        pXenGfxExtension->XgfxMode = FALSE;
    }
}

static VOID NTAPI
XenGfxReleaseFrameBuffer(PXENGFX_DEVICE_EXTENSION pXenGfxExtension)
{
    ULONG FBPfns, i;
    ULONG32 *pGartReg;

    if (pXenGfxExtension->pGartMappingReg != NULL) {
        // Sanity
        ASSERT(pXenGfxExtension->pGartMappingReg >=
               (pXenGfxExtension->pGartBaseReg + pXenGfxExtension->StolenPfns));

        FBPfns = pXenGfxExtension->SystemBufferSize/PAGE_SIZE;
        pGartReg = pXenGfxExtension->pGartMappingReg;

        // Invalidate GART entries
        for (i = 0; i < FBPfns; i++)
            pGartReg[i] = XGFX_GART_CLEAR_PFN;

        pXenGfxExtension->pGartMappingReg = NULL;
    }

    (VOID)VideoPortReadRegisterUlong((PULONG)(pXenGfxExtension->pGlobal + XGFX_INVALIDATE_GART));

    // Free any system memory allocated for the frame buffer
    if (pXenGfxExtension->pSystemBuffer != NULL) {
        XenGfxFreeSystemPages(pXenGfxExtension->pSystemBufferContext);
        pXenGfxExtension->pSystemBufferContext = NULL;
        pXenGfxExtension->pSystemBuffer = NULL;
        pXenGfxExtension->SystemBufferSize = 0;
    }
}

static VOID NTAPI
XenGfxFreeResources(PXENGFX_DEVICE_EXTENSION pXenGfxExtension)
{
    XenGfxReleaseFrameBuffer(pXenGfxExtension);

    pXenGfxExtension->pGartBaseReg = NULL;
    pXenGfxExtension->pGartMappingReg = NULL;

    if (pXenGfxExtension->pModes != NULL) {
        XenGfxReleaseModes(pXenGfxExtension->pModes);
        pXenGfxExtension->pModes = NULL;
    }

    if (pXenGfxExtension->pEdid != NULL) {
        XenGfxFreeContiguousPages(pXenGfxExtension->pEdid, 1);
        pXenGfxExtension->pEdid = NULL;
    }

    if (pXenGfxExtension->pXgfxRegBase != NULL) {
        VideoPortFreeDeviceBase(pXenGfxExtension, pXenGfxExtension->pXgfxRegBase);
        pXenGfxExtension->pGart = NULL;
        pXenGfxExtension->pVCrtc0 = NULL;
        pXenGfxExtension->pGlobal = NULL;
        pXenGfxExtension->pXgfxRegBase = NULL;
        pXenGfxExtension->pGartBaseReg = NULL;
        pXenGfxExtension->pGartMappingReg = NULL;
    }
}

static BOOLEAN NTAPI
XenGfxInitializeEdid(PXENGFX_DEVICE_EXTENSION pXenGfxExtension)
{
    UCHAR Sum = 0;
    ULONG i;
    UCHAR *pEdidBuf;
    int   notDone;
    PUCHAR edidOffset = pXenGfxExtension->pVCrtc0 + XGFX_VCRTC_EDID;
    PULONG pEdid;

    // Allocate a single page for the VCRTC0 EDID and fetch it.
    pXenGfxExtension->pEdid = XenGfxAllocateContiguousPages(1);
    if (pXenGfxExtension->pEdid == NULL) {
        TraceError(("%s Failed to allocate EDID page!\n", __FUNCTION__));
        return FALSE;
    }
    
    pEdid = (PULONG)pXenGfxExtension->pEdid;
    //Request memory
    VideoPortWriteRegisterUlong((PULONG)(pXenGfxExtension->pVCrtc0 + XGFX_VCRTC_EDID_REQUEST), 1);

    do {
        notDone = VideoPortReadRegisterUlong( (PULONG) (pXenGfxExtension->pVCrtc0 + XGFX_VCRTC_EDID_REQUEST));
    }while (notDone);

    for (i = 0; i < 4096/sizeof(ULONG); i++) {
        pEdid[i] = VideoPortReadRegisterUlong( (PULONG) (edidOffset + (i * sizeof(ULONG))));
    }

    // Check the checksum
    pEdidBuf = (UCHAR*)pXenGfxExtension->pEdid;
    for (i = 0; i < XENGFX_EDID_SIZE; i++)
        Sum += pEdidBuf[i];

    if (Sum != 0) {
        TraceWarning(("%s EDID checksum is not valid.\n", __FUNCTION__));
    }

    // The XDDM driver will not attempt to report extensions after the EDID. Clear
    // the Extension flag.
    if (pXenGfxExtension->pEdid->ExtensionFlag[0] != 0) {
        pXenGfxExtension->pEdid->ExtensionFlag[0] = 0;
        Sum = 1;
    }

    // Recalculate the checksum if needed.
    if (Sum != 0) {
        Sum = 0;
        pXenGfxExtension->pEdid->Checksum[0] = 0;
        for (i = 0; i < XENGFX_EDID_SIZE; i++)
            Sum += pEdidBuf[i];
        pXenGfxExtension->pEdid->Checksum[0] = -Sum;
    }

    return TRUE;
}

static BOOLEAN NTAPI
XenGfxInitializeModes(PXENGFX_DEVICE_EXTENSION pXenGfxExtension)
{
    XENGFX_MODE_VALUES ModeValues = {0};

    ModeValues.pEdid           = pXenGfxExtension->pEdid;
    ModeValues.MaxHorizontal   = pXenGfxExtension->MaxHorizontal;
    ModeValues.MaxVertical     = pXenGfxExtension->MaxVertical;
    ModeValues.StrideAlignment = pXenGfxExtension->StrideAlignment;
    ModeValues.XgfxFormat      = XGFX_VCRTC_VALID_FORMAT_BGRX8888;

    pXenGfxExtension->ModeIndex = XENGFX_INVALID_MODE_INDEX;
    pXenGfxExtension->ModeCount = XenGfxCreateModes(&ModeValues);
    if (pXenGfxExtension->ModeCount == 0) {
        TraceError(("%s Failed in XenGfxInitializeModes() call.\n", __FUNCTION__));
        return FALSE;
    }
    pXenGfxExtension->pModes = ModeValues.pModes;
    pXenGfxExtension->MaxStride = XENGFX_MAX(pXenGfxExtension->MaxStride, ModeValues.MaxStride);
    pXenGfxExtension->MaxHeight = XENGFX_MAX(pXenGfxExtension->MaxHeight, ModeValues.MaxHeight);

    return TRUE;
}

static BOOLEAN NTAPI
XenGfxCreateFrameBuffer(PXENGFX_DEVICE_EXTENSION pXenGfxExtension)
{
    ULONG GartSize, FBPfns, TotalPfns, i;
    ULONG32 *pGartReg;
    PHYSICAL_ADDRESS PhysAddr;
    ULONG_PTR StrideAlignment;
    UCHAR *pBuf;

    // Get some values
    pXenGfxExtension->SystemBufferSize = 
        XENGFX_MASK_ALIGN((pXenGfxExtension->MaxStride * pXenGfxExtension->MaxHeight), XENGFX_PAGE_ALIGN_MASK);
    GartSize =
        VideoPortReadRegisterUlong((PULONG)(pXenGfxExtension->pGlobal + XGFX_GART_SIZE));
    GartSize *= PAGE_SIZE;
    pXenGfxExtension->StolenPfns =
        VideoPortReadRegisterUlong((PULONG)(pXenGfxExtension->pGlobal + XGFX_STOLEN_SIZE));

    FBPfns = pXenGfxExtension->SystemBufferSize/PAGE_SIZE;

    // The XDDM driver leaves the stolen space intact since there is no good way to restore it
    // given there are no driver/device unload routines for an XDDM miniport.
    pXenGfxExtension->pGartMappingReg = pXenGfxExtension->pGartBaseReg + pXenGfxExtension->StolenPfns;

    // Determine if there is an alignment requirement beyond page alignment and apply it to the 
    // GART mapping start offset.
    if (pXenGfxExtension->StrideAlignment > XENGFX_PAGE_ALIGN_MASK) {
        StrideAlignment = pXenGfxExtension->StrideAlignment;
        (ULONG_PTR)pXenGfxExtension->pGartMappingReg += (StrideAlignment >> 12);
        (ULONG_PTR)pXenGfxExtension->pGartMappingReg &= ~(StrideAlignment >> 12);
    }

    // Sanity check that it will all fit
    TotalPfns = ((ULONG)(pXenGfxExtension->pGartMappingReg - pXenGfxExtension->pGartBaseReg)) + FBPfns;
    if (TotalPfns > GartSize) {
        // SNO - unless a completely bogus mode from the EDID was specified
        TraceError(("%s Aperture too small for frame buffer - Aparture PFNs = 0x%x, Required PFNs = 0x%x\n",
                    __FUNCTION__, GartSize, TotalPfns));
        return FALSE;
    }

    // Now we need some guest system memory to back this bad boy with. Allocate a region outside
    // the kernel heaps.
    pXenGfxExtension->pSystemBuffer = 
        XenGfxAllocateSystemPages(pXenGfxExtension->SystemBufferSize,
                                  &pXenGfxExtension->pSystemBufferContext);
    if (pXenGfxExtension->pSystemBuffer == NULL) {     
        TraceError(("%s Failed to allocate system memory for a frame buffer!\n", __FUNCTION__));
        pXenGfxExtension->pSystemBufferContext = NULL;
        return FALSE;
    }
    pBuf = (UCHAR*)pXenGfxExtension->pSystemBuffer;    
    
    // Finally map it into the GART
    pGartReg = pXenGfxExtension->pGartMappingReg;
    for (i = 0; i < FBPfns; i++) {
        XenGfxGetPhysicalAddressess(pBuf, &PhysAddr, 1);
        pGartReg[i] = XGFX_GART_REG_MASK & (XGFX_GART_VALID_PFN | (ULONG32)(PhysAddr.QuadPart/PAGE_SIZE));
        pBuf += PAGE_SIZE;
    }

    (VOID)VideoPortReadRegisterUlong((PULONG)(pXenGfxExtension->pGlobal + XGFX_INVALIDATE_GART));

    return TRUE;
}

static VOID NTAPI
XenGfxDpc(PVOID pHwDeviceExtension, PVOID pContext)
{
    UNREFERENCED_PARAMETER(pHwDeviceExtension);
    UNREFERENCED_PARAMETER(pContext);

    // Not currently used, multiple child devices not yet supported
}

static BOOLEAN NTAPI
XenGfxInterrupt(PVOID pHwDeviceExtension)
{
    PXENGFX_DEVICE_EXTENSION pXenGfxExtension = (PXENGFX_DEVICE_EXTENSION)pHwDeviceExtension;
    ULONG StatusReg;
    
    if (InterlockedExchangeAdd(&pXenGfxExtension->Initialized, 0) == 0) {
        return FALSE;
    }

    StatusReg = VideoPortReadRegisterUlong((PULONG)(pXenGfxExtension->pGlobal + XGFX_ISR));
    if (StatusReg & XGFX_ISR_INT) {
        VideoPortWriteRegisterUlong((PULONG)(pXenGfxExtension->pGlobal + XGFX_ISR), StatusReg);
        
        // Even though a single monitor can be unplugged on desktop system there is no clear way
        // to handle this since returning no child devices connected does nothing useful in XDDM.
        // Instead XGFX will always return an EDID so we don't have to deal with this for a single
        // monitor.

        // VideoPortQueueDpc(pHwDeviceExtension, XenGfxDpc, NULL);
        return TRUE;
    }

    return FALSE;
}

static VP_STATUS NTAPI
XenGfxFindAdapter(PVOID pHwDeviceExtension,
                  PVOID pHwContext,
                  PWSTR pArgumentString, 
                  PVIDEO_PORT_CONFIG_INFO pConfigInfo,
                  PUCHAR pAgain)
{
#define XENGFX_NUM_RANGES 4
    VP_STATUS Status;
    ULONG Slot, i, Magic, Rev;
    VIDEO_ACCESS_RANGE AccessRanges[XENGFX_NUM_RANGES]; // 2 MMIO, 1 IRQ, 1 PIO
    PXENGFX_DEVICE_EXTENSION pXenGfxExtension = (PXENGFX_DEVICE_EXTENSION)pHwDeviceExtension;    

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (pConfigInfo->Length != sizeof(VIDEO_PORT_CONFIG_INFO)) {
        TraceError(("%s Invalid VIDEO_PORT_CONFIG_INFO length!\n", __FUNCTION__));
        return ERROR_INVALID_PARAMETER;
    }

    VideoPortZeroMemory(AccessRanges, sizeof(VIDEO_ACCESS_RANGE));

    // Retrieve access ranges for the XenGfx device including the IRQ resource.
    Status = VideoPortGetAccessRanges(pHwDeviceExtension,
                                      0,
                                      NULL,
                                      XENGFX_NUM_RANGES,
                                      AccessRanges,
                                      NULL,
                                      NULL,
                                      &Slot);
    if (Status != NO_ERROR) {
        TraceError(("VideoPortGetAccessRanges failed - Status: 0x%x\n", Status));
        return Status;
    }

    // Check that the IRQ was found
    if ((pConfigInfo->BusInterruptLevel == 0)||(pConfigInfo->BusInterruptVector == 0)) {
        TraceWarning(("%s could not located Interrupt values??? Level: %d Vector: %d\n",
                     __FUNCTION__, pConfigInfo->BusInterruptLevel, pConfigInfo->BusInterruptVector));
        pConfigInfo->BusInterruptLevel = 0;
        pConfigInfo->BusInterruptVector = 0;
        pXenGfxExtension->NoIrq = TRUE;
        TraceWarning(("%s proceeding with interrupts disabled...\n", __FUNCTION__));
    }

    // Not using int10 calls so these can be zero
    pConfigInfo->VdmPhysicalVideoMemoryAddress.QuadPart = 0;
    pConfigInfo->VdmPhysicalVideoMemoryLength           = 0;

    // Locate and map in our IO spaces
    for (i = 0; i < XENGFX_NUM_RANGES; i++) {
        // Is it a valid range?
        if (AccessRanges[i].RangeLength == 0) {
            continue;
        }

        // MMIO or PIO
        if (AccessRanges[i].RangeInIoSpace == 0) {
            // Is this the graphics aperture in BAR0, not mapped here, just save
            // the bus relative address
            if (AccessRanges[i].RangeLength > XENGFX_XGFXREG_MAX_SIZE) {
                pXenGfxExtension->GraphicsApertureBase = AccessRanges[i].RangeStart;
                continue;
            }

            if (pXenGfxExtension->pXgfxRegBase != NULL) {
                TraceWarning(("%s MMIO register range already set??? Ignore this resource at %d == %x:%x\n",
                              __FUNCTION__, i, AccessRanges[i].RangeStart.HighPart, AccessRanges[i].RangeStart.LowPart));
                continue;
            }

            pXenGfxExtension->pXgfxRegBase = 
                VideoPortGetDeviceBase(pHwDeviceExtension,
                                       AccessRanges[i].RangeStart,
                                       AccessRanges[i].RangeLength,
                                       VIDEO_MEMORY_SPACE_MEMORY);
            if (pXenGfxExtension->pXgfxRegBase == NULL) {
                TraceWarning(("VideoPortGetDeviceBase(MMIO register range) failed!\n"));
                XenGfxFreeResources(pXenGfxExtension);
                return ERROR_NOT_ENOUGH_MEMORY;
            }
            // Set pointer to Global regs, VCRTC0 bank and GART
            pXenGfxExtension->pGlobal = pXenGfxExtension->pXgfxRegBase + XGFX_GLOBAL_OFFSET;
            pXenGfxExtension->pVCrtc0 = pXenGfxExtension->pXgfxRegBase + XGFX_VCRTC_OFFSET;
            pXenGfxExtension->pGart = pXenGfxExtension->pXgfxRegBase + XGFX_GART_OFFSET;

            // Mapping register pointers
            pXenGfxExtension->pGartBaseReg = (PULONG32)pXenGfxExtension->pGart;
            pXenGfxExtension->pGartMappingReg = NULL;
            continue;
        }

        // Else this is a Port I/O resource for accessing the MMIO registers via PIO.
        TraceVerbose(("PIO resource at %d == %x:%x\n", i,
                     AccessRanges[i].RangeStart.HighPart, AccessRanges[i].RangeStart.LowPart));
    }

    // Get registry value for enabling DualView mode
    Status = VideoPortGetRegistryParameters(pHwDeviceExtension,
                                            L"EnableDualView",
                                            FALSE,
                                            XenGfxRegistryCallback,
                                            &pXenGfxExtension->DualViewSupport);
    if (pConfigInfo->Length != sizeof(VIDEO_PORT_CONFIG_INFO)) {
        TraceWarning(("%s Could not read EnableDualView value - Status: 0x%x\n", __FUNCTION__, Status));
        pXenGfxExtension->DualViewSupport = 0;
    }
    else if (pXenGfxExtension->DualViewSupport != 0) {
        TraceVerbose(("%s DualView not yet supported, disabling.\n", __FUNCTION__));
        pXenGfxExtension->DualViewSupport = 0;
    }

    // Reset the XGFX virtual adapter to a known state.
    VideoPortReadRegisterUlong((PULONG)(pXenGfxExtension->pGlobal + XGFX_RESET));

    // Sanity check the magic value and the current rev.
    Magic = VideoPortReadRegisterUlong((PULONG)(pXenGfxExtension->pGlobal + XGFX_MAGIC));
    Rev = VideoPortReadRegisterUlong((PULONG)(pXenGfxExtension->pGlobal + XGFX_REV));
    if ((Magic != XGFX_MAGIC_VALUE)||(Rev != XGFX_CURRENT_REV)) {
        TraceError(("%s Invalid XGFX Magic or Rev. Magic (expected 0x%x): 0x%x Rev (expected 0x%x): 0x%x\n",
                    __FUNCTION__, XGFX_MAGIC_VALUE, Magic, XGFX_CURRENT_REV, Rev));
        return ERROR_INVALID_PARAMETER;
    }

    // Fetch some hardware specific limits for VCRTC0
    pXenGfxExtension->MaxHorizontal = 
        VideoPortReadRegisterUlong((PULONG)(pXenGfxExtension->pVCrtc0 + XGFX_VCRTC_MAX_HORIZONTAL));
    pXenGfxExtension->MaxVertical = 
        VideoPortReadRegisterUlong((PULONG)(pXenGfxExtension->pVCrtc0 + XGFX_VCRTC_MAX_VERTICAL));
    pXenGfxExtension->StrideAlignment = 
        VideoPortReadRegisterUlong((PULONG)(pXenGfxExtension->pVCrtc0 + XGFX_VCRTC_STRIDE_ALIGNMENT));

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return NO_ERROR;    
}

static BOOLEAN NTAPI
XenGfxInitialize(PVOID pHwDeviceExtension)
{
    PXENGFX_DEVICE_EXTENSION pXenGfxExtension = (PXENGFX_DEVICE_EXTENSION)pHwDeviceExtension;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    // Currently a single VCRTC is supported that will report a single child device. Support
    // for multiple child devices will allow cloned views. To get independent views then
    // DualView support must also be implemented.

    // Setup the one EDID for VCTRC0
    if (!XenGfxInitializeEdid(pXenGfxExtension)) {
        XenGfxFreeResources(pXenGfxExtension);
        return FALSE;
    }

    // Setup static Modes list using the EDID monitor information
    if (!XenGfxInitializeModes(pXenGfxExtension)) {
        XenGfxFreeResources(pXenGfxExtension);
        return FALSE;
    }

    // Create a frame buffer for VCRTC0
    if (!XenGfxCreateFrameBuffer(pXenGfxExtension)) {
        XenGfxFreeResources(pXenGfxExtension);
        return FALSE;
    }
    
    // This is the primary
    pXenGfxExtension->IsPrimary = TRUE;

    // Device is up, switch to initialized
    InterlockedExchange(&pXenGfxExtension->Initialized, 1);

    // Switch to XGFX mode
    XenGfxChangeXgfxMode(pXenGfxExtension, TRUE);

    // Ready to run. The call to set the mode will finish setting up VCRTC0 and
    // enable it.

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return TRUE;    
}

static VP_STATUS NTAPI
XenGfxSetPowerState(PVOID pHwDeviceExtension, 
                    ULONG HwId, 
                    PVIDEO_POWER_MANAGEMENT pVideoPowerControl)
{
    TraceVerbose(("====> '%s'.\n", __FUNCTION__));
    TraceVerbose(("PowerState: %d\n", pVideoPowerControl->PowerState));
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return NO_ERROR;
}

static VP_STATUS NTAPI
XenGfxGetPowerState(PVOID pHwDeviceExtension, 
                    ULONG HwId, 
                    PVIDEO_POWER_MANAGEMENT pVideoPowerControl)
{
    TraceVerbose(("====> '%s'.\n", __FUNCTION__));
    TraceVerbose(("PowerState: %d\n", pVideoPowerControl->PowerState));
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return NO_ERROR;
}

static VP_STATUS NTAPI
XenGfxGetVideoChildDescriptor(PVOID pHwDeviceExtension, 
                              PVIDEO_CHILD_ENUM_INFO pChildEnumInfo, 
                              PVIDEO_CHILD_TYPE pVideoChildType,
                              PUCHAR pChildDescriptor,
                              PULONG pUId, 
                              PULONG pUnused)
{
    PXENGFX_DEVICE_EXTENSION pXenGfxExtension = (PXENGFX_DEVICE_EXTENSION)pHwDeviceExtension;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (pChildEnumInfo->ChildIndex == DISPLAY_ADAPTER_HW_ID)
        return ERROR_NO_MORE_DEVICES;    

    if ((pChildDescriptor == NULL)||(pChildEnumInfo->ChildDescriptorSize < XENGFX_EDID_SIZE))
        return ERROR_NO_MORE_DEVICES;

    if (pXenGfxExtension->pEdid == NULL)
        return ERROR_NO_MORE_DEVICES;

    *pVideoChildType = Monitor;
    *pUId = pChildEnumInfo->ChildIndex;
    *pUnused = 0;

    // Copy over the one EDID from VCRTC0. Note any extensions were cleared out so it is
    // of fixed size.
    VideoPortMoveMemory(pChildDescriptor, pXenGfxExtension->pEdid, XENGFX_EDID_SIZE);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return ERROR_NO_MORE_DEVICES;
}

static BOOLEAN NTAPI
XenGfxSetCurrentMode(PXENGFX_DEVICE_EXTENSION pXenGfxExtension,
                     PVIDEO_MODE pRequestedMode,
                     PSTATUS_BLOCK pStatusBlock)
{
    VP_STATUS Status;
    ULONG ModeRequested = pRequestedMode->RequestedMode & 0x3fffffff;
    XENGFX_MODE *pMode;    

    if (ModeRequested >= pXenGfxExtension->ModeCount) {
        TraceError(("%s Invalid parameter!\n", __FUNCTION__));
        pStatusBlock->Status = STATUS_INVALID_PARAMETER;
        return FALSE;
    }
    pMode = &pXenGfxExtension->pModes[ModeRequested];

    // Re-enable XGFX mode in case this is returning from a reset
    XenGfxChangeXgfxMode(pXenGfxExtension, TRUE);    

    // Enbable VCRT0 and setup mode values, use fallback value for format. Note that the set mode
    // call comes in before the call to map video memory. These values are not set until the map
    // call arrives and posts the values via XGFX_VCRTC_BASE.
    VideoPortWriteRegisterUlong((PULONG)(pXenGfxExtension->pVCrtc0 + XGFX_VCRTC_FORMAT),
                                pMode->XgfxFormat);
    VideoPortWriteRegisterUlong((PULONG)(pXenGfxExtension->pVCrtc0 + XGFX_VCRTC_HORIZONTAL_ACTIVE),
                                pMode->XResolution - 1);
    VideoPortWriteRegisterUlong((PULONG)(pXenGfxExtension->pVCrtc0 + XGFX_VCRTC_VERTICAL_ACTIVE),
                                pMode->YResolution - 1);
    VideoPortWriteRegisterUlong((PULONG)(pXenGfxExtension->pVCrtc0 + XGFX_VCRTC_STRIDE),
                                pMode->ScreenStride);    

    pXenGfxExtension->ModeIndex = ModeRequested;
    pStatusBlock->Status = NO_ERROR;

    TraceVerbose(("%s Set Mode: %d\n", __FUNCTION__, ModeRequested));

    return TRUE;
}

static BOOLEAN NTAPI
XenGfxResetDevice(PXENGFX_DEVICE_EXTENSION pXenGfxExtension, 
                  PSTATUS_BLOCK pStatusBlock)
{
    BOOLEAN Ret = TRUE;

    TraceVerbose(("%s RESET\n", __FUNCTION__));

    // Disable XGFX mode
    XenGfxChangeXgfxMode(pXenGfxExtension, FALSE);

    pStatusBlock->Status = NO_ERROR;
    
    
    Ret = XenGfxVgaResetMode3((PUCHAR)XENGFX_SHADOW_PORT_BASE,
                              (PUCHAR)XENGFX_VBE_PORT_BASE);
    if (!Ret) {
        TraceError(("%s XenGfxVgaResetMode3() failed.\n", __FUNCTION__));
        pStatusBlock->Status = ERROR_NOT_ENOUGH_MEMORY;
    }

    return Ret;
}

static BOOLEAN NTAPI
XenGfxMapVideoMemory(PXENGFX_DEVICE_EXTENSION pXenGfxExtension,
                     PVIDEO_MEMORY pRequestedAddress, 
                     PVIDEO_MEMORY_INFORMATION pMapInformation,
                     PSTATUS_BLOCK pStatusBlock)
{
    VP_STATUS Status = NO_ERROR;
    PHYSICAL_ADDRESS VideoMemory;
    ULONG MemSpace = VIDEO_MEMORY_SPACE_MEMORY;
    ULONG Offset;
    ULONG ControlReg;
    XENGFX_MODE *pMode;

    TraceVerbose(("%s Map VideoRamBase: %p\n", __FUNCTION__, pRequestedAddress->RequestedVirtualAddress));

    // All our modes are VBE_MODE_ATTRIBUTE_LINEAR_FRAME_BUFFER_MODE
    pMode = &pXenGfxExtension->pModes[pXenGfxExtension->ModeIndex];

    // Offset into the graphics aperture in bytes.
    Offset = ((ULONG)(pXenGfxExtension->pGartMappingReg - pXenGfxExtension->pGartBaseReg))*PAGE_SIZE;

    VideoMemory.QuadPart = pXenGfxExtension->GraphicsApertureBase.QuadPart + Offset;

    pMapInformation->VideoRamBase = pRequestedAddress->RequestedVirtualAddress;
    pMapInformation->VideoRamLength = pMode->ScreenStride*pMode->YResolution;
    
    Status = VideoPortMapMemory(pXenGfxExtension,
                                VideoMemory,
                                &pMapInformation->VideoRamLength,
                                &MemSpace,
                                &pMapInformation->VideoRamBase);
    if (Status != NO_ERROR) {
        TraceError(("VideoPortMapMemory failed - Status: 0x%x\n", Status));
        pStatusBlock->Status = Status;
        return FALSE;
    }

    pMapInformation->FrameBufferBase = pMapInformation->VideoRamBase;
    pMapInformation->FrameBufferLength = pMapInformation->VideoRamLength;
    pStatusBlock->Information = sizeof(VIDEO_MEMORY_INFORMATION);
    pStatusBlock->Status = NO_ERROR;

    // Enable VCRTC0 rastering before committing values and video memory.
    ControlReg = VideoPortReadRegisterUlong((PULONG)(pXenGfxExtension->pVCrtc0 + XGFX_VCRTC_CONTROL));
    VideoPortWriteRegisterUlong((PULONG)(pXenGfxExtension->pVCrtc0 + XGFX_VCRTC_CONTROL),
                                (ControlReg|XGFX_VCRTC_CONTROL_ENABLE));

    // Commit by writting the frame buffer offset in XGFX_VCRTC0_BASE. This commits the current
    // mode information from the set mode call.
    VideoPortWriteRegisterUlong((PULONG)(pXenGfxExtension->pVCrtc0 + XGFX_VCRTC_BASE), Offset);

    TraceVerbose(("%s Mapped VideoRamBase: %p VideoRamLength: 0x%x\n", __FUNCTION__,
                 pMapInformation->VideoRamBase, pMapInformation->VideoRamLength));
   
    return TRUE;
}

static BOOLEAN NTAPI
XenGfxUnmapVideoMemory(PXENGFX_DEVICE_EXTENSION pXenGfxExtension,
                       PVIDEO_MEMORY pVideoMemory,
                       PSTATUS_BLOCK pStatusBlock)
{
    VP_STATUS Status;
    ULONG ControlReg;

    TraceVerbose(("%s Unmap VideoRamBase: %p\n", __FUNCTION__, pVideoMemory->RequestedVirtualAddress));

    // Disable rastering for VCRTC0
    ControlReg = VideoPortReadRegisterUlong((PULONG)(pXenGfxExtension->pVCrtc0 + XGFX_VCRTC_CONTROL));
    ControlReg &= ~(XGFX_VCRTC_CONTROL_ENABLE);
    VideoPortWriteRegisterUlong((PULONG)(pXenGfxExtension->pVCrtc0 + XGFX_VCRTC_CONTROL), ControlReg);

    // Commit by writting the frame buffer offset in XGFX_VCRTC0_BASE.
    VideoPortWriteRegisterUlong((PULONG)(pXenGfxExtension->pVCrtc0 + XGFX_VCRTC_BASE), 0);

    Status = VideoPortUnmapMemory(pXenGfxExtension, pVideoMemory->RequestedVirtualAddress, NULL);
    if (Status != NO_ERROR)
        TraceError(("%s Failed to unmap memory: %p Status: %x\n", __FUNCTION__,
                   pVideoMemory->RequestedVirtualAddress, Status));    

    pStatusBlock->Status = Status;

    return (Status == NO_ERROR);
}

static BOOLEAN NTAPI
XenGfxQueryNumAvailableModes(PXENGFX_DEVICE_EXTENSION pXenGfxExtension,
                             PVIDEO_NUM_MODES pAvailableModes,
                             PSTATUS_BLOCK pStatusBlock)
{
    pAvailableModes->NumModes = pXenGfxExtension->ModeCount;
    pAvailableModes->ModeInformationLength = sizeof(VIDEO_MODE_INFORMATION);
    pStatusBlock->Information = sizeof(VIDEO_NUM_MODES);
    pStatusBlock->Status = NO_ERROR;

    return TRUE;
}

static BOOLEAN NTAPI
XenGfxQueryAvailableModes(PXENGFX_DEVICE_EXTENSION pXenGfxExtension,
                          PVIDEO_MODE_INFORMATION pReturnedModes, 
                          PSTATUS_BLOCK pStatusBlock)
{
    PXENGFX_MODE pMode;
    PVIDEO_MODE_INFORMATION pModeInfo;
    ULONG i;

    pMode = pXenGfxExtension->pModes;
    pModeInfo = pReturnedModes;

    for (i = 0; i < pXenGfxExtension->ModeCount; i++, pMode++, pModeInfo++) {
        VideoPortZeroMemory(pModeInfo, sizeof(VIDEO_MODE_INFORMATION));
        XenGfxGetModeInfo(pMode, pModeInfo, i);
    }

    pStatusBlock->Information = sizeof(VIDEO_MODE_INFORMATION)*pXenGfxExtension->ModeCount;
    pStatusBlock->Status = NO_ERROR;
    return TRUE;
}

static BOOLEAN NTAPI
XenGfxQueryCurrentMode(PXENGFX_DEVICE_EXTENSION pXenGfxExtension,
                       PVIDEO_MODE_INFORMATION pModeInfo, 
                       PSTATUS_BLOCK pStatusBlock)
{
    
    if (pXenGfxExtension->ModeIndex >= pXenGfxExtension->ModeCount) {
        pStatusBlock->Status = STATUS_INVALID_PARAMETER;
        return FALSE; // SNO
    }
    
    VideoPortZeroMemory(pModeInfo, sizeof(VIDEO_MODE_INFORMATION));
    XenGfxGetModeInfo(&pXenGfxExtension->pModes[pXenGfxExtension->ModeIndex],
                      pModeInfo,
                      pXenGfxExtension->ModeIndex);
    
    pStatusBlock->Information = sizeof(VIDEO_MODE_INFORMATION);
    pStatusBlock->Status = NO_ERROR;
    return TRUE;
}

static BOOLEAN NTAPI
XenGfxStartIO(PVOID pHwDeviceExtension, PVIDEO_REQUEST_PACKET pRequestPacket)
{
    BOOLEAN Ret = FALSE;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    pRequestPacket->StatusBlock->Status = STATUS_NOT_IMPLEMENTED;

    switch (pRequestPacket->IoControlCode) {
    case IOCTL_VIDEO_MAP_VIDEO_MEMORY:
    {
        if (pRequestPacket->InputBufferLength < sizeof(VIDEO_MEMORY) ) {
            TraceError(("Invalid input parameter for IOCTL_VIDEO_MAP_VIDEO_MEMORY\n"));
            pRequestPacket->StatusBlock->Status = STATUS_INVALID_PARAMETER;
            break;
        }       
        if (pRequestPacket->OutputBufferLength < sizeof(VIDEO_MEMORY_INFORMATION)) {
            TraceError(("Insufficent output buffer for IOCTL_VIDEO_MAP_VIDEO_MEMORY\n"));
            pRequestPacket->StatusBlock->Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        Ret = XenGfxMapVideoMemory((PXENGFX_DEVICE_EXTENSION)pHwDeviceExtension,
                                   (PVIDEO_MEMORY)pRequestPacket->InputBuffer, 
                                   (PVIDEO_MEMORY_INFORMATION)pRequestPacket->OutputBuffer, 
                                   pRequestPacket->StatusBlock);
        break;
    }

    case IOCTL_VIDEO_UNMAP_VIDEO_MEMORY:
    {    
        if (pRequestPacket->InputBufferLength < sizeof(VIDEO_MEMORY)) {
            TraceError(("Invalid input parameter for IOCTL_VIDEO_UNMAP_VIDEO_MEMORY\n"));
            pRequestPacket->StatusBlock->Status = STATUS_INVALID_PARAMETER;
            break;
        }
        Ret = XenGfxUnmapVideoMemory((PXENGFX_DEVICE_EXTENSION)pHwDeviceExtension,
                                     (PVIDEO_MEMORY)pRequestPacket->InputBuffer,
                                     pRequestPacket->StatusBlock);
        break;
    }
    case IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES:
    {
        TraceVerbose(("Query available modes\n"));
        if (pRequestPacket->OutputBufferLength < sizeof(VIDEO_NUM_MODES)) {
            TraceError(("Invalid input parameter for IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES\n"));
            pRequestPacket->StatusBlock->Status = STATUS_INVALID_PARAMETER;
            break;
        }
        Ret = XenGfxQueryNumAvailableModes((PXENGFX_DEVICE_EXTENSION)pHwDeviceExtension,
                                           (PVIDEO_NUM_MODES)pRequestPacket->OutputBuffer,
                                           pRequestPacket->StatusBlock);
        break;
    }
    case IOCTL_VIDEO_QUERY_AVAIL_MODES:
    {
        TraceVerbose(("Query mode info\n"));        
        if (pRequestPacket->OutputBufferLength <
            ((PXENGFX_DEVICE_EXTENSION)pHwDeviceExtension)->ModeCount * sizeof(VIDEO_MODE_INFORMATION)) {
            TraceError(("Invalid input parameter for IOCTL_VIDEO_QUERY_AVAIL_MODES\n"));
            pRequestPacket->StatusBlock->Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        Ret = XenGfxQueryAvailableModes((PXENGFX_DEVICE_EXTENSION)pHwDeviceExtension,
                                        (PVIDEO_MODE_INFORMATION)pRequestPacket->OutputBuffer, 
                                        pRequestPacket->StatusBlock);
        break;
    }
    case IOCTL_VIDEO_SET_CURRENT_MODE:
    {
        TraceVerbose(("Set current mode\n")); 
        if (pRequestPacket->InputBufferLength < sizeof(VIDEO_MODE)) {
            TraceError(("Invalid input parameter for IOCTL_VIDEO_SET_CURRENT_MODE\n"));
            pRequestPacket->StatusBlock->Status = STATUS_INVALID_PARAMETER;
            break;
        }
        Ret = XenGfxSetCurrentMode((PXENGFX_DEVICE_EXTENSION)pHwDeviceExtension,
                                   (PVIDEO_MODE)pRequestPacket->InputBuffer,
                                   pRequestPacket->StatusBlock);
        break;
    }
    case IOCTL_VIDEO_QUERY_CURRENT_MODE:
    {
        TraceVerbose(("Query current mode\n"));
        if (pRequestPacket->OutputBufferLength < sizeof(VIDEO_MODE_INFORMATION)) {
            TraceError(("Invalid input parameter for IOCTL_VIDEO_QUERY_CURRENT_MODE\n"));
            pRequestPacket->StatusBlock->Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        Ret = XenGfxQueryCurrentMode((PXENGFX_DEVICE_EXTENSION)pHwDeviceExtension,
                                     (PVIDEO_MODE_INFORMATION)pRequestPacket->OutputBuffer,
                                     pRequestPacket->StatusBlock);
        break;
    }
    case IOCTL_VIDEO_RESET_DEVICE:
    {
        TraceVerbose(("Reset device\n"));
        Ret = XenGfxResetDevice((PXENGFX_DEVICE_EXTENSION)pHwDeviceExtension,
                                pRequestPacket->StatusBlock);
        break;
    }
    default:
        TraceWarning(("%s - Unknown IOCTL - 0x%08x\n", __FUNCTION__, pRequestPacket->IoControlCode));          
        break;
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    
    return Ret;
}

ULONG
DriverEntry(PVOID pContext1, PVOID pContext2)
{
    ULONG Ret;
    VIDEO_HW_INITIALIZATION_DATA VideoInitData;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));    

    VideoPortZeroMemory(&VideoInitData, sizeof(VideoInitData));
    VideoInitData.HwInitDataSize = sizeof(VIDEO_HW_INITIALIZATION_DATA);
    VideoInitData.HwDeviceExtensionSize = sizeof(XENGFX_DEVICE_EXTENSION);
    VideoInitData.HwFindAdapter = XenGfxFindAdapter;
    VideoInitData.HwInitialize = XenGfxInitialize;
    VideoInitData.HwInterrupt = XenGfxInterrupt;
    VideoInitData.HwStartIO = XenGfxStartIO;
    VideoInitData.HwSetPowerState = XenGfxSetPowerState;
    VideoInitData.HwGetPowerState = XenGfxGetPowerState;
    VideoInitData.HwGetVideoChildDescriptor = XenGfxGetVideoChildDescriptor;

    if ((Ret = VideoPortInitialize(pContext1, pContext2, &VideoInitData, NULL)) != 0) {
        TraceError(("VideoPortInitialize failed - %d\n", Ret));
        return STATUS_UNSUCCESSFUL;
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return NO_ERROR;
}
