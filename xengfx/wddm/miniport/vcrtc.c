//
// vcrtc.c - Xen Windows PV WDDM Miniport Driver vCRTC management routines.
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


#include "xengfxwd.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE,XenGfxAllocateVCrtcBanks)
#pragma alloc_text(PAGE,XenGfxFreeVCrtcBanks)
#pragma alloc_text(PAGE,XenGfxEnableVCrtcs)
#endif

BOOLEAN
XenGfxSupportedVCrtcFormat(XENGFX_VCRTC *pVCrtc, D3DDDIFORMAT DdiFormat)
{
    ULONG XgfxFormat, ValidFormats;

    XgfxFormat = XenGfxXgfxFormatFromDdiFormat(DdiFormat);
    if (XgfxFormat == XGFX_VCRTC_VALID_FORMAT_NONE)
        return FALSE;

    ValidFormats = READ_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_VALID_FORMAT));
    if (XgfxFormat & ValidFormats)
        return TRUE;

    return FALSE;
}

static ULONG
XenGfxPreferredVCrtcFormat(XENGFX_VCRTC *pVCrtc)
{
    ULONG XgfxFormat, ValidFormats, i;

    // Determine which formats the VCRTC supports. This will be used to set
    // up the mode information. Note that the VCRTC may support multiple formats
    // but it seems it is not terribly useful to report more than the first best
    // supported format (starting with the 32 BPP formats). If none of the 
    // XENGFX_D3D_FORMAT_COUNT supported formats are available, the fall-back 
    // XGFX_VCRTC_VALID_FORMAT_RGBX8888 will be used.
    ValidFormats = READ_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_VALID_FORMAT));
    XgfxFormat = XGFX_VCRTC_VALID_FORMAT_RGBX8888;

    for (i = 0; i < XENGFX_D3D_FORMAT_COUNT; i++) {
        // Formats are in preferential order in the array.
        if (g_XenGfxFormatMap[i].XgfxFormat & ValidFormats) {
            XgfxFormat = g_XenGfxFormatMap[i].XgfxFormat;
            break;
        }
    }

    return XgfxFormat;
}

BOOLEAN
XenGfxAllocateVCrtcBanks(XENGFX_DEVICE_EXTENSION *pXenGfxExtension)
{
    ULONG i;
    PAGED_CODE();

    // T & S Level 3
    ASSERT(pXenGfxExtension->VCrtcCount == 0);
    ASSERT(pXenGfxExtension->ppVCrtcBanks == NULL);

    // Determine how many VCRTCs there are and how many child devices to support and reconcile.
    pXenGfxExtension->VCrtcMaxCount = READ_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_NVCRTC));
    if (pXenGfxExtension->VCrtcRegistryCount != 0)
        pXenGfxExtension->VCrtcCount = XENGFX_MIN(pXenGfxExtension->VCrtcRegistryCount, pXenGfxExtension->VCrtcMaxCount);
    else
        pXenGfxExtension->VCrtcCount = XENGFX_MIN(XENGFX_DEFAULT_VCRTC_COUNT, pXenGfxExtension->VCrtcMaxCount);

    pXenGfxExtension->ppVCrtcBanks = 
        (XENGFX_VCRTC**)ExAllocatePoolWithTag(NonPagedPool,
                                              pXenGfxExtension->VCrtcCount*sizeof(XENGFX_VCRTC*),
                                              XENGFX_TAG);
    if (pXenGfxExtension->ppVCrtcBanks == NULL) {
        TraceError(("%s Failed to allocate VCRTC banks array!\n", __FUNCTION__));
        return FALSE;
    }
    RtlZeroMemory(pXenGfxExtension->ppVCrtcBanks, pXenGfxExtension->VCrtcCount*sizeof(XENGFX_VCRTC*));

    for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) {
        pXenGfxExtension->ppVCrtcBanks[i] = 
            (XENGFX_VCRTC*)ExAllocatePoolWithTag(NonPagedPool, sizeof(XENGFX_VCRTC), XENGFX_TAG);
        if (pXenGfxExtension->ppVCrtcBanks[i] == NULL) {
            TraceWarning(("%s Failed to allocate VCRTC bank at %d!\n", __FUNCTION__, i));
            return FALSE;
        }
        RtlZeroMemory(pXenGfxExtension->ppVCrtcBanks[i], sizeof(XENGFX_VCRTC));

        // Set the register range for this VCRTC bank
        pXenGfxExtension->ppVCrtcBanks[i]->pVCrtcRegs = \
            pXenGfxExtension->pVCrtcsRegs + ((i << 0x10) & 0xF0000);

        // These are the same values for our purposes.
        pXenGfxExtension->ppVCrtcBanks[i]->ChildUid = i;
        pXenGfxExtension->ppVCrtcBanks[i]->VidPnTargetId = i;
        // Calculate the preferred pixel format - this remains the same
        pXenGfxExtension->ppVCrtcBanks[i]->PreferredPixelFormat = 
            XenGfxPreferredVCrtcFormat(pXenGfxExtension->ppVCrtcBanks[i]);        
        // Current mode information
        RtlZeroMemory(&pXenGfxExtension->ppVCrtcBanks[i]->CurrentMode, sizeof(XENGFX_MODE));
        pXenGfxExtension->ppVCrtcBanks[i]->CurrentModeIndex = XENGFX_INVALID_MODE_INDEX;
        // No source is associated at startup
        pXenGfxExtension->ppVCrtcBanks[i]->VidPnSourceId = D3DDDI_ID_UNINITIALIZED;
        // No staging values to start with
        pXenGfxExtension->ppVCrtcBanks[i]->StagedModeIndex = XENGFX_INVALID_MODE_INDEX;
        pXenGfxExtension->ppVCrtcBanks[i]->StagedVidPnSourceId = D3DDDI_ID_UNINITIALIZED;
        pXenGfxExtension->ppVCrtcBanks[i]->StagedFlags = XENGFX_STAGED_FLAG_UNSET;
    }

    return TRUE;
}

VOID
XenGfxFreeVCrtcBanks(XENGFX_DEVICE_EXTENSION *pXenGfxExtension)
{
    ULONG i;
    PAGED_CODE();

    if (pXenGfxExtension->ppVCrtcBanks != NULL) {
        for (i = 0; i < pXenGfxExtension->VCrtcCount; i++)          
            ExFreePoolWithTag(pXenGfxExtension->ppVCrtcBanks[i], XENGFX_TAG);

        ExFreePoolWithTag(pXenGfxExtension->ppVCrtcBanks, XENGFX_TAG);
        pXenGfxExtension->ppVCrtcBanks = NULL;
        pXenGfxExtension->VCrtcCount = 0;
    }
}

static BOOLEAN
XenGfxInitializeVCrtcModes(XENGFX_VCRTC *pVCrtc)
{
    XENGFX_MODE_VALUES ModeValues = {0};
    ULONG ModeCount;

    ModeValues.pEdid           = pVCrtc->pEdid;
    ModeValues.MaxHorizontal   = pVCrtc->MaxHorizontal;
    ModeValues.MaxVertical     = pVCrtc->MaxVertical;
    ModeValues.StrideAlignment = pVCrtc->StrideAlignment;
    ModeValues.XgfxFormat      = pVCrtc->PreferredPixelFormat;
    
    ModeCount = XenGfxCreateModes(&ModeValues);
    if (ModeCount == 0) {
        TraceError(("%s failed in XenGfxCreateModes() call.\n", __FUNCTION__));
        return FALSE;
    }

    // Create a ref counted mode set object
    pVCrtc->pModeSet =
        (XENGFX_MODE_SET*)ExAllocatePoolWithTag(NonPagedPool, sizeof(XENGFX_MODE_SET), XENGFX_TAG);
    if (pVCrtc->pModeSet == NULL) {
        TraceError(("%s failed to allocate mode set.\n", __FUNCTION__));
        XenGfxReleaseModes(ModeValues.pModes);
        return FALSE;
    }

    pVCrtc->pModeSet->ChildUid = pVCrtc->ChildUid;
    pVCrtc->pModeSet->RefCount = 1;
    pVCrtc->pModeSet->ModeCount = ModeCount;
    pVCrtc->pModeSet->pModes = ModeValues.pModes;

    return TRUE;
}

static VOID
XenGfxResetEdidChecksum(XENGFX_VCRTC *pVCrtc)
{
    UCHAR Sum = 0;
    ULONG i;
    UCHAR *pEdidBuf = (UCHAR*)pVCrtc->pEdid;

    pVCrtc->pEdid->Checksum[0] = 0;
    for (i = 0; i < XENGFX_EDID_SIZE; i++)
        Sum += pEdidBuf[i];
    pVCrtc->pEdid->Checksum[0] = -Sum;
}

/* 
 * Verify that Edid is not empty.  If it is, fill in with a fake one.
 */
static void verifyEdid(UCHAR * pEdid)
{
#include "xengfx_edid_1280_1024.c"
    int i;
    
    for (i = 0; i < XENGFX_EDID_SIZE; i++) {
        if (pEdid[i]) return;
    }

    TraceWarning(("%s failed to find valid EDID, using default", __FUNCTION__));
    memcpy(pEdid, xengfx_edid_1280_1024, XENGFX_EDID_SIZE);
}

static BOOLEAN
XenGfxInitializeVCrtcEdid(XENGFX_VCRTC *pVCrtc)
{
    int             notDone;
    int             i;
    PUCHAR          edidOffset = pVCrtc->pVCrtcRegs + XGFX_VCRTC_EDID;
    PULONG          pEdid;
    UCHAR           Sum = 0;
    PUCHAR          pEdidChar;
    PXENGFX_EDID    pEdidStruct;
    
    pVCrtc->pEdid = ExAllocatePoolWithTag(NonPagedPool, 4096, XENGFX_TAG);
    if (pVCrtc->pEdid == NULL) {
        TraceError(("%s out of memory", __FUNCTION__));
        return FALSE;
    }
    pEdid = (PULONG)pVCrtc->pEdid;

    // Request memory
    WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_EDID_REQUEST), 1);

    do {
        notDone = READ_REGISTER_ULONG( (PULONG) (pVCrtc->pVCrtcRegs + XGFX_VCRTC_EDID_REQUEST));
    }while (notDone);

    for (i = 0; i < 4096/sizeof(ULONG); i++) {
        pEdid[i] = READ_REGISTER_ULONG ((PULONG) (edidOffset + (i*sizeof(ULONG))));
    }
    //Fake it for now.
    verifyEdid((PUCHAR)pVCrtc->pEdid);

    //Check the checksum 
    pEdidChar = (PUCHAR)pVCrtc->pEdid;
    for (i= 0; i < XENGFX_EDID_SIZE;i++) {
        Sum += pEdidChar[i];
    }
    if (Sum != 0) {
        TraceWarning(("%s EDID checksum is invalid.\n", __FUNCTION__));
        XenGfxResetEdidChecksum(pVCrtc);
    }

   
    // Calculate the size since there may be extensions.
    pEdidStruct = (XENGFX_EDID*)pVCrtc->pEdid;
    pVCrtc->EdidSize = XENGFX_EDID_SIZE;
    if (pEdidStruct->ExtensionFlag[0] > 0)
        pVCrtc->EdidSize += XENGFX_EDID_SIZE*(pEdidStruct->ExtensionFlag[0]);

    ASSERT(pVCrtc->EdidSize <= PAGE_SIZE);

    // NOTE XGFX will always return a valid EDID for any VCRTC. If the device is not plugged
    // or has no EDID, a platform default will be provided.

    return TRUE;
}

static VOID
XenGfxCleanupVCrtc(XENGFX_DEVICE_EXTENSION *pXenGfxExtension, XENGFX_VCRTC *pVCrtc)
{
    // Cleanup EDID and Modes - must be called with vCRTC lock
    if (pVCrtc->pEdid != NULL) {
        ExFreePoolWithTag(pVCrtc->pEdid, XENGFX_TAG);
        pVCrtc->pEdid = NULL;
        pVCrtc->EdidPageBase.QuadPart = 0;
        pVCrtc->EdidSize = 0;
    }

    if (pVCrtc->pModeSet != NULL) {
        ASSERT(pVCrtc->pModeSet->pModes != NULL);
        ASSERT(pVCrtc->pModeSet->RefCount > 0);
        if (--pVCrtc->pModeSet->RefCount == 0) {
            XenGfxReleaseModes(pVCrtc->pModeSet->pModes);
            ExFreePoolWithTag(pVCrtc->pModeSet, XENGFX_TAG);
        }

        // Drop any reference to the set
        pVCrtc->pModeSet = NULL;
    }
}

static BOOLEAN
XenGfxReconfigureConnectedVCrtc(XENGFX_DEVICE_EXTENSION *pXenGfxExtension,
                                XENGFX_VCRTC *pVCrtc)
{
    DXGK_CHILD_STATUS ChildStatus;
    BOOLEAN r = FALSE;

    // Sanity
    ASSERT(pVCrtc->pModeSet == NULL);
    ASSERT(pVCrtc->pEdid == NULL);

    do {
        // First, cleanup the current VCRTC state
        XenGfxCleanupVCrtc(pXenGfxExtension, pVCrtc);

        // Get an EDID for this VCRTC
        if (!XenGfxInitializeVCrtcEdid(pVCrtc))
            break;

        // Now some modes
        if (!XenGfxInitializeVCrtcModes(pVCrtc))
            break;

        // Got here, success - set connected and indicate the change to the child status.
        InterlockedExchange(&pVCrtc->Connected, XENV4V_CONNECTED);

        // Indicate the child device state changed and the external device was disconnected.
        ChildStatus.ChildUid = pVCrtc->ChildUid;
        ChildStatus.Type = StatusConnection;
        ChildStatus.HotPlug.Connected = TRUE;

        // A PDO will be created for connected devices.
        pXenGfxExtension->DxgkInterface.DxgkCbIndicateChildStatus(pXenGfxExtension->hDxgkHandle, &ChildStatus);

        r = TRUE;
    } while (FALSE);

    if (!r)
        XenGfxCleanupVCrtc(pXenGfxExtension, pVCrtc);

    return r;
}

static BOOLEAN
XenGfxReconfigureDisconnectedVCrtc(XENGFX_DEVICE_EXTENSION *pXenGfxExtension,
                                   XENGFX_VCRTC *pVCrtc)
{
    DXGK_CHILD_STATUS ChildStatus;

    // Cleanup the VCRTC
    XenGfxCleanupVCrtc(pXenGfxExtension, pVCrtc);

    // Disconnected state
    InterlockedExchange(&pVCrtc->Connected, XENV4V_DISCONNECTED);

    // Indicate the child device state changed and the external device was disconnected.
    ChildStatus.ChildUid = pVCrtc->ChildUid;
    ChildStatus.Type = StatusConnection;
    ChildStatus.HotPlug.Connected = FALSE;

    pXenGfxExtension->DxgkInterface.DxgkCbIndicateChildStatus(pXenGfxExtension->hDxgkHandle, &ChildStatus);

    return TRUE;
}

VOID
XenGfxDetectChildStatusChanges(XENGFX_DEVICE_EXTENSION *pXenGfxExtension)
{
    XENGFX_VCRTC *pVCrtc;
    KIRQL Irql;
    ULONG i;
    ULONG StatusReg;

    if (InterlockedExchangeAdd(&pXenGfxExtension->Initialized, 0) == 0)
        return; // stopping or stopped device... 

    // This is the main spot where the VCRTC state can change so it has to be locked.
    KeAcquireSpinLock(&pXenGfxExtension->VCrtcLock, &Irql);

    for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) {
        pVCrtc = pXenGfxExtension->ppVCrtcBanks[i];

        StatusReg = READ_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_STATUS));
        if (((StatusReg & XGFX_VCRTC_STATUS_HOTPLUG) && (XenGfxMonitorConnected(pVCrtc))) ||
           (((StatusReg & XGFX_VCRTC_STATUS_HOTPLUG) == 0) && (!XenGfxMonitorConnected(pVCrtc)))) {
            continue;
        }

        // State did change, process the reconfigure action
        if (StatusReg & XGFX_VCRTC_STATUS_HOTPLUG) {
            if (!XenGfxReconfigureConnectedVCrtc(pXenGfxExtension, pVCrtc))
                TraceError(("%s XenGfxReconfigureConnectedVCrtc() failed for VCTRC bank %d!\n", __FUNCTION__, i));
        }
        else {
            if (!XenGfxReconfigureDisconnectedVCrtc(pXenGfxExtension, pVCrtc))
                TraceError(("%s XenGfxReconfigureDisconnectedVCrtc() failed for VCTRC bank %d!\n", __FUNCTION__, i));
        }
    }

    KeReleaseSpinLock(&pXenGfxExtension->VCrtcLock, Irql);
}

BOOLEAN
XenGfxEnableVCrtcs(XENGFX_DEVICE_EXTENSION *pXenGfxExtension)
{
    XENGFX_VCRTC *pVCrtc;
    ULONG i, Max;
    BOOLEAN r = TRUE;
    PAGED_CODE();

    // T & S Level 3
    // Only called during startup, read max resolution and stride values, cursor values
    // for all active VCRTCs
    pXenGfxExtension->MaxStrideAlignment = 0;

    for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) {
        pVCrtc = pXenGfxExtension->ppVCrtcBanks[i];

        pVCrtc->MaxHorizontal = READ_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_MAX_HORIZONTAL));
        pVCrtc->MaxVertical = READ_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_MAX_VERTICAL));
        pVCrtc->MaxHorizontal++;
        pVCrtc->MaxVertical++;
        pVCrtc->StrideAlignment = READ_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_STRIDE_ALIGNMENT));
        if (READ_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_CURSOR_STATUS)) & XGFX_VCRTC_CURSOR_STATUS_SUPPORTED) {
            pVCrtc->CursorSupported = TRUE;
            Max = READ_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_CURSOR_MAXSIZE));
            pVCrtc->MaxCursorHeight = (Max & 0x000FFFF);
            pVCrtc->MaxCursorWidth = ((Max >> 16) & 0x000FFFF);
        }
        else {
            pVCrtc->CursorSupported = FALSE;
            pVCrtc->MaxCursorHeight = 0;
            pVCrtc->MaxCursorWidth = 0;
        }

        // Sanity check to see if these are valid values.
        if (pVCrtc->StrideAlignment > XENGFX_MAX_STRIDE_ALIGNMENT) {
            TraceError(("%s Alignment requirement beyond 4M not supported - stride alignment: %d (0x%x)\n", __FUNCTION__,
                       pVCrtc->StrideAlignment, pVCrtc->StrideAlignment));
            r = FALSE;
            break;
        }

        if ((pVCrtc->MaxCursorHeight > XENGFX_MAX_CURSOR_DIMENSION)||
            (pVCrtc->MaxCursorWidth > XENGFX_MAX_CURSOR_DIMENSION)) {
            // How big of a cursor do you want?
            TraceError(("%s Cursor height/width - height: %d (0x%x) width: %d (0x%x)\n", __FUNCTION__,
                       pVCrtc->MaxCursorHeight, pVCrtc->MaxCursorHeight,
                       pVCrtc->MaxCursorWidth, pVCrtc->MaxCursorWidth));
            r = FALSE;
            break;
        }

        // Enable Hotplug and retrace interrupts on this VCRTC
        WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_STATUS_INT),
                             (XGFX_VCRTC_STATUS_INT_HOTPLUG_EN|XGFX_VCRTC_STATUS_INT_RETRACE_EN));


        pXenGfxExtension->MaxStrideAlignment = \
            XENGFX_MAX(pXenGfxExtension->MaxStrideAlignment, pVCrtc->StrideAlignment);
    }

    return r;
}

VOID
XenGfxDisableVCrtcs(XENGFX_DEVICE_EXTENSION *pXenGfxExtension)
{
    XENGFX_VCRTC *pVCrtc;
    KIRQL Irql;
    ULONG i;

    // T & S Level 3
    // Only called during startup and shutdown, do a general cleanup of each active VCTRC.
    for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) {
        pVCrtc = pXenGfxExtension->ppVCrtcBanks[i];

        // Have to lock when accessing the mode set
        KeAcquireSpinLock(&pXenGfxExtension->VCrtcLock, &Irql);
        XenGfxCleanupVCrtc(pXenGfxExtension, pVCrtc);
        KeReleaseSpinLock(&pXenGfxExtension->VCrtcLock, Irql);

        // Clear value for connected
        InterlockedExchange(&pVCrtc->Connected, XENV4V_DISCONNECTED);
        
        // Disable interrupts
        WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_STATUS_INT), 0);

        // Reset VCRTC values
        pVCrtc->MaxHorizontal = 0;
        pVCrtc->MaxVertical = 0;
        pVCrtc->StrideAlignment = 0;
        pVCrtc->CursorSupported = FALSE;
        pVCrtc->MaxCursorHeight = 0;
        pVCrtc->MaxCursorWidth = 0;       
    }

    pXenGfxExtension->MaxStrideAlignment = 0;
}

VOID
XenGfxSetPrimaryForVCrtc(XENGFX_DEVICE_EXTENSION *pXenGfxExtension, XENGFX_VCRTC *pVCrtc)
{
    ULONG ControlReg;
    PHYSICAL_ADDRESS baseAddress = {0};

    // T & S Level 2
    if (!XenGfxMonitorConnected(pVCrtc)) {
        TraceError(("%s vCRTC=%p no monitor present??\n", __FUNCTION__, pVCrtc));
        return;
    }

    // This should only be called when the mode and source address values are in place.
    // Saved current mode can be accessed outside of the lock as with all the HW registers here
    // whose use is synchronized at T & S Level 2

    // Enable rastering for this VCRTC
    ControlReg = READ_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_CONTROL));
    WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_CONTROL),
                         (ControlReg|XGFX_VCRTC_CONTROL_ENABLE));

    // Setup mode values, use fallback value for format.
    WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_FORMAT), pVCrtc->CurrentMode.XgfxFormat);
    WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_HORIZONTAL_ACTIVE), pVCrtc->CurrentMode.XResolution - 1);
    WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_VERTICAL_ACTIVE), pVCrtc->CurrentMode.YResolution - 1);
    WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_STRIDE), pVCrtc->CurrentMode.ScreenStride);

    // Commit by writing the frame buffer offset in XGFX_VCRTCn_BASE.
    // QAD Set base address to back buffer
    baseAddress.QuadPart = pVCrtc->PrimaryAddress.QuadPart;
    pVCrtc->primary = TRUE;

    WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_BASE), (ULONG)baseAddress.QuadPart);
    //WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_LINEOFFSET), (ULONG)baseAddress.QuadPart);

    TraceVerbose(("%s vCRTC=%p Set Mode: %d\n", __FUNCTION__, pVCrtc, pVCrtc->CurrentModeIndex));
}

VOID
XenGfxClearPrimaryForVCrtc(XENGFX_DEVICE_EXTENSION *pXenGfxExtension, XENGFX_VCRTC *pVCrtc)
{
    ULONG ControlReg;

    // T & S Level 2

    // Disable rastering for this VCRTC
    ControlReg = READ_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_CONTROL));
    ControlReg &= ~(XGFX_VCRTC_CONTROL_ENABLE);
    WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_CONTROL), ControlReg);

    // Commit by writting the frame buffer offset in XGFX_VCRTCn_BASE.
    WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_BASE), 0);
}

XENGFX_MODE_SET*
XenGfxGetModeSet(XENGFX_DEVICE_EXTENSION *pXenGfxExtension, ULONG ChildUid)
{
    KIRQL Irql;    
    XENGFX_VCRTC *pVCrtc;
    XENGFX_MODE_SET *pModeSet = NULL;

    if (ChildUid >= pXenGfxExtension->VCrtcCount)
        return NULL;

    KeAcquireSpinLock(&pXenGfxExtension->VCrtcLock, &Irql);
    
    pVCrtc = pXenGfxExtension->ppVCrtcBanks[ChildUid];
    if (XenGfxMonitorConnected(pVCrtc)) {
        ASSERT(pVCrtc->pModeSet != NULL);
        pVCrtc->pModeSet->RefCount++;
        pModeSet = pVCrtc->pModeSet;
    }

    KeReleaseSpinLock(&pXenGfxExtension->VCrtcLock, Irql);
    pVCrtc->primary = FALSE;
    return pModeSet;
}

VOID
XenGfxPutModeSet(XENGFX_DEVICE_EXTENSION *pXenGfxExtension, XENGFX_MODE_SET* pModeSet)
{
    KIRQL Irql;
    ULONG i;

    if (!ARGUMENT_PRESENT(pModeSet))
        return;

    KeAcquireSpinLock(&pXenGfxExtension->VCrtcLock, &Irql);

    ASSERT(pModeSet->RefCount > 0);
    if (--pModeSet->RefCount == 0) {
        XenGfxReleaseModes(pModeSet->pModes);
        ExFreePoolWithTag(pModeSet, XENGFX_TAG);
    }

    KeReleaseSpinLock(&pXenGfxExtension->VCrtcLock, Irql);
}

void
XenGfxChildStatusChangeDpc(KDPC *pDpc,
                           VOID *pDeferredContext,
                           VOID *pSystemArgument1,
                           VOID *pSystemArgument2)
{
    UNREFERENCED_PARAMETER(pDpc);
    UNREFERENCED_PARAMETER(pSystemArgument1);
    UNREFERENCED_PARAMETER(pSystemArgument2);

    // See if any child statuses have changed - monitors hot plugged/unplugged.
    XenGfxDetectChildStatusChanges((XENGFX_DEVICE_EXTENSION*)pDeferredContext);
}
