//
// vidpn.c - Xen Windows PV WDDM Miniport Driver Video Present Network routines.
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

typedef struct _XENGFX_SOURCE_MAP_ENTRY {
    D3DDDI_VIDEO_PRESENT_SOURCE_ID VidPnSourceId;
    D3DKMDT_GRAPHICS_RENDERING_FORMAT GraphicsFormat;
    BOOLEAN FormatSet;
} XENGFX_SOURCE_MAP_ENTRY, *PXENGFX_SOURCE_MAP_ENTRY;

typedef struct _XENGFX_PINNED_MODES {
    BOOLEAN SourcePinned;
    D3DKMDT_2DREGION SourcePrimSurfSize;
    BOOLEAN TargetPinned;
    D3DKMDT_2DREGION TargetActiveSize;
} XENGFX_PINNED_MODES, *PXENGFX_PINNED_MODES;

typedef enum _XENGFX_PINNED_STATE {
    XENGFX_PS_UNPINNED = 0,
    XENGFX_PS_PINNED   = 1,
    XENGFX_PS_ERROR    = 2
} XENGFX_PINNED_STATE;

static __inline XENGFX_PINNED_STATE
XenGfxPinnedModeState(NTSTATUS Status, VOID *pAcquiredMode)
{
    if (Status == STATUS_SUCCESS)
        return (pAcquiredMode != NULL) ? XENGFX_PS_PINNED : XENGFX_PS_UNPINNED;
    else if (!NT_SUCCESS(Status))
        return XENGFX_PS_ERROR;
    else /* Status == STATUS_GRAPHICS_MODE_NOT_PINNED) */
        return XENGFX_PS_UNPINNED;
}

static BOOLEAN
XenGfxIsSupportedSourceMode(XENGFX_VCRTC *pVCrtc, D3DKMDT_VIDPN_SOURCE_MODE *pVidPnSourceModeInfo);

static BOOLEAN
XenGfxIsSupportedTargetMode(XENGFX_VCRTC *pVCrtc, D3DKMDT_VIDPN_TARGET_MODE *pVidPnTargetModeInfo);

static BOOLEAN
XenGfxIsSupportedSourceModeSet(XENGFX_VCRTC *pVCrtc,
                               D3DKMDT_HVIDPNSOURCEMODESET hVidPnSourceModeSet,
                               CONST DXGK_VIDPNSOURCEMODESET_INTERFACE *pVidPnSourceModeSetInterface,
                               XENGFX_PINNED_MODES *pPinnedModes);

static BOOLEAN
XenGfxIsSupportedTargetModeSet(XENGFX_VCRTC *pVCrtc,
                               D3DKMDT_HVIDPNTARGETMODESET hVidPnTargetModeSet,
                               CONST DXGK_VIDPNTARGETMODESET_INTERFACE *pVidPnTargetModeSetInterface,
                               XENGFX_PINNED_MODES *pPinnedModes);

static NTSTATUS
XenGfxAddTargetMode(D3DKMDT_HVIDPNTARGETMODESET hVidPnTargetModeSet,
                    CONST DXGK_VIDPNTARGETMODESET_INTERFACE *pVidPnTargetModeSetInterface,
                    XENGFX_MODE *pMode);

static NTSTATUS
XenGfxAddSourceMode(D3DKMDT_HVIDPNSOURCEMODESET hVidPnSourceModeSet,
                    CONST DXGK_VIDPNSOURCEMODESET_INTERFACE *pVidPnSourceModeSetInterface,
                    XENGFX_MODE *pMode);

static NTSTATUS
XenGfxUpdateTargetModeSet(XENGFX_VCRTC *pVCrtc,
                          XENGFX_MODE_SET *pModeSet,
                          CONST D3DKMDT_HVIDPN hConstrainingVidPn,
                          DXGK_VIDPN_INTERFACE *pVidPnInterface,                          
                          D3DKMDT_VIDPN_PRESENT_PATH *pCurrVidPnPresentPathInfo);

static NTSTATUS
XenGfxUpdateSourceModeSet(XENGFX_VCRTC *pVCrtc,
                          XENGFX_MODE_SET *pModeSet,
                          CONST D3DKMDT_HVIDPN hConstrainingVidPn,
                          DXGK_VIDPN_INTERFACE *pVidPnInterface,                          
                          D3DKMDT_VIDPN_PRESENT_PATH *pCurrVidPnPresentPathInfo);

static BOOLEAN
XenGfxCompareMonitorModes(XENGFX_MODE *pMode,
                          D3DKMDT_HMONITORSOURCEMODESET hMonitorSourceModeSet,
                          CONST DXGK_MONITORSOURCEMODESET_INTERFACE *pMonitorSourceModeSetInterface);

static VOID
XenGfxInitMonitorSourceMode(D3DKMDT_MONITOR_SOURCE_MODE *pVidPnMonitorSourceModeInfo,
                            XENGFX_MODE *pMode);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE,XenGfxIsSupportedVidPn)
#pragma alloc_text(PAGE,XenGfxRecommendFunctionalVidPn)
#pragma alloc_text(PAGE,XenGfxEnumVidPnCofuncModality)
#pragma alloc_text(PAGE,XenGfxSetVidPnSourceAddress)
#pragma alloc_text(PAGE,XenGfxSetVidPnSourceVisibility)
#pragma alloc_text(PAGE,XenGfxUpdateActiveVidPnPresentPath)
#pragma alloc_text(PAGE,XenGfxRecommendMonitorModes)
#pragma alloc_text(PAGE,XenGfxRecommendVidPnTopology)
#pragma alloc_text(PAGE,XenGfxIsSupportedSourceMode)
#pragma alloc_text(PAGE,XenGfxIsSupportedTargetMode)
#pragma alloc_text(PAGE,XenGfxIsSupportedSourceModeSet)
#pragma alloc_text(PAGE,XenGfxIsSupportedTargetModeSet)
#pragma alloc_text(PAGE,XenGfxAddTargetMode)
#pragma alloc_text(PAGE,XenGfxAddSourceMode)
#pragma alloc_text(PAGE,XenGfxUpdateTargetModeSet)
#pragma alloc_text(PAGE,XenGfxUpdateSourceModeSet)
#pragma alloc_text(PAGE,XenGfxCompareMonitorModes)
#pragma alloc_text(PAGE,XenGfxInitMonitorSourceMode)
#endif

static BOOLEAN
XenGfxIsSupportedPath(D3DKMDT_VIDPN_PRESENT_PATH *pCurrVidPnPresentPathInfo)
{
    // Bare minimum support to start with. OK with any of the uncommited states for transformations.
    if ((pCurrVidPnPresentPathInfo->ContentTransformation.Scaling != D3DKMDT_VPPS_UNINITIALIZED)&&
        (pCurrVidPnPresentPathInfo->ContentTransformation.Scaling != D3DKMDT_VPPS_IDENTITY)&&
        (pCurrVidPnPresentPathInfo->ContentTransformation.Scaling != D3DKMDT_VPPS_UNPINNED)&&
        (pCurrVidPnPresentPathInfo->ContentTransformation.Scaling != D3DKMDT_VPPS_NOTSPECIFIED)) {
        TraceVerbose(("%s unsupported Scaling value: %d\n", __FUNCTION__, pCurrVidPnPresentPathInfo->ContentTransformation.Scaling));
        return FALSE;
    }

    if ((pCurrVidPnPresentPathInfo->ContentTransformation.ScalingSupport.Centered != 0)||
        (pCurrVidPnPresentPathInfo->ContentTransformation.ScalingSupport.Stretched != 0)) {
        /*(pCurrVidPnPresentPathInfo->ContentTransformation.ScalingSupport.AspectRatioCenteredMax != 0)*/
        /*(pCurrVidPnPresentPathInfo->ContentTransformation.ScalingSupport.Custom != 0)*/
        TraceVerbose(("%s unsupported ScalingSupport value: %d\n", __FUNCTION__, pCurrVidPnPresentPathInfo->ContentTransformation.ScalingSupport));
        return FALSE;
    }

    if ((pCurrVidPnPresentPathInfo->ContentTransformation.Rotation != D3DKMDT_VPPR_UNINITIALIZED)&&
        (pCurrVidPnPresentPathInfo->ContentTransformation.Rotation != D3DKMDT_VPPR_IDENTITY)&&
        (pCurrVidPnPresentPathInfo->ContentTransformation.Rotation != D3DKMDT_VPPR_UNPINNED)&&
        (pCurrVidPnPresentPathInfo->ContentTransformation.Rotation != D3DKMDT_VPPR_NOTSPECIFIED)) {
        TraceVerbose(("%s unsupported Rotation value: %d\n", __FUNCTION__, pCurrVidPnPresentPathInfo->ContentTransformation.Rotation));
        return FALSE;
    }

    if ((pCurrVidPnPresentPathInfo->ContentTransformation.RotationSupport.Rotate90 != 0)||
        (pCurrVidPnPresentPathInfo->ContentTransformation.RotationSupport.Rotate180 != 0)||
        (pCurrVidPnPresentPathInfo->ContentTransformation.RotationSupport.Rotate270 != 0)) {
        TraceVerbose(("%s unsupported RotationSupport value: %d\n", __FUNCTION__, pCurrVidPnPresentPathInfo->ContentTransformation.RotationSupport));
        return FALSE;
    }

    if ((pCurrVidPnPresentPathInfo->VisibleFromActiveTLOffset.cx != 0)||
        (pCurrVidPnPresentPathInfo->VisibleFromActiveTLOffset.cy != 0)||
        (pCurrVidPnPresentPathInfo->VisibleFromActiveBROffset.cx != 0)||
        (pCurrVidPnPresentPathInfo->VisibleFromActiveBROffset.cy != 0)) {
        TraceVerbose(("%s TL/BR offsets not supported.\n", __FUNCTION__));
        return FALSE;
    }

    if ((pCurrVidPnPresentPathInfo->VidPnTargetColorBasis != D3DKMDT_CB_SRGB)&&
        (pCurrVidPnPresentPathInfo->VidPnTargetColorBasis != D3DKMDT_CB_UNINITIALIZED)) {
        TraceVerbose(("%s unsupported ColorBasis: %d.\n", __FUNCTION__, pCurrVidPnPresentPathInfo->VidPnTargetColorBasis));
        return FALSE;
    }

    if ((pCurrVidPnPresentPathInfo->Content != D3DKMDT_VPPC_UNINITIALIZED)&&
        (pCurrVidPnPresentPathInfo->Content != D3DKMDT_VPPC_GRAPHICS)&&
        (pCurrVidPnPresentPathInfo->Content != D3DKMDT_VPPC_NOTSPECIFIED)) {
        TraceVerbose(("%s unsupported Content: %d.\n", __FUNCTION__));
        return FALSE;
    }

    if ((pCurrVidPnPresentPathInfo->CopyProtection.CopyProtectionType != D3DKMDT_VPPMT_NOPROTECTION)&&
        (pCurrVidPnPresentPathInfo->CopyProtection.CopyProtectionType != D3DKMDT_VPPMT_UNINITIALIZED)) {
        TraceVerbose(("%s CopyProtection not supported.\n", __FUNCTION__));
        return FALSE;
    }    

    if ((pCurrVidPnPresentPathInfo->GammaRamp.Type != D3DDDI_GAMMARAMP_DEFAULT)&&
        (pCurrVidPnPresentPathInfo->GammaRamp.Type != D3DDDI_GAMMARAMP_UNINITIALIZED)) {
        TraceVerbose(("%s non-default gamma ramp not supported.\n", __FUNCTION__));
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
XenGfxIsSupportedSourceMode(XENGFX_VCRTC *pVCrtc, D3DKMDT_VIDPN_SOURCE_MODE *pVidPnSourceModeInfo)
{
    PAGED_CODE();
    // Only supporting graphics type for now.
    if (pVidPnSourceModeInfo->Type != D3DKMDT_RMT_GRAPHICS) {
        TraceVerbose(("%s unsupported mode type: %d\n", __FUNCTION__, pVidPnSourceModeInfo->Type));
        return FALSE;
    }

    // Check the visible and primary surfaces match
    if (!XenGfxCompare2DRegion(pVidPnSourceModeInfo->Format.Graphics.VisibleRegionSize,
                               pVidPnSourceModeInfo->Format.Graphics.PrimSurfSize)) {
        TraceVerbose(("%s visible and primary surface size mismatch.\n", __FUNCTION__));
        return FALSE;
    }

    // Will the CRTC for this source along this path handles the resolution.
    if ((pVidPnSourceModeInfo->Format.Graphics.PrimSurfSize.cx > pVCrtc->MaxHorizontal)||
        (pVidPnSourceModeInfo->Format.Graphics.PrimSurfSize.cy > pVCrtc->MaxVertical)) {
        TraceVerbose(("%s source mode resolution too large for vCRTC.\n", __FUNCTION__));
        return FALSE;
    }

    if ((pVidPnSourceModeInfo->Format.Graphics.ColorBasis != D3DKMDT_CB_SRGB)&&
        (pVidPnSourceModeInfo->Format.Graphics.ColorBasis != D3DKMDT_CB_UNINITIALIZED)) {
        TraceVerbose(("%s unsupported color basis: %d.\n", __FUNCTION__, pVidPnSourceModeInfo->Format.Graphics.ColorBasis));
        return FALSE;
    }

    if (XenGfxXgfxFormatFromDdiFormat(pVidPnSourceModeInfo->Format.Graphics.PixelFormat) == XGFX_VCRTC_VALID_FORMAT_NONE) {
        TraceVerbose(("%s unsupported pixel format: %d.\n", __FUNCTION__, pVidPnSourceModeInfo->Format.Graphics.PixelFormat));
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
XenGfxIsSupportedTargetMode(XENGFX_VCRTC *pVCrtc, D3DKMDT_VIDPN_TARGET_MODE *pVidPnTargetModeInfo)
{
    D3DKMDT_VIDEO_SIGNAL_INFO *pVideoSignalInfo;
    PAGED_CODE();

    pVideoSignalInfo = &pVidPnTargetModeInfo->VideoSignalInfo;

    // Will the CRTC for this target handles the resolution.
    if ((pVideoSignalInfo->ActiveSize.cx > pVCrtc->MaxHorizontal)||
        (pVideoSignalInfo->ActiveSize.cy > pVCrtc->MaxVertical)) {
        TraceVerbose(("%s target mode resolution to large for vCRTC.\n", __FUNCTION__));
        return FALSE;
    }

    // Expected values without resolution values being present.
    if ((pVideoSignalInfo->VideoStandard != D3DKMDT_VSS_OTHER)||
        (pVideoSignalInfo->TotalSize.cx != D3DKMDT_DIMENSION_NOTSPECIFIED)||
        (pVideoSignalInfo->TotalSize.cy != D3DKMDT_DIMENSION_NOTSPECIFIED)||
        (pVideoSignalInfo->VSyncFreq.Numerator != XENGFX_DEFAULT_VSYNC * 1000)||
        (pVideoSignalInfo->VSyncFreq.Denominator != 1000)||
        (pVideoSignalInfo->HSyncFreq.Denominator != 1000)||
        (pVideoSignalInfo->ScanLineOrdering != D3DDDI_VSSLO_PROGRESSIVE)) {
        TraceVerbose(("%s unsupported target mode value(s).\n", __FUNCTION__));
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN
XenGfxIsSupportedSourceModeSet(XENGFX_VCRTC *pVCrtc,
                               D3DKMDT_HVIDPNSOURCEMODESET hVidPnSourceModeSet,
                               CONST DXGK_VIDPNSOURCEMODESET_INTERFACE *pVidPnSourceModeSetInterface,
                               XENGFX_PINNED_MODES *pPinnedModes)
{
    D3DKMDT_VIDPN_SOURCE_MODE *pCurrVidPnSourceModeInfo = NULL;
    D3DKMDT_VIDPN_SOURCE_MODE *pNextVidPnSourceModeInfo;
    XENGFX_PINNED_STATE PinnedState;
    NTSTATUS Status;
    BOOLEAN r;
    PAGED_CODE();

    // If there is a pinned, mode validate only this mode.
    Status = pVidPnSourceModeSetInterface->pfnAcquirePinnedModeInfo(hVidPnSourceModeSet, &pCurrVidPnSourceModeInfo);
    PinnedState = XenGfxPinnedModeState(Status, pCurrVidPnSourceModeInfo);
    if (PinnedState == XENGFX_PS_PINNED) {
        r = XenGfxIsSupportedSourceMode(pVCrtc, pCurrVidPnSourceModeInfo);
        if (r) {
            pPinnedModes->SourcePinned = TRUE;
            pPinnedModes->SourcePrimSurfSize = pCurrVidPnSourceModeInfo->Format.Graphics.PrimSurfSize;
        }
        pVidPnSourceModeSetInterface->pfnReleaseModeInfo(hVidPnSourceModeSet, pCurrVidPnSourceModeInfo);        
        return r;
    }
    else if (PinnedState == XENGFX_PS_ERROR) {
        TraceError(("%s pfnAcquirePinnedModeInfo failed: 0x%x\n", __FUNCTION__, Status));
        return FALSE; // bad handles - probably low memory
    }

    Status = pVidPnSourceModeSetInterface->pfnAcquireFirstModeInfo(hVidPnSourceModeSet, &pCurrVidPnSourceModeInfo);
    if (Status == STATUS_GRAPHICS_DATASET_IS_EMPTY) {
        // Empty set, that is OK
        return TRUE;
    }
    else if (!NT_SUCCESS(Status)) {
        TraceError(("%s pfnAcquireFirstModeInfo failed: 0x%x\n", __FUNCTION__, Status));
        return FALSE; // bad handles - probably low memory       
    }

    while (TRUE) {
        // Test the unpinned modes, only need to find one that will potentially work to
        // report this is supported.
        if (XenGfxIsSupportedSourceMode(pVCrtc, pCurrVidPnSourceModeInfo)) {
            pVidPnSourceModeSetInterface->pfnReleaseModeInfo(hVidPnSourceModeSet, pCurrVidPnSourceModeInfo);
            return TRUE;
        }

        Status = pVidPnSourceModeSetInterface->pfnAcquireNextModeInfo(hVidPnSourceModeSet, pCurrVidPnSourceModeInfo, &pNextVidPnSourceModeInfo);
        // Done with the last path.
        pVidPnSourceModeSetInterface->pfnReleaseModeInfo(hVidPnSourceModeSet, pCurrVidPnSourceModeInfo);

        if (Status == STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET) {
            return FALSE; // done enumerating, did not find any that can be implemented.
        }
        else if (!NT_SUCCESS(Status)) {
            TraceError(("%s pfnAcquireNextModeInfo failed: 0x%x\n", __FUNCTION__, Status));
            return FALSE;
        }
        pCurrVidPnSourceModeInfo = pNextVidPnSourceModeInfo;
    }

    // Nothing supported found.
    return FALSE;
}

static BOOLEAN
XenGfxIsSupportedTargetModeSet(XENGFX_VCRTC *pVCrtc,
                               D3DKMDT_HVIDPNTARGETMODESET hVidPnTargetModeSet,
                               CONST DXGK_VIDPNTARGETMODESET_INTERFACE *pVidPnTargetModeSetInterface,
                               XENGFX_PINNED_MODES *pPinnedModes)
{ 
    D3DKMDT_VIDPN_TARGET_MODE *pCurrVidPnTargetModeInfo;
    D3DKMDT_VIDPN_TARGET_MODE *pNextVidPnTargetModeInfo;
    XENGFX_PINNED_STATE PinnedState;
    NTSTATUS Status;
    BOOLEAN r;
    PAGED_CODE();   

    // If there is a pinned, mode validate only this mode.
    Status = pVidPnTargetModeSetInterface->pfnAcquirePinnedModeInfo(hVidPnTargetModeSet, &pCurrVidPnTargetModeInfo);
    PinnedState = XenGfxPinnedModeState(Status, pCurrVidPnTargetModeInfo);
    if (PinnedState == XENGFX_PS_PINNED) {
        r = XenGfxIsSupportedTargetMode(pVCrtc, pCurrVidPnTargetModeInfo);
        if (r) {
            pPinnedModes->TargetPinned = TRUE;
            pPinnedModes->TargetActiveSize = pCurrVidPnTargetModeInfo->VideoSignalInfo.ActiveSize;
        }
        pVidPnTargetModeSetInterface->pfnReleaseModeInfo(hVidPnTargetModeSet, pCurrVidPnTargetModeInfo);
        return r;
    }
    else if (PinnedState == XENGFX_PS_ERROR) {
        TraceError(("%s pfnAcquirePinnedModeInfo failed: 0x%x\n", __FUNCTION__, Status));
        return FALSE; // bad handles - probably low memory
    }

    Status = pVidPnTargetModeSetInterface->pfnAcquireFirstModeInfo(hVidPnTargetModeSet, &pCurrVidPnTargetModeInfo);
    if (Status == STATUS_GRAPHICS_DATASET_IS_EMPTY) {
        // Empty set, that is OK
        return TRUE;
    }
    else if (!NT_SUCCESS(Status)) {
        TraceError(("%s pfnAcquireFirstModeInfo failed: 0x%x\n", __FUNCTION__, Status));
        return FALSE; // bad handles - probably low memory       
    }

    while (TRUE) {
        // Test the unpinned modes, only need to find one that will potentially work to
        // report this is supported.
        if (XenGfxIsSupportedTargetMode(pVCrtc, pCurrVidPnTargetModeInfo)) {
            pVidPnTargetModeSetInterface->pfnReleaseModeInfo(hVidPnTargetModeSet, pCurrVidPnTargetModeInfo);
            return TRUE;
        }

        Status = pVidPnTargetModeSetInterface->pfnAcquireNextModeInfo(hVidPnTargetModeSet, pCurrVidPnTargetModeInfo, &pNextVidPnTargetModeInfo);
        // Done with the last path.
        pVidPnTargetModeSetInterface->pfnReleaseModeInfo(hVidPnTargetModeSet, pCurrVidPnTargetModeInfo);

        if (Status == STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET) {
            return FALSE; // done enumerating, did not find any that can be implemented.
        }
        else if (!NT_SUCCESS(Status)) {
            TraceError(("%s pfnAcquireNextModeInfo failed: 0x%x\n", __FUNCTION__, Status));
            return FALSE;
        }
        pCurrVidPnTargetModeInfo = pNextVidPnTargetModeInfo;
    }

    // Nothing supported found.
    return FALSE;
}

static NTSTATUS
XenGfxAddTargetMode(D3DKMDT_HVIDPNTARGETMODESET hVidPnTargetModeSet,
                    CONST DXGK_VIDPNTARGETMODESET_INTERFACE *pVidPnTargetModeSetInterface,
                    XENGFX_MODE *pMode)
{
    D3DKMDT_VIDPN_TARGET_MODE *pVidPnTargetMode;
    D3DKMDT_VIDEO_SIGNAL_INFO *pVideoSignalInfo;
    NTSTATUS Status;
    PAGED_CODE();

    Status = pVidPnTargetModeSetInterface->pfnCreateNewModeInfo(hVidPnTargetModeSet,
                                                                &pVidPnTargetMode);
    if (!NT_SUCCESS(Status)) {
        TraceError(("%s pfnCreateNewModeInfo failed: 0x%x\n", __FUNCTION__, Status));
        return Status; // low memory.
    }

    // Let OS assign the ID, set the preferred mode field.
    if (pMode->Flags & XENGFX_MODE_FLAG_EDID_MODE)
        pVidPnTargetMode->Preference = D3DKMDT_MP_PREFERRED;
    else
        pVidPnTargetMode->Preference = D3DKMDT_MP_NOTPREFERRED;

    // Init signal information (much like what is done for setting up a monitor mode).
    pVideoSignalInfo = &pVidPnTargetMode->VideoSignalInfo;
    pVideoSignalInfo->VideoStandard = D3DKMDT_VSS_OTHER;
    pVideoSignalInfo->TotalSize.cx = D3DKMDT_DIMENSION_NOTSPECIFIED;
    pVideoSignalInfo->TotalSize.cy = D3DKMDT_DIMENSION_NOTSPECIFIED;
    pVideoSignalInfo->ActiveSize.cx = pMode->XResolution;
    pVideoSignalInfo->ActiveSize.cy = pMode->YResolution;
    pVideoSignalInfo->VSyncFreq.Numerator = XENGFX_DEFAULT_VSYNC * 1000;
    pVideoSignalInfo->VSyncFreq.Denominator = 1000;
    pVideoSignalInfo->HSyncFreq.Numerator = XENGFX_DEFAULT_VSYNC * pMode->YResolution * 1000 * (105 / 100);
    pVideoSignalInfo->HSyncFreq.Denominator = 1000;
    pVideoSignalInfo->PixelRate = pMode->XResolution * pMode->YResolution * XENGFX_DEFAULT_VSYNC;
    pVideoSignalInfo->ScanLineOrdering = D3DDDI_VSSLO_PROGRESSIVE;

    // Add it
    Status = pVidPnTargetModeSetInterface->pfnAddMode(hVidPnTargetModeSet, pVidPnTargetMode);
    if (!NT_SUCCESS(Status)) {
        TraceError(("%s pfnAddMode failed: 0x%x\n", __FUNCTION__, Status));
        pVidPnTargetModeSetInterface->pfnReleaseModeInfo(hVidPnTargetModeSet, pVidPnTargetMode);
        return Status; // low memory.
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
XenGfxAddSourceMode(D3DKMDT_HVIDPNSOURCEMODESET hVidPnSourceModeSet,
                    CONST DXGK_VIDPNSOURCEMODESET_INTERFACE *pVidPnSourceModeSetInterface,
                    XENGFX_MODE *pMode)
{
    D3DKMDT_VIDPN_SOURCE_MODE *pVidPnSourceMode;
    D3DKMDT_GRAPHICS_RENDERING_FORMAT *pGraphicsRenderingFormat;
    NTSTATUS Status;
    PAGED_CODE();

    Status = pVidPnSourceModeSetInterface->pfnCreateNewModeInfo(hVidPnSourceModeSet,
                                                                &pVidPnSourceMode);
    if (!NT_SUCCESS(Status)) {
        TraceError(("%s pfnCreateNewModeInfo failed: 0x%x\n", __FUNCTION__, Status));
        return Status; // low memory.
    }

    // Let OS assign the ID, set the type.
    pVidPnSourceMode->Type = D3DKMDT_RMT_GRAPHICS;

    // Initialize the rendering format per our constraints and the current mode.
    pGraphicsRenderingFormat = &pVidPnSourceMode->Format.Graphics;
    pGraphicsRenderingFormat->PrimSurfSize.cx = pMode->XResolution;
    pGraphicsRenderingFormat->PrimSurfSize.cy = pMode->YResolution;
    pGraphicsRenderingFormat->VisibleRegionSize.cx = pMode->XResolution;
    pGraphicsRenderingFormat->VisibleRegionSize.cy = pMode->YResolution;
    pGraphicsRenderingFormat->Stride = pMode->ScreenStride;
    pGraphicsRenderingFormat->PixelFormat = XenGfxDdiFormatFromXgfxFormat(pMode->XgfxFormat);
    pGraphicsRenderingFormat->ColorBasis = D3DKMDT_CB_SRGB;
    pGraphicsRenderingFormat->PixelValueAccessMode = D3DKMDT_PVAM_DIRECT;

    // Add it
    Status = pVidPnSourceModeSetInterface->pfnAddMode(hVidPnSourceModeSet, pVidPnSourceMode);
    if (!NT_SUCCESS(Status)) {
        TraceError(("%s pfnAddMode failed: 0x%x\n", __FUNCTION__, Status));
        pVidPnSourceModeSetInterface->pfnReleaseModeInfo(hVidPnSourceModeSet, pVidPnSourceMode);
        return Status; // low memory.
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
XenGfxUpdateTargetModeSet(XENGFX_VCRTC *pVCrtc,
                          XENGFX_MODE_SET *pModeSet,
                          CONST D3DKMDT_HVIDPN hConstrainingVidPn,
                          DXGK_VIDPN_INTERFACE *pVidPnInterface,                          
                          D3DKMDT_VIDPN_PRESENT_PATH *pCurrVidPnPresentPathInfo)
{
    D3DKMDT_HVIDPNTARGETMODESET hVidPnTargetModeSet = NULL;
    CONST DXGK_VIDPNTARGETMODESET_INTERFACE *pVidPnTargetModeSetInterface;
    D3DKMDT_VIDPN_TARGET_MODE *pPinnedVidPnTargetModeInfo = NULL;
    D3DKMDT_HVIDPNSOURCEMODESET hVidPnSourceModeSet = NULL;
    CONST DXGK_VIDPNSOURCEMODESET_INTERFACE *pVidPnSourceModeSetInterface;
    D3DKMDT_VIDPN_SOURCE_MODE *pPinnedVidPnSourceModeInfo = NULL;
    XENGFX_PINNED_STATE PinnedState;
    XENGFX_MODE *pMode;
    ULONG Count = 0, i;
    NTSTATUS Status = STATUS_SUCCESS;
    PAGED_CODE();

    Status = pVidPnInterface->pfnAcquireTargetModeSet(hConstrainingVidPn,
                                                      pCurrVidPnPresentPathInfo->VidPnTargetId,
                                                      &hVidPnTargetModeSet,
                                                      &pVidPnTargetModeSetInterface);
    if (!NT_SUCCESS(Status)) {
        TraceError(("%s pfnAcquireTargetModeSet failed: 0x%x\n", __FUNCTION__, Status));
        return Status; // low memory - bail out on operation.
    }

    Status = pVidPnInterface->pfnAcquireSourceModeSet(hConstrainingVidPn,
                                                      pCurrVidPnPresentPathInfo->VidPnSourceId,
                                                      &hVidPnSourceModeSet,
                                                      &pVidPnSourceModeSetInterface);
    if (!NT_SUCCESS(Status)) {
        pVidPnInterface->pfnReleaseTargetModeSet(hConstrainingVidPn, hVidPnTargetModeSet);
        TraceError(("%s pfnAcquireSourceModeSet failed: 0x%x\n", __FUNCTION__, Status));
        return Status; // low memory - bail out on operation.
    }

    do {
        // If the target mode set already has a pinned mode, don't do any updates.
        Status = pVidPnTargetModeSetInterface->pfnAcquirePinnedModeInfo(hVidPnTargetModeSet, &pPinnedVidPnTargetModeInfo);
        PinnedState = XenGfxPinnedModeState(Status, pPinnedVidPnTargetModeInfo);
        if (PinnedState == XENGFX_PS_PINNED) {
            // Drop out
            Status = STATUS_SUCCESS;
            break;
        }
        if (PinnedState == XENGFX_PS_ERROR) {
            TraceError(("%s pfnAcquirePinnedModeInfo(target) failed: 0x%x\n", __FUNCTION__, Status));
            pPinnedVidPnTargetModeInfo = NULL;
            break; // unknown nasty failure
        }

        // Done with existing target mode set
        pVidPnInterface->pfnReleaseTargetModeSet(hConstrainingVidPn, hVidPnTargetModeSet);
        hVidPnTargetModeSet = NULL;

        // Acquire any pinned source mode since this will constrain the target modes that are added.
        Status = pVidPnSourceModeSetInterface->pfnAcquirePinnedModeInfo(hVidPnSourceModeSet, &pPinnedVidPnSourceModeInfo);
        PinnedState = XenGfxPinnedModeState(Status, pPinnedVidPnSourceModeInfo);
        if (PinnedState == XENGFX_PS_ERROR) {
            TraceError(("%s pfnAcquirePinnedModeInfo(source) failed: 0x%x\n", __FUNCTION__, Status));
            pPinnedVidPnSourceModeInfo = NULL;
            break; // unknown nasty failure
        }
        if (PinnedState == XENGFX_PS_UNPINNED)
            pPinnedVidPnSourceModeInfo = NULL;

        // Make a new target mode set
        Status = pVidPnInterface->pfnCreateNewTargetModeSet(hConstrainingVidPn,
                                                            pCurrVidPnPresentPathInfo->VidPnTargetId,
                                                            &hVidPnTargetModeSet,
                                                            &pVidPnTargetModeSetInterface);
        if (!NT_SUCCESS(Status)) {
            TraceError(("%s pfnCreateNewTargetModeSet failed: 0x%x\n", __FUNCTION__, Status));
            hVidPnTargetModeSet = NULL;
            break; // no memory
        }

        // Enumerate over the modes for the vCRTC adding them. This is more or less what the sample
        // does. This could be done using the monitor modes set but it is not clear whether that
        // would contain all the modes needed.

        // N.B. If there is no mode set, commit an empty set to this path since there is nothing to
        // initialize it with. Other possible options would be to leave it as is or add a
        // default mode set. It seems the sample would effectively do what is done here.
        if (pModeSet != NULL)
            Count = pModeSet->ModeCount;

        for (i = 0; i < Count; i++) {
            pMode = &pModeSet->pModes[i];

            // Only target modes that match a pinned source mode
            if (pPinnedVidPnSourceModeInfo != NULL) {               
                if ((pPinnedVidPnSourceModeInfo->Format.Graphics.PrimSurfSize.cx == pMode->XResolution)&&
                    (pPinnedVidPnSourceModeInfo->Format.Graphics.PrimSurfSize.cy == pMode->YResolution)) {
                    if (!XenGfxSupportedVCrtcFormat(pVCrtc,
                                                    pPinnedVidPnSourceModeInfo->Format.Graphics.PixelFormat)) {
                        continue;
                    }
                }
                else {
                    continue;
                }
            }

            // Add the next mode to the set.
            Status = XenGfxAddTargetMode(hVidPnTargetModeSet,
                                         pVidPnTargetModeSetInterface,
                                         pMode);
            if (!NT_SUCCESS(Status)) {
                TraceError(("%s XenGfxAddTargetMode failed: 0x%x\n", __FUNCTION__, Status));
                break;
            }
        }

        if (!NT_SUCCESS(Status))
            break;

        Status = pVidPnInterface->pfnAssignTargetModeSet(hConstrainingVidPn,
                                                         pCurrVidPnPresentPathInfo->VidPnTargetId,
                                                         hVidPnTargetModeSet);
        if (NT_SUCCESS(Status))
            hVidPnTargetModeSet = NULL;
        else
            TraceError(("%s pfnAssignTargetModeSet failed: 0x%x\n", __FUNCTION__, Status));

    } while (FALSE);

    if (pPinnedVidPnSourceModeInfo != NULL)
        pVidPnSourceModeSetInterface->pfnReleaseModeInfo(hVidPnSourceModeSet, pPinnedVidPnSourceModeInfo);

    if (pPinnedVidPnTargetModeInfo != NULL)
        pVidPnTargetModeSetInterface->pfnReleaseModeInfo(hVidPnTargetModeSet, pPinnedVidPnTargetModeInfo);

    if (hVidPnSourceModeSet != NULL)
        pVidPnInterface->pfnReleaseSourceModeSet(hConstrainingVidPn, hVidPnSourceModeSet);

    if (hVidPnTargetModeSet != NULL)
        pVidPnInterface->pfnReleaseTargetModeSet(hConstrainingVidPn, hVidPnTargetModeSet);

    return Status;
}

static NTSTATUS
XenGfxUpdateSourceModeSet(XENGFX_VCRTC *pVCrtc,
                          XENGFX_MODE_SET *pModeSet,
                          CONST D3DKMDT_HVIDPN hConstrainingVidPn,
                          DXGK_VIDPN_INTERFACE *pVidPnInterface,
                          D3DKMDT_VIDPN_PRESENT_PATH *pCurrVidPnPresentPathInfo)
{ 
    D3DKMDT_HVIDPNSOURCEMODESET hVidPnSourceModeSet = NULL;
    CONST DXGK_VIDPNSOURCEMODESET_INTERFACE *pVidPnSourceModeSetInterface;
    D3DKMDT_VIDPN_SOURCE_MODE *pPinnedVidPnSourceModeInfo = NULL;
    D3DKMDT_HVIDPNTARGETMODESET hVidPnTargetModeSet = NULL;
    CONST DXGK_VIDPNTARGETMODESET_INTERFACE *pVidPnTargetModeSetInterface;
    D3DKMDT_VIDPN_TARGET_MODE *pPinnedVidPnTargetModeInfo = NULL;
    XENGFX_PINNED_STATE PinnedState;
    XENGFX_MODE *pMode;
    ULONG Count = 0, i;
    NTSTATUS Status = STATUS_SUCCESS;
    PAGED_CODE();   

    Status = pVidPnInterface->pfnAcquireSourceModeSet(hConstrainingVidPn,
                                                      pCurrVidPnPresentPathInfo->VidPnSourceId,
                                                      &hVidPnSourceModeSet,
                                                      &pVidPnSourceModeSetInterface);
    if (!NT_SUCCESS(Status)) {        
        TraceError(("%s pfnAcquireSourceModeSet failed: 0x%x\n", __FUNCTION__, Status));
        return Status; // low memory - bail out on operation.
    }

    Status = pVidPnInterface->pfnAcquireTargetModeSet(hConstrainingVidPn,
                                                      pCurrVidPnPresentPathInfo->VidPnTargetId,
                                                      &hVidPnTargetModeSet,
                                                      &pVidPnTargetModeSetInterface);
    if (!NT_SUCCESS(Status)) {
        pVidPnInterface->pfnReleaseSourceModeSet(hConstrainingVidPn, hVidPnSourceModeSet);
        TraceError(("%s pfnAcquireTargetModeSet failed: 0x%x\n", __FUNCTION__, Status));
        return Status; // low memory - bail out on operation.
    }    

    do {
        // If the source mode set already has a pinned mode, don't do any updates.
        Status = pVidPnSourceModeSetInterface->pfnAcquirePinnedModeInfo(hVidPnSourceModeSet, &pPinnedVidPnSourceModeInfo);
        PinnedState = XenGfxPinnedModeState(Status, pPinnedVidPnSourceModeInfo);
        if (PinnedState == XENGFX_PS_PINNED) {
            // Sanity check to make sure this pinned source mode specifies a pixel format
            // that this vCRTC can handle.
            if (XenGfxSupportedVCrtcFormat(pVCrtc, pPinnedVidPnSourceModeInfo->Format.Graphics.PixelFormat))
                Status = STATUS_SUCCESS;                
            else
                Status = STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
            // Drop out            
            break;
        }
        if (PinnedState == XENGFX_PS_ERROR) {
            TraceError(("%s pfnAcquirePinnedModeInfo(source) failed: 0x%x\n", __FUNCTION__, Status));
            pPinnedVidPnSourceModeInfo = NULL;
            break; // unknown nasty failure
        }
        // Done with existing target mode set
        pVidPnInterface->pfnReleaseSourceModeSet(hConstrainingVidPn, hVidPnSourceModeSet);
        hVidPnSourceModeSet = NULL;

        // Acquire any pinned target mode since this will constrain the source modes that are added.
        Status = pVidPnTargetModeSetInterface->pfnAcquirePinnedModeInfo(hVidPnTargetModeSet, &pPinnedVidPnTargetModeInfo);
        PinnedState = XenGfxPinnedModeState(Status, pPinnedVidPnTargetModeInfo);
        if (PinnedState == XENGFX_PS_ERROR) {
            TraceError(("%s pfnAcquirePinnedModeInfo(target) failed: 0x%x\n", __FUNCTION__, Status));
            pPinnedVidPnTargetModeInfo = NULL;
            break; // unknown nasty failure
        }
        if (PinnedState == XENGFX_PS_UNPINNED)
            pPinnedVidPnTargetModeInfo = NULL;

        // Make a new source mode set
        Status = pVidPnInterface->pfnCreateNewSourceModeSet(hConstrainingVidPn,
                                                            pCurrVidPnPresentPathInfo->VidPnSourceId,
                                                            &hVidPnSourceModeSet,
                                                            &pVidPnSourceModeSetInterface);
        if (!NT_SUCCESS(Status)) {
            TraceError(("%s pfnCreateNewSourceModeSet failed: 0x%x\n", __FUNCTION__, Status));
            hVidPnTargetModeSet = NULL;
            break; // no memory
        }

        // Enumerate over the modes for the vCRTC adding them. This is more or less what the sample
        // does. This could be done using the monitor modes set but it is not clear whether that
        // would contain all the modes needed.

        // N.B. If there is no mode set, commit an empty set to this path since there is nothing to
        // initialize it with. Other possible options would be to leave it as is or add a
        // default mode set. It seems the sample would effectively do what is done here.
        if (pModeSet != NULL)
            Count = pModeSet->ModeCount;

        for (i = 0; i < Count; i++) {
            pMode = &pModeSet->pModes[i];

            // Only target modes that match a pinned source mode
            if (pPinnedVidPnTargetModeInfo != NULL) {               
                if ((pPinnedVidPnTargetModeInfo->VideoSignalInfo.ActiveSize.cx != pMode->XResolution)||
                    (pPinnedVidPnTargetModeInfo->VideoSignalInfo.ActiveSize.cy != pMode->YResolution)) {
                    continue;
                }
            }

            // Add the next mode to the set.
            Status = XenGfxAddSourceMode(hVidPnSourceModeSet,
                                         pVidPnSourceModeSetInterface,
                                         pMode);
            if (!NT_SUCCESS(Status)) {
                TraceError(("%s XenGfxAddSourceMode failed: 0x%x\n", __FUNCTION__, Status));
                break;
            }
        }

        if (!NT_SUCCESS(Status))
            break;

        Status = pVidPnInterface->pfnAssignSourceModeSet(hConstrainingVidPn,
                                                         pCurrVidPnPresentPathInfo->VidPnSourceId,
                                                         hVidPnSourceModeSet);
        if (NT_SUCCESS(Status))
            hVidPnSourceModeSet = NULL;
        else
            TraceError(("%s pfnAssignSourceModeSet failed: 0x%x\n", __FUNCTION__, Status));

    } while (FALSE);

    if (pPinnedVidPnTargetModeInfo != NULL)
        pVidPnTargetModeSetInterface->pfnReleaseModeInfo(hVidPnTargetModeSet, pPinnedVidPnTargetModeInfo);

    if (pPinnedVidPnSourceModeInfo != NULL)
        pVidPnSourceModeSetInterface->pfnReleaseModeInfo(hVidPnSourceModeSet, pPinnedVidPnSourceModeInfo);    

    if (hVidPnTargetModeSet != NULL)
        pVidPnInterface->pfnReleaseTargetModeSet(hConstrainingVidPn, hVidPnTargetModeSet);

    if (hVidPnSourceModeSet != NULL)
        pVidPnInterface->pfnReleaseSourceModeSet(hConstrainingVidPn, hVidPnSourceModeSet);

    return Status;
}

static ULONG
XenGfxValidateNewMode(XENGFX_VCRTC *pVCrtc, XENGFX_SOURCE_MAP_ENTRY *pSourceEntry)
{
    ULONG i;
    XENGFX_MODE *pMode;

    // T & S Level 2
    ASSERT(pVCrtc->pModeSet != NULL); // already checked there is a monitor connected
    ASSERT(pVCrtc->pModeSet->pModes != NULL); // already checked there is a monitor connected
    ASSERT(pSourceEntry->FormatSet); // already checked there is a new mode set

    if (pVCrtc->pModeSet->ModeCount < 1) {
        TraceError(("%s monitor connected but no modes for vCRTC at %p??\n", __FUNCTION__, pVCrtc));
        return XENGFX_INVALID_MODE_INDEX;
    }

    for (i = 0; i < pVCrtc->pModeSet->ModeCount; i++) {
        pMode = &pVCrtc->pModeSet->pModes[i];
        if ((pMode->XResolution == pSourceEntry->GraphicsFormat.VisibleRegionSize.cx)&&
            (pMode->YResolution == pSourceEntry->GraphicsFormat.VisibleRegionSize.cy)&&
            (XenGfxSupportedVCrtcFormat(pVCrtc, pSourceEntry->GraphicsFormat.PixelFormat))&&
            (pMode->ScreenStride == pSourceEntry->GraphicsFormat.Stride))
            return i;
    }

    return XENGFX_INVALID_MODE_INDEX;
}

static BOOLEAN
XenGfxCompareMonitorModes(XENGFX_MODE *pMode,
                          D3DKMDT_HMONITORSOURCEMODESET hMonitorSourceModeSet,
                          CONST DXGK_MONITORSOURCEMODESET_INTERFACE *pMonitorSourceModeSetInterface)
{ 
    D3DKMDT_MONITOR_SOURCE_MODE *pCurrMonitorSourceModeInfo;
    D3DKMDT_MONITOR_SOURCE_MODE *pNextMonitorSourceModeInfo;
    D3DKMDT_2DREGION ActiveSize;
    NTSTATUS Status;
    BOOLEAN r = TRUE;
    PAGED_CODE();   

    // T & S Level 2

    // Enumerate monitor modes and determine if the mode already exists.
    Status = pMonitorSourceModeSetInterface->pfnAcquireFirstModeInfo(hMonitorSourceModeSet, &pCurrMonitorSourceModeInfo);
    if (Status == STATUS_GRAPHICS_DATASET_IS_EMPTY) {
        // Empty set, that is OK
        return FALSE;
    }
    if (!NT_SUCCESS(Status)) {
        TraceError(("%s pfnAcquireFirstModeInfo failed: 0x%x\n", __FUNCTION__, Status));
        return TRUE; // bad mode set? - more likely low memory - probably can't add to it
    }

    while (TRUE) {
        ActiveSize = pCurrMonitorSourceModeInfo->VideoSignalInfo.ActiveSize;
        
        // Match, then it is already there.
        if ((ActiveSize.cx == pMode->XResolution)&&(ActiveSize.cy == pMode->YResolution)) {
            pMonitorSourceModeSetInterface->pfnReleaseModeInfo(hMonitorSourceModeSet, pCurrMonitorSourceModeInfo);
            break;
        }

        Status = pMonitorSourceModeSetInterface->pfnAcquireNextModeInfo(hMonitorSourceModeSet, pCurrMonitorSourceModeInfo, &pNextMonitorSourceModeInfo);
        pMonitorSourceModeSetInterface->pfnReleaseModeInfo(hMonitorSourceModeSet, pCurrMonitorSourceModeInfo);

        if (Status == STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET) {
            r = FALSE;
            break;
        }
        else if (!NT_SUCCESS(Status)) {
            TraceError(("%s pfnAcquireNextPathInfo failed: 0x%x\n", __FUNCTION__, Status));
            break; // bad mode set? - more likely low memory - probably can't add to it
        }        
        pCurrMonitorSourceModeInfo = pNextMonitorSourceModeInfo;
    }

    return r;
}

static VOID
XenGfxInitMonitorSourceMode(D3DKMDT_MONITOR_SOURCE_MODE *pVidPnMonitorSourceModeInfo,
                            XENGFX_MODE *pMode)
{
    D3DKMDT_VIDEO_SIGNAL_INFO *pVideoSignalInfo = &pVidPnMonitorSourceModeInfo->VideoSignalInfo;
    PAGED_CODE();

    // T & S Level 2
    pVidPnMonitorSourceModeInfo->ColorBasis = D3DKMDT_CB_SRGB;
    pVidPnMonitorSourceModeInfo->ColorCoeffDynamicRanges.FirstChannel = 8;
    pVidPnMonitorSourceModeInfo->ColorCoeffDynamicRanges.SecondChannel = 8;
    pVidPnMonitorSourceModeInfo->ColorCoeffDynamicRanges.ThirdChannel = 8;
    pVidPnMonitorSourceModeInfo->ColorCoeffDynamicRanges.FourthChannel = 0;
    pVidPnMonitorSourceModeInfo->Origin = D3DKMDT_MCO_DRIVER;

    if (pMode->Flags & XENGFX_MODE_FLAG_EDID_MODE)
        pVidPnMonitorSourceModeInfo->Preference = D3DKMDT_MP_PREFERRED;
    else
        pVidPnMonitorSourceModeInfo->Preference = D3DKMDT_MP_NOTPREFERRED;

    pVideoSignalInfo->VideoStandard = D3DKMDT_VSS_OTHER;
    pVideoSignalInfo->TotalSize.cx = D3DKMDT_DIMENSION_NOTSPECIFIED;
    pVideoSignalInfo->TotalSize.cy = D3DKMDT_DIMENSION_NOTSPECIFIED;
    pVideoSignalInfo->ActiveSize.cx = pMode->XResolution;
    pVideoSignalInfo->ActiveSize.cy = pMode->YResolution;
    pVideoSignalInfo->VSyncFreq.Numerator = XENGFX_DEFAULT_VSYNC * 1000;
    pVideoSignalInfo->VSyncFreq.Denominator = 1000;
    pVideoSignalInfo->HSyncFreq.Numerator = XENGFX_DEFAULT_VSYNC * pMode->YResolution * 1000 * (105 / 100);
    pVideoSignalInfo->HSyncFreq.Denominator = 1000;
    pVideoSignalInfo->PixelRate = pMode->XResolution * pMode->YResolution * XENGFX_DEFAULT_VSYNC;
    pVideoSignalInfo->ScanLineOrdering = D3DDDI_VSSLO_PROGRESSIVE;
}

NTSTATUS APIENTRY
XenGfxIsSupportedVidPn(CONST HANDLE  hAdapter,
                       DXGKARG_ISSUPPORTEDVIDPN *pIsSupportedVidPn)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    DXGK_VIDPN_INTERFACE *pVidPnInterface = NULL;
    D3DKMDT_HVIDPNTOPOLOGY hVidPnTopology;
    DXGK_VIDPNTOPOLOGY_INTERFACE *pVidPnTopologyInterface;
    D3DKMDT_VIDPN_PRESENT_PATH *pCurrVidPnPresentPathInfo;
    D3DKMDT_VIDPN_PRESENT_PATH *pNextVidPnPresentPathInfo;
    D3DKMDT_HVIDPNSOURCEMODESET hVidPnSourceModeSet;
    CONST DXGK_VIDPNSOURCEMODESET_INTERFACE *pVidPnSourceModeSetInterface;
    D3DKMDT_HVIDPNTARGETMODESET hVidPnTargetModeSet;
    CONST DXGK_VIDPNTARGETMODESET_INTERFACE *pVidPnTargetModeSetInterface;
    XENGFX_PINNED_MODES PinnedModes;
    NTSTATUS Status;
    BOOLEAN End = FALSE;
    ULONG i = 0;
    PAGED_CODE();

    XenGfxEnter(__FUNCTION__, 2);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pIsSupportedVidPn))
        return STATUS_INVALID_PARAMETER;

    pIsSupportedVidPn->IsVidPnSupported = FALSE;

    Status = pXenGfxExtension->DxgkInterface.DxgkCbQueryVidPnInterface(pIsSupportedVidPn->hDesiredVidPn, DXGK_VIDPN_INTERFACE_VERSION_V1, &pVidPnInterface);
    if (!NT_SUCCESS(Status)) {
        TraceError(("%s DxgkCbQueryVidPnInterface failed: 0x%x\n", __FUNCTION__, Status));
        return STATUS_NO_MEMORY; // SNO
    }

    Status = pVidPnInterface->pfnGetTopology(pIsSupportedVidPn->hDesiredVidPn, &hVidPnTopology, &pVidPnTopologyInterface);
    if (!NT_SUCCESS(Status)) {
        TraceError(("%s pfnGetTopology failed: 0x%x\n", __FUNCTION__, Status));
        return STATUS_NO_MEMORY; // SNO
    }

    Status = pVidPnTopologyInterface->pfnAcquireFirstPathInfo(hVidPnTopology, &pCurrVidPnPresentPathInfo);
    if (Status == STATUS_GRAPHICS_DATASET_IS_EMPTY) {
        // Empty topology, that is OK (case 3 in the docs)
        pIsSupportedVidPn->IsVidPnSupported = TRUE;
        return STATUS_SUCCESS;
    }
    else if (!NT_SUCCESS(Status)) {
        TraceError(("%s pfnAcquireFirstPathInfo failed: 0x%x\n", __FUNCTION__, Status));
        return STATUS_NO_MEMORY; // bad topology? - probably low memory       
    }
    
    // TODO for now actual monitor modes are not being used to validate the proposed topology. If
    // this is needed, the block below would need to be locked.

    // The topology is the set of all paths and the sources/targets they connect to. A path brings those
    // objects and their mode sets/modes into the topology by being connected to them. Other sources/targets
    // may exist outside the topology. We do not care about those. The loop below will handle cases 1 and 2
    // in the docs. Don't need to lock for vCRTC access right now - only reading read-only values to
    // check vCRTC codec capabilities for the topology.
    while (TRUE) {
        PinnedModes.SourcePinned = PinnedModes.TargetPinned = FALSE;

        // -- Path --
        if (i == pXenGfxExtension->VCrtcCount) {
            // Can't be more paths than sources/targets?
            TraceError(("%s more paths in topology than there are targets/sources??\n", __FUNCTION__));
            Status = STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
            break;
        }
        
        if (!XenGfxIsSupportedPath(pCurrVidPnPresentPathInfo)) {
            pVidPnTopologyInterface->pfnReleasePathInfo(hVidPnTopology, pCurrVidPnPresentPathInfo);
            Status = STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
            break;
        }

        // -- Target --
        if (pCurrVidPnPresentPathInfo->VidPnTargetId >= pXenGfxExtension->VCrtcCount) {
            // Invalid VidPnTargetId
            TraceError(("%s invalid VidPnTargetId %d for path at %d??\n",
                        __FUNCTION__, pCurrVidPnPresentPathInfo->VidPnTargetId, i));
            Status = STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
            break;
        }

        // Check the target mode set for the VidPnTargetId of this path. Note there is
        // a 1 to 1 mapping from targets to paths.
        Status = pVidPnInterface->pfnAcquireTargetModeSet(pIsSupportedVidPn->hDesiredVidPn,
                                                          pCurrVidPnPresentPathInfo->VidPnTargetId,
                                                          &hVidPnTargetModeSet,
                                                          &pVidPnTargetModeSetInterface);
        if (!NT_SUCCESS(Status)) {
            TraceError(("%s pfnAcquireTargetModeSet failed: 0x%x\n", __FUNCTION__, Status));
            break;
        }

        if (!XenGfxIsSupportedTargetModeSet(pXenGfxExtension->ppVCrtcBanks[pCurrVidPnPresentPathInfo->VidPnTargetId],
                                            hVidPnTargetModeSet,
                                            pVidPnTargetModeSetInterface,
                                            &PinnedModes)) {
            pVidPnInterface->pfnReleaseTargetModeSet(pIsSupportedVidPn->hDesiredVidPn, hVidPnTargetModeSet);
            Status = STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
            break;
        }

        pVidPnInterface->pfnReleaseTargetModeSet(pIsSupportedVidPn->hDesiredVidPn, hVidPnTargetModeSet);

        // -- Source --
        if (pCurrVidPnPresentPathInfo->VidPnSourceId >= pXenGfxExtension->VCrtcCount) {
            // Invalid VidPnTargetId
            TraceError(("%s invalid VidPnSourceId %d for path at %d??\n",
                        __FUNCTION__, pCurrVidPnPresentPathInfo->VidPnSourceId, i));
            Status = STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
            break;
        }

        // Check the source mode set for the VidPnSourceId of this path. Note we could scan
        // the sets more than once if a source is on multiple paths - this is OK.
        Status = pVidPnInterface->pfnAcquireSourceModeSet(pIsSupportedVidPn->hDesiredVidPn,
                                                          pCurrVidPnPresentPathInfo->VidPnSourceId,
                                                          &hVidPnSourceModeSet,
                                                          &pVidPnSourceModeSetInterface);
        if (!NT_SUCCESS(Status)) {
            TraceError(("%s pfnAcquireSourceModeSet failed: 0x%x\n", __FUNCTION__, Status));
            break;
        }

        if (!XenGfxIsSupportedSourceModeSet(pXenGfxExtension->ppVCrtcBanks[pCurrVidPnPresentPathInfo->VidPnTargetId],
                                            hVidPnSourceModeSet,
                                            pVidPnSourceModeSetInterface,
                                            &PinnedModes)) {
            pVidPnInterface->pfnReleaseSourceModeSet(pIsSupportedVidPn->hDesiredVidPn, hVidPnSourceModeSet);
            Status = STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
            break;
        }

        pVidPnInterface->pfnReleaseSourceModeSet(pIsSupportedVidPn->hDesiredVidPn, hVidPnSourceModeSet);

        // -- Pinned --
        // Since transformation, rotation, etc is not supported right now, the pinned target and source must match eachother
        // to support this pinning. The check handles clone mode also in that it tests each source against its target.
        if ((PinnedModes.SourcePinned)&&(PinnedModes.TargetPinned)) {
            if (!XenGfxCompare2DRegion(PinnedModes.SourcePrimSurfSize, PinnedModes.TargetActiveSize)) {
                TraceVerbose(("%s pinned source and target modes don't match.\n", __FUNCTION__, Status));
                Status = STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
                break;
            }
        }

        // -- Next --
        Status = pVidPnTopologyInterface->pfnAcquireNextPathInfo(hVidPnTopology, pCurrVidPnPresentPathInfo, &pNextVidPnPresentPathInfo);
        // Done with the last path.
        pVidPnTopologyInterface->pfnReleasePathInfo(hVidPnTopology, pCurrVidPnPresentPathInfo);

        if (Status == STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET) {
            End = TRUE;
            break;
        }
        else if (!NT_SUCCESS(Status)) {
            TraceError(("%s pfnAcquireNextPathInfo failed: 0x%x\n", __FUNCTION__, Status));
            break;
        }
        pCurrVidPnPresentPathInfo = pNextVidPnPresentPathInfo;
        i++;
    }

    if (!End) // broke out early, cleanup current path
        pVidPnTopologyInterface->pfnReleasePathInfo(hVidPnTopology, pCurrVidPnPresentPathInfo);

    if (!NT_SUCCESS(Status))
        return Status;

    XenGfxLeave(__FUNCTION__);

    pIsSupportedVidPn->IsVidPnSupported = TRUE;

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxRecommendFunctionalVidPn(CONST HANDLE hAdapter,
                               CONST DXGKARG_RECOMMENDFUNCTIONALVIDPN *CONST pRecommendFunctionalVidPn)
{
    PAGED_CODE();
    // T & S Level 2
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pRecommendFunctionalVidPn))
        return STATUS_INVALID_PARAMETER;

    XenGfxLeave(__FUNCTION__);

    // Though this routine is still used on Vista (not Win7), it is only caused by either a
    // D3DKMTInvalidateActiveVidPn from user mode or due to display altering hot keys. The former is
    // unlikely because our display DLL currently does nothing. The latter is not present on the
    // virtual HW. So for now, just ignore it.
    return STATUS_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN;
}

NTSTATUS APIENTRY
XenGfxEnumVidPnCofuncModality(CONST HANDLE hAdapter,
                              CONST DXGKARG_ENUMVIDPNCOFUNCMODALITY *CONST pEnumCofuncModality)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    DXGK_VIDPN_INTERFACE *pVidPnInterface = NULL;
    DXGK_MONITOR_INTERFACE *pMonitorInterface;
    D3DKMDT_HVIDPNTOPOLOGY hVidPnTopology;
    DXGK_VIDPNTOPOLOGY_INTERFACE *pVidPnTopologyInterface;
    D3DKMDT_VIDPN_PRESENT_PATH *pCurrVidPnPresentPathInfo;
    D3DKMDT_VIDPN_PRESENT_PATH *pNextVidPnPresentPathInfo;
    D3DKMDT_VIDPN_PRESENT_PATH CurrPathInfo;    
    BOOLEAN UpdatePath;
    XENGFX_MODE_SET *pModeSet = NULL;
    NTSTATUS Status;
    BOOLEAN End = FALSE;
    ULONG i;
    PAGED_CODE();

    XenGfxEnter(__FUNCTION__, 2);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pEnumCofuncModality))
        return STATUS_INVALID_PARAMETER;

    Status = pXenGfxExtension->DxgkInterface.DxgkCbQueryVidPnInterface(pEnumCofuncModality->hConstrainingVidPn, DXGK_VIDPN_INTERFACE_VERSION_V1, &pVidPnInterface);
    if (!NT_SUCCESS(Status)) {
        TraceError(("%s DxgkCbQueryVidPnInterface failed: 0x%x\n", __FUNCTION__, Status));
        return STATUS_NO_MEMORY; // SNO
    }

    Status = pXenGfxExtension->DxgkInterface.DxgkCbQueryMonitorInterface(pXenGfxExtension->hDxgkHandle, DXGK_MONITOR_INTERFACE_VERSION_V1, &pMonitorInterface);
    if (!NT_SUCCESS(Status)) {
        TraceError(("%s DxgkCbQueryMonitorInterface failed: 0x%x\n", __FUNCTION__, Status));
        return STATUS_NO_MEMORY; // SNO
    }

    Status = pVidPnInterface->pfnGetTopology(pEnumCofuncModality->hConstrainingVidPn, &hVidPnTopology, &pVidPnTopologyInterface);
    if (!NT_SUCCESS(Status)) {
        TraceError(("%s pfnGetTopology failed: 0x%x\n", __FUNCTION__, Status));
        return STATUS_NO_MEMORY; // SNO
    }

    Status = pVidPnTopologyInterface->pfnAcquireFirstPathInfo(hVidPnTopology, &pCurrVidPnPresentPathInfo);
    if (Status == STATUS_GRAPHICS_DATASET_IS_EMPTY) {
        // Empty topology, nothing to do.
        return STATUS_SUCCESS;
    }
    else if (!NT_SUCCESS(Status)) {
        TraceError(("%s pfnAcquireFirstPathInfo failed: 0x%x\n", __FUNCTION__, Status));
        return STATUS_NO_MEMORY; // bad topology? - probably low memory       
    }

    for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) { // can't be more paths than sources/targets
        // -- Path --
        UpdatePath = FALSE;
        RtlMoveMemory(&CurrPathInfo, pCurrVidPnPresentPathInfo, sizeof(D3DKMDT_VIDPN_PRESENT_PATH));

        if ((pEnumCofuncModality->EnumPivotType != D3DKMDT_EPT_SCALING)&&
            (pCurrVidPnPresentPathInfo->ContentTransformation.Scaling == D3DKMDT_VPPS_UNPINNED)) {
            RtlZeroMemory(&CurrPathInfo.ContentTransformation.ScalingSupport, sizeof(D3DKMDT_VIDPN_PRESENT_PATH_SCALING_SUPPORT));
            CurrPathInfo.ContentTransformation.ScalingSupport.Identity = TRUE;            
            UpdatePath = TRUE;
        }

        if ((pEnumCofuncModality->EnumPivotType != D3DKMDT_EPT_ROTATION)&&
            (pCurrVidPnPresentPathInfo->ContentTransformation.Rotation == D3DKMDT_VPPS_UNPINNED)) {
            RtlZeroMemory(&CurrPathInfo.ContentTransformation.RotationSupport, sizeof(D3DKMDT_VIDPN_PRESENT_PATH_ROTATION_SUPPORT));
            CurrPathInfo.ContentTransformation.RotationSupport.Identity = TRUE;
            UpdatePath = TRUE;
        }

        if (CurrPathInfo.CopyProtection.CopyProtectionType != D3DKMDT_VPPMT_NOPROTECTION) {
            RtlZeroMemory(&CurrPathInfo.CopyProtection, sizeof(D3DKMDT_VIDPN_PRESENT_PATH_COPYPROTECTION));
            CurrPathInfo.CopyProtection.CopyProtectionType = D3DKMDT_VPPMT_NOPROTECTION;
            UpdatePath = TRUE;
        } 

        // TODO how exactly do you specify the other path values? Like:
        // VisibleFromActive*, ColorBasis values, Content, Gamma etc.
        // According to the docs, pfnUpdatePathSupportInfo only updates transforms and content protection!

        if (UpdatePath) {
            Status = pVidPnTopologyInterface->pfnUpdatePathSupportInfo(hVidPnTopology, &CurrPathInfo);
            if (!NT_SUCCESS(Status)) {
                TraceError(("%s pfnUpdatePathSupportInfo failed: 0x%x\n", __FUNCTION__, Status));
                break;
            }
        }

        // -- Target & Source --
        pModeSet = XenGfxGetModeSet(pXenGfxExtension, pCurrVidPnPresentPathInfo->VidPnTargetId);

        if ((pEnumCofuncModality->EnumPivotType != D3DKMDT_EPT_VIDPNTARGET)||
            (pEnumCofuncModality->EnumPivot.VidPnTargetId != pCurrVidPnPresentPathInfo->VidPnTargetId)) {
            Status = XenGfxUpdateTargetModeSet(pXenGfxExtension->ppVCrtcBanks[pCurrVidPnPresentPathInfo->VidPnTargetId],
                                               pModeSet,
                                               pEnumCofuncModality->hConstrainingVidPn,
                                               pVidPnInterface,
                                               pCurrVidPnPresentPathInfo);
            if (!NT_SUCCESS(Status)) {
                TraceError(("%s XenGfxUpdateTargetModeSet failed: 0x%x\n", __FUNCTION__, Status));
                break;
            }
        }

        if ((pEnumCofuncModality->EnumPivotType != D3DKMDT_EPT_VIDPNSOURCE)||
            (pEnumCofuncModality->EnumPivot.VidPnSourceId != pCurrVidPnPresentPathInfo->VidPnSourceId)) {
            Status = XenGfxUpdateSourceModeSet(pXenGfxExtension->ppVCrtcBanks[pCurrVidPnPresentPathInfo->VidPnTargetId],
                                               pModeSet,
                                               pEnumCofuncModality->hConstrainingVidPn,
                                               pVidPnInterface,                                               
                                               pCurrVidPnPresentPathInfo);
            if (!NT_SUCCESS(Status)) {
                TraceError(("%s XenGfxUpdateSourceModeSet failed: 0x%x\n", __FUNCTION__, Status));
                break;
            }
        }

        if (pModeSet != NULL)
            XenGfxPutModeSet(pXenGfxExtension, pModeSet);

        pModeSet = NULL;

        // -- Next --
        Status = pVidPnTopologyInterface->pfnAcquireNextPathInfo(hVidPnTopology, pCurrVidPnPresentPathInfo, &pNextVidPnPresentPathInfo);
        // Done with the last path.
        pVidPnTopologyInterface->pfnReleasePathInfo(hVidPnTopology, pCurrVidPnPresentPathInfo);

        if (Status == STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET) {
            End = TRUE;
            break;
        }
        else if (!NT_SUCCESS(Status)) {
            TraceError(("%s pfnAcquireNextPathInfo failed: 0x%x\n", __FUNCTION__, Status));
            break;
        }
        pCurrVidPnPresentPathInfo = pNextVidPnPresentPathInfo;
    }

    if (!End) {
        // Broke out early, cleanup current path and release any mode set
        pVidPnTopologyInterface->pfnReleasePathInfo(hVidPnTopology, pCurrVidPnPresentPathInfo);
        if (pModeSet != NULL)
            XenGfxPutModeSet(pXenGfxExtension, pModeSet);
    }

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxSetVidPnSourceAddress(CONST HANDLE hAdapter,
                            CONST DXGKARG_SETVIDPNSOURCEADDRESS *pSetVidPnSourceAddress)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    XENGFX_VCRTC *pVCrtc;
    KIRQL Irql;
    ULONG i;
    PAGED_CODE();

    // T & S Level 2
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pSetVidPnSourceAddress))
        return STATUS_INVALID_PARAMETER;

    // Set the source address for each vCRTC that is a target of the source. For
    // clone mode this could be > 1.
    // Note this routine could be called at DIRQL for an MMIO–based flip. 
    for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) {
        pVCrtc = pXenGfxExtension->ppVCrtcBanks[i];
        if (pVCrtc->VidPnSourceId == pSetVidPnSourceAddress->VidPnSourceId)
            pVCrtc->PrimaryAddress = pSetVidPnSourceAddress->PrimaryAddress;
    }

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxSetVidPnSourceVisibility(CONST HANDLE hAdapter,
                               CONST DXGKARG_SETVIDPNSOURCEVISIBILITY *pSetVidPnSourceVisibility)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    XENGFX_VCRTC *pVCrtc;
    ULONG i;
    PAGED_CODE();

    // T & S Level 2
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pSetVidPnSourceVisibility))
        return STATUS_INVALID_PARAMETER;

    // Reconfigure each vCRTC that is a target of the source. For clone mode this could be > 1.    
    for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) {
        pVCrtc = pXenGfxExtension->ppVCrtcBanks[i];
        if (pVCrtc->VidPnSourceId == pSetVidPnSourceVisibility->VidPnSourceId) {
            if (pSetVidPnSourceVisibility->Visible)
                XenGfxSetPrimaryForVCrtc(pXenGfxExtension, pVCrtc); // start scanning source
            else
                XenGfxClearPrimaryForVCrtc(pXenGfxExtension, pVCrtc); // stop scanning source
        }
    }

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}


NTSTATUS APIENTRY
XenGfxCommitVidPn(CONST HANDLE hAdapter,
                  CONST DXGKARG_COMMITVIDPN *CONST pCommitVidPn)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    DXGK_VIDPN_INTERFACE *pVidPnInterface = NULL;
    D3DKMDT_HVIDPNTOPOLOGY hVidPnTopology;
    DXGK_VIDPNTOPOLOGY_INTERFACE *pVidPnTopologyInterface;
    D3DKMDT_VIDPN_PRESENT_PATH *pCurrVidPnPresentPathInfo;
    D3DKMDT_VIDPN_PRESENT_PATH *pNextVidPnPresentPathInfo;  
    D3DKMDT_HVIDPNSOURCEMODESET hVidPnSourceModeSet;
    DXGK_VIDPNSOURCEMODESET_INTERFACE *pVidPnSourceModeSetInterface;
    D3DKMDT_VIDPN_SOURCE_MODE *pPinnedVidPnSourceModeInfo;
    XENGFX_SOURCE_MAP_ENTRY *pSourceMap;
    XENGFX_SOURCE_MAP_ENTRY *pSourceEntry;
    XENGFX_PINNED_STATE PinnedState;
    XENGFX_VCRTC *pVCrtc;
    NTSTATUS Status;
    KIRQL Irql;
    ULONG i;

    // T & S Level 2
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pCommitVidPn))
        return STATUS_INVALID_PARAMETER;


    // This is where a new VidPN is set for the adapter. The source -> target mapping
    // must be saved for all the paths.
    Status = pXenGfxExtension->DxgkInterface.DxgkCbQueryVidPnInterface(pCommitVidPn->hFunctionalVidPn, DXGK_VIDPN_INTERFACE_VERSION_V1, &pVidPnInterface);
    if (!NT_SUCCESS(Status)) {
        TraceError(("%s DxgkCbQueryVidPnInterface failed: 0x%x\n", __FUNCTION__, Status));
        return Status; // SNO
    }

    Status = pVidPnInterface->pfnGetTopology(pCommitVidPn->hFunctionalVidPn, &hVidPnTopology, &pVidPnTopologyInterface);
    if (!NT_SUCCESS(Status)) {
        TraceError(("%s pfnGetTopology failed: 0x%x\n", __FUNCTION__, Status));
        return Status; // SNO
    }

    // Enumerate paths and determine which sources are associated with which targets.
    Status = pVidPnTopologyInterface->pfnAcquireFirstPathInfo(hVidPnTopology, &pCurrVidPnPresentPathInfo);
    if (Status == STATUS_GRAPHICS_DATASET_IS_EMPTY) {
        // Empty topology       
        return STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
    }
    else if (!NT_SUCCESS(Status)) {        
        TraceError(("%s pfnAcquireFirstPathInfo failed: 0x%x\n", __FUNCTION__, Status));
        return STATUS_NO_MEMORY; // bad topology? - probably low memory       
    }

    // Alloc a buffer to temporarily hold the new mappings
    pSourceMap = (XENGFX_SOURCE_MAP_ENTRY*)ExAllocatePoolWithTag(NonPagedPool,
                  pXenGfxExtension->VCrtcCount*sizeof(XENGFX_SOURCE_MAP_ENTRY),
                  XENGFX_TAG);
    if (pSourceMap == NULL)
        return STATUS_NO_MEMORY;

    RtlZeroMemory(pSourceMap, pXenGfxExtension->VCrtcCount*sizeof(XENGFX_SOURCE_MAP_ENTRY));
    for (i = 0; i < pXenGfxExtension->VCrtcCount; i++)
        pSourceMap[i].VidPnSourceId = D3DDDI_ID_UNINITIALIZED;

    for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) { // can't be more paths than sources/targets

        // Do we care about this path further? Note that in the case where a single source is specified,
        // if it has been removed from a path to a target, the map below will include this information since
        // the value will be left as D3DDDI_ID_UNINITIALIZED and will be seen when reconciled.
        if ((pCommitVidPn->AffectedVidPnSourceId != D3DDDI_ID_ALL)&&
            (pCommitVidPn->AffectedVidPnSourceId != pCurrVidPnPresentPathInfo->VidPnSourceId)) {
            pVidPnTopologyInterface->pfnReleasePathInfo(hVidPnTopology, pCurrVidPnPresentPathInfo);
            continue;
        }

        // Path targets must have a monitor attached if D3DKMDT_MCC_ENFORCE is specified. If not then the
        // new VidPN must be rejected and the current one kept.
        if (pCommitVidPn->MonitorConnectivityChecks == D3DKMDT_MCC_ENFORCE) {
            pVCrtc = pXenGfxExtension->ppVCrtcBanks[pCurrVidPnPresentPathInfo->VidPnTargetId];

            // Check at this point in time by just reading the status register whether a monitor is 
            // connected even though a DPC could be running or run to change the vCRTC state simultaneously.
            if ((READ_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_STATUS)) & XGFX_VCRTC_STATUS_HOTPLUG) == 0) {
                Status = STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY;
                pVidPnTopologyInterface->pfnReleasePathInfo(hVidPnTopology, pCurrVidPnPresentPathInfo);
                break;
            }
        }

        // On each path with source changes, set the source associated with the target/vCRTC.
        pSourceMap[pCurrVidPnPresentPathInfo->VidPnTargetId].VidPnSourceId = pCurrVidPnPresentPathInfo->VidPnSourceId;

        // Fetch the pinned mode information to update the vCRTCs with
        Status = pVidPnInterface->pfnAcquireSourceModeSet(pCommitVidPn->hFunctionalVidPn,
                                                          pCurrVidPnPresentPathInfo->VidPnSourceId,
                                                          &hVidPnSourceModeSet,
                                                          &pVidPnSourceModeSetInterface);
        if (!NT_SUCCESS(Status)) {
            TraceError(("%s pfnAcquireSourceModeSet on path in new VidPN failed: 0x%x\n", __FUNCTION__, Status));
            pVidPnTopologyInterface->pfnReleasePathInfo(hVidPnTopology, pCurrVidPnPresentPathInfo);
            break;
        }

        Status = pVidPnSourceModeSetInterface->pfnAcquirePinnedModeInfo(hVidPnSourceModeSet, &pPinnedVidPnSourceModeInfo);
        PinnedState = XenGfxPinnedModeState(Status, pPinnedVidPnSourceModeInfo);
        if (PinnedState == XENGFX_PS_PINNED) {
            if (pPinnedVidPnSourceModeInfo->Type == D3DKMDT_RMT_GRAPHICS) {
                pSourceMap[pCurrVidPnPresentPathInfo->VidPnTargetId].GraphicsFormat = pPinnedVidPnSourceModeInfo->Format.Graphics;
                pSourceMap[pCurrVidPnPresentPathInfo->VidPnTargetId].FormatSet = TRUE;
            }
            else {
                TraceWarning(("%s pfnAcquirePinnedModeInfo returned non-graphical information, keeping current mode values.\n", __FUNCTION__));
            }
            pVidPnSourceModeSetInterface->pfnReleaseModeInfo(hVidPnSourceModeSet, pPinnedVidPnSourceModeInfo);                        
        }
        else if (PinnedState == XENGFX_PS_ERROR) {
            TraceError(("%s pfnAcquirePinnedModeInfo for current source failed: 0x%x\n", __FUNCTION__, Status));
            pVidPnInterface->pfnReleaseSourceModeSet(pCommitVidPn->hFunctionalVidPn, hVidPnSourceModeSet);
            pVidPnTopologyInterface->pfnReleasePathInfo(hVidPnTopology, pCurrVidPnPresentPathInfo);
            break;      
        }

        pVidPnInterface->pfnReleaseSourceModeSet(pCommitVidPn->hFunctionalVidPn, hVidPnSourceModeSet);

        Status = pVidPnTopologyInterface->pfnAcquireNextPathInfo(hVidPnTopology, pCurrVidPnPresentPathInfo, &pNextVidPnPresentPathInfo);
        // Done with the last path.
        pVidPnTopologyInterface->pfnReleasePathInfo(hVidPnTopology, pCurrVidPnPresentPathInfo);

        if (Status == STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET) {
            break;
        }
        else if (!NT_SUCCESS(Status)) {
            TraceError(("%s pfnAcquireNextPathInfo failed: 0x%x\n", __FUNCTION__, Status));
            break;
        }
        pCurrVidPnPresentPathInfo = pNextVidPnPresentPathInfo;
    }

    if (Status == STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET)
        Status = STATUS_SUCCESS;

    // Drop out here for errors
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(pSourceMap, XENGFX_TAG);
        return Status;
    }    

    // Reconcile the new map with the old, determine what has changed. Stage everything
    // and only commit changes when everything is validated.
    for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) {
        pVCrtc = pXenGfxExtension->ppVCrtcBanks[i];
        pSourceEntry = &pSourceMap[i];

        // Reset all staging values to defaults.
        pVCrtc->StagedModeIndex = XENGFX_INVALID_MODE_INDEX;        
        pVCrtc->StagedVidPnSourceId = D3DDDI_ID_UNINITIALIZED;
        pVCrtc->StagedPixelFormat = XGFX_VCRTC_VALID_FORMAT_NONE;
        pVCrtc->StagedFlags = XENGFX_STAGED_FLAG_UNSET;

        // Test if new mode information could be obtained above.
        if (!pSourceEntry->FormatSet) {
            pVCrtc->StagedFlags |= XENGFX_STAGED_FLAG_SKIP;
            continue;
        }

        // Case: |T| ... |T|
        // Do nothing.
        if ((pVCrtc->VidPnSourceId == D3DDDI_ID_UNINITIALIZED)&&
            (pSourceEntry->VidPnSourceId == D3DDDI_ID_UNINITIALIZED)) {            
            continue;
        }

        // Case: |T|<-|S| ... |T|
        // Path was removed, stage a reset
        if ((pVCrtc->VidPnSourceId != D3DDDI_ID_UNINITIALIZED)&&
            (pSourceEntry->VidPnSourceId == D3DDDI_ID_UNINITIALIZED)) {
            pVCrtc->StagedFlags |= XENGFX_STAGED_FLAG_CLEAR;
            continue;
        }

        // All other cases:
        //      |T|       ... |T|<-|S|     new path and source
        //      |T|<-|S1| ... |T|<-|S2|    new source
        //      |T|<-|S1| ... |T|<-|S1|    same source
        //      |T|<-|S1| ... |T|<-|S1'|   same source, new mode
        // Check for monitor, validate mode, stage values
        if (XenGfxMonitorConnected(pVCrtc)) {
            pVCrtc->StagedModeIndex = XenGfxValidateNewMode(pVCrtc, pSourceEntry);
            if (pVCrtc->StagedModeIndex == XENGFX_INVALID_MODE_INDEX) {
                Status = STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED;
                break;
            }
        }        
        pVCrtc->StagedVidPnSourceId = pSourceEntry->VidPnSourceId;
        pVCrtc->StagedPixelFormat = XenGfxXgfxFormatFromDdiFormat(pSourceEntry->GraphicsFormat.PixelFormat);
        // Want to do a reset to stop scanning to any primary surface that is currently
        // programmed for the vCRTC.
        pVCrtc->StagedFlags |= XENGFX_STAGED_FLAG_CLEAR;
    }

    // Lock for the VidPN commit since the vCRTCs mode information (which is transient)
    // will be accessed.
    KeAcquireSpinLock(&pXenGfxExtension->VCrtcLock, &Irql);

    for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) {
        pVCrtc = pXenGfxExtension->ppVCrtcBanks[i];

        // Commit all staged values if everything is reconciled and validated above else
        // reject the VidPN.
        if (NT_SUCCESS(Status)) {
            if ((pVCrtc->StagedFlags & XENGFX_STAGED_FLAG_SKIP) == 0) {
                pVCrtc->CurrentModeIndex = pVCrtc->StagedModeIndex;
                pVCrtc->VidPnSourceId = pVCrtc->StagedVidPnSourceId;

                // Set the new mode format
                if (pVCrtc->StagedPixelFormat != XGFX_VCRTC_VALID_FORMAT_NONE)
                    pVCrtc->pModeSet->pModes[pVCrtc->CurrentModeIndex].XgfxFormat = pVCrtc->StagedPixelFormat;

                // Make a copy of the current mode that can be accessed outside of the lock
                RtlMoveMemory(&pVCrtc->CurrentMode, &pVCrtc->pModeSet->pModes[pVCrtc->CurrentModeIndex], sizeof(XENGFX_MODE));

                if (pVCrtc->StagedFlags & XENGFX_STAGED_FLAG_CLEAR)
                    XenGfxClearPrimaryForVCrtc(pXenGfxExtension, pVCrtc);            
            }
        }

        // Clear all staging values
        pVCrtc->StagedModeIndex = XENGFX_INVALID_MODE_INDEX;
        pVCrtc->StagedVidPnSourceId = D3DDDI_ID_UNINITIALIZED;
        pVCrtc->StagedFlags = XENGFX_STAGED_FLAG_UNSET;
    }
  
    KeReleaseSpinLock(&pXenGfxExtension->VCrtcLock, Irql);

    ExFreePoolWithTag(pSourceMap, XENGFX_TAG);

    XenGfxLeave(__FUNCTION__);

    return Status;
}

NTSTATUS APIENTRY
XenGfxUpdateActiveVidPnPresentPath(CONST HANDLE hAdapter,
                                   CONST DXGKARG_UPDATEACTIVEVIDPNPRESENTPATH *CONST pUpdateActiveVidPnPresentPath)
{
    PAGED_CODE();
    // T & S Level 2
    XenGfxEnter(__FUNCTION__, 2);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pUpdateActiveVidPnPresentPath))
        return STATUS_INVALID_PARAMETER;

    // Probably don't need to do too much with this one.

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxRecommendMonitorModes(CONST HANDLE hAdapter,
                            CONST DXGKARG_RECOMMENDMONITORMODES *CONST pRecommendMonitorModes)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    D3DKMDT_HMONITORSOURCEMODESET hMonitorSourceModeSet;
    CONST DXGK_MONITORSOURCEMODESET_INTERFACE *pMonitorSourceModeSetInterface;
    D3DKMDT_MONITOR_SOURCE_MODE *pNewMonitorSourceModeInfo;
    XENGFX_MODE_SET *pModeSet;
    XENGFX_MODE *pMode;
    XENGFX_MODE **ppAddModes;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG i;
    PAGED_CODE();

    // T & S Level 2
    XenGfxEnter(__FUNCTION__, 2);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pRecommendMonitorModes))
        return STATUS_INVALID_PARAMETER;

    ASSERT(pRecommendMonitorModes->VideoPresentTargetId < pXenGfxExtension->VCrtcCount);
    hMonitorSourceModeSet = pRecommendMonitorModes->hMonitorSourceModeSet;
    pMonitorSourceModeSetInterface = pRecommendMonitorModes->pMonitorSourceModeSetInterface;

    // It seems reasonable to assume this is called when a monitor is hotplugged to allow modes to be added
    // the the monitor source mode set.
    //
    // N.B. The working assumption here is that the monitor modes are gotten from the EDID query
    // on the child device. This set should include 3 standard timings and the detailed timing 
    // for the preferred mode. This corresponds to the modes with either XENGFX_MODE_FLAG_BASE_SET
    // or XENGFX_MODE_FLAG_EDID_MODE flags set. It remains to be seen how the directx kernel handles
    // this.
    pModeSet = XenGfxGetModeSet(pXenGfxExtension, pRecommendMonitorModes->VideoPresentTargetId);
    if (pModeSet == NULL)
        return STATUS_SUCCESS; // no monitor at this point

    // Temp queue to hold modes to recommend.
    ppAddModes =
        (XENGFX_MODE**)ExAllocatePoolWithTag(NonPagedPool, 
                                             pModeSet->ModeCount*sizeof(XENGFX_MODE),
                                             XENGFX_TAG);
    if (ppAddModes == NULL) {
        XenGfxPutModeSet(pXenGfxExtension, pModeSet);
        return STATUS_NO_MEMORY;
    }
    RtlZeroMemory(ppAddModes, pModeSet->ModeCount*sizeof(XENGFX_MODE));
    
    for (i = 0; i < pModeSet->ModeCount; i++) {
        if (!XenGfxCompareMonitorModes(&pModeSet->pModes[i],
                                       hMonitorSourceModeSet,
                                       pMonitorSourceModeSetInterface)) {
            ppAddModes[i] = &pModeSet->pModes[i];
        }
    }

    // Add any missing modes
    for (i = 0; i < pModeSet->ModeCount; i++) {
        if (ppAddModes[i] == NULL)
            continue;

        Status = pMonitorSourceModeSetInterface->pfnCreateNewModeInfo(hMonitorSourceModeSet, &pNewMonitorSourceModeInfo);
        if (!NT_SUCCESS(Status)) {
            TraceError(("%s pfnCreateNewModeInfo failed: 0x%x\n", __FUNCTION__, Status));
            break; // bad mode set? - probably low memory       
        }

        XenGfxInitMonitorSourceMode(pNewMonitorSourceModeInfo, ppAddModes[i]);

        Status = pMonitorSourceModeSetInterface->pfnAddMode(hMonitorSourceModeSet, pNewMonitorSourceModeInfo);
        if (!NT_SUCCESS(Status)) {
            TraceError(("%s pfnCreateNewModeInfo pfnAddMode: 0x%x\n", __FUNCTION__, Status));
            pMonitorSourceModeSetInterface->pfnReleaseModeInfo(hMonitorSourceModeSet, pNewMonitorSourceModeInfo);
        }
    }

    ExFreePoolWithTag(ppAddModes, XENGFX_TAG);
    XenGfxPutModeSet(pXenGfxExtension, pModeSet);

    XenGfxLeave(__FUNCTION__);

    return Status;
}

NTSTATUS APIENTRY
XenGfxRecommendVidPnTopology(CONST HANDLE hAdapter,
                             CONST DXGKARG_RECOMMENDVIDPNTOPOLOGY *CONST pRecommendVidPnTopology)
{
    PAGED_CODE();
    XenGfxEnter(__FUNCTION__, 3);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pRecommendVidPnTopology))
        return STATUS_INVALID_PARAMETER;

    XenGfxLeave(__FUNCTION__);

    return STATUS_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY;
}

