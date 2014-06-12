//
// xendisp.c - XENGFX Windows PV Display Driver
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


#include <stdarg.h>
#include <devioctl.h>
#include "xendisp.h"

// Display Driver Helper Routines

static WCHAR *g_DllName = L"XENGFXDP";

#ifdef DBG
static enum XenGfxDebugLevel eDefaultLevel = DEBUG_LEVEL_INFO;
#else
static enum XenGfxDebugLevel eDefaultLevel = DEBUG_LEVEL_WARNING;
#endif

void XenGfxDebugPrint(XenGfxDebugLevel eLevel, char *szMessage, ...)
{
    va_list vaList;
    va_start(vaList, szMessage);

    if (eLevel >= eDefaultLevel) 
        EngDebugPrint(STANDARD_DEBUG_PREFIX, szMessage, vaList);
}

BOOL XenGfxIsModeSupported(PVIDEO_MODE_INFORMATION pModeInfo)
{
    /* If number of planes > 1 or banked or non graphics mode
     * do not support the mode.
     */
    if (pModeInfo->NumberOfPlanes != 1 || 
        !(pModeInfo->AttributeFlags & VIDEO_MODE_GRAPHICS) ||
        pModeInfo->AttributeFlags & VIDEO_MODE_BANKED ||
        ( pModeInfo->BitsPerPlane != 8 && 
	      pModeInfo->BitsPerPlane != 16 &&
          pModeInfo->BitsPerPlane != 24 && 
	      pModeInfo->BitsPerPlane != 32 ))
        return FALSE;

    return TRUE;
}

BOOL XenGfxAreModesSame(PVIDEO_MODE_INFORMATION pVideoModeInfo, 
                        DEVMODEW *pDevMode)
{
    if (pDevMode->dmBitsPerPel == 
        pVideoModeInfo->NumberOfPlanes * pVideoModeInfo->BitsPerPlane &&
        pDevMode->dmPelsWidth == pVideoModeInfo->VisScreenWidth &&
        pDevMode->dmPelsHeight == pVideoModeInfo->VisScreenHeight &&
        pDevMode->dmDisplayFrequency == pVideoModeInfo->Frequency)
        return TRUE;

    return FALSE;
}

void GetHTAndBMPFormat(ULONG ulBitCount, PULONG pulHT, PULONG pulBMP)
{
    ULONG ulHTFormat;
    ULONG ulBmpFormat;

    switch (ulBitCount) {
        case 8:
            ulHTFormat =  HT_FORMAT_8BPP;
            ulBmpFormat = BMF_8BPP;
            break;
        case 16:
            ulHTFormat = HT_FORMAT_16BPP;
            ulBmpFormat = BMF_16BPP;
            break;
        case 24:
            ulHTFormat = HT_FORMAT_24BPP;
            ulBmpFormat = BMF_24BPP;
            break;
        case 32:
        default:
            ulHTFormat = HT_FORMAT_32BPP;
            ulBmpFormat = BMF_32BPP;
    }

    if (pulHT)
        *pulHT = ulHTFormat;
    if (pulBMP)
        *pulBMP = ulBmpFormat;
}

void PrintModeInfo(PVIDEO_MODE_INFORMATION pVideoModeInfo, PPDEV pDev,
                   DEVMODEW *pDevModeInfo)
{
    if (pVideoModeInfo != NULL)
        XenGfxDebugPrint(DEBUG_LEVEL_INFO, "Video Mode Info - %d X %d X %d\n",
                         pVideoModeInfo->VisScreenWidth,
                         pVideoModeInfo->VisScreenHeight,
                         pVideoModeInfo->NumberOfPlanes * 
                         pVideoModeInfo->BitsPerPlane);

    if (pDevModeInfo != NULL)
        XenGfxDebugPrint(DEBUG_LEVEL_INFO, "DEVINFO Mode Info - %d X %d X %d\n", 
                         pDevModeInfo->dmPelsWidth, pDevModeInfo->dmPelsHeight,
                         pDevModeInfo->dmBitsPerPel);

    if (pDev != NULL)
        XenGfxDebugPrint(DEBUG_LEVEL_INFO, 
                         "PDev Mode Info - %d X %d X %d; Mode - %d\n",
                         pDev->ulPelsWidth, pDev->ulPelsHeight,
                         pDev->ulBitsPerPel, pDev->ulMode);
}

void CopyVideoModeInfoToDevModeInfo(PVIDEO_MODE_INFORMATION pVideoModeInfo, 
                                    DEVMODEW *pDevMode)
{
    RtlCopyMemory(pDevMode->dmDeviceName, g_DllName, sizeof(g_DllName));
    pDevMode->dmSpecVersion = DM_SPECVERSION;
    pDevMode->dmDriverVersion = DM_SPECVERSION;
    pDevMode->dmSize = sizeof(DEVMODEW);
    pDevMode->dmDriverExtra = 0;

    pDevMode->dmFields = DM_BITSPERPEL | DM_PELSWIDTH | 
                         DM_PELSHEIGHT | DM_DISPLAYFREQUENCY | 
			 DM_DISPLAYFLAGS;
    pDevMode->dmBitsPerPel = pVideoModeInfo->NumberOfPlanes * 
                             pVideoModeInfo->BitsPerPlane;
    pDevMode->dmPelsWidth = pVideoModeInfo->VisScreenWidth;
    pDevMode->dmPelsHeight = pVideoModeInfo->VisScreenHeight;
    pDevMode->dmDisplayFrequency = pVideoModeInfo->Frequency;
    pDevMode->dmDisplayFlags = 0;
}

void CopyCurrentModeInfoToPDEV(HANDLE hDrv, PVIDEO_MODE_INFORMATION pVideoModeInfo, PPDEV pDev)
{
    pDev->hDriver = hDrv;
    pDev->ulMode = pVideoModeInfo->ModeIndex;
    pDev->ulBitsPerPel = pVideoModeInfo->NumberOfPlanes * 
                         pVideoModeInfo->BitsPerPlane;
    pDev->ulPelsWidth = pVideoModeInfo->VisScreenWidth;
    pDev->ulPelsHeight = pVideoModeInfo->VisScreenHeight;
    pDev->ulFrequency = pVideoModeInfo->Frequency;
    pDev->ulScreenDelta = pVideoModeInfo->ScreenStride;
}

void InitializeDeviceCapabilities(PVIDEO_MODE_INFORMATION pVideoModeInfo, ULONG *pGDIInfo, ULONG ulGDISize)
{
    GDIINFO gdi;

    if (pGDIInfo == NULL || pVideoModeInfo == NULL || ulGDISize  < sizeof(GDIINFO)) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "Invalid input to intialize dev capabilities!\n");
        return;
    }

    RtlZeroMemory(&gdi, sizeof(GDIINFO));

    gdi.ulVersion = GDI_DRIVER_VERSION;
    gdi.ulTechnology = DT_RASDISPLAY;
    gdi.ulHorzSize = pVideoModeInfo->XMillimeter;
    gdi.ulVertSize = pVideoModeInfo->YMillimeter;
    gdi.ulHorzRes = pVideoModeInfo->VisScreenWidth;
    gdi.ulVertRes = pVideoModeInfo->VisScreenHeight;
    gdi.cBitsPixel = pVideoModeInfo->BitsPerPlane;
    gdi.cPlanes = pVideoModeInfo->NumberOfPlanes;
    gdi.ulNumColors = -1;
    gdi.ulLogPixelsX = 96;
    gdi.ulLogPixelsY = 96;
    gdi.flTextCaps = TC_RA_ABLE;
    gdi.ulDACRed = pVideoModeInfo->NumberRedBits;
    gdi.ulDACGreen = pVideoModeInfo->NumberGreenBits;
    gdi.ulDACBlue = pVideoModeInfo->NumberBlueBits;
    gdi.ulAspectX = 24; 
    gdi.ulAspectY = 24;
    gdi.ulAspectXY = 33;
    gdi.xStyleStep = 1;
    gdi.yStyleStep = 1;
    gdi.denStyleStep = 3;
    gdi.ulPrimaryOrder = PRIMARY_ORDER_CBA; 
    gdi.ulHTPatternSize = HT_PATSIZE_4x4_M; 
    GetHTAndBMPFormat(pVideoModeInfo->NumberOfPlanes * pVideoModeInfo->BitsPerPlane, &gdi.ulHTOutputFormat, NULL);
    gdi.flHTFlags = HT_FLAG_ADDITIVE_PRIMS;
    gdi.ulVRefresh = pVideoModeInfo->Frequency;

    RtlCopyMemory(pGDIInfo, &gdi, sizeof(GDIINFO));
}

void InitializeDevInfo(PVIDEO_MODE_INFORMATION pVideoModeInfo, PPDEV pDev, 
                       DEVINFO *pDevInfo, ULONG ulDevInfoSize)
{
    if (pVideoModeInfo == NULL || pDevInfo == NULL || ulDevInfoSize < sizeof(DEVINFO)) {
         XenGfxDebugPrint(DEBUG_LEVEL_ERROR, 
 	                   "Invalid input to initialize dev info!\n");
         return;
    }

    RtlZeroMemory(pDevInfo, sizeof(DEVINFO));

    pDevInfo->flGraphicsCaps = GCAPS_OPAQUERECT | GCAPS_LAYERED;
    pDevInfo->cxDither = 8;
    pDevInfo->cyDither = 8;

    GetHTAndBMPFormat(pVideoModeInfo->NumberOfPlanes * pVideoModeInfo->BitsPerPlane,
                      NULL, &pDevInfo->iDitherFormat);
    /* Note: Taking the color mask from video mode info
     * is resulting in palette display issues.  So, going with
     * the below.
     */
    pDev->hPalette = pDevInfo->hpalDefault = 
        EngCreatePalette(PAL_BITFIELDS, 0, NULL, 0xFF0000, 0xFF00, 0xFF);
}

DWORD XenGfxGetNumModesFromMiniport(HANDLE hDrv, PDWORD pNumModes, PDWORD pModeInfoSize)
{
    DWORD dwRet, dwRetBytes;
    VIDEO_NUM_MODES videoNumModes;

    if (pNumModes == NULL || pModeInfoSize == NULL) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "GetNumModesFromMiniport: Invalid input!\n");
        return -1;
    }

    dwRet = EngDeviceIoControl(hDrv, IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES, 
                               NULL, 0, &videoNumModes, 
			                   sizeof(VIDEO_NUM_MODES), &dwRetBytes);
    if (dwRet != 0) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR,
                         "Unable to query number of available modes.  Error - %d\n",
                         dwRet);
        return dwRet;
    }

    *pModeInfoSize = videoNumModes.ModeInformationLength;
    *pNumModes = videoNumModes.NumModes;
    return dwRet;
}

DWORD XenGfxGetModesFromMiniport(HANDLE hDrv, 
                                 PVIDEO_MODE_INFORMATION pModeInfo,
                                 DWORD dwModeInfoSize, DWORD dwNumModes)
{

    DWORD dwRet, dwRetBytes, dwTotalModeInfoSize;

    if (dwModeInfoSize == 0 || dwNumModes == 0 || pModeInfo == NULL) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "XenGfxGetModesFromMiniport: Invalid input!\n");
        return -1;
    }

    dwTotalModeInfoSize = dwModeInfoSize * dwNumModes;
    dwRet = EngDeviceIoControl(hDrv, IOCTL_VIDEO_QUERY_AVAIL_MODES, 
                               NULL, 0, pModeInfo, 
                               dwTotalModeInfoSize, &dwRetBytes); 
    if (dwRet != 0) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "Unable to query available modes! Error - %d\n", dwRet);
        return dwRet;
    }

    return dwRet;
}

DWORD XenGfxGetSupportedModes(HANDLE hDrv, PVIDEO_MODE_INFORMATION *ppModeInfo, PDWORD pNumModes)
{
    DWORD dwCount, dwRet, dwModeInfoSize;
    DWORD dwNumModes, dwTotalModeInfoSize, dwNumNewModes;
    PVIDEO_MODE_INFORMATION pLocalModeInfo, pTempInfo, pNewModeInfo;

    if (ppModeInfo == NULL || pNumModes == NULL) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "Invalid input param to XenGfxGetSupportedModes!\n");
        return -1;
    }

    dwRet = XenGfxGetNumModesFromMiniport(hDrv, &dwNumModes, &dwModeInfoSize);
    if (dwRet != 0 || dwModeInfoSize == 0 || dwNumModes == 0) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "XenGfxGetNumModesFromMiniport failed!  Error - %d\n", dwRet);
        return -1;
    }

    dwTotalModeInfoSize = dwModeInfoSize * dwNumModes;
    pLocalModeInfo =
        (PVIDEO_MODE_INFORMATION)EngAllocMem(FL_ZERO_MEMORY, dwTotalModeInfoSize, XENGFX_DISPLAY_ALLOC_TAG);
    if (pLocalModeInfo == NULL) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "Unable to allocate memory for local mode info!\n");
        return -1;
    }

    dwRet = XenGfxGetModesFromMiniport(hDrv, pLocalModeInfo, dwModeInfoSize, dwNumModes);
    if (dwRet != 0) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "XenGfxGetModesFromMiniport failed!  Error - %d\n", dwRet);
        EngFreeMem(pLocalModeInfo);
        return -1;
    }

    for (dwCount=0, pTempInfo = pLocalModeInfo, dwNumNewModes = 0; 
         dwCount < dwNumModes; dwCount++) {
        if (XenGfxIsModeSupported(pTempInfo) == FALSE) {
            pTempInfo = (PVIDEO_MODE_INFORMATION)((PUCHAR)pTempInfo + sizeof(VIDEO_MODE_INFORMATION));
            continue;
        }
        
        dwNumNewModes++;
        pTempInfo = (PVIDEO_MODE_INFORMATION)((PUCHAR)pTempInfo + sizeof(VIDEO_MODE_INFORMATION));
    }

    XenGfxDebugPrint(DEBUG_LEVEL_INFO, "Number of valid modes - %d, ModeInfoSize is - %d\n",
                     dwNumNewModes, dwModeInfoSize);
    dwTotalModeInfoSize = dwModeInfoSize * dwNumNewModes;
    *ppModeInfo = 
        (PVIDEO_MODE_INFORMATION)EngAllocMem(FL_ZERO_MEMORY, dwTotalModeInfoSize, XENGFX_DISPLAY_ALLOC_TAG);
    if (*ppModeInfo == NULL) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR,
	                     "Unable to allocate mode info buffer of size - %d!\n",
                         dwTotalModeInfoSize); 
        EngFreeMem(pLocalModeInfo);
        return -1;
    }

    for (dwCount=0, pTempInfo = pLocalModeInfo, pNewModeInfo = *ppModeInfo;
         dwCount < dwNumModes; dwCount++) {
        if (!XenGfxIsModeSupported(pTempInfo)) {
            pTempInfo = (PVIDEO_MODE_INFORMATION)((PUCHAR)pTempInfo + sizeof(VIDEO_MODE_INFORMATION));
            continue;
        }
    
        RtlCopyMemory(pNewModeInfo, pTempInfo, sizeof(VIDEO_MODE_INFORMATION));
        pNewModeInfo = (PVIDEO_MODE_INFORMATION)((PUCHAR)pNewModeInfo + sizeof(VIDEO_MODE_INFORMATION));
        pTempInfo = (PVIDEO_MODE_INFORMATION)((PUCHAR)pTempInfo + sizeof(VIDEO_MODE_INFORMATION));
    }

    *pNumModes = dwNumNewModes;
    EngFreeMem(pLocalModeInfo);
    return 0;
}

DWORD XenGfxGetCurrentMode(HANDLE hDrv, DEVMODEW *pDevModew, 
                           PVIDEO_MODE_INFORMATION pCurModeInfo)
{
    PVIDEO_MODE_INFORMATION pAvailableModes, pTempInfo;
    DWORD dwNumModes, dwRet, dwCount;

    if (pCurModeInfo == NULL) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "Invalid video mode pointer passed!\n");
        return -1;
    }

    if (pDevModew->dmBitsPerPel == 0 && pDevModew->dmPelsWidth == 0 &&
        pDevModew->dmPelsHeight == 0 && pDevModew->dmDisplayFrequency == 0)
        XenGfxDebugPrint(DEBUG_LEVEL_INFO, "Devmode info all 0!  Shoudl we choose current mode?\n");

    dwRet = XenGfxGetSupportedModes(hDrv, &pAvailableModes, &dwNumModes);
    if (dwRet != 0) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, 
                         "Get supported modes call within get current mode failed.  Error - %d\n",
                         dwRet);
        return -1;
    }

    for (dwCount=0, pTempInfo = pAvailableModes; dwCount < dwNumModes; dwCount++) {
        if (XenGfxAreModesSame(pTempInfo, pDevModew)) {
            RtlCopyMemory(pCurModeInfo, pTempInfo, sizeof(VIDEO_MODE_INFORMATION));
            break;
        }

        pTempInfo = (PVIDEO_MODE_INFORMATION)((PUCHAR)pTempInfo + sizeof(VIDEO_MODE_INFORMATION));
    }

    EngFreeMem(pAvailableModes);
    return 0;
}

DWORD XenGfxSetCurrentDisplayMode(PPDEV pDev)
{
    DWORD dwRet, dwRetBytes;
    VIDEO_MODE vMode;

    vMode.RequestedMode = pDev->ulMode;
    dwRet =  EngDeviceIoControl(pDev->hDriver, 
                                IOCTL_VIDEO_SET_CURRENT_MODE, &vMode,
                                sizeof(VIDEO_MODE), 0, 0, &dwRetBytes);
    if (dwRet != 0)
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, 
                         "Unable to set current display mode! Error - %d\n",
                         dwRet);

    return dwRet;
}

DWORD XenGfxResetDevice(PPDEV pDev)
{
    DWORD dwRet, dwRetBytes;

    dwRet = EngDeviceIoControl(pDev->hDriver, IOCTL_VIDEO_RESET_DEVICE,
                               0, 0, 0, 0, &dwRetBytes);
    if (dwRet != 0)
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "Reset device failed with error - %d\n", dwRet);

    return dwRet;
}

DWORD XenGfxMapVideoMemory(PPDEV pDev)
{
    DWORD dwRet, dwRetBytes;
    VIDEO_MEMORY videoMem;
    VIDEO_MEMORY_INFORMATION videoMemInfo;

    videoMem.RequestedVirtualAddress = 0;
    dwRet = EngDeviceIoControl(pDev->hDriver, 
                               IOCTL_VIDEO_MAP_VIDEO_MEMORY, 
                               &videoMem, sizeof(VIDEO_MEMORY),
                               &videoMemInfo, 
                               sizeof(VIDEO_MEMORY_INFORMATION), &dwRetBytes);
    if (dwRet != 0) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "Unable to map video memory!  Error - %d\n", dwRet);
        pDev->pFrameBuffer = (PULONG) NULL;
        return dwRet;
    }

    pDev->pFrameBuffer = (PULONG) videoMemInfo.FrameBufferBase;
    return dwRet;
}

DWORD XenGfxUnmapVideoMemory(PPDEV pDev)
{
    DWORD dwRet, dwRetBytes;
    VIDEO_MEMORY videoMem;

    if ( pDev->pFrameBuffer == NULL )
        return 0;

    videoMem.RequestedVirtualAddress = pDev->pFrameBuffer;
    dwRet = EngDeviceIoControl(pDev->hDriver,
                               IOCTL_VIDEO_UNMAP_VIDEO_MEMORY,
                               &videoMem, sizeof(VIDEO_MEMORY),
                               0, 0, &dwRetBytes);

    pDev->pFrameBuffer = (PULONG) NULL;
    if (dwRet != 0 )
         XenGfxDebugPrint(DEBUG_LEVEL_ERROR,
                           "Unable to unmap video memory!  Error - %d\n",
                           dwRet);
    return dwRet;
}

// Core Display Driver

static DRVFN gDispDrvFn[] = 
{
    { INDEX_DrvAssertMode,       (PFN) XenGfxDrvAssertMode     },
    { INDEX_DrvCompletePDEV,     (PFN) XenGfxDrvCompletePDEV   },
    { INDEX_DrvDisableDriver,    (PFN) XenGfxDrvDisableDriver  },
    { INDEX_DrvDisablePDEV,      (PFN) XenGfxDrvDisablePDEV    },
    { INDEX_DrvDisableSurface,   (PFN) XenGfxDrvDisableSurface },
    { INDEX_DrvEnablePDEV,       (PFN) XenGfxDrvEnablePDEV     },
    { INDEX_DrvEnableSurface,    (PFN) XenGfxDrvEnableSurface  },
    { INDEX_DrvGetModes,         (PFN) XenGfxDrvGetModes       }
};

BOOL DrvEnableDriver(IN ULONG iEngineVersion, IN ULONG cj, OUT DRVENABLEDATA *pded)
{
    UNREFERENCED_PARAMETER(iEngineVersion);

    XenGfxDebugPrint(DEBUG_LEVEL_INFO, "In DrvEnableDriver!\n");

    if (pded == NULL) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "DRVENABLEDATA is NULL!\n");
        return FALSE;
    }

    if (cj < sizeof(DRVENABLEDATA)) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "DRVENABLEDATA size too small!\n");
        return FALSE;
    }

    pded->iDriverVersion = DDI_DRIVER_VERSION_NT5_01;
    pded->c = sizeof(gDispDrvFn) / sizeof(DRVFN);
    pded->pdrvfn = gDispDrvFn;

    return TRUE;
}

BOOL XenGfxDrvAssertMode(IN DHPDEV dhpdev, IN BOOL bEnable)
{
    PPDEV pDev = (PPDEV)dhpdev;

    XenGfxDebugPrint(DEBUG_LEVEL_INFO, "In XenGfxDrvAssertMode; Enable - %d\n", bEnable);
    PrintModeInfo(NULL, pDev, NULL);

    if (!bEnable){
        XenGfxResetDevice(pDev);
    } else {
        XenGfxSetCurrentDisplayMode(pDev);
    }
    return TRUE;
}

VOID XenGfxDrvCompletePDEV(IN DHPDEV dhpdev, IN HDEV hdev)
{
    PPDEV pDev = (PPDEV)dhpdev;
    XenGfxDebugPrint(DEBUG_LEVEL_INFO, "In XenGfxDrvCompletePDEV - %x\n", pDev);

    PrintModeInfo(NULL, pDev, NULL);
    pDev->hDev = hdev;
}

VOID XenGfxDrvDisableDriver(VOID)
{
    XenGfxDebugPrint(DEBUG_LEVEL_INFO, "XenGfxDisableDriver\n");
}

VOID XenGfxDrvDisablePDEV(IN DHPDEV dhpdev)
{
    PPDEV pDev = (PPDEV)dhpdev;

    XenGfxDebugPrint(DEBUG_LEVEL_INFO, "XenGfxDrvDisablePDEV - %x\n", pDev);
    EngDeletePalette(pDev->hPalette);
    EngFreeMem(dhpdev);
}

VOID XenGfxDrvDisableSurface(IN DHPDEV dhpdev)
{
    PPDEV pDev = (PPDEV)dhpdev;

    XenGfxDebugPrint(DEBUG_LEVEL_INFO, "XenGfxDrvDisableSurface\n");

    EngDeleteSurface((HSURF)pDev->hBitmap);
}

DHPDEV XenGfxDrvEnablePDEV(IN DEVMODEW *pdm, IN LPWSTR pwszLogAddress, 
                           IN ULONG cPat,  OUT HSURF  *phsurfPatterns, 
                           IN ULONG cjCaps, OUT ULONG *pdevcaps, 
                           IN ULONG cjDevInfo,  OUT DEVINFO *pdi, 
                           IN HDEV hdev, IN LPWSTR pwszDeviceName, 
                           IN HANDLE hDriver)
{
    DWORD dwRet;
    PPDEV pDev;
    VIDEO_MODE_INFORMATION vCurModeInfo;

    XenGfxDebugPrint(DEBUG_LEVEL_INFO, "In XenGfxDrvEnablePDEV\n");

    if (pdm == NULL) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "DevMode pointer is null!\n");
        return NULL;
    }

    dwRet = XenGfxGetCurrentMode(hDriver, pdm, &vCurModeInfo);
    if (dwRet != 0) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR,
                         "Unable to retrieve current mode!  Error - %d\n",
                         dwRet);
        return NULL;
    }

    pDev = EngAllocMem(FL_ZERO_MEMORY, sizeof(PDEV), XENGFX_DISPLAY_ALLOC_TAG);
    if (pDev == NULL) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "Unable to allocate PDEV\n");
        return NULL;
    }

    CopyCurrentModeInfoToPDEV(hDriver, &vCurModeInfo, pDev);
    InitializeDeviceCapabilities(&vCurModeInfo, pdevcaps, cjCaps);
    InitializeDevInfo(&vCurModeInfo, pDev, pdi, cjDevInfo);

    PrintModeInfo(&vCurModeInfo, pDev, pdm);
    XenGfxDebugPrint(DEBUG_LEVEL_INFO, "Returning PDEV - %x\n", pDev);

    return ((DHPDEV)pDev);
}

HSURF XenGfxDrvEnableSurface(IN DHPDEV dhpdev)
{
    SIZEL sizl;
    HBITMAP hBitmap;
    PPDEV pDev = (PPDEV)dhpdev;
    ULONG ulBMPFormat;

    XenGfxDebugPrint(DEBUG_LEVEL_INFO, "In XenGfxDrvEnableSurface\n");
    PrintModeInfo(NULL, pDev, NULL);

    XenGfxSetCurrentDisplayMode(pDev);
    XenGfxMapVideoMemory(pDev);

    sizl.cx = pDev->ulPelsWidth;
    sizl.cy = pDev->ulPelsHeight;
    GetHTAndBMPFormat(pDev->ulBitsPerPel, NULL, &ulBMPFormat);

    /* @TODO: Currently we are not creating a device managed surface.
     * To turn this into a xenvesa framebuffer front end driver
     * we need to create device managed surface and the below with
     * be extended then.
     */
    hBitmap = EngCreateBitmap(sizl, pDev->ulScreenDelta, ulBMPFormat,
                              pDev->ulScreenDelta > 0 ? BMF_TOPDOWN : 0,
                              pDev->pFrameBuffer);
    if (hBitmap == 0) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "EngCreateBitmap failed!\n");
        return 0;
    }                              

    if (EngAssociateSurface((HSURF)hBitmap, pDev->hDev, (FLONG)0) != TRUE) {
        XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "EngAssociateSurface failed!\n");
        return 0;
    }

    pDev->hBitmap = hBitmap;

    return (HSURF)hBitmap;     
}

ULONG XenGfxDrvGetModes(IN HANDLE hDriver, IN ULONG cjSize, OUT DEVMODEW *pdm)
{
    DWORD dwCount, dwRet, dwNumModes = 0;
    PVIDEO_MODE_INFORMATION pModeInfo, pTempInfo;

    dwRet = XenGfxGetSupportedModes(hDriver, &pModeInfo, &dwNumModes);
    if (dwRet != 0 || dwNumModes <= 0 || pModeInfo == NULL) {
         XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "Get supported modes failed!  Error - %d\n", dwRet);
         return 0;
    }

    if (pdm == NULL) {
        EngFreeMem(pModeInfo);
        return dwNumModes * sizeof(DEVMODEW);
    }

    if (cjSize < dwNumModes * sizeof(DEVMODEW)) {
         XenGfxDebugPrint(DEBUG_LEVEL_ERROR, "DEVMODEW buffer size too small!\n");        
         EngFreeMem(pModeInfo);        
         return 0;
    }

    RtlZeroMemory(pdm, dwNumModes * sizeof(DEVMODEW));
    for (dwCount = 0, pTempInfo = pModeInfo; dwCount < dwNumModes; dwCount++) {
        CopyVideoModeInfoToDevModeInfo(pTempInfo, pdm);

        PrintModeInfo(NULL, NULL, pdm);
        pTempInfo = (PVIDEO_MODE_INFORMATION)((PUCHAR)pTempInfo + sizeof(VIDEO_MODE_INFORMATION));
        pdm = (DEVMODEW *)((PUCHAR)pdm + sizeof(DEVMODEW));
    }

    EngFreeMem(pModeInfo);
    return dwNumModes * sizeof(DEVMODEW);
}
