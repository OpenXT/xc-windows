//
// helper.c - Xen Windows Vesa Display Driver helper to
// communicate with miniport and provide debugging support etc.
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



#include "helper.h"
#include <stdarg.h>

static WCHAR *gDllName = L"XENVESA_DISPLAY";
//@TODO: Switch to ERROR level before shipping
static enum XenVesaDebugLevel eDefaultLevel = DEBUG_LEVEL_INFO;

void XenVesaDebugPrint(XenVesaDebugLevel eLevel, char *szMessage, ...)
{
    va_list vaList;
    va_start(vaList, szMessage);

    if ( eLevel >= eDefaultLevel ) 
        EngDebugPrint(STANDARD_DEBUG_PREFIX, szMessage, vaList);
}

BOOL XenVesaIsModeSupported(PVIDEO_MODE_INFORMATION pModeInfo)
{
    /* If number of planes > 1 or banked or non graphics mode
     * do not support the mode.
     */
    if ( pModeInfo->NumberOfPlanes != 1 || 
         !(pModeInfo->AttributeFlags & VIDEO_MODE_GRAPHICS) ||
         pModeInfo->AttributeFlags & VIDEO_MODE_BANKED ||
         ( pModeInfo->BitsPerPlane != 8 && 
	 pModeInfo->BitsPerPlane != 16 &&
         pModeInfo->BitsPerPlane != 24 && 
	 pModeInfo->BitsPerPlane != 32 ) )
        return FALSE;

    return TRUE;
}

BOOL XenVesaAreModesSame(PVIDEO_MODE_INFORMATION pVideoModeInfo, 
                         DEVMODEW *pDevMode)
{
    if ( pDevMode->dmBitsPerPel == 
         pVideoModeInfo->NumberOfPlanes * pVideoModeInfo->BitsPerPlane &&
         pDevMode->dmPelsWidth == pVideoModeInfo->VisScreenWidth &&
         pDevMode->dmPelsHeight == pVideoModeInfo->VisScreenHeight &&
         pDevMode->dmDisplayFrequency == pVideoModeInfo->Frequency )
        return TRUE;

    return FALSE;
}

void GetHTAndBMPFormat(ULONG ulBitCount, PULONG pulHT, PULONG pulBMP)
{
    ULONG ulHTFormat;
    ULONG ulBmpFormat;

    switch(ulBitCount)
    {
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

    if ( pulHT )
        *pulHT = ulHTFormat;
    if ( pulBMP )
        *pulBMP = ulBmpFormat;
}

void PrintModeInfo(PVIDEO_MODE_INFORMATION pVideoModeInfo, PPDEV pDev,
                   DEVMODEW *pDevModeInfo)
{
    if ( pVideoModeInfo != NULL )
        XenVesaDebugPrint(DEBUG_LEVEL_INFO, "Video Mode Info - %d X %d X %d\n",
                          pVideoModeInfo->VisScreenWidth,
                          pVideoModeInfo->VisScreenHeight,
                          pVideoModeInfo->NumberOfPlanes * 
                          pVideoModeInfo->BitsPerPlane);

    if ( pDevModeInfo != NULL )
        XenVesaDebugPrint(DEBUG_LEVEL_INFO, "DEVINFO Mode Info - %d X %d X %d\n", 
                          pDevModeInfo->dmPelsWidth, pDevModeInfo->dmPelsHeight,
                          pDevModeInfo->dmBitsPerPel);

    if ( pDev != NULL )
        XenVesaDebugPrint(DEBUG_LEVEL_INFO, 
                          "PDev Mode Info - %d X %d X %d; Mode - %d\n",
                          pDev->ulPelsWidth, pDev->ulPelsHeight,
                          pDev->ulBitsPerPel, pDev->ulMode);
}

void CopyVideoModeInfoToDevModeInfo(PVIDEO_MODE_INFORMATION pVideoModeInfo, 
                                    DEVMODEW *pDevMode)
{
    RtlCopyMemory(pDevMode->dmDeviceName, gDllName, sizeof(gDllName));
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

void CopyCurrentModeInfoToPDEV(HANDLE hDrv, 
                              PVIDEO_MODE_INFORMATION pVideoModeInfo, 
			      PPDEV pDev)
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

void InitializeDeviceCapabilities(PVIDEO_MODE_INFORMATION pVideoModeInfo, 
                                  ULONG *pGDIInfo, ULONG ulGDISize)
{
    GDIINFO gdi;

    if ( pGDIInfo == NULL || pVideoModeInfo == NULL || 
         ulGDISize  < sizeof(GDIINFO) )
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR, 
 	                  "Invalid input to intialize dev capabilities!\n");
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
    GetHTAndBMPFormat(pVideoModeInfo->NumberOfPlanes * 
                     pVideoModeInfo->BitsPerPlane, &gdi.ulHTOutputFormat, NULL);
    gdi.flHTFlags = HT_FLAG_ADDITIVE_PRIMS;
    gdi.ulVRefresh = pVideoModeInfo->Frequency;

    RtlCopyMemory(pGDIInfo, &gdi, sizeof(GDIINFO));
}


void InitializeDevInfo(PVIDEO_MODE_INFORMATION pVideoModeInfo, PPDEV pDev, 
                       DEVINFO *pDevInfo, ULONG ulDevInfoSize)
{
    if ( pVideoModeInfo == NULL || pDevInfo == NULL || 
         ulDevInfoSize < sizeof(DEVINFO) )
    {
         XenVesaDebugPrint(DEBUG_LEVEL_ERROR, 
 	                   "Invalid input to initialize dev info!\n");
         return;
    }

    RtlZeroMemory(pDevInfo, sizeof(DEVINFO));

    pDevInfo->flGraphicsCaps = GCAPS_OPAQUERECT | GCAPS_LAYERED;
    pDevInfo->cxDither = 8;
    pDevInfo->cyDither = 8;

    GetHTAndBMPFormat(
                 pVideoModeInfo->NumberOfPlanes * pVideoModeInfo->BitsPerPlane,
		 NULL, &pDevInfo->iDitherFormat);
    /* Note: Taking the color mask from video mode info
     * is resulting in palette display issues.  So, going with
     * the below.
     */
    pDev->hPalette = pDevInfo->hpalDefault = EngCreatePalette(PAL_BITFIELDS, 
                            0, NULL, 0xFF0000, 0xFF00, 0xFF);
}

DWORD XenVesaGetNumModesFromMiniport(HANDLE hDrv, PDWORD pNumModes, 
                                     PDWORD pModeInfoSize)
{
    DWORD dwRet, dwRetBytes;
    VIDEO_NUM_MODES videoNumModes;

    if ( pNumModes == NULL || pModeInfoSize == NULL )
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR,
	                  "GetNumModesFromMiniport: Invalid input!\n");
        return -1;
    }

    dwRet = EngDeviceIoControl(hDrv, IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES, 
                               NULL, 0, &videoNumModes, 
			       sizeof(VIDEO_NUM_MODES), &dwRetBytes);
    if ( dwRet != 0 )
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR,
                    "Unable to query number of available modes.  Error - %d\n",
                    dwRet);
        return dwRet;
    }

    *pModeInfoSize = videoNumModes.ModeInformationLength;
    *pNumModes = videoNumModes.NumModes;
    return dwRet;
}

DWORD XenVesaGetModesFromMiniport(HANDLE hDrv, 
                                  PVIDEO_MODE_INFORMATION pModeInfo,
                                  DWORD dwModeInfoSize, DWORD dwNumModes)
{

    DWORD dwRet, dwRetBytes, dwTotalModeInfoSize;

    if ( dwModeInfoSize == 0 || dwNumModes == 0 || pModeInfo == NULL )
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR,
	                  "XenVesaGetModesFromMiniport: Invalid input!\n");
        return -1;
    }

    dwTotalModeInfoSize = dwModeInfoSize * dwNumModes;
    dwRet = EngDeviceIoControl(hDrv, IOCTL_VIDEO_QUERY_AVAIL_MODES, 
                               NULL, 0, pModeInfo, 
			       dwTotalModeInfoSize, &dwRetBytes); 
    if ( dwRet != 0 )
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR,
	                  "Unable to query available modes! Error - %d\n",
			  dwRet);
        return dwRet;
    }

    return dwRet;
}

DWORD XenVesaGetSupportedModes(HANDLE hDrv, PVIDEO_MODE_INFORMATION *ppModeInfo,
                               PDWORD pNumModes)
{
    DWORD dwCount, dwRet, dwModeInfoSize;
    DWORD dwNumModes, dwTotalModeInfoSize, dwNumNewModes;
    PVIDEO_MODE_INFORMATION pLocalModeInfo, pTempInfo, pNewModeInfo;

    if ( ppModeInfo == NULL || pNumModes == NULL )
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR, 
                          "Invalid input param to XenVesaGetSupportedModes!\n");
        return -1;
    }

    dwRet = XenVesaGetNumModesFromMiniport(hDrv, &dwNumModes, &dwModeInfoSize);
    if ( dwRet != 0 || dwModeInfoSize == 0 || dwNumModes == 0 )
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR, 
                  "XenVesaGetNumModesFromMiniport failed!  Error - %d\n",
		  dwRet);
        return -1;
    }

    dwTotalModeInfoSize = dwModeInfoSize * dwNumModes;
    pLocalModeInfo = (PVIDEO_MODE_INFORMATION) EngAllocMem(FL_ZERO_MEMORY, 
                      dwTotalModeInfoSize, XENVESA_DISPLAY_ALLOC_TAG);
    if ( pLocalModeInfo == NULL )
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR, 
	                  "Unable to allocate memory for local mode info!\n");
        return -1;
    }

    dwRet = XenVesaGetModesFromMiniport(hDrv, pLocalModeInfo, 
                                        dwModeInfoSize, dwNumModes);
    if ( dwRet != 0)
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR,
       	                  "XenVesaGetModesFromMiniport failed!  Error - %d\n",
			  dwRet);
        EngFreeMem(pLocalModeInfo);
        return -1;
    }

    for ( dwCount=0, pTempInfo = pLocalModeInfo, dwNumNewModes = 0; 
          dwCount < dwNumModes; dwCount++ )
    {
        if ( XenVesaIsModeSupported(pTempInfo) == FALSE )
        {
            pTempInfo = (PVIDEO_MODE_INFORMATION)((PUCHAR)pTempInfo + 
	                sizeof(VIDEO_MODE_INFORMATION));
            continue;
        }
        
        dwNumNewModes++;
        pTempInfo = (PVIDEO_MODE_INFORMATION)((PUCHAR)pTempInfo + 
	            sizeof(VIDEO_MODE_INFORMATION));
    }

    XenVesaDebugPrint(DEBUG_LEVEL_INFO, 
                      "Number of valid modes - %d, ModeInfoSize is - %d\n",
                      dwNumNewModes, dwModeInfoSize);
    dwTotalModeInfoSize = dwModeInfoSize * dwNumNewModes;
    *ppModeInfo = (PVIDEO_MODE_INFORMATION) EngAllocMem(FL_ZERO_MEMORY, 
                  dwTotalModeInfoSize, XENVESA_DISPLAY_ALLOC_TAG);
    if (*ppModeInfo == NULL )
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR,
	                  "Unable to allocate mode info buffer of size - %d!\n",
                          dwTotalModeInfoSize); 
        EngFreeMem(pLocalModeInfo);
        return -1;
    }

    for ( dwCount=0, pTempInfo = pLocalModeInfo, pNewModeInfo = *ppModeInfo;
          dwCount < dwNumModes; dwCount++ )
    {
        if ( XenVesaIsModeSupported(pTempInfo) == FALSE )
        {
            pTempInfo = (PVIDEO_MODE_INFORMATION)((PUCHAR)pTempInfo + 
	                sizeof(VIDEO_MODE_INFORMATION));
            continue;
        }
    
        RtlCopyMemory(pNewModeInfo, pTempInfo, sizeof(VIDEO_MODE_INFORMATION));
        pNewModeInfo = (PVIDEO_MODE_INFORMATION)((PUCHAR)pNewModeInfo + 
	               sizeof(VIDEO_MODE_INFORMATION));
        pTempInfo = (PVIDEO_MODE_INFORMATION)((PUCHAR)pTempInfo + 
	            sizeof(VIDEO_MODE_INFORMATION));
    }

    *pNumModes = dwNumNewModes;
    EngFreeMem(pLocalModeInfo);
    return 0;
}

DWORD XenVesaGetCurrentMode(HANDLE hDrv, DEVMODEW *pDevModew, 
                            PVIDEO_MODE_INFORMATION pCurModeInfo)
{
    PVIDEO_MODE_INFORMATION pAvailableModes, pTempInfo;
    DWORD dwNumModes, dwRet, dwCount;

    if (pCurModeInfo == NULL )
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR, 
	                  "Invalid video mode pointer passed!\n");
        return -1;
    }

    if ( pDevModew->dmBitsPerPel == 0 && pDevModew->dmPelsWidth == 0 &&
         pDevModew->dmPelsHeight == 0 && pDevModew->dmDisplayFrequency == 0 )
        XenVesaDebugPrint(DEBUG_LEVEL_INFO, 
                      "Devmode info all 0!  Shoudl we choose current mode?\n");

    dwRet = XenVesaGetSupportedModes(hDrv, &pAvailableModes, &dwNumModes);
    if ( dwRet != 0 )
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR, 
       "Get supported modes call within get current mode failed.  Error - %d\n",
        dwRet);
        return -1;
    }

    for ( dwCount=0, pTempInfo = pAvailableModes; dwCount < dwNumModes; 
          dwCount++ )
    {
        if ( XenVesaAreModesSame(pTempInfo, pDevModew) )
        {
            RtlCopyMemory(pCurModeInfo, pTempInfo, 
	                  sizeof(VIDEO_MODE_INFORMATION));
            break;
        }

        pTempInfo = (PVIDEO_MODE_INFORMATION)((PUCHAR)pTempInfo + 
	             sizeof(VIDEO_MODE_INFORMATION));
    }

    EngFreeMem(pAvailableModes);
    return 0;
}

DWORD XenVesaSetCurrentDisplayMode(PPDEV pDev)
{
    DWORD dwRet, dwRetBytes;
    VIDEO_MODE vMode;

    vMode.RequestedMode = pDev->ulMode;
    dwRet =  EngDeviceIoControl(pDev->hDriver, 
                                IOCTL_VIDEO_SET_CURRENT_MODE, &vMode,
				sizeof(VIDEO_MODE), 0, 0, &dwRetBytes);
    if (dwRet != 0 )
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR, 
                          "Unable to set current display mode! Error - %d\n",
                          dwRet);

    return dwRet;
}

DWORD XenVesaResetDevice(PPDEV pDev)
{
    DWORD dwRet, dwRetBytes;

    dwRet = EngDeviceIoControl(pDev->hDriver, IOCTL_VIDEO_RESET_DEVICE,
                               0, 0, 0, 0, &dwRetBytes);
    if ( dwRet != 0)
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR,
                          "Reset device failed with error - %d\n",
                          dwRet);

    return dwRet;
}

DWORD XenVesaMapVideoMemory(PPDEV pDev)
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

    if (dwRet != 0 )
    {
         XenVesaDebugPrint(DEBUG_LEVEL_ERROR, 
	                   "Unable to map video memory!  Error - %d\n",
			   dwRet);
	 pDev->pFrameBuffer = (PULONG) NULL;
         return dwRet;
    }

    pDev->pFrameBuffer = (PULONG) videoMemInfo.FrameBufferBase;
    return dwRet;
}

DWORD XenVesaUnmapVideoMemory(PPDEV pDev)
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
         XenVesaDebugPrint(DEBUG_LEVEL_ERROR,
                           "Unable to unmap video memory!  Error - %d\n",
                           dwRet);
    return dwRet;
}

