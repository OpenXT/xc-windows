//
// xenvesa-display.c - Xen Windows Vesa Display Driver
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


#include "xenvesa-display.h"
#include "helper.h"

static DRVFN gDispDrvFn[] = 
{
    { INDEX_DrvAssertMode,       (PFN) XenVesaDrvAssertMode     },
    { INDEX_DrvCompletePDEV,     (PFN) XenVesaDrvCompletePDEV   },
    { INDEX_DrvDisableDriver,    (PFN) XenVesaDrvDisableDriver  },
    { INDEX_DrvDisablePDEV,      (PFN) XenVesaDrvDisablePDEV    },
    { INDEX_DrvDisableSurface,   (PFN) XenVesaDrvDisableSurface },
    { INDEX_DrvEnablePDEV,       (PFN) XenVesaDrvEnablePDEV     },
    { INDEX_DrvEnableSurface,    (PFN) XenVesaDrvEnableSurface  },
    { INDEX_DrvGetModes,         (PFN) XenVesaDrvGetModes       }
};

BOOL DrvEnableDriver(IN ULONG iEngineVersion, IN ULONG cj, 
                     OUT DRVENABLEDATA *pded)
{
    UNREFERENCED_PARAMETER(iEngineVersion);

    XenVesaDebugPrint(DEBUG_LEVEL_INFO, 
                      "In DrvEnableDriver!\n");

    if ( pded == NULL )
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR, 
	                  "DRVENABLEDATA is NULL!\n");
        return FALSE;
    }

    if ( cj < sizeof(DRVENABLEDATA) )
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR, 
	                  "DRVENABLEDATA size too small!\n");
        return FALSE;
    }

    pded->iDriverVersion = DDI_DRIVER_VERSION_NT5_01;
    pded->c = sizeof(gDispDrvFn) / sizeof(DRVFN);
    pded->pdrvfn = gDispDrvFn;

    return TRUE;
}

BOOL XenVesaDrvAssertMode(IN DHPDEV dhpdev, IN BOOL bEnable)
{
    PPDEV pDev = (PPDEV)dhpdev;

    XenVesaDebugPrint(DEBUG_LEVEL_INFO, 
                      "In XenVesaDrvAssertMode; Enable - %d\n", bEnable);
    PrintModeInfo(NULL, pDev, NULL);

    if ( bEnable == FALSE )
        XenVesaResetDevice(pDev);
    else
        XenVesaSetCurrentDisplayMode(pDev);

    return TRUE;
}

VOID XenVesaDrvCompletePDEV(IN DHPDEV dhpdev, IN HDEV hdev)
{
    PPDEV pDev = (PPDEV)dhpdev;
    XenVesaDebugPrint(DEBUG_LEVEL_INFO, 
                      "In XenVesaDrvCompletePDEV - %x\n", pDev);

    PrintModeInfo(NULL, pDev, NULL);
    pDev->hDev = hdev;
}

VOID XenVesaDrvDisableDriver(VOID)
{
    XenVesaDebugPrint(DEBUG_LEVEL_INFO, 
                      "XenVesaDisableDriver\n");
}

VOID XenVesaDrvDisablePDEV(IN DHPDEV dhpdev)
{
    PPDEV pDev = (PPDEV)dhpdev;
    XenVesaDebugPrint(DEBUG_LEVEL_INFO, 
                      "XenVesaDrvDisablePDEV - %x\n", pDev);

    EngDeletePalette(pDev->hPalette);
    EngFreeMem(dhpdev);
}

VOID XenVesaDrvDisableSurface(IN DHPDEV dhpdev)
{
    PPDEV pDev = (PPDEV)dhpdev;

    XenVesaDebugPrint(DEBUG_LEVEL_INFO, 
                      "XenVesaDrvDisableSurface\n");

    EngDeleteSurface((HSURF)pDev->hBitmap);
    XenVesaUnmapVideoMemory(pDev);
}

DHPDEV XenVesaDrvEnablePDEV(IN DEVMODEW *pdm, IN LPWSTR pwszLogAddress, 
                            IN ULONG cPat,  OUT HSURF  *phsurfPatterns, 
			    IN ULONG cjCaps, OUT ULONG *pdevcaps, 
			    IN ULONG cjDevInfo,  OUT DEVINFO *pdi, 
			    IN HDEV hdev, IN LPWSTR pwszDeviceName, 
			    IN HANDLE hDriver)
{
    DWORD dwRet;
    PPDEV pDev;
    VIDEO_MODE_INFORMATION vCurModeInfo;

    XenVesaDebugPrint(DEBUG_LEVEL_INFO, "In XenVesaDrvEnablePDEV\n");

    if ( pdm == NULL )
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR, "DevMode pointer is null!\n");
        return NULL;
    }

    dwRet = XenVesaGetCurrentMode(hDriver, pdm, &vCurModeInfo);
    if ( dwRet != 0 )
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR,
                          "Unable to retrieve current mode!  Error - %d\n",
                          dwRet);
        return NULL;
    }

    pDev = EngAllocMem(FL_ZERO_MEMORY, sizeof(PDEV), XENVESA_DISPLAY_ALLOC_TAG);
    if ( pDev == NULL )
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR, "Unable to allocate PDEV\n");
        return NULL;
    }

    CopyCurrentModeInfoToPDEV(hDriver, &vCurModeInfo, pDev);
    InitializeDeviceCapabilities(&vCurModeInfo, pdevcaps, cjCaps);
    InitializeDevInfo(&vCurModeInfo, pDev, pdi, cjDevInfo);

    PrintModeInfo(&vCurModeInfo, pDev, pdm);
    XenVesaDebugPrint(DEBUG_LEVEL_INFO, "Returning PDEV - %x\n", pDev);
    return ((DHPDEV)pDev);
}

HSURF XenVesaDrvEnableSurface(IN DHPDEV dhpdev)
{
    SIZEL sizl;
    HBITMAP hBitmap;
    PPDEV pDev = (PPDEV)dhpdev;
    ULONG ulBMPFormat;

    XenVesaDebugPrint(DEBUG_LEVEL_INFO, "In XenVesaDrvEnableSurface\n");
    PrintModeInfo(NULL, pDev, NULL);

    XenVesaSetCurrentDisplayMode(pDev);
    XenVesaMapVideoMemory(pDev);

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
    if (hBitmap == 0 )
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR, "EngCreateBitmap failed!\n");
        return 0;
    }                              

    if ( EngAssociateSurface((HSURF)hBitmap, pDev->hDev, (FLONG)0) != TRUE )
    {
        XenVesaDebugPrint(DEBUG_LEVEL_ERROR, "EngAssociateSurface failed!\n");
        return 0;
    }

    pDev->hBitmap = hBitmap;
    return (HSURF)hBitmap;
     
}

ULONG XenVesaDrvGetModes(IN HANDLE hDriver, IN ULONG cjSize, OUT DEVMODEW *pdm)
{
    DWORD dwCount, dwRet, dwNumModes = 0;
    PVIDEO_MODE_INFORMATION pModeInfo, pTempInfo;

    dwRet = XenVesaGetSupportedModes(hDriver, &pModeInfo, &dwNumModes);
    if ( dwRet != 0 || dwNumModes <= 0 || pModeInfo == NULL)
    {
         XenVesaDebugPrint(DEBUG_LEVEL_ERROR, 
	                   "Get supported modes failed!  Error - %d\n",
			   dwRet);
         return 0;
    }

    if ( pdm == NULL )
    {
        EngFreeMem(pModeInfo);
        return dwNumModes * sizeof(DEVMODEW);
    }

    if ( cjSize < dwNumModes * sizeof(DEVMODEW) )
    {
         XenVesaDebugPrint(DEBUG_LEVEL_ERROR, 
	                   "DEVMODEW buffer size too small!\n");        
         EngFreeMem(pModeInfo);        
         return 0;
    }

    RtlZeroMemory(pdm, dwNumModes * sizeof(DEVMODEW));
    for ( dwCount = 0, pTempInfo = pModeInfo; dwCount < dwNumModes; dwCount++ )
    {
        CopyVideoModeInfoToDevModeInfo(pTempInfo, pdm);

        PrintModeInfo(NULL, NULL, pdm);
        pTempInfo = (PVIDEO_MODE_INFORMATION)((PUCHAR)pTempInfo + 
	            sizeof(VIDEO_MODE_INFORMATION));
        pdm = (DEVMODEW *)((PUCHAR)pdm + sizeof(DEVMODEW));
    }

    EngFreeMem(pModeInfo);
    return dwNumModes * sizeof(DEVMODEW);
}


