//
// helper.h - Xen Windows Vesa Display Driver helper to
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


#include "xenvesa-display.h"
#include <devioctl.h>

#define STANDARD_DEBUG_PREFIX "XenVesa Display: "
typedef enum {
    DEBUG_LEVEL_INFO,
    DEBUG_LEVEL_WARNING,
    DEBUG_LEVEL_ERROR,
} XenVesaDebugLevel;

void XenVesaDebugPrint(XenVesaDebugLevel eLevel, char *szMessage, ...);

void CopyVideoModeInfoToDevModeInfo(PVIDEO_MODE_INFORMATION pVideoModeInfo,
                                    DEVMODEW *pDevMode);
void CopyCurrentModeInfoToPDEV(HANDLE hDrv, 
                               PVIDEO_MODE_INFORMATION pVideoModeInfo, 
			       PPDEV pDev);
void InitializeDeviceCapabilities(PVIDEO_MODE_INFORMATION pVideoModeInfo, 
                                  ULONG *pGDIInfo, ULONG ulGDISize);
void InitializeDevInfo(PVIDEO_MODE_INFORMATION pVideoModeInfo, PPDEV pDev, 
                       DEVINFO *pDevInfo, ULONG ulDevInfoSize);
void GetHTAndBMPFormat(ULONG ulBitCount, PULONG pulHT, PULONG pulBMP);
void PrintModeInfo(PVIDEO_MODE_INFORMATION pVideoModeInfo, PPDEV pDev,
                   DEVMODEW *pDevModeInfo);

DWORD XenVesaGetSupportedModes(HANDLE hDrv, PVIDEO_MODE_INFORMATION *ppModeInf,
                               PDWORD pNumModes);
DWORD XenVesaGetCurrentMode(HANDLE hDrv, DEVMODEW *pDevModew, 
                            PVIDEO_MODE_INFORMATION pCurModeInfo);
DWORD XenVesaSetCurrentDisplayMode(PPDEV pDev);
DWORD XenVesaResetDevice(PPDEV pDev);
DWORD XenVesaMapVideoMemory(PPDEV pDev);
DWORD XenVesaUnmapVideoMemory(PPDEV pDev);

