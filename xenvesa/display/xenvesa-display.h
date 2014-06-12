//
// xenvesa-display.h - Xen Windows Vesa Display Driver
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


#ifndef _XENVESA_DISPLAY_H_
#define _XENVESA_DISPLAY_H_

#include <windef.h>
#include <wingdi.h>
#include <winddi.h>
#include <ntddvdeo.h>

#define XENVESA_DISPLAY_ALLOC_TAG  0x58454E76

typedef struct  _PDEV
{
    HANDLE         hDriver;
    HDEV           hDev;
    HBITMAP        hBitmap;
    HPALETTE       hPalette;

    ULONG          ulMode;
    ULONG          ulPelsWidth;
    ULONG          ulPelsHeight;
    ULONG          ulBitsPerPel;
    ULONG          ulFrequency;
    ULONG          ulScreenDelta;

    PULONG         pFrameBuffer;
} PDEV, *PPDEV;

BOOL XenVesaDrvAssertMode(IN DHPDEV dhpdev, IN BOOL bEnable);
VOID XenVesaDrvCompletePDEV(IN DHPDEV dhpdev, IN HDEV hdev);
VOID XenVesaDrvDisableDriver(VOID);
VOID XenVesaDrvDisablePDEV(IN DHPDEV dhpdev);
VOID XenVesaDrvDisableSurface(IN DHPDEV dhpdev);
DHPDEV XenVesaDrvEnablePDEV(IN DEVMODEW *pdm, 
                            IN LPWSTR pwszLogAddress, IN ULONG cPat, 
			    OUT HSURF  *phsurfPatterns, IN ULONG cjCaps, 
			    OUT ULONG *pdevcaps, IN ULONG cjDevInfo, 
			    OUT DEVINFO *pdi, IN HDEV hdev, 
			    IN LPWSTR pwszDeviceName, IN HANDLE hDriver);
HSURF XenVesaDrvEnableSurface(IN DHPDEV dhpdev);
ULONG XenVesaDrvGetModes(IN HANDLE hDriver, IN ULONG cjSize, OUT DEVMODEW *pdm);

#endif /* _XENVESA_DISPLAY_H_ */

