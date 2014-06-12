//
// xengfxd3d.h - Xen Windows WDDM D3D Display Driver
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


#ifndef XENGFXD3D_H
#define XENGFXD3D_H

#include "d3d.h"

VOID XenD3dDbgLog(CONST CHAR *pFormat, ...);

#ifndef DBG
#define XenD3dTraceDebug(a) XenD3dDbgLog a
#else
#define XenD3dTraceDebug(a) do {} while (FALSE)
#endif

typedef struct _XENGFX_D3D_ADAPTER {
    HANDLE hAdapter;
    UINT Interface;
    UINT Version;
    D3DDDI_ADAPTERCALLBACKS AdapterCallbacks;
    XENGFX_UMDRIVERPRIVATE UMDriverPrivate;
} XENGFX_D3D_ADAPTER, *PXENGFX_D3D_ADAPTER;

typedef struct _XENGFX_D3D_DEVICE {
    XENGFX_D3D_ADAPTER *pXenD3dAdapter;
    HANDLE hDevice;
    UINT Interface;
    UINT Version;
    D3DDDI_DEVICECALLBACKS DeviceCallbacks;
    D3DDDI_CREATEDEVICEFLAGS Flags;
} XENGFX_D3D_DEVICE, *PXENGFX_D3D_DEVICE;

#endif //XENGFXD3D_H
