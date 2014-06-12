//
// d3d.h
//
// D3D Definitions shared between the display and miniport drivers.
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


#ifndef D3D_H
#define D3D_H

#define XENGFX_D3D_MAGIC        0x44334458 // 'XD3D'
#define XENGFX_D3D_VERSION      0x1
#define XENGFX_D3D_FORMAT_COUNT 7

// Zero is unused by D3DKMDT_STANDARDALLOCATION_TYPE
typedef enum _XENGFX_STANDARDALLOCATION_TYPE {
    XENGFX_USERALLOCATION_TYPE       = 0,
    XENGFX_SHAREDPRIMARYSURFACE_TYPE = 1,
    XENGFX_SHADOWSURFACE_TYPE        = 2,
    XENGFX_STAGINGSURFACE_TYPE       = 3
} XENGFX_STANDARDALLOCATION_TYPE;

#define XENGFX_ALLOCATION_STATE_NONE         0x00000000
#define XENGFX_ALLOCATION_STATE_ASSIGNED     0x00000001
#define XENGFX_ALLOCATION_STATE_VISIBLE      0x00000002

typedef struct _XENGFX_UMDRIVERPRIVATE {
    ULONG Magic;
    ULONG Version;
    USHORT VendorId;
    USHORT DeviceId;
    ULONG ApertureSize;
    GUID AdapterGuid;
} XENGFX_UMDRIVERPRIVATE, *PXENGFX_UMDRIVERPRIVATE;

typedef struct _XENGFX_SURFACE_DESC {
    ULONG XResolution;
    ULONG YResolution;
    ULONG BytesPerPixel;
    ULONG Stride;
    D3DDDIFORMAT Format;
    D3DDDI_RATIONAL RefreshRate;
} XENGFX_SURFACE_DESC, *PXENGFX_SURFACE_DESC;

typedef struct _XENGFX_D3D_ALLOCATION {
    XENGFX_STANDARDALLOCATION_TYPE Type;
    BOOLEAN Primary;
    D3DDDI_VIDEO_PRESENT_SOURCE_ID VidPnSourceId;
    XENGFX_SURFACE_DESC SurfaceDesc;
    ULONG ByteAlignment; // StrideAlignment + 1 for alignment bytes    
} XENGFX_D3D_ALLOCATION, *PXENGFX_D3D_ALLOCATION;

#endif //D3D_H
