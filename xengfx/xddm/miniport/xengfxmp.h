//
// xengfxmp.h - Xen Windows PV XDDM Miniport Driver
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


#ifndef XENGFXMP_H
#define XENGFXMP_H

#include <ntstatus.h>
#include <miniport.h>
#include <ntddvdeo.h>
#include <video.h>
#include <devioctl.h>
#include <dderror.h>
#include "xengfx_shared.h"
#include "xengfx_regs.h"

typedef struct _XENGFX_DEVICE_EXTENSION
{
    volatile LONG Initialized;
    BOOLEAN NoIrq;
    BOOLEAN XgfxMode;

    PUCHAR pXgfxRegBase;
    PUCHAR pGlobal;
    PUCHAR pVCrtc0;
    PUCHAR pGart;

    PHYSICAL_ADDRESS GraphicsApertureBase;

    ULONG MaxHorizontal;
    ULONG MaxVertical;
    ULONG StrideAlignment;

    ULONG ModeCount;
    ULONG ModeIndex;
    ULONG MaxStride;
    ULONG MaxHeight;
    XENGFX_MODE *pModes;

    XENGFX_EDID *pEdid;
    PHYSICAL_ADDRESS EdidPageBase;

    PVOID pSystemBuffer;
    PVOID pSystemBufferContext;
    ULONG SystemBufferSize;

    PULONG32 pGartBaseReg;
    PULONG32 pGartMappingReg;
    ULONG StolenPfns;    

    // DualView support (not currently supported)
    ULONG DualViewSupport;
    BOOLEAN IsPrimary;
    struct _XENGFX_DEVICE_EXTENSION *pPrimaryExtension;

} XENGFX_DEVICE_EXTENSION, *PXENGFX_DEVICE_EXTENSION;

#endif // XENGFXMP_H
