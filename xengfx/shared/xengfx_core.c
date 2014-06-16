//
// xengfx_core.c - Core XGFX support routines
//
// Copyright (c) 2008 Citrix, Inc.
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


#include <ntddk.h>
#include <ntstrsafe.h>
#include "xengfx_shared.h"
#include "xengfx_regs.h"

// Standard 32 BPP Mode set
typedef struct _XENGFX_STD_MODE {
    ULONG32 XResolution;
    ULONG32 YResolution;
    ULONG32 AspectN;
    ULONG32 AspectD;
    ULONG32 InBaseSet;
} XENGFX_STD_MODE;

static const XENGFX_STD_MODE g_StandardModes[] = {
    {800, 600, 4, 3, 1},
    {1024, 768, 4, 3, 1},
    {1400, 1050, 4, 3, 0},
    {1600, 1200, 4, 3, 0},
    {1280, 1024, 5, 4, 0},
    {1280, 800, 8, 5, 0},
    {1440, 900, 8, 5, 0},
    {1680, 1050, 8, 5, 0},
    {1920, 1200, 8, 5, 0},
    {2560, 1600, 8, 5, 0},
    {1600, 900, 16, 9, 0},
    {1920, 1080, 16, 9, 0},
    {0, 0, 0, 0, 0},
};

static __inline ULONG32
XenGfxGCD(ULONG32 m, ULONG32 n)
{
    ULONG32 r;

    if (m < n) {
        r = m;
        m = n;
        n = r;
    }
	
    for ( ; ; ) {
        r = m % n;
        if (r == 0)
            break;
        m = n; n = r;
    }
    return n;
}

ULONG NTAPI
XenGfxCreateModes(XENGFX_MODE_VALUES *pModeValues)
{
    XENGFX_TIMING_DESCRIPTOR *pDescriptor;
    XENGFX_STD_MODE Mode;
    const XENGFX_STD_MODE *pStdModes;
    XENGFX_MODE *pModes;
    USHORT Gcd;
    ULONG Count, i = 0;
    BOOLEAN Add = TRUE;
    ULONG BitsPerPixel = XenGfxGetBitsPerPixel(pModeValues->XgfxFormat);

    if ((pModeValues->pEdid == NULL)||
        (pModeValues->MaxHorizontal == 0)||
        (pModeValues->MaxVertical == 0)) {
        TraceError(("%s Invalid argument(s) (pEdid = %p MaxHorizontal = 0x%x MaxVertical = 0x%x)\n",
                    __FUNCTION__, pModeValues->pEdid, pModeValues->MaxHorizontal, pModeValues->MaxVertical));
        return 0;
    }

    // First, locate the resolution reported in the EDID descriptor #1 for
    // the monitor associated with VCRTC0.
    pDescriptor = (XENGFX_TIMING_DESCRIPTOR*)(&pModeValues->pEdid->Descriptor1);
    Mode.XResolution = pDescriptor->HorizontalActive & 0x00FF;
    Mode.XResolution |= ((pDescriptor->HorizontalActiveHigh << 4) & 0x0F00);
    Mode.YResolution = pDescriptor->VerticalActive & 0x00FF;
    Mode.YResolution |= ((pDescriptor->VerticalActiveHigh << 4) & 0x0F00);
    Gcd = (USHORT)XenGfxGCD(Mode.XResolution, Mode.YResolution);
    ASSERT(Gcd > 0);
    Mode.AspectN = Mode.XResolution/Gcd;
    Mode.AspectD = Mode.YResolution/Gcd;
    if ((Mode.XResolution > pModeValues->MaxHorizontal)||
        (Mode.YResolution > pModeValues->MaxVertical)) {
        TraceWarning(("%s Resolution reported by EDID greater than max VCRTC0 values?\n", __FUNCTION__));
        TraceWarning(("%s EDID x=0x%x y=0x%x MAX x=0x%x y=0x%x\n", __FUNCTION__,
                      Mode.XResolution, Mode.YResolution,
                      pModeValues->MaxHorizontal, pModeValues->MaxVertical));
        Add = FALSE;
    }

    // Allocate an array - it will be bigger than what we need but not enough
    // to be an issue.
    Count = sizeof(g_StandardModes)/sizeof(XENGFX_STD_MODE) + 1;
    pModes = (XENGFX_MODE*)ExAllocatePoolWithTag(NonPagedPool,
                                                 Count*sizeof(XENGFX_MODE),
                                                 XENGFX_TAG);
    if (pModes == NULL) {
        TraceError(("%s Failed to allocate a Modes array!\n", __FUNCTION__));
        return 0;
    }
    RtlZeroMemory(pModes, Count*sizeof(XENGFX_MODE));

    // Loop and load standard modes along with the mode from the EDID
    for (pStdModes = g_StandardModes; (pStdModes->XResolution != 0); pStdModes++) {
        // If the EDID mode is in the list, don't add it
        if ((pStdModes->XResolution == Mode.XResolution)&&
            (pStdModes->YResolution == Mode.YResolution))
            Add = FALSE;

        // If a mode is larger than the EDID mode don't use it
        if ((pStdModes->XResolution > Mode.XResolution)||
            (pStdModes->YResolution > Mode.YResolution))
            continue;

        // If a mode is larger than the max values don't use it
        if ((pStdModes->XResolution > pModeValues->MaxHorizontal)||
            (pStdModes->YResolution > pModeValues->MaxVertical))
            continue;

        // Load any that have InBaseSet set or have matching aspect ratios
        if ((pStdModes->InBaseSet == 1)||
            ((pStdModes->AspectN == Mode.AspectN)&&(pStdModes->AspectD == Mode.AspectD))) {
            pModes[i].XResolution = pStdModes->XResolution;
            pModes[i].YResolution = pStdModes->YResolution;
            pModes[i].BitsPerPixel = BitsPerPixel;
            pModes[i].ScreenStride = XENGFX_MASK_ALIGN(((BitsPerPixel >> 3)*pStdModes->XResolution),
                                                       pModeValues->StrideAlignment);
            pModes[i].XgfxFormat = pModeValues->XgfxFormat;
            if (pStdModes->InBaseSet == 1)
               pModes[i].Flags |= XENGFX_MODE_FLAG_BASE_SET;

            pModeValues->MaxStride =
                XENGFX_MAX(pModeValues->MaxStride, pModes[i].ScreenStride);
            pModeValues->MaxHeight =
                XENGFX_MAX(pModeValues->MaxHeight, pStdModes->YResolution);            
            i++;
        }
    }

    // Add EDID mode values at the end
    if (Add) {
        pModes[i].XResolution = Mode.XResolution;
        pModes[i].YResolution = Mode.YResolution;
        pModes[i].BitsPerPixel = BitsPerPixel;
        pModes[i].ScreenStride = XENGFX_MASK_ALIGN(((BitsPerPixel >> 3)*Mode.XResolution),
                                                   pModeValues->StrideAlignment);
        pModes[i].XgfxFormat = pModeValues->XgfxFormat;
        pModeValues->MaxStride =
            XENGFX_MAX(pModeValues->MaxStride, pModes[i].ScreenStride);
        pModeValues->MaxHeight =
            XENGFX_MAX(pModeValues->MaxHeight, Mode.YResolution);
        pModes[i].Flags |= XENGFX_MODE_FLAG_EDID_MODE;
        i++;
    }

    pModeValues->pModes = pModes;
    return i; // Mode count
}

ULONG NTAPI
XenGfxCreateBaseSetModes(XENGFX_MODE_VALUES *pModeValues)
{
    const XENGFX_STD_MODE *pStdModes;
    XENGFX_MODE *pModes;
    ULONG Count, i = 0;
    ULONG BitsPerPixel = XenGfxGetBitsPerPixel(pModeValues->XgfxFormat);

    // Allocate an array - it will be bigger than what we need but not enough
    // to be an issue.
    Count = sizeof(g_StandardModes)/sizeof(XENGFX_STD_MODE);
    pModes = (XENGFX_MODE*)ExAllocatePoolWithTag(NonPagedPool,
                                                 Count*sizeof(XENGFX_MODE),
                                                 XENGFX_TAG);
    if (pModes == NULL) {
        TraceError(("%s Failed to allocate a Modes array!\n", __FUNCTION__));
        return 0;
    }
    RtlZeroMemory(pModes, Count*sizeof(XENGFX_MODE));

    // Loop and load standard base set modes
    for (pStdModes = g_StandardModes; (pStdModes->XResolution != 0); pStdModes++) {
        // Load any that have InBaseSet set
        if (pStdModes->InBaseSet == 1) {
            pModes[i].XResolution = pStdModes->XResolution;
            pModes[i].YResolution = pStdModes->YResolution;
            pModes[i].BitsPerPixel = BitsPerPixel;
            pModes[i].ScreenStride = XENGFX_MASK_ALIGN(((BitsPerPixel >> 3)*pStdModes->XResolution),
                                                       pModeValues->StrideAlignment);
            pModes[i].XgfxFormat = pModeValues->XgfxFormat;
            pModes[i].Flags |= XENGFX_MODE_FLAG_BASE_SET;

            pModeValues->MaxStride =
                XENGFX_MAX(pModeValues->MaxStride, pModes[i].ScreenStride);
            pModeValues->MaxHeight =
                XENGFX_MAX(pModeValues->MaxHeight, pStdModes->YResolution);            
            i++;
        }
    }

    pModeValues->pModes = pModes;
    return (i - 1); // Mode count
}

VOID NTAPI
XenGfxReleaseModes(XENGFX_MODE *pModes)
{
    if (pModes != NULL)
        ExFreePoolWithTag(pModes, XENGFX_TAG);
}

ULONG NTAPI
XenGfxGetBitsPerPixel(ULONG XgfxFormat)
{
    switch (XgfxFormat) {
    case XGFX_VCRTC_VALID_FORMAT_RGB555:
    case XGFX_VCRTC_VALID_FORMAT_BGR555:
    case XGFX_VCRTC_VALID_FORMAT_RGB565:
    case XGFX_VCRTC_VALID_FORMAT_BGR565:
        return 16;
    case XGFX_VCRTC_VALID_FORMAT_RGB888:
    case XGFX_VCRTC_VALID_FORMAT_BGR888:
        return 24;
    case XGFX_VCRTC_VALID_FORMAT_RGBX8888:
    case XGFX_VCRTC_VALID_FORMAT_BGRX8888:
        return 32;
    case XGFX_VCRTC_VALID_FORMAT_NONE:
    default:
        return XENGFX_UNSET_BPP;
    };
}
