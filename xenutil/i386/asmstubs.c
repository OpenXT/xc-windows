/*
 * Copyright (c) 2009 Citrix Systems, Inc.
 * 
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

#include <wdm.h>
#include "xsapi.h"
#include "scsiboot.h"
#include "hvm.h"

VOID
_cpuid(ULONG leaf, ULONG *peax, ULONG *pebx, ULONG *pecx,
       ULONG *pedx)
{
    ULONG reax, rebx, recx, redx;
    _asm {
        mov ebx, 0x72746943;
        mov ecx, 0x582f7869;
        mov edx, 0x56506e65;
        mov eax, leaf;
        cpuid;
        mov reax, eax;
        mov rebx, ebx;
        mov recx, ecx;
        mov redx, edx;
    };
    *peax = reax;
    *pebx = rebx;
    *pecx = recx;
    *pedx = redx;
}

ULONG_PTR
_readcr3(VOID)
{
    uint32_t pd;

    _asm{
        _emit 0x0f;
        _emit 0x20;
        _emit 0xd8;
        mov pd, eax;
    }

    return pd;
}

ULONG_PTR
_readcr4(VOID)
{
    uint32_t pd;

    _asm{
        _emit 0x0f;
        _emit 0x20;
        _emit 0xe0;
        mov pd, eax;
    }

    return pd;
}

VOID
_wrmsr(uint32_t msr, uint32_t lowbits, uint32_t highbits)
{
    _asm {
        mov eax, lowbits;
        mov edx, highbits;
        mov ecx, msr;
        wrmsr;
    };
}

