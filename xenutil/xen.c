/*
 * Copyright (c) 2012 Citrix Systems, Inc.
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

#include "xenutl.h"

static ULONG XenCPUIDBaseLeaf = 0x40000000;

VOID
XenCpuid(ULONG leaf, ULONG *peax, ULONG *pebx, ULONG *pecx, ULONG *pedx)
{
    _cpuid(leaf + XenCPUIDBaseLeaf, peax, pebx, pecx, pedx);
}

BOOLEAN
CheckXenHypervisor(void)
{
    ULONG eax, ebx ='fool', ecx = 'beef', edx = 'dead';
    char signature[13];

    //
    // Check that we're running on Xen and that CPUID supports leaves up to
    // at least 0x40000002 which we need to get the hypercall page info.
    //
    // Note: The Xen CPUID leaves may have been shifted upwards by a
    // multiple of 0x100.
    //

    for (; XenCPUIDBaseLeaf <= 0x40000100; XenCPUIDBaseLeaf += 0x100)
    {
        _cpuid(XenCPUIDBaseLeaf, &eax, &ebx, &ecx, &edx);

        *(ULONG*)(signature + 0) = ebx;
        *(ULONG*)(signature + 4) = ecx;
        *(ULONG*)(signature + 8) = edx;
        signature[12] = 0;
        if ( ((strcmp("XenVMMXenVMM", signature) == 0)||
              (strcmp("XciVMMXciVMM", signature) == 0))&&
               (eax >= (XenCPUIDBaseLeaf + 2)))
        {
            return TRUE;
        }
    }
    return FALSE;
}


