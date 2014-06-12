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

PVOID XenevtchnAllocIoMemory(ULONG nr_bytes, PHYSICAL_ADDRESS *pa);
PFN_NUMBER XenevtchnAllocIoPFN(void);
void XenevtchnReleaseIoMemory(PVOID va, ULONG nr_bytes);
void XenevtchnReleaseIoPFN(PFN_NUMBER pfn);

VOID __XenevtchnShutdownIoHole(const char *module);
#define XenevtchnShutdownIoHole() \
        __XenevtchnShutdownIoHole(XENTARGET);

VOID __XenevtchnInitIoHole(const char *module, PHYSICAL_ADDRESS base, PVOID base_va, ULONG nbytes);
#define XenevtchnInitIoHole(_base, _base_va, _nbytes) \
        __XenevtchnInitIoHole(XENTARGET, (_base), (_base_va), (_nbytes))

BOOLEAN __XenevtchnIsMyIoHole(const char *module);
#define XenevtchnIsMyIoHole() \
        __XenevtchnIsMyIoHole(XENTARGET)

