/*
 * Copyright (c) 2007 Citrix Systems, Inc.
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

/* Shims which make it easier to work with a bunch of different DDKs */
#ifndef XSCOMPAT_H__
#define XSCOMPAT_H__

/* An actual Linux- or Xen-style memory barrier.  Inhibits both
   compiler and processor reorderings. */
__declspec(inline)
VOID
XsMemoryBarrier(void)
{
    KeMemoryBarrier();
    _ReadWriteBarrier();
}

/* Likewise for reads */
__declspec(inline)
VOID
XsReadMemoryBarrier(void)
{
    _mm_lfence();
    _ReadBarrier();
}

/* And for writes */
__declspec(inline)
VOID
XsWriteMemoryBarrier(void)
{
    /* x86 already guarantees not to re-order writes, so don't need a
       processor barrier here.  Still need the compiler barrier,
       though. */
    _WriteBarrier();
}

#endif /* !XSCOMPAT_H__ */
