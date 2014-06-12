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

#include <wrapper_types.h>

#ifndef _GNTMAP_H
#define _GNTMAP_H

#ifdef XSAPI_FUTURE_GRANT_MAP
__MAKE_WRAPPER_PRIV(ALIEN_GRANT_REF, xen_grant_ref_t)
static __inline ALIEN_GRANT_REF
wrap_ALIEN_GRANT_REF(xen_grant_ref_t x)
{
    return __wrap_ALIEN_GRANT_REF(x ^ 0xbeefbeef);
}
static __inline xen_grant_ref_t
unwrap_ALIEN_GRANT_REF(ALIEN_GRANT_REF x)
{
    return __unwrap_ALIEN_GRANT_REF(x) ^ 0xbeefbeef;
}
#endif

#endif  // _GNTMAP_H


