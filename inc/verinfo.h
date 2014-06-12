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

/* Version information common to all files. */

#undef VER_COMPANYNAME_STR
#undef VER_PRODUCTNAME_STR
#undef VER_LEGALCOPYRIGHT_STR
#undef VER_MAJOR_VERSION
#undef VER_MINOR_VERSION
#undef VER_MICRO_VERSION
#undef VER_BUILD_NR

/* The product build system will insert branding here ... */
/*@IMPORT_BRANDING@*/

/* ... otherwise we provide sane defaults when doing a local build. */
#ifndef BRANDING_IMPORTED
#define VER_COMPANYNAME_STR    "OpenXT"
#define VER_PRODUCTNAME_STR    "OpenXT Tools for Virtual Machines"
#define VER_LEGALCOPYRIGHT_STR "Empty"
#define VER_MAJOR_VERSION       6
#define VER_MINOR_VERSION       0
#define VER_MICRO_VERSION       0
#define VER_BUILD_NR            99999
#endif

#define BUILD_VERSION_STRING(_major, _minor, _micro, _build)    \
        #_major ## "." ##                                       \
        #_minor ## "." ##                                       \
        #_micro ## "." ##                                       \
        #_build

#define VER_VERSION_STRING                      \
        BUILD_VERSION_STRING(VER_MAJOR_VERSION, \
                             VER_MINOR_VERSION, \
                             VER_MICRO_VERSION, \
                             VER_BUILD_NR)

