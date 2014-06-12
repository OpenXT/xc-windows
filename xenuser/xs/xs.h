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

/**************************************************************************
 *
 * XS.DLL IS OBSOLETE AND SHOULD NOT BE USED FOR NEW PROGRAMS.  THIS IS
 * PURELY A COMPATIBILITY LAYER OVER XS2.DLL.
 *
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 * DO NOT USE
 */
#ifndef _XS_H_
#define _XS_H_

#include <windows.h>

#ifdef XSAPI_EXPORTS
    #ifdef XSAPI_STATIC_LIB
    #define XS_API
    #else
    #define XS_API __declspec(dllexport)
    #endif
#else
    #ifdef XSAPI_STATIC_LIB
    #define XS_API  extern
    #else
    #define XS_API __declspec(dllimport)
    #endif
#endif


#if defined (__cplusplus)
extern "C" {
#endif

/* DO NOT USE */
XS_API HANDLE __cdecl xs_domain_open(void);
/* DO NOT USE */
XS_API void __cdecl xs_daemon_close(HANDLE hXS);
/* DO NOT USE */
XS_API BOOL __cdecl xs_transaction_start(HANDLE hXS);
/* DO NOT USE */
XS_API BOOL __cdecl xs_transaction_end(HANDLE hXS, BOOL fAbort);
/* DO NOT USE */
XS_API BOOL __cdecl xs_write( HANDLE hXS, const char *path, const char *data);
/* DO NOT USE */
XS_API BOOL __cdecl xs_write_bin( HANDLE hXS, const char *path,
                                const void *data, size_t size);
/* DO NOT USE */
XS_API char ** __cdecl xs_directory(HANDLE hXS, const char *path,
                                  unsigned int *num);
/* DO NOT USE */
XS_API void * __cdecl xs_read(HANDLE hXS, const char *path, size_t *len);
/* DO NOT USE */
XS_API BOOL __cdecl xs_remove( HANDLE hXS, const char *path);
/* DO NOT USE */
XS_API int __cdecl xs_watch( HANDLE hXS, const char *path, HANDLE event);
/* DO NOT USE */
XS_API BOOL __cdecl xs_unwatch(HANDLE hXS, int handle);
/* DO NOT USE */
XS_API VOID __cdecl xs_free(void *mem);

#if defined (__cplusplus)
};
#endif

#endif // _XS_H_
