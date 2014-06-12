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

/* Private userspace functions.  These are either in xsutil.dll or
 * xs.dll. */
#ifndef XS_PRIVATE_H__
#define XS_PRIVATE_H__

#ifdef XSUTIL_EXPORTS
#define XSUTIL_API __declspec(dllexport)
#else
#define XSUTIL_API __declspec(dllimport)
#endif


#if defined (__cplusplus)
extern "C" {
#endif

struct xs_error_renderer {
    void (WINAPI *render)(struct xs_error_renderer *ths, const char *msg);
};

XSUTIL_API int WINAPI xs_is_physical_session(void);
XSUTIL_API char *WINAPI xs_vasprintf(const char *fmt, va_list args);
XSUTIL_API char *WINAPI xs_asprintf(const char *fmt, ...);
XSUTIL_API void WINAPI xs_win_err(int code, struct xs_error_renderer *,
                                  const char *fmt, ...);
XSUTIL_API void WINAPI xs_vwin_err(int err, int code,
                                   struct xs_error_renderer *,
                                   const char *fmt, va_list args);
XSUTIL_API void WINAPI xs_err(int code, struct xs_error_renderer *,
                              const char *fmt, ...);
XSUTIL_API void WINAPI xs_errx(int code, struct xs_error_renderer *,
                               const char *fmt, ...);

XSUTIL_API void WINAPI xs_win_warn(struct xs_error_renderer *,
                                   const char *fmt, ...);
XSUTIL_API void WINAPI xs_vwin_warn(int code, struct xs_error_renderer *,
                                    const char *fmt, va_list args);
XSUTIL_API void WINAPI xs_warn(struct xs_error_renderer *, const char *fmt,
                               ...);
XSUTIL_API void WINAPI xs_warnx(struct xs_error_renderer *, const char *fmt,
                                ...);

XSUTIL_API extern struct xs_error_renderer xs_render_error_msgbox;
XSUTIL_API extern struct xs_error_renderer xs_render_error_stderr;

XSUTIL_API char *WINAPI xs_vassemble_strings(const char *sep, va_list *args);
XSUTIL_API char *WINAPI xs_assemble_strings(const char *sep, ...);

#ifdef XS2_API
XS2_API int WINAPI xs2_listen_suspend(HANDLE hXS, HANDLE event);
XS2_API BOOL WINAPI xs2_unlisten_suspend(HANDLE hXS);
XS2_API void WINAPI xs2_get_xen_time(HANDLE hXS, FILETIME *out);
XS2_API void WINAPI xs2_make_precious(HANDLE hXS);
XS2_API void WINAPI xs2_unmake_precious(HANDLE hXS);
XS2_API void WINAPI xs2_log(HANDLE hXS, const char *fmt, ...);
XS2_API void WINAPI xs2_vlog(HANDLE hXS, const char *fmt, va_list args);
typedef struct {
    ULONG64 __h;
} WRITE_ON_CLOSE_HANDLE;
static __inline WRITE_ON_CLOSE_HANDLE
wrap_WRITE_ON_CLOSE_HANDLE(ULONG64 x)
{
    WRITE_ON_CLOSE_HANDLE h;
    h.__h = x;
    return h;
}
static __inline ULONG64
unwrap_WRITE_ON_CLOSE_HANDLE(WRITE_ON_CLOSE_HANDLE h)
{
    return h.__h;
}
#define null_WRITE_ON_CLOSE_HANDLE() wrap_WRITE_ON_CLOSE_HANDLE(0)
#define is_null_WRITE_ON_CLOSE_HANDLE(h) ((h).__h == 0)

XS2_API WRITE_ON_CLOSE_HANDLE WINAPI xs2_write_on_close(struct xs2_handle *xih,
                                                        const char *path,
                                                        const void *data,
                                                        size_t data_size);
XS2_API void WINAPI xs2_cancel_write_on_close(struct xs2_handle *xih,
                                              WRITE_ON_CLOSE_HANDLE handle);
#endif

#if defined (__cplusplus)
};
#endif

#if DBG

#include <stdarg.h>         // va_list
#include <stdio.h>          // vsprintf
#include <malloc.h>

#include <assert.h>
#include <tchar.h>

__inline void DebugPrint( IN LPCTSTR msg, IN ... )
{
    TCHAR   buffer[256];
    int     res;
    va_list args;

    va_start( args, msg );
    res = _vsntprintf(buffer, sizeof(buffer) / sizeof(buffer[0]), msg, args);
    if (res >= 0)
    {
        OutputDebugString( buffer );
    }
    else
    {
        TCHAR *p;
        int count;

        count = 512;
        for (;;) {
            p = (TCHAR *)malloc(count * sizeof (TCHAR));
            if (!p) {
                OutputDebugString(_T("Out of memory for debug message!"));
                break;
            }
            res = _vsntprintf(p, count, msg, args);
            if (res >= 0)
                break;

            free(p);
            count += 256;
        }
        if (p) {
            OutputDebugString( p );
            free(p);
        }
    }
    va_end(args);
}

#define DBGPRINT(_x_) DebugPrint _x_
#define ASSERT  assert

#else

#define DBGPRINT(_x_) 
#define ASSERT  

#endif // DBG

#endif /* !XS_PRIVATE_H__ */
