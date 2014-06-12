/*
 * Copyright (c) 2010 Citrix Systems, Inc.
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

/* A collection of various user-space utility functions which are
   shared between several programs. */
#include <windows.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include "xs_private.h"
#include "xs2.h"

typedef DWORD WTSGetActiveConsoleSessionId_t(void);

/* Ick ick ick.  Our build VMs don't have wtsapi32.h, so just copy and
   paste chunks of it in here. */
typedef enum _WTS_INFO_CLASS {
    WTSInitialProgram,
    WTSApplicationName,
    WTSWorkingDirectory,
    WTSOEMId,
    WTSSessionId,
    WTSUserName,
    WTSWinStationName,
    WTSDomainName,
    WTSConnectState,
    WTSClientBuildNumber,
    WTSClientName,
    WTSClientDirectory,
    WTSClientProductId,
    WTSClientHardwareId,
    WTSClientAddress,
    WTSClientDisplay,
    WTSClientProtocolType,
} WTS_INFO_CLASS;

#define WTS_CURRENT_SESSION ((DWORD)-1)
#define WTS_CURRENT_SERVER_HANDLE  ((HANDLE)NULL)

BOOL WINAPI WTSQuerySessionInformationA(HANDLE hServer,
                                        DWORD SessionId,
                                        WTS_INFO_CLASS WTSInfoClass,
                                        LPSTR * ppBuffer,
                                        DWORD * pBytesReturned);

VOID WINAPI WTSFreeMemory(PVOID pMemory);

int WINAPI xs_uninstalling(void) { 
	struct xs2_handle *xs_handle;
	xs_handle = xs2_open();
	if (!xs_handle)
		return -1;
	if(!xs2_write(xs_handle, "attr/PVAddonsUninstalled", "1"))
	{
		xs2_close(xs_handle);
		return -1;
	}
	xs2_close(xs_handle);
	return 0;
}

int WINAPI
xs_is_physical_session(void)
{
    HMODULE kernel32;
    WTSGetActiveConsoleSessionId_t *WTSGetActiveConsoleSessionId;
    DWORD consoleSession;
    DWORD currentSession;
    LPSTR currentSessionP;
    DWORD currentSessionSize;

    if (!WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE,
                                     WTS_CURRENT_SESSION,
                                     WTSSessionId,
                                     &currentSessionP,
                                     &currentSessionSize)) {
        return -1;
    }
    if (currentSessionSize != sizeof(ULONG)) {
        WTSFreeMemory(currentSessionP);
        return -1;
    }
    currentSession = *(ULONG *)currentSessionP;
    WTSFreeMemory(currentSessionP);

    kernel32 = LoadLibrary("kernel32.dll");
    if (!kernel32) {
        /* Huh? */
        return -1;
    }
    WTSGetActiveConsoleSessionId = (WTSGetActiveConsoleSessionId_t *)
        GetProcAddress(kernel32, "WTSGetActiveConsoleSessionId");
    if (!WTSGetActiveConsoleSessionId) {
        /* Probably on Windows 2000 -> assume not in rdp if we're in
           session 0. */
        FreeLibrary(kernel32);
        if (currentSession == 0)
            return 1;
        else
            return 0;
    }
    consoleSession = WTSGetActiveConsoleSessionId();
    FreeLibrary(kernel32);

    if (currentSession == consoleSession)
        return 1;
    else
        return 0;
}


char * WINAPI
xs_vasprintf(const char *fmt, va_list args)
{
    char *buf;
    unsigned buf_size;

    buf_size = 4;
    while (1) {
        buf = malloc(buf_size);
        if (!buf)
            return NULL;
        if (_vsnprintf(buf, buf_size - 1, fmt, args) != -1)
            return buf;
        free(buf);
        buf_size *= 2;
    }
}

char * WINAPI
xs_asprintf(const char *fmt, ...)
{
    va_list args;
    char *res;

    va_start(args, fmt);
    res = xs_vasprintf(fmt, args);
    va_end(args);
    return res;
}

static void
_warn(struct xs_error_renderer *renderer, const char *errString,
      const char *fmt, va_list args)
{
    char *msg1;
    char *msg2;

    msg1 = xs_vasprintf(fmt, args);
    if (msg1) {
        if (errString)
            msg2 = xs_asprintf("%s: %s", msg1, errString);
        else
            msg2 = msg1;
    } else {
        msg2 = NULL;
    }

    if (msg2) {
        renderer->render(renderer, msg2);
        free(msg2);
    } else {
        renderer->render(renderer,
                         "An error occurred.  There was a further error when formatting the error message");
        renderer->render(renderer, fmt);
    }
    if (msg2 != msg1)
        free(msg1);
}

static void
_err(int code, struct xs_error_renderer *renderer, const char *errString,
     const char *fmt, va_list args)
{
    _warn(renderer, errString, fmt, args);
    exit(code);
}

void WINAPI
xs_err(int code, struct xs_error_renderer *renderer, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    _err(code, renderer, strerror(errno), fmt, args);
}

void WINAPI
xs_warn(struct xs_error_renderer *renderer, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    _warn(renderer, strerror(errno), fmt, args);
}

void WINAPI
xs_errx(int code, struct xs_error_renderer *renderer, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    _err(code, renderer, NULL, fmt, args);
}

void WINAPI
xs_warnx(struct xs_error_renderer *renderer, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    _warn(renderer, NULL, fmt, args);
    va_end(args);
}

void WINAPI
xs_vwin_err(int err, int code, struct xs_error_renderer *r, const char *fmt,
            va_list args)
{
    char *errMsg;

    if (!FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM | 50,
                        NULL,
                        err,
                        0,
                        (LPSTR)&errMsg,
                        0,
                        NULL)) {
        errMsg = xs_asprintf("unknown error %d", err);
    }

    _err(code, r, errMsg, fmt, args);
}

void WINAPI
xs_vwin_warn(int code, struct xs_error_renderer *r, const char *fmt,
             va_list args)
{
    char *errMsg;
    int localfree;

    localfree = 1;
    if (!FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM | 50,
                        NULL,
                        code,
                        0,
                        (LPSTR)&errMsg,
                        0,
                        NULL)) {
        errMsg = xs_asprintf("unknown error %d", code);
        localfree = 0;
    }

    _warn(r, errMsg, fmt, args);
    if (localfree)
        LocalFree(errMsg);
    else
        free(errMsg);
}

void WINAPI
xs_win_err(int code, struct xs_error_renderer *renderer, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    xs_vwin_err(GetLastError(), code, renderer, fmt, args);
}

void WINAPI
xs_win_warn(struct xs_error_renderer *renderer, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    xs_vwin_warn(GetLastError(), renderer, fmt, args);
    va_end(args);
}

static void WINAPI
render_error_msgbox(struct xs_error_renderer *r, const char *msg)
{
    UNREFERENCED_PARAMETER(r);
    MessageBox(NULL, msg, "Error", MB_OK|MB_ICONERROR);
}

struct xs_error_renderer xs_render_error_msgbox = {
    render_error_msgbox
};

static void WINAPI
render_error_stderr(struct xs_error_renderer *r, const char *msg)
{
    UNREFERENCED_PARAMETER(r);
    fprintf(stderr, "error: %s\n", msg);
}

struct xs_error_renderer xs_render_error_stderr = {
    render_error_stderr
};

char *WINAPI
xs_vassemble_strings(const char *sep, va_list *args)
{
    char *buf;
    char *new_buf;
    const char *next_arg;
    size_t s;

    next_arg = va_arg(*args, const char *);
    s = strlen(next_arg);
    buf = malloc(s + 1);
    if (!buf) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    memcpy(buf, next_arg, s + 1);

    while (1) {
        next_arg = va_arg(*args, const char *);
        if (!next_arg)
            break;
        new_buf = malloc(strlen(buf) + strlen(next_arg) + strlen(sep) + 1);
        if (!new_buf) {
            free(buf);
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }
        sprintf(new_buf, "%s%s%s", buf, sep, next_arg);
        free(buf);
        buf = new_buf;
    }

    return buf;
}

char *WINAPI
xs_assemble_strings(const char *sep, ...)
{
    va_list args;
    char *res;
    va_start(args, sep);
    res = xs_vassemble_strings(sep, &args);
    va_end(args);
    return res;
}

