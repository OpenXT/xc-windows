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

#pragma warning(push, 3)
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <malloc.h>
#include <assert.h>
#pragma warning(pop)

#define XS2API_EXPORTS
#include "xs2.h"
#include "xs_ioctl.h"
#include "xs_private.h"

#define XS2_MAGIC 0x7e6ec777

struct xs2_handle {
    unsigned refcount;
    HANDLE device;
    BOOL have_transaction;

    /* Usually ERROR_SUCCESS, but set to other things if we've failed
       the transaction from in userspace (e.g. malloc() failed).  In
       that case, the kernel still believes the transaction to be
       valid, but we have to abort it and make sure we return the
       right thing from transaction_end.

       Note that failures in kernel space do *not* set this. */
    DWORD trans_status;
};

struct xs2_watch {
    struct xs2_handle *xs_handle;
    int watch_handle;
};

static BOOL
xs2_ioctl(struct xs2_handle *handle, DWORD dwCtrlCode, const void *pInBuffer,
          DWORD InBufferSize, void *pOutBuffer, DWORD *pOutBufferSize)
{
    BOOL bResult=FALSE;
    DWORD tmp, error;

    assert(handle != NULL);

    if (pOutBufferSize == NULL) {
        tmp = 0;
        pOutBufferSize = &tmp;
    }

    bResult = DeviceIoControl(handle->device,
                              dwCtrlCode,
                              (void *)pInBuffer,
                              InBufferSize, 
                              pOutBuffer,
                              *pOutBufferSize,
                              pOutBufferSize,
                              NULL);

    if( !bResult )
    {
        /* Save the error code so that the tracing code does not change it since the 
           caller depends on GetLastError() */
        error = GetLastError();
        DBGPRINT(( "Error performing IOCTL to XenBus driver.  Error code %d, control %d.\n",
                   error, dwCtrlCode));
        SetLastError(error);
    }
    return bResult;
}

/* We wrap malloc() and free() a little bit more than xs.dll did, so
   that we stand some chance of detecting a malloc()ed pointer getting
   passed to xs2_free() or an xs2_alloc()ed one getting passed to
   free().
*/
static void *
xs2_alloc(size_t size)
{
    void *buf;

    buf = malloc(size + 8);
    if (!buf) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    memset(buf, 0, size + 8);
    *(unsigned *)buf = XS2_MAGIC;
    return (void *)((ULONG_PTR)buf + 8);
}

XS2_API void
xs2_free(const void *buf)
{
    void *orig_buf;

    if (!buf)
        return;
    orig_buf = (void *)((ULONG_PTR)buf - 8);
    if (*(unsigned *)orig_buf != XS2_MAGIC) {
        /* Whoops... xs2_free() called on a non-xs_malloc() buffer.
           We can't just free() it, because we don't know where it was
           allocated from (the main application might use a different
           CRT to us).  Crash the application. */
        OutputDebugString("xs2_free() invoked on bad pointer");
        DebugBreak();
    }
    free(orig_buf);
}

struct xs2_handle *
xs2_open()
{
    struct xs2_handle *handle;

    handle = xs2_alloc(sizeof(*handle));
    if (handle == NULL)
        return NULL;

    handle->device = CreateFile("\\\\.\\XenBus",
                                GENERIC_READ | GENERIC_WRITE,
                                0,
                                NULL,
                                OPEN_EXISTING,
                                0,
                                NULL);
    if (handle->device == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        xs2_free(handle);
        SetLastError(e);
        return NULL;
    }

    handle->refcount = 1;
    return handle;
}

static void
xs2_drop_handle_ref(struct xs2_handle *handle)
{
    handle->refcount--;
    if (handle->refcount == 0)
        xs2_free(handle);
}

void
xs2_close(struct xs2_handle *handle)
{
    if (handle == NULL)
        return;

    CloseHandle(handle->device);
    handle->device = INVALID_HANDLE_VALUE;
    xs2_drop_handle_ref(handle);
}

BOOL
xs2_transaction_start(struct xs2_handle *handle)
{
    assert(handle != NULL);

    /* Remember, the kernel driver always opens a transaction, even
       when it returns an error. */
    if (!handle->have_transaction) {
        handle->have_transaction = TRUE;
        handle->trans_status = ERROR_SUCCESS;
    }

    return xs2_ioctl(handle, IOCTL_XS_TRANS_START, NULL, 0, NULL, NULL);
}

static BOOL
xs2_transaction_end(struct xs2_handle *xih, BOOL fAbort)
{
    BOOL fResult;
    DWORD dwAbort;

    assert(xih != NULL);

    if (xih->have_transaction && xih->trans_status != ERROR_SUCCESS)
        fAbort = TRUE;

    dwAbort = fAbort;

    fResult = xs2_ioctl(xih, IOCTL_XS_TRANS_END, &dwAbort, sizeof(DWORD),
                        NULL, NULL);

    if (xih->have_transaction && xih->trans_status != ERROR_SUCCESS) {
        fResult = FALSE;
        SetLastError(xih->trans_status);
    }
    xih->have_transaction = FALSE;

    return fResult;
}

XS2_API void
xs2_transaction_abort(struct xs2_handle *handle)
{
    xs2_transaction_end(handle, TRUE);
}

XS2_API BOOL
xs2_transaction_commit(struct xs2_handle *handle)
{
    return xs2_transaction_end(handle, FALSE);
}

XS2_API void *
xs2_read(struct xs2_handle *xih, const char *path, size_t *len)
{
    BOOL fResult;
    DWORD buflen;
    XS_READ_MSG *pOutBuf;
    PCHAR data;
    size_t _len;

    assert(xih != NULL);

    if (!len) len = &_len;

    *len = 0;

    fResult = FALSE;
    buflen = INITIAL_OUTBUF_SIZE+sizeof(XS_READ_MSG);
    pOutBuf = malloc(buflen);

    if (!pOutBuf)
    {
        DBGPRINT(("Unable to allocate buffer in xs_read.\n"));
        xih->trans_status = ERROR_NOT_ENOUGH_MEMORY;
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    fResult = xs2_ioctl(xih, IOCTL_XS_READ, (void*)path,
                        (DWORD)(strlen(path) + 1), pOutBuf,
                        &buflen);

    while (!fResult && GetLastError() == ERROR_MORE_DATA)
    {
        buflen = pOutBuf->len + sizeof(XS_READ_MSG);
        DBGPRINT(( "xs_read(): allocating more buffer - %d\n", buflen));
        free(pOutBuf);

        pOutBuf = malloc(buflen + 1);

        if (!pOutBuf)
        {
            DBGPRINT(("xs_read(): Cannot allocate buffer length %d\n", buflen));
            xih->trans_status = ERROR_NOT_ENOUGH_MEMORY;
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }

        fResult = xs2_ioctl(xih, IOCTL_XS_READ, (void*)path,
                            (DWORD)(strlen(path) + 1), pOutBuf, &buflen);
    }

    if (!fResult)
    {
        DWORD error = GetLastError();
        DBGPRINT(("xs_read(): unable to read the specified path %s - err %d\n", path, GetLastError()));
        free(pOutBuf);
        SetLastError(error);
        return NULL;
    }

    data = xs2_alloc(pOutBuf->len+1);
    if (!data)
    {
        DBGPRINT(("Unable to allocate result buffer length %d in xs_read\n",
             pOutBuf->len + 1));
        xih->trans_status = ERROR_NOT_ENOUGH_MEMORY;
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    }
    else
    {
        memcpy(data, pOutBuf->data, pOutBuf->len);
        data[pOutBuf->len] = '\0';
        *len = buflen - sizeof(XS_READ_MSG);
    }
    free(pOutBuf);

    return data;
}

XS2_API BOOL
xs2_remove(struct xs2_handle *xih, const char *path)
{
    return xs2_ioctl(xih, IOCTL_XS_REMOVE, path, (DWORD)(strlen(path) + 1),
                     NULL, NULL);
}

XS2_API BOOL
xs2_write_bin(struct xs2_handle *xih, const char *path, const void *data,
              size_t data_len)
{
    BOOL fResult;
    XS_WRITE_MSG *pMsg;
    size_t buflen;

    assert(xih != NULL);

    fResult = FALSE;
    pMsg = NULL;
    buflen = sizeof(XS_WRITE_MSG)+data_len+strlen(path)+1;
    pMsg = malloc(buflen);
    if (!pMsg)
    {
        DBGPRINT(("Cannot allocate pMsg in xs_write\n"));
        xih->trans_status = ERROR_NOT_ENOUGH_MEMORY;
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    pMsg->len = (unsigned)buflen;
    strcpy((char*)pMsg->data, path);
    memcpy(pMsg->data + strlen(path)+1, data, data_len);

    fResult = xs2_ioctl(xih, IOCTL_XS_WRITE, pMsg, (DWORD)buflen, NULL,
                        NULL);

    free(pMsg);

    return fResult;
}

XS2_API BOOL
xs2_write(struct xs2_handle *xih, const char *path, const char *data )
{
    return xs2_write_bin(xih, path, data, strlen(data));
}

XS2_API char **
xs2_directory(struct xs2_handle *xih, const char *path, unsigned int *num)
{
    BOOL fResult;
    DWORD len;
    int i;
    XS_DIR_MSG *pOutBuf;
    char **table;
    char *currdata;

    assert(xih != NULL);

    if (num != NULL)
        *num = 0;

    len = sizeof(XS_DIR_MSG)+ INITIAL_OUTBUF_SIZE;
    pOutBuf = malloc(len);
    if (!pOutBuf)
    {
        DBGPRINT(("xs_directory(): Failed to allocate OutBuf len %d\n",
             len));
        xih->trans_status = ERROR_NOT_ENOUGH_MEMORY;
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    fResult = xs2_ioctl(xih, IOCTL_XS_DIRECTORY, path,
                        (DWORD)(strlen(path)+1), pOutBuf, &len);
    while (!fResult && GetLastError() == ERROR_MORE_DATA)
    {
        len = pOutBuf->len + sizeof(XS_DIR_MSG);
        free(pOutBuf);

        DBGPRINT(( "xs_directory(): allocating more buffer - %d\n", len));

        pOutBuf = malloc(len);
        if (!pOutBuf)
        {
            DBGPRINT(( "xs_directory(): could not allocate buffer length %d\n", len));
            xih->trans_status = ERROR_NOT_ENOUGH_MEMORY;
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }

        fResult = xs2_ioctl(xih, IOCTL_XS_DIRECTORY, path,
                            (DWORD)(strlen(path)+1), pOutBuf,
                            &len);
    }

    if (!fResult) {
        DWORD error = GetLastError();
        DBGPRINT(( "xs_directory(): unable to ls the path \'%s\' - err %d\n", path, GetLastError()));
        free(pOutBuf);
        SetLastError(error);
        return NULL;
    }

    table = (char**) xs2_alloc((pOutBuf->count+1) * sizeof(void*));
    if (!table)
    {
        DBGPRINT(( "xs_directory(): cannot allocate table of %d entries\n",
              pOutBuf->count));
        free(pOutBuf);
        xih->trans_status = ERROR_NOT_ENOUGH_MEMORY;
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    currdata = (char*) pOutBuf->data;
    for (i=0; i < pOutBuf->count; i++)
    {
        DBGPRINT(( "xs_directory(): data - %s\n", currdata));

        table[i] = xs2_alloc(strlen(currdata) + 1);
        if (!table[i])
            goto failed_to_allocate_table;
        memcpy(table[i], currdata, strlen(currdata) + 1);
        currdata += strlen(currdata) + 1;
    }

    if (num != NULL)
        *num = pOutBuf->count;

    free(pOutBuf);

    return table;

 failed_to_allocate_table:
    DBGPRINT(("xs_directory(): failed to allocate table entry %d/%d\n",
         i, pOutBuf->count));
    for (i = 0; i < pOutBuf->count; i++)
        xs2_free(table[i]);
    xs2_free(table);
    free(pOutBuf);
    xih->trans_status = ERROR_NOT_ENOUGH_MEMORY;
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return NULL;
}

XS2_API struct xs2_watch *
xs2_watch(struct xs2_handle *xih, const char *path, HANDLE event)
{
    XS_WATCH_MSG *msg;
    size_t l;
    size_t buflen;
    int handle;
    DWORD outlen;
    struct xs2_watch *watch;

    assert(xih != NULL);

    watch = xs2_alloc(sizeof(*watch));
    if (!watch)
        return NULL;

    l = strlen(path);
    buflen = sizeof(*msg) + l + 1;
    outlen = sizeof(handle);
    msg = malloc(buflen);
    if (!msg) {
        xs2_free(watch);
        xih->trans_status = ERROR_NOT_ENOUGH_MEMORY;
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    msg->event = event;
    memcpy(msg->path, path, l + 1);
    if (!xs2_ioctl(xih, IOCTL_XS_WATCH, msg, (DWORD)buflen, &handle,
                   &outlen)) {
        DWORD error = GetLastError();
        free(msg);
        xs2_free(watch);
        SetLastError(error);
        return NULL;
    }
    free(msg);

    xih->refcount++;
    watch->xs_handle = xih;
    watch->watch_handle = handle;
    return watch;
}

XS2_API void
xs2_unwatch(struct xs2_watch *watch)
{
    struct xs2_handle *xih = watch->xs_handle;

    if (xih->device != INVALID_HANDLE_VALUE)
        xs2_ioctl(xih, IOCTL_XS_UNWATCH,
                  &watch->watch_handle, sizeof(watch->watch_handle),
                  NULL, NULL);

    xs2_drop_handle_ref(watch->xs_handle);
    xs2_free(watch);
}

int
xs2_listen_suspend(struct xs2_handle *xih, HANDLE event)
{
    XS_LISTEN_SUSPEND_MSG msg;

    msg.handle = event;
    return xs2_ioctl(xih, IOCTL_XS_LISTEN_SUSPEND, &msg, sizeof(msg),
                     NULL, NULL);
}

BOOL
xs2_unlisten_suspend(struct xs2_handle *xih)
{
    return xs2_ioctl(xih, IOCTL_XS_UNLISTEN_SUSPEND, NULL, 0, NULL, NULL);
}


void
xs2_get_xen_time(struct xs2_handle *xih, FILETIME *out)
{
    ULONG64 res = 0;
    DWORD outlen = sizeof(res);
    xs2_ioctl(xih, IOCTL_XS_GET_XEN_TIME, NULL, 0, &res, &outlen);
    out->dwLowDateTime = (DWORD)res;
    out->dwHighDateTime = (DWORD)(res >> 32);
}

void
xs2_make_precious(struct xs2_handle *xih)
{
    ULONG64 res = 0;
    DWORD outlen = sizeof(res);
    xs2_ioctl(xih, IOCTL_XS_MAKE_PRECIOUS, NULL, 0, &res, &outlen);
}

void
xs2_unmake_precious(struct xs2_handle *xih)
{
    ULONG64 res = 0;
    DWORD outlen = sizeof(res);
    xs2_ioctl(xih, IOCTL_XS_UNMAKE_PRECIOUS, NULL, 0, &res, &outlen);
}

void
xs2_vlog(struct xs2_handle *xih, const char *fmt, va_list list)
{
    char *buf;
    DWORD buf_len;
    int l;

    buf_len = 128;
    buf = malloc(buf_len);
    if (!buf)
        goto do_log;
    while (1) {
        l = _vsnprintf(buf, buf_len, fmt, list);
        if (l >= 0 && l < (int)buf_len)
            break;
        free(buf);
        buf_len *= 2;
        buf = malloc(buf_len);
        if (!buf)
            break;
    }
do_log:
    if (buf == NULL) {
        /* Urk, can't format the message.  Just print the format
           string and hope that's good enough. */
        buf = (char *)fmt;
    }
    xs2_ioctl(xih, IOCTL_XS_LOG, buf, buf_len, NULL, NULL);
    if (buf != fmt)
        free(buf);
}

void
xs2_log(struct xs2_handle *xih, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    xs2_vlog(xih, fmt, args);
    va_end(args);
}

WRITE_ON_CLOSE_HANDLE
xs2_write_on_close(struct xs2_handle *xih, const char *path, const void *data,
                   size_t data_size)
{
    XS_WRITE_ON_CLOSE_IN inp;
    XS_WRITE_ON_CLOSE_OUT out;
    DWORD outsize;
    if (data_size != (unsigned)data_size) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return null_WRITE_ON_CLOSE_HANDLE();
    }
    outsize = sizeof(out);
    inp.path = (ULONG64)(ULONG_PTR)path;
    inp.data = (ULONG64)(ULONG_PTR)data;
    inp.data_len = (unsigned)data_size;
    if (!xs2_ioctl(xih, IOCTL_XS_WRITE_ON_CLOSE, &inp, sizeof(inp),
                   &out, &outsize))
        return null_WRITE_ON_CLOSE_HANDLE();

    return wrap_WRITE_ON_CLOSE_HANDLE(out.handle);
}

void
xs2_cancel_write_on_close(struct xs2_handle *xih,
                          WRITE_ON_CLOSE_HANDLE handle)
{
    XS_CANCEL_WRITE_ON_CLOSE in;

    if (is_null_WRITE_ON_CLOSE_HANDLE(handle))
        return;

    in.handle = unwrap_WRITE_ON_CLOSE_HANDLE(handle);
    if (!xs2_ioctl(xih, IOCTL_XS_CANCEL_WRITE_ON_CLOSE, &in, sizeof(in),
                   NULL, NULL)) {
        OutputDebugString("failed to cancel write-on-close entry");
        DebugBreak();
    }
}
