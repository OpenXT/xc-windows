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

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <xs2.h>
#include <xs_private.h>
#include <xenops.h>

#include "v2v_private.h"

/* Like malloc(), but set the win32 last error */
void *
ymalloc(size_t size)
{
    void *work;
    work = malloc(size);
    if (!work) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    memset(work, 0, size);
    return work;
}

char *
ystrdup(const char *str)
{
    size_t len = strlen(str) + 1;
    char *res;
    res = ymalloc(len);
    if (!res)
        return res;
    memcpy(res, str, len);
    return res;
}

void
yfree(const void *ptr)
{
    DWORD err;
    err = GetLastError();
    free((void *)ptr);
    SetLastError(err);
}

char *
xenstore_readv_string(struct xs2_handle *xs2, ...)
{
    char *path;
    va_list args;
    void *res;

    va_start(args, xs2);
    path = xs_vassemble_strings("/", &args);
    va_end(args);
    if (!path)
        return NULL;
    res = xs2_read(xs2, path, NULL);
    yfree(path);
    return res;
}

struct xs2_watch *
xenstore_watchv(struct xs2_handle *xs2, HANDLE event, ...)
{
    char *path;
    va_list args;
    struct xs2_watch *res;

    va_start(args, event);
    path = xs_vassemble_strings("/", &args);
    va_end(args);
    if (!path)
        return NULL;
    res = xs2_watch(xs2, path, event);
    yfree(path);
    return res;
}

BOOL
xenstore_printfv(struct xs2_handle *xs2, ...)
{
    va_list args;
    char *path;
    char *buf;
    const char *fmt;
    BOOL res;

    va_start(args, xs2);
    path = xs_vassemble_strings("/", &args);
    if (!path) {
        va_end(args);
        return FALSE;
    }
    fmt = va_arg(args, const char *);
    buf = xs_vasprintf(fmt, args);
    va_end(args);
    if (!buf) {
        yfree(path);
        return FALSE;
    }

    res = xs2_write(xs2, path, buf);
    yfree(path);
    yfree(buf);
    return res;
}

BOOL
xenstore_scatter(struct xs2_handle *xs2, const char *prefix, ...)
{
    va_list args;
    BOOL res;
    enum xenstore_scatter_type type;
    const char *name;

    res = TRUE;
    va_start(args, prefix);
    while (1) {
        name = va_arg(args, const char *);
        if (!name)
            break;
        type = va_arg(args, enum xenstore_scatter_type);
        switch (type) {
        case xenstore_scatter_type_grant_ref: {
            GRANT_REF gref;
            gref = va_arg(args, GRANT_REF);
            res = xenstore_printfv(xs2, prefix, name, NULL,
                                   "%d", xen_GRANT_REF(gref));
            break;
        }
        case xenstore_scatter_type_evtchn_port: {
            EVTCHN_PORT port;
            port = va_arg(args, EVTCHN_PORT);
            res = xenstore_printfv(xs2, prefix, name, NULL,
                                   "%d", unwrap_EVTCHN_PORT(port));
            break;
        }
        case xenstore_scatter_type_string: {
            const char *str;
            str = va_arg(args, const char *);
            res = xenstore_printfv(xs2, prefix, name, NULL, "%s", str);
            break;
        }
        case xenstore_scatter_type_int: {
            int i;
            i = va_arg(args, int);
            res = xenstore_printfv(xs2, prefix, name, NULL, "%d", i);
            break;
        }
        default: {
            SetLastError(ERROR_INVALID_FUNCTION);
            res = FALSE;
            break;
        }
        }
        if (!res)
            break;
    }
    va_end(args);
    return res;
}

BOOL
xenstore_gather(struct xs2_handle *xs2, const char *prefix, ...)
{
    va_list args;
    const char *name;
    enum xenstore_gather_type type;
    char *raw_data;
    int r;
    BOOL res;

    res = TRUE;
    va_start(args, prefix);
    while (1) {
        name = va_arg(args, const char *);
        if (!name)
            break;
        type = va_arg(args, enum xenstore_gather_type);
        raw_data = xenstore_readv_string(xs2,
                                        prefix,
                                        name,
                                        NULL);
        if (!raw_data) {
            res = FALSE;
            break;
        }

        switch (type) {
        case xenstore_gather_type_alien_grant_ref: {
            ALIEN_GRANT_REF *gref;
            unsigned raw;
            gref = va_arg(args, ALIEN_GRANT_REF *);
            r = sscanf(raw_data, "%d", &raw);
            *gref = wrap_ALIEN_GRANT_REF(raw);
            break;
        }

        case xenstore_gather_type_alien_evtchn_port: {
            ALIEN_EVTCHN_PORT *out;
            unsigned raw;
            out = va_arg(args, ALIEN_EVTCHN_PORT *);
            r = sscanf(raw_data, "%d", &raw);
            *out = wrap_ALIEN_EVTCHN_PORT(raw);
            break;
        }

        case xenstore_gather_type_int: {
            int *out;
            out = va_arg(args, int *);
            r = sscanf(raw_data, "%d", out);
            break;
        }

        default: {
            SetLastError(ERROR_INVALID_FUNCTION);
            res = FALSE;
            r = 1;
            break;
        }
        }

        xs2_free(raw_data);
        if (r != 1) {
            SetLastError(ERROR_INVALID_DATA);
            res = FALSE;
        }
        if (!res)
            break;
    }
    va_end(args);

    return res;
}

