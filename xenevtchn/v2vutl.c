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

#include <ntddk.h>
#include <ntstrsafe.h>
#define XSAPI_FUTURE_GRANT_MAP
#define XSAPI_FUTURE_CONNECT_EVTCHN
#include "xsapi.h"
#include "xsapi-future.h"
#include "scsiboot.h"
#include "../xenutil/evtchn.h"
#include "../xenutil/gntmap.h"

#include "v2v_private.h"

static char *
v2v_xenstore_vassemble_strings(const char *sep, va_list *args)
{
    NTSTATUS status;
    char *buf;
    char *new_buf;
    const char *next_arg;
    size_t nlen, slen, blen;

    next_arg = va_arg(*args, const char *);

    status = RtlStringCchLengthA(next_arg, NTSTRSAFE_MAX_CCH, &nlen);
    if (!NT_SUCCESS(status))
        return NULL;

    status = RtlStringCchLengthA(sep, NTSTRSAFE_MAX_CCH, &slen);
    if (!NT_SUCCESS(status))
        return NULL;

    blen = nlen + 1;
    buf = ExAllocatePoolWithTag(PagedPool, blen, V2V_TAG);
    if (!buf)        
        return NULL;    

    status = RtlStringCchCopyNA(buf, blen, next_arg, blen - 1);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buf, V2V_TAG);
        return NULL;
    }

    while (1) {
        next_arg = va_arg(*args, const char *);
        if (!next_arg)
            break;

        status = RtlStringCchLengthA(next_arg, NTSTRSAFE_MAX_CCH, &nlen);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(buf, V2V_TAG);
            return NULL;
        }
        blen += (nlen + slen + 1);

        new_buf = ExAllocatePoolWithTag(PagedPool, blen, V2V_TAG);
        if (!new_buf) {
            ExFreePoolWithTag(buf, V2V_TAG);
            return NULL;
        }

        status = RtlStringCchPrintfA(new_buf, blen, "%s%s%s", buf, sep, next_arg);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(buf, V2V_TAG);
            return NULL;
        }
            
        ExFreePoolWithTag(buf, V2V_TAG);
        buf = new_buf;
    }

    return buf;
}

int
v2v_string_to_num(const char *str, int *val)
{
#define V2V_SAFE_INT_STRING 25
    NTSTATUS status;
    size_t slen;
    ANSI_STRING as;
    UNICODE_STRING us;

    if ((!str)||(!val))
        return -1;

    /* it is unlikely a decimal number would be bigger than 20 chars (2^64)
       or there about - check for a reasonable size */
    status = RtlStringCchLengthA(str, V2V_SAFE_INT_STRING, &slen);
    if ((!NT_SUCCESS(status))||(slen == 0))
        return -1;

    RtlInitAnsiString(&as, str);
    status = RtlAnsiStringToUnicodeString(&us, &as, TRUE);
    if (!NT_SUCCESS(status))
        return -1;

    status = RtlUnicodeStringToInteger(&us, 10, (PULONG)val);
    RtlFreeUnicodeString(&us);
    return (NT_SUCCESS(status) ? 1 : 0);
}

char *
v2v_string_dup(const char *src, BOOLEAN np)
{
    NTSTATUS status;
    char *buf;
    size_t slen;

    status = RtlStringCchLengthA(src, NTSTRSAFE_MAX_CCH, &slen);
    if (!NT_SUCCESS(status))
        return NULL;

    buf = ExAllocatePoolWithTag((np ? NonPagedPool : PagedPool), slen + 1, V2V_TAG);
    if (!buf)        
        return NULL;    

    status = RtlStringCchCopyNA(buf, slen + 1, src, slen);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buf, V2V_TAG);
        return NULL;
    }
    return buf;
}

NTSTATUS
v2v_xenstore_readv_string(char **val_out, xenbus_transaction_t xbt, ...)
{
#define V2V_OUTBUF_SIZE     128
    NTSTATUS status;
    va_list args;
    char *path;
    char *data;
    char *res = NULL;
    size_t blen = V2V_OUTBUF_SIZE;
    size_t llen = V2V_OUTBUF_SIZE;

    if (!val_out)
        return STATUS_INVALID_PARAMETER;
    *val_out = NULL;

    if (!xenbus_await_initialisation())
        return STATUS_NO_SUCH_DEVICE;

    va_start(args, xbt);
    path = v2v_xenstore_vassemble_strings("/", &args);
    va_end(args);
    if (!path)
        return STATUS_NO_MEMORY;

    do {        
        status = xenbus_read_bin(xbt, path, NULL, &data, &blen);
        if (!NT_SUCCESS(status))
            break; /* STATUS_OBJECT_NAME_NOT_FOUND indicates the path does not exist */
        
        if (blen <= llen)
            break;

        /* we need more room, free what we got and try again */
        XmFreeMemory(data);
        data = NULL;
        llen = blen;
    } while (TRUE);

    ExFreePoolWithTag(path, V2V_TAG);

    /* Did we get anything */
    if (!NT_SUCCESS(status))
        return status;

    if (data) {
        res = (char*)ExAllocatePoolWithTag(PagedPool, blen + 1, V2V_TAG);
        if (!res) {
            XmFreeMemory(data);
            return STATUS_NO_MEMORY;
        }
        memcpy(res, data, blen);
        XmFreeMemory(data);
        res[blen] = '\0';
        *val_out = res;
        return STATUS_SUCCESS;
    }
    
    return STATUS_UNSUCCESSFUL; /* shouldn't happen */
}

NTSTATUS
v2v_xenstore_watchv(struct xenbus_watch_handler **xwh_out, PKEVENT event, ...)
{
    char *path;
    va_list args;

    if (!xwh_out)
        return STATUS_INVALID_PARAMETER;
    *xwh_out = NULL;

    if (!xenbus_await_initialisation())
        return STATUS_NO_SUCH_DEVICE;

    va_start(args, event);
    path = v2v_xenstore_vassemble_strings("/", &args);
    va_end(args);
    if (!path)
        return STATUS_NO_MEMORY;

    *xwh_out = xenbus_watch_path_event(path, event);

    ExFreePoolWithTag(path, V2V_TAG);

    if (!(*xwh_out))
        return STATUS_UNSUCCESSFUL;

    return STATUS_SUCCESS;
}

NTSTATUS
v2v_xenstore_watchv_cb(struct xenbus_watch_handler **xwh_out, void (*watch_cb)(void *), void *ctx, ...)
{
    char *path;
    va_list args;

    if (!xwh_out)
        return STATUS_INVALID_PARAMETER;
    *xwh_out = NULL;

    if (!xenbus_await_initialisation())
        return STATUS_NO_SUCH_DEVICE;

    va_start(args, ctx);
    path = v2v_xenstore_vassemble_strings("/", &args);
    va_end(args);
    if (!path)
        return STATUS_NO_MEMORY;

    *xwh_out = xenbus_watch_path(path, watch_cb, ctx);

    ExFreePoolWithTag(path, V2V_TAG);

    if (!(*xwh_out))
        return STATUS_UNSUCCESSFUL;

    return STATUS_SUCCESS;
}

NTSTATUS
v2v_xenstore_printfv(xenbus_transaction_t xbt, ...)
{
    NTSTATUS status = STATUS_SUCCESS;
    va_list args;
    char *path = NULL;
    char *buf = NULL;
    const char *fmt;
    size_t slen;

    do {
        if (!xenbus_await_initialisation()) {
            status = STATUS_NO_SUCH_DEVICE;
            break;
        }

        va_start(args, xbt);
        path = v2v_xenstore_vassemble_strings("/", &args);
        if (!path) {
            va_end(args);
            status = STATUS_NO_MEMORY;
            break;
        }

        fmt = va_arg(args, const char *);
        buf = Xmvasprintf(fmt, args);
        va_end(args);
        if (!buf) {
            status = STATUS_NO_MEMORY;
            break;
        }
        
        status = RtlStringCchLengthA(buf, NTSTRSAFE_MAX_CCH, &slen);
        if (!NT_SUCCESS(status))
            break;

        status = xenbus_write_bin(xbt, path, NULL, buf, slen);
    } while (FALSE);

    if (path)
        ExFreePoolWithTag(path, V2V_TAG);
    if (buf)
        XmFreeMemory(buf);

    return status;
}

NTSTATUS
v2v_xenstore_scatter(xenbus_transaction_t xbt, const char *prefix, ...)
{
    NTSTATUS status = STATUS_SUCCESS;
    va_list args;    
    enum xenstore_scatter_type type;
    const char *name;

    va_start(args, prefix);
    while (1) {
        name = va_arg(args, const char *);
        if (!name)
            break;
        type = va_arg(args, enum xenstore_scatter_type);
        switch (type) {
        case xenstore_scatter_type_grant_ref: {
            uint32_t xen_gref;
            xen_gref = va_arg(args, uint32_t);
            status = v2v_xenstore_printfv(xbt, prefix, name, NULL,
                                   "%d", xen_gref);
            break;
        }
        case xenstore_scatter_type_evtchn_port: {
            unsigned xen_port;
            xen_port = va_arg(args, unsigned);
            status = v2v_xenstore_printfv(xbt, prefix, name, NULL,
                                   "%d", xen_port);
            break;
        }
        case xenstore_scatter_type_string: {
            const char *str;
            str = va_arg(args, const char *);
            status = v2v_xenstore_printfv(xbt, prefix, name, NULL, "%s", str);
            break;
        }
        case xenstore_scatter_type_int: {
            int i;
            i = va_arg(args, int);
            status = v2v_xenstore_printfv(xbt, prefix, name, NULL, "%d", i);
            break;
        }
        default: {
            status = STATUS_NOT_IMPLEMENTED;
            break;
        }
        }
        if (!NT_SUCCESS(status))
            break;
    }
    va_end(args);
    return status;
}

NTSTATUS
v2v_xenstore_gather(xenbus_transaction_t xbt, const char *prefix, ...)
{
    NTSTATUS status = STATUS_SUCCESS;
    va_list args;
    const char *name;
    enum xenstore_gather_type type;
    char *raw_data;
    int r;

    va_start(args, prefix);
    while (1) {
        name = va_arg(args, const char *);
        if (!name)
            break;
        type = va_arg(args, enum xenstore_gather_type);
        status = v2v_xenstore_readv_string(&raw_data, xbt, prefix, name, NULL);
        if (!NT_SUCCESS(status))
            break;

        switch (type) {
        case xenstore_gather_type_alien_grant_ref: {
            ALIEN_GRANT_REF *gref;
            int raw;
            gref = va_arg(args, ALIEN_GRANT_REF *);
            r = v2v_string_to_num(raw_data, &raw);
            *gref = wrap_ALIEN_GRANT_REF((unsigned)raw);
            break;
        }

        case xenstore_gather_type_alien_evtchn_port: {
            ALIEN_EVTCHN_PORT *out;
            int raw;
            out = va_arg(args, ALIEN_EVTCHN_PORT *);
            r = v2v_string_to_num(raw_data, &raw);
            *out = wrap_ALIEN_EVTCHN_PORT((unsigned)raw);
            break;
        }

        case xenstore_gather_type_int: {
            int *out;
            out = va_arg(args, int *);
            r = v2v_string_to_num(raw_data, out);
            break;
        }

        default: {
            status = STATUS_NOT_IMPLEMENTED;
            r = 1;
            break;
        }
        }

        ExFreePoolWithTag(raw_data, V2V_TAG);
        if (r != 1) {
            status = STATUS_INVALID_PARAMETER;
        }
        if (!NT_SUCCESS(status))
            break;
    }
    va_end(args);

    return status;
}

NTSTATUS
v2v_xenops_grant_map(volatile void **map_out, struct grant_map_detail **detail_out,
                    DOMAIN_ID domid, unsigned nr_grefs, ALIEN_GRANT_REF *grefs,
                    BOOLEAN readonly)
{
    NTSTATUS status = STATUS_SUCCESS;
    GRANT_MODE mode = readonly ? GRANT_MODE_RO : GRANT_MODE_RW;

    if (!map_out || !detail_out || !grefs)
        return STATUS_INVALID_PARAMETER;    

    *map_out = NULL;
    *detail_out = NULL;

    status = GntmapMapGrants(domid, nr_grefs, grefs, mode, detail_out);
    if (!NT_SUCCESS(status))
        return status;
    XM_ASSERT(detail_out != NULL);

    try {    
        *map_out =
            MmMapLockedPagesSpecifyCache(GntmapMdl(*detail_out),
                                         KernelMode,
                                         MmCached,
                                         NULL,
                                         FALSE,
                                         NormalPagePriority);
    } except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }

    if (!NT_SUCCESS(status)) {
        GntmapUnmapGrants(*detail_out);
        *detail_out = NULL;
    }

    return status;
}

void v2v_xenops_grant_unmap(void *map, struct grant_map_detail *detail)
{
    if (detail != NULL) {
        MmUnmapLockedPages(map, GntmapMdl(detail));
        GntmapUnmapGrants(detail);
    }
}
