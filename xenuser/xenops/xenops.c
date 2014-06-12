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

#pragma warning(push,3)
#include <windows.h>
#include <winioctl.h>
#include <malloc.h>
#pragma warning(pop)

#define XENOPS_API_EXPORTS
#include "xs_ioctl.h"
#include "xenops.h"

static GRANT_MAP_HANDLE
wrap_GRANT_MAP_HANDLE(ULONG64 r)
{
    GRANT_MAP_HANDLE gmh;
    memcpy(gmh.bytes, &r, sizeof(r));
    return gmh;
}

static ULONG64
unwrap_GRANT_MAP_HANDLE(GRANT_MAP_HANDLE gmh)
{
    return *((ULONG64*)gmh.bytes);
}

static GRANT_REF
wrap_GRANT_REF(xenops_grant_ref_t gref)
{
    return __wrap_GRANT_REF((gref << 10) ^ 0xdeadbeef);
}

struct xenops_handle {
    HANDLE device;
};

struct xenops_handle *
xenops_open(void)
{
    struct xenops_handle *handle;

    handle = malloc(sizeof(*handle));
    if (!handle) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    handle->device = CreateFile("\\\\.\\XenBus",
                                GENERIC_READ | GENERIC_WRITE,
                                0,
                                NULL,
                                OPEN_EXISTING,
                                0,
                                NULL);
    if (handle->device == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        free(handle);
        SetLastError(e);
        return NULL;
    }

    return handle;
}

void
xenops_close(struct xenops_handle *xh)
{
    CloseHandle(xh->device);
    free(xh);
}

static BOOL
xenops_grant(struct xenops_handle *h, DOMAIN_ID domid, void *start,
             GRANT_REF *res, BOOLEAN readonly)
{
    XS_GRANT_ACCESS_IN in;
    XS_GRANT_ACCESS_OUT out;
    DWORD ignore;

    in.domid = unwrap_DOMAIN_ID(domid);
    in.readonly = readonly;
    in.virt_addr = (ULONG64)start;
    if (!DeviceIoControl(h->device, IOCTL_XS_GRANT_ACCESS,
                         &in, sizeof(in), &out, sizeof(out),
                         &ignore, NULL)) {
        *res = null_GRANT_REF();
        return FALSE;
    }
    *res = wrap_GRANT_REF(out.grant_reference);
    return TRUE;
}

BOOL
xenops_grant_readonly(struct xenops_handle *h, DOMAIN_ID domid,
                      const void *start, GRANT_REF *out)
{
    return xenops_grant(h, domid, (void *)start, out, TRUE);
}

BOOL
xenops_grant_readwrite(struct xenops_handle *h, DOMAIN_ID domid,
                       void *start, GRANT_REF *out)
{
    return xenops_grant(h, domid, start, out, FALSE);
}

BOOL
xenops_ungrant(struct xenops_handle *h, GRANT_REF gref)
{
    XS_UNGRANT_ACCESS in;
    DWORD ignore;

    if (is_null_GRANT_REF(gref))
        return TRUE;
    in.grant_reference = xen_GRANT_REF(gref);
    return DeviceIoControl(h->device, IOCTL_XS_UNGRANT_ACCESS,
                           &in, sizeof(in), NULL, 0, &ignore, NULL);
}

BOOL
xenops_grant_set_quota(struct xenops_handle *h, unsigned quota)
{
    XS_GRANT_QUOTA in;
    DWORD ignore;

    in.quota = quota;
    return DeviceIoControl(h->device, IOCTL_XS_GRANT_SET_QUOTA,
                           &in, sizeof(in), NULL, 0, &ignore, NULL);
}

unsigned
xenops_grant_get_quota(struct xenops_handle *h)
{
    XS_GRANT_QUOTA out;
    DWORD ignore;

    if (!DeviceIoControl(h->device, IOCTL_XS_GRANT_GET_QUOTA,
                         NULL, 0, &out, sizeof(out), &ignore,
                         NULL)) {
        OutputDebugString("Kernel rejected our attempt to get grant quota!\n");
        DebugBreak();
    }
    return out.quota;
}

static BOOL
xenops_grant_map(struct xenops_handle *h,
                 DOMAIN_ID domid,
                 unsigned nr_grefs,
                 ALIEN_GRANT_REF *grefs,
                 GRANT_MAP_HANDLE *handle,
                 volatile void **map,
                 BOOLEAN readonly)
{
    XS_GRANT_MAP_IN *in;
    XS_GRANT_MAP_OUT out;
    DWORD ignore;
    DWORD in_size;
    BOOL res;
    unsigned x;

    in_size = sizeof(*in) + sizeof(in->grant_refs[0]) * nr_grefs;
    in = malloc(in_size);
    if (!in) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    memset(in, 0, sizeof(*in));
    in->domid = unwrap_DOMAIN_ID(domid);
    in->readonly = readonly;
    in->nr_grefs = nr_grefs;
    for (x = 0; x < nr_grefs; x++)
        in->grant_refs[x] = unwrap_ALIEN_GRANT_REF(grefs[x]);

    res = DeviceIoControl(h->device, IOCTL_XS_GRANT_MAP,
                          in, in_size, &out, sizeof(out),
                          &ignore, NULL);
    free(in);
    if (res) {
        *handle = wrap_GRANT_MAP_HANDLE(out.handle);
        *map = (void *)(ULONG_PTR)out.virt_addr;
    } else {
        *handle = null_GRANT_MAP_HANDLE();
        *map = NULL;
    }
    return res;
}

BOOL
xenops_grant_map_readonly(struct xenops_handle *h,
                          DOMAIN_ID domid,
                          unsigned nr_grefs,
                          ALIEN_GRANT_REF *grefs,
                          GRANT_MAP_HANDLE *handle,
                          volatile const void **map)
{
    return xenops_grant_map(h, domid, nr_grefs, grefs, handle,
                            (volatile void **)map, TRUE);
}

BOOL
xenops_grant_map_readwrite(struct xenops_handle *h,
                           DOMAIN_ID domid,
                           unsigned nr_grefs,
                           ALIEN_GRANT_REF *grefs,
                           GRANT_MAP_HANDLE *handle,
                           volatile void **map)
{
    return xenops_grant_map(h, domid, nr_grefs, grefs, handle, map, FALSE);
}

void
xenops_unmap_grant(struct xenops_handle *h, GRANT_MAP_HANDLE handle)
{
    XS_GRANT_UNMAP in;
    DWORD ignore;
    BOOL res;

    if (is_null_GRANT_MAP_HANDLE(handle))
        return;

    in.handle = unwrap_GRANT_MAP_HANDLE(handle);
    res = DeviceIoControl(h->device, IOCTL_XS_GRANT_UNMAP,
                          &in, sizeof(in), NULL, 0, &ignore, NULL);
    if (!res) {
        /* This can't happen */
        OutputDebugString("Kernel rejected our attempt to unmap a gref!\n");
        DebugBreak();
    }
}

BOOL
xenops_evtchn_listen(struct xenops_handle *h, DOMAIN_ID domid, HANDLE event,
                     EVTCHN_PORT *evtchn_port)
{
    XS_EVTCHN_LISTEN_IN in;
    XS_EVTCHN_LISTEN_OUT out;
    DWORD ignore;

    in.domid = unwrap_DOMAIN_ID(domid);
    in.event_handle = (ULONG64)(ULONG_PTR)event;
    out.evtchn_port = 0xf001dead;
    if (!DeviceIoControl(h->device, IOCTL_XS_EVTCHN_LISTEN,
                         &in, sizeof(in), &out, sizeof(out),
                         &ignore, NULL)) {
        *evtchn_port = null_EVTCHN_PORT();
        return FALSE;
    }
    *evtchn_port = wrap_EVTCHN_PORT(out.evtchn_port);
    return TRUE;
}

BOOL
xenops_evtchn_connect(struct xenops_handle *h, DOMAIN_ID domid,
                      ALIEN_EVTCHN_PORT remote_port, HANDLE event,
                      EVTCHN_PORT *evtchn_port)
{
    XS_EVTCHN_CONNECT_IN in;
    XS_EVTCHN_CONNECT_OUT out;
    DWORD ignore;

    in.domid = unwrap_DOMAIN_ID(domid);
    in.remote_port = unwrap_ALIEN_EVTCHN_PORT(remote_port);
    in.event_handle = (ULONG64)(ULONG_PTR)event;
    out.evtchn_port = 0xf001dead;
    if (!DeviceIoControl(h->device, IOCTL_XS_EVTCHN_CONNECT,
                         &in, sizeof(in), &out, sizeof(out),
                         &ignore, NULL)) {
        *evtchn_port = null_EVTCHN_PORT();
        return FALSE;
    }
    *evtchn_port = wrap_EVTCHN_PORT(out.evtchn_port);
    return TRUE;
}

void
xenops_evtchn_close(struct xenops_handle *h, EVTCHN_PORT evtchn_port)
{
    XS_EVTCHN_CLOSE op;
    DWORD ignore;

    if (is_null_EVTCHN_PORT(evtchn_port))
        return;

    op.evtchn_port = unwrap_EVTCHN_PORT(evtchn_port);
    if (!DeviceIoControl(h->device, IOCTL_XS_EVTCHN_CLOSE, &op, sizeof(op),
                         NULL, 0, &ignore, NULL)) {
        /* This can't happen */
        OutputDebugString("Kernel rejected our attempt to close an event channel port!\n");
        DebugBreak();
    }
}

void
xenops_evtchn_notify(struct xenops_handle *h, EVTCHN_PORT evtchn_port)
{
    XS_EVTCHN_KICK op;
    DWORD ignore;

    op.evtchn_port = unwrap_EVTCHN_PORT(evtchn_port);
    if (!DeviceIoControl(h->device, IOCTL_XS_EVTCHN_KICK, &op, sizeof(op),
                         NULL, 0, &ignore, NULL)) {
        /* This can't happen */
        OutputDebugString("Kernel rejected our attempt to kick an event channel port!\n");
        DebugBreak();
    }
}
