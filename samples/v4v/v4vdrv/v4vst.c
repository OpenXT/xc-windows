/*
 * Copyright (c) 2011 Citrix Systems, Inc.
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
#include "types.h"
#include "v4vdrv.h"
#include "xsapi.h"
#include "../xenutil/hypercall.h"
#include "../xenutil/evtchn.h"
#include "xen_types.h"
DEFINE_XEN_GUEST_HANDLE(void);

#include "v4v.h"

static VOID
v4v_hexdump(void *_b, int len)
{
    uint8_t *b = _b;
    int s = 0;
    int e = len;
    int i, j;

    for (i = 0; i < (e + 15); i += 16) {
        DbgPrint("[V4V]  %08x:\n", i);
        for (j = 0; j < 16; ++j) {
            int k = i + j;
            if (j == 8)
                DbgPrint(" ");
            if ((k >= s) && (k < e))
                DbgPrint("%02x", b[k]);
            else
                DbgPrint("  ");
        }
        DbgPrint("  ");

        for (j = 0; j < 16; ++j) {
            int k = i + j;
            if (j == 8)
                DbgPrint(" ");
            if ((k >= s) && (k < e))
                DbgPrint("%c", ((b[k] > 32) && (b[k] < 127)) ? b[k] : '.');
            else
                DbgPrint(" ");
        }
        DbgPrint("\n");
    }
}

static VOID
v4v_dump_ring(v4v_ring_t *r)
{
    DbgPrint("[V4V] v4v_ring_t at %p:\n", r);
    DbgPrint("[V4V] r->rx_ptr=%d r->tx_ptr=%d r->len=%d\n", r->rx_ptr, r->tx_ptr, r->len);
    //v4v_hexdump(r->ring, r->len);
    //DbgPrint("[V4V]\n");
}

struct v4v_virq_notify {
    void (*virq_notify_fn)(void *virq_notify_ctx);
    void *virq_notify_ctx;
};

static EVTCHN_PORT v4v_virq_port = {0};

static NTSTATUS
v4v_initialize(struct v4v_virq_notify *virq_notify)
{
    ASSERT(virq_notify != NULL);
    ASSERT(virq_notify->virq_notify_fn != NULL);

    /* This must only be called once */
    if (!is_null_EVTCHN_PORT(v4v_virq_port)) {
        DbgPrint("[V4V] VIRQ alread connected?\n");
        return STATUS_UNSUCCESSFUL;
    }

    v4v_virq_port = EvtchnBindVirq(VIRQ_V4V, virq_notify->virq_notify_fn, virq_notify->virq_notify_ctx);
    if (is_null_EVTCHN_PORT(v4v_virq_port)) {
        DbgPrint("[V4V] failed to bind V4V VIRQ!\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
v4v_uninitialize(void)
{
    if (!is_null_EVTCHN_PORT(v4v_virq_port)) {
        EvtchnClose(v4v_virq_port);
        v4v_virq_port = null_EVTCHN_PORT();
        return STATUS_SUCCESS;
    }
    DbgPrint("[V4V] VIRQ not connected?\n");
    return STATUS_UNSUCCESSFUL;
}

static NTSTATUS
v4v_register_ring(v4v_ring_t *ring, v4v_pfn_list_t *pfn_list)
{
    int err;

    ASSERT(ring != NULL);

    err = HYPERVISOR_v4v_op(V4VOP_register_ring, ring, pfn_list, 0, 0, 0);
    if (err != 0) {
        DbgPrint("%s - register ring failed - hypercall err: %d\n", V4VDRV_LOGTAG, err);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
v4v_unregister_ring(v4v_ring_t *ring)
{
    int err;

    ASSERT(ring != NULL);

    err = HYPERVISOR_v4v_op(V4VOP_unregister_ring, ring, 0, 0, 0, 0);
    if (err != 0) {
        DbgPrint("%s - unregister ring failed - hypercall err: %d\n", V4VDRV_LOGTAG, err);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
v4v_send(v4v_addr_t *src, v4v_addr_t *dest, uint32_t protocol, void *buf, uint32_t buf_len, uint32_t *read_out)
{
    int err;
    NTSTATUS status = STATUS_SUCCESS;

    ASSERT(src != NULL);
    ASSERT(dest != NULL);
    ASSERT(buf != NULL);
    ASSERT(read_out != NULL);

    *read_out = 0;

    err = HYPERVISOR_v4v_op(V4VOP_send, src, dest, buf, buf_len, protocol);
    if (err < 0) {
        switch (err) {
        case -EAGAIN:
            status = STATUS_RETRY;
            break;
        case -EINVAL:
            status = STATUS_INVALID_PARAMETER;
            break;
        case -ENOMEM:
            status = STATUS_NO_MEMORY;
            break;
        case -ENOSPC:
            status = STATUS_BUFFER_OVERFLOW;
            break;
        case -ENOSYS:
            status = STATUS_NOT_IMPLEMENTED;
            break;
        case -ENOTCONN:
        case -ECONNREFUSED:
            status = STATUS_PORT_DISCONNECTED;
            break;
        case -EFAULT:
        default:
            DbgPrint("%s - send data failed - hypercall err: %d\n", V4VDRV_LOGTAG, err);
            status = STATUS_UNSUCCESSFUL;
        };       
    }
    else {
        *read_out = (uint32_t)err;
    }

    return status;
}

static NTSTATUS
v4v_notify(v4v_ring_data_t *ring_data)
{
    int err;

    ASSERT(ring_data != NULL);

    err = HYPERVISOR_v4v_op(V4VOP_notify, ring_data, 0, 0, 0, 0);
    if (err != 0) {
        DbgPrint("%s - notify ring data failed - hypercall err: %d\n", V4VDRV_LOGTAG, err);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

#define V4VDRV_RING_SIZE 64
#define V4VDRV_RING_PORT 1
#define V4VDRV_RING_PROTOCOL 1
#define V4VDRV_DPC_TIMEOUT 5000 //ms
#define V4VDRV_RECV_SIZE 64
#define LargeIntRelDelay(ms) (ULONG64) -(10000 * ((LONG32) (ms)))

static BOOLEAN g_init = FALSE;
static KTIMER g_timer = {0};
static KDPC g_dpc = {0};
static v4v_ring_t *g_ring = NULL;
static LARGE_INTEGER g_timeout = {0};
static BOOLEAN g_hosed = FALSE;

static void
V4vVirqNotify(void *ctx)
{
    ctx;
    DbgPrint("%s - notification on VIRQ_V4V\n", V4VDRV_LOGTAG);
}

static void
V4vTimerNotify(PKDPC dpc, PVOID ctx, PVOID sarg1, PVOID sarg2)
{
    char *data = "abcdefgh";
    NTSTATUS status;
    v4v_addr_t dest, dest_out;
    size_t msize;
    char buf[V4VDRV_RECV_SIZE];
    int i = 0;
    uint32_t protocol_out, read_out;
    UCHAR ring_data_buf[sizeof(v4v_ring_data_t) + sizeof(v4v_ring_data_ent_t)];
    v4v_ring_data_t *ring_data;
    v4v_ring_data_ent_t *ring_data_ent;

    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(sarg1);
    UNREFERENCED_PARAMETER(sarg2);

    dest.port = V4VDRV_RING_PORT;
    dest.domain = g_ring->id.partner;

    /* See if we are in a bad state */
    if (g_hosed) {
        DbgPrint("%s - we are in a bad state - do nothing\n", V4VDRV_LOGTAG);
        goto notify_out;
    }

    /* First try sending some goodies */
    status = v4v_send(&g_ring->id.addr, &dest, V4VDRV_RING_PROTOCOL, data, 8, &read_out);
    switch (status) {
    case STATUS_SUCCESS:
        DbgPrint("%s - send data successful - read: 0x%x\n", V4VDRV_LOGTAG, read_out);
        break;
    case STATUS_RETRY:
        DbgPrint("%s - send data: ring full, cannot send\n", V4VDRV_LOGTAG);
        break;
    case STATUS_PORT_DISCONNECTED:
        DbgPrint("%s - send data: other end not connected\n", V4VDRV_LOGTAG);
        goto notify_out;
    default:
        DbgPrint("%s - send failed - error: 0x%x\n", V4VDRV_LOGTAG, status);
    };

    /* Now try to see if there is any data */
    while (g_ring->rx_ptr != g_ring->tx_ptr) {
        v4v_dump_ring(g_ring);
        i++;
        msize = v4v_copy_out(g_ring, &dest_out, &protocol_out, buf, V4VDRV_RECV_SIZE, 1);
        if (msize != (size_t)-1) {
            if (msize <= V4VDRV_RECV_SIZE) {
                DbgPrint("%s(%d) - I just read final 0x%x bytes from my partner %d\n", V4VDRV_LOGTAG, i, msize, dest.domain);
            }
            else {
                DbgPrint("%s(%d) - I just read 0x%x bytes partial message of 0x%x total bytes from my partner %d\n",
                         V4VDRV_LOGTAG, i, V4VDRV_RECV_SIZE, msize, dest.domain);
            }
        }
        else {
            DbgPrint("%s(%d) - I just read nothing from my partner %d, ending read loop\n", V4VDRV_LOGTAG, i, dest.domain);
            break;
        }

        if (i == 200) {
            DbgPrint("%s(%d) - too many read attempts, ending read loop\n", V4VDRV_LOGTAG, i);
            g_hosed = TRUE;
            break;
        }
    }

    /* Call notify to tell xen we read data and see if there is space available */
    RtlZeroMemory(ring_data_buf, sizeof(v4v_ring_data_t) + sizeof(v4v_ring_data_ent_t));
    ring_data = (v4v_ring_data_t*)ring_data_buf;
    ring_data_ent = (v4v_ring_data_ent_t*)(ring_data_buf + FIELD_OFFSET(v4v_ring_data_t, data));
    ring_data->magic = V4V_RING_DATA_MAGIC;
    ring_data->nent = 1;
    ring_data_ent->ring = dest;
    ring_data_ent->space_required = 8;

    status = v4v_notify(ring_data);
    if (!NT_SUCCESS(status)) {
        DbgPrint("%s - notify failed - error: 0x%x\n", V4VDRV_LOGTAG, status);
        goto notify_out;
    }

    DbgPrint("%s - notify flags: 0x%x\n", V4VDRV_LOGTAG, ring_data_ent->flags);

notify_out:
    KeSetTimer(&g_timer, g_timeout, &g_dpc);
}

NTSTATUS
V4vStartDriverTest(V4VD_IOCD_START_DRIVER_TEST *sdt)
{
    NTSTATUS status = STATUS_SUCCESS, status2;
    struct v4v_virq_notify notify = {V4vVirqNotify, NULL};
    v4v_pfn_list_t *pfn_list = NULL;
    v4v_pfn_t *ptr;
    PHYSICAL_ADDRESS pa;

    DbgPrint("%s - start simple test\n", V4VDRV_LOGTAG);

    do {
        if (g_init) {
            DbgPrint("%s - simple test already running - cannot start!\n", V4VDRV_LOGTAG);
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        pfn_list = ExAllocatePoolWithTag(NonPagedPool, sizeof(v4v_pfn_list_t) + sizeof(v4v_pfn_t), V4VDRV_TAG);
        if (pfn_list == NULL) {
            DbgPrint("%s - driver test cannot allocate pfn list!\n", V4VDRV_LOGTAG);
            status = STATUS_NO_MEMORY;
            break;
        }

        g_ring = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, V4VDRV_TAG);
        if (g_ring == NULL) {
            DbgPrint("%s - driver test cannot allocate ring!\n", V4VDRV_LOGTAG);
            status = STATUS_NO_MEMORY;
            break;
        }

        // Setup the ring
        RtlZeroMemory(g_ring, sizeof(struct v4v_ring) + V4VDRV_RING_SIZE);
        g_ring->magic = V4V_RING_MAGIC;
        g_ring->id.addr.port = V4VDRV_RING_PORT;
        g_ring->id.addr.domain = DOMID_SELF;
        g_ring->id.partner = sdt->partnerDomain;
        g_ring->len = V4VDRV_RING_SIZE;
        g_ring->rx_ptr = 0; // start at beginning

        // Setup the pfn list
        RtlZeroMemory(pfn_list, sizeof(struct v4v_pfn_list_t) + sizeof(v4v_pfn_t));
        pfn_list->magic = V4V_PFN_LIST_MAGIC;
        pfn_list->npage = 1;
        ptr = (v4v_pfn_t*)((UCHAR*)pfn_list + FIELD_OFFSET(v4v_pfn_list_t, pages));
        pa = MmGetPhysicalAddress(g_ring);
        *ptr = pa.QuadPart/PAGE_SIZE;

        KeInitializeTimer(&g_timer);
        KeInitializeDpc(&g_dpc, V4vTimerNotify, NULL);
        g_timeout.QuadPart = LargeIntRelDelay(V4VDRV_DPC_TIMEOUT);
    
        status = v4v_initialize(&notify);
        if (!NT_SUCCESS(status)) {
            DbgPrint("%s - driver test failed to initialize V4V core - error: 0x%x\n", V4VDRV_LOGTAG, status);
            break;
        }

        status = v4v_register_ring(g_ring, pfn_list);
        if (!NT_SUCCESS(status)) {
            DbgPrint("%s - driver test failed to register ring - error: 0x%x\n", V4VDRV_LOGTAG, status);
            status2 = v4v_uninitialize();
            if (!NT_SUCCESS(status2)) {
                DbgPrint("%s - driver test failed to uninitialize V4V core - error: 0x%x\n", V4VDRV_LOGTAG, status2);
            }
            break;
        }

        KeSetTimer(&g_timer, g_timeout, &g_dpc);

        g_init = TRUE;
    } while (FALSE);

    if ((!NT_SUCCESS(status))&&(g_ring != NULL)) {
        ExFreePoolWithTag(g_ring, V4VDRV_TAG);
        g_ring = NULL;
    }

    if (pfn_list != NULL) {
        ExFreePoolWithTag(pfn_list, V4VDRV_TAG); 
    }
    return STATUS_SUCCESS;
}

VOID
V4vStopDriverTest(void)
{
    NTSTATUS status;

    if (!g_init) {
        DbgPrint("%s - driver test not running - cannot stop!\n", V4VDRV_LOGTAG);
        return;
    }

    /* Cancel our timer on the way out. It is ok to cancel it even if it is not in the
       queue. This will cover all cases (set or not). */
    KeCancelTimer(&g_timer);

    status = v4v_unregister_ring(g_ring);
    if (!NT_SUCCESS(status)) {
        DbgPrint("%s - driver test failed to unregister ring - error: 0x%x\n", V4VDRV_LOGTAG, status);
    }

    status = v4v_uninitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrint("%s - driver test failed to uninitialize V4V core - error: 0x%x\n", V4VDRV_LOGTAG, status);
    }

    ExFreePoolWithTag(g_ring, V4VDRV_TAG); 
    g_ring = NULL;
    g_hosed = FALSE;
    g_init = FALSE;
}
