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

#include <ntifs.h>
#include <csq.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include "xenv4v.h"

// A line is something like:
// (12 + (16 * 2) + (2 * 1) + 2 + (16 * 1) + (2 * 1) + 1) = 67 --> 128
#define XENV4V_DUMP_SIZE 127

static VOID
V4vHexdumpRing(void *_b, int len)
{
    uint8_t *b = _b;
    int s = 0;
    int e = len;
    int i, j;
    char *buf;
    char *fmt;

    buf = (char*)ExAllocatePoolWithTag(NonPagedPool, 2*(XENV4V_DUMP_SIZE + 1), XENV4V_TAG);
    if (buf == NULL) {
        TraceError(("failed to allocate ring dump buffer\n"));
        return;
    }
    RtlZeroMemory(buf, 2*(XENV4V_DUMP_SIZE + 1));
    // Two areas, the main buffer to cat into and the format buffer
    fmt = buf + XENV4V_DUMP_SIZE + 1;

    for (i = 0; i < (e + 15); i += 16) {
        RtlStringCchPrintfA(buf, XENV4V_DUMP_SIZE, "[%08x]: ", i);
        for (j = 0; j < 16; ++j) {
            int k = i + j;
            if (j == 8) {
                RtlStringCchCatA(buf, XENV4V_DUMP_SIZE, " ");
            }

            if ((k >= s) && (k < e)) {
                RtlStringCchPrintfA(fmt, XENV4V_DUMP_SIZE, "%02x", b[k]);
                RtlStringCchCatA(buf, XENV4V_DUMP_SIZE, fmt);
            }
            else {
                RtlStringCchCatA(buf, XENV4V_DUMP_SIZE, "  ");
            }
        }
        
        RtlStringCchCatA(buf, XENV4V_DUMP_SIZE, "  ");

        for (j = 0; j < 16; ++j) {
            int k = i + j;
            if (j == 8) {
                RtlStringCchCatA(buf, XENV4V_DUMP_SIZE, " ");
            }
            
            if ((k >= s) && (k < e)) {
                RtlStringCchPrintfA(fmt, XENV4V_DUMP_SIZE, "%c", ((b[k] > 32) && (b[k] < 127)) ? b[k] : '.');
                RtlStringCchCatA(buf, XENV4V_DUMP_SIZE, fmt);
            }
            else {
                RtlStringCchCatA(buf, XENV4V_DUMP_SIZE, " ");
            }
        }
        RtlStringCchCatA(buf, XENV4V_DUMP_SIZE, "\n");
        TraceNotice((buf));      
    }

    ExFreePoolWithTag(buf, XENV4V_TAG);
}

// Caller must hold lock
VOID
V4vDumpRing(v4v_ring_t *r)
{
    TraceNotice(("v4v_ring_t at %p:\n", r));
    TraceNotice(("r->rx_ptr=%d r->tx_ptr=%d r->len=%d\n", r->rx_ptr, r->tx_ptr, r->len));
    V4vHexdumpRing((void*)r->ring, r->len);
}

// Caller must hold lock
VOID
V4vRecoverRing(XENV4V_CONTEXT *ctx)
{
    // It's all gone horribly wrong
    TraceError(("something went horribly wrong in a ring - dumping and attempting a recovery\n"));
    
    V4vDumpRing(ctx->ringObject->ring);
    // Xen updates tx_ptr atomically to always be pointing somewhere sensible
    ctx->ringObject->ring->rx_ptr = ctx->ringObject->ring->tx_ptr;
}

static v4v_pfn_list_t*
V4vAllocatePfnList(uint8_t *buf, uint32_t npages)
{    
    v4v_pfn_list_t   *pfns;
    PHYSICAL_ADDRESS  pa;
    uint32_t          len = sizeof(v4v_pfn_list_t) + (sizeof(v4v_pfn_t) * npages);
    uint32_t          i;

    pfns = (v4v_pfn_list_t*)ExAllocatePoolWithTag(NonPagedPool, len, XENV4V_TAG);
    if (pfns == NULL) {
        return NULL;
    }
    RtlZeroMemory(pfns, len);
    pfns->magic = V4V_PFN_LIST_MAGIC;
    pfns->npage = npages;

    for (i = 0; i < npages; i++) {
        pa = MmGetPhysicalAddress(buf);
        pfns->pages[i] = pa.QuadPart/PAGE_SIZE;
        buf += PAGE_SIZE;
    }

    return pfns;
}

XENV4V_RING*
V4vAllocateRing(uint32_t ringLength)
{
    uint32_t     length;
    uint32_t     npages;
    XENV4V_RING *robj;

    // OK, make it
    robj = (XENV4V_RING*)ExAllocatePoolWithTag(NonPagedPool, sizeof(XENV4V_RING), XENV4V_TAG);
    if (robj == NULL) {
        return NULL;
    }
    RtlZeroMemory(robj, sizeof(XENV4V_RING));
    InitializeListHead(&robj->le);

    // Add one ref count for the caller creating the ring
    robj->refc = 1;

    length = ringLength + sizeof(v4v_ring_t);
    npages = (length + PAGE_SIZE - 1) >> PAGE_SHIFT;

    robj->ring = (v4v_ring_t*)ExAllocatePoolWithTag(NonPagedPool, length, XENV4V_TAG);
    if (robj->ring == NULL) {
        ExFreePoolWithTag(robj, XENV4V_TAG);
        return NULL;
    }
    RtlZeroMemory(robj->ring, length);
    KeInitializeSpinLock(&robj->lock);
    robj->ring->magic = V4V_RING_MAGIC;
    robj->ring->len = ringLength;
    robj->ring->rx_ptr = robj->ring->tx_ptr = 0;
    robj->ring->id.addr.port = V4V_PORT_NONE;
    robj->ring->id.addr.domain = V4V_DOMID_NONE;

    robj->pfnList = V4vAllocatePfnList((uint8_t*)robj->ring, npages);
    if (robj->pfnList == NULL) {
        ExFreePoolWithTag(robj->ring, XENV4V_TAG);
        ExFreePoolWithTag(robj, XENV4V_TAG);
        return NULL;
    }

    return robj;
}

ULONG32
V4vAddRefRing(XENV4V_EXTENSION *pde, XENV4V_RING *robj)
{
    KLOCK_QUEUE_HANDLE lqh;
    ULONG32            count;

    KeAcquireInStackQueuedSpinLock(&pde->ringLock, &lqh);
    count = ++robj->refc;
    KeReleaseInStackQueuedSpinLock(&lqh);

    return count;
}

ULONG32
V4vReleaseRing(XENV4V_EXTENSION *pde, XENV4V_RING *robj)
{
    KLOCK_QUEUE_HANDLE lqh;
    ULONG32            count;

    KeAcquireInStackQueuedSpinLock(&pde->ringLock, &lqh);
    ASSERT(robj->refc != 1); // SNO, really bad    
    count = --robj->refc;
    if (count == 1) {
        // Nobody but the list is holding us so remove ourself
        RemoveEntryList(&robj->le);
        count = 0;
    }
    KeReleaseInStackQueuedSpinLock(&lqh);

    if (count == 0) {
        // If it was successfully registered, then unregister it here
        if (robj->registered) {
            V4vUnregisterRing(robj);
        }
        if (robj->pfnList != NULL) {
            ExFreePoolWithTag(robj->pfnList, XENV4V_TAG);
        }
        if (robj->ring != NULL) {
            ExFreePoolWithTag(robj->ring, XENV4V_TAG);
        }
        ExFreePoolWithTag(robj, XENV4V_TAG);
    }

    return count;
}

static BOOLEAN
V4vPortInUse(XENV4V_EXTENSION *pde, uint32_t port, uint32_t *maxOut)
{
    BOOLEAN      ret = FALSE;
    XENV4V_RING *robj = NULL;

    if (!IsListEmpty(&pde->ringList)) {
        robj = (XENV4V_RING*)pde->ringList.Flink;
        while (robj != (XENV4V_RING*)&pde->ringList) {
            if (robj->ring->id.addr.port == port) {
                ret = TRUE; // found one
            }
            // Bump the max
            if ((maxOut != NULL)&&(robj->ring->id.addr.port > *maxOut)) {
                *maxOut = robj->ring->id.addr.port;
            }
            robj = (XENV4V_RING*)robj->le.Flink;
        }
    }

    return ret;
}

// Must be called at PASSIVE level
uint32_t
V4vRandomPort(XENV4V_EXTENSION *pde)
{
    uint32_t port;

    port = RtlRandomEx(&pde->seed);
    port |= 0x80000000U;
    return ((port > 0xf0000000U) ? (port - 0x10000000) : port);
}

// Must be called holding the lock
uint32_t
V4vSparePortNumber(XENV4V_EXTENSION *pde, uint32_t port)
{
    uint32_t max = 0x80000000U;

    if (V4vPortInUse(pde, port, &max)) {
        port = max + 1;
    }

    return port;
}

// Must be called holding the lock
BOOLEAN
V4vRingIdInUse(XENV4V_EXTENSION *pde, struct v4v_ring_id *id)
{
    XENV4V_RING *robj = NULL;

    if (!IsListEmpty(&pde->ringList)) {
        robj = (XENV4V_RING*)pde->ringList.Flink;
        while (robj != (XENV4V_RING*)&pde->ringList) {
            if ((robj->ring->id.addr.port == id->addr.port)&&
                (robj->ring->id.partner == id->partner)) {
                return TRUE;
            }
            robj = (XENV4V_RING*)robj->le.Flink;
        }
    }

    return FALSE;
}

// Must be called holding the lock
VOID
V4vLinkToRingList(XENV4V_EXTENSION *pde, XENV4V_RING *robj)
{
    // Add a reference for the list - mainly for consistency
    robj->refc++;
	
    // Link this context into the adapter list
    InsertHeadList(&pde->ringList, &(robj->le));
    //TraceInfo(("added ring object %p to list.\n", robj));
}
