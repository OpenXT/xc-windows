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
#include <xsapi.h>
#define XSAPI_FUTURE_GRANT_MAP
#include <xsapi-future.h>
#include <scsiboot.h>

#include "hypercall.h"
#include "iohole.h"
#include "xenbus.h"
#include "gntmap.h"
#include "evtchn.h"
#include "xenutl.h"

#include <grant_table.h>

#define GNTMAP_HANDLE_VALID 0x80000000

struct grant_map_detail {
    unsigned nr_grefs;
    unsigned suspend_count;
};

PMDL
GntmapMdl(struct grant_map_detail *gmd)
{
    return (PMDL)(gmd + 1);
}

static unsigned *
get_gmd_handles(struct grant_map_detail *gmd)
{
    PMDL mdl;
    mdl = GntmapMdl(gmd);
    return (unsigned *)((ULONG_PTR)mdl + mdl->Size);
}

static uint64_t *
get_gmd_bus_addrs(struct grant_map_detail *gmd)
{
    return (uint64_t *)(get_gmd_handles(gmd) + gmd->nr_grefs);
}

static unsigned
gmd_size_for_nr_grefs(unsigned nr_grefs)
{
    return sizeof(struct grant_map_detail) + sizeof(MDL) +
        (sizeof(uint64_t) + sizeof(unsigned) + sizeof(PFN_NUMBER)) * nr_grefs;
}

NTSTATUS
GntmapMapGrants(DOMAIN_ID domid,
                unsigned nr_grefs,
                const ALIEN_GRANT_REF *grefs,
                GRANT_MODE mode,
                struct grant_map_detail **detail)
{
    struct grant_map_detail *work;
    gnttab_map_grant_ref_t *ops;
    int rc;
    unsigned x;
    PFN_NUMBER pfn;
    PMDL mdl;
    NTSTATUS status;
    SUSPEND_TOKEN token;

    XM_ASSERT(*detail == 0);

    if (nr_grefs > (32768 - sizeof(MDL)) / sizeof(PFN_NUMBER)) {
        /* Trying to map this much would overflow the MDL size field */
        return STATUS_INVALID_PARAMETER;
    }

    status = STATUS_INSUFFICIENT_RESOURCES;
    ops = XmAllocateZeroedMemory(sizeof(*ops) * nr_grefs);
    work = XmAllocateZeroedMemory(gmd_size_for_nr_grefs(nr_grefs));
    if (!work || !ops)
        goto err;

    work->nr_grefs = nr_grefs;

    mdl = GntmapMdl(work);
    mdl->Size = (SHORT)(sizeof(*mdl) + sizeof(PFN_NUMBER) * nr_grefs);
    mdl->MdlFlags = MDL_PAGES_LOCKED | MDL_IO_SPACE;
    mdl->ByteCount = nr_grefs * PAGE_SIZE;
    for (x = 0; x < nr_grefs; x++) {
        pfn = XenevtchnAllocIoPFN();
        if (!pfn)
            goto err;
        MmGetMdlPfnArray(mdl)[x] = pfn;
        ops[x].host_addr = (ULONG64)pfn << PAGE_SHIFT;
        ops[x].flags = GNTMAP_host_map;
        if (unwrap_GRANT_MODE(mode) == unwrap_GRANT_MODE(GRANT_MODE_RO))
            ops[x].flags |= GNTMAP_readonly;
        ops[x].ref = unwrap_ALIEN_GRANT_REF(grefs[x]);
        ops[x].dom = (domid_t)unwrap_DOMAIN_ID(domid);
    }

    token = EvtchnAllocateSuspendToken("gntmap");
    rc = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, ops, nr_grefs);
    work->suspend_count = SuspendGetCount();
    EvtchnReleaseSuspendToken(token);
    if (rc < 0) {
        TraceWarning(("Failed to do grant hypercall: %d", rc));
        status = STATUS_UNSUCCESSFUL;
        goto err;
    }
    status = STATUS_SUCCESS;
    for (x = 0; x < nr_grefs; x++) {
        if (ops[x].status) {
            TraceWarning(("Grant map operation %d/%d failed: %d\n",
                          x, nr_grefs, ops[x].status));
            status = STATUS_UNSUCCESSFUL;
        } else {
            get_gmd_handles(work)[x] = ops[x].handle | GNTMAP_HANDLE_VALID;
            get_gmd_bus_addrs(work)[x] = ops[x].dev_bus_addr;
        }
    }

err:
    XmFreeMemory(ops);
    if (!NT_SUCCESS(status)) {
        if (work)
            GntmapUnmapGrants(work);
    } else {
        *detail = work;
    }

    return status;
}

void
GntmapUnmapGrants(struct grant_map_detail *detail)
{
    gnttab_unmap_grant_ref_t op;
    int rc;
    unsigned x;
    PMDL mdl;
    SUSPEND_TOKEN token;

    XM_ASSERT(detail != NULL);
    mdl = GntmapMdl(detail);
    XM_ASSERT((mdl->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA) == 0);
    XM_ASSERT(mdl->MdlFlags & (MDL_PAGES_LOCKED|MDL_IO_SPACE));

    for (x = 0; x < detail->nr_grefs; x++) {
        if (get_gmd_handles(detail)[x] & GNTMAP_HANDLE_VALID) {
            memset(&op, 0, sizeof(op));
            op.host_addr = (ULONG64)MmGetMdlPfnArray(mdl)[x] << PAGE_SHIFT;
            op.dev_bus_addr = get_gmd_bus_addrs(detail)[x];
            op.handle = get_gmd_handles(detail)[x] & ~GNTMAP_HANDLE_VALID;
            token = EvtchnAllocateSuspendToken("gnt unmap");
            if (detail->suspend_count == SuspendGetCount()) {
                rc = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op,
                                               1);
                XM_ASSERT(rc == 0);
                XM_ASSERT(op.status == 0);
            }
            EvtchnReleaseSuspendToken(token);
        }
        if (MmGetMdlPfnArray(mdl)[x])
            XenevtchnReleaseIoPFN(MmGetMdlPfnArray(mdl)[x]);
    }
    XmFreeMemory(detail);
}

NTSTATUS
xenbus_read_grant_ref(xenbus_transaction_t xbt, const char *prefix,
                      const char *node, ALIEN_GRANT_REF *gref)
{
    NTSTATUS status;
    ULONG64 res;

    *gref = null_ALIEN_GRANT_REF();
    status = xenbus_read_int(xbt, prefix, node, &res);
    if (!NT_SUCCESS(status))
        return status;
    if (res != (unsigned)res || res == 0) {
        xenbus_fail_transaction(xbt, STATUS_DATA_ERROR);
        return STATUS_DATA_ERROR;
    }
    *gref = wrap_ALIEN_GRANT_REF((unsigned)res);
    return STATUS_SUCCESS;
}
