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

/* All the bits needed to expose an interface to userspace. */
#include "ntddk.h"
#define XSAPI_FUTURE_GRANT_MAP
#define XSAPI_FUTURE_CONNECT_EVTCHN
#include "xsapi.h"
#include "xsapi-future.h"
#include "xenevtchn.h"
#include "scsiboot.h"

#include "../xenutil/xenbus.h"
#include "../xenutil/evtchn.h"
#include "../xenutil/balloon.h"
#include "../xenutil/gntmap.h"
#include "../xenutil/diags.h"

/* By default, a process is only allowed to grant out access to 1MiB
   of memory, just as an anti-foot-shooting measure. */
#define GRANT_DEFAULT_QUOTA 256

struct user_grant {
    LIST_ENTRY list;
    PMDL mdl;
    GRANT_REF gref;
};

struct user_evtchn {
    LIST_ENTRY list;
    EVTCHN_PORT port;
    PKEVENT event;
};

struct write_on_close {
    LIST_ENTRY list;
    char *path;
    char *data;
    size_t data_size;
};

struct user_grant_map {
    LIST_ENTRY list;
    struct grant_map_detail *detail;
    PVOID virt_addr;
};

struct xevtchn_process_block {
    struct xevtchn_process_block *next;
    PEPROCESS process;
    LONG refcount;
    KSPIN_LOCK lock;
    LIST_ENTRY write_on_close; /* List of struct write_on_close,
                                * threaded on the list field. */
    LIST_ENTRY user_grants; /* List of struct user_grant, threaded
                             * through list field. */
    LIST_ENTRY user_grant_maps; /* List of struct user_grant_map,
                                 * threaded through the list field. */

    unsigned grant_quota;
    unsigned nr_grants;
};

/* Hash table from EPROCESSes to xevtchn_process_blocks */
#define NR_PROCESS_HASH_BUCKETS 32
static struct xevtchn_process_block *
xevtchn_active_process[NR_PROCESS_HASH_BUCKETS];
static KSPIN_LOCK
xevtchn_active_process_lock;

/* Support for freezing the Xenbus userspace interface so that we
   don't have stuff sitting on the ring when we hibernate. */
static LIST_ENTRY XenbusIrpQueue;
static KEVENT UserXenbusIdle;
static ULONG UserXenbusRequestsLive;
static KSPIN_LOCK XenbusFreezeLock;

static void
ReferenceXprocess(struct xevtchn_process_block *xpb)
{
    InterlockedIncrement(&xpb->refcount);
}

static void
DereferenceXprocess(struct xevtchn_process_block *xpb)
{
    if (!InterlockedDecrement(&xpb->refcount))
        XmFreeMemory(xpb);
}

static unsigned
HashEprocess(PEPROCESS process)
{
    unsigned e = (unsigned)(ULONG_PTR)process;
    unsigned acc;
    acc = e;
    e /= NR_PROCESS_HASH_BUCKETS;
    acc ^= e;
    e /= NR_PROCESS_HASH_BUCKETS;
    acc ^= e;
    e /= NR_PROCESS_HASH_BUCKETS;
    acc ^= e;
    return acc % NR_PROCESS_HASH_BUCKETS;
}

static struct xevtchn_process_block *
EprocessToXprocess(PEPROCESS process)
{
    unsigned hash = HashEprocess(process);
    struct xevtchn_process_block *cursor, **prev;
    KIRQL irql;

    KeAcquireSpinLock(&xevtchn_active_process_lock, &irql);
    prev = &xevtchn_active_process[hash];
    cursor = *prev;
    while (cursor && cursor->process != process) {
        prev = &cursor->next;
        cursor = *prev;
    }
    if (cursor) {
        /* Pull-to-front */
        *prev = cursor->next;
        cursor->next = xevtchn_active_process[hash];
        xevtchn_active_process[hash] = cursor;

        ReferenceXprocess(cursor);
    }
    KeReleaseSpinLock(&xevtchn_active_process_lock, irql);
    return cursor;
}

static struct xevtchn_process_block *
CurrentXprocess(void)
{
    return EprocessToXprocess(PsGetCurrentProcess());
}

static struct xevtchn_process_block *
NewXprocess(PEPROCESS process)
{
    unsigned hash = HashEprocess(process);
    struct xevtchn_process_block *work;
    KIRQL irql;

    work = XmAllocateZeroedMemory(sizeof(*work));
    if (!work)
        return NULL;
    InitializeListHead(&work->write_on_close);
    InitializeListHead(&work->user_grants);
    InitializeListHead(&work->user_grant_maps);
    ObReferenceObject(process);
    work->process = process;

    /* refcount = 2 because we're going to add it to the list (+1) and
       the caller needs a reference as well (+1) */
    work->refcount = 2;

    work->grant_quota = GRANT_DEFAULT_QUOTA;

    KeInitializeSpinLock(&work->lock);

    KeAcquireSpinLock(&xevtchn_active_process_lock, &irql);
    work->next = xevtchn_active_process[hash];
    xevtchn_active_process[hash] = work;
    KeReleaseSpinLock(&xevtchn_active_process_lock, irql);

    return work;
}

/* Find the process in the hash table and then remove it.  This is
   only valid when the process is shutting down. */
static struct xevtchn_process_block *
PopXprocess(PEPROCESS process)
{
    unsigned hash = HashEprocess(process);
    struct xevtchn_process_block *cursor, **prev;
    KIRQL irql;

    /* Quick lock-free test.  There are no memory barriers here, which
       means that a parallel insertion of the same process might not
       serialise correctly.  That's okay, because we know the process
       has finished running userspace, and so can't do any of the
       ioctls which would cause it to be added back to the hash. */
    if (!xevtchn_active_process[hash])
        return NULL;

    KeAcquireSpinLock(&xevtchn_active_process_lock, &irql);
    prev = &xevtchn_active_process[hash];
    cursor = *prev;
    while (cursor && cursor->process != process) {
        prev = &cursor->next;
        cursor = *prev;
    }
    if (cursor)
        *prev = cursor->next;
    KeReleaseSpinLock(&xevtchn_active_process_lock, irql);

    /* We removed it from the list, which would require a deref,
       except that the caller needs a reference, which cancels that
       out, so just leave the refcount alone. */

    return cursor;
}

/* Find the user watch with handle @handle and remove it from the
   list.  Returns the UWH or NULL if it wasn't found. */
static PUSER_WATCH_HANDLE
PopUserWatch(PXENEVTCHN_ACTIVE_HANDLE xah, int handle)
{
    KIRQL irql;
    PUSER_WATCH_HANDLE uwh;

    KeAcquireSpinLock(&xah->watches_lock, &irql);
    for (uwh = xah->watches; uwh && uwh->handle != handle; uwh = uwh->next)
        ;
    if (uwh) {
        if (uwh->prev)
            uwh->prev->next = uwh->next;
        else
            xah->watches = uwh->next;
        if (uwh->next)
            uwh->next->prev = uwh->prev;
        uwh->prev = uwh->next = NULL;
    }
    KeReleaseSpinLock(&xah->watches_lock, irql);
    return uwh;
}

/* Release @uwh.  The caller is expected to have ensured that it is no
   longer on the list.  No-op if @uwh is NULL. */
static void
ReleaseUserWatch(PUSER_WATCH_HANDLE uwh)
{
    if (uwh == NULL)
        return;
    XM_ASSERT(uwh->prev == NULL);
    XM_ASSERT(uwh->next == NULL);
    if (uwh->evt)
        ObDereferenceObject(uwh->evt);
    if (uwh->wh)
        xenbus_unregister_watch(uwh->wh);
    XmFreeMemory(uwh);
}

/* Attach a user watch to an active handle.  Returns the new handle
   for the watch, or -1 on error.  Note that there is nothing to stop
   userspace from unregistering (and thus freeing) the UWH once this
   has been called. */
static int
AttachUserWatch(PXENEVTCHN_ACTIVE_HANDLE xah, PUSER_WATCH_HANDLE uwh)
{
    KIRQL irql;
    int handle;
    PUSER_WATCH_HANDLE ouwh;

    XM_ASSERT(!uwh->prev);
    XM_ASSERT(!uwh->next);

    handle = 0;
    while (handle != -1) {
        KeAcquireSpinLock(&xah->watches_lock, &irql);
        for (ouwh = xah->watches;
             ouwh && ouwh->handle != handle;
             ouwh = ouwh->next)
            ;
        if (ouwh) {
            /* Drop the lock so as we let DPCs and APCs run and
               prevent a DoS when you have lots of watches on a single
               handle.  This is more of an anti-foot-shooting measure
               than a real security concern, because only the
               administrator is actually allowed to create watches. */
            KeReleaseSpinLock(&xah->watches_lock, irql);
            handle++;
            continue;
        }
        uwh->handle = handle;
        uwh->next = xah->watches;
        if (xah->watches)
            xah->watches->prev = uwh;
        xah->watches = uwh;
        KeReleaseSpinLock(&xah->watches_lock, irql);
        return handle;
    }

    return -1;
}

static PXENEVTCHN_ACTIVE_HANDLE
XenevtchnFindActiveHandle(
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx, 
    PFILE_OBJECT pfo
)
{
    PLIST_ENTRY head = &pXevtdx->ActiveHandles;
    PLIST_ENTRY entry;
    KIRQL irql;

    KeAcquireSpinLock(&pXevtdx->ActiveHandleLock, &irql);
    for (entry = head->Flink; entry != head;) {
        if (((PXENEVTCHN_ACTIVE_HANDLE)entry)->FileObject == pfo) {
            KeReleaseSpinLock(&pXevtdx->ActiveHandleLock, irql);
            return( (PXENEVTCHN_ACTIVE_HANDLE)entry );
        }
        entry = entry->Flink;
    }

    KeReleaseSpinLock(&pXevtdx->ActiveHandleLock, irql);
    return( NULL );
}

/* Release one unit of grant quota */
static void
GrantQuotaCredit(struct xevtchn_process_block *xpb)
{
    KIRQL irql;

    KeAcquireSpinLock(&xpb->lock, &irql);
    XM_ASSERT(xpb->nr_grants);
    xpb->nr_grants--;
    KeReleaseSpinLock(&xpb->lock, irql);
}

/* Consume one unit of grant quota */
static BOOLEAN
GrantQuotaDebit(struct xevtchn_process_block *xpb)
{
    KIRQL irql;
    BOOLEAN res;

    KeAcquireSpinLock(&xpb->lock, &irql);
    if (xpb->nr_grants < xpb->grant_quota) {
        xpb->nr_grants++;
        res = TRUE;
    } else {
        res = FALSE;
    }
    KeReleaseSpinLock(&xpb->lock, irql);
    return res;
}

static NTSTATUS
DoGrantAccess(unsigned _domid, ULONG64 va, BOOLEAN readonly,
              uint32_t *xen_grant_ref_out)
{
    DOMAIN_ID domid = wrap_DOMAIN_ID(_domid);
    GRANT_MODE mode = readonly ? GRANT_MODE_RO : GRANT_MODE_RW;
    struct xevtchn_process_block *xpb = CurrentXprocess();
    struct user_grant *ug;
    PFN_NUMBER frame;
    BOOLEAN locked;
    NTSTATUS res;
    KIRQL irql;

    locked = FALSE;
    ug = NULL;

    if (!xpb) {
        xpb = NewXprocess(PsGetCurrentProcess());
        if (!xpb) {
            res = STATUS_INSUFFICIENT_RESOURCES;
            goto err;
        }
    }

    if (!GrantQuotaDebit(xpb)) {
        res = STATUS_QUOTA_EXCEEDED;
        goto err;
    }

    res = STATUS_INVALID_PARAMETER;
    if (va & (PAGE_SIZE-1))
        goto err;
#ifdef AMD64
    if (IoIs32bitProcess(NULL) && (va > 0xfffff000))
        goto err;
#endif

    res = STATUS_INSUFFICIENT_RESOURCES;
    ug = XmAllocateZeroedMemory(sizeof(*ug));
    if (!ug)
        goto err;

    ug->mdl = IoAllocateMdl((PVOID)(ULONG_PTR)va,
                            PAGE_SIZE,
                            FALSE,
                            TRUE,
                            NULL);
    if (!ug->mdl)
        goto err;

    try {
        MmProbeAndLockPages(ug->mdl, UserMode,
                            readonly ? IoReadAccess : IoModifyAccess);
        locked = TRUE;
    } except (EXCEPTION_EXECUTE_HANDLER) {
        res = STATUS_ACCESS_VIOLATION;
        goto err;
    }
    XM_ASSERT(MmGetMdlByteCount(ug->mdl) == PAGE_SIZE);
    XM_ASSERT(MmGetMdlByteOffset(ug->mdl) == 0);
    XM_ASSERT(ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(ug->mdl),
                                             MmGetMdlByteCount(ug->mdl)) == 1);

    frame = MmGetMdlPfnArray(ug->mdl)[0];

    ug->gref = GnttabGrantForeignAccess(domid, frame, mode);
    if (is_null_GRANT_REF(ug->gref)) {
        res = STATUS_INSUFFICIENT_RESOURCES;
        goto err;
    }

    *xen_grant_ref_out = xen_GRANT_REF(ug->gref);

    KeAcquireSpinLock(&xpb->lock, &irql);
    InsertHeadList(&xpb->user_grants, &ug->list);
    KeReleaseSpinLock(&xpb->lock, irql);

    DereferenceXprocess(xpb);

    return STATUS_SUCCESS;

err:
    if (ug) {
        if (ug->mdl) {
            if (locked)
                MmUnlockPages(ug->mdl);
            IoFreeMdl(ug->mdl);
        }
        XmFreeMemory(ug);
    }
    if (xpb) {
        GrantQuotaCredit(xpb);
        DereferenceXprocess(xpb);
    }
    return res;
}

static NTSTATUS
DoUngrantAccess(uint32_t xen_grant_ref)
{
    struct xevtchn_process_block *xpb = CurrentXprocess();
    PLIST_ENTRY ple;
    struct user_grant *ug;
    NTSTATUS status;
    KIRQL irql;

    status = STATUS_INVALID_PARAMETER;
    if (!xpb)
        return status;

    /* Shut the compiler up */
    ug = NULL;

    KeAcquireSpinLock(&xpb->lock, &irql);
    for (ple = xpb->user_grants.Flink;
         ple != &xpb->user_grants;
         ple = ple->Flink) {
        ug = CONTAINING_RECORD(ple, struct user_grant, list);
        if (xen_GRANT_REF(ug->gref) == xen_grant_ref)
            break;
    }
    if (ple == &xpb->user_grants) {
    failed:
        KeReleaseSpinLock(&xpb->lock, irql);
        DereferenceXprocess(xpb);
        return status;
    }
    XM_ASSERT(ug);
    status = GnttabEndForeignAccess(ug->gref);
    if (!NT_SUCCESS(status))
        goto failed;

    /* We're now guaranteed to success */
    RemoveEntryList(&ug->list);
    KeReleaseSpinLock(&xpb->lock, irql);
    GrantQuotaCredit(xpb);
    DereferenceXprocess(xpb);

    MmUnlockPages(ug->mdl);
    IoFreeMdl(ug->mdl);
    XmFreeMemory(ug);

    return STATUS_SUCCESS;
}

static NTSTATUS
DoGrantGetQuota(unsigned *quota)
{
    struct xevtchn_process_block *xpb = CurrentXprocess();

    if (!xpb) {
        *quota = GRANT_DEFAULT_QUOTA;
    } else {
        *quota = xpb->grant_quota;
        DereferenceXprocess(xpb);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
DoGrantSetQuota(unsigned quota)
{
    struct xevtchn_process_block *xpb = CurrentXprocess();
    KIRQL irql;
    NTSTATUS status;

    if (!xpb) {
        xpb = NewXprocess(PsGetCurrentProcess());
        if (!xpb)
            return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeAcquireSpinLock(&xpb->lock, &irql);
    if (xpb->nr_grants > quota) {
        status = STATUS_INVALID_QUOTA_LOWER;
    } else {
        xpb->grant_quota = quota;
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&xpb->lock, irql);
    DereferenceXprocess(xpb);
    return status;
}

static NTSTATUS
DoGrantMap(unsigned _domid, unsigned nr_grefs, unsigned *_grefs,
           BOOLEAN readonly, ULONG64 *handle, ULONG64 *_va)
{
    struct xevtchn_process_block *xpb = CurrentXprocess();
    DOMAIN_ID domid = wrap_DOMAIN_ID(_domid);
    GRANT_MODE mode = readonly ? GRANT_MODE_RO : GRANT_MODE_RW;
    ALIEN_GRANT_REF *grefs;
    struct user_grant_map *ugm;
    NTSTATUS status;
    unsigned x;
    BOOLEAN mapped;
    KIRQL irql;

    mapped = FALSE;
    ugm = NULL;

    if (!xpb) {
        xpb = NewXprocess(PsGetCurrentProcess());
        if (!xpb)
            return STATUS_INSUFFICIENT_RESOURCES;
    }

    grefs = XmAllocateMemory(sizeof(grefs[0]) * nr_grefs);
    if (!grefs) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto err;
    }

    for (x = 0; x < nr_grefs; x++)
        grefs[x] = wrap_ALIEN_GRANT_REF(_grefs[x]);

    ugm = XmAllocateZeroedMemory(sizeof(*ugm));
    if (!ugm) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto err;
    }
    status = GntmapMapGrants(domid, nr_grefs, grefs, mode, &ugm->detail);
    if (!NT_SUCCESS(status))
        goto err;

    try {
        /* XXX what if the grant is readonly? */
        ugm->virt_addr =
            MmMapLockedPagesSpecifyCache(GntmapMdl(ugm->detail),
                                         UserMode,
                                         MmCached,
                                         NULL,
                                         FALSE,
                                         NormalPagePriority);
        mapped = TRUE;
    } except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
        goto err;
    }

    *handle = (ULONG64)(ULONG_PTR)ugm;
    *_va = (ULONG64)ugm->virt_addr;

    KeAcquireSpinLock(&xpb->lock, &irql);
    InsertHeadList(&xpb->user_grant_maps, &ugm->list);
    KeReleaseSpinLock(&xpb->lock, irql);
    DereferenceXprocess(xpb);

    XmFreeMemory(grefs);
    return STATUS_SUCCESS;

err:
    if (ugm) {
        if (mapped)
            MmUnmapLockedPages(ugm->virt_addr, GntmapMdl(ugm->detail));
        if (ugm->detail)
            GntmapUnmapGrants(ugm->detail);
        XmFreeMemory(ugm);
    }
    XmFreeMemory(grefs);
    DereferenceXprocess(xpb);
    return status;
}

static void
ReleaseUserGrantMap(struct user_grant_map *ugm)
{
    MmUnmapLockedPages(ugm->virt_addr, GntmapMdl(ugm->detail));
    GntmapUnmapGrants(ugm->detail);
    XmFreeMemory(ugm);
}

static NTSTATUS
DoGrantUnmap(ULONG64 handle)
{
    struct xevtchn_process_block *xpb = CurrentXprocess();
    struct user_grant_map *ugm;
    PLIST_ENTRY ple;
    KIRQL irql;

    if (!xpb)
        return STATUS_INVALID_PARAMETER;

    /* Shut the compiler up */
    ugm = NULL;

    KeAcquireSpinLock(&xpb->lock, &irql);
    for (ple = xpb->user_grant_maps.Flink;
         ple != &xpb->user_grant_maps;
         ple = ple->Flink) {
        ugm = CONTAINING_RECORD(ple, struct user_grant_map, list);
        if ((ULONG64)(ULONG_PTR)ugm == handle)
            break;
    }
    if (ple == &xpb->user_grant_maps) {
        KeReleaseSpinLock(&xpb->lock, irql);
        DereferenceXprocess(xpb);
        return STATUS_INVALID_PARAMETER;
    }
    RemoveEntryList(&ugm->list);
    KeReleaseSpinLock(&xpb->lock, irql);

    ReleaseUserGrantMap(ugm);

    DereferenceXprocess(xpb);

    return STATUS_SUCCESS;
}

static void
UserEventFired(void *ctxt)
{
    struct user_evtchn *ev = ctxt;

    KeSetEvent(ev->event, EVENT_INCREMENT, FALSE);
}

static NTSTATUS
DoEvtchnListenConnect(PXENEVTCHN_ACTIVE_HANDLE xah,
                      PIRP irp,
                      DOMAIN_ID domid,
                      HANDLE event_handle,
                      ALIEN_EVTCHN_PORT remote_port,
                      unsigned *out_port)
{
    NTSTATUS status;
    struct user_evtchn *ue;

    ue = XmAllocateZeroedMemory(sizeof(*ue));
    if (!ue) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto err;
    }

    status = ObReferenceObjectByHandle(event_handle,
                                       EVENT_MODIFY_STATE,
                                       *ExEventObjectType,
                                       irp->RequestorMode,
                                       &ue->event,
                                       NULL);
    if (!NT_SUCCESS(status))
        goto err;

    if (is_null_ALIEN_EVTCHN_PORT(remote_port)) {
        ue->port = EvtchnAllocUnboundDpc(domid, UserEventFired, ue);
        status = STATUS_INSUFFICIENT_RESOURCES;
    } else {
        ue->port = EvtchnConnectRemotePort(domid, remote_port,
                                           UserEventFired, ue);
        status = STATUS_UNSUCCESSFUL;
    }
    if (is_null_EVTCHN_PORT(ue->port))
        goto err;

    *out_port = xen_EVTCHN_PORT(ue->port);

    ExAcquireFastMutex(&xah->user_evtchns_mux);
    InsertTailList(&xah->user_evtchns, &ue->list);
    ExReleaseFastMutex(&xah->user_evtchns_mux);

    return STATUS_SUCCESS;

err:
    if (ue) {
        if (!is_null_EVTCHN_PORT(ue->port))
            EvtchnClose(ue->port);
        if (ue->event)
            ObDereferenceObject(ue->event);
    }
    return status;
}

static NTSTATUS
DoEvtchnListen(PXENEVTCHN_ACTIVE_HANDLE xah,
               PIRP irp,
               unsigned _domid,
               ULONG64 _event_handle,
               unsigned *out_port)
{
    DOMAIN_ID domid = wrap_DOMAIN_ID(_domid);
    HANDLE event_handle = (HANDLE)(ULONG_PTR)_event_handle;

    return DoEvtchnListenConnect(xah, irp, domid, event_handle,
                                 null_ALIEN_EVTCHN_PORT(), out_port);
}

static NTSTATUS
DoEvtchnConnect(PXENEVTCHN_ACTIVE_HANDLE xah,
                PIRP irp,
                unsigned _domid,
                unsigned _remote_port,
                ULONG64 _event_handle,
                unsigned *out_port)
{
    DOMAIN_ID domid = wrap_DOMAIN_ID(_domid);
    HANDLE event_handle = (HANDLE)(ULONG_PTR)_event_handle;
    ALIEN_EVTCHN_PORT remote_port = wrap_ALIEN_EVTCHN_PORT(_remote_port);
    return DoEvtchnListenConnect(xah, irp, domid, event_handle, remote_port,
                                 out_port);
}

static NTSTATUS
DoEvtchnClose(PXENEVTCHN_ACTIVE_HANDLE xah, unsigned xen_port)
{
    PLIST_ENTRY ple;
    struct user_evtchn *ue;

    ExAcquireFastMutex(&xah->user_evtchns_mux);
    for (ple = xah->user_evtchns.Flink;
         ple != &xah->user_evtchns;
         ple = ple->Flink) {
        ue = CONTAINING_RECORD(ple, struct user_evtchn, list);
        if (xen_port == xen_EVTCHN_PORT(ue->port))
            break;
    }
    if (ple == &xah->user_evtchns) {
        ExReleaseFastMutex(&xah->user_evtchns_mux);
        return STATUS_INVALID_PARAMETER;
    }
    RemoveEntryList(ple);
    ExReleaseFastMutex(&xah->user_evtchns_mux);

    /* Not strictly necessary, but avoids a compiler warning */
    ue = CONTAINING_RECORD(ple, struct user_evtchn, list);
    EvtchnClose(ue->port);
    ObDereferenceObject(ue->event);
    XmFreeMemory(ue);

    return STATUS_SUCCESS;
}

static NTSTATUS
DoEvtchnKick(PXENEVTCHN_ACTIVE_HANDLE xah, unsigned xen_port)
{
    PLIST_ENTRY ple;
    struct user_evtchn *ue;
    NTSTATUS status;

    status = STATUS_INVALID_PARAMETER;
    ExAcquireFastMutex(&xah->user_evtchns_mux);
    for (ple = xah->user_evtchns.Flink;
         ple != &xah->user_evtchns;
         ple = ple->Flink) {
        ue = CONTAINING_RECORD(ple, struct user_evtchn, list);
        if (xen_port == xen_EVTCHN_PORT(ue->port)) {
            EvtchnNotifyRemote(ue->port);
            status = STATUS_SUCCESS;
            break;
        }
    }
    ExReleaseFastMutex(&xah->user_evtchns_mux);
    return status;
}

static unsigned
userspace_strlen(char *path)
{
    unsigned acc;
    acc = 0;
    while (1) {
        ProbeForRead(path + acc, 1, 1);
        if (!path[acc])
            return acc;
        acc++;
    }
}

static NTSTATUS
DoWriteOnClose(PIRP irp, ULONG64 path, ULONG64 data, ULONG data_size, ULONG64 *handle)
{
    NTSTATUS status;
    struct xevtchn_process_block *xpb = CurrentXprocess();
    struct write_on_close *woc;
    size_t path_size;
    KIRQL irql;

    if (!xpb) {
        xpb = NewXprocess(PsGetCurrentProcess());
        if (!xpb)
            return STATUS_INSUFFICIENT_RESOURCES;
    }

    try {
        ProbeForRead((void *)(ULONG_PTR)data, data_size, 1);
        if (irp->RequestorMode == KernelMode)
            path_size = strlen((char *)(ULONG_PTR)path);
        else
            path_size = userspace_strlen((char *)(ULONG_PTR)path);
    } except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    if (path_size > 65536)
        return STATUS_INVALID_PARAMETER;

    woc = XmAllocateZeroedMemory(sizeof(*woc));
    if (!woc)
        return STATUS_INSUFFICIENT_RESOURCES;

    woc->path =
        ExAllocatePoolWithQuotaTag(NonPagedPool | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE,
                                   path_size + 1,
                                   'cowx');
    woc->data =
        ExAllocatePoolWithQuotaTag(NonPagedPool | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE,
                                   data_size,
                                   'cowx');
    if (!woc->path || !woc->data) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto err;
    }

    try {
        memcpy(woc->path, (void *)(ULONG_PTR)path, path_size);
        memcpy(woc->data, (void *)(ULONG_PTR)data, data_size);
    } except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        goto err;
    }

    woc->path[path_size] = 0;
    woc->data_size = data_size;

    *handle = (ULONG64)(ULONG_PTR)woc;
    KeAcquireSpinLock(&xpb->lock, &irql);
    InsertHeadList(&xpb->write_on_close, &woc->list);
    KeReleaseSpinLock(&xpb->lock, irql);

    DereferenceXprocess(xpb);   

    return STATUS_SUCCESS;

err:
    if (woc) {
        if (woc->path)
            ExFreePool(woc->path);
        if (woc->data)
            ExFreePool(woc->data);
        XmFreeMemory(woc);
    }
    if (xpb)
        DereferenceXprocess(xpb);

    return status;
}

static NTSTATUS
DoCancelWriteOnClose(ULONG64 handle)
{
    PLIST_ENTRY ple;
    struct xevtchn_process_block *xpb = CurrentXprocess();
    struct write_on_close *woc;
    KIRQL irql;

    /* Can't clear one if one was never set for this process */
    if (!xpb)
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&xpb->lock, &irql);
    for (ple = xpb->write_on_close.Flink;
         ple != &xpb->write_on_close;
         ple = ple->Flink) {
        woc = CONTAINING_RECORD(ple, struct write_on_close, list);
        if ((ULONG64)(ULONG_PTR)woc == handle) {
            RemoveEntryList(&woc->list);
            KeReleaseSpinLock(&xpb->lock, irql);
            DereferenceXprocess(xpb);
            ExFreePool(woc->path);
            ExFreePool(woc->data);
            XmFreeMemory(woc);
            return STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&xpb->lock, irql);
    DereferenceXprocess(xpb);

    return STATUS_INVALID_PARAMETER;
}



NTSTATUS
XenevtchnDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG inSize = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PXENEVTCHN_ACTIVE_HANDLE pah = 
        XenevtchnFindActiveHandle(pXevtdx, stack->FileObject);
    NTSTATUS Status;
    ULONG Info = 0;
    KIRQL irql;

    KeAcquireSpinLock(&XenbusFreezeLock, &irql);
    if (XenbusIsFrozen()) {
        TraceVerbose (("Queuing IRP for frozen xenbus.\n"));
        IoMarkIrpPending(Irp);
        InsertTailList(&XenbusIrpQueue, &Irp->Tail.Overlay.ListEntry);
        KeReleaseSpinLock(&XenbusFreezeLock, irql);
        return STATUS_PENDING;
    }
    UserXenbusRequestsLive++;
    KeClearEvent(&UserXenbusIdle);
    KeReleaseSpinLock(&XenbusFreezeLock, irql);
    
    if (pah == NULL) {
        Status = STATUS_INVALID_HANDLE;
        goto out;
    }

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {

        case IOCTL_XS_TRANS_START:
        {
            if (!xenbus_await_initialisation()) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            if (!is_nil_xenbus_transaction_t(pah->xbt)) {
                Status = STATUS_REQUEST_OUT_OF_SEQUENCE;
            } else {
                xenbus_transaction_start(&pah->xbt);
                Status = STATUS_SUCCESS;
            }
            break;
        }

        case IOCTL_XS_TRANS_END:
        {
            PULONG pAbort = (PULONG) Irp->AssociatedIrp.SystemBuffer;

            if (!xenbus_await_initialisation()) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            if (inSize < sizeof(ULONG)) {
                Status = STATUS_INVALID_USER_BUFFER;
            } else {
                if (is_nil_xenbus_transaction_t(pah->xbt)) {
                    Status = STATUS_REQUEST_OUT_OF_SEQUENCE;
                } else {
                    Status = xenbus_transaction_end(pah->xbt,
                                                    *pAbort);
                    pah->xbt = XBT_NIL;
                    Info = sizeof(ULONG);
                }
            }
            break;
        }

        case IOCTL_XS_READ:
        {
            PCHAR data;
            PCHAR path = Irp->AssociatedIrp.SystemBuffer;
            XS_READ_MSG* pOutMsg = (XS_READ_MSG*)Irp->AssociatedIrp.SystemBuffer;
            ULONG i;
            size_t len;

            if (!xenbus_await_initialisation()) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            for (i = 0; i < inSize && *(path+i) != '\0'; i++)
                ;
            if (i == inSize || outSize < sizeof(XS_READ_MSG)) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }

            Status = xenbus_read_bin(pah->xbt, path, NULL, &data, &len);

            if (NT_SUCCESS(Status)) {
                pOutMsg->len = (ULONG)len;

                if (len > (outSize - sizeof(XS_READ_MSG))) {
                    Status = STATUS_BUFFER_OVERFLOW;
                    len = sizeof(XS_READ_MSG);
                } else {
                    memcpy(pOutMsg->data, data, len);
                    len += sizeof(XS_READ_MSG);
                }
                Info = (ULONG)len;
                XmFreeMemory(data);
            }
            break;
        }

        case IOCTL_XS_DIRECTORY:
        {
            PCHAR *dirs;
            PCHAR path = Irp->AssociatedIrp.SystemBuffer;
            ULONG i;
            size_t bytesToCopy=0, bytesCopied=0, totalBytes=0;
            XS_DIR_MSG* pOutMsg = (XS_DIR_MSG*)Irp->AssociatedIrp.SystemBuffer;
            char *outBuffer = pOutMsg->data;
            BOOLEAN fSkip=FALSE;

            if (!xenbus_await_initialisation()) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            for (i = 0; i < inSize && *(path+i) != '\0'; i++)
                ;
            if (i == inSize || outSize < sizeof(XS_DIR_MSG)) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }

            Status = xenbus_ls(pah->xbt, path, &dirs);

            if (NT_SUCCESS(Status)) {
                // Copy result
                for (i=0;dirs[i];i++) {
                    bytesToCopy = strlen(dirs[i]) + 1;
                    totalBytes += bytesToCopy;

                    if (!fSkip)
                    {
                        // Make sure we have enough room
                        if (bytesCopied + bytesToCopy < (int)(outSize - sizeof(XS_DIR_MSG)))
                        {
                            memcpy(outBuffer + bytesCopied, dirs[i], bytesToCopy);
                            bytesCopied += bytesToCopy;
                        }
                        else
                        {
                            fSkip= TRUE;
                        }
                    }
                    XmFreeMemory(dirs[i]);
                }

                if (fSkip)
                {
                    TraceDebug (("not enough buffer - has %d needed %d\n",
                                outSize - sizeof(XS_DIR_MSG),
                                totalBytes + 1));

                    Status = STATUS_BUFFER_OVERFLOW;
                    pOutMsg->len =
                        (ULONG)(totalBytes + 1); // let the caller knows how much room we need

                    Info = sizeof(XS_DIR_MSG);
                }
                else
                {
                    // null-terminate the entire array
                    *(outBuffer + totalBytes) = '\0';

                                        // include the null above
                    pOutMsg->len = (ULONG)(totalBytes + 1);

                                        // num of strings in the array
                    pOutMsg->count = i;

                    Info = pOutMsg->len + sizeof(XS_DIR_MSG);
                }

                XmFreeMemory(dirs);

            }
            break;
        }

        case IOCTL_XS_WRITE:
        {
            XS_WRITE_MSG *pMsg = (XS_WRITE_MSG*)Irp->AssociatedIrp.SystemBuffer;
            LONG dataSize = inSize - FIELD_OFFSET(XS_WRITE_MSG, data);
            LONG dataStart;

            if (!xenbus_await_initialisation()) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            if (dataSize < 0 ) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }
            /* Find end of path and start of data */
            for (dataStart = 0;
                 dataStart < dataSize && pMsg->data[dataStart];
                 dataStart++)
                ;
            dataStart++; /* Skip nul */
            if (dataStart > dataSize) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }
            Status = xenbus_write_bin(pah->xbt, pMsg->data,
                                      NULL,
                                      pMsg->data + dataStart,
                                      dataSize - dataStart);

            break;
        }

        case IOCTL_XS_REMOVE:
        {
            ULONG len;
            PCHAR path = (PCHAR)Irp->AssociatedIrp.SystemBuffer;

            if (!xenbus_await_initialisation()) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            /* Check that the string is properly null terminated. */
            for (len = 0; len < inSize && path[len]; len++)
                ;
            if (len == inSize) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }
            Status = xenbus_remove(pah->xbt, path);
            break;
        }

        case IOCTL_XS_WATCH:
        {
            XS_WATCH_MSG *msg;
            XS_WATCH_MSG_32 *msg32;
            int *phandle = (int *)Irp->AssociatedIrp.SystemBuffer;
            int handle;
            PUSER_WATCH_HANDLE uwh;
            HANDLE eventHandle;
            char *path;

            if (!xenbus_await_initialisation()) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            msg = NULL;
            msg32 = NULL;

#ifdef _WIN64
            if (IoIs32bitProcess(Irp))
                msg32 = (XS_WATCH_MSG_32*)Irp->AssociatedIrp.SystemBuffer;
            else
                msg = (XS_WATCH_MSG*)Irp->AssociatedIrp.SystemBuffer;
#else
            msg = (XS_WATCH_MSG*)Irp->AssociatedIrp.SystemBuffer;
#endif

            /* Check that the string is null terminated and that we
               have a large enough out buffer. */
            if (msg) {
                if (inSize <= sizeof(HANDLE) ||
                    msg->path[inSize - sizeof(HANDLE)-1] ||
                    outSize != sizeof(handle)) {
                    Status = STATUS_INVALID_USER_BUFFER;
                    break;
                }
                eventHandle = msg->event;
                path = msg->path;
            } else {
                if (inSize <= sizeof(ULONG) ||
                    msg32->path[inSize - sizeof(ULONG)-1] ||
                    outSize != sizeof(handle)) {
                    Status = STATUS_INVALID_USER_BUFFER;
                    break;
                }
                eventHandle = (HANDLE)(ULONG_PTR)msg32->event;
                path = msg32->path;
            }

            Status = STATUS_INSUFFICIENT_RESOURCES;
            uwh = XmAllocateZeroedMemory(sizeof(*uwh));
            if (uwh) {
                Status = ObReferenceObjectByHandle(eventHandle,
                                                   EVENT_MODIFY_STATE,
                                                   *ExEventObjectType,
                                                   Irp->RequestorMode,
                                                   &uwh->evt,
                                                   NULL);
            }
            if (NT_SUCCESS(Status)) {
                uwh->wh = xenbus_watch_path_event(path, uwh->evt);
                if (!uwh->wh)
                    Status = STATUS_UNSUCCESSFUL;
            }

            if (NT_SUCCESS(Status)) {
                handle = AttachUserWatch(pah, uwh);
                if (handle != -1) {
                    *phandle = handle;
                    Info = sizeof(handle);
                    Status = STATUS_SUCCESS;
                } else {
                    Status = STATUS_UNSUCCESSFUL;
                }
            }

            if (!NT_SUCCESS(Status))
                ReleaseUserWatch(uwh);

            break;
        }

        case IOCTL_XS_UNWATCH:
        {
            ULONG *pId = (ULONG *)Irp->AssociatedIrp.SystemBuffer;
            PUSER_WATCH_HANDLE uwh;

            if (!xenbus_await_initialisation()) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            if (inSize != sizeof(ULONG)) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }
            uwh = PopUserWatch(pah, *pId);
            if (!uwh) {
                Status = STATUS_INVALID_PARAMETER;
            } else {
                ReleaseUserWatch(uwh);
                Status = STATUS_SUCCESS;
            }
            break;
        }
        
        case IOCTL_XS_ENABLE_UNINST: {
            pXevtdx->UninstEnabled = TRUE;
            IoInvalidateDeviceState(pXevtdx->PhysicalDeviceObject);
            Status = STATUS_SUCCESS;
            xenbus_write(XBT_NIL, "data/uninstallation-started", "1");
            break;
        }

        case IOCTL_XS_UNINST_IN_PROGRESS: {
            if (pXevtdx->UninstEnabled)
                Status = STATUS_SUCCESS;
            else
                Status = STATUS_UNSUCCESSFUL;
            break;
        }

        case IOCTL_XS_SET_LOGLEVEL: {
            XS_LOGLEVEL_MSG *msg =
                (XS_LOGLEVEL_MSG *)Irp->AssociatedIrp.SystemBuffer;
            if (inSize < sizeof(*msg)) {
                Status = STATUS_INVALID_USER_BUFFER;
            } else {
                XenTraceSetLevels(msg->dispositions);
                Status = STATUS_SUCCESS;
            }
            break;
        }

        case IOCTL_XS_LISTEN_SUSPEND: {
            XS_LISTEN_SUSPEND_MSG *msg = Irp->AssociatedIrp.SystemBuffer;
            PKEVENT new;

            if (!xenbus_await_initialisation()) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            if (inSize < sizeof(*msg)) {
                Status = STATUS_INVALID_USER_BUFFER;
            } else {
                Status = ObReferenceObjectByHandle(msg->handle,
                                                   EVENT_MODIFY_STATE,
                                                   *ExEventObjectType,
                                                   Irp->RequestorMode,
                                                   &new,
                                                   NULL);
                if (NT_SUCCESS(Status)) {
                    KeAcquireSpinLock(&pXevtdx->ActiveHandleLock, &irql);
                    if (pah->suspend_event) {
                        Status = STATUS_DEVICE_BUSY;
                    } else {
                        pah->suspend_event = new;
                        Status = STATUS_SUCCESS;
                    }
                    KeReleaseSpinLock(&pXevtdx->ActiveHandleLock, irql);
                    if (Status != STATUS_SUCCESS)
                        ObDereferenceObject(new);
                }
            }
            break;
        }

        case IOCTL_XS_UNLISTEN_SUSPEND: {
            PKEVENT evt;

            if (!xenbus_await_initialisation()) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            KeAcquireSpinLock(&pXevtdx->ActiveHandleLock, &irql);
            evt = pah->suspend_event;
            pah->suspend_event = NULL;
            KeReleaseSpinLock(&pXevtdx->ActiveHandleLock, irql);
            if (evt) {
                Status = STATUS_SUCCESS;
                ObDereferenceObject(evt);
            } else {
                Status = STATUS_REQUEST_OUT_OF_SEQUENCE;
            }
            break;
        }

        case IOCTL_XS_GET_XEN_TIME: {
            if (!XenPVFeatureEnabled(DEBUG_MTC_PROTECTED_VM) && !xenbus_await_initialisation()) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            if (outSize != sizeof(ULONG64)) {
                Status = STATUS_INVALID_USER_BUFFER;
            } else {
                Status = STATUS_SUCCESS;
                *(ULONG64*)Irp->AssociatedIrp.SystemBuffer = HvmGetXenTime();
                Info = sizeof(ULONG64);
            }
            break;
        }

        case IOCTL_XS_GET_LOG_SIZE: {
            if (outSize != sizeof(ULONG)) {
                Status = STATUS_INVALID_USER_BUFFER;
            } else {
                *(ULONG*)Irp->AssociatedIrp.SystemBuffer =
                    HvmGetLogRingSize();
                Info = sizeof(ULONG);
                Status = STATUS_SUCCESS;
            }
            break;
        }

        case IOCTL_XS_GET_LOG: {
            Status =
                HvmGetLogRing(Irp->AssociatedIrp.SystemBuffer, outSize);
            if (NT_SUCCESS(Status))
                Info = outSize;
            break;
        }

        case IOCTL_XS_MAKE_PRECIOUS: {
            if (pah->precious)
                TraceWarning(("xenevtchn handle made precious several times?\n"));
            pah->precious = TRUE;
            Status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_XS_UNMAKE_PRECIOUS: {
            if (!pah->precious)
                TraceWarning(("tried to clear the precious flag when it was already clear?\n"));
            pah->precious = FALSE;
            Status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_XS_LOG: {
            TraceNotice(("USER: %.*s\n", inSize,
                         Irp->AssociatedIrp.SystemBuffer));
            Status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_XS_QUERY_BALLOON: {
            XS_QUERY_BALLOON *xsqb = Irp->AssociatedIrp.SystemBuffer;

            if (outSize < sizeof(*xsqb)) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }

            BalloonQuery(xsqb);

            Info = sizeof(*xsqb);
            Status = STATUS_SUCCESS;
            break;
        }

        case  IOCTL_XS_GRANT_ACCESS: {
            XS_GRANT_ACCESS_IN *inp = Irp->AssociatedIrp.SystemBuffer;
            XS_GRANT_ACCESS_OUT *out = Irp->AssociatedIrp.SystemBuffer;
            uint32_t gref;

            if (inSize != sizeof(*inp) || outSize != sizeof(*out)) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }

            Status = DoGrantAccess(inp->domid, inp->virt_addr, inp->readonly,
                                   &gref);
            if (NT_SUCCESS(Status)) {
                out->grant_reference = gref;
                Info = sizeof(*out);
            }
            break;
        }

        case  IOCTL_XS_UNGRANT_ACCESS: {
            XS_UNGRANT_ACCESS *inp = Irp->AssociatedIrp.SystemBuffer;

            if (inSize != sizeof(*inp)) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }
            Status = DoUngrantAccess(inp->grant_reference);
            break;
        }

        case IOCTL_XS_GRANT_MAP: {
            XS_GRANT_MAP_IN *inp = Irp->AssociatedIrp.SystemBuffer;
            XS_GRANT_MAP_OUT *out = Irp->AssociatedIrp.SystemBuffer;
            ULONG64 handle;
            ULONG64 va;

            if (inSize < sizeof(*inp) ||
                inp->nr_grefs == 0 ||
                inp->nr_grefs > XS_GRANT_MAP_MAX_GREFS ||
                inSize != sizeof(*inp) +
                          sizeof(inp->grant_refs[0]) * inp->nr_grefs ||
                outSize != sizeof(*out)) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }

            Status = DoGrantMap(inp->domid, inp->nr_grefs, inp->grant_refs,
                                inp->readonly, &handle, &va);
            if (NT_SUCCESS(Status)) {
                out->handle = handle;
                out->virt_addr = va;
                Info = sizeof(*out);
            }

            break;
        }

        case  IOCTL_XS_GRANT_UNMAP: {
            XS_GRANT_UNMAP *inp = Irp->AssociatedIrp.SystemBuffer;

            if (inSize != sizeof(*inp)) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }
            Status = DoGrantUnmap(inp->handle);
            break;
        }

        case IOCTL_XS_EVTCHN_LISTEN: {
            XS_EVTCHN_LISTEN_IN *inp = Irp->AssociatedIrp.SystemBuffer;
            XS_EVTCHN_LISTEN_OUT *out = Irp->AssociatedIrp.SystemBuffer;
            unsigned port;

            if (inSize != sizeof(*inp) || outSize != sizeof(*out)) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }

            Status = DoEvtchnListen(pah, Irp, inp->domid, inp->event_handle,
                                    &port);
            if (NT_SUCCESS(Status)) {
                out->evtchn_port = port;
                Info = sizeof(*out);
            }

            break;
        }

        case IOCTL_XS_EVTCHN_CLOSE: {
            XS_EVTCHN_CLOSE *inp = Irp->AssociatedIrp.SystemBuffer;

            if (inSize != sizeof(*inp)) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }

            Status = DoEvtchnClose(pah, inp->evtchn_port);
            break;
        }

        case IOCTL_XS_EVTCHN_CONNECT: {
            XS_EVTCHN_CONNECT_IN *inp = Irp->AssociatedIrp.SystemBuffer;
            XS_EVTCHN_CONNECT_OUT *out = Irp->AssociatedIrp.SystemBuffer;
            unsigned port;

            if (inSize != sizeof(*inp) || outSize != sizeof(*out)) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }

            Status = DoEvtchnConnect(pah, Irp, inp->domid, inp->remote_port,
                                     inp->event_handle, &port);
            if (NT_SUCCESS(Status)) {
                out->evtchn_port = port;
                Info = sizeof(*out);
            }

            break;
        }

        case IOCTL_XS_EVTCHN_KICK: {
            XS_EVTCHN_KICK *inp = Irp->AssociatedIrp.SystemBuffer;

            if (inSize != sizeof(*inp)) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }

            Status = DoEvtchnKick(pah, inp->evtchn_port);
            break;
        }

        case IOCTL_XS_WRITE_ON_CLOSE: {
            XS_WRITE_ON_CLOSE_IN *inp = Irp->AssociatedIrp.SystemBuffer;
            XS_WRITE_ON_CLOSE_OUT *out = Irp->AssociatedIrp.SystemBuffer;
            ULONG64 handle;

            if (inSize != sizeof(*inp) || outSize != sizeof(*out)) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }

            Status = DoWriteOnClose(Irp, inp->path, inp->data,
                                    inp->data_len, &handle);
            if (NT_SUCCESS(Status)) {
                out->handle = handle;
                Info = sizeof(*out);
            }

            break;
        }

        case IOCTL_XS_CANCEL_WRITE_ON_CLOSE: {
            XS_CANCEL_WRITE_ON_CLOSE *inp = Irp->AssociatedIrp.SystemBuffer;

            if (inSize != sizeof(*inp)) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }

            Status = DoCancelWriteOnClose(inp->handle);
            break;
        }

        case IOCTL_XS_GRANT_SET_QUOTA: {
            XS_GRANT_QUOTA *inp = Irp->AssociatedIrp.SystemBuffer;

            if (inSize != sizeof(*inp)) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }

            Status = DoGrantSetQuota(inp->quota);
            break;
        }

        case IOCTL_XS_GRANT_GET_QUOTA: {
            XS_GRANT_QUOTA *out = Irp->AssociatedIrp.SystemBuffer;

            if (outSize != sizeof(*out)) {
                Status = STATUS_INVALID_USER_BUFFER;
                break;
            }

            Status = DoGrantGetQuota(&out->quota);
            if (NT_SUCCESS(Status))
                Info = sizeof(*out);

            break;
        }

        case IOCTL_XS_DIAG_ACPIDUMP: {
            Status = DiagsAcpiDump(Irp->AssociatedIrp.SystemBuffer,
                                   outSize,
                                   &Info);
            break;
        }

        case IOCTL_XS_DIAG_GETE820: {
            Status = DiagsGetE820(Irp->AssociatedIrp.SystemBuffer,
                                  outSize,
                                  &Info);
            break;
        }

        case IOCTL_XS_DIAG_PCICONFIG: {
            Status = DiagsPciConfig(Irp->AssociatedIrp.SystemBuffer,
                                    outSize,
                                    &Info);
            break;
        }

        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    
out:
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    KeAcquireSpinLock(&XenbusFreezeLock, &irql);
    /* Strictly speaking, we'd only need to set the event if
       XenbusFrozen is true, but this is a relatively slow path and
       doing it unconditionally is much easier to understand. */
    if (--UserXenbusRequestsLive == 0)
        KeSetEvent(&UserXenbusIdle,
                   IO_NO_INCREMENT,
                   FALSE);
    KeReleaseSpinLock(&XenbusFreezeLock, irql);

    return Status;
}

NTSTATUS
XenevtchnCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx = 
        (PXENEVTCHN_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PXENEVTCHN_ACTIVE_HANDLE xhp;
    KIRQL irql;
    NTSTATUS res;

    if (pXevtdx->Header.Signature != XENEVTCHN_FDO_SIGNATURE) {
        /* Verbose because an untrusted local user can trigger this,
           and we don't want a DoS attack. */
        TraceVerbose(("Trying to open a non-FDO xenevtchn device?\n"));
        res = STATUS_ACCESS_DENIED;
    } else {
        xhp = XmAllocateMemory(sizeof(XENEVTCHN_ACTIVE_HANDLE));
        if (xhp == NULL) {
            res = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            memset(xhp, 0, sizeof(*xhp));
            xhp->FileObject = stack->FileObject;
            xhp->xbt = XBT_NIL;
            KeInitializeSpinLock(&xhp->watches_lock);

            ExInitializeFastMutex(&xhp->user_evtchns_mux);
            InitializeListHead(&xhp->user_evtchns);

            KeAcquireSpinLock(&pXevtdx->ActiveHandleLock, &irql);
            InsertHeadList(&pXevtdx->ActiveHandles, &xhp->ListEntry);
            pXevtdx->ActiveHandleCount++;
            TraceVerbose(("%s: %d active handles\n", __FUNCTION__,
                          pXevtdx->ActiveHandleCount));
            KeReleaseSpinLock(&pXevtdx->ActiveHandleLock, irql);
            res = STATUS_SUCCESS;
        }
    }

    Irp->IoStatus.Status = res;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return res;
}

NTSTATUS
XenevtchnClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx = 
        (PXENEVTCHN_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT pfo = stack->FileObject;
    PLIST_ENTRY head = &pXevtdx->ActiveHandles;
    PLIST_ENTRY entry;
    KIRQL irql;
    NTSTATUS res = STATUS_UNSUCCESSFUL;
    PUSER_WATCH_HANDLE uwh;
    struct user_evtchn *ue;

    TraceDebug (("enter\n"));

    xenbus_await_initialisation();

    KeAcquireSpinLock(&pXevtdx->ActiveHandleLock, &irql);
    for (entry = head->Flink; entry != head;) {
        PLIST_ENTRY this = entry;
        PXENEVTCHN_ACTIVE_HANDLE pah = (PXENEVTCHN_ACTIVE_HANDLE)this;
        entry = entry->Flink;
        if (pah->FileObject == pfo) {
            XM_ASSERT(pXevtdx->ActiveHandleCount != 0);
            pXevtdx->ActiveHandleCount--;
            RemoveEntryList(this);
            TraceVerbose(("%s: %d active handles\n", __FUNCTION__,
                          pXevtdx->ActiveHandleCount));
            KeReleaseSpinLock(&pXevtdx->ActiveHandleLock, irql);

            /* No more need to worry about synchronisation, since
               nobody else can get a pointer to this handle
               structure. */

            if (pah->precious)
                TraceWarning(("Closing a precious xenevtchn handle?\n"));

            while (pah->watches) {
                uwh = PopUserWatch(pah, pah->watches->handle);
                XM_ASSERT(uwh != NULL);
                ReleaseUserWatch(uwh);
            }

            /* Abort any pending transaction, since we know it's never
               going to complete. */
            if (!is_nil_xenbus_transaction_t(pah->xbt))
                (VOID)xenbus_transaction_end(pah->xbt, 1);
            if (pah->suspend_event)
                ObDereferenceObject(pah->suspend_event);

            while (!IsListEmpty(&pah->user_evtchns)) {
                ue = CONTAINING_RECORD(pah->user_evtchns.Flink,
                                       struct user_evtchn,
                                       list);
                RemoveEntryList(&ue->list);
                EvtchnClose(ue->port);
                ObDereferenceObject(ue->event);
                XmFreeMemory(ue);
            }            

            XmFreeMemory(this);
            res = STATUS_SUCCESS;
            break;
        }
    }

    if (res == STATUS_UNSUCCESSFUL) {
        TraceError (("Attempt to close a handle which was never created?\n"));
        KeReleaseSpinLock(&pXevtdx->ActiveHandleLock, irql);
    }
    Irp->IoStatus.Status = res;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return res;
}

void
FreezeXenbus(void)
{
    KIRQL irql;

    TraceVerbose(("Freezing xenbus.\n"));
    KeAcquireSpinLock(&XenbusFreezeLock, &irql);
    if (XenbusIsFrozen()) {
        TraceWarning (("Tried to freeze xenbus twice?\n"));
        KeReleaseSpinLock(&XenbusFreezeLock, irql);
        return;
    }
    XenbusSetFrozen(TRUE);
    for(;;) {
        if (UserXenbusRequestsLive == 0) {
            ASSERT(XenbusIsFrozen());
            /* We've simultaneously observed XenbusFrozen to be high
               and UserXenbusRequestsLive to be 0.  That's enough to
               guarantee that there will be no further requests until
               the bus is unfrozen. */
            KeReleaseSpinLock(&XenbusFreezeLock, irql);
            TraceVerbose(("Xenbus frozen.\n"));
            return;
        }
        KeReleaseSpinLock(&XenbusFreezeLock, irql);
        KeWaitForSingleObject(&UserXenbusIdle,
                              Executive,
                              KernelMode,
                              FALSE,
                              NULL);
        KeAcquireSpinLock(&XenbusFreezeLock, &irql);
    }
}

static VOID
_UnfreezeXenbus(PVOID ctxt)
{
    PDEVICE_OBJECT DeviceObject = ctxt;
    PLIST_ENTRY le, next;
    KIRQL irql;
    PIRP Irp;

    XM_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    KeAcquireSpinLock(&XenbusFreezeLock, &irql);
    if (!XenbusIsFrozen()) {
        TraceWarning (("Unfreeze xenbus when it was already unfrozen?\n"));
        KeReleaseSpinLock(&XenbusFreezeLock, irql);
        return;
    }
    ASSERT(UserXenbusRequestsLive == 0);
    XenbusSetFrozen(FALSE);
    le = XenbusIrpQueue.Flink;
    InitializeListHead(&XenbusIrpQueue);
    KeReleaseSpinLock(&XenbusFreezeLock, irql);

    TraceVerbose(("Resubmitting frozen xenbus request.\n"));
    while (le != &XenbusIrpQueue) {
        next = le->Flink;
        Irp = CONTAINING_RECORD(le, IRP, Tail.Overlay.ListEntry);
        XenevtchnDeviceControl(DeviceObject, Irp);
        le = next;
    }
    TraceVerbose(("Unfroze xenbus.\n"));
}

void
UnfreezeXenbus(PDEVICE_OBJECT DeviceObject)
{
    TraceVerbose(("Scheduling xenbus unfreeze.\n"));

    XenQueueWork(_UnfreezeXenbus, DeviceObject);
}

void
InitUsermodeInterfaceEarly(void)
{
    InitializeListHead(&XenbusIrpQueue);
    KeInitializeEvent(&UserXenbusIdle, NotificationEvent, TRUE);
    KeInitializeSpinLock(&XenbusFreezeLock);
    KeInitializeSpinLock(&xevtchn_active_process_lock);
}

static void
xenevtchn_suspend_handler(void *data, SUSPEND_TOKEN token)
{
    KIRQL irql;
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx = data;
    PLIST_ENTRY head = &pXevtdx->ActiveHandles;
    PLIST_ENTRY entry;
    PXENEVTCHN_ACTIVE_HANDLE pah;

    UNREFERENCED_PARAMETER(token);

    KeAcquireSpinLock(&pXevtdx->ActiveHandleLock, &irql);
    for (entry = head->Flink; entry != head;) {
        pah = (PXENEVTCHN_ACTIVE_HANDLE)entry;
        if (pah->suspend_event)
            KeSetEvent(pah->suspend_event, IO_NO_INCREMENT, FALSE);
        entry = entry->Flink;
    }
    KeReleaseSpinLock(&pXevtdx->ActiveHandleLock, irql);
}

void
InitUsermodeInterfaceLate(PXENEVTCHN_DEVICE_EXTENSION pXendx)
{
    EvtchnRegisterSuspendHandler(xenevtchn_suspend_handler, pXendx,
                                 "xenevtchn_suspend_handler",
                                 SUSPEND_CB_LATE);
}

void
XevtchnProcessCleanup(void)
{
    struct xevtchn_process_block *xpb;
    PLIST_ENTRY entry;
    PLIST_ENTRY next_entry;
    struct user_grant *ug;
    struct user_grant_map *ugm;
    struct write_on_close *woc;
    NTSTATUS res;
    LARGE_INTEGER i;

    xpb = PopXprocess(PsGetCurrentProcess());
    if (!xpb)
        return;

    /* Don't need to take the xpb lock, because we're the last thread
       in this process. */

    /* Process any write on close handlers here. Note this must be done
       because in the case of a process crash, this routine is called before
       the file close routine. */
    while (!IsListEmpty(&xpb->write_on_close)) {
        woc = CONTAINING_RECORD(xpb->write_on_close.Flink,
                                struct write_on_close,
                                list);
        RemoveEntryList(&woc->list);
        xenbus_write_bin(XBT_NIL, woc->path, NULL, woc->data,
                         woc->data_size);
        ExFreePool(woc->path);
        ExFreePool(woc->data);
        XmFreeMemory(woc);
    }

    for (entry = xpb->user_grants.Flink;
         entry != &xpb->user_grants;
         entry = next_entry) {
        next_entry = entry->Flink;
        ug = CONTAINING_RECORD(entry, struct user_grant, list);
        for (;;) {
            res = GnttabEndForeignAccess(ug->gref);
            if (NT_SUCCESS(res))
                break;
            i.QuadPart = -10000000;
            KeDelayExecutionThread(KernelMode, FALSE, &i);
        }
        MmUnlockPages(ug->mdl);
        ExFreePool(ug->mdl);
        XmFreeMemory(ug);
    }

    for (entry = xpb->user_grant_maps.Flink;
         entry != &xpb->user_grant_maps;
         entry = next_entry) {
        next_entry = entry->Flink;
        ugm = CONTAINING_RECORD(entry, struct user_grant_map, list);
        ReleaseUserGrantMap(ugm);
    }

    /* Just for sanity */
    InitializeListHead(&xpb->write_on_close);
    InitializeListHead(&xpb->user_grants);
    InitializeListHead(&xpb->user_grant_maps);

    DereferenceXprocess(xpb);
}
