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

/* Interface to grant tables.  At the moment, only access (rather than
   transfer) entries are supported. */

#include <ntddk.h>

#include "xsapi.h"

#include "hvm.h"
#include "hypercall.h"
#include "iohole.h"
#include "gnttab.h"

#include <grant_table.h>
#include <memory.h>

#include "scsiboot.h"

/* XXX this should be in a header file somewhere */
#define NR_RESERVED_ENTRIES 8

#define GRANT_ENTRIES_PER_PAGE (PAGE_SIZE / sizeof(grant_entry_t))
#define MAX_NR_GRANT_FRAMES 32
#define MAX_NR_GRANT_ENTRIES (MAX_NR_GRANT_FRAMES * GRANT_ENTRIES_PER_PAGE)

struct grant_cache {
    LIST_ENTRY list;
    unsigned id;
    unsigned nr_outstanding;
    unsigned population;
    unsigned min_population;
    GRANT_REF head_free;
};

/* These should arguably be dynamically allocated.  This can waste up
   to about 600k of kernel memory; not disastrous, but pretty bad.
   Making them dynamically allocated is non-trivial, because we
   sometimes need to expand the tables with interrupts off. */
static grant_entry_t *GnttabTableInd[MAX_NR_GRANT_FRAMES];
#define GRANT_ENTRY(ref) GnttabTableInd[xen_GRANT_REF(ref) / GRANT_ENTRIES_PER_PAGE][xen_GRANT_REF(ref) % GRANT_ENTRIES_PER_PAGE]
static PHYSICAL_ADDRESS GnttabPhysAddrs[MAX_NR_GRANT_FRAMES];

/* Free GRANT_REF list.  Each slot here contains a potential future
   value for each gnttab_free_head or the grant cache free head
   pointer.  When you allocate from the main pool, you set
   gnttab_free_head to gnttab_list[xen_GRANT_REF(gnttab_free_head)]
   and return the old gnttab_free_head.

   As such, for each x in range, there is precisely one y so that
   xen_GRANT_REF(gnttab_list[y]) == x.  If x is assigned to cache z,
   then the cache ID of gnttab_list[y] will be congruent to z;
   otherwise, it will be zero. */
static GRANT_REF gnttab_list[MAX_NR_GRANT_ENTRIES];

/* Information needed to restore the grant table when we come back
   from save/restore. */
static uint32_t gnttab_pfns[MAX_NR_GRANT_ENTRIES];
static domid_t gnttab_domids[MAX_NR_GRANT_ENTRIES];
static uint8_t gnttab_readonly_flags[MAX_NR_GRANT_ENTRIES/8];

static unsigned gnttab_free_count;
static GRANT_REF gnttab_free_head;
static int nr_grant_frames;

static struct irqsafe_lock gnttab_lock;

static struct irqsafe_lock grant_cache_list_lock;
static LIST_ENTRY grant_cache_list;

/* We allocate cache entries in blocks of this many, and trim if a
   cache goes above twice this many. */
#define GNTTAB_CACHE_THRESHOLD 64

/* Change the cache id on a grant ref and return it. */
static GRANT_REF
ChangeGrantCache(GRANT_REF ref, int cache)
{
    return wrap_GRANT_REF(xen_GRANT_REF(ref), cache);
}

/* The 10 flags bits of a GRANT_REF are defined as follows:

   0-1 -> cache_id % 4 if it came from a cache, 0 otherwise.
   2-9 -> reserved.
*/
#define GRANT_REF_cache(gr) (__unwrap_GRANT_REF(gr) & 0x3)

static BOOLEAN
valid_GRANT_REF(GRANT_REF gr)
{
    if (is_null_GRANT_REF(gr))
        return FALSE;
    if (xen_GRANT_REF(gr) >= (int)(GRANT_ENTRIES_PER_PAGE * nr_grant_frames))
        return FALSE;
    return TRUE;
}

#define GRANT_REF_NEXT(g) (gnttab_list[xen_GRANT_REF(g)])

static void
put_free_entry(GRANT_REF ref, BOOLEAN locked)
{
    KIRQL old_irql = PASSIVE_LEVEL;

    if (!locked)
        old_irql = acquire_irqsafe_lock(&gnttab_lock);

    XM_ASSERT(valid_GRANT_REF(ref));
    XM_ASSERT(is_null_GRANT_REF(GRANT_REF_NEXT(ref)));
    GRANT_REF_NEXT(ref) = gnttab_free_head;
    gnttab_free_head = ref;
    gnttab_free_count++;

    if (!locked)
        release_irqsafe_lock(&gnttab_lock, old_irql);
}

/* Called with the grant table lock already acquired. */
static int
ExpandGrantTable(VOID)
{
    grant_entry_t *shared_va;
    static int grant_table_fully_mapped;
    int x;
    int ret;
    int starting_ref;

    TraceVerbose(("Expanding grant table (%d frames mapped)\n",
                  nr_grant_frames));
    if (nr_grant_frames == MAX_NR_GRANT_FRAMES || grant_table_fully_mapped) {
        TraceWarning (("Grant table reached maximum size\n"));
        return 0;
    }

    shared_va = XenevtchnAllocIoMemory(PAGE_SIZE,
                                       &GnttabPhysAddrs[nr_grant_frames]);
    if (!shared_va) {
        TraceWarning (("Failed to extend grant table.\n"));
        return 0;
    }
    ret = AddPageToPhysmap((PFN_NUMBER)(GnttabPhysAddrs[nr_grant_frames].QuadPart / PAGE_SIZE),
                           XENMAPSPACE_grant_table,
                           nr_grant_frames);
    if (ret) {
        /* Note that we leak the IO memory here.  There's nothing we
           can do about that.  This should be limited to a single
           frame, so it's not too bad. */
        TraceWarning (("Xen rejected attempt to expand grant table: %x\n",
                       ret));
        grant_table_fully_mapped = 1;
        return 0;
    }

    TraceNotice(("%s: GRANT TABLE %d: (%d - %d) at %p (%x)\n",
                 __FUNCTION__, 
                 nr_grant_frames,
                 nr_grant_frames * GRANT_ENTRIES_PER_PAGE,
                 ((nr_grant_frames + 1) * GRANT_ENTRIES_PER_PAGE) - 1,
                 shared_va, GnttabPhysAddrs[nr_grant_frames]));

    GnttabTableInd[nr_grant_frames] = shared_va;

    /* The new page is now mapped into place.  Hook it up. */
    starting_ref = nr_grant_frames * GRANT_ENTRIES_PER_PAGE;
    nr_grant_frames++;

    for (x = 0; x < GRANT_ENTRIES_PER_PAGE; x++) {
        GRANT_REF ref = wrap_GRANT_REF(x + starting_ref, 0);

        /* Hack: make sure we don't allocate a reserved entry. */
        if (xen_GRANT_REF(ref) < NR_RESERVED_ENTRIES)
            continue;

        /* Invalidate the entry */
        GRANT_ENTRY(ref).domid = DOMID_INVALID;
        GRANT_ENTRY(ref).flags = 0;
        GRANT_ENTRY(ref).frame = x + starting_ref;

        put_free_entry(ref, TRUE);
    }

    return 1;
}

static GRANT_REF
get_free_entry(BOOLEAN locked)
{
    KIRQL old_irql = PASSIVE_LEVEL;
    GRANT_REF ref;

    if (!locked)
        old_irql = acquire_irqsafe_lock(&gnttab_lock);

    if (gnttab_free_count == 0)
        ExpandGrantTable();
    if (gnttab_free_count == 0) {
        release_irqsafe_lock(&gnttab_lock, old_irql);
        TraceInfo (("Grant table full, returning error.\n"));
        return null_GRANT_REF();
    }

    gnttab_free_count--;
    ref = gnttab_free_head;
    XM_ASSERT(valid_GRANT_REF(ref));
    gnttab_free_head = GRANT_REF_NEXT(ref);
    XM_ASSERT(EQUIV(gnttab_free_count == 0, is_null_GRANT_REF(gnttab_free_head)));
    GRANT_REF_NEXT(ref) = null_GRANT_REF();

    if (!locked)
        release_irqsafe_lock(&gnttab_lock, old_irql);

    XM_ASSERT3U(GRANT_REF_cache(ref), ==, 0);
    return ref;
}

static void
put_cache_entry(struct grant_cache *gc, GRANT_REF ref)
{
    XM_ASSERT3U(GRANT_REF_cache(ref), ==, gc->id);

    XM_ASSERT(is_null_GRANT_REF(GRANT_REF_NEXT(ref)));
    GRANT_REF_NEXT(ref) = gc->head_free;
    gc->head_free = ref;
    gc->population++;
}

static BOOLEAN
ReplenishCache(struct grant_cache *gc, unsigned target_pop)
{
    KIRQL old_irql;

    XM_ASSERT(gc->population < target_pop);

    old_irql = acquire_irqsafe_lock(&gnttab_lock);

    while (gc->population < target_pop) {
        GRANT_REF ref;

        ref = get_free_entry(TRUE);
        if (is_null_GRANT_REF(ref))
            break;

        ref = ChangeGrantCache(ref, gc->id);
        put_cache_entry(gc, ref);
    }

    release_irqsafe_lock(&gnttab_lock, old_irql);
    return (gc->population == target_pop) ? TRUE : FALSE;
}

static GRANT_REF
get_cache_entry(struct grant_cache *gc)
{
    GRANT_REF ref;

    if (gc->population == 0)
        return null_GRANT_REF();

    gc->population--;
    ref = gc->head_free;
    XM_ASSERT(valid_GRANT_REF(ref));
    gc->head_free = GRANT_REF_NEXT(ref);
    XM_ASSERT(EQUIV(gc->population == 0, is_null_GRANT_REF(gc->head_free)));
    GRANT_REF_NEXT(ref) = null_GRANT_REF();

    XM_ASSERT3U(GRANT_REF_cache(ref), ==, gc->id);
    return ref;
}

static VOID
TrimCache(struct grant_cache *gc, unsigned target_pop)
{
    KIRQL old_irql;

    XM_ASSERT(gc->population >= target_pop);

    old_irql = acquire_irqsafe_lock(&gnttab_lock);

    while (gc->population > target_pop) {
        GRANT_REF ref;

        ref = get_cache_entry(gc);
        XM_ASSERT(!is_null_GRANT_REF(ref));

        ref = ChangeGrantCache(ref, 0);
        put_free_entry(ref, TRUE);
    }

    release_irqsafe_lock(&gnttab_lock, old_irql);
}

GRANT_REF
GnttabGetGrantRef(VOID)
{
    return get_free_entry(FALSE);
}

void
GnttabGrantForeignAccessRef(DOMAIN_ID _domid, PFN_NUMBER frame, GRANT_MODE mode,
                            GRANT_REF ref)
{
    int readonly = unwrap_GRANT_MODE(mode);
    xen_grant_ref_t xgr = xen_GRANT_REF(ref);
    domid_t domid = (domid_t)unwrap_DOMAIN_ID(_domid);
    XM_ASSERT(readonly == 0 || readonly == 1);
#ifdef AMD64
    XM_ASSERT((frame >> 32) == 0);
#endif
    GRANT_ENTRY(ref).frame = (uint32_t)frame;
    GRANT_ENTRY(ref).domid = domid;
    gnttab_pfns[xgr] = (uint32_t)frame;
    gnttab_domids[xgr] = domid;
    if (readonly) {
        gnttab_readonly_flags[xgr/8] |=  (1 << (xgr % 8));
        readonly = GTF_readonly;
    } else {
        gnttab_readonly_flags[xgr/8] &= ~(1 << (xgr % 8));
    }
    XsMemoryBarrier();
    GRANT_ENTRY(ref).flags = (uint16_t)(GTF_permit_access | readonly);
}

GRANT_REF
GnttabGrantForeignAccess(DOMAIN_ID domid, PFN_NUMBER frame, GRANT_MODE mode)
{
    GRANT_REF ref;

    ref = get_free_entry(FALSE);
    if (is_null_GRANT_REF(ref)) {
        TraceInfo (("Out of grant references...\n"));
        return ref;
    }
    GnttabGrantForeignAccessRef(domid, frame, mode, ref);

    return ref;
}

static NTSTATUS
GnttabEndForeignAccessRef(GRANT_REF ref)
{
    uint16_t flags, nflags;

    XM_ASSERT(valid_GRANT_REF(ref));
    nflags = GRANT_ENTRY(ref).flags;
    do {
        flags = nflags;
        if (flags & (GTF_reading | GTF_writing)) {
            TraceWarning (("releasing an in-use gnttab entry\n"));
            return STATUS_DEVICE_BUSY;
        }
        nflags = InterlockedCompareExchange16((SHORT*)&GRANT_ENTRY(ref).flags,
                                              0,
                                              flags);
    } while (nflags != flags);

    GRANT_ENTRY(ref).domid = DOMID_INVALID;
    GRANT_ENTRY(ref).frame = xen_GRANT_REF(ref);

    gnttab_pfns[xen_GRANT_REF(ref)] = 0;
    gnttab_domids[xen_GRANT_REF(ref)] = DOMID_INVALID;

    return STATUS_SUCCESS;
}

NTSTATUS
GnttabEndForeignAccess(GRANT_REF ref)
{
    NTSTATUS status;
    XM_ASSERT(GRANT_REF_cache(ref) == 0);
    status = GnttabEndForeignAccessRef(ref);
    if (NT_SUCCESS(status))
        put_free_entry(ref, FALSE);
    return status;
}

GRANT_REF
GnttabGrantForeignAccessCache(DOMAIN_ID domid,
                              PFN_NUMBER frame,
                              GRANT_MODE mode,
                              __inout struct grant_cache *gc)
{
    GRANT_REF ref;

    ref = get_cache_entry(gc);
    if (is_null_GRANT_REF(ref)) {
        ReplenishCache(gc, gc->population + GNTTAB_CACHE_THRESHOLD);
        ref = get_cache_entry(gc);
        if (is_null_GRANT_REF(ref))
            return null_GRANT_REF();
    }

    GnttabGrantForeignAccessRef(domid, frame, mode, ref);
    gc->nr_outstanding++;

    return ref;
}

NTSTATUS
GnttabEndForeignAccessCache(GRANT_REF ref,
                            __inout struct grant_cache *gc)
{
    NTSTATUS status;

    status = GnttabEndForeignAccessRef(ref);
    if (!NT_SUCCESS(status))
        return status;

    gc->nr_outstanding--;

    put_cache_entry(gc, ref);

    if (gc->population > gc->min_population &&
        gc->population > gc->nr_outstanding + GNTTAB_CACHE_THRESHOLD * 2) {
        unsigned target = gc->population - GNTTAB_CACHE_THRESHOLD;
        if (target < gc->min_population)
            target = gc->min_population;
        TrimCache(gc, target);
    }

    return STATUS_SUCCESS;
}

struct grant_cache *
GnttabAllocCache(ULONG min_population)
{
    struct grant_cache *work;
    static int next_id;
    KIRQL irql;

    work = XmAllocateMemory(sizeof(*work));
    if (!work)
        return NULL;
    work->population = 0;
    work->min_population = min_population;
    work->head_free = null_GRANT_REF();
    work->id = next_id++ & 3;
    if (!work->id)
        work->id = next_id++ & 3;
    work->nr_outstanding = 0;

    while (work->population < min_population) {
        if (!ReplenishCache(work, min_population)) {
            GnttabFreeCache(work);
            return NULL;
        }
    }

    irql = acquire_irqsafe_lock(&grant_cache_list_lock);
    InsertTailList(&grant_cache_list, &work->list);
    release_irqsafe_lock(&grant_cache_list_lock, irql);

    return work;
}

VOID
GnttabFreeCache(struct grant_cache *gc)
{
    KIRQL irql;

    irql = acquire_irqsafe_lock(&grant_cache_list_lock);
    RemoveEntryList(&gc->list);
    release_irqsafe_lock(&grant_cache_list_lock, irql);

    XM_ASSERT(gc->nr_outstanding == 0);
    gc->min_population = 0;
    TrimCache(gc, 0);

    XmFreeMemory(gc);
}

/* Restart grant tables following a resume from save/restore or
   following recovery from hibernation. */
static VOID
_GnttabResume(void)
{
    unsigned x;
    int ret;

    /* Remap the grant tables.  This can't fail, since it should be
       just as easy to recover as it was to map them the first time
       around.  If it does fail, we're pretty much screwed anyway, so
       just XM_ASSERT success. */
    for ( x = 0; x < (unsigned)nr_grant_frames; x++ ) {
        ret = AddPageToPhysmap((PFN_NUMBER)(GnttabPhysAddrs[x].QuadPart / PAGE_SIZE),
                               XENMAPSPACE_grant_table,
                               x);
        XM_ASSERT(ret == 0);
    }

    /* Walk the grant tables and repopulate form the save copy. */
    for (x = 0; x < nr_grant_frames * GRANT_ENTRIES_PER_PAGE; x++) {
        if (gnttab_pfns[x]) {
            int readonly;
            GRANT_REF gref = wrap_GRANT_REF(x, 0);
            if (gnttab_readonly_flags[x/8] & (1 << (x % 8))) {
                readonly = GTF_readonly;
            } else {
                readonly = 0;
            }
            GRANT_ENTRY(gref).frame = gnttab_pfns[x];
            GRANT_ENTRY(gref).domid = gnttab_domids[x];
            XsMemoryBarrier();
            GRANT_ENTRY(gref).flags =
                (uint16_t)(GTF_permit_access | readonly);
        }
    }
}

static void
GnttabResume(void *ignore, SUSPEND_TOKEN token)
{
    UNREFERENCED_PARAMETER(ignore);
    UNREFERENCED_PARAMETER(token);

    _GnttabResume();
}

static BOOLEAN GnttabStarted = FALSE;

NTSTATUS
GnttabInit(void)
{
    KIRQL irql;
    static struct SuspendHandler *sh;
    int i;

    if (!AustereMode && GnttabStarted) {
        TraceVerbose(("grant tables already started\n"));
        return STATUS_SUCCESS;
    }

    if (!sh) {
        InitializeListHead(&grant_cache_list);

        // Initialise global state. We need to do this for hiber mode
        // since previous global state may still be hanging around.
        for (i = 0; i < MAX_NR_GRANT_FRAMES; i++) {
            GnttabTableInd[i] = NULL;
            GnttabPhysAddrs[i].QuadPart = 0;
        }

        for (i = 0; i < MAX_NR_GRANT_ENTRIES; i++) {
            gnttab_list[i] = null_GRANT_REF();

            gnttab_pfns[i] = 0;
            gnttab_domids[i] = DOMID_INVALID;
            if (i % 8 == 0)
                gnttab_readonly_flags[i / 8] = 0;
        }

        sh = EvtchnRegisterSuspendHandler(GnttabResume, NULL,
                                          "GnttabResume",
                                          SUSPEND_CB_EARLY);

        irql = acquire_irqsafe_lock(&gnttab_lock);

        gnttab_free_count = 0;
        gnttab_free_head = null_GRANT_REF();
        nr_grant_frames = 0;

        ExpandGrantTable();

        release_irqsafe_lock(&gnttab_lock, irql);
    } else {
        /* Allocate space to map the grant tables. */
        for (i = 0; i < nr_grant_frames; i++) {
            GnttabTableInd[i] =
                XenevtchnAllocIoMemory(PAGE_SIZE, &GnttabPhysAddrs[i]);
        }

        /* Remap the table and reinstantiate any references which were
           extant when we hibernated. */
        irql = acquire_irqsafe_lock(&gnttab_lock);
        _GnttabResume();
        release_irqsafe_lock(&gnttab_lock, irql);
    }

    GnttabStarted = TRUE;

    return STATUS_SUCCESS;
}

VOID
GnttabCleanup(void)
{
    PLIST_ENTRY ple;
    struct grant_cache *gc;
    KIRQL irql;

    GnttabStarted = FALSE;

    /* Can't release evtchn IO memory, doesn't matter because it's
       freed implicitly when the driver unloads, which is about to
       happen */

    TraceNotice(("Gnttab cleanup with %d grant references outstanding against main pool.\n",
                 nr_grant_frames * GRANT_ENTRIES_PER_PAGE -
                 gnttab_free_count));
    irql = acquire_irqsafe_lock(&grant_cache_list_lock);
    for (ple = grant_cache_list.Flink;
         ple != &grant_cache_list;
         ple = ple->Flink) {
        gc = CONTAINING_RECORD(ple, struct grant_cache, list);
        TraceNotice(("GC id %d with %d outstanding, population %d, min pop %d.\n",
                     gc->id, gc->nr_outstanding, gc->population,
                     gc->min_population));
    }
    release_irqsafe_lock(&grant_cache_list_lock, irql);
}
