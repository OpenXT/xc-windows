//++

/*
 * Copyright (c) 2013 Citrix Systems, Inc.
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

//
// balloon.c
//
// This module supports the Xen balloon functionality, that is, dynamic memory
// assignment and removal from a domain.
//
// Copyright (c) 2007, XenSource, Inc. - All rights reserved.
//
//--

#pragma warning (push, 3)

#include <ntddk.h>
#include <ntstrsafe.h>
#include "xsapi.h"
#include "scsiboot.h"

#include "hvm.h"
#include "hypercall.h"
#include "xenbus.h"
#include "xenutl.h"

#include <xen_types.h>
#include <memory.h>
#include <hvm_params.h>

#include "balloon.h"

#pragma warning (pop)

#define range_set_index_t PFN_NUMBER
#include "rangeset.c"

#define MIN(a, b)   ((a) < (b) ? (a) : (b))

#define TIME_US(_us)        ((_us) * 10)
#define TIME_MS(_ms)        (TIME_US((_ms) * 1000))
#define TIME_S(_s)          (TIME_MS((_s) * 1000))
#define TIME_RELATIVE(_t)   (-(_t))

// Keep a made up MDL up our sleeve with room for the maximal number of
// PFN_NUMBERs.
//
// We also need an array of PFN_NUMBERs when communicating to Xen which pages
// are being returned or reclaimed, and that memory must be locked.  We could
// use the list as it exists in the page of pages and do the following every
// time we talk to Xen (for each page of pages)-
//
//  . Allocate an MDL
//  . Probe and Lock pages
//  . Virtual Lock
//  . Talk to Xen
//  . Virtual unlock
//  . Unlock pages
//  . Free MDL
//
// but that all seems like a lot of code, or in particular, a lot of guest
// OS calls.  Instead we'll reuse(/overload) the PFN array.
//
// Fortunately the native size of a Windows PFN is the same as the native
// (guest) size of a Xen PFN.

#define SHORT_MAX           (1 << 15)
#define MAX_PAGES_PER_MDL   ((SHORT_MAX - sizeof(MDL)) / sizeof(PFN_NUMBER))

#define BALLOON_PFN_ARRAY_SIZE  (MAX_PAGES_PER_MDL)

typedef struct _BALLOON
{
    ULONG               TopPage;

    // We aim for CurrentPages == TargetPages.
    ULONG               CurrentPages;
    ULONG               TargetPages;
    ULONG               MaxPages;

    // Various interesting statistics
    ULONG               AllocateFail;
    ULONG               PartialAllocate;
    ULONG               PartialPopulate;

    struct range_set    PfnsBalloonedOut;

    // Our pre-built MDL
    MDL                 Mdl;
    PFN_NUMBER          PfnArray[BALLOON_PFN_ARRAY_SIZE];

    KEVENT              WorkerDoneEvent;
    struct xm_thread    *WorkerThread;

    // Failure insertion and self-test flags
    BOOLEAN             FIST_inflation;
    BOOLEAN             FIST_deflation;

    // State flags
    BOOLEAN             Frozen;
    BOOLEAN             Initialized;
    BOOLEAN             Advertized;
    ULONG               AdvertizedSuspendCount;
    BOOLEAN             Active;
    ULONG               ActiveSuspendCount;

} BALLOON;

// There's only one balloon in a domain so make it global to make debugging
// easier.
static BALLOON Balloon;

static NTSTATUS
BalloonReadTargetPages(
    OUT ULONG   *TargetPages
    )
{
    ULONG64     Target;
    NTSTATUS    status;

    status = xenbus_read_int(XBT_NIL, "memory", "target", &Target);
    if (!NT_SUCCESS(status))
        goto fail1;

    *TargetPages = (ULONG)(Target / 4);
    return STATUS_SUCCESS;

fail1:
    TraceError(("%s: fail1 (%08x)\n", __FUNCTION__, status));

    return status;
}

static NTSTATUS
BalloonReadMaxPages(
    OUT ULONG   *MaxPages
    )
{
    ULONG64     StaticMax;
    NTSTATUS    status;

    status = xenbus_read_int(XBT_NIL, "memory", "static-max", &StaticMax);
    if (!NT_SUCCESS(status))
        goto fail1;

    *MaxPages = (ULONG)(StaticMax / 4);
    return STATUS_SUCCESS;
    
fail1:
    TraceError(("%s: fail1 (%08x)\n", __FUNCTION__, status));

    return status;
}

static ULONG
BalloonGetTopPage(
    VOID
    )
{
    PHYSICAL_MEMORY_RANGE   *Range;
    PHYSICAL_ADDRESS        TopAddress;
    ULONG                   Index;

    Range = MmGetPhysicalMemoryRanges();

    TopAddress.QuadPart = 0ull;
    for (Index = 0; Range[Index].BaseAddress.QuadPart != 0 || Range[Index].NumberOfBytes.QuadPart != 0; Index++) {
        PHYSICAL_ADDRESS EndAddress;
        CHAR Key[32];

        EndAddress.QuadPart = Range[Index].BaseAddress.QuadPart + Range[Index].NumberOfBytes.QuadPart;

        TraceInfo(("PHYSICAL MEMORY: RANGE[%u] %08x.%08x - %08x.%08x\n",
                   Index, Range[Index].BaseAddress.HighPart, Range[Index].BaseAddress.LowPart,
                   EndAddress.HighPart, EndAddress.LowPart));

        (VOID) Xmsnprintf(Key, sizeof (Key), "data/physical-memory/range%u", Index);

        (VOID) xenbus_printf(XBT_NIL, Key, "base", "%08x.%08x", 
                             Range[Index].BaseAddress.HighPart,
                             Range[Index].BaseAddress.LowPart);

        (VOID) xenbus_printf(XBT_NIL, Key, "end", "%08x.%08x",
                             EndAddress.HighPart,
                             EndAddress.LowPart);

        if (EndAddress.QuadPart > TopAddress.QuadPart)
            TopAddress.QuadPart = EndAddress.QuadPart;
    }

    TraceNotice(("PHYSICAL MEMORY: TOP = %08x.%08x\n", TopAddress.HighPart, TopAddress.LowPart));

    return (ULONG)(TopAddress.QuadPart >> PAGE_SHIFT);
}

typedef MDL *
(*PMM_ALLOCATE_PAGES_FOR_MDL_EX)(
    IN  LARGE_INTEGER,
    IN  LARGE_INTEGER,
    IN  LARGE_INTEGER,
    IN  SIZE_T,
    IN  MEMORY_CACHING_TYPE,
    IN  ULONG);

PMM_ALLOCATE_PAGES_FOR_MDL_EX   __MmAllocatePagesForMdlEx;
BOOLEAN                         AllocatorInitialized = FALSE;

static VOID
BalloonInitializeAllocator(
    VOID
    )
{
    UNICODE_STRING  Name;

    XM_ASSERT(__MmAllocatePagesForMdlEx == NULL);
    RtlInitUnicodeString(&Name, L"MmAllocatePagesForMdlEx");
    __MmAllocatePagesForMdlEx = (PMM_ALLOCATE_PAGES_FOR_MDL_EX)(ULONG_PTR)MmGetSystemRoutineAddress(&Name);

    AllocatorInitialized = TRUE;
}

// Look at index @Start in the heap, and push it down into its
// children so as to make it the root of a heap, assuming that both of
// its children are already heaps. */
static VOID
BalloonHeapPushDown(
    IN  PFN_NUMBER  *Heap,
    IN  ULONG       Start,
    IN  ULONG       Count
    )
{
    ULONG           LeftChild;
    ULONG           RightChild;

#define SWAP_NODES(_x, _y)              \
    do {                                \
        PFN_NUMBER  __val = Heap[(_y)]; \
                                        \
        Heap[(_y)] = Heap[(_x)];        \
        Heap[(_x)] = __val;             \
    } while (FALSE)

again:
    LeftChild = Start * 2 + 1;
    RightChild = Start * 2 + 2;

    if (RightChild < Count) {
        XM_ASSERT(Heap[LeftChild] != Heap[Start]);
        XM_ASSERT(Heap[RightChild] != Heap[Start]);
        XM_ASSERT(Heap[LeftChild] != Heap[RightChild]);

        if (Heap[LeftChild] < Heap[Start] &&
            Heap[RightChild] < Heap[Start])
            return;

        if (Heap[LeftChild] < Heap[Start] &&
            Heap[RightChild] > Heap[Start]) {
            SWAP_NODES(RightChild, Start);
            XM_ASSERT(Heap[RightChild] < Heap[Start]);
            Start = RightChild;
            goto again;
        }

        if (Heap[RightChild] < Heap[Start] &&
            Heap[LeftChild] > Heap[Start]) {
            SWAP_NODES(LeftChild, Start);
            XM_ASSERT(Heap[LeftChild] < Heap[Start]);
            Start = LeftChild;
            goto again;
        }

        // (Heap[LeftChild] > Heap[Start] &&
        //  Heap[RightChild] > Heap[Start])
        if (Heap[LeftChild] > Heap[RightChild]) {
            SWAP_NODES(LeftChild, Start);
            XM_ASSERT(Heap[LeftChild] < Heap[Start]);
            Start = LeftChild;
        } else {
            SWAP_NODES(RightChild, Start);
            XM_ASSERT(Heap[RightChild] < Heap[Start]);
            Start = RightChild;
        }

        goto again;
    }

    if (LeftChild < Count) {    // Only one child
        XM_ASSERT(Heap[LeftChild] != Heap[Start]);
        if (Heap[LeftChild] < Heap[Start])
            return;

        SWAP_NODES(LeftChild, Start);
        XM_ASSERT(Heap[LeftChild] < Heap[Start]);
        Start = LeftChild;
        goto again;
    }

#undef SWAP_NODES
}

// Turn an array of PFNs into a max heap (largest node at root)
static VOID
BalloonCreateHeap(
    IN  PFN_NUMBER  *Array,
    IN  ULONG       Count
    )
{
    LONG Index = (LONG)Count;

    while (--Index >= 0)
        BalloonHeapPushDown(Array, (ULONG)Index, Count);
}

static VOID
__BalloonCheckHeap(
    IN  ULONG               Line,
    IN  const PFN_NUMBER    *Array,
    IN  ULONG               Count
    )
{
    ULONG                   Index;

    for (Index = 0; Index < Count / 2; Index++) {
        ULONG   LeftChild = Index * 2 + 1;
        ULONG   RightChild = Index * 2 + 2;

        if (LeftChild < Count) {
            if (Array[Index] <= Array[LeftChild]) {
                TraceNotice(("PFN[%d] (%p) <= PFN[%d] (%p) (at line %d)\n",
                             Index, Array[Index],
                             LeftChild, Array[LeftChild],
                             Line));
                }
        }
        if (RightChild < Count) {
            if (Array[Index] <= Array[RightChild]) {
                TraceNotice(("PFN[%d] (%p) <= PFN[%d] (%p) (at line %d)\n",
                             Index, Array[Index],
                             RightChild, Array[RightChild],
                             Line));
                }
        }
    }
}

#define BalloonCheckHeap(_Array, _Count)    \
        __BalloonCheckHeap(__LINE__, (_Array), (_Count))

static VOID
BalloonSortPfnArray(
    IN  PFN_NUMBER  *Array,
    IN  ULONG       Count
    )
{
    ULONG           Unsorted;

    // Heap sort to keep stack usage down
    BalloonCreateHeap(Array, Count);
    BalloonCheckHeap(Array, Count);

    for (Unsorted = Count; Unsorted != 0; --Unsorted) {
        PFN_NUMBER  Pfn = Array[0];

        Array[0] = Array[Unsorted - 1];
        Array[Unsorted - 1] = Pfn;

        BalloonHeapPushDown(Array, 0, Unsorted - 1);
        BalloonCheckHeap(Array, Unsorted - 1);
    }
}

static MDL *
BalloonAllocatePagesForMdl(
    IN  ULONG       Count
    )
{
    LARGE_INTEGER   LowAddress;
    LARGE_INTEGER   HighAddress;
    LARGE_INTEGER   SkipBytes;
    SIZE_T          TotalBytes;
    MDL             *Mdl;

    XM_ASSERT(AllocatorInitialized);

    LowAddress.QuadPart = 0ull;
    HighAddress.QuadPart = ~0ull;
    SkipBytes.QuadPart = 0ull;
    TotalBytes = (SIZE_T)Count << PAGE_SHIFT;
    
    if (__MmAllocatePagesForMdlEx != NULL)
        Mdl = __MmAllocatePagesForMdlEx(LowAddress,
                                        HighAddress,
                                        SkipBytes,
                                        TotalBytes,
                                        MmCached,
                                        MM_DONT_ZERO_ALLOCATION);
    else
        Mdl = MmAllocatePagesForMdl(LowAddress,
                                    HighAddress,
                                    SkipBytes,
                                    TotalBytes);

    if (Mdl == NULL)
        goto done;

    XM_ASSERT((Mdl->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA |
                                MDL_PARTIAL_HAS_BEEN_MAPPED |
                                MDL_PARTIAL |
                                MDL_PARENT_MAPPED_SYSTEM_VA |
                                MDL_SOURCE_IS_NONPAGED_POOL |
                                MDL_IO_SPACE)) == 0);

done:
    return Mdl;
}

static VOID
BalloonFreePagesFromMdl(
    IN  MDL         *Mdl,
    IN  BOOLEAN     Check
    )
{
    volatile UCHAR  *Mapping;
    ULONG           Index;

    if (!Check)
        goto done;

    // Sanity check:
    //
    // Make sure that things written to the page really do stick. 
    // If the page is still ballooned out at the hypervisor level
    // then writes will be discarded and reads will give back
    // all 1s. */

    Mapping = MmMapLockedPagesSpecifyCache(Mdl,
                                           KernelMode,
                                           MmCached,
                                           NULL,
                                           FALSE,
                                           LowPagePriority);
    if (Mapping == NULL) {
        // Windows couldn't map the mempry. That's kind of sad, but not
        // really an error: it might be that we're very low on kernel
        // virtual address space.
        goto done;
    }

    // Write and read the first byte in each page to make sure it's backed
    // by RAM.
    XM_ASSERT((Mdl->ByteCount & (PAGE_SIZE - 1)) == 0);

    for (Index = 0; Index < Mdl->ByteCount >> PAGE_SHIFT; Index++)
        Mapping[Index << PAGE_SHIFT] = (UCHAR)Index;

    for (Index = 0; Index < Mdl->ByteCount >> PAGE_SHIFT; Index++) {
        if (Mapping[Index << PAGE_SHIFT] != (UCHAR)Index) {
            PFN_NUMBER  *Array = MmGetMdlPfnArray(Mdl);

            TraceCritical(("%s: PFN[%d] (%p): read 0x%02x, expected 0x%02x\n",
                           __FUNCTION__, Index, Array[Index],
                           Mapping[Index << PAGE_SHIFT], (UCHAR)Index));
            XM_BUG();
        }
    }

done:
    MmFreePagesFromMdl(Mdl);
}

#define MIN_PAGES_PER_S 10000ull

static BOOLEAN
BalloonAllocatePfnArray(
    IN  ULONG       Requested,
    OUT PULONG      pAllocated
    )
{
    LARGE_INTEGER   Start;
    LARGE_INTEGER   End;
    ULONGLONG       TimeDelta;
    BOOLEAN         Slow;
    MDL             *Mdl;
    ULONG           Allocated;
    PFN_NUMBER      *Array;

    XM_ASSERT(Requested <= BALLOON_PFN_ARRAY_SIZE);

    KeQuerySystemTime(&Start);

    Allocated = 0;

    Mdl = BalloonAllocatePagesForMdl(Requested);
    if (Mdl == NULL) {
        Balloon.AllocateFail++;
        goto done;
    }

    XM_ASSERT(Mdl->ByteOffset == 0);
    XM_ASSERT((Mdl->ByteCount & (PAGE_SIZE - 1)) == 0);
    XM_ASSERT(Mdl->MdlFlags & MDL_PAGES_LOCKED);

    Allocated = Mdl->ByteCount >> PAGE_SHIFT;

    if (Allocated < Requested) {
        TraceNotice(("%s: partial allocation (%d < %d)\n", __FUNCTION__, Allocated, Requested));
        Balloon.PartialAllocate++;
    }

    Array = MmGetMdlPfnArray(Mdl);
    BalloonSortPfnArray(Array, Allocated);
    RtlCopyMemory(Balloon.PfnArray, Array, Allocated * sizeof (PFN_NUMBER));

    ExFreePool(Mdl);

done:
    TraceVerbose(("%s: %d page(s)\n", __FUNCTION__, Allocated));

    KeQuerySystemTime(&End);
    TimeDelta = (End.QuadPart - Start.QuadPart) / 10000ull;

    Slow = FALSE;
    if (TimeDelta != 0) {
        ULONGLONG   Rate;

        Rate = (ULONGLONG)(Allocated * 1000) / TimeDelta;
        if (Rate < MIN_PAGES_PER_S) {
            TraceWarning(("%s: ran for more than %dms\n", __FUNCTION__, TimeDelta));
            Slow = TRUE;
        }
    }

    *pAllocated = Allocated;
    return Slow;
}

static BOOLEAN
BalloonPopulatePfnArray(
    IN  ULONG                   Requested,
    OUT PULONG                  pPopulated
    )
{
    xen_memory_reservation_t    reservation;
    LARGE_INTEGER               Start;
    LARGE_INTEGER               End;
    ULONGLONG                   TimeDelta;
    BOOLEAN                     Slow;
    ULONG                       Populated;

    XM_ASSERT(Requested <= BALLOON_PFN_ARRAY_SIZE);

    KeQuerySystemTime(&Start);

    RangeSetPopMany(&(Balloon.PfnsBalloonedOut),
                    &(Balloon.PfnArray[0]),
                    Requested);

    SET_XEN_GUEST_HANDLE(reservation.extent_start, Balloon.PfnArray);
    reservation.extent_order = 0;
    reservation.mem_flags = 0;   // unused
    reservation.domid = DOMID_SELF;
    reservation.nr_extents = Requested;

    Populated = HYPERVISOR_memory_op(XENMEM_populate_physmap, &reservation);
    if (Populated < Requested) {
        Balloon.PartialPopulate++;

        // This should not fail as we're simply handing back part of a range we'd previously popped.
        RangeSetAddItems(&(Balloon.PfnsBalloonedOut),
                         &(Balloon.PfnArray[Populated]),
                         Requested - Populated);
    } else if (Populated > Requested) {
        XM_BUG();
    }

    RangeSetDropRseCache(&(Balloon.PfnsBalloonedOut));

    TraceVerbose(("%s: %d page(s)\n", __FUNCTION__, Populated));

    KeQuerySystemTime(&End);
    TimeDelta = (End.QuadPart - Start.QuadPart) / 10000ull;

    Slow = FALSE;
    if (TimeDelta != 0) {
        ULONGLONG   Rate;

        Rate = (ULONGLONG)(Populated * 1000) / TimeDelta;
        if (Rate < MIN_PAGES_PER_S) {
            TraceWarning(("%s: ran for more than %dms\n", __FUNCTION__, TimeDelta));
            Slow = TRUE;
        }
    }

    *pPopulated = Populated;
    return Slow;
}

static BOOLEAN
BalloonReleasePfnArray(
    IN  ULONG                   Requested,
    OUT PULONG                  pReleased
    )
{
    xen_memory_reservation_t    reservation;
    LARGE_INTEGER               Start;
    LARGE_INTEGER               End;
    ULONGLONG                   TimeDelta;
    BOOLEAN                     Slow;
    ULONG                       Index;
    ULONG                       Registered;
    ULONG                       Released;

    XM_ASSERT(Requested <= BALLOON_PFN_ARRAY_SIZE);

    KeQuerySystemTime(&Start);

    Released = 0;

    if (Requested == 0)
        goto done;

    for (Index = 0; Index < Requested; Index++) {
        if (Balloon.PfnArray[Index] == 0) {
            TraceError(("%s: PFN[%d] == 0\n", __FUNCTION__, Index));
            XM_BUG();
        }
    }

    Registered = RangeSetAddItems(&(Balloon.PfnsBalloonedOut), 
                                  &(Balloon.PfnArray[0]),
                                  Requested);
    if (Registered < Requested) {
        TraceError(("%s: failed to register %d page(s)\n", __FUNCTION__,
                    Requested - Registered));
        if (Registered == 0)
            goto done;
    }

    SET_XEN_GUEST_HANDLE(reservation.extent_start, Balloon.PfnArray);
    reservation.extent_order = 0;
    reservation.mem_flags = 0;   // unused
    reservation.domid = DOMID_SELF;
    reservation.nr_extents = Registered;

    Released = HYPERVISOR_memory_op(XENMEM_decrease_reservation, &reservation);
    if (Released < Registered) {
        TraceWarning(("%s: partial release (%d < %d)\n", __FUNCTION__, Released, Registered));

        // This should not fail as we're removing ranges we just added
        RangeSetRemoveItems(&(Balloon.PfnsBalloonedOut),
                            &(Balloon.PfnArray[Released]),
                            Registered - Released);
    } else if (Released > Registered) {
        XM_BUG();
    }

    RtlZeroMemory(Balloon.PfnArray, Released * sizeof (PFN_NUMBER));

done:
    RangeSetDropRseCache(&(Balloon.PfnsBalloonedOut));

    TraceVerbose(("%s: %d page(s)\n", __FUNCTION__, Released));

    KeQuerySystemTime(&End);
    TimeDelta = (End.QuadPart - Start.QuadPart) / 10000ull;

    Slow = FALSE;
    if (TimeDelta != 0) {
        ULONGLONG   Rate;

        Rate = (ULONGLONG)(Released * 1000) / TimeDelta;
        if (Rate < MIN_PAGES_PER_S) {
            TraceWarning(("%s: ran for more than %dms\n", __FUNCTION__, TimeDelta));
            Slow = TRUE;
        }
    }

    *pReleased = Released;
    return Slow;
}

static BOOLEAN
BalloonFreePfnArray(
    IN  ULONG       Requested,
    IN  BOOLEAN     Check,
    OUT PULONG      pFreed
    )
{
    ULONG           Index;
    ULONG           Freed;
    MDL             *Mdl;
    LARGE_INTEGER   Start;
    LARGE_INTEGER   End;
    ULONGLONG       TimeDelta;
    BOOLEAN         Slow;

    XM_ASSERT(Requested <= BALLOON_PFN_ARRAY_SIZE);

    KeQuerySystemTime(&Start);

    Freed = 0;

    if (Requested == 0)
        goto done;

    for (Index = 0; Index < Requested; Index++) {
        if (Balloon.PfnArray[Index] == 0) {
            TraceError(("%s: PFN[%d] == 0\n", __FUNCTION__, Index));
            XM_BUG();
        }
    }

    Mdl = &(Balloon.Mdl);
    Mdl->Next = NULL;
    Mdl->Size = (SHORT)(sizeof(MDL) + (sizeof(PFN_NUMBER) * Requested));
    Mdl->MdlFlags = MDL_PAGES_LOCKED;
    Mdl->Process = NULL;
    Mdl->MappedSystemVa = NULL;
    Mdl->StartVa = NULL;
    Mdl->ByteCount = Requested << PAGE_SHIFT;
    Mdl->ByteOffset = 0;

    BalloonFreePagesFromMdl(Mdl, Check);
    Freed = Requested;

    RtlZeroMemory(Balloon.PfnArray, Freed * sizeof (PFN_NUMBER));

done:
    TraceVerbose(("%s: %d page(s)\n", __FUNCTION__, Freed));

    KeQuerySystemTime(&End);
    TimeDelta = (End.QuadPart - Start.QuadPart) / 10000ull;

    Slow = FALSE;
    if (TimeDelta != 0) {
        ULONGLONG   Rate;

        Rate = (ULONGLONG)(Freed * 1000) / TimeDelta;
        if (Rate < MIN_PAGES_PER_S) {
            TraceWarning(("%s: ran for more than %dms\n", __FUNCTION__, TimeDelta));
            Slow = TRUE;
        }
    }

    *pFreed = Freed;
    return Slow;
}

static ULONG
BalloonDeflate(
    IN  ULONG       Requested,
    OUT ULONGLONG   *pTimeDelta OPTIONAL
    )
{
    LARGE_INTEGER   Start;
    LARGE_INTEGER   End;
    BOOLEAN         Abort;
    ULONG           Returned;

    XM_ASSERT(!Balloon.Frozen);

    KeQuerySystemTime(&Start);
    TraceVerbose(("%s: ====>\n", __FUNCTION__));

    Returned = 0;
    if (Balloon.FIST_deflation)
        goto done;

    Abort = FALSE;
    while (Returned < Requested) {
        ULONG           ThisTime = MIN(Requested - Returned, BALLOON_PFN_ARRAY_SIZE);
        ULONG           Populated;
        ULONG           Freed;

        Abort |= BalloonPopulatePfnArray(ThisTime, &Populated);
        Abort |= (Populated < ThisTime);
        Abort |= BalloonFreePfnArray(Populated, TRUE, &Freed);

        XM_ASSERT(Freed == Populated);

        RtlZeroMemory(Balloon.PfnArray, BALLOON_PFN_ARRAY_SIZE * sizeof (PFN_NUMBER));
        Returned += Freed;

        if (Abort)
            break;
    }

done:
    TraceVerbose(("%s: <====\n", __FUNCTION__));
    KeQuerySystemTime(&End);

    if (pTimeDelta != NULL)
        *pTimeDelta = (End.QuadPart - Start.QuadPart) / 10000ull;

    return Returned;
}

static VOID
BalloonPodSweep(void)
{
    xen_pod_sweep_t sweep;
    LONG            Count;

    sweep.domid = DOMID_SELF;
    sweep.limit = 0;

    Count = HYPERVISOR_memory_op(XENMEM_pod_sweep, &sweep);
    if (Count < 0) {
        TraceWarning(("%s: HYPERVISOR_memory_op(XENMEM_pod_sweep, ...) failed (%08x)\n",
                      __FUNCTION__,
                      Count));
    } else {
        TraceVerbose(("%s: %d page(s)\n", __FUNCTION__, Count));
    }
}

static LONG
BalloonInflate(
    IN  ULONG       Requested,
    OUT ULONGLONG   *pTimeDelta OPTIONAL
    )
{
    LARGE_INTEGER   Start;
    LARGE_INTEGER   End;
    BOOLEAN         Abort;
    ULONG           Acquired;

    XM_ASSERT(!Balloon.Frozen);

    KeQuerySystemTime(&Start);
    TraceVerbose(("%s: ====>\n", __FUNCTION__));

    Acquired = 0;
    if (Balloon.FIST_inflation)
        goto done;

    // Asking Xen to sweep for zeroed pages just prior to a balloon inflation
    // increases performance, but there's no point in doing it unless we can
    // use an allocator that does not touch the pages it allocates.
    XM_ASSERT(AllocatorInitialized);
    if (__MmAllocatePagesForMdlEx != NULL)
        BalloonPodSweep();

    Abort = FALSE;
    while (Acquired < Requested) {
        ULONG           ThisTime = MIN(Requested - Acquired, BALLOON_PFN_ARRAY_SIZE);
        ULONG           Allocated;
        ULONG           Released;

        Abort |= BalloonAllocatePfnArray(ThisTime, &Allocated);
        Abort |= (Allocated < ThisTime);
        Abort |= BalloonReleasePfnArray(Allocated, &Released);

        if (Released < Allocated) {
            ULONG   Freed;

            RtlMoveMemory(&(Balloon.PfnArray[0]),
                          &(Balloon.PfnArray[Released]),
                          (Allocated - Released) * sizeof (PFN_NUMBER));

            BalloonFreePfnArray(Allocated - Released, FALSE, &Freed);
            XM_ASSERT3U(Freed, ==, (Allocated - Released));

            Abort |= (Released == 0);
        }

        RtlZeroMemory(Balloon.PfnArray, BALLOON_PFN_ARRAY_SIZE * sizeof (PFN_NUMBER));
        Acquired += Released;

        if (Abort)
            break;
    }

done:
    TraceVerbose(("%s: <====\n", __FUNCTION__));
    KeQuerySystemTime(&End);

    if (pTimeDelta != NULL)
        *pTimeDelta = (End.QuadPart - Start.QuadPart) / 10000ull;

    return Acquired;
}

static VOID
BalloonTargetChanged(
    IN  VOID    *Context
    )
{
    ULONG       TargetPages;
    NTSTATUS    status;

    UNREFERENCED_PARAMETER(Context);

    status = BalloonReadTargetPages(&TargetPages);
    if (!NT_SUCCESS(status))
        goto done;

    if (TargetPages > Balloon.MaxPages) {
        TraceWarning(("%s: target (%dk) > static-max (%dk)\n", __FUNCTION__,
                      TargetPages * 4, Balloon.MaxPages * 4));
        TargetPages = Balloon.MaxPages;
    }

    if (TargetPages != Balloon.TargetPages) {
        TraceNotice(("%s: %dk -> %dk\n", __FUNCTION__,
                     Balloon.TargetPages * 4, TargetPages * 4));
        Balloon.TargetPages = TargetPages;
    }

done:
    // Always wake up the worker thread regardless of whether target has
    // actually changed or not
    KeSetEvent(&(Balloon.WorkerThread->event), IO_NO_INCREMENT, FALSE);
}

static VOID
BalloonFISTChanged(
    IN  VOID    *Context
    )
{
    UNREFERENCED_PARAMETER(Context);

    xenbus_read_feature_flag(XBT_NIL, "FIST/balloon", "inflation",
                             &(Balloon.FIST_inflation));
    xenbus_read_feature_flag(XBT_NIL, "FIST/balloon", "deflation",
                             &(Balloon.FIST_deflation));
}

#define BALLOON_PAUSE   1 // in s

static NTSTATUS
BalloonWorkerThread(
    IN  struct xm_thread        *Self,
    IN  VOID                    *Context
    )
{
    struct xenbus_watch_handler *TargetWatch;
    struct xenbus_watch_handler *FISTWatch;
    LARGE_INTEGER               Timeout;
    LARGE_INTEGER               *pTimeout;
    ULONG                       CurrentPages;
    ULONG                       PagesDelta;
    ULONGLONG                   TimeDelta;
    NTSTATUS                    status;

    UNREFERENCED_PARAMETER(Context);

    TraceVerbose(("%s: ====>\n", __FUNCTION__));
     
    TargetWatch = xenbus_watch_path("memory/target", BalloonTargetChanged, NULL);

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (TargetWatch == NULL)
        goto fail1;

    FISTWatch = xenbus_watch_path("FIST", BalloonFISTChanged, NULL);

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (FISTWatch == NULL)
        goto fail2;

    Timeout.QuadPart = TIME_RELATIVE(TIME_S(BALLOON_PAUSE));

    pTimeout = NULL;    // Indefinite wait
    while (!Self->exit) {
        // NOTE: We rely on the fact that suspend/resume fires all
        // watches, so we'll get woken up on every migration and will
        // be able to re-advertize the feature flag.
        if (!Balloon.Advertized ||
            Balloon.AdvertizedSuspendCount != SuspendGetCount()) {
            Balloon.AdvertizedSuspendCount = SuspendGetCount();
            xenbus_write_feature_flag(XBT_NIL, "control", "feature-balloon", TRUE);
            Balloon.Advertized = TRUE;
        }

        KeWaitForSingleObject(&Self->event,
                              Executive,
                              KernelMode,
                              FALSE,
                              pTimeout);
        KeClearEvent(&Self->event);

        if (Self->exit) {
            // The xapi protocol is:
            //
            // - check feature-balloon
            // - write target
            // - check feature-balloon again
            //
            // and we're expected to respond to the balloon request if both reads
            // of the feature flag return TRUE.  We're allowed to respond even
            // when the flag is clear, but we're not required to.
            // Therefore we do one more interation after clearing the feature flag
            XM_ASSERT(Balloon.Advertized);
            xenbus_write_feature_flag(XBT_NIL, "control", "feature-balloon", FALSE);
            Balloon.Advertized = FALSE;
        }

        if (Balloon.Frozen)
            continue;

        if (!Balloon.Active ||
            Balloon.ActiveSuspendCount != SuspendGetCount()) {
            Balloon.ActiveSuspendCount = SuspendGetCount();
            TraceNotice(("%s: activating\n", __FUNCTION__));
            xenbus_write_feature_flag(XBT_NIL, "control", "balloon-active", TRUE);
            Balloon.Active = TRUE;
        }

        CurrentPages = Balloon.CurrentPages;

        PagesDelta = 0;
        TimeDelta = 0ull;
        if (Balloon.TargetPages < Balloon.CurrentPages) {
            PagesDelta = BalloonInflate(Balloon.CurrentPages - Balloon.TargetPages, &TimeDelta);
            CurrentPages = Balloon.CurrentPages - PagesDelta;
        } else if (Balloon.TargetPages > Balloon.CurrentPages) {
            PagesDelta = BalloonDeflate(Balloon.TargetPages - Balloon.CurrentPages, &TimeDelta);
            CurrentPages = Balloon.CurrentPages + PagesDelta;
        }

        if (PagesDelta != 0) {
            if (TimeDelta != 0) {
                TraceNotice(("%s: %s balloon by %d page(s) in %llums (%lluk/s)\n", __FUNCTION__,
                             (CurrentPages < Balloon.CurrentPages) ? "inflated" : "deflated",
                             PagesDelta, TimeDelta, (ULONGLONG)(PagesDelta * 4 * 1000) / TimeDelta));
            } else {
                TraceNotice(("%s: %s balloon by %d page(s)\n", __FUNCTION__,
                             (CurrentPages < Balloon.CurrentPages) ? "inflated" : "deflated",
                             PagesDelta));
            }
        }

        Balloon.CurrentPages = CurrentPages;

        XM_ASSERT(RangeSetItems(&(Balloon.PfnsBalloonedOut)) == Balloon.MaxPages - Balloon.CurrentPages);

        if (Balloon.CurrentPages == Balloon.TargetPages) {
            XM_ASSERT(Balloon.Active);
            TraceNotice(("%s: de-activating\n", __FUNCTION__));
            xenbus_write_feature_flag(XBT_NIL, "control", "balloon-active", FALSE);
            Balloon.Active = FALSE;

            KeSetEvent(&(Balloon.WorkerDoneEvent), IO_NO_INCREMENT, FALSE);
            pTimeout = NULL;
            continue;
        }

        TraceNotice(("%s: pausing for %ds (target = %dk, current = %dk)\n", __FUNCTION__,
                     BALLOON_PAUSE, Balloon.TargetPages * 4, Balloon.CurrentPages * 4));

        pTimeout = &Timeout;
    }

    if (Balloon.Active) {
        xenbus_write_feature_flag(XBT_NIL, "control", "feature-balloon", FALSE);
        Balloon.Active = FALSE;
    }

    if (Balloon.Advertized) {
        xenbus_write_feature_flag(XBT_NIL, "control", "feature-balloon", FALSE);
        Balloon.Advertized = FALSE;
    }

    xenbus_unregister_watch(FISTWatch);
    xenbus_unregister_watch(TargetWatch);

    KeSetEvent(&(Balloon.WorkerDoneEvent), IO_NO_INCREMENT, FALSE);

    TraceVerbose(("%s: <====\n", __FUNCTION__));
    return STATUS_SUCCESS;

fail2:
    TraceError(("%s: fail2\n", __FUNCTION__));

    xenbus_unregister_watch(TargetWatch);

fail1:
    TraceError(("%s: fail1 (%08x)\n", __FUNCTION__, status));

    KeSetEvent(&(Balloon.WorkerDoneEvent), IO_NO_INCREMENT, FALSE);

    TraceVerbose(("%s: <====\n", __FUNCTION__));
    return status;
}

static NTSTATUS
BalloonSpawnWorkerThread(
    VOID
    )
{
    NTSTATUS status;

    XM_ASSERT(Balloon.WorkerThread == NULL);

    Balloon.WorkerThread = XmSpawnThread(BalloonWorkerThread, NULL);

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (Balloon.WorkerThread == NULL)
        goto fail1;
        
    return STATUS_SUCCESS;
    
fail1:    
    TraceError(("%s: fail1 (%08x)\n", __FUNCTION__, status));

    return status;
}

BOOLEAN
BalloonIsEmpty(
    VOID
    )
{
    return (Balloon.CurrentPages == Balloon.MaxPages) ? TRUE : FALSE;
}

VOID
BalloonFreeze(
    VOID
    )
{
    Balloon.Frozen = TRUE;
}

VOID
BalloonThaw(
    VOID
    )
{
    Balloon.Frozen = FALSE;
}

/* Xen 4.1: HVMOP_wheres_my_memory is obsolete and unsupported...
static VOID
BalloonXenDump(
    VOID
    )
{
    xen_hvm_wheres_my_memory_t  xen_mem;
    static CHAR                 Buffer[PAGE_SIZE];
    LONG                        Ret;
    ULONG                       Start;
    ULONG                       End;

    xen_mem.buffer_size = sizeof(Buffer);
    xen_mem.buffer_va = (ULONG64)(ULONG_PTR)Buffer;
    xen_mem.domid = DOMID_SELF;

    RtlZeroMemory(Buffer, sizeof (Buffer));

    Ret = (LONG)HYPERVISOR_hvm_op(HVMOP_wheres_my_memory, &xen_mem);
    if (Ret < 0) {
        TraceInternal(("HYPERVISOR_hvm_op(HVMOP_wheres_my_memory, ...) failed (%08x)\n",
                       Ret));
        return;
    }

    if (Buffer[0] == '\0') {
        TraceInternal(("HYPERVISOR_hvm_op(HVMOP_wheres_my_memory, ...) returned an empty buffer\n"));
        return;
    }

    TraceInternal(("Xen memory summary:\n"));

    Start = End = 0;
    while (End < sizeof (Buffer) && Buffer[End] != '\0') {
        if (Buffer[End] == '\n') {
            Buffer[End++] = '\0';
            XM_ASSERT(End > Start);
            TraceInternal(("> %s\n", &Buffer[Start]));
            Start = End;
            continue;
        }
        End++;
    }
}*/

static VOID
BalloonDebugDump(
    VOID    *Context
    )
{
    UNREFERENCED_PARAMETER(Context);

    TraceInternal(("MaxPages: %d (%dk), CurrentPages: %d (%dk), TargetPages: %d (%dk)\n",
                 Balloon.MaxPages, Balloon.MaxPages * 4,
                 Balloon.CurrentPages, Balloon.CurrentPages * 4,
                 Balloon.TargetPages, Balloon.TargetPages * 4));

    TraceInternal(("%d allocation failures, %d partial allocations, %d partial populates\n",
                 Balloon.AllocateFail,
                 Balloon.PartialAllocate,
                 Balloon.PartialPopulate));

    TraceInternal(("FIST flags: inflation %s, deflation %s\n",
                 (Balloon.FIST_inflation) ? "ON" : "OFF", 
                 (Balloon.FIST_deflation) ? "ON" : "OFF"));

    RangeSetDump(&(Balloon.PfnsBalloonedOut));

    //BalloonXenDump();
}

NTSTATUS
BalloonInit(
    VOID
    )
{
    ULONG       MaxPages;
    NTSTATUS    status;

    XM_ASSERT(!AustereMode);

    TraceVerbose(("%s: ====>\n", __FUNCTION__));

    if (Balloon.Initialized)
        goto done;

    Balloon.TopPage = BalloonGetTopPage();

    status = BalloonReadMaxPages(&MaxPages);
    if (!NT_SUCCESS(status))
        goto fail1;

#ifndef AMD64
    if (!IsPAEEnabled()) {
        TraceNotice(("PAE is OFF\n"));

        status = STATUS_UNSUCCESSFUL;
        if (MaxPages > (1ul << 20)) {
            xenbus_write(XBT_NIL, "data/warning", "Non-PAE OS cannot access all of RAM");
            goto fail2;
        }
    } else {
        TraceNotice(("PAE is ON\n"));
    }
#endif  // AMD64

    Balloon.TargetPages = Balloon.CurrentPages = Balloon.MaxPages = MaxPages;

    BalloonInitializeAllocator();

    RangeSetInit(&(Balloon.PfnsBalloonedOut));

    KeInitializeEvent(&(Balloon.WorkerDoneEvent), NotificationEvent, FALSE);

    status = BalloonSpawnWorkerThread();
    if (!NT_SUCCESS(status))
        goto fail3;

    EvtchnSetupDebugCallback(BalloonDebugDump, NULL);

    // We rely on the initial target watch registration causing the worker thread event
    // to be set.
    KeWaitForSingleObject(&(Balloon.WorkerDoneEvent),
                          Executive,
                          KernelMode,
                          FALSE,
                          NULL);

    Balloon.Initialized = TRUE;

done:
    TraceVerbose(("%s: <====\n", __FUNCTION__));
    return STATUS_SUCCESS;

fail3:
    TraceError(("%s: fail3\n", __FUNCTION__));

#ifndef AMD64
fail2:
    TraceError(("%s: fail2\n", __FUNCTION__));
#endif  // AMD64

fail1:
    TraceError(("%s: fail1 (%08x)\n", __FUNCTION__, status));

    TraceVerbose(("%s: <====\n", __FUNCTION__));
    return status;
}

VOID
BalloonQuery(
    OUT XS_QUERY_BALLOON    *query
    )
{
    query->max_pages = Balloon.MaxPages;
    query->current_pages = Balloon.CurrentPages;
    query->target_pages = Balloon.TargetPages;
    query->allocations_failed = Balloon.AllocateFail;
    query->partial_allocations = Balloon.PartialAllocate;
}
