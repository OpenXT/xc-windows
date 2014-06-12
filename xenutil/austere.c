/* Various utility functions which are useful to the boot device
   driver.  Windows boot device drivers run in a very restricted
   environment, so we have to implement things like malloc()
   ourselves, which is a bit of a pain */

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


/* Copyright (c) 2006 XenSource, Inc. */

#include "xenutl.h"
#include "vbd_special.h"

//
// Dont care about unreferenced formal parameters here
//
#pragma warning( disable : 4100 )

ULONG _OperatingMode;

/* Malloc implementation:

   We have a single fixed size heap to play with.  Allocations of
   PAGE_SIZE or larger must be page aligned, while anything smaller
   than that only needs to be four byte aligned.

   The idea here is to have a two level heap, with the topmost level
   dealing in runs of contiguous pages and the second level dealing
   with smaller allocations from sub-heaps allocated with the first
   allocator.

   The big allocator is fairly easy: for every page in the heap, we
   track how large an allocation it starts, and whether it's currently
   in use or not.  Allocating is a simple matter of find a large
   enough allocation which is currently free and then hiving a few
   pages off the front.  We don't do coallescing of neighbouring free
   blocks at this level, until an allocation fails.  We maintain a
   cursor into the big heap.  After an allocation, the cursor is set
   to point immediately after the allocated block, while after a free
   it points to the freed block.  When we allocate something, we start
   from the cursor.

   The small allocator works in a bunch of sub-heaps, each of which is
   a page allocated from the big heap.  Sub-heaps are threaded on a
   double linked list, which is pull-to-front when an allocation
   succeeds out of a subheap or when we free something from the
   subheap.  Inside the subheap, allocations use a fairly standard
   model, in which every block has a header saying the block's size
   and whether it's currently free and a trailer which repeats the
   block's size.

   This isn't the cleverest allocator out there, and it's certainly
   not the fastest or most space efficient, but it's good enough for
   our purposes. */

#define FREE_CHUNK 0x80000000

#define MallocDebug(x) do {} while (0)
//#define MallocDebug(x) TraceDebug(x)
#define MallocTrace(x) do {} while (0)
//#define MallocTrace(x) TraceDebug(x)

/***************************** BIG ALLOCATOR ***************************/
static unsigned char *big_heap_start;
static ULONG heap_block_sizes[AUSTERE_HEAP_PAGES];
static ULONG big_heap_cursor;
static PHYSICAL_ADDRESS big_heap_base;
static int nr_heap_pages;

/* Try to compact any adjacent runs of free blocks in the big heap.
   Returns 1 if we did anything, 0 otherwise. */
static int
CompactBigHeap(VOID)
{
    int ret = 0;
    int i;
    int size;

    for (i = 0; i < nr_heap_pages; ) {
        size = heap_block_sizes[i] & ~FREE_CHUNK;
        if ((heap_block_sizes[i] & FREE_CHUNK)       &&
            (i + size < nr_heap_pages)               &&
            (heap_block_sizes[i + size] & FREE_CHUNK)  ) {
            MallocDebug(("Merge run at %x with run at %x.\n",
                         i, i + size));
            heap_block_sizes[i] = size +
                heap_block_sizes[i + size];
            MallocDebug(("New block at %x size %x.\n",
                         i, heap_block_sizes[i]));
            ret = 1;
            continue;
        }
        i += size;
    }
    return ret;
}

/* Pad nBytes to a multiple of PAGE_SIZE and then allocate a chunk of
   that size with at least page alignment */
static PVOID
BigAllocation(size_t nBytes)
{
    ULONG nPages;
    ULONG i, n;
    PVOID res;
    int repeat = 0;

    nPages = (ULONG)((nBytes + PAGE_SIZE - 1) / PAGE_SIZE);
    MallocDebug(("Big allocation: %d pages, %d bytes.\n", nPages,
             nBytes));
 retry:
    i = big_heap_cursor % nr_heap_pages;
    for (;;) {
        n = heap_block_sizes[i] & ~FREE_CHUNK;
        if (n >= nPages && heap_block_sizes[i] & FREE_CHUNK)
            break;
        i = (i + n) % nr_heap_pages;
        if (i == big_heap_cursor) {
            MallocDebug(("BigAllocation %d pages (%d bytes) failed initially.\n",
                     nPages, nBytes));
            if (!repeat && nPages > 1) {
                MallocDebug(("Trying compaction...\n"));
                if (CompactBigHeap()) {
                    repeat = 1;
                    MallocDebug(("Retry allocation.\n"));
                    goto retry;
                }
            }
            TraceWarning(("BigAllocation %d pages (%d bytes) failed.\n",
                          nPages, nBytes));
            return NULL;
        }
    }

    MallocDebug(("Allocating big alloc at %d.\n", i));
    res = (PVOID)(big_heap_start + i * PAGE_SIZE);
    if (heap_block_sizes[i] != (nPages | FREE_CHUNK)) {
        /* Split the chunk. */
        XM_ASSERT(heap_block_sizes[i] & FREE_CHUNK);
        XM_ASSERT(heap_block_sizes[i] > (nPages | FREE_CHUNK));
        MallocDebug(("Split chunk: %x != %x.\n",
                 heap_block_sizes[i], nPages));
        XM_ASSERT(i + nPages <= AUSTERE_HEAP_PAGES);
        if (i + nPages != AUSTERE_HEAP_PAGES)
            heap_block_sizes[i + nPages] =
                heap_block_sizes[i] - nPages;
        XM_ASSERT(heap_block_sizes[i + nPages] & FREE_CHUNK);
    }
    heap_block_sizes[i] = nPages;
    big_heap_cursor = (i + nPages) % nr_heap_pages;
    MallocDebug(("Big alloc at %x\n", res));
    return res;
}

static VOID
BigFreeMemory(PVOID block)
{
    int start_nr;
    start_nr = (int)(((unsigned char *)block - big_heap_start) / PAGE_SIZE);
    if (start_nr < 0 || start_nr >= nr_heap_pages) {
        TraceError(("Free of something outside heap: %x.\n",
                    block));
        return;
    }
    if (heap_block_sizes[start_nr] & FREE_CHUNK) {
        TraceError(("Double free of %x.\n", block));
        return;
    }

    heap_block_sizes[start_nr] |= FREE_CHUNK;
    big_heap_cursor = start_nr;
}

/**************************** SMALL ALLOCATOR **************************/

/* PAGE_SIZE - 12 -> make a struct subheap be exactly one page */
/* XXX Should arguably maintain a cursor into subheaps as well as one
   into the big heap.  Not worth the effort, really. */
#define SUBHEAP_SIZE 4084
struct subheap {
    struct subheap *next, *prev;
    unsigned long free_bytes;
    unsigned char heap[SUBHEAP_SIZE];
};

static struct subheap *head_subheap;

/* nBytes *includes* header and trailer and any padding needed */
static PVOID
TrySmallAllocation(struct subheap *sh, size_t nBytes)
{
    unsigned char *ptr;
    ULONG size;

    if (sh->free_bytes < nBytes) {
        /* Shouldn't happen */
        TraceError(("Heap full!\n"));
        return NULL;
    }

        ASSERT(nBytes < SUBHEAP_SIZE);

    /* Keep PREfast happy. */
    size = 0xf001dead;

    /* Find a chunk */
    for (ptr = sh->heap; ptr < (unsigned char *)(sh + 1); ptr += size) {
        ULONG header;
        ULONG trailer;

        header = *(ULONG *)ptr;
        if (header == 0)
            TraceError(("Heap corruption: header 0.\n"));
        if (header & FREE_CHUNK) {
            size = header & ~FREE_CHUNK;
            if (size >= nBytes)
                break;
        } else {
            size = header;
        }
        /* Check the trailer while we're here */
        trailer = *(ULONG *)(ptr + size - sizeof(ULONG));
        MallocDebug(("Chunk at %x, heap start %x, header %x, trailer %x.\n",
                     ptr, sh + 1, header, trailer));
        if (trailer != size)
            TraceError(("Heap chain corrupt: header %x, trailer %x.\n",
                        header, trailer));
    }

    if (ptr == (unsigned char *)(sh + 1)) {
        MallocDebug(("Heap full!\n"));
        return NULL;
    }
    if (ptr > (unsigned char *)(sh + 1)) {
        TraceError(("Ran off end of heap: %x > %x + %x.\n",
                    ptr, sh, sizeof(*sh)));
        return NULL;
    }

    /* We have a valid chunk.  Consider splitting it up a bit. */
    if (size > nBytes + 64) {
        /* Split the chunk */
        MallocDebug(("Split chunk size %x, nbytes %x.\n",
                 size, nBytes));
                /* Typecasts safe because nBytes and size both less
                   than PAGE_SIZE */
        *(ULONG *)ptr = (ULONG)nBytes;
        *(ULONG *)(ptr + nBytes - sizeof(ULONG)) = (ULONG)nBytes;
        *(ULONG *)(ptr + nBytes) =
                    (ULONG)((size - nBytes) | FREE_CHUNK);
        *(ULONG *)(ptr + size - sizeof(ULONG)) =
                    (ULONG)(size - nBytes);
        sh->free_bytes -= (ULONG)nBytes;
    } else {
        /* Mark the chunk as being in use */
        *(ULONG *)ptr = size;
        sh->free_bytes -= size;
    }

    MallocDebug(("Complete allocation size %x, return %x size %x.\n",
             nBytes, ptr + sizeof(ULONG), size));

    return (PVOID)(ptr + sizeof(ULONG));
}

static struct subheap *
NewSubheap(VOID)
{
    struct subheap *sh;
    sh = BigAllocation(sizeof(*sh));
    if (!sh)
        return sh;
    sh->free_bytes = SUBHEAP_SIZE;
    sh->next = sh->prev = NULL;
    *(ULONG *)sh->heap = SUBHEAP_SIZE | FREE_CHUNK;
    *(ULONG *)(sh->heap + SUBHEAP_SIZE - sizeof(ULONG)) = SUBHEAP_SIZE;
    return sh;
}

static PVOID
SmallAllocation(size_t nBytes)
{
    struct subheap *sh;
    PVOID res = NULL;

    MallocDebug(("Small allocation, %d bytes.\n", nBytes));

    /* Round up */
    nBytes = (nBytes + 3) & ~3;
    /* Leave room for header and trailer */
    nBytes += sizeof(ULONG) * 2;

    for (sh = head_subheap; sh; sh = sh->next) {
        if (sh->free_bytes > nBytes) {
            MallocDebug(("Try allocate from %x.\n", sh));
            res = TrySmallAllocation(sh, nBytes);
            MallocDebug(("Allocate gives %x.\n", res));
            if (res)
                break;
        } else {
            MallocDebug(("sh %x too full for %x (%x)).\n",
                    sh, nBytes, sh->free_bytes));
        }
    }
    if (!res) {
        MallocDebug(("New subheap needed.\n"));
        sh = NewSubheap();
        MallocDebug(("New subheap is %x.\n", sh));
        if (sh) {
            res = TrySmallAllocation(sh, nBytes);
            MallocDebug(("Allocate %x.\n", res));
            if (!res) {
                TraceError(("Badness: allocation of %d failed on new subheap.\n",
                            nBytes));
            }
        }
    }
    if (!res) {
        TraceError(("Small allocation of %d failed!\n", nBytes));
        return NULL;
    }

    if (sh != head_subheap) {
        /* Pull the subheap to the head of the list */
        if (sh->prev)
            sh->prev->next = sh->next;
        if (sh->next)
            sh->next->prev = sh->prev;
        sh->prev = NULL;
        sh->next = head_subheap;
        head_subheap = sh;
    }

    return res;
}

static VOID
SmallFreeMemory(PVOID block)
{
    struct subheap *sh;
    PUCHAR ptr = block;
    ULONG size;

    sh = (struct subheap *)((ULONG_PTR)block & ~(PAGE_SIZE - 1));

    /* Backtrack to find the header */
    ptr -= sizeof(ULONG);
    size = *(ULONG *)ptr;
    if (size & FREE_CHUNK) {
        TraceError(("Double free of %x (%x)!\n", block, size));
        return;
    }

    MallocDebug(("Free %x, size %x.\n", block, size));

    sh->free_bytes += size;

    if (sh->free_bytes == SUBHEAP_SIZE) {
        MallocDebug(("Release subheap with %d free.\n",
                 sh->free_bytes));
        /* Everything in this subheap is free.  Release the
           subheap back to the big pool */
        if (sh->next)
            sh->next->prev = sh->prev;
        if (sh->prev)
            sh->prev->next = sh->next;
        if (sh == head_subheap)
            head_subheap = sh->next;
        BigFreeMemory(sh);
        return;
    }

    /* Consider coallescing with our neighbours.  Note that we
       never have to coallesce more than one block in each
       direction. */

    /* Is there a free block above us? */
    if (ptr + size < (unsigned char *)(sh + 1) &&
        (*(ULONG *)(ptr + size) & FREE_CHUNK)) {
        MallocDebug(("Merge up.\n"));
        /* Yes.  Expand this chunk to cover it. */
        size += *(ULONG *)(ptr + size);
        size &= ~FREE_CHUNK;
        *(ULONG *)ptr =    size;
        *(ULONG *)(ptr + size - sizeof(ULONG)) = size;
    }
    MallocDebug(("Done merge up.\n"));

    /* Is there a free block below us? */
    if (ptr > sh->heap) {
        ULONG lsize;
        unsigned char *l;
        MallocDebug(("Maybe merge down.\n"));
        lsize = *(ULONG *)(ptr - sizeof(ULONG));
        l = ptr - lsize;
        if (*(ULONG *)l & FREE_CHUNK) {
            /* Yes */
            MallocDebug(("Merge down.\n"));
            lsize += size;
            *(ULONG *)l = lsize;
            *(ULONG *)(l + lsize - sizeof(ULONG)) = lsize;
            ptr = l;
        }
    }

    MallocDebug(("Finished merging.\n"));

    /* This block is now free */
    *(ULONG *)ptr |= FREE_CHUNK;
    MallocDebug(("Done free.\n"));

    if (sh != head_subheap) {
        /* Pull the subheap to the head of the list */
        if (sh->prev)
            sh->prev->next = sh->next;
        if (sh->next)
            sh->next->prev = sh->prev;
        sh->prev = NULL;
        sh->next = head_subheap;
        head_subheap = sh;
    }
}

/************************** TOP LEVEL ALLOCATOR ************************/
PVOID
_XmAllocateMemory(size_t nBytes, const char *caller)
{
    PVOID res;

    if (nBytes < sizeof(PVOID))
        nBytes = sizeof(PVOID);

    if (!AustereMode) {
        XM_ASSERT3U(KeGetCurrentIrql(), <=, DISPATCH_LEVEL);
        res = ExAllocatePoolWithTag(NonPagedPool,
                                    nBytes,
                                    'xenm');
    } else {
        if (nBytes < PAGE_SIZE - sizeof(ULONG) * 5)
            res = SmallAllocation(nBytes);
        else
            res = BigAllocation(nBytes);

        XM_ASSERT(res != NULL);
        memset(res, 0, nBytes);
    }

    MallocTrace(("%s: allocate %d -> 0x%p\n", caller, nBytes, res));
    return res;
}

PVOID
_XmAllocateZeroedMemory(size_t nBytes, const char *caller)
{
    PVOID res;

    res = _XmAllocateMemory(nBytes, caller);
    if (res == NULL)
        return NULL;

    return memset(res, 0, nBytes);
}


PVOID
XmAllocatePhysMemory(size_t nBytes, PHYSICAL_ADDRESS *pa)
{
    PVOID res;

    res = XmAllocateMemory(nBytes);
    if (res == NULL)
        return NULL;

    *pa = MmGetPhysicalAddress(res);
    return res;
}

static void *pending_release;
static struct irqsafe_lock pending_release_lock;

VOID
XmFreeMemory(PVOID block)
{
    if (!block)
        return;

    MallocTrace(("release 0x%p\n", block));

    if (!AustereMode) {
        KIRQL irql;

        if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
            /* Just put it on the queue to release later */
            irql = acquire_irqsafe_lock(&pending_release_lock);
            *(PVOID *)block = pending_release;
            pending_release = block;
            release_irqsafe_lock(&pending_release_lock, irql);
            return;
        }

        ExFreePoolWithTag(block, 'xenm');
        block = NULL;

        if (pending_release) {
            irql = acquire_irqsafe_lock(&pending_release_lock);
            block = pending_release;
            pending_release = NULL;
            release_irqsafe_lock(&pending_release_lock, irql);

            while (block) {
                PVOID next = *(PVOID *)block;

                ExFreePoolWithTag(block, 'xenm');
                block = next;
            }
        }
    } else {
        XM_ASSERT((ULONG_PTR)block >= (ULONG_PTR)big_heap_start);
        XM_ASSERT((ULONG_PTR)block < (ULONG_PTR)big_heap_start + nr_heap_pages * PAGE_SIZE);

        if ((ULONG_PTR)block & (PAGE_SIZE - 1)) {
            SmallFreeMemory(block);
        } else {
            BigFreeMemory(block);
        }
    }
}

VOID
XmInitMemory(PVOID heap, ULONG nr_pages, PHYSICAL_ADDRESS base)
{
    big_heap_base = base;
    big_heap_start = heap;
    big_heap_cursor = 0;
    nr_heap_pages = nr_pages;
    if (nr_pages > AUSTERE_HEAP_PAGES) {
        TraceBugCheck(("Given too many pages for XmInitMemory: got %d, should have max %d.\n",
                       nr_pages, AUSTERE_HEAP_PAGES));
        return;
    }
    heap_block_sizes[0] = nr_heap_pages | FREE_CHUNK;
    head_subheap = NULL;
}

/* -------------------------------------------------------------------- */
/* End of malloc implementation */

//
// lutoa    long unsigned to ascii
// litoa    long integer to ascii
//
// Arguments:
//  number  number to be converted to ascii.
//  str     output buffer (for the ascii version)
//  base    numeric base (must be less than 16 which is not checked)
//  bufsz   number of bytes in the output buffer, should include
//          enough space for the trailing null.
//
// Return Value:
//          Returns the number of characters written to the buffer not
//          including the terminating null.  Equivalent of calling
//          strlen on the output buffer after execution.
//
// Note: These routines are static and are never called with less than one
// byte to store data in.  We return length so there is no need to null
// terminate the string (the caller will take care of terminating the final
// string).
//

static size_t
lutoa(
    unsigned long number,
    char *str,
    int base,
    size_t bufsz
)
{
    static char numbers[] = "0123456789ABCDEF";
    LONG i = 0;
    ULONG j = 0;
    CHAR buf[32];

    do{
        buf[i++] = numbers[number % base];
    } while ((number /= base ) > 0);

    while ((i > 0) && bufsz--) {
        str[j++] = buf[--i];
    }

    return j;
}

/* Surprise!  Windows 2003 drivers can't do proper division on 64 bit
   integers when loaded on windows 2000 because _aulldvrm is missing.
   They can do division by a constant, though, which is all we
   need. */
static size_t
lutoaX(
    unsigned long long number,
    char *str,
    size_t bufsz
)
{
    static char numbers[] = "0123456789ABCDEF";
    LONG i = 0;
    ULONG j = 0;
    CHAR buf[32];

    do{
        buf[i++] = numbers[number % 16];
    } while ((number /= 16 ) > 0);

    while ((i > 0) && bufsz--) {
        str[j++] = buf[--i];
    }

    return j;
}

static size_t
litoa(
    long number,
    char *str,
    int base,
    size_t bufsz
)
{
    static char numbers[] = "0123456789ABCDEF";
    LONG i = 0;
    ULONG j = 0;
    BOOLEAN negative = FALSE;
    CHAR buf[32];

    negative = (BOOLEAN)(number < 0);

    if (number < 0) {
        negative = TRUE;
        number = -number;
    }

    do {
        buf[i++] = numbers[number % base];
    } while ((number /= base ) > 0);

    if (negative)
        buf[i++] = '-';

    while ((i > 0) && bufsz--) {
        str[j++] = buf[--i];
    }

    return j;
}

static size_t
_Xmvsnprintf(char* s, size_t bufsz, const char* fmt, va_list stack)
{
    ULONG_PTR narg;
    char  *sarg;
    size_t il;
    size_t n;
    unsigned long long ull;

    if (!bufsz)
    {
       return 0;
    }
   
    // subtract out space for the trailing null.
    n = bufsz - 1;

    for (; *fmt && (n > 0); ++fmt) {
        if (*fmt != '%') {
            *s++ = *fmt;
            n--;
            continue;
        }

        fmt++;

        if (*fmt == '\0') {
            // Don't trip on malformed format string ending in '%'.
            break;
        }

        /* Just strip any field lengths out */
        while (*fmt >= '0' && *fmt <= '9') 
            fmt++;

        if (*fmt == 'l') {
            /* We always use longs, so just ignore this. */
            fmt++;

            /* If we want longlongs, then tough */
            if (*fmt == 'l')
                fmt++;
        }

        switch(*fmt) {
            case 'd':
                narg = va_arg(stack, ULONG);
                il =litoa((int)narg, s, 10, n);
                break;
            case 'u':
                narg = va_arg(stack, ULONG);
                il =lutoa((unsigned)narg, s, 10, n);
                break;
            case 'x':
                narg = va_arg(stack, ULONG);
                il =lutoa((unsigned)narg, s, 16, n);
                break;
            case 'p':
                narg = va_arg(stack, ULONG_PTR);
                il = lutoaX(narg, s, n);
                break;
            case 'I':
                /* Hack: we need %I64x to generate xenbus watch
                 * tokens. */
                if (fmt[1] == '6' &&
                    fmt[2] == '4' &&
                    fmt[3] == 'x') {
                    ull = va_arg(stack, unsigned long long);
                    il = lutoaX(ull, s, n);
                    fmt += 3;
                } else {
                    il = 0;
                }
                break;
            case 's':
                sarg = va_arg(stack, char *);
                if (sarg == NULL)
                    sarg = "(null)";
                il = strlen(sarg);
                if (il > n)
                {
                    il = n;
                }
                memcpy(s, sarg, il);
                break;
            default:
                il = 0;
                break;
        }
        s += il;
        n -= il;
    }

    *s = 0;

    va_end(stack);

    if (n == 0) {
        /* Ran out of space in the buffer. */
        return (int)bufsz;
    }

    return (int)(bufsz - n) - 1;
}

size_t
Xmvsnprintf(char *buf, size_t size, const char *fmt,
            va_list args)
{
    if (AustereMode)
    {
        return _Xmvsnprintf(buf, size, fmt, args);
    }
    else
    {
        NTSTATUS status;

        status = RtlStringCbVPrintfA(buf, size, fmt, args);

        if (NT_SUCCESS(status))
        {
            return strlen(buf);
        }

        if (status == STATUS_BUFFER_OVERFLOW)
        {
            return (int)size;
        }

        return 0;
    }
}

size_t
Xmsnprintf(char *buf, size_t size, const char *fmt, ...)
{
    va_list args;
    size_t done;

    va_start(args, fmt);
    done = Xmvsnprintf(buf, size, fmt, args);
    va_end(args);
    return done;
}

char *
Xmvasprintf(const char *fmt, va_list args)
{
    char *work;
    size_t work_size;
    size_t r;

    work_size = 32;
    while (1) {
        work = XmAllocateMemory(work_size);
        if (!work)
            return work;
        r = Xmvsnprintf(work, work_size, fmt, args);
        if (r == 0) {
            XmFreeMemory(work);
            return NULL;
        }
        if (r < work_size) {
            return work;
        }
        XmFreeMemory(work);
        work_size *= 2;
    }
}

char *
Xmasprintf(const char *fmt, ...)
{
    va_list args;
    char *work;

    va_start(args, fmt);
    work = Xmvasprintf(fmt, args);
    va_end(args);
    return work;
}

ULONG GetOperatingMode(VOID)
{
    return _OperatingMode;
}

VOID SetOperatingMode(ULONG x)
{
    _OperatingMode = x;
}
