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

#include "ntddk.h"
#include "xsapi.h"
#include "nbl_hash.h"

#define NBL_LOG_SIZE 32
#define NBL_NR_HASH_ENTRIES 512
#define NBL_MAX_HASH_DEPTH 16

struct nbl_hash_log_entry {
    ULONG_PTR params[4];
};

struct nbl_hash_entry {
    struct nbl_hash_entry *next;

    /* Deliberately not a PNET_BUFFER_LIST, because it might have been
     * freed and we don't want anyone dereferencing it */
    ULONG_PTR nbl_addr;

    unsigned log_ptr;
    struct nbl_hash_log_entry log[NBL_LOG_SIZE];
};

static struct irqsafe_lock
nbl_lock;
static struct nbl_hash_entry *
nbl_hash[NBL_NR_HASH_ENTRIES];

static unsigned
hash_fn(ULONG_PTR base)
{
    unsigned acc;

    acc = 0;
    base /= 32;
    while (base != 0) {
        acc ^= base % NBL_NR_HASH_ENTRIES;
        base /= NBL_NR_HASH_ENTRIES;
    }
    return acc;
}

#if ENABLE_NBL_LOG
void
_nbl_log(ULONG_PTR ptr, const ULONG_PTR *params, unsigned nr_params)
{
    const unsigned h = hash_fn(ptr);
    struct nbl_hash_entry *nhe, **pprev, *new_nhe, *tmp_nhe;
    KIRQL irql;
    unsigned depth;
    struct nbl_hash_log_entry *nhle;

    XM_ASSERT(nr_params <= 4);

    irql = acquire_irqsafe_lock(&nbl_lock);
    pprev = &nbl_hash[h];
    nhe = *pprev;
    depth = 0;
    while (nhe && nhe->nbl_addr != ptr) {
        pprev = &nhe->next;
        nhe = *pprev;
        depth++;
    }
    if (nhe) {
        /* Pull-to-front list */
        *pprev = nhe->next;
        nhe->next = nbl_hash[h];
        nbl_hash[h] = nhe;
    } else {
        release_irqsafe_lock(&nbl_lock, irql);

        new_nhe = XmAllocateZeroedMemory(sizeof(*nhe));
        XM_ASSERT(new_nhe != NULL);
        new_nhe->nbl_addr = ptr;

        irql = acquire_irqsafe_lock(&nbl_lock);
        new_nhe->next = nbl_hash[h];
        nbl_hash[h] = new_nhe;

        nhe = NULL;
        if (depth >= NBL_MAX_HASH_DEPTH) {
            pprev = &new_nhe->next;
            nhe = *pprev;
            depth = 1;
            while (nhe && depth < NBL_MAX_HASH_DEPTH) {
                pprev = &nhe->next;
                nhe = *pprev;
                depth++;
            }
            XM_ASSERT(nhe != NULL);
            *pprev = NULL;

            release_irqsafe_lock(&nbl_lock, irql);
            while (nhe) {
                tmp_nhe = nhe->next;
                XmFreeMemory(nhe);
                nhe = tmp_nhe;
            }
            irql = acquire_irqsafe_lock(&nbl_lock);
        }

        nhe = new_nhe;
    }

    nhle = &nhe->log[nhe->log_ptr++ % NBL_LOG_SIZE];
    memcpy(nhle->params, params, nr_params * sizeof(ULONG_PTR));
    memset(nhle->params + nr_params, 0,
           sizeof(nhle->params) - nr_params * sizeof(nhle->params[0]));
    release_irqsafe_lock(&nbl_lock, irql);
}
#endif

static void
nbl_hash_dump(void *ignore)
{
    NTSTATUS status;
    KIRQL irql;
    unsigned x;
    struct nbl_hash_entry *nhe;
    unsigned ptr;

    UNREFERENCED_PARAMETER(ignore);

    status = try_acquire_irqsafe_lock(&nbl_lock, &irql);
    if (!NT_SUCCESS(status)) {
        TraceError(("Cannot get NBL hash lock -> no hash dump\n"));
        return;
    }

    for (x = 0; x < NBL_NR_HASH_ENTRIES; x++) {
        for (nhe = nbl_hash[x]; nhe != NULL; nhe = nhe->next) {
            TraceInternal(("Log for %p:\n", nhe->nbl_addr));
            if (nhe->log_ptr < NBL_LOG_SIZE)
                ptr = 0;
            else
                ptr = nhe->log_ptr - NBL_LOG_SIZE;
            for (; ptr < nhe->log_ptr; ptr++)
                TraceInternal(("\t%x: %p %p %p %p\n",
                               ptr,
                               nhe->log[ptr % NBL_LOG_SIZE].params[0],
                               nhe->log[ptr % NBL_LOG_SIZE].params[1],
                               nhe->log[ptr % NBL_LOG_SIZE].params[2],
                               nhe->log[ptr % NBL_LOG_SIZE].params[3]));
        }
    }

    release_irqsafe_lock(&nbl_lock, irql);
}

static EVTCHN_DEBUG_CALLBACK
hash_cb;

static unsigned
nbl_hash_cntr;

/* Yes, this is racy.  No, I don't care. */
void
nbl_hash_init(void)
{
    if (ENABLE_NBL_LOG && nbl_hash_cntr++ == 0)
        hash_cb = EvtchnSetupDebugCallback(nbl_hash_dump, NULL);
}

void
nbl_hash_deinit(void)
{
    if (ENABLE_NBL_LOG && --nbl_hash_cntr == 0)
        EvtchnReleaseDebugCallback(hash_cb);
}

