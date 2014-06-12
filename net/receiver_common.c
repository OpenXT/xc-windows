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

#ifndef NDIS60_MINIPORT
#pragma warning( push, 3 )

#include "precomp.h"
#include "stdlib.h"
#include "scsiboot.h"
#include "ntstrsafe.h"

#pragma warning( pop )

#else /* NDIS60_MINIPORT */
#include "common.h"
#endif /* NDIS60_MINIPORT */

#include "..\..\xenutil\gnttab.h"

static VOID ReceiverCommonReturnRfd(PRECEIVER_COMMON RecvCommon,
                                    PMP_RFD pMpRfd,
                                    uint16_t id);
static PMP_RFD ReceiverCommonAllocateRfd(PRECEIVER_COMMON RecvCommon);
static void ReceiverCommonReleaseRfd(PMP_RFD rfd, PRECEIVER_COMMON RecvCommon,
                                     BOOLEAN toCache);

#define INVALID_RX_SHADOW_ID ((uint16_t)0x7fff)

static RX_SHADOW *
ReceiverCommonGetShadow(PRECEIVER_COMMON RecvCommon, uint16_t id)
{
    XM_ASSERT3U(id, <, MAX_RX_FRAGS);
    return &(RecvCommon->Shadows[id]);
}

static uint16_t
ReceiverCommonAllocateShadow(PRECEIVER_COMMON RecvCommon)
{
    uint16_t id;
    RX_SHADOW *shadow;

    if (RecvCommon->NrFreeIds == 0)
        return INVALID_RX_SHADOW_ID;

    RecvCommon->NrFreeIds--;

    id = RecvCommon->NextFreeId;
    XM_ASSERT(id != INVALID_RX_SHADOW_ID);

    shadow = ReceiverCommonGetShadow(RecvCommon, id);
    XM_ASSERT(!shadow->InUse);
    shadow->InUse = TRUE;

    XM_ASSERT3P(shadow->Rfd, ==, NULL);

    XM_ASSERT(RecvCommon->NrFreeIds == 0 ||
              shadow->Next != INVALID_RX_SHADOW_ID);
    RecvCommon->NextFreeId = shadow->Next;
    shadow->Next = INVALID_RX_SHADOW_ID;

    return id;
}
    
static VOID   
__ReceiverCommonFreeShadow(PRECEIVER_COMMON RecvCommon, uint16_t id, BOOLEAN check)
{
    RX_SHADOW *shadow;

    shadow = ReceiverCommonGetShadow(RecvCommon, id);
    XM_ASSERT(!check || shadow->InUse);
    shadow->InUse = FALSE;

    XM_ASSERT3P(shadow->Rfd, ==, NULL);

    XM_ASSERT(!check || shadow->Next == INVALID_RX_SHADOW_ID);
    shadow->Next = RecvCommon->NextFreeId;
    RecvCommon->NextFreeId = id;
    if (RecvCommon->NrFreeIds < MAX_RX_FRAGS)
        RecvCommon->NrFreeIds++;
}

#define ReceiverCommonFreeShadow(_RecvCommon, _id) \
        __ReceiverCommonFreeShadow((_RecvCommon), (_id), TRUE)

NTSTATUS
ReceiverCommonInitialize(PRECEIVER_COMMON RecvCommon, PADAPTER Adapter)
{
    PFN_NUMBER pfn;

    TraceDebug (("Init Rx\n"));

    RecvCommon->Adapter = Adapter;

    NdisAllocateSpinLock(&RecvCommon->Lock);

    RecvCommon->SharedRing = XmAllocateZeroedMemory(PAGE_SIZE);
    if (RecvCommon->SharedRing == NULL)
        goto no_memory;
    SHARED_RING_INIT(RecvCommon->SharedRing);
    FRONT_RING_INIT(&RecvCommon->Ring, RecvCommon->SharedRing, PAGE_SIZE);
    pfn = (PFN_NUMBER)(MmGetPhysicalAddress(RecvCommon->SharedRing).QuadPart >> 12);
    RecvCommon->RingGrantRef =
        GnttabGrantForeignAccess(Adapter->BackendDomid,
                                 (ULONG_PTR)pfn,
                                 GRANT_MODE_RW);
    if (is_null_GRANT_REF(RecvCommon->RingGrantRef))
        goto no_memory;
    return STATUS_SUCCESS;

no_memory:
    ReceiverCommonCleanup(RecvCommon);
    return STATUS_INSUFFICIENT_RESOURCES;
}

VOID
ReceiverCommonCleanup(PRECEIVER_COMMON RecvCommon)
{
#ifdef NDIS60_MINIPORT
    NdisFreeSpinLock(&Receiver->Lock);
#endif

    if (!is_null_GRANT_REF(RecvCommon->RingGrantRef)) {
        (VOID) GnttabEndForeignAccess(RecvCommon->RingGrantRef);
        RecvCommon->RingGrantRef = null_GRANT_REF();
    }
    XmFreeMemory(RecvCommon->SharedRing);
    RecvCommon->SharedRing = NULL;

}

NDIS_STATUS
ReceiverCommonInitializeBuffers(PRECEIVER_COMMON RecvCommon)
{
    uint16_t i;

    /* We can't cope with running out of grefs while pushing an RFD
       onto the ring, so pre-allocate enough to be sure that we never
       will. */
    RecvCommon->GrantCache = GnttabAllocCache(NET_RX_RING_SIZE);
    if (!RecvCommon->GrantCache)
        return NDIS_STATUS_RESOURCES;

    RtlZeroMemory(RecvCommon->Shadows, sizeof (RecvCommon->Shadows));

    RecvCommon->NextFreeId = INVALID_RX_SHADOW_ID;
    RecvCommon->NrFreeIds = 0;
    for (i = 0; i < MAX_RX_FRAGS; i++)
        __ReceiverCommonFreeShadow(RecvCommon, i, FALSE);

    XM_ASSERT3U(RecvCommon->NrFreeIds, ==, MAX_RX_FRAGS);

    RecvCommon->PendingRfds = 0;

    NdisAcquireSpinLock(&RecvCommon->Lock);
    (VOID) ReceiverCommonReplenishRxRing(RecvCommon);

    XM_ASSERT3U(RecvCommon->Ring.sring->req_prod.__idx, ==, RecvCommon->PendingRfds);

    TraceInfo(("%d RFDs.\n", RecvCommon->PendingRfds));
    NdisReleaseSpinLock(&RecvCommon->Lock);

    return NDIS_STATUS_SUCCESS;
}

/* The backend just sent us an RFD with id @id.  Find the RFD, revoke
   the grant reference, and add the id to the freelist.  Returns the
   RFD. */
static PMP_RFD
ReceiverCommonReceiveRfd(PRECEIVER_COMMON RecvCommon, uint16_t id)
{
    RX_SHADOW *shadow;
    PMP_RFD rfd;
    NTSTATUS grant_status;

    XM_ASSERT3U(id, <, MAX_RX_FRAGS);

    shadow = ReceiverCommonGetShadow(RecvCommon, id);
    rfd = shadow->Rfd;

    shadow->Rfd = NULL;
    ReceiverCommonFreeShadow(RecvCommon, id);

    XM_ASSERT(rfd != NULL);
    grant_status = GnttabEndForeignAccessCache(rfd->Gref,
                                               RecvCommon->GrantCache);
    XM_ASSERT(NT_SUCCESS(grant_status));
    rfd->Gref = null_GRANT_REF();

    RecvCommon->PendingRfds--;
    return rfd;
}

void
ReceiverCommonCleanupBuffers(PRECEIVER_COMMON RecvCommon)
{
    uint16_t i;

    /* Tear down all RFDs ... */
    for (i = 0; i < MAX_RX_FRAGS; i++) {
        RX_SHADOW *shadow;

        shadow = ReceiverCommonGetShadow(RecvCommon, i);
        if (shadow->InUse) {
            PMP_RFD rfd;

            rfd = ReceiverCommonReceiveRfd(RecvCommon, i);

            ReceiverCommonReleaseRfd(rfd, RecvCommon, FALSE);
        }
    }
    XM_ASSERT3U(RecvCommon->PendingRfds, ==, 0);
    XM_ASSERT3U(RecvCommon->NrFreeIds, ==, MAX_RX_FRAGS);

    /* ... including cached ones. */
    while (RecvCommon->NumCachedRfds != 0) {
        PMP_RFD rfd;

        XM_ASSERT(RecvCommon->RfdCacheHead != NULL);

        rfd = CONTAINING_RECORD(RecvCommon->RfdCacheHead, MP_RFD, Mdl);
        RecvCommon->RfdCacheHead = rfd->Mdl.Next;
        RecvCommon->NumCachedRfds--;

        ReceiverCommonReleaseRfd(rfd, RecvCommon, FALSE);
    }
    XM_ASSERT3U(RecvCommon->CurrNumRfd, ==, 0);

    if (RecvCommon->GrantCache != NULL)
        GnttabFreeCache(RecvCommon->GrantCache);

    RecvCommon->GrantCache = NULL;
}

static void
ReceiverCommonReleaseRfd(PMP_RFD rfd, PRECEIVER_COMMON RecvCommon,
                         BOOLEAN toCache)
{
    /* Reset the MDL fields */
    XM_ASSERT3P(rfd->Mdl.StartVa, ==, rfd->ReceiveBufferVirt);
    rfd->Mdl.MappedSystemVa = rfd->ReceiveBufferVirt;
    rfd->Mdl.ByteOffset = 0;
    rfd->Mdl.ByteCount = 0;

    XM_ASSERT(is_null_GRANT_REF(rfd->Gref));

    /* Only put the RFD back in the cache if:

       a) It's likely to be useful again soon, and
       b) We don't have too many cached RFDs already.

       64 is pretty arbitrary, but looks plausible.
    */
    if (toCache && RecvCommon->NumCachedRfds < 64) {
        XM_ASSERT(EQUIV(RecvCommon->RfdCacheHead == NULL,
                        RecvCommon->NumCachedRfds == 0));

        RecvCommon->NumCachedRfds++;
        rfd->Mdl.Next = RecvCommon->RfdCacheHead;
        RecvCommon->RfdCacheHead = &rfd->Mdl;
        return;
    }

    XmFreeMemory(rfd->ReceiveBufferVirt);
    XmFreeMemory(rfd);

    RecvCommon->CurrNumRfd--;
}

static PMP_RFD
ReceiverCommonAllocateRfd(PRECEIVER_COMMON RecvCommon)
{
    PMP_RFD rfd;
    PMDL mdl;

    if (RecvCommon->RfdCacheHead) {
        rfd = CONTAINING_RECORD(RecvCommon->RfdCacheHead, MP_RFD, Mdl);
        RecvCommon->RfdCacheHead = rfd->Mdl.Next;
        RecvCommon->NumCachedRfds--;

        XM_ASSERT(EQUIV(RecvCommon->RfdCacheHead == NULL,
                        RecvCommon->NumCachedRfds == 0));
        return rfd;
    }

    rfd = XmAllocateZeroedMemory(sizeof(*rfd));
    if (!rfd) {
        TraceError(("Failed to allocate RFD\n"));
        return NULL;
    }
    rfd->ReceiveBufferVirt = XmAllocateMemory(PAGE_SIZE);
    if (rfd->ReceiveBufferVirt == NULL) {
        TraceError (("Failed to allocate packet buf.\n"));
        goto err;
    }
    rfd->ReceiveBufferPhys = MmGetPhysicalAddress(rfd->ReceiveBufferVirt);

    mdl = &rfd->Mdl;
    mdl->Next = NULL;
    mdl->Size = sizeof(*mdl) + sizeof(PFN_NUMBER);
    mdl->MdlFlags = (MDL_MAPPED_TO_SYSTEM_VA | MDL_PAGES_LOCKED |
                     MDL_SOURCE_IS_NONPAGED_POOL);
    mdl->Process = NULL;
    mdl->MappedSystemVa = rfd->ReceiveBufferVirt;
    mdl->StartVa = rfd->ReceiveBufferVirt;
    mdl->ByteCount = 0;
    mdl->ByteOffset = 0;

    XM_ASSERT3P(&rfd->MdlPfn, ==, (PPFN_NUMBER)(mdl+1));
    rfd->MdlPfn = (PFN_NUMBER)(rfd->ReceiveBufferPhys.QuadPart / PAGE_SIZE);

    RecvCommon->CurrNumRfd++;

    RecvCommon->NumRfdAllocations++;

    return rfd;

err:
    ReceiverCommonReleaseRfd(rfd, RecvCommon, FALSE);
    return NULL;
}

static VOID
ReceiverCommonReturnRfd(
    IN  PRECEIVER_COMMON RecvCommon,
    IN  PMP_RFD rfd,
    IN  uint16_t id
)
/*++
Routine Description:

    Recycle a RFD and put it back onto the receive list 
    Assumption: Rcv spinlock has been acquired 

Arguments:

    Adapter     Pointer to our adapter
    pMpRfd      Pointer to the RFD 

Return Value:

    None
    
--*/
{
    PADAPTER Adapter = RecvCommon->Adapter;
    RING_IDX req_prod;
    netif_rx_request_t *req;
    PFN_NUMBER pfn;

    XM_ASSERT(is_null_GRANT_REF(rfd->Gref));

    pfn = (PFN_NUMBER)(rfd->ReceiveBufferPhys.QuadPart >> 12);
    rfd->Gref = GnttabGrantForeignAccessCache(Adapter->BackendDomid,
                                              pfn,
                                              GRANT_MODE_RW,
                                              RecvCommon->GrantCache);
    /* Because the grant cache is pre-populated with enough grefs
       that we never run out. */
    XM_ASSERT(!is_null_GRANT_REF(rfd->Gref));
    RecvCommon->PendingRfds++;

    req_prod = RecvCommon->Ring.req_prod_pvt;

    req = RING_GET_REQUEST(&RecvCommon->Ring, req_prod);
    req->gref = xen_GRANT_REF(rfd->Gref);
    req->id = id;

    RecvCommon->Ring.req_prod_pvt = RING_IDX_PLUS(req_prod, 1);
}

BOOLEAN
ReceiverCommonReplenishRxRing(PRECEIVER_COMMON RecvCommon)
{
    int notify;

    while (RecvCommon->NrFreeIds != 0) {
        uint16_t id;
        RX_SHADOW *shadow;
        PMP_RFD rfd;

        id = ReceiverCommonAllocateShadow(RecvCommon);
        shadow = ReceiverCommonGetShadow(RecvCommon, id);

        rfd = ReceiverCommonAllocateRfd(RecvCommon);
        if (rfd == NULL) {
            ReceiverCommonFreeShadow(RecvCommon, id);
            break;
        }

        shadow->Rfd = rfd;
        ReceiverCommonReturnRfd(RecvCommon, rfd, id);
    }

    if (__RING_IDX_DIFFERENCE(RecvCommon->Ring.req_prod_pvt,
                              RecvCommon->Ring.rsp_cons) >
        NET_RX_RING_SIZE)
        TraceWarning(("RX ring has overflowed producing requests: req_prod_pvt %d, rsp_prod %d, req_prod %d, rsp_cons %d\n",
                      RecvCommon->Ring.req_prod_pvt,
                      RecvCommon->Ring.sring->rsp_prod,
                      RecvCommon->Ring.sring->req_prod,
                      RecvCommon->Ring.rsp_cons));

    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&RecvCommon->Ring, notify);

    return (notify != 0) ? TRUE : FALSE;
}

void
ReceiverCommonRestartEarly(PRECEIVER_COMMON RecvCommon)
{
    uint16_t i;

    SHARED_RING_INIT(RecvCommon->SharedRing);
    FRONT_RING_INIT(&RecvCommon->Ring, RecvCommon->SharedRing, PAGE_SIZE);

    /* Free any pending receives */
    for (i = 0; i < MAX_RX_FRAGS; i++) {
        RX_SHADOW *shadow;

        shadow = ReceiverCommonGetShadow(RecvCommon, i);
        if (shadow->InUse) {
            PMP_RFD rfd;

            rfd = ReceiverCommonReceiveRfd(RecvCommon, i);

            ReceiverCommonReleaseRfd(rfd, RecvCommon, FALSE);
        }
    }
    XM_ASSERT3U(RecvCommon->PendingRfds, ==, 0);
    XM_ASSERT3U(RecvCommon->NrFreeIds, ==, MAX_RX_FRAGS);
}

void
ReceiverCommonRestartLate(PRECEIVER_COMMON RecvCommon)
{
    NdisAcquireSpinLock(&RecvCommon->Lock);
    (VOID) ReceiverCommonReplenishRxRing(RecvCommon);
    NdisReleaseSpinLock(&RecvCommon->Lock);
}

/* Pull a packet off of the ring and build the RFD chain.  We always
   pull out a full packet, even if we hit an error. */
NDIS_STATUS
ReceiverCommonReceiveRfdChain(PRECEIVER Receiver, uint16_t *Flags,
                              PMP_RFD *PrefixRfd, PMP_RFD *HeadRfd,
                              PULONG TotOctets, PULONG TotFrags)
{
    PMDL headMdl;
    MDL **ppPrevMdl;
    PMP_RFD currRfd;
    netif_rx_response_t* response;
    ULONG totOctets;
    ULONG totFrags;
    LONG status;

    headMdl = NULL;
    ppPrevMdl = &headMdl;

    *Flags = 0;
    *PrefixRfd = NULL;
    totOctets = 0;
    totFrags = 0;
    status = 0;

    do {
        response = RING_GET_RESPONSE(&Receiver->Common.Ring, 
                                     Receiver->Common.Ring.rsp_cons);

        if (response->status < 0 && status >= 0)
            status = response->status;

        currRfd = ReceiverCommonReceiveRfd(&Receiver->Common, response->id);

        if (response->flags & NETRXF_gso_prefix) {
            XM_ASSERT(response->flags & NETRXF_more_data);

            Receiver->Common.Gso++;

            *Flags |= response->flags;

            currRfd->Mdl.ByteOffset = 0;
            currRfd->Mdl.MappedSystemVa = currRfd->Mdl.StartVa;
            currRfd->Mdl.ByteCount = 0;
            currRfd->Mdl.Next = NULL;
            currRfd->GsoSize = response->offset;
            *PrefixRfd = currRfd;

            goto loop;
        }

        Receiver->Common.Fragments++;

        *Flags |= response->flags;

        currRfd->Mdl.ByteOffset = response->offset;
        currRfd->Mdl.MappedSystemVa = (PUCHAR)currRfd->Mdl.StartVa + response->offset;
        currRfd->Mdl.ByteCount = response->status;
        totOctets += response->status;
        totFrags++;
        *ppPrevMdl = &currRfd->Mdl;
        ppPrevMdl = &currRfd->Mdl.Next;

        XM_ASSERT3U((response->flags & ~(NETRXF_more_data|NETRXF_csum_blank|NETRXF_data_validated)), ==, 0);

loop:
        Receiver->Common.Ring.rsp_cons =
            RING_IDX_PLUS(Receiver->Common.Ring.rsp_cons, 1);
    } while (response->flags & NETRXF_more_data);
    *ppPrevMdl = NULL;

    *HeadRfd = CONTAINING_RECORD(headMdl, MP_RFD, Mdl);
    *TotOctets = totOctets;
    *TotFrags = totFrags;

    if (status < 0)
        return NDIS_STATUS_FAILURE;
    else
        return NDIS_STATUS_SUCCESS;
}

/* Walk an MDL chain and release it.  The MDLs must be the ones
   embedded in MP_RFD structures. */
VOID
ReceiverCommonReleaseMdlChain(PRECEIVER_COMMON RecvCommon, PMDL HeadMdl)
{
    PMDL mdl;
    PMDL nextMdl;
    PMP_RFD rfd;

    XM_ASSERT(RecvCommon != NULL);

    for (mdl = HeadMdl; mdl != NULL; mdl = nextMdl) {
        nextMdl = mdl->Next;
        rfd = CONTAINING_RECORD(mdl, MP_RFD, Mdl);
        ReceiverCommonReleaseRfd(rfd, RecvCommon, TRUE);
    }
}

VOID
ReceiverCommonReleaseRfdChain(PRECEIVER_COMMON RecvCommon, PMP_RFD HeadRfd)
{
    XM_ASSERT(RecvCommon != NULL);

    if (HeadRfd != NULL)
        ReceiverCommonReleaseMdlChain(RecvCommon, &HeadRfd->Mdl);
}

VOID
ReceiverCommonDebugDump(PRECEIVER_COMMON RecvCommon)
{
    TraceInternal(("RXc: %I64d frames, %d GSO, %d frags.\n",
                   RecvCommon->Frames,
                   RecvCommon->Gso,
                   RecvCommon->Fragments));
    TraceInternal(("RXc: shared ring at %p\n", RecvCommon->SharedRing));
    if (RecvCommon->Ring.sring != NULL) 
        TraceInternal(("RXc ring: req_prod %x (pvt %x), rsp_prod %x, rsp_cons %x, rsp_event %x\n",
                       RecvCommon->Ring.sring->req_prod,
                       RecvCommon->Ring.req_prod_pvt,
                       RecvCommon->Ring.sring->rsp_prod,
                       RecvCommon->Ring.rsp_cons,
                       RecvCommon->Ring.sring->rsp_event));
    TraceInternal(("RXc: %d cached RFds, %d current rfds, %d rfds allocated\n",
                   RecvCommon->NumCachedRfds,
                   RecvCommon->CurrNumRfd,
                   RecvCommon->NumRfdAllocations));
}
