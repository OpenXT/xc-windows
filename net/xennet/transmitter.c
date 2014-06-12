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

#pragma warning( push, 3 )
#include "precomp.h"
#include "scsiboot.h"
#include "netif.h"
#include "xennet_common.h"
#pragma warning( pop )

#define INVALID_SHADOW_IND (WrapTxId(0x7fff))

struct PacketOverlayTx {
    PNDIS_PACKET next; /* Linked list of packets queued for transmission */
    PNDIS_PACKET prev;
    unsigned __head_shadow:15;
    unsigned bounced:1;
    unsigned total_size:16;
};
#define PACKET_TX_OVERLAY(pkt) ((struct PacketOverlayTx *)&(pkt)->MiniportReservedEx[0])
 
CASSERT(sizeof(struct PacketOverlayTx) <= 3 * sizeof(PVOID));

static VOID TransmitScheduledPackets(PTRANSMITTER Transmitter,
                                     BOOLEAN from_dpc);
static VOID QueueFakeArp(PADAPTER Adapter);
static NDIS_STATUS CompletePacketBackend(PTRANSMITTER Transmitter,
                                         PNDIS_PACKET packet,
                                         uint16_t resp_status);
static void ReleaseTxShadows(PTRANSMITTER Transmitter,
                             PNDIS_PACKET packet);

static netif_tx_id_t
WrapTxId(uint16_t id)
{
    netif_tx_id_t work;
    /* We only have 15 bits available in the tx packet overlay */
    XM_ASSERT((id & 0x8000) == 0);
    work.__id = id;
    return work;
}

static uint16_t
UnwrapTxId(netif_tx_id_t id)
{
    return id.__id;
}

static struct tx_shadow *
TxShadowForId(PTRANSMITTER Transmitter, netif_tx_id_t id)
{
    return &Transmitter->tx_shadow[UnwrapTxId(id)];
}

static BOOLEAN
TxIndexValid(netif_tx_id_t ind)
{
    if (ind.__id < MAX_TX_FRAGS)
        return TRUE;
    else
        return FALSE;
}

static netif_tx_id_t
TxPacketHeadShadow(PNDIS_PACKET packet)
{
    return WrapTxId((uint16_t)PACKET_TX_OVERLAY(packet)->__head_shadow);
}

static void
TxPacketSetHeadShadow(PNDIS_PACKET packet, netif_tx_id_t id)
{
    PACKET_TX_OVERLAY(packet)->__head_shadow = UnwrapTxId(id);
}

NDIS_STATUS
TransmitterInitialize(PTRANSMITTER Transmitter, PADAPTER Adapter)
{
    uint16_t i;

    NdisAllocateSpinLock(&Transmitter->SendLock);
    Transmitter->Adapter = Adapter;
    for (i = 0; i < MAX_TX_FRAGS; i++) {
        Transmitter->tx_shadow[i].gref = null_GRANT_REF();
        Transmitter->tx_shadow[i].next = WrapTxId(i + 1);
    }
    Transmitter->tx_shadow[i-1].next = INVALID_SHADOW_IND;
    Transmitter->next_free_tx_id = WrapTxId(0);
    Transmitter->nr_free_tx_ids = MAX_TX_FRAGS;
    Transmitter->min_free_tx_ids = MAX_TX_FRAGS;

    Transmitter->tx_ring_shared = XmAllocateMemory(PAGE_SIZE);
    if (!Transmitter->tx_ring_shared)
        goto no_memory;
    SHARED_RING_INIT(Transmitter->tx_ring_shared);
    FRONT_RING_INIT(&Transmitter->tx_ring, Transmitter->tx_ring_shared,
                    PAGE_SIZE);

    Transmitter->bounce_buffer = XmAllocateMemory(65536);
    if (!Transmitter->bounce_buffer) {
        TraceError(("Failed to allocate bounce buffer!\n"));
        goto no_memory;
    }

    Transmitter->bounce_buffer_mdl =
        XmAllocateMemory(sizeof(MDL) +
                         sizeof(PFN_NUMBER) * (65536/PAGE_SIZE));
    if (!Transmitter->bounce_buffer_mdl) {
        TraceInfo(("Failed allocate bounce buffer MDL!\n"));
        goto no_memory;
    }
    memset(Transmitter->bounce_buffer_mdl, 0, sizeof(MDL));
    Transmitter->bounce_buffer_mdl->ByteOffset = 0;
    for (i = 0; i < 65536/PAGE_SIZE; i++) {
        MmGetMdlPfnArray(Transmitter->bounce_buffer_mdl)[i] =
            (PFN_NUMBER)(MmGetPhysicalAddress( (PVOID)((ULONG_PTR)Transmitter->bounce_buffer +
                                                       PAGE_SIZE * i) ).QuadPart >>
                         PAGE_SHIFT);
    }

    Transmitter->grant_cache = GnttabAllocCache(0);
    if (!Transmitter->grant_cache)
        goto no_memory;

    Transmitter->tx_ring_ref =
        GnttabGrantForeignAccess(Adapter->BackendDomid,
                                 (ULONG_PTR)(MmGetPhysicalAddress(Transmitter->tx_ring_shared).QuadPart >> 12),
                                 GRANT_MODE_RW);
    if (is_null_GRANT_REF(Transmitter->tx_ring_ref))
        goto no_memory;

    return NDIS_STATUS_SUCCESS;

no_memory:
    TransmitterCleanup(Transmitter);
    return NDIS_STATUS_RESOURCES;
}

void
TransmitterCleanup(PTRANSMITTER Transmitter)
{
    TraceVerbose(("Cleaning up the transmitter...\n"));

    if (!is_null_GRANT_REF(Transmitter->tx_ring_ref)) {
        (VOID) GnttabEndForeignAccess(Transmitter->tx_ring_ref);
        Transmitter->tx_ring_ref = null_GRANT_REF();
    }
    
    if (Transmitter->grant_cache != NULL)
        GnttabFreeCache(Transmitter->grant_cache);
    Transmitter->grant_cache = NULL;

    XmFreeMemory(Transmitter->bounce_buffer_mdl);
    Transmitter->bounce_buffer_mdl = NULL;

    XmFreeMemory(Transmitter->bounce_buffer);
    Transmitter->bounce_buffer = NULL;

    XmFreeMemory(Transmitter->tx_ring_shared);
    Transmitter->tx_ring_shared = NULL;
}

void
TransmitterWaitForIdle(PTRANSMITTER Transmitter)
{
    LARGE_INTEGER interval;

    interval.QuadPart = -100000; /* 100ms in units of 100ns */

    /* Wait for pending TX requests to complete. */
    NdisAcquireSpinLock(&Transmitter->SendLock);
    while (Transmitter->nTxInFlight) {
        TraceVerbose (("%d tx.\n", Transmitter->nTxInFlight));
        NdisReleaseSpinLock(&Transmitter->SendLock);
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        NdisAcquireSpinLock(&Transmitter->SendLock);
    }
    NdisReleaseSpinLock(&Transmitter->SendLock);
}

/* This cleanup routine is used during surprise removal. Any outstanding Tx packets
 * will keep a ref count on the device preventing it from being removed (i.e. it will
 * never be halted). This routine does not wait for the packets to be returned because
 * the backend is gone. Instead it just runs the entire outstanding Tx list and
 * completes them.
 */
void
TransmitterForceFreePackets(PTRANSMITTER Transmitter)
{
    PNDIS_PACKET packet;
    unsigned nr_drops;

    NdisAcquireSpinLock(&Transmitter->SendLock);
    Transmitter->Adapter->ring_disconnected = 0;

    nr_drops = 0;
    while (Transmitter->HeadTxPacket) {
        packet = Transmitter->HeadTxPacket;
        Transmitter->HeadTxPacket = PACKET_TX_OVERLAY(packet)->next;
        CompletePacketBackend(Transmitter, packet, NETIF_RSP_OKAY);
        ReleaseTxShadows(Transmitter, packet);

        NdisReleaseSpinLock(&Transmitter->SendLock);
        NdisMSendComplete(Transmitter->Adapter->AdapterHandle,
                          packet,
                          NDIS_STATUS_SUCCESS);
        NdisAcquireSpinLock(&Transmitter->SendLock);
        Transmitter->nTxInFlight--;
        nr_drops++;
    }

    if (nr_drops)
        TraceNotice(("Dropped %d packets on suprise removal of device (in-flight=%d).\n",
                    nr_drops, Transmitter->nTxInFlight));

    NdisReleaseSpinLock(&Transmitter->SendLock);
}

void
RestartTransmitterEarly(PTRANSMITTER Transmitter)
{
    PNDIS_PACKET last_on_ring;

    SHARED_RING_INIT(Transmitter->tx_ring_shared);
    FRONT_RING_INIT(&Transmitter->tx_ring, Transmitter->tx_ring_shared,
                    PAGE_SIZE);

    /* There may be some packets which were on the ring when we
     * suspended, but for which we're not quite sure whether they've
     * been transmitted yet.  We can either try to replay them, and
     * risk a dupe if they've already been transmitted, or drop them.
     * We choose the drop them, because that's slightly less likely to
     * trigger bugs in stupid applications.
     */
    Transmitter->HeadPacketForDrop = Transmitter->HeadTxPacket;
    Transmitter->HeadTxPacket = Transmitter->HeadUntransPacket;
    if (Transmitter->HeadUntransPacket) {
        last_on_ring = PACKET_TX_OVERLAY(Transmitter->HeadUntransPacket)->prev;
        PACKET_TX_OVERLAY(Transmitter->HeadUntransPacket)->prev = NULL;
    } else {
        XM_ASSERT3P(Transmitter->HeadUnprepPacket, ==, NULL);
        last_on_ring = Transmitter->TailTxPacket;
        Transmitter->TailTxPacket = NULL;
    }
    if (last_on_ring) {
        XM_ASSERT(Transmitter->HeadPacketForDrop != NULL);
        PACKET_TX_OVERLAY(last_on_ring)->next = NULL;
    } else {
        XM_ASSERT3P(Transmitter->HeadPacketForDrop, ==, NULL);
    }
}

static NDIS_STATUS
CompletePacketBackend(PTRANSMITTER Transmitter, PNDIS_PACKET packet,
                      uint16_t resp_status)
{
    NDIS_STATUS status;

    if (PACKET_TX_OVERLAY(packet)->bounced)
        Transmitter->bounce_buffer_in_use = 0;
    if (PACKET_TX_OVERLAY(packet)->total_size) {
        *(PULONG)&NDIS_PER_PACKET_INFO_FROM_PACKET(packet,
                                                   TcpLargeSendPacketInfo) = 
            PACKET_TX_OVERLAY(packet)->total_size;
    }
    switch (resp_status) {
    case NETIF_RSP_OKAY:
        Transmitter->Adapter->TxGood++;
        status = NDIS_STATUS_SUCCESS;
        break;
    case NETIF_RSP_ERROR:
        Transmitter->Adapter->TxError++;
        status = NDIS_STATUS_FAILURE;
        break;
    case NETIF_RSP_DROPPED:
        Transmitter->Adapter->TxDropped++;
        status = NDIS_STATUS_BUFFER_OVERFLOW;
        break;
    default:
        TraceError (("Bad status %d.\n", resp_status));
        status = NDIS_STATUS_FAILURE;
        break;
    }

    return status;
}

static void
ReleaseTxShadows(PTRANSMITTER Transmitter, PNDIS_PACKET packet)
{
    netif_tx_id_t id;
    netif_tx_id_t n;
    struct tx_shadow *shadow;

    id = TxPacketHeadShadow(packet);
    while (TxIndexValid(id)) {
        shadow = TxShadowForId(Transmitter, id);        
        if (!is_null_GRANT_REF(shadow->gref))
            GnttabEndForeignAccessCache(shadow->gref,
                                        Transmitter->grant_cache);
        shadow->gref = null_GRANT_REF();
        shadow->in_use = 0;
        shadow->packet = NULL;
        n = shadow->next;
        shadow->next = Transmitter->next_free_tx_id;
        Transmitter->next_free_tx_id = id;
        id = n;

        Transmitter->nr_free_tx_ids++;
    }
}

void
RestartTransmitterLate(PTRANSMITTER Transmitter)
{
    PNDIS_PACKET packet;
    unsigned nr_drops;

    NdisAcquireSpinLock(&Transmitter->SendLock);
    Transmitter->Adapter->ring_disconnected = 0;

    /* If we're not sure whether a packet has been transmitted yet,
       drop it. */
    nr_drops = 0;
    while (Transmitter->HeadPacketForDrop) {
        packet = Transmitter->HeadPacketForDrop;
        Transmitter->HeadPacketForDrop = PACKET_TX_OVERLAY(packet)->next;
        CompletePacketBackend(Transmitter, packet, NETIF_RSP_OKAY);
        ReleaseTxShadows(Transmitter, packet);

        NdisReleaseSpinLock(&Transmitter->SendLock);
        NdisMSendComplete(Transmitter->Adapter->AdapterHandle,
                          packet,
                          NDIS_STATUS_SUCCESS);
        NdisAcquireSpinLock(&Transmitter->SendLock);
        Transmitter->nTxInFlight--;
        nr_drops++;
    }

    if (nr_drops)
        TraceNotice(("Dropped %d packets on %s coming back from suspend/resume.\n",
                     nr_drops, Transmitter->Adapter->XenbusPrefix));

    /* Queue up three fake ARPs, since they can get lost and having
       several is harmless. */
    QueueFakeArp(Transmitter->Adapter);
    QueueFakeArp(Transmitter->Adapter);
    QueueFakeArp(Transmitter->Adapter);

    /* Kick the state machine to get it going again. */
    TransmitScheduledPackets(Transmitter, FALSE);

    NdisReleaseSpinLock(&Transmitter->SendLock);
}

/* Returns a currently-unused transmit id.  Must be called under the
   send lock.  Bugchecks if we run out of ids; the caller is expected
   to ensure that enough are available by looking at
   Adapter->Transmitter.nr_free_tx_ids. */
static netif_tx_id_t
AllocateTxId(PTRANSMITTER Transmitter)
{
    netif_tx_id_t res;
    struct tx_shadow *shadow;

    XM_ASSERT(Transmitter->nr_free_tx_ids != 0);
    res = Transmitter->next_free_tx_id;
    XM_ASSERT(TxIndexValid(res));
    shadow = TxShadowForId(Transmitter, res);
    XM_ASSERT(!shadow->in_use);
    shadow->in_use = 1;
    shadow->is_fake_arp = 0;
    shadow->is_extra = 0;
    Transmitter->next_free_tx_id = shadow->next;
    shadow->next = INVALID_SHADOW_IND;
    Transmitter->nr_free_tx_ids--;
    if (Transmitter->nr_free_tx_ids < Transmitter->min_free_tx_ids)
        Transmitter->min_free_tx_ids = Transmitter->nr_free_tx_ids;
    return res;
}


/* Prepare a packet assuming that its payload is in @pMdl */
/* Returns -1 if the ring's busy, or 0 on success. */
static int
PreparePacketMdl(PNDIS_PACKET packet, PTRANSMITTER Transmitter, PMDL pMdl,
                 UINT nrDescriptors, UINT totalLength)
{
    ULONG mss;
    unsigned extra;
    netif_tx_id_t id;
    struct tx_shadow *shadow = NULL;
    netif_tx_request_t *req = NULL;
    BOOLEAN firstFrag;
    unsigned descriptors_used = 0;

    XM_ASSERT(pMdl != NULL);

    mss =
        (ULONG)(ULONG_PTR)NDIS_PER_PACKET_INFO_FROM_PACKET(packet,
                                                           TcpLargeSendPacketInfo);
    if (mss != 0) {
        XM_ASSERT3U(mss, <, 65536);
        Transmitter->nLargeSends++;
        extra = 1;
    } else {
        extra = 0;
    }

    if (nrDescriptors + extra > Transmitter->nr_free_tx_ids) {
        /* Not enough TX IDs for this packet. */
        return -1;
    }

    firstFrag = TRUE;
    while (pMdl) {
        PPFN_NUMBER pfns = MmGetMdlPfnArray(pMdl);
        ULONG pfnInd;
        ULONG pageOff;
        ULONG bytesInMdl;

        bytesInMdl = MmGetMdlByteCount(pMdl);
        pageOff = MmGetMdlByteOffset(pMdl);
        pfnInd = 0;
        while (bytesInMdl != 0) {
            ULONG bytesInPage;

            bytesInPage = bytesInMdl;
            if (bytesInPage + pageOff > PAGE_SIZE)
                bytesInPage = PAGE_SIZE - pageOff;
            Transmitter->nTxFrags++;
            id = AllocateTxId(Transmitter);
            descriptors_used++;
            XM_ASSERT3U(descriptors_used, <=, nrDescriptors + extra);
            if (shadow)
                shadow->next = id;
            else
                TxPacketSetHeadShadow(packet, id);
            shadow = TxShadowForId(Transmitter, id);
            shadow->next = INVALID_SHADOW_IND;
            shadow->is_extra = 0;
            shadow->packet = packet;
            req = &shadow->req;
            req->id = id;
            XM_ASSERT(is_null_GRANT_REF(shadow->gref));
            shadow->gref =
                GnttabGrantForeignAccessCache(Transmitter->Adapter->BackendDomid,
                                              pfns[pfnInd],
                                              GRANT_MODE_RO,
                                              Transmitter->grant_cache);
            if (is_null_GRANT_REF(shadow->gref)) {
                TraceWarning (("Out of grant references?\n"));
                /* Hack: pass it through to the backend so that it
                   comes back as an error, and then handle the error
                   from the normal send completion path. */
            }
            req->gref = xen_GRANT_REF(shadow->gref);
            req->offset = (uint16_t)pageOff;
            req->flags = NETTXF_more_data;
            if (firstFrag) {
                req->size = (uint16_t)totalLength;
                if (Transmitter->tx_csum_tcp_offload ||
                    Transmitter->tx_csum_udp_offload) {
                    NDIS_TCP_IP_CHECKSUM_PACKET_INFO info;
                    /* Despite what the DDK documentation says, this
                       macro returns the value of the checksum info,
                       not a pointer to the value. */
                    info.Value =
                        (ULONG)(ULONG_PTR)NDIS_PER_PACKET_INFO_FROM_PACKET(packet,
                                                                           TcpIpChecksumPacketInfo);
                    if ( info.Transmit.NdisPacketChecksumV4 &&
                         ((info.Transmit.NdisPacketTcpChecksum &&
                           Transmitter->tx_csum_tcp_offload) ||
                          (info.Transmit.NdisPacketUdpChecksum &&
                           Transmitter->tx_csum_udp_offload)) ) {
                        /* There's an implicit assumption in the
                           xennet protocol that you'll never get a
                           packet which needs both UDP and TCP
                           checksums.  This seems safe. :) */
                        req->flags |= NETTXF_csum_blank;
                        Transmitter->nTxCsumOffload++;
                    }
                }

                if (extra) {
                    struct netif_extra_info *e;

                    shadow->next = AllocateTxId(Transmitter);
                    descriptors_used++;
                    shadow = TxShadowForId(Transmitter, shadow->next);
                    shadow->next = INVALID_SHADOW_IND;
                    shadow->is_extra = 1;
                    e = &shadow->extra;
                    req->flags |= NETTXF_extra_info | NETTXF_csum_blank;
                    e->type = XEN_NETIF_EXTRA_TYPE_GSO;
                    e->flags = 0;
                    e->u.gso.size = (uint16_t)mss;
                    e->u.gso.type = XEN_NETIF_GSO_TYPE_TCPV4;
                    e->u.gso.pad = 0;
                    e->u.gso.features = 0;
                }
            } else {
                req->size = (uint16_t)bytesInPage;
            }
            firstFrag = FALSE;

            pageOff = 0;
            bytesInMdl -= bytesInPage;
            pfnInd++;
        }
        pMdl = pMdl->Next;
    }

    XM_ASSERT(req != NULL);
    XM_ASSERT3U(descriptors_used, <=, nrDescriptors + extra);
    XM_ASSERT(descriptors_used > 0);

    /* Clear the more_data flag in the last request */
    req->flags &= ~NETTXF_more_data;

    TxShadowForId(Transmitter,
                  TxPacketHeadShadow(packet))->nr_reqs_outstanding_packet =
        (uint16_t)(descriptors_used - extra);
    if (mss)
        PACKET_TX_OVERLAY(packet)->total_size = totalLength;
    else
        PACKET_TX_OVERLAY(packet)->total_size = 0;

    return 0;
}

static int
LinearisePacket(PNDIS_PACKET packet, PVOID dest, ULONG dest_size)
{
    unsigned dest_off;
    PNDIS_BUFFER buffer;
    PVOID va;
    UINT buf_len;

    dest_off = 0;
    NdisQueryPacket(packet, NULL, NULL, &buffer, NULL);
    while (buffer) {
        NdisQueryBufferSafe(buffer,
                            &va,
                            &buf_len,
                            NormalPagePriority);
        if (!va)
            return -1;
        XM_ASSERT3U(buf_len + dest_off, <=, dest_size);
        memcpy((PVOID)((ULONG_PTR)dest+dest_off), va, buf_len);
        dest_off += buf_len;
        NdisGetNextBuffer(buffer, &buffer);
    }
    return dest_off;
}

/* Prepare a packet for transmission.  Handles allocating grant
   references and preparing the bounce buffer.  Called under the send
   lock, and the send lock is held when this returns, but the send
   lock can be dropped temporarily while this is running. */
/* Returns -1 if the ring's busy, 0 on success, or 1 if the packet
   needs to be linearised by the caller. */
static int
PreparePacketGrant(PNDIS_PACKET packet, PTRANSMITTER Transmitter)
{
    UINT nrDescriptors;
    UINT totalLength;
    PMDL pMdl;

    NdisQueryPacket(packet,
                    &nrDescriptors,
                    NULL,
                    &pMdl,
                    &totalLength);
    if (nrDescriptors > XENNET_MAX_FRAGS_PER_PACKET) {
        /* We're going to have to linearise the packet. */
        return 1;
    }

    PACKET_TX_OVERLAY(packet)->bounced = 0;
    return PreparePacketMdl(packet, Transmitter, pMdl, nrDescriptors,
                            totalLength);
}

/* Prepare the next packet from Transmitter->HeadUnprepPacket, and advance
   HeadUnprepPacket. */
/* TODO: Most of this can actually run without the send lock. */
static int
PreparePacket(PTRANSMITTER Transmitter, BOOLEAN from_dpc)
{
    PNDIS_PACKET packet = Transmitter->HeadUnprepPacket;
    int rc;

    if (TxIndexValid(TxPacketHeadShadow(packet))) {
        /* Already prepared.  Can happen when we're retrying stalled
           packets or when recovering from suspend/resume. */
        return 0;
    }
    rc = PreparePacketGrant(packet, Transmitter);
    switch (rc) {
    case 0:
        /* Success */
        Transmitter->HeadUnprepPacket = PACKET_TX_OVERLAY(packet)->next;
        return 0;
    case -1:
        /* Back off */
        return -1;
    case 1: {
        int totalLength;

        /* Packet has too many fragments.  Linearise it.  This is
         * rare. */

        /* ``Lock'' the bounce buffer. */
        if (Transmitter->bounce_buffer_in_use)
            return -1; /* This needs to be after the NotifyRemote
                          above. */
        Transmitter->bounce_buffer_in_use = 1;

        if (from_dpc) {
            NdisDprReleaseSpinLock(&Transmitter->SendLock);
        } else {
            NdisReleaseSpinLock(&Transmitter->SendLock);
        }
        totalLength = LinearisePacket(packet, Transmitter->bounce_buffer, 65536);
        if (from_dpc) {
            NdisDprAcquireSpinLock(&Transmitter->SendLock);
        } else {
            NdisAcquireSpinLock(&Transmitter->SendLock);
        }

        /* This is subtle.  We dropped the lock for a bit, so another
           vcpu could have got in and tried to prepare some more
           packets.  However, we know that they'll start at
           HeadUnpreparedPacket, which is us, and they'll fail,
           because we already have the bounce buffer lock.  This means
           that HeadUnpreparedPacket will still point at our packet
           when we reacquire the lock, and so everything is safe. */
        XM_ASSERT3P(packet, ==, Transmitter->HeadUnprepPacket);

        if (totalLength < 0) {
            /* Uh oh, failed to linearise. */
            TraceError(("Failed to linearise packet!\n"));
            Transmitter->bounce_buffer_in_use = 0;
            return -1;
        }

        PACKET_TX_OVERLAY(packet)->bounced = 1;
        Transmitter->bounce_buffer_mdl->ByteCount = totalLength;
        if (PreparePacketMdl(packet, Transmitter,
                             Transmitter->bounce_buffer_mdl,
                             (totalLength + PAGE_SIZE - 1) / PAGE_SIZE,
                             totalLength) < 0) {
            /* Not enough TX descriptors available at this time.
               Release the bounce buffer and try again later. */
            Transmitter->bounce_buffer_in_use = 0;
            return -1;
        } else {
            /* Packet is now fully prepared. */
            Transmitter->HeadUnprepPacket = PACKET_TX_OVERLAY(packet)->next;
            Transmitter->nBounced++;
            return 0;
        }
    }
    default:
        TraceBugCheck(("unexpected return from PreparePacketGrant: %d\n", rc));
        return 0;
    }
}

/* Take Transmitter->HeadUntransPacket and put it in the ring.  Returns 0
   on success or -1 on error.  Advances HeadUntransPacket on
   success.  Assumes the packet has already been prepared. */
static int
SubmitPacket(PTRANSMITTER Transmitter, RING_IDX cons)
{
    PADAPTER Adapter = Transmitter->Adapter;
    unsigned nr_slots;
    netif_tx_id_t shadow;
    struct tx_shadow *shad;
    netif_tx_request_t *req;
    netif_tx_id_t head_shadow;
    PNDIS_PACKET packet = Transmitter->HeadUntransPacket;

    UNREFERENCED_PARAMETER(cons);

    if (Adapter->ring_disconnected) {
        /* Can't submit at the moment */
        return -1;
    }

    head_shadow = TxPacketHeadShadow(packet);
    XM_ASSERT(TxIndexValid(head_shadow));

    /* Check that we have enough TX slots available on the ring. */
    nr_slots = 0;
    for (shadow = head_shadow;
         TxIndexValid(shadow);
         shadow = TxShadowForId(Transmitter, shadow)->next)
        nr_slots++;

    if (RING_PROD_SLOTS_AVAIL(&Transmitter->tx_ring) < nr_slots)
        return -1;

    Transmitter->HeadUntransPacket = PACKET_TX_OVERLAY(packet)->next;

    /* Looks good, transmit */
    Transmitter->nTxPackets++;
    for (shadow = head_shadow; TxIndexValid(shadow); shadow = shad->next) {
        shad = TxShadowForId(Transmitter, shadow);

        req = RING_GET_REQUEST(&Transmitter->tx_ring,
                               Transmitter->tx_ring.req_prod_pvt);
        *req = shad->req;
        Transmitter->tx_ring.req_prod_pvt =
            RING_IDX_PLUS(Transmitter->tx_ring.req_prod_pvt, 1);
    }

    TraceProfile(("%s(%s, %d)\n", __FUNCTION__, Adapter->XenbusPrefix, nr_slots)); 

    return 0;
}

/* Calculate the IP header checksum, since NDIS doesn't always bother.
 * We make various assumptions about where NDIS is going to put
 * fragment boundaries. */
static void
FixupIpCsum(PNDIS_PACKET packet)
{
    PNDIS_BUFFER pbuf;
    UINT bufLength;
    struct iphdr *iph;
    struct ethhdr *eh;
    unsigned hdr_len;
    NDIS_TCP_IP_CHECKSUM_PACKET_INFO info;
    ULONG mss;
    uint32_t acc;

    info.Value =
        (ULONG)(ULONG_PTR)NDIS_PER_PACKET_INFO_FROM_PACKET(packet,
                                                           TcpIpChecksumPacketInfo);
    mss =
        (ULONG)(ULONG_PTR)NDIS_PER_PACKET_INFO_FROM_PACKET(packet,
                                                           TcpLargeSendPacketInfo);

    if (mss == 0 &&
        !(info.Transmit.NdisPacketChecksumV4 &&
          info.Transmit.NdisPacketIpChecksum))
        return;

    NdisQueryPacket(packet, NULL, NULL, &pbuf, NULL);
    NdisQueryBufferSafe(pbuf, &eh, &bufLength, NormalPagePriority);
    if (!eh)
        return;

    XM_ASSERT3U(bufLength, >=, sizeof(*eh));
    XM_ASSERT3U(eh->proto, ==, TPID_IPV4);

    if (bufLength == sizeof(*eh)) {
        NdisGetNextBuffer(pbuf, &pbuf);
        NdisQueryBufferSafe(pbuf, &iph, &bufLength, NormalPagePriority);
    } else {
        iph = (struct iphdr *)(eh+1);
        bufLength -= sizeof(*eh);
    }
    if (!iph)
        return;

    if (bufLength < sizeof(*iph))
        return;

    hdr_len = (iph->len_version & 0x0f) << 2;
    if (bufLength > hdr_len)
        bufLength = hdr_len;

    iph->check = 0;
    acc = 0;
    for (;;) {
        acc = acc_ip_csum(iph, bufLength, acc);

        hdr_len -= bufLength;
        if (hdr_len == 0)
            break;

        NdisGetNextBuffer(pbuf, &pbuf);
        NdisQueryBufferSafe(pbuf, &iph, &bufLength, NormalPagePriority);
        if (!iph)
            return;

        if (bufLength > hdr_len)
            bufLength = hdr_len;
    }
    iph->check = ~fold_ip_csum(acc);
}

static void
FixupTcpCsum(PNDIS_PACKET packet)
{
    PNDIS_BUFFER pbuf;
    UINT bufLength;
    struct iphdr *iph;
    struct ethhdr *eh;
    struct tcphdr *th;
    struct tcp_pseudo_header tph;
    unsigned hdr_len;
    unsigned data_len;
    NDIS_TCP_IP_CHECKSUM_PACKET_INFO info;
    ULONG mss;
    uint32_t acc;
    uint16_t csum;

    info.Value =
        (ULONG)(ULONG_PTR)NDIS_PER_PACKET_INFO_FROM_PACKET(packet,
                                                           TcpIpChecksumPacketInfo);
    mss =
        (ULONG)(ULONG_PTR)NDIS_PER_PACKET_INFO_FROM_PACKET(packet,
                                                           TcpLargeSendPacketInfo);

    if (mss == 0 &&
        !(info.Transmit.NdisPacketChecksumV4 &&
          info.Transmit.NdisPacketTcpChecksum))
        return;

    NdisQueryPacket(packet, NULL, NULL, &pbuf, &data_len);
    NdisQueryBufferSafe(pbuf, &eh, &bufLength, NormalPagePriority);
    if (!eh)
        return;

    XM_ASSERT3U(eh->proto, ==, TPID_IPV4);

    XM_ASSERT3U(bufLength, >=, sizeof(*eh));
    if (bufLength == sizeof(*eh)) {
        NdisGetNextBuffer(pbuf, &pbuf);
        NdisQueryBufferSafe(pbuf, &iph, &bufLength, NormalPagePriority);
    } else {
        iph = (struct iphdr *)(eh+1);
        bufLength -= sizeof(*eh);
    }
    if (!iph)
        return;

    if (bufLength < sizeof(*iph))
        return;

    hdr_len = (iph->len_version & 0x0f) << 2;

    if (bufLength < hdr_len)
        return;
    if (bufLength == hdr_len) {
        NdisGetNextBuffer(pbuf, &pbuf);
        NdisQueryBufferSafe(pbuf, &th, &bufLength, NormalPagePriority);
    } else {
        th = (struct tcphdr *)((ULONG_PTR)iph + hdr_len);
        bufLength -= hdr_len;
    }
    if (!th)
        return;

    if (bufLength < sizeof(*th))
        return;

    tph.saddr = iph->src;
    tph.daddr = iph->dest;
    tph.mbz = 0;
    tph.ptcl = IPPROTO_TCP;
    tph.length = htons((uint16_t)(data_len - sizeof(struct ethhdr) - hdr_len));

    acc = acc_ip_csum(&tph, sizeof(tph), 0);
    csum = fold_ip_csum(acc);

    if (th->checksum != csum && mss == 0)
        TraceWarning(("bad pseudo header checksum in non-LSO packet: found %04x, expected %04x\n",
                      th->checksum,
                      csum));

    th->checksum = csum;
}


/* Add a packet to the end of the TX list.  Assumes the send lock is
   held and that the packet hasn't been prepared yet. */
static void
ScheduleTxPacket(PTRANSMITTER Transmitter, PNDIS_PACKET packet)
{

    /* We count queued packets as in flight since they're treated the
       same by adapter shutdown, which is the only consumer of this
       field. */
    Transmitter->nTxInFlight++;
    if (Transmitter->nTxInFlight > Transmitter->nTxInFlightMax)
        Transmitter->nTxInFlightMax = Transmitter->nTxInFlight;
    Transmitter->nQueuedPackets++;

    PACKET_TX_OVERLAY(packet)->prev = Transmitter->TailTxPacket;
    PACKET_TX_OVERLAY(packet)->next = NULL;
    TxPacketSetHeadShadow(packet, INVALID_SHADOW_IND);
    if (Transmitter->TailTxPacket) {
        PACKET_TX_OVERLAY(Transmitter->TailTxPacket)->next = packet;
    } else {
        Transmitter->HeadTxPacket = packet;
    }
    Transmitter->TailTxPacket = packet;
    if (!Transmitter->HeadUnprepPacket)
        Transmitter->HeadUnprepPacket = packet;
    if (!Transmitter->HeadUntransPacket)
        Transmitter->HeadUntransPacket = packet;
}

/* Walk the TX list, preparing packets and transferring them to the
   ring.  Assumes the send lock is held on entry, and holds it on
   exit, but can drop it while running. */
static VOID
TransmitScheduledPackets(PTRANSMITTER Transmitter, BOOLEAN from_dpc)
{
    PADAPTER Adapter = Transmitter->Adapter;
    int notify;

    /* First try to transmit any prepared packets which we haven't
       sent yet. */
    while (Transmitter->HeadUntransPacket != Transmitter->HeadUnprepPacket) {
        if (SubmitPacket(Transmitter, Transmitter->tx_ring.rsp_cons) < 0) {
            /* The ring is full.  Stop putting stuff on it. */
            goto end;
        }
        Transmitter->nQueuedPackets--;
    }

    /* Now deal with unprepared packets.  Note that PreparePacket can
       drop the send lock. */
    while (Transmitter->HeadUnprepPacket) {
        if (PreparePacket(Transmitter, from_dpc) < 0) {
            /* Can't prepare the packet at this time, probably
               collided over the bounce buffer.  There's not much
               point in trying subsequent packets at this time. */
            goto end;
        }
        while (Transmitter->HeadUntransPacket != Transmitter->HeadUnprepPacket) {
            if (SubmitPacket(Transmitter, Transmitter->tx_ring.rsp_cons) < 0) {
                /* The ring is full.  Stop. */
                goto end;
            }
            Transmitter->nQueuedPackets--;
        }
    }

end:
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&Transmitter->tx_ring, notify);

    TraceProfile(("%s(%s)%s\n", __FUNCTION__, Adapter->XenbusPrefix, (notify) ? "[NOTIFY]" : ""));

    if (notify) {
        EvtchnNotifyRemote(Transmitter->Adapter->evtchn);
        Transmitter->nTxEvents++;
    }
}

VOID
MPSendPackets(
    IN NDIS_HANDLE      MiniportAdapterContext,
    IN PPNDIS_PACKET    PacketArray,
    IN UINT             NumberOfPackets
    )
/*++

Routine Description:

    Send Packet Array handler. Either this or our SendPacket handler 
    is called based on which one is enabled in our Miniport 
    Characteristics.

Arguments:

    MiniportAdapterContext  Pointer to our adapter
    PacketArray             Set of packets to send
    NumberOfPackets         Self-explanatory.  Usually 1.

Return Value:

    None

--*/
{
    PADAPTER  Adapter = (PADAPTER)MiniportAdapterContext;
    PTRANSMITTER Transmitter = &Adapter->Transmitter;
    UINT    i;

    for (i = 0; i < NumberOfPackets; i++) {
        if (Transmitter->tx_csum_ip_offload)
            FixupIpCsum(PacketArray[i]);

        if (Transmitter->tx_csum_tcp_offload)
            FixupTcpCsum(PacketArray[i]);
    }

    NdisAcquireSpinLock(&Transmitter->SendLock);

    if (Adapter->Shutdown || Adapter->media_disconnect || Adapter->RemovalPending) {
        NDIS_STATUS status;
        /* Despite what the documentation may think, Windows will
           occasionally try to transmit on an interface after it's
           been MPHalt()ed.  This seems to be because receiving a TCP
           packet will cause it to immediately generate an ACK.  We
           can work around this by just releasing the packets from
           here without sending them over the ring.

           We avoid the obvious use-after-free provided Windows only
           does the stupid thing in response to received packets,
           because we know that the receiver is shut down early in
           MPHalt(). */
        if (Adapter->RemovalPending) {
            /* If blocked by PnP removal notification, should return this status */
            TraceWarning(("Transmitting %d packets during pending removal\n",
                          NumberOfPackets));
            status = NDIS_STATUS_NOT_ACCEPTED;
        }
        else if (Adapter->Shutdown) {
            TraceWarning(("Transmitting %d packets after adapter shutdown!\n",
                          NumberOfPackets));
            status = NDIS_STATUS_CLOSING;
        }         
        else {
            TraceWarning(("Transmitting %d packets with no link!\n",
                          NumberOfPackets));
            status = NDIS_STATUS_NO_CABLE;
        }
        Transmitter->Adapter->TxDropped += NumberOfPackets;
        NdisReleaseSpinLock(&Transmitter->SendLock);
        for (i = 0; i < NumberOfPackets; i++) {
            NdisMSendComplete(Transmitter->Adapter->AdapterHandle,
                              PacketArray[i],
                              status);
        }
        return;
    }

    Transmitter->nTxBatches++;

    for (i = 0; i < NumberOfPackets; i++)
        ScheduleTxPacket(Transmitter, PacketArray[i]);

    TransmitScheduledPackets(Transmitter, FALSE);

    if (Transmitter->nQueuedPackets > Transmitter->nQueuedPacketsMax)
        Transmitter->nQueuedPacketsMax = Transmitter->nQueuedPackets;

    NdisReleaseSpinLock(&Transmitter->SendLock);
    return;
}

NDIS_STATUS
MpHandleSendInterrupt(PTRANSMITTER Transmitter)
/*++
Routine Description:

    Interrupt handler for sending processing
    Re-claim the send resources, complete sends and get more to send from the send wait queue

    The caller must ensure that this is only run on one vcpu at a time
    for any given adapter, and is called at DISPATCH_LEVEL.

    Acquires and releases the send lock.

Arguments:

    Transmitter     Pointer to our transmitter block

Return Value:

    NDIS_STATUS_SUCCESS
    NDIS_STATUS_HARD_ERRORS
    NDIS_STATUS_PENDING

--*/
{
    RING_IDX        prod, cons;
    int             status;
    netif_tx_response_t *resp;
    netif_tx_id_t   id;
    int             delta;
    unsigned        x;
    PNDIS_PACKET    packet;
    struct tx_shadow *shadow;
    struct tx_shadow *head_shadow;

#define MAX_PENDING_COMPLETES 32
    PNDIS_PACKET    pendingCompletes[MAX_PENDING_COMPLETES];
    int             pendingStatuses[MAX_PENDING_COMPLETES];
    unsigned        nrPendingCompletes;

    if (!RING_HAS_UNCONSUMED_RESPONSES(&Transmitter->tx_ring))
        return NDIS_STATUS_SUCCESS;

    /* Note that we drop the lock from in the main loop */
    NdisDprAcquireSpinLock(&Transmitter->SendLock);

    nrPendingCompletes = 0;

 top:
    prod = Transmitter->tx_ring.sring->rsp_prod;

    /* Make sure no reads in the ring get reordered before the read of prod. */
    rmb();

    cons = Transmitter->tx_ring.rsp_cons;
    while (!RING_IDXS_EQ(cons, prod)) {
        resp = RING_GET_RESPONSE(&Transmitter->tx_ring, cons);

        if (resp->status == NETIF_RSP_NULL) {
            /* Not a real response (probably a TSO extra request), so
               no id field or anything like that.  Just skip it; we'll
               release the shadow when we complete the relevant
               packet. */
            cons = RING_IDX_PLUS(cons, 1);
            continue;
        }

        id = resp->id;
        XM_ASSERT(TxIndexValid(id));
        shadow = TxShadowForId(Transmitter, id);

        if (shadow->is_fake_arp) {
            GnttabEndForeignAccessCache(shadow->gref,
                                        Transmitter->grant_cache);
            shadow->gref = null_GRANT_REF();
            XmFreeMemory(shadow->fake_arp_buf);
            shadow->fake_arp_buf = NULL;
            shadow->in_use = 0;
            shadow->next = Transmitter->next_free_tx_id;
            Transmitter->next_free_tx_id = id;
            Transmitter->nr_free_tx_ids++;
            cons = RING_IDX_PLUS(cons, 1);
            continue;
        }

        if (shadow->is_extra) {
            head_shadow = NULL;
            packet = NULL;
        } else {
            packet = shadow->packet;
            head_shadow = TxShadowForId(Transmitter,
                                        TxPacketHeadShadow(packet));
            XM_ASSERT(head_shadow->nr_reqs_outstanding_packet != 0);
            head_shadow->nr_reqs_outstanding_packet--;
        }
        if (head_shadow && head_shadow->nr_reqs_outstanding_packet == 0) {
            if (nrPendingCompletes == MAX_PENDING_COMPLETES) {
                /* We can safely drop the lock here, since it's only
                   really protecting the grant cache at this stage.
                   We know that nobody else is trying to complete
                   requests off of the ring because this DPC can only
                   run on one vcpu at a time. */

                /* Update tx_ring.rsp_cons so that concurrent sends on
                   other vcpus can proceed without queuing. */
                Transmitter->tx_ring.rsp_cons = cons;

                NdisDprReleaseSpinLock(&Transmitter->SendLock);
                for (x = 0; x < MAX_PENDING_COMPLETES; x++) {
                    NdisMSendComplete(Transmitter->Adapter->AdapterHandle,
                                      pendingCompletes[x],
                                      pendingStatuses[x]);
                }
                NdisDprAcquireSpinLock(&Transmitter->SendLock);
                XM_ASSERT3U(Transmitter->nTxInFlight, >=, nrPendingCompletes);
                Transmitter->nTxInFlight -= nrPendingCompletes;
                nrPendingCompletes = 0;
            }

            status = CompletePacketBackend(Transmitter, packet,
                                           resp->status);
            pendingCompletes[nrPendingCompletes] = packet;
            pendingStatuses[nrPendingCompletes] = status;

            /* Unhook from the TX list */
            XM_ASSERT(packet != Transmitter->HeadUnprepPacket);
            XM_ASSERT(packet != Transmitter->HeadUntransPacket);
            if (PACKET_TX_OVERLAY(packet)->next) {
                PACKET_TX_OVERLAY(PACKET_TX_OVERLAY(packet)->next)->prev =
                    PACKET_TX_OVERLAY(packet)->prev;
            } else {
                XM_ASSERT3P(packet, ==, Transmitter->TailTxPacket);
                Transmitter->TailTxPacket =
                    PACKET_TX_OVERLAY(packet)->prev;
            }
            if (PACKET_TX_OVERLAY(packet)->prev) {
                PACKET_TX_OVERLAY(PACKET_TX_OVERLAY(packet)->prev)->next =
                    PACKET_TX_OVERLAY(packet)->next;
            } else {
                XM_ASSERT3P(packet, ==, Transmitter->HeadTxPacket);
                Transmitter->HeadTxPacket =
                    PACKET_TX_OVERLAY(packet)->next;
            }

            ReleaseTxShadows(Transmitter, packet);
            nrPendingCompletes++;
        }

        cons = RING_IDX_PLUS(cons, 1);
    }

    Transmitter->tx_ring.rsp_cons = cons;

    if (RING_HAS_UNCONSUMED_RESPONSES(&Transmitter->tx_ring))
        goto top;

    TransmitScheduledPackets(Transmitter, TRUE);

    /* Ask for another interrupt when some more TX requests are
       complete.  These interrupts can be delayed almost arbitrarily
       without affecting correctness, but you need to avoid queueing
       packets because there aren't enough TX slots available.  The
       magic number 64 happens to work reasonably well, but this is
       unlikely to be the best possible strategy. */
    delta = __RING_IDX_DIFFERENCE(Transmitter->tx_ring.sring->req_prod,
                                  Transmitter->tx_ring.rsp_cons);
    if (delta >= 64)
        delta = 64;
    if (delta <= 0)
        delta = 1;
    Transmitter->tx_ring.sring->rsp_event =
        RING_IDX_PLUS(Transmitter->tx_ring.rsp_cons, delta);
    mb();
    if (RING_HAS_UNCONSUMED_RESPONSES(&Transmitter->tx_ring))
        goto top;

    NdisDprReleaseSpinLock(&Transmitter->SendLock);

    if (nrPendingCompletes) {
        /* It's a pity that NdisMSendComplete needs to be called
           without holding the send lock, but nTxInFlight must be
           updated whilst holding it, and we have to do nTxInFlight
           after SendComplete. */
        for (x = 0; x < nrPendingCompletes; x++) {
            NdisMSendComplete(Transmitter->Adapter->AdapterHandle,
                              pendingCompletes[x],
                              pendingStatuses[x]);
        }

        NdisDprAcquireSpinLock(&Transmitter->SendLock);
        XM_ASSERT3U(Transmitter->nTxInFlight, >=, nrPendingCompletes);
        Transmitter->nTxInFlight -= nrPendingCompletes;
        NdisDprReleaseSpinLock(&Transmitter->SendLock);
    }

    return NDIS_STATUS_SUCCESS;
}



/* Queue a fake broadcast ARP reply, to encourage bridges to learn our
   new location after a migration.  Call under the send lock.  Can
   fail without giving an error indication to the caller. */
static VOID
QueueFakeArp(PADAPTER Adapter)
{
    PTRANSMITTER Transmitter = &Adapter->Transmitter;
    void *buf;
    struct ethhdr *eh;
    GRANT_REF gref;
    struct arphdr *ah;
    PHYSICAL_ADDRESS pa;
    netif_tx_request_t *req;
    struct tx_shadow *shadow;
    netif_tx_id_t id;

    NdisAcquireSpinLock(&Adapter->address_list_lock);

    /* Can't do anything if we don't have an IP address. */
    if (Adapter->nr_addresses <= 0) {
        NdisReleaseSpinLock(&Adapter->address_list_lock);
        TraceInfo(("Not sending fake ARP due to lack of addresses.\n"));
        return;
    }

    buf = XmAllocatePhysMemory(PAGE_SIZE, &pa);
    if (!buf) {
        NdisReleaseSpinLock(&Adapter->address_list_lock);
        TraceWarning(("No memory for fake arp?\n"));
        return;
    }

    /* Set up the packet */
    eh = buf;
    memset(eh->dest, 0xff, ETH_LENGTH_OF_ADDRESS);
    memcpy(eh->src, Adapter->CurrentAddress, ETH_LENGTH_OF_ADDRESS);
    eh->proto = 0x0608;
    ah = (struct arphdr *)(eh + 1);
    ah->hrd_fmt = 0x0100;
    ah->proto_fmt = 0x0008;
    ah->hrd_len = 0x06;
    ah->proto_len = 0x04;
    ah->operation = 0x0200;
    memcpy(ah->snd_hrd_addr, Adapter->CurrentAddress, ETH_LENGTH_OF_ADDRESS);
    memcpy(ah->snd_proto_addr, Adapter->address_list, 4);
    memset(ah->tgt_hrd_addr, 0xff, ETH_LENGTH_OF_ADDRESS);
    memset(ah->tgt_proto_addr, 0xff, 4);

    NdisReleaseSpinLock(&Adapter->address_list_lock);

    if (!Transmitter->nr_free_tx_ids || RING_FULL(&Transmitter->tx_ring)) {
        /* We're about to transmit a lot of stuff anyway, so don't
           need to bother with the ARP. */
        XmFreeMemory(buf);
        TraceInfo(("Not sending fake ARP because ring busy.\n"));
        return;
    }
    gref = GnttabGrantForeignAccessCache(Adapter->BackendDomid,
                                         (ULONG_PTR)(pa.QuadPart >> PAGE_SHIFT),
                                         GRANT_MODE_RO,
                                         Transmitter->grant_cache);
    if (is_null_GRANT_REF(gref)) {
        XmFreeMemory(buf);
        TraceInfo(("Not sending fake ARP due to lack of grefs.\n"));
        return;
    }

    id = AllocateTxId(Transmitter);
    shadow = TxShadowForId(Transmitter, id);
    shadow->gref = gref;
    shadow->next = INVALID_SHADOW_IND;
    shadow->is_extra = 0;
    shadow->is_fake_arp = 1;
    shadow->fake_arp_buf = buf;

    req = &shadow->req;
    req->id = id;
    req->gref = xen_GRANT_REF(gref);
    req->offset = 0;
    req->flags = 0;
    req->size = sizeof(*ah) + sizeof(*eh);

    *(RING_GET_REQUEST(&Transmitter->tx_ring, Transmitter->tx_ring.req_prod_pvt)) =
        *req;
    Transmitter->tx_ring.req_prod_pvt = RING_IDX_PLUS(Transmitter->tx_ring.req_prod_pvt,
                                                 1);

    TraceInfo(("Queued fake arp.\n"));
}

void
TransmitterDebugDump(PTRANSMITTER Transmitter)
{
    TraceInternal(("%d TX in flight, %d max, %d free ids, %d min, %d queued, %d max.\n",
                   Transmitter->nTxInFlight,
                   Transmitter->nTxInFlightMax,
                   Transmitter->nr_free_tx_ids,
                   Transmitter->min_free_tx_ids,
                   Transmitter->nQueuedPackets,
                   Transmitter->nQueuedPacketsMax));
    Transmitter->nTxInFlightMax = Transmitter->nTxInFlight;
    Transmitter->min_free_tx_ids = Transmitter->nr_free_tx_ids;
    Transmitter->nQueuedPacketsMax = Transmitter->nQueuedPackets;
    TraceInternal(("tx_csum %d TCP, %d UDP, %d IP (%d safe)\n",
                   Transmitter->tx_csum_tcp_offload,
                   Transmitter->tx_csum_udp_offload,
                   Transmitter->tx_csum_ip_offload,
                   Transmitter->tx_csum_offload_safe));
    TraceInternal(("Transmitted %d packets (%d frags, %d batches, %d events, %d bounce, %d large)\n",
                   Transmitter->nTxPackets,
                   Transmitter->nTxFrags,
                   Transmitter->nTxBatches,
                   Transmitter->nTxEvents,
                   Transmitter->nBounced,
                   Transmitter->nLargeSends));
    Transmitter->nTxPackets = 0;
    Transmitter->nTxFrags = 0;
    Transmitter->nTxEvents = 0;
    Transmitter->nTxBatches = 0;
    Transmitter->nBounced = 0;
    Transmitter->nLargeSends = 0;
    TraceInternal(("%d tx csum offloads.\n", Transmitter->nTxCsumOffload));
    Transmitter->nTxCsumOffload = 0;
    if (Transmitter->tx_ring.sring != NULL)
        TraceInternal(("TX ring: req_prod %x (pvt %x), rsp_prod %x, rsp_cons %x, rsp_event %x\n",
                       Transmitter->tx_ring.sring->req_prod,
                       Transmitter->tx_ring.req_prod_pvt,
                       Transmitter->tx_ring.sring->rsp_prod,
                       Transmitter->tx_ring.rsp_cons,
                       Transmitter->tx_ring.sring->rsp_event));
}
