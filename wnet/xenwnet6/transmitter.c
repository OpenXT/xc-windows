/*
 * Copyright (c) 2012 Citrix Systems, Inc.
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

#include "common.h"
#include "nbl_hash.h"
#include "config.h"
#include "wlan.h"

#include "..\..\xenutil\gnttab.h"

#define XENNET_GET_NET_BUFFER_LIST_RESERVED(nbl)\
    (&(nbl)->MiniportReserved[0])

#define XENNET_GET_NET_BUFFER_LIST_FROM_RESERVED(r) \
    (CONTAINING_RECORD((r), NET_BUFFER_LIST, MiniportReserved))

#define XENNET_INVALID_TX_SHADOW_ID    (WrapTxId(0xff, 0xff))

static VOID 
TransmitterCleanupNetBuffer (
    IN  PTRANSMITTER    Transmitter,
    IN  PNET_BUFFER     NetBuffer
    );

static VOID
TransmitterUpdateStatistics (
    IN  PTRANSMITTER    Transmitter,
    IN  PNET_BUFFER     NetBuffer
    );

static VOID
TransmitterRun (
    IN  PTRANSMITTER Transmitter,
    BOOLEAN dpcLevel
    );

static NDIS_STATUS
TransmitterInitializeBounceBuffer (
    IN  PTRANSMITTER Transmitter
    );

static BOOLEAN
TransmitterPrepareNetBuffer (
    IN  PTRANSMITTER    Transmitter,
    IN  PNET_BUFFER     NetBuffer
    );

static VOID
TransmitterSend (
    IN  PTRANSMITTER Transmitter,
    BOOLEAN dpcLevel
    );

/* The generation stuff won't work if the number of TX frags
 * changes */
CASSERT(XENNET_MAX_TX_FRAGS == 256);

static void _TransmitterSanityCheck(PTRANSMITTER t, unsigned line);
#define TransmitterSanityCheck(x) _TransmitterSanityCheck((x), __LINE__)

static netif_tx_id_t
WrapTxId(uint16_t index, uint16_t generation)
{
    netif_tx_id_t id;

    XM_ASSERT3U(index & 0xff, ==, index);
    id.__id = index | (generation << 8);

    return id;
}

static void
UnwrapTxId(netif_tx_id_t id, uint16_t *index, uint16_t *generation)
{
    if (index != NULL)
        *index = id.__id & 0xff;

    if (generation != NULL)
        *generation = id.__id >> 8;
}

static BOOLEAN
TxIdValid(netif_tx_id_t id)
{
    if (id.__id & 0x8000)
        return FALSE;
    else
        return TRUE;
}

static PXENNET_TX_SHADOW
TransmitterGetTxShadow(PTRANSMITTER Transmitter, netif_tx_id_t id)
{
    uint16_t index;
    uint16_t generation;
    PXENNET_TX_SHADOW txShadow;

    XM_ASSERT(TxIdValid(id));
    UnwrapTxId(id, &index, &generation);

    txShadow = &Transmitter->TxShadowInfo.TxShadow[index];
    XM_ASSERT3U(txShadow->Generation, ==, generation);

    return txShadow;
}

static netif_tx_id_t
TransmitterAllocateTxShadowId(PTRANSMITTER Transmitter)
{
    netif_tx_id_t id = Transmitter->TxShadowInfo.HeadFreeId;
    uint16_t index;
    uint16_t generation;
    PXENNET_TX_SHADOW txShadow;

    XM_ASSERT(TxIdValid(id));
    UnwrapTxId(id, &index, &generation);

    txShadow = &Transmitter->TxShadowInfo.TxShadow[index];
    XM_ASSERT3U(txShadow->Generation, ==, generation);

    XM_ASSERT(Transmitter->TxShadowInfo.AvailableShadows != 0);
    XM_ASSERT(!txShadow->InUse);

    txShadow->InUse = TRUE;

    generation = ++txShadow->Generation;
    id = WrapTxId(index, generation);

    Transmitter->TxShadowInfo.AvailableShadows--;
    Transmitter->TxShadowInfo.HeadFreeId = txShadow->Next;
    txShadow->Next = XENNET_INVALID_TX_SHADOW_ID;

    XM_ASSERT(TxIdValid(Transmitter->TxShadowInfo.HeadFreeId) || 
              Transmitter->TxShadowInfo.AvailableShadows == 0);

    return id;
}

static VOID
TransmitterFreeTxShadowId(PTRANSMITTER Transmitter, netif_tx_id_t id, BOOLEAN initialize)
{
    uint16_t index;
    uint16_t generation;
    PXENNET_TX_SHADOW txShadow;

    XM_ASSERT(TxIdValid(id));
    UnwrapTxId(id, &index, &generation);

    txShadow = &Transmitter->TxShadowInfo.TxShadow[index];
    XM_ASSERT3U(txShadow->Generation, ==, generation);

    XM_ASSERT(Transmitter->TxShadowInfo.AvailableShadows < XENNET_MAX_TX_FRAGS);
    if (!initialize) {
        XM_ASSERT(txShadow->InUse);
        txShadow->InUse = FALSE;
    }

    XM_ASSERT(!txShadow->OwnedByBackend);
    XM_ASSERT(is_null_GRANT_REF(txShadow->GrantRef));
    XM_ASSERT(!txShadow->IsExtra);
    XM_ASSERT(!txShadow->IsFakeArp);
    XM_ASSERT3P(txShadow->Buffer, ==, NULL);

    txShadow->Next = Transmitter->TxShadowInfo.HeadFreeId;
    Transmitter->TxShadowInfo.HeadFreeId = id;
    Transmitter->TxShadowInfo.AvailableShadows++;
}

static ULONG
TransmitterBounceNetBuffer (
    IN  PTRANSMITTER    Transmitter,
    IN  PNET_BUFFER     NetBuffer
    )
{
    ULONG bytesCopied = 0;
    NDIS_NET_BUFFER_LIST_8021Q_INFO ndis8021QInfo;
    PNET_BUFFER_LIST netBufferList;
    USHORT protocol = TPID_8021_Q;
    USHORT tci;
    PXENNET_NET_BUFFER_RESERVED xennetBuffer;

    XM_ASSERT(Transmitter != NULL);
    XM_ASSERT(NetBuffer != NULL);

    if (Transmitter->BounceBufferInUse != TRUE) {
        xennetBuffer = XENNET_GET_NET_BUFFER_RESERVED(NetBuffer);
        XM_ASSERT3U(xennetBuffer->Magic, ==, XENNET_BUFFER_MAGIC);

        netBufferList = xennetBuffer->NetBufferList;
        ndis8021QInfo.Value = NET_BUFFER_LIST_INFO(netBufferList, 
                                                   Ieee8021QNetBufferListInfo);

        if (ndis8021QInfo.TagHeader.UserPriority != 0) {
            bytesCopied = GetNetBufferData(NetBuffer, 
                                           0, 
                                           Transmitter->BounceBuffer, 
                                           12);
            
            memcpy(&Transmitter->BounceBuffer[12], &protocol, 2);
            bytesCopied += 2;
            tci = BUILD_TCI(ndis8021QInfo.TagHeader.UserPriority,
                            ndis8021QInfo.TagHeader.CanonicalFormatId,
                            ndis8021QInfo.TagHeader.VlanId);
            tci = htons(tci);

            memcpy(&Transmitter->BounceBuffer[14], &tci, 2);
            bytesCopied += 2;
            bytesCopied += GetNetBufferData(NetBuffer, 
                                            12, 
                                            &Transmitter->BounceBuffer[16], 
                                            XENNET_BOUNCE_BUFFER_SIZE - 16);

            if (bytesCopied != NET_BUFFER_DATA_LENGTH(NetBuffer) + 4) {
                TraceWarning(("Failed to read NET_BUFFER data for injecting 802.1Q TCI!\n"));
            }

        } else {
            bytesCopied = GetNetBufferData(NetBuffer, 
                                           0, 
                                           Transmitter->BounceBuffer, 
                                           XENNET_BOUNCE_BUFFER_SIZE);

            if (bytesCopied != NET_BUFFER_DATA_LENGTH(NetBuffer)) {
                TraceWarning(("Failed to read NET_BUFFER data for bouncing!\n"));
            }
        }

        if (bytesCopied) {
            Transmitter->BounceBufferMdl->ByteCount = bytesCopied;
            Transmitter->BounceBufferInUse = TRUE;
            Transmitter->BounceCount++;
        }
    }

    return bytesCopied;
}

static ULONG
TransmitterCountTcpPayloadBytes(PNET_BUFFER NetBuffer,
                                ULONG TcpHeaderOffset)
{
    uint16_t doffAndFlags;
    ULONG tcpHeaderSize;
    PXENNET_NET_BUFFER_RESERVED xennetBuffer;

    CASSERT(sizeof(doffAndFlags) == RTL_FIELD_SIZE(struct tcphdr,
                                                   off_and_flags));
    GetNetBufferData(NetBuffer,
                     TcpHeaderOffset + FIELD_OFFSET(struct tcphdr,
                                                    off_and_flags),
                     &doffAndFlags,
                     sizeof(doffAndFlags));
    tcpHeaderSize = (doffAndFlags & 0xf0) / 4;

    xennetBuffer = XENNET_GET_NET_BUFFER_RESERVED(NetBuffer);
    XM_ASSERT3U(xennetBuffer->Magic, ==, XENNET_BUFFER_MAGIC);

    return xennetBuffer->TotalSize - (TcpHeaderOffset + tcpHeaderSize);
}

static BOOLEAN
MaybeCompleteNetBufferList(PTRANSMITTER Transmitter,
                           PNET_BUFFER_LIST netBufferList,
                           NDIS_STATUS status)
{
    BOOLEAN isLso;
    ULONG tcpHeaderOffset;
    NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO tcpLso;
    PNET_BUFFER netBuffer;
    PXENNET_NET_BUFFER_RESERVED xennetBuffer;
    PXENNET_NET_BUFFER_LIST_RESERVED listReserved;

    XM_ASSERT3P(NET_BUFFER_LIST_NEXT_NBL(netBufferList), ==, NULL);

    nbl_log(netBufferList, NBL_TRANSMITTER_MAYBE_CLEANUP, status);

    /* Ensure all net buffer transmission is completed before removing
       from pending list. */
    for (netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList); 
         netBuffer; 
         netBuffer = NET_BUFFER_NEXT_NB(netBuffer)) {
        xennetBuffer = XENNET_GET_NET_BUFFER_RESERVED(netBuffer);
        XM_ASSERT3U(xennetBuffer->Magic, ==, XENNET_BUFFER_MAGIC);
        if (xennetBuffer->State != Completed) {
            break;
        }
    }

    if (netBuffer) {
        /* Still have uncompleted buffers in this list -> can't
           complete it. */
        nbl_log(netBufferList, NBL_TRANSMITTER_MAYBE_CLEANUP_DONT,
                (ULONG_PTR)netBuffer);
        return FALSE;
    }

    nbl_log(netBufferList, NBL_TRANSMITTER_MAYBE_CLEANUP_DO);

    /* Do we need to do LSO processing? */
    tcpLso.Value = NET_BUFFER_LIST_INFO(netBufferList,
                                        TcpLargeSendNetBufferListInfo);

    if (tcpLso.LsoV1Transmit.MSS != 0)
        isLso = TRUE;
    else
        isLso = FALSE;
    tcpHeaderOffset = tcpLso.LsoV1Transmit.TcpHeaderOffset;

    tcpLso.LsoV1TransmitComplete.TcpPayload = 0;
    listReserved = (PXENNET_NET_BUFFER_LIST_RESERVED)XENNET_GET_NET_BUFFER_LIST_RESERVED(netBufferList);

    RemoveEntryList(&listReserved->ListEntry);
    Transmitter->QueuedCount--;
    memset(listReserved, 0, sizeof (XENNET_NET_BUFFER_LIST_RESERVED));

    /* Iterate the buffers in the list and add up the various
       statistics.  Also accumulate the TCP payload byte count across
       all packets in the list. */
    for (netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList); 
         netBuffer; 
         netBuffer = NET_BUFFER_NEXT_NB(netBuffer)) {
        if (isLso)
            tcpLso.LsoV1TransmitComplete.TcpPayload +=
                TransmitterCountTcpPayloadBytes(netBuffer,
                                                tcpHeaderOffset);
        TransmitterUpdateStatistics(Transmitter, 
                                    netBuffer);
        xennetBuffer = XENNET_GET_NET_BUFFER_RESERVED(netBuffer);

        /* Only clean the miniport context region up here if this is not a WLAN
         * driver. The WLAN driver uses the miniport context area during its cleanup
         * and will handle cleaning this up.
         */
#ifndef XEN_WIRELESS
        memset(xennetBuffer, 0, sizeof (XENNET_NET_BUFFER_RESERVED));
#endif
    }

    if (isLso)
        NET_BUFFER_LIST_INFO(netBufferList,
                             TcpLargeSendNetBufferListInfo) =
            tcpLso.Value;

    NET_BUFFER_LIST_STATUS(netBufferList) = status;
    return TRUE;
}

static VOID 
TransmitterCleanup (
    IN  PTRANSMITTER Transmitter,
    BOOLEAN TearDown
    )
{
    XM_ASSERT(Transmitter != NULL);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (!TearDown)
    {
        XM_ASSERT(IsListEmpty(&Transmitter->QueuedList));
        XM_ASSERT3U(Transmitter->QueuedCount, ==, 0);
    }

    XmFreeMemory(Transmitter->BounceBuffer);
    XmFreeMemory(Transmitter->BounceBufferMdl);
    NdisFreeSpinLock(&Transmitter->Lock);
    if (!is_null_GRANT_REF(Transmitter->RingGrantRef)) {
        (VOID) GnttabEndForeignAccess(Transmitter->RingGrantRef);
        Transmitter->RingGrantRef = null_GRANT_REF();
    }
    XmFreeMemory(Transmitter->SharedRing);
    if (!is_null_GRANT_REF(Transmitter->ArpGrantRef)) {
        (VOID) GnttabEndForeignAccess(Transmitter->ArpGrantRef);
        Transmitter->ArpGrantRef = null_GRANT_REF();
    }
    XmFreeMemory(Transmitter->ArpBuffer);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}

VOID
TransmitterForceFreePackets (
    IN  PTRANSMITTER    Transmitter
    )
{
    PLIST_ENTRY entry;
    NET_BUFFER_LIST *netBufferList;
    NET_BUFFER_LIST *headNetBufferList;
    NET_BUFFER_LIST **pTailNetBufferList;
    PXENNET_NET_BUFFER_LIST_RESERVED listReserved;
    PNET_BUFFER netBuffer;
    PXENNET_NET_BUFFER_RESERVED xennetBuffer;
    netif_tx_id_t id;
    PXENNET_TX_SHADOW txShadow;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    headNetBufferList = NULL;
    pTailNetBufferList = &headNetBufferList;

    XennetAcquireSpinLock(&Transmitter->Lock, FALSE);
    TransmitterSanityCheck(Transmitter);

    entry = Transmitter->QueuedList.Flink;
    while (entry != &Transmitter->QueuedList) {
        PLIST_ENTRY next = entry->Flink;

        listReserved = CONTAINING_RECORD(entry, 
                                         XENNET_NET_BUFFER_LIST_RESERVED, 
                                         ListEntry);
        netBufferList = XENNET_GET_NET_BUFFER_LIST_FROM_RESERVED(listReserved);
        //nbl_log(netBufferList, NBL_TRANSMITTER_RESUME_LATE);

        TraceWarning (("Freeing netBuffer list %p\n", netBufferList));

        for (netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
             netBuffer;
             netBuffer = NET_BUFFER_NEXT_NB(netBuffer)) {
            xennetBuffer = XENNET_GET_NET_BUFFER_RESERVED(netBuffer);
            XM_ASSERT3U(xennetBuffer->Magic, ==, XENNET_BUFFER_MAGIC);

            nbl_log(netBufferList, NBL_TRANSMITTER_RESUME_LATE_BUFFER,
                    (ULONG_PTR)netBuffer, xennetBuffer->State);
            /* Pretend that the backend just finished this net
               buffer for us. */

            /* First return every fragment */
            id = xennetBuffer->TxShadowHeadId;
            while (TxIdValid(id)) {
                txShadow = TransmitterGetTxShadow(Transmitter, id);

                txShadow->OwnedByBackend = FALSE;

                if (!txShadow->IsExtra) {
                    XM_ASSERT(xennetBuffer->PhysicalBufferCount != 0);
                    xennetBuffer->PhysicalBufferCount--;
                }
                id = txShadow->Next;
            }

            /* Now complete the net buffer itself. */
            xennetBuffer->State = Completed;

            TransmitterCleanupNetBuffer(Transmitter, netBuffer);
            if (xennetBuffer->Bounced) {
                XM_ASSERT(Transmitter->BounceBufferInUse);
                Transmitter->BounceBufferInUse = FALSE;
            }
        }

        if (MaybeCompleteNetBufferList(Transmitter, netBufferList, NDIS_STATUS_SUCCESS)) {
            XM_ASSERT3P(NET_BUFFER_LIST_NEXT_NBL(netBufferList), ==, NULL);
            *pTailNetBufferList = netBufferList;
            pTailNetBufferList = &NET_BUFFER_LIST_NEXT_NBL(netBufferList);
        }    

        entry = next;
    }

    TransmitterSanityCheck(Transmitter);
    XennetReleaseSpinLock(&Transmitter->Lock, FALSE);

    if (headNetBufferList) {
#ifdef XEN_WIRELESS
        WlanSendNetBufferListsComplete(headNetBufferList);
#endif
        NdisMSendNetBufferListsComplete(Transmitter->Adapter->NdisAdapterHandle,
                                        headNetBufferList,
                                        0);
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}

static VOID 
TransmitterCleanupNetBuffer (
    IN  PTRANSMITTER    Transmitter,
    IN  PNET_BUFFER     NetBuffer
    )
{
    netif_tx_id_t id;
    netif_tx_id_t n;
    PXENNET_TX_SHADOW txShadow;
    PXENNET_NET_BUFFER_RESERVED xennetBuffer;

    xennetBuffer = XENNET_GET_NET_BUFFER_RESERVED(NetBuffer);
    XM_ASSERT3U(xennetBuffer->Magic, ==, XENNET_BUFFER_MAGIC);

    XM_ASSERT(TxIdValid(xennetBuffer->TxShadowHeadId));

    id = xennetBuffer->TxShadowHeadId;
    while (TxIdValid(id)) {
        txShadow = TransmitterGetTxShadow(Transmitter, id);

        /* ``Real'' slots should be de-OwnedByBackend when they
           complete.  Extras are special, because they're not
           completed explicitly and are instead completed when the
           owning netbuffer completes. */
        if (txShadow->IsExtra) {
            txShadow->IsExtra = FALSE;
            txShadow->OwnedByBackend = FALSE;
        } else {
            XM_ASSERT3P(txShadow->Buffer, ==, NetBuffer);
            txShadow->Buffer = NULL;

            if (!is_null_GRANT_REF(txShadow->GrantRef)) {
                GnttabEndForeignAccessCache(txShadow->GrantRef,
                                            Transmitter->Adapter->GrantCache);
                txShadow->GrantRef = null_GRANT_REF();
            }
        }

        n = txShadow->Next;

        TransmitterFreeTxShadowId(Transmitter, id, FALSE);
        id = n;
    }            

    xennetBuffer->TxShadowHeadId = XENNET_INVALID_TX_SHADOW_ID;
    return;
}

VOID
TransmitterDebugDump (
    IN PTRANSMITTER Transmitter
    )
{
    TraceInternal(("TX: Bounce in use: %d, count %d\n",
                   Transmitter->BounceBufferInUse,
                   Transmitter->BounceCount));

    TraceInternal(("TX: Broadcast: %d octets, %d packets.\n",
                   Transmitter->BroadcastOctets,
                   Transmitter->BroadcastPkts));

    TraceInternal(("TX: Unicast: %d octets, %d packets.\n",
                   Transmitter->UcastOctets,
                   Transmitter->UcastPkts));

    TraceInternal(("TX: Multicast: %d octets, %d packets.\n",
                   Transmitter->MulticastOctets,
                   Transmitter->MulticastPkts));

    TraceInternal(("TX: Completed %I64d frames.\n",
                   Transmitter->CompletedFrames));

    TraceInternal(("TX: csum offload safe: %d.  TCP %d, UDP %d, IP %d.  Done %d.\n",
                   Transmitter->ChecksumOffloadSafe,
                   Transmitter->TcpChecksumOffload,
                   Transmitter->UdpChecksumOffload,
                   Transmitter->IpChecksumOffload,
                   Transmitter->NrCsumOffloads));

    TraceInternal(("TX: Lso available %d, in use %d.\n",
                   Transmitter->LsoAvailable,
                   Transmitter->LargeSendOffload));

    TraceInternal(("TX: Dropped %d, errors %d, frags %d, large sends %d, sent %I64d.\n",
                   Transmitter->DroppedFrames,
                   Transmitter->Errors,
                   Transmitter->Fragments,
                   Transmitter->LargeSends,
                   Transmitter->SentFrames));

    TraceInternal(("TX: %d interrupts, %d notify.\n",
                   Transmitter->Interrupts,
                   Transmitter->RemoteNotifies));

    TraceInternal(("TX: %d shadows available.\n",
                   Transmitter->TxShadowInfo.AvailableShadows));

    TraceInternal(("TX: req_prod_pvt %x, rsp_cons %x, last notify at producer %x\n",
                   Transmitter->Ring.req_prod_pvt,
                   Transmitter->Ring.rsp_cons,
                   Transmitter->LastProdNotify));
    if (Transmitter->Ring.sring)
        TraceInternal(("TX: req_prod %x, rsp_prod %x, rsp_event %x, req_event %x\n",
                       Transmitter->Ring.sring->req_prod,
                       Transmitter->Ring.sring->rsp_prod,
                       Transmitter->Ring.sring->rsp_event,
                       Transmitter->Ring.sring->req_event));

    TraceInternal(("TX: pause state %d\n",
                   Transmitter->PauseState));

    return;
}

VOID 
TransmitterDelete (
    IN OUT PTRANSMITTER* Transmitter,
    BOOLEAN TearDown
    )
{
    XM_ASSERT(Transmitter != NULL);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (*Transmitter) {
        TransmitterCleanup(*Transmitter, TearDown);
        XmFreeMemory(*Transmitter);
        *Transmitter = NULL;
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}

VOID
TransmitterHandleNotification (
    IN  PTRANSMITTER Transmitter
    )
{
    RING_IDX consumer;
    LONG delta;
    PNET_BUFFER_LIST headNetBufferList;
    NET_BUFFER_LIST **pTailNetBufferList;
    netif_tx_id_t id;
    NDIS_STATUS ndisStatus;
    PNET_BUFFER netBuffer;
    PNET_BUFFER_LIST netBufferList;
    RING_IDX producer;
    netif_tx_response_t* response;
    PXENNET_TX_SHADOW txShadow;
    PXENNET_NET_BUFFER_RESERVED xennetBuffer;
    unsigned nr_to_complete;

    if (!RING_HAS_UNCONSUMED_RESPONSES(&Transmitter->Ring)) {
        return;
    }
    
    headNetBufferList = NULL;
    pTailNetBufferList = &headNetBufferList;

    nr_to_complete = 0;
    Transmitter->Interrupts++;
    XennetAcquireSpinLock(&Transmitter->Lock, TRUE);
    for (;;) {
        producer = Transmitter->Ring.sring->rsp_prod;
        rmb();        
        for(consumer = Transmitter->Ring.rsp_cons; 
            !RING_IDXS_EQ(consumer, producer);
            consumer = RING_IDX_PLUS(consumer, 1)) {

            response = RING_GET_RESPONSE(&Transmitter->Ring, consumer);
            if (response->status == NETIF_RSP_NULL) {
                continue;
            }

            id = response->id;
            XM_ASSERT(TxIdValid(id));

            txShadow = TransmitterGetTxShadow(Transmitter, id);
            XM_ASSERT(!txShadow->IsExtra);
            XM_ASSERT(txShadow->OwnedByBackend);
            txShadow->OwnedByBackend = FALSE;

            if (txShadow->IsFakeArp) {
                txShadow->IsFakeArp = FALSE;
                txShadow->GrantRef = null_GRANT_REF();
                TransmitterFreeTxShadowId(Transmitter, id, FALSE);
                continue;
            }

            netBuffer = txShadow->Buffer;
            xennetBuffer = XENNET_GET_NET_BUFFER_RESERVED(netBuffer);
            XM_ASSERT3U(xennetBuffer->Magic, ==, XENNET_BUFFER_MAGIC);
            netBufferList = xennetBuffer->NetBufferList;

            nbl_log(netBufferList, NBL_TRANSMITTER_BUFFER_COMPLETE,
                    (ULONG_PTR)netBuffer, xennetBuffer->PhysicalBufferCount);

            XM_ASSERT(xennetBuffer->PhysicalBufferCount != 0);
            xennetBuffer->PhysicalBufferCount--;
            if (xennetBuffer->PhysicalBufferCount != 0)
                continue;

            XM_ASSERT3U(xennetBuffer->State, ==, Sent);
            xennetBuffer->State = Completed;

            TransmitterCleanupNetBuffer(Transmitter, netBuffer);
            if (xennetBuffer->Bounced) {
                XM_ASSERT(Transmitter->BounceBufferInUse);
                Transmitter->BounceBufferInUse = FALSE;
            }

            ndisStatus = TransmitterProcessResponseStatus(Transmitter, 
                                                          response);
            if (MaybeCompleteNetBufferList(Transmitter, netBufferList, ndisStatus)) {
                XM_ASSERT3P(NET_BUFFER_LIST_NEXT_NBL(netBufferList), ==, NULL);
                *pTailNetBufferList = netBufferList;
                pTailNetBufferList = &NET_BUFFER_LIST_NEXT_NBL(netBufferList);
            }
        }

        Transmitter->Ring.rsp_cons = consumer;
        if (RING_HAS_UNCONSUMED_RESPONSES(&Transmitter->Ring)) {
            continue;
        }

        TransmitterRun(Transmitter, TRUE);
        delta = __RING_IDX_DIFFERENCE(Transmitter->Ring.sring->req_prod,
                                      Transmitter->Ring.rsp_cons);
        if (delta >= 64) {
            delta = 64;
        }

        if (delta <= 0) {
            delta = 1;
        }

        Transmitter->Ring.sring->rsp_event =
            RING_IDX_PLUS(Transmitter->Ring.rsp_cons, delta);

        mb();
        if (!RING_HAS_UNCONSUMED_RESPONSES(&Transmitter->Ring)) {
            break;
        }
    }
    XennetReleaseSpinLock(&Transmitter->Lock, TRUE);

    if (headNetBufferList) {
#ifdef XEN_WIRELESS
        WlanSendNetBufferListsComplete(headNetBufferList);
#endif
        NdisMSendNetBufferListsComplete(Transmitter->Adapter->NdisAdapterHandle,
                                        headNetBufferList,
                                        NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
    }

    return;
}

NDIS_STATUS
TransmitterInitialize (
    IN  PTRANSMITTER    Transmitter,
    IN  PADAPTER        Adapter
    )
{
    uint16_t i;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PHYSICAL_ADDRESS pa;
    PFN_NUMBER pfn;

    XM_ASSERT(Transmitter != NULL);
    XM_ASSERT(Adapter != NULL);
    XM_ASSERT(Adapter->GrantCache != NULL);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    Transmitter->Adapter = Adapter;
    NdisAllocateSpinLock(&Transmitter->Lock);
    Transmitter->SharedRing = XmAllocateZeroedMemory(PAGE_SIZE);
    if (!Transmitter->SharedRing) {
        ndisStatus = NDIS_STATUS_RESOURCES;
        goto exit;
    }

    SHARED_RING_INIT(Transmitter->SharedRing);
    FRONT_RING_INIT(&Transmitter->Ring, Transmitter->SharedRing, PAGE_SIZE);

    pfn = (PFN_NUMBER)(MmGetPhysicalAddress(Transmitter->SharedRing).QuadPart >> 12);
    Transmitter->RingGrantRef =
        GnttabGrantForeignAccess(Adapter->BackendDomid,
                                 (ULONG_PTR)pfn,
                                 GRANT_MODE_RW);

    if (is_null_GRANT_REF(Transmitter->RingGrantRef)) {
        ndisStatus = NDIS_STATUS_RESOURCES;
        goto exit;
    }

    Transmitter->TxShadowInfo.HeadFreeId = XENNET_INVALID_TX_SHADOW_ID;
    for (i = 0; i < XENNET_MAX_TX_FRAGS; i++)
        TransmitterFreeTxShadowId(Transmitter, WrapTxId(i, 0), TRUE);
    XM_ASSERT3U(Transmitter->TxShadowInfo.AvailableShadows, ==, XENNET_MAX_TX_FRAGS);

    InitializeListHead(&Transmitter->QueuedList);
    ndisStatus = TransmitterInitializeBounceBuffer(Transmitter);
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        goto exit;
    }

    Transmitter->ArpBuffer = XmAllocatePhysMemory(PAGE_SIZE, &pa);
    if (!Transmitter->ArpBuffer) {
        ndisStatus = NDIS_STATUS_RESOURCES;
        goto exit;
    }

    pfn = (PFN_NUMBER)(pa.QuadPart >> PAGE_SHIFT);
    Transmitter->ArpGrantRef = GnttabGrantForeignAccess(Adapter->BackendDomid,
                                                        (ULONG_PTR)pfn,
                                                        GRANT_MODE_RO);

    /* Default IP csum offload to on.  This isn't what's recommended
       by the NDIS documentation, but it seems to be necessary to make
       networking work when you come back from hibernation (because
       Windows assumes that you preserve csum offload settings across
       hibernation, but we don't have anywhere to stash the data, and
       so we just have to guess the most likely answer). */
    Transmitter->IpChecksumOffload = TRUE;

exit:
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return ndisStatus;
}

static NDIS_STATUS 
TransmitterInitializeBounceBuffer (
    IN  PTRANSMITTER Transmitter
    )
{
    ULONG i;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PPFN_NUMBER pfn;
    PUCHAR va;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    Transmitter->BounceBuffer = XmAllocateMemory(XENNET_BOUNCE_BUFFER_SIZE);
    if (!Transmitter->BounceBuffer) {
        ndisStatus = NDIS_STATUS_RESOURCES;
        TraceError(("Failed to allocate bounce buffer!\n"));
        goto exit;
    }

    Transmitter->BounceBufferMdl =
        XmAllocateZeroedMemory(sizeof(MDL) +
                             sizeof(PFN_NUMBER) * XENNET_BOUNCE_BUFFER_PAGES);

    if (!Transmitter->BounceBufferMdl) {
        ndisStatus = NDIS_STATUS_RESOURCES;
        TraceInfo(("Failed allocate bounce buffer MDL!\n"));
        goto exit;
    }

    pfn = MmGetMdlPfnArray(Transmitter->BounceBufferMdl);
    va = Transmitter->BounceBuffer;
    for (i = 0; i < XENNET_BOUNCE_BUFFER_PAGES; i++, va += PAGE_SIZE) {
        pfn[i] = (PFN_NUMBER)(MmGetPhysicalAddress(va).QuadPart >> PAGE_SHIFT);
    }

exit:
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return ndisStatus;
}

static VOID
TransmitterPrepare (
    IN  PTRANSMITTER Transmitter
    )
{
    PLIST_ENTRY entry;
    PNET_BUFFER netBuffer;
    PNET_BUFFER_LIST netBufferList;
    PXENNET_NET_BUFFER_LIST_RESERVED listReserved;
    PXENNET_NET_BUFFER_RESERVED xennetBuffer;

    entry = Transmitter->QueuedList.Flink;
    while (entry != &Transmitter->QueuedList) {
        listReserved = CONTAINING_RECORD(entry, 
                                         XENNET_NET_BUFFER_LIST_RESERVED, 
                                         ListEntry);

        netBufferList = XENNET_GET_NET_BUFFER_LIST_FROM_RESERVED(listReserved);
        nbl_log(netBufferList, NBL_TRANSMITTER_PREPARE);
        for (netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
             netBuffer;
             netBuffer = NET_BUFFER_NEXT_NB(netBuffer)) {

            xennetBuffer = XENNET_GET_NET_BUFFER_RESERVED(netBuffer);
            XM_ASSERT3U(xennetBuffer->Magic, ==, XENNET_BUFFER_MAGIC);

            nbl_log(netBufferList, NBL_TRANSMITTER_PREPARE_BUFFER,
                    (ULONG_PTR)netBuffer, xennetBuffer->State);
            if (xennetBuffer->State == Unprepared) {
                if (!TransmitterPrepareNetBuffer(Transmitter, netBuffer)) {
                    nbl_log(netBufferList, NBL_TRANSMITTER_PREPARE_FAILED);
                    goto done;
                }
            }
        }

        entry = entry->Flink;
    }

done:
    return;
}

static BOOLEAN
TransmitterPrepareNetBuffer (
    IN  PTRANSMITTER    Transmitter,
    IN  PNET_BUFFER     NetBuffer
    )
{
    PADAPTER Adapter = Transmitter->Adapter;
    ULONG byteCount;
    ULONG count;
    ULONG dataSize;
    ULONG extra;
    BOOLEAN firstFragment;
    netif_tx_id_t id;
    PMDL mdl;
    ULONG mdlByteCount;
    ULONG mdlByteOffset;
    PPFN_NUMBER mdlPfns;
    ULONG mss;
    PNET_BUFFER_LIST netBufferList;
    NDIS_NET_BUFFER_LIST_8021Q_INFO ndis8021QInfo;
    ULONG offset;
    ULONG pfnIndex;
    netif_tx_request_t* request;
    BOOLEAN result = TRUE;
    NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO tcpLSOInfo;
    PXENNET_TX_SHADOW txShadow;
    PXENNET_NET_BUFFER_RESERVED xennetBuffer;
    unsigned nr_frags;

    xennetBuffer = XENNET_GET_NET_BUFFER_RESERVED(NetBuffer);
    XM_ASSERT3U(xennetBuffer->Magic, ==, XENNET_BUFFER_MAGIC);

    netBufferList = xennetBuffer->NetBufferList;
    nbl_log(netBufferList, NBL_TRANSMITTER_PREPARE_BUFFER2,
            (ULONG_PTR)NetBuffer);
    ndis8021QInfo.Value = NET_BUFFER_LIST_INFO(netBufferList, 
                                               Ieee8021QNetBufferListInfo);

    if ((xennetBuffer->PhysicalBufferCount >= XENNET_MAX_FRAGS_PER_PACKET) ||
        (AdapterIs8021PEnabled(Transmitter->Adapter) && 
            (ndis8021QInfo.TagHeader.UserPriority != 0))) {

        nbl_log(netBufferList, NBL_TRANSMITTER_BOUNCE_BUFFER,
                (ULONG_PTR)NetBuffer, xennetBuffer->PhysicalBufferCount);
        if (!xennetBuffer->Bounced &&
            !TransmitterBounceNetBuffer(Transmitter, NetBuffer)) {
            nbl_log(netBufferList, NBL_TRANSMITTER_BOUNCE_FAILED,
                    (ULONG_PTR)NetBuffer);

            result = FALSE;
            goto exit;
        }

        xennetBuffer->Bounced = 1;
        mdl = Transmitter->BounceBufferMdl;
        offset = 0;
        dataSize = Transmitter->BounceBufferMdl->ByteCount;
        count = (dataSize + Transmitter->BounceBufferMdl->ByteOffset +
                 PAGE_SIZE - 1) / PAGE_SIZE;
    } else if (xennetBuffer->PhysicalBufferCount != 0) {
        mdl = NET_BUFFER_CURRENT_MDL(NetBuffer);
        offset = NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer); 
        count = xennetBuffer->PhysicalBufferCount;
        dataSize = NET_BUFFER_DATA_LENGTH(NetBuffer);
    } else {
        nbl_log(netBufferList, NBL_TRANSMITTER_EMPTY_BUFFER,
                (ULONG_PTR)NetBuffer);
        xennetBuffer->State = Completed;
        goto exit;
    }

    tcpLSOInfo.Value = NET_BUFFER_LIST_INFO(netBufferList, 
                                            TcpLargeSendNetBufferListInfo);
    
    if (tcpLSOInfo.LsoV1Transmit.MSS) {
        mss = tcpLSOInfo.LsoV1Transmit.MSS;

    } else if (tcpLSOInfo.LsoV2Transmit.MSS) {
        mss = tcpLSOInfo.LsoV2Transmit.MSS;

    } else {
        mss = 0;
    }

    XM_ASSERT3U(mss, <=, XENNET_BOUNCE_BUFFER_SIZE);
    
    if (mss) {
        extra = 1;
        Transmitter->LargeSends++;

    } else {
        extra = 0;
    }

    if ((count + extra) >= Transmitter->TxShadowInfo.AvailableShadows) {
        nbl_log(netBufferList, NBL_TRANSMITTER_TOO_BUSY,
                count, extra, Transmitter->TxShadowInfo.AvailableShadows);
        result = FALSE;
        goto exit;
    }

    nr_frags = 0;

    firstFragment = TRUE;
    request = NULL;
    txShadow = NULL;

    for (; mdl && dataSize; mdl = mdl->Next) {
        mdlByteCount = MmGetMdlByteCount(mdl);
        if (mdlByteCount <= offset) {
            offset -= mdlByteCount;
            continue;
        }

        mdlByteCount -= offset;
        mdlByteOffset = MmGetMdlByteOffset(mdl) + offset;
        offset = 0;
        pfnIndex = 0;
        if (mdlByteOffset >= PAGE_SIZE) {
            mdlByteOffset -= PAGE_SIZE;
            XM_ASSERT3U(mdlByteOffset, <, PAGE_SIZE);
            pfnIndex++;
        }

        XM_ASSERT(mdlByteCount != 0);
        
        if (mdlByteCount > dataSize)
            mdlByteCount = dataSize;
        dataSize -= mdlByteCount;

        for (mdlPfns = MmGetMdlPfnArray(mdl); 
             mdlByteCount; 
             mdlByteCount -= byteCount, mdlByteOffset = 0, pfnIndex++) {

            Transmitter->Fragments++;
            nr_frags++;
            if ((mdlByteCount + mdlByteOffset) > PAGE_SIZE) {
                byteCount = PAGE_SIZE - mdlByteOffset;

            } else {
                byteCount = mdlByteCount;
            }

            id = TransmitterAllocateTxShadowId(Transmitter);
            if (txShadow) {
                txShadow->Next = id;
            } else {
                xennetBuffer->TxShadowHeadId = id;
            }

            txShadow = TransmitterGetTxShadow(Transmitter, id);

            XM_ASSERT(txShadow->InUse);

            txShadow->Buffer = NetBuffer;
            txShadow->Next = XENNET_INVALID_TX_SHADOW_ID;
            txShadow->GrantRef =
                GnttabGrantForeignAccessCache(Adapter->BackendDomid,
                                              mdlPfns[pfnIndex],
                                              GRANT_MODE_RO,
                                              Transmitter->Adapter->GrantCache);

            if (is_null_GRANT_REF(txShadow->GrantRef)) {
                TraceWarning(("Out of grant references?\n"));

                //
                // Handle error on send completion path.
                //

            }

            request = &txShadow->Request;
            request->id = id;
            request->gref = xen_GRANT_REF(txShadow->GrantRef);
            request->flags = NETTXF_more_data;
            if (firstFragment) {
                firstFragment = FALSE;
                if (xennetBuffer->Bounced) {
                    request->size = (USHORT)Transmitter->BounceBufferMdl->ByteCount;

                } else {
                    request->size = (USHORT)NET_BUFFER_DATA_LENGTH(NetBuffer);
                }

                if (Transmitter->TcpChecksumOffload ||
                    Transmitter->UdpChecksumOffload) {
                    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO info;

                    info.Value =
                        NET_BUFFER_LIST_INFO(netBufferList,
                                             TcpIpChecksumNetBufferListInfo);
                    if (info.Transmit.IsIPv4) {
                        if ((Transmitter->TcpChecksumOffload && info.Transmit.TcpChecksum) ||
                            (Transmitter->UdpChecksumOffload && info.Transmit.UdpChecksum)) {
                            request->flags |= NETTXF_csum_blank;
                            Transmitter->NrCsumOffloads++;
                        }
                    }
                }

                if (extra) {
                    txShadow->Next = TransmitterAllocateTxShadowId(Transmitter);
                    txShadow = TransmitterGetTxShadow(Transmitter, txShadow->Next);
                    nr_frags++;
                    txShadow->Next = XENNET_INVALID_TX_SHADOW_ID;
                    txShadow->IsExtra = TRUE;
                    XennetInitializeExtraInfo(&txShadow->ExtraInfo, mss);
                    request->flags |= NETTXF_extra_info | NETTXF_csum_blank;
                }

            } else {
                request->size = (USHORT)byteCount;
            }

            request->offset = (USHORT)mdlByteOffset;
        }
    }

    XM_ASSERT(request != NULL);

    /* count is an *upper bound* on the number of buffers which we
       might need (because PhysicalBufferCount is), so it's acceptable
       for nr_frags to be too small.  It's not acceptable for it to be
       too big. */
    XM_ASSERT3U(nr_frags, <=, extra + count);

    xennetBuffer->PhysicalBufferCount = (USHORT)(nr_frags - extra);
    request->flags &= ~NETTXF_more_data;

    xennetBuffer->TotalSize = mss ? NET_BUFFER_DATA_LENGTH(NetBuffer) : 0;
    xennetBuffer->State = Prepared;

exit:
    return result;
}

NDIS_STATUS
TransmitterRestart (
    IN  PTRANSMITTER    Transmitter
    )
{
    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    XennetAcquireSpinLock(&Transmitter->Lock, FALSE);
    TransmitterRun(Transmitter, FALSE);
    XennetReleaseSpinLock(&Transmitter->Lock, FALSE);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return NDIS_STATUS_SUCCESS;
}

VOID
TransmitterResumeEarly (
    IN  PTRANSMITTER    Transmitter
    )
{
    ULONG count;
    PLIST_ENTRY entry;
    PXENNET_NET_BUFFER_LIST_RESERVED listReserved;
    PNET_BUFFER netBuffer;
    PNET_BUFFER_LIST netBufferList;
    PXENNET_NET_BUFFER_RESERVED xennetBuffer;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    SHARED_RING_INIT(Transmitter->SharedRing);
    FRONT_RING_INIT(&Transmitter->Ring, Transmitter->SharedRing, PAGE_SIZE);

    TransmitterSanityCheck(Transmitter);

    count = 0;
    for (entry = Transmitter->QueuedList.Flink;
         entry != &Transmitter->QueuedList;
         entry = entry->Flink) {
        listReserved = CONTAINING_RECORD(entry, 
                                         XENNET_NET_BUFFER_LIST_RESERVED, 
                                         ListEntry);

        netBufferList = XENNET_GET_NET_BUFFER_LIST_FROM_RESERVED(listReserved);
        nbl_log(netBufferList, NBL_TRANSMITTER_RESUME_EARLY);

        for (netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
             netBuffer;
             netBuffer = NET_BUFFER_NEXT_NB(netBuffer)) {
            xennetBuffer = XENNET_GET_NET_BUFFER_RESERVED(netBuffer);
            XM_ASSERT3U(xennetBuffer->Magic, ==, XENNET_BUFFER_MAGIC);

            nbl_log(netBufferList, NBL_TRANSMITTER_RESUME_EARLY_BUFFER,
                    (ULONG_PTR)netBuffer, xennetBuffer->State);

            /* If a buffer has been sent but not completed, we don't
               know whether the backend actually got around to
               transmitting it.  Dropping a packet is marginally safer
               than duplicating one, we so when we're not sure we just
               drop it. */
            if (xennetBuffer->State == Sent)
                xennetBuffer->State = Drop;
        }
        count++;
    }

    TraceNotice(("Dropping %d net buffer lists on resume.\n", 
                 count));

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}

VOID
TransmitterResumeLate (
    IN  PTRANSMITTER    Transmitter
    )
{
    PLIST_ENTRY entry;
    NET_BUFFER_LIST *netBufferList;
    NET_BUFFER_LIST *headNetBufferList;
    NET_BUFFER_LIST **pTailNetBufferList;
    PXENNET_NET_BUFFER_LIST_RESERVED listReserved;
    PNET_BUFFER netBuffer;
    PXENNET_NET_BUFFER_RESERVED xennetBuffer;
    netif_tx_id_t id;
    PXENNET_TX_SHADOW txShadow;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    headNetBufferList = NULL;
    pTailNetBufferList = &headNetBufferList;

    XennetAcquireSpinLock(&Transmitter->Lock, FALSE);
    TransmitterSanityCheck(Transmitter);

    entry = Transmitter->QueuedList.Flink;
    while (entry != &Transmitter->QueuedList) {
        PLIST_ENTRY next = entry->Flink;

        listReserved = CONTAINING_RECORD(entry, 
                                         XENNET_NET_BUFFER_LIST_RESERVED, 
                                         ListEntry);
        netBufferList = XENNET_GET_NET_BUFFER_LIST_FROM_RESERVED(listReserved);
        nbl_log(netBufferList, NBL_TRANSMITTER_RESUME_LATE);

        for (netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
             netBuffer;
             netBuffer = NET_BUFFER_NEXT_NB(netBuffer)) {
            xennetBuffer = XENNET_GET_NET_BUFFER_RESERVED(netBuffer);
            XM_ASSERT3U(xennetBuffer->Magic, ==, XENNET_BUFFER_MAGIC);

            nbl_log(netBufferList, NBL_TRANSMITTER_RESUME_LATE_BUFFER,
                    (ULONG_PTR)netBuffer, xennetBuffer->State);
            if (xennetBuffer->State == Drop) {
                /* Pretend that the backend just finished this net
                   buffer for us. */

                /* First return every fragment */
                id = xennetBuffer->TxShadowHeadId;
                while (TxIdValid(id)) {
                    txShadow = TransmitterGetTxShadow(Transmitter, id);

                    XM_ASSERT(!txShadow->IsFakeArp);

                    if (txShadow->OwnedByBackend && !txShadow->IsExtra) {
                        txShadow->OwnedByBackend = FALSE;

                        XM_ASSERT(xennetBuffer->PhysicalBufferCount != 0);
                        xennetBuffer->PhysicalBufferCount--;
                    }
                    id = txShadow->Next;
                }
                XM_ASSERT3U(xennetBuffer->PhysicalBufferCount, ==, 0);

                /* Now complete the net buffer itself. */
                xennetBuffer->State = Completed;

                TransmitterCleanupNetBuffer(Transmitter, netBuffer);
                if (xennetBuffer->Bounced) {
                    XM_ASSERT(Transmitter->BounceBufferInUse);
                    Transmitter->BounceBufferInUse = FALSE;
                }
            }
        }

        if (MaybeCompleteNetBufferList(Transmitter, netBufferList, NDIS_STATUS_SUCCESS)) {
            XM_ASSERT3P(NET_BUFFER_LIST_NEXT_NBL(netBufferList), ==, NULL);
            *pTailNetBufferList = netBufferList;
            pTailNetBufferList = &NET_BUFFER_LIST_NEXT_NBL(netBufferList);
        }    

        entry = next;
    }

    TransmitterSanityCheck(Transmitter);
    XennetReleaseSpinLock(&Transmitter->Lock, FALSE);

    if (headNetBufferList) {
#ifdef XEN_WIRELESS
        WlanSendNetBufferListsComplete(headNetBufferList);
#endif
        NdisMSendNetBufferListsComplete(Transmitter->Adapter->NdisAdapterHandle,
                                        headNetBufferList,
                                        0);
    }

    TransmitterRestart(Transmitter);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}

static VOID
TransmitterRun (
    IN  PTRANSMITTER Transmitter,
    BOOLEAN dpcLevel
    )
{
    TransmitterPrepare(Transmitter);
    TransmitterSend(Transmitter, dpcLevel);
    return;
}

static VOID
TransmitterSend (
    IN  PTRANSMITTER Transmitter,
    BOOLEAN dpcLevel
    )
{
    PLIST_ENTRY entry;
    PNET_BUFFER netBuffer;
    PNET_BUFFER_LIST netBufferList;
    PXENNET_NET_BUFFER_LIST_RESERVED listReserved;
    ULONG notify;
    PXENNET_NET_BUFFER_RESERVED xennetBuffer;
    ULONG sent;

    UNREFERENCED_PARAMETER(dpcLevel);

    sent = 0;

    entry = Transmitter->QueuedList.Flink;
    while (entry != &Transmitter->QueuedList) {
        listReserved = CONTAINING_RECORD(entry, 
                                         XENNET_NET_BUFFER_LIST_RESERVED, 
                                         ListEntry);

        netBufferList = XENNET_GET_NET_BUFFER_LIST_FROM_RESERVED(listReserved);
        nbl_log(netBufferList, NBL_TRANSMITTER_SEND);
        for (netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
             netBuffer;
             netBuffer = NET_BUFFER_NEXT_NB(netBuffer)) {

            xennetBuffer = XENNET_GET_NET_BUFFER_RESERVED(netBuffer);
            XM_ASSERT3U(xennetBuffer->Magic, ==, XENNET_BUFFER_MAGIC);

            nbl_log(netBufferList, NBL_TRANSMITTER_SEND_BUFFER,
                    (ULONG_PTR)netBuffer, xennetBuffer->State);

            if (xennetBuffer->State == Prepared) {
#ifdef USE_V4V
                if (xennetBuffer->EapPacket)
                {
                    NTSTATUS status;
                    PXENNET_NET_BUFFER_LIST_RESERVED listReserved;

                    TraceDebug (("Sending EAP packet via V4V\n"));

                    //
                    // Remove the entry in the queued list. BUT.....
                    //
                    // This is going on the assumption that there is only
                    // one NB in the list. Otherwise, we will try to dequeue
                    // the list multiple times. Since we are only concerned
                    // with EAP packets, this should be OK.
                    //
                    XM_ASSERT3U(Transmitter->QueuedCount, >, 0);
                    listReserved =
                        (PXENNET_NET_BUFFER_LIST_RESERVED)XENNET_GET_NET_BUFFER_LIST_RESERVED(netBufferList);
                    RemoveEntryList(&listReserved->ListEntry);
                    Transmitter->QueuedCount--;

                    XennetReleaseSpinLock(&Transmitter->Lock, dpcLevel);
                    //
                    // Send the EAP packet out over the V4V interconnect
                    //
                    status = WlanV4vSendNetBuffer(Transmitter->Adapter, netBuffer);
                    XennetAcquireSpinLock(&Transmitter->Lock, dpcLevel);
                    if (status != STATUS_SUCCESS)
                    {
                        nbl_log(netBufferList, NBL_TRANSMITTER_SEND_FAILED,
                                (ULONG_PTR)netBuffer);
                        Transmitter->Errors++;
                        goto done;
                    }

                    //
                    // Get rid of all the extra data structures normally
                    // used to share data with dom0 (such as grant refs).
                    //
                    TransmitterCleanupNetBuffer(Transmitter, netBuffer);

                    Transmitter->CompletedFrames++;
                    xennetBuffer->State = Completed;
                }
                else
#endif
                  if (!TransmitterSendNetBuffer(Transmitter, netBuffer)) {
                    nbl_log(netBufferList, NBL_TRANSMITTER_SEND_FAILED,
                            (ULONG_PTR)netBuffer);
                    goto done;
                }
                sent++;
            }
        }

        entry = entry->Flink;
    }

done:
    XM_ASSERT(IMPLY(sent != 0, Transmitter->Adapter->RingConnected));
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&Transmitter->Ring, notify);
    if (notify) {
        Transmitter->RemoteNotifies++;
        EvtchnNotifyRemote(Transmitter->Adapter->EvtchnPort);
        Transmitter->LastProdNotify = Transmitter->Ring.req_prod_pvt;
    }

    return;
}

VOID
TransmitterSendFakeArp (
    IN  PTRANSMITTER    Transmitter,
    IN  PUCHAR          CurrentAddress,
    IN  PUCHAR          IpAddress
    )
{
    struct arphdr* ah;
    struct ethhdr *eh = (struct ethhdr *)Transmitter->ArpBuffer;
    netif_tx_id_t id;
    netif_tx_request_t* request;
    PXENNET_TX_SHADOW txShadow;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (!Transmitter->TxShadowInfo.AvailableShadows ||
        RING_FULL(&Transmitter->Ring)) {
        
        TraceError(("Insufficient resources to send fake ARP.\n"));
        goto exit;
    }

    memset(eh->dest, 0xFF, ETH_LENGTH_OF_ADDRESS);
    memcpy(eh->src, CurrentAddress, ETH_LENGTH_OF_ADDRESS);
    eh->proto = 0x0608;
    ah = (struct arphdr*)(eh + 1);
    ah->hrd_fmt = 0x0100;
    ah->proto_fmt = 0x0008;
    ah->hrd_len = 0x06;
    ah->proto_len = 0x04;
    ah->operation = 0x0200;
    memcpy(ah->snd_hrd_addr, CurrentAddress, ETH_LENGTH_OF_ADDRESS);
    memcpy(ah->snd_proto_addr, IpAddress, 4);
    memset(ah->tgt_hrd_addr, 0xFF, ETH_LENGTH_OF_ADDRESS);
    memset(ah->tgt_proto_addr, 0xFF, 4);
    id = TransmitterAllocateTxShadowId(Transmitter);
    txShadow = TransmitterGetTxShadow(Transmitter, id);
    txShadow->GrantRef = Transmitter->ArpGrantRef;
    txShadow->IsFakeArp = TRUE;
    txShadow->OwnedByBackend = TRUE;
    txShadow->Next = XENNET_INVALID_TX_SHADOW_ID;
    request = &txShadow->Request;
    request->id = id;
    request->gref = xen_GRANT_REF(txShadow->GrantRef);
    request->flags = 0;
    request->offset = 0;
    request->size = sizeof(*eh) + sizeof(*ah);
    request = RING_GET_REQUEST(&Transmitter->Ring,
                               Transmitter->Ring.req_prod_pvt);

    *request = txShadow->Request;
    Transmitter->Ring.req_prod_pvt =
        RING_IDX_PLUS(Transmitter->Ring.req_prod_pvt, 1);

exit:
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}

BOOLEAN
TransmitterSendNetBuffer (
    IN  PTRANSMITTER    Transmitter,
    IN  PNET_BUFFER     NetBuffer
    )
{
    ULONG count;
    netif_tx_id_t next;
    netif_tx_request_t* request;
    BOOLEAN result = TRUE;
    PXENNET_TX_SHADOW txShadow;
    netif_tx_id_t id;
    PXENNET_NET_BUFFER_RESERVED xennetBuffer;

    xennetBuffer = XENNET_GET_NET_BUFFER_RESERVED(NetBuffer);
    XM_ASSERT3U(xennetBuffer->Magic, ==, XENNET_BUFFER_MAGIC);

    XM_ASSERT(TxIdValid(xennetBuffer->TxShadowHeadId));
    XM_ASSERT(xennetBuffer->State == Prepared);

    if (Transmitter->Adapter->Flags &
        (XENNET_ADAPTER_STOPPING | XENNET_ADAPTER_STOPPED)) {
        result = FALSE;
        goto exit;
    }

    if (Transmitter->Adapter->RemovalPending) {
        result = FALSE;
        /* If blocked by PnP removal notification, should return this status */
        TraceWarning(("Transmitting packets during pending removal\n"));
        goto exit;
    }

    if (!Transmitter->Adapter->RingConnected) {
        result = FALSE;
        goto exit;
    }

    for (count = 0, id = xennetBuffer->TxShadowHeadId;
         TxIdValid(id);
         id = txShadow->Next) {
        txShadow = TransmitterGetTxShadow(Transmitter, id);
        count++;
    }
    
    XM_ASSERT(count != 0); 

    if (RING_PROD_SLOTS_AVAIL(&Transmitter->Ring) < count) {
        result = FALSE;
        goto exit;
    }

    xennetBuffer->State = Sent;
    Transmitter->SentFrames++;

    for (id = xennetBuffer->TxShadowHeadId;
         TxIdValid(id);
         id = next) {

        txShadow = TransmitterGetTxShadow(Transmitter, id);
        XM_ASSERT(txShadow->InUse);
        XM_ASSERT(!txShadow->OwnedByBackend);
        txShadow->OwnedByBackend = TRUE;
        next = txShadow->Next;
        request = RING_GET_REQUEST(&Transmitter->Ring,
                                   Transmitter->Ring.req_prod_pvt);

        *request = txShadow->Request;
        Transmitter->Ring.req_prod_pvt =
            RING_IDX_PLUS(Transmitter->Ring.req_prod_pvt, 1);
    } 

exit:
    return result;
}

/* Calculate the IP header checksum and drop it into the packet.  This
   assumes that there will not be a fragment boundary in the middle of
   the header. */
static void
TransmitterFixupIpChecksum(PNET_BUFFER NetBuffer,
                           PNET_BUFFER_LIST NetBufferList)
{
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;
    NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO lsoInfo;
    PMDL mdl;
    ULONG mdlOffset;
    ULONG hdrLen;
    struct iphdr *iph;

    nbl_log(NetBufferList, NBL_TRANSMITTER_FIXUP_IP_CSUM);

    csumInfo.Value =
        NET_BUFFER_LIST_INFO(NetBufferList,
                             TcpIpChecksumNetBufferListInfo);
    /* LSO packets always need IP csum offload, regardless of whether
       NDIS says they do. */
    lsoInfo.Value = NET_BUFFER_LIST_INFO(NetBufferList,
                                         TcpLargeSendNetBufferListInfo);
    if (lsoInfo.LsoV1Transmit.MSS == 0 &&
        (!csumInfo.Transmit.IsIPv4 ||
         !csumInfo.Transmit.IpHeaderChecksum))
        return;

    mdl = NET_BUFFER_CURRENT_MDL(NetBuffer);
    mdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer);
    if (MmGetMdlByteCount(mdl) - mdlOffset == sizeof(struct ethhdr)) {
        mdl = mdl->Next;
        mdlOffset = 0;
        /* NDIS shouldn't be telling us to offload an IP checksum with
           a bad encapsulation. */
        XM_ASSERT(mdl != NULL);
    } else {
        mdlOffset += sizeof(struct ethhdr);
    }
    if (MmGetMdlByteCount(mdl) - mdlOffset < sizeof(struct iphdr)) {
        static BOOLEAN warned;
        if (!warned)
            TraceWarning(("Uh oh: fragment boundary in middle of IP header (%d, %d, %d)\n",
                          MmGetMdlByteCount(mdl), mdlOffset,
                          sizeof(struct iphdr)));
        warned = TRUE;
        return;
    }
    iph = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if (iph == NULL)
        return;
    iph = (struct iphdr *)((ULONG_PTR)iph + mdlOffset);
    hdrLen = (iph->len_version & 0x0f) * 4;
    if (MmGetMdlByteCount(mdl) - mdlOffset < hdrLen) {
        static BOOLEAN warned;
        if (!warned)
            TraceWarning(("Uh oh: fragment boundary in middle of IP options (%d, %d, %d)\n",
                          MmGetMdlByteCount(mdl), mdlOffset,
                          iph->len_version));
        warned = TRUE;
        return;
    }

    iph->check = 0;
    iph->check = compute_ip_csum(iph, hdrLen);
}

/* Calculate the TCP pseudo header checksum and drop it into the packet.  This
   assumes that there will not be a fragment boundary in the middle of
   the header. */
static void
TransmitterFixupTcpChecksum(PNET_BUFFER NetBuffer,
                            PNET_BUFFER_LIST NetBufferList)
{
    ULONG dataLen = NET_BUFFER_DATA_LENGTH(NetBuffer);
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;
    NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO lsoInfo;
    PMDL mdl;
    ULONG mdlOffset;
    ULONG hdrLen;
    struct iphdr *iph;
    struct tcphdr *th;
    struct tcp_pseudo_header tph;
    uint32_t csum_accumulator;
    uint16_t csum;

    nbl_log(NetBufferList, NBL_TRANSMITTER_FIXUP_TCP_CSUM);

    csumInfo.Value =
        NET_BUFFER_LIST_INFO(NetBufferList,
                             TcpIpChecksumNetBufferListInfo);

    // Non LSO packets should already have a good pseudo header checksum
    lsoInfo.Value = NET_BUFFER_LIST_INFO(NetBufferList,
                                         TcpLargeSendNetBufferListInfo);
    if (lsoInfo.LsoV1Transmit.MSS == 0 &&
        (!csumInfo.Transmit.IsIPv4 ||
         !csumInfo.Transmit.TcpChecksum))
        return;

    mdl = NET_BUFFER_CURRENT_MDL(NetBuffer);
    mdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer);

    // Skip MAC header
    if (MmGetMdlByteCount(mdl) - mdlOffset == sizeof(struct ethhdr)) {
        mdl = mdl->Next;
        mdlOffset = 0;
        XM_ASSERT(mdl != NULL);
    } else {
        mdlOffset += sizeof(struct ethhdr);
    }

    if (MmGetMdlByteCount(mdl) - mdlOffset < sizeof(struct iphdr)) {
        static BOOLEAN warned;
        if (!warned)
            TraceWarning(("Uh oh: fragment boundary in middle of IP header (%d, %d, %d)\n",
                          MmGetMdlByteCount(mdl), mdlOffset,
                          sizeof(struct iphdr)));
        warned = TRUE;
        return;
    }

    iph = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if (iph == NULL)
        return;
    iph = (struct iphdr *)((ULONG_PTR)iph + mdlOffset);

    hdrLen = (iph->len_version & 0x0f) * 4;
    if (MmGetMdlByteCount(mdl) - mdlOffset < hdrLen) {
        static BOOLEAN warned;
        if (!warned)
            TraceWarning(("Uh oh: fragment boundary in middle of IP options (%d, %d, %d)\n",
                          MmGetMdlByteCount(mdl), mdlOffset,
                          iph->len_version));
        warned = TRUE;
        return;
    }

    // Skip IP header
    if (MmGetMdlByteCount(mdl) - mdlOffset == hdrLen) {
        mdl = mdl->Next;
        mdlOffset = 0;
        XM_ASSERT(mdl != NULL);
    } else {
        mdlOffset += hdrLen;
    }

    if (MmGetMdlByteCount(mdl) - mdlOffset < sizeof(struct tcphdr)) {
        static BOOLEAN warned;
        if (!warned)
            TraceWarning(("Uh oh: fragment boundary in middle of TCP header (%d, %d, %d)\n",
                          MmGetMdlByteCount(mdl), mdlOffset,
                          sizeof(struct tcphdr)));
        warned = TRUE;
        return;
    }

    tph.saddr = iph->src;
    tph.daddr = iph->dest;
    tph.mbz = 0;
    tph.ptcl = IPPROTO_TCP;
    tph.length = htons((uint16_t)(dataLen - sizeof(struct ethhdr) - hdrLen));

    csum_accumulator = acc_ip_csum(&tph, sizeof(tph), 0);
    csum = fold_ip_csum(csum_accumulator);

    th = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if (th == NULL)
        return;
    th = (struct tcphdr *)((ULONG_PTR)th + mdlOffset);

    if (th->checksum != csum && lsoInfo.LsoV1Transmit.MSS == 0)
        TraceWarning(("bad pseudo header checksum in non-LSO packet: found %04x, expected %04x\n",
                      th->checksum,
                      csum));

    th->checksum = csum;
}

NDIS_STATUS
TransmitterSendNetBufferLists (
    IN  PTRANSMITTER        Transmitter,
    IN  PNET_BUFFER_LIST*   NetBufferList,
    IN  NDIS_PORT_NUMBER    PortNumber,
    IN  ULONG               SendFlags
    )
{
    PNET_BUFFER_LIST currNetBufferList;
    BOOLEAN dpcLevel;
    PXENNET_NET_BUFFER_LIST_RESERVED listReserved;
    PNET_BUFFER netBuffer;
    PNET_BUFFER_LIST nextNetBufferList;
    NDIS_STATUS ndisStatus = NDIS_STATUS_PENDING;

    UNREFERENCED_PARAMETER(PortNumber);
    dpcLevel = NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendFlags) ? TRUE : FALSE;

    if (AdapterIsStopped(Transmitter->Adapter)) {
        ndisStatus = NDIS_STATUS_PAUSED;
        goto done;
    }

    if (Transmitter->Adapter->RemovalPending) {
        ndisStatus = NDIS_STATUS_PAUSED;
        /* If blocked by PnP removal notification, should return this status */
        TraceWarning(("Transmitting buffer lists during pending removal\n"));
        goto done;
    }

    for (currNetBufferList = *NetBufferList;
         currNetBufferList != NULL;
         currNetBufferList = nextNetBufferList) {
        PXENNET_NET_BUFFER_RESERVED xennetBuffer;

        nbl_log(currNetBufferList, NBL_TRANSMITTER_SEND2);

        nextNetBufferList = NET_BUFFER_LIST_NEXT_NBL(currNetBufferList);
        NET_BUFFER_LIST_NEXT_NBL(currNetBufferList) = NULL;

        listReserved = (PXENNET_NET_BUFFER_LIST_RESERVED)XENNET_GET_NET_BUFFER_LIST_RESERVED(currNetBufferList);        
        memset(listReserved, 0, sizeof (XENNET_NET_BUFFER_LIST_RESERVED));

        XM_ASSERT3P(NET_BUFFER_LIST_FIRST_NB(currNetBufferList), !=, NULL);
        for (netBuffer = NET_BUFFER_LIST_FIRST_NB(currNetBufferList);
             netBuffer != NULL; 
             netBuffer = NET_BUFFER_NEXT_NB(netBuffer)) {

            XM_ASSERT3U(NET_BUFFER_DATA_LENGTH(netBuffer), <=, XENNET_BOUNCE_BUFFER_SIZE);

            xennetBuffer = XENNET_GET_NET_BUFFER_RESERVED(netBuffer);

            /* Only init the miniport context region here if this is not a WLAN
             * driver. The WLAN driver uses the miniport context and will initialize it
             * prior to this call.
             */
#ifndef XEN_WIRELESS
            memset(xennetBuffer, 0, sizeof (XENNET_NET_BUFFER_RESERVED));
#endif

            nbl_log(currNetBufferList, NBL_TRANSMITTER_SEND2_BUFFER,
                    (ULONG_PTR)netBuffer);
            xennetBuffer->Magic = XENNET_BUFFER_MAGIC;
            xennetBuffer->Bounced = 0;
            xennetBuffer->NetBufferList = currNetBufferList;
            /* Note that NdisQueryNetBufferPhysicalCount() gives the number of 'physical breaks'
               This gives us an upper bound on the number of segments; we may actually
               need less than this. */
            xennetBuffer->PhysicalBufferCount = (USHORT)NdisQueryNetBufferPhysicalCount(netBuffer) + 1;
            xennetBuffer->State = Unprepared;
            xennetBuffer->TxShadowHeadId = XENNET_INVALID_TX_SHADOW_ID;

            if (Transmitter->IpChecksumOffload)
                TransmitterFixupIpChecksum(netBuffer,
                                           currNetBufferList);

            if (Transmitter->TcpChecksumOffload)
                TransmitterFixupTcpChecksum(netBuffer,
                                            currNetBufferList);
        }

        XennetAcquireSpinLock(&Transmitter->Lock, dpcLevel);
        TransmitterSanityCheck(Transmitter);

        if (Transmitter->PauseState != TransmitterPauseRunning ||
            !Transmitter->Adapter->MediaConnected) {
            XennetReleaseSpinLock(&Transmitter->Lock, dpcLevel);

            NET_BUFFER_LIST_NEXT_NBL(currNetBufferList) = nextNetBufferList;

            ndisStatus = NDIS_STATUS_PAUSED;
            break;
        }

        InsertTailList(&Transmitter->QueuedList, &listReserved->ListEntry);

        Transmitter->QueuedCount++;

        TransmitterSanityCheck(Transmitter);
        XennetReleaseSpinLock(&Transmitter->Lock, dpcLevel);
    }
    *NetBufferList = currNetBufferList;

done:
    XennetAcquireSpinLock(&Transmitter->Lock, dpcLevel);
    TransmitterSanityCheck(Transmitter);
    TransmitterRun(Transmitter, dpcLevel);
    TransmitterSanityCheck(Transmitter);
    XennetReleaseSpinLock(&Transmitter->Lock, dpcLevel);    

    return ndisStatus;
}

static VOID
TransmitterUpdateStatistics (
    IN  PTRANSMITTER    Transmitter,
    IN  PNET_BUFFER     NetBuffer
    )
{
    PUCHAR ethHeader;
    ULONG length;
    PMDL mdl = NET_BUFFER_CURRENT_MDL(NetBuffer);
    ULONG nbLength = NET_BUFFER_DATA_LENGTH(NetBuffer);

    NdisQueryMdl(mdl, &ethHeader, &length, NormalPagePriority);
    if (ethHeader != NULL) {
        ethHeader += NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer);
        if (ETH_IS_BROADCAST(ethHeader)) {
            Transmitter->BroadcastPkts++;
            Transmitter->BroadcastOctets += nbLength;

        } else if (ETH_IS_MULTICAST(ethHeader)) {
            Transmitter->MulticastPkts++;
            Transmitter->MulticastOctets += nbLength;

        } else{
            Transmitter->UcastPkts++;
            Transmitter->UcastOctets += nbLength;
        }
    }

    return;
}

VOID
TransmitterWaitForIdle (
    PTRANSMITTER    Transmitter,
    BOOLEAN         Locked
    )
{
    LARGE_INTEGER delay1s;

    delay1s.QuadPart = -1000000;

    if (!Locked)
        XennetAcquireSpinLock(&Transmitter->Lock, FALSE);

    while (!IsListEmpty(&Transmitter->QueuedList)) {
        TraceWarning(("%s: %d outstanding\n", __FUNCTION__,
                      Transmitter->QueuedCount));

        TransmitterSanityCheck(Transmitter);
        TransmitterRun(Transmitter, FALSE);
        TransmitterSanityCheck(Transmitter);

        XennetReleaseSpinLock(&Transmitter->Lock, FALSE);    
        KeDelayExecutionThread(KernelMode, FALSE, &delay1s);
        XennetAcquireSpinLock(&Transmitter->Lock, FALSE);
    }
    XM_ASSERT3U(Transmitter->QueuedCount, ==, 0);
    XM_ASSERT3U(Transmitter->TxShadowInfo.AvailableShadows, ==, XENNET_MAX_TX_FRAGS);
    TransmitterSanityCheck(Transmitter);

    if (!Locked)
        XennetReleaseSpinLock(&Transmitter->Lock, FALSE);    

    return ;
}

void
TransmitterPause(PTRANSMITTER Transmitter)
{
    TraceVerbose(("====> %s\n", __FUNCTION__));

    NdisAcquireSpinLock(&Transmitter->Lock);

    XM_ASSERT3U(Transmitter->PauseState, ==, TransmitterPauseRunning);
    Transmitter->PauseState = TransmitterPausePausing;

    TransmitterWaitForIdle(Transmitter, TRUE);

    Transmitter->PauseState = TransmitterPausePaused;
    NdisReleaseSpinLock(&Transmitter->Lock);

    TraceVerbose(("<==== %s\n", __FUNCTION__));
}

void
TransmitterUnpause(PTRANSMITTER Transmitter)
{
    TraceVerbose(("====> %s\n", __FUNCTION__));

    NdisAcquireSpinLock(&Transmitter->Lock);
    XM_ASSERT3U(Transmitter->PauseState, ==, TransmitterPausePaused);
    Transmitter->PauseState = TransmitterPauseRunning;
    NdisReleaseSpinLock(&Transmitter->Lock);

    TraceVerbose(("<==== %s\n", __FUNCTION__));
}

#if XENNET6_TRANSMITTER_SANITY
#pragma warning(disable: 4100)

static void
_TransmitterSanityCheck(PTRANSMITTER Transmitter, unsigned line)
{
    PLIST_ENTRY ple;
    PNET_BUFFER netBuffer;
    PXENNET_NET_BUFFER_RESERVED xennetBuffer;
    PXENNET_NET_BUFFER_LIST_RESERVED listReserved;
    PNET_BUFFER_LIST netBufferList;
    PXENNET_TX_SHADOW txShadow;
    netif_tx_id_t index;
    unsigned nr_bufs;
    unsigned count;

    TraceDebug(("Transmitter sanity check from %d\n", line));

    XM_ASSERT(Transmitter->Adapter != NULL);
    XM_ASSERT(Transmitter->QueuedList.Flink != NULL);
    XM_ASSERT(Transmitter->QueuedList.Blink != NULL);

    count = 0;
    for (ple = Transmitter->QueuedList.Flink;
         ple != &Transmitter->QueuedList;
         ple = ple->Flink) {
        XM_ASSERT(ple != NULL);
        listReserved = CONTAINING_RECORD(ple,
                                         XENNET_NET_BUFFER_LIST_RESERVED, 
                                         ListEntry);
        netBufferList = XENNET_GET_NET_BUFFER_LIST_FROM_RESERVED(listReserved);
        nbl_log(netBufferList, NBL_TRANSMITTER_SANITY_CHECK);
        for (netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
             netBuffer;
             netBuffer = NET_BUFFER_NEXT_NB(netBuffer)) {
            xennetBuffer = XENNET_GET_NET_BUFFER_RESERVED(netBuffer);
            nbl_log(netBufferList, NBL_TRANSMITTER_SANITY_CHECK_BUFFER,
                    (ULONG_PTR)netBuffer);
            XM_ASSERT3U(xennetBuffer->Magic, ==, XENNET_BUFFER_MAGIC);
            XM_ASSERT3U(xennetBuffer->State, >=, Unprepared);
            XM_ASSERT3U(xennetBuffer->State, <=, Drop);
            XM_ASSERT3U(xennetBuffer->NetBufferList, ==, netBufferList);
            if (xennetBuffer->State == Prepared ||
                xennetBuffer->State == Sent) {
                XM_ASSERT(xennetBuffer->PhysicalBufferCount != 0);
                XM_ASSERT(TxIdValid(xennetBuffer->TxShadowHeadId));
                nr_bufs = 0;
                for (index = xennetBuffer->TxShadowHeadId;
                     TxIdValid(index);
                     index = txShadow->Next) {
                    txShadow = TransmitterGetTxShadow(Transmitter, index);
                    nbl_log(netBufferList,
                            NBL_TRANSMITTER_SANITY_SHADOW,
                            (ULONG_PTR)netBuffer,
                            index.__id,
                            txShadow->IsExtra |
                            (txShadow->InUse << 1) |
                            (txShadow->OwnedByBackend << 1) |
                            (txShadow->IsFakeArp << 1));
                    XM_ASSERT(txShadow->InUse);
                    if (xennetBuffer->State == Prepared) {
                        XM_ASSERT(!txShadow->OwnedByBackend);
                        if (!txShadow->IsExtra)
                            nr_bufs++;
                    } else {
                        if (txShadow->OwnedByBackend &&
                            !txShadow->IsExtra)
                            nr_bufs++;
                    }
                    XM_ASSERT(!txShadow->IsFakeArp);
                    if (txShadow->IsExtra)
                        XM_ASSERT3P(txShadow->Buffer, ==, NULL);
                    else
                        XM_ASSERT3P(txShadow->Buffer, ==, netBuffer);
                }
                XM_ASSERT3U(nr_bufs, ==,
                            xennetBuffer->PhysicalBufferCount);
            }
        }
        count++;
    }
    XM_ASSERT3U(Transmitter->QueuedCount, ==, count);
}
#else
static void
_TransmitterSanityCheck(PTRANSMITTER t, unsigned line)
{
    UNREFERENCED_PARAMETER(t);
    UNREFERENCED_PARAMETER(line);
}
#endif

