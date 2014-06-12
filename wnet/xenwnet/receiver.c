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

#pragma warning( push, 3 )
#include "precomp.h"
#include "scsiboot.h"
#include "netif.h"
#include "xennet_common.h"
#include "..\xenutil\registry.h"
#pragma warning( pop )

struct PacketOverlayRx {
    PNDIS_PACKET next; /* Linked list of packets queued for release */
};
#define PACKET_RX_OVERLAY(pkt) ((struct PacketOverlayRx *)&(pkt)->MiniportReservedEx[0])
 
CASSERT(sizeof(struct PacketOverlayRx) <= 3 * sizeof(PVOID));

static NDIS_STATUS ReceiverInitializeBuffers(PRECEIVER Receiver);

static VOID
ReceiverInitializeConfiguration(PRECEIVER Receiver)
{
    PKEY_VALUE_PARTIAL_INFORMATION pInfo;
    NTSTATUS status;

#ifndef XEN_WIRELESS
    status = XenReadRegistryValue(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\xennet\\Parameters",
#else
    status = XenReadRegistryValue(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\xenwnet\\Parameters",
#endif
                                  L"LowResources",
                                  &pInfo);
    if (!NT_SUCCESS(status)) {
        TraceVerbose(("LowResources switch: not present\n"));
        goto done;
    }

    if (pInfo->Type != REG_DWORD) {
        TraceError(("LowResources switch: wrong type\n"));
        ExFreePool(pInfo);
        goto done;
    }

    Receiver->LowResources = *(DWORD *)pInfo->Data;
    ExFreePool(pInfo);

done:
    TraceInfo(("LowResources: %08x\n", Receiver->LowResources));
}

NDIS_STATUS
ReceiverInitialize(PRECEIVER Receiver, PADAPTER Adapter)
{
    NDIS_STATUS stat;

    stat = ReceiverCommonInitialize(&Receiver->Common, Adapter);
    if (stat != NDIS_STATUS_SUCCESS)
        return stat;

    stat = ReceiverInitializeBuffers(Receiver);
    if (stat != NDIS_STATUS_SUCCESS)
        return stat;

    ReceiverInitializeConfiguration(Receiver);

    return NDIS_STATUS_SUCCESS;
}

void
ReceiverCleanup(PRECEIVER Receiver)
{
    ReceiverCommonCleanup(&Receiver->Common);
    ReceiverCommonCleanupBuffers(&Receiver->Common);

    if (Receiver->RecvPacketPool != NULL) {
        TraceDebug (("Freeing packet pool.\n"));
        NdisFreePacketPool(Receiver->RecvPacketPool);
        Receiver->RecvPacketPool = NULL;
    }
}

static NDIS_STATUS
ReceiverInitializeBuffers(PRECEIVER Receiver)
{
    NDIS_STATUS Status;

    /* We must always be able to allocate a packet from DoRxPacket. */
    NdisAllocatePacketPoolEx(
            &Status,
            &Receiver->RecvPacketPool,
            XENNET_MAX_RFDS,
            0xffff - XENNET_MAX_RFDS,
            PROTOCOL_RESERVED_SIZE_IN_PACKET);

    if (Status != NDIS_STATUS_SUCCESS)
        return Status;

    return ReceiverCommonInitializeBuffers(&Receiver->Common);
}

/* Release a packet now that NDIS is finished with it. */
/* Maps to ReceiverReleaseNetBufferList() in xennet6 */
static void
ReceiverReleasePacket(PRECEIVER Receiver, PNDIS_PACKET Packet)
{
    PMDL headMdl;

    NdisQueryPacket(Packet, NULL, NULL, &headMdl, NULL);
    ReceiverCommonReleaseMdlChain(&Receiver->Common, headMdl);
    NdisDprFreePacketNonInterlocked(Packet);
}

/* Maps to ReceiverReturnNetBufferListList() in xennet6 */
VOID
MPReturnPacket(
    IN  NDIS_HANDLE     MiniportAdapterContext,
    IN  PNDIS_PACKET    Packet
)
/*++

Routine Description:

    MiniportReturnPacket handler

Arguments:

    MiniportAdapterContext  Pointer to our adapter
    Packet                  Pointer to a packet being returned to the miniport

Return Value:

    None

Note:
    ReturnPacketHandler is called at DPC. take advantage of this fact when acquiring or releasing
    spinlocks

--*/
{
    PADAPTER Adapter = (PADAPTER)MiniportAdapterContext;
    PRECEIVER Receiver = &Adapter->Receiver;
    PNDIS_PACKET *pReturnList = &Receiver->ReturnList;
    PNDIS_PACKET Old;

    do {
        Old = *pReturnList;
        
        PACKET_RX_OVERLAY(Packet)->next = Old;
    } while (InterlockedCompareExchangePointer(pReturnList, Packet, Old) != Old);

    /* The synchronisation isn't right here, but that's okay, because
       it's only a debug aid anyway (and synchronising would be too
       expensive, anyway). */
    Receiver->nPendingSwizzle++;
    if (Receiver->nPendingSwizzle > Receiver->nPendingSwizzleMax)
        Receiver->nPendingSwizzleMax = Receiver->nPendingSwizzle;

    TraceProfile(("%s(%s, %p)\n", __FUNCTION__, Adapter->XenbusPrefix, Packet));
}

static VOID
ReceiverSwizzle(
    IN  PRECEIVER   Receiver
)
{
    PADAPTER        Adapter = Receiver->Common.Adapter;
    PNDIS_PACKET    *pReturnList = &Receiver->ReturnList;
    PNDIS_PACKET    Packet;

    Packet = InterlockedExchangePointer(pReturnList, NULL);

    while (Packet != NULL) {
        PNDIS_PACKET Next = PACKET_RX_OVERLAY(Packet)->next;
        
        ReceiverReleasePacket(Receiver, Packet);
        Receiver->nRxInNdis--;

        Packet = Next;
    }

    Receiver->nPendingSwizzle = 0;
    if (ReceiverCommonReplenishRxRing(&Receiver->Common)) {
        EvtchnNotifyRemote(Adapter->evtchn);
        Receiver->nRemoteNotifies++;
    }
}

/* We've received a csum_blank packet, but we don't want to let
   Windows see it like.  Calculate the checksum and dump it in the
   packet.  This only works for TCP and UDP on IPv4; on anything else
   it's a no-op. */
static VOID
FixupChecksum(PNDIS_PACKET packet)
{
    PNDIS_BUFFER pbuf;
    PNDIS_BUFFER pbuf_next;
    UINT bufLength;
    UINT len;
    struct ethhdr *eh;
    struct iphdr *ih;
    uint32_t csum_accumulator;
    uint32_t *ptr;
    uint16_t *csum_field;

    NdisQueryPacket(packet, NULL, NULL, &pbuf, NULL);
    NdisQueryBufferSafe(pbuf, &eh, &bufLength, NormalPagePriority);
    if (!eh || bufLength < sizeof(*eh))
        return;
    if (eh->proto != TPID_IPV4) {
        static BOOLEAN warned;
        if (!warned) {
            TraceWarning(("Asked to perform checksum calculation on non-IP ethernet prototocol %x!\n", eh->proto));
            warned = TRUE;
        }
        return;
    }
    ih = (struct iphdr *)(eh + 1);
    bufLength -= sizeof(*eh);
    if (bufLength < sizeof(*ih) ||
        bufLength < (UINT)(ih->len_version & 0x0f) * 4)
        return;
    ptr = (uint32_t *)((ULONG_PTR)ih + (ih->len_version & 0x0f)*4);
    len = ntohs(ih->tot_len) - (ih->len_version & 0x0f) * 4;

    bufLength -= (ih->len_version & 0x0f) * 4;
    if (bufLength > len)
        bufLength = len;

    if (ih->proto == IPPROTO_UDP) {
        if (bufLength < sizeof(struct udphdr))
            return;
        csum_field = &((struct udphdr *)ptr)->checksum;
    } else if (ih->proto == IPPROTO_TCP) {
        if (bufLength < sizeof(struct tcphdr))
            return;
        csum_field = &((struct tcphdr *)ptr)->checksum;
    } else {
        static BOOLEAN warned;
        /* Uh oh: don't know what this protocol is, so can't do
           checksum calculation for it. */
        if (!warned) {
            TraceWarning(("Asked to perform checksum calculation for unknown protocol %d!\n",
                          ih->proto));
            warned = TRUE;
        }
        return;
    }

    if (ih->proto == IPPROTO_TCP) {
        struct tcp_pseudo_header tph;
        uint16_t csum;

        tph.saddr = ih->src;
        tph.daddr = ih->dest;
        tph.mbz = 0;
        tph.ptcl = IPPROTO_TCP;
        tph.length = htons((uint16_t)len);

        csum_accumulator = acc_ip_csum(&tph, sizeof(tph), 0);
        csum = fold_ip_csum(csum_accumulator);

        if (*csum_field != csum)
            TraceWarning(("invlid pseudo header checksum: expected %04x, found %04x\n", csum, *csum_field));

        *csum_field = csum;
    }

    csum_accumulator = acc_ip_csum(ptr, bufLength, 0);
    len -= bufLength;

    while (len) {
        NdisGetNextBuffer(pbuf, &pbuf_next);
        if (pbuf_next == NULL)
            break;
        pbuf = pbuf_next;
        NdisQueryBufferSafe(pbuf, &ptr, &bufLength, NormalPagePriority);

        /* The buffer is already mapped into our RX buffer pool, so we
           should always be able to get a virtual address for it. */
        XM_ASSERT(ptr != NULL);

        if (bufLength > len)
            bufLength = len;

        csum_accumulator = acc_ip_csum(ptr, bufLength, csum_accumulator);
        len -= bufLength;
    }

    *csum_field = ~fold_ip_csum(csum_accumulator);
}

/* Invoked from the RX DPC.  Receives a single packet and returns a
   pointer to it.  prod is the observed produce pointer on the RX ring
   and is used to assert that the backend is not misbehaving. */
/* Maps to ReceiverReceiveNetBufferList() in xennet6 */
static NTSTATUS
ReceiverReceivePacket(
    IN  PRECEIVER       Receiver,
    OUT PNDIS_PACKET    *pPacket,
    OUT ULONG           *pTotFrags
    )
{
    struct ethhdr *eh;
    PNDIS_PACKET work;
    NDIS_STATUS stat;
    PNDIS_BUFFER buffer;
    uint16_t head_flags;
    UINT buffer_length;
    ULONG totOctets;
    ULONG totFrags;
    PMP_RFD prefixRfd;
    PMP_RFD headRfd;

    stat = ReceiverCommonReceiveRfdChain(Receiver, &head_flags, &prefixRfd,
                                         &headRfd, &totOctets, &totFrags);
    if (stat != NDIS_STATUS_SUCCESS) {
        Receiver->Common.Adapter->RxError++;
        goto discard;
    }
    XM_ASSERT(totFrags > 0);

    /* There should never be a prefix as we do not enable GSO on the
       receive path. */
    XM_ASSERT(prefixRfd == NULL);

    NdisDprAllocatePacketNonInterlocked(&stat, &work,
                                        Receiver->RecvPacketPool);
    if (stat != NDIS_STATUS_SUCCESS) {
        Receiver->nRxDiscards++;
        goto discard;
    }

    NDIS_SET_PACKET_HEADER_SIZE(work, XENNET_PACKET_HDR_SIZE);
    NdisChainBufferAtFront(work, &headRfd->Mdl);

    /* Ick: find the ethernet and IP headers so that we can check (a)
       the MAC address is for us, and (b) whether to indicate RX csum
       offload.  We rely on the fact that netback always puts the
       ethernet and IP headers in the same fragment. */

    buffer = &headRfd->Mdl;
    buffer_length = buffer->ByteCount;

    stat = STATUS_UNSUCCESSFUL;
    if (buffer_length < sizeof(struct ethhdr)) {
        NdisDprFreePacketNonInterlocked(work);
        Receiver->nRxDiscards++;
        goto discard;
    }
        
    Receiver->Common.Adapter->RxGood++;

    eh = (struct ethhdr *)buffer->MappedSystemVa;

    stat = NDIS_STATUS_INVALID_PACKET;
    if (!MacAddressInteresting(eh->dest, Receiver->Common.Adapter)) {
        Receiver->Common.Adapter->MacMisdirect++;
        NdisDprFreePacketNonInterlocked(work);
        goto discard;
    }

    if (eh->proto == TPID_IPV4) {
        BOOLEAN needCsumFixup;
        NDIS_TCP_IP_CHECKSUM_PACKET_INFO CsumInfo;

        CsumInfo.Value = 0;

        needCsumFixup = (head_flags & NETRXF_csum_blank) ? TRUE : FALSE;

        if (head_flags & NETRXF_data_validated) {
            struct iphdr *ih = (struct iphdr *)(eh + 1);

            if (ih->proto == IPPROTO_TCP &&
                Receiver->rx_csum_tcp_offload) {
                CsumInfo.Receive.NdisPacketTcpChecksumSucceeded = 1;
                Receiver->nRxCsumOffload++;
            } else if (ih->proto == IPPROTO_UDP &&
                       Receiver->rx_csum_udp_offload) {
                CsumInfo.Receive.NdisPacketUdpChecksumSucceeded = 1;
                Receiver->nRxCsumOffload++;
            }
        }

        if (needCsumFixup) {
            FixupChecksum(work);
            Receiver->nRxCsumFixup++;
        }

        NDIS_PER_PACKET_INFO_FROM_PACKET(work, TcpIpChecksumPacketInfo) =
            (PVOID)(ULONG_PTR)CsumInfo.Value;
    }

    NDIS_SET_PACKET_STATUS(work, NDIS_STATUS_SUCCESS);

    *pPacket = work;
    *pTotFrags = totFrags;

    return NDIS_STATUS_SUCCESS;

discard:
    ReceiverCommonReleaseRfdChain(&Receiver->Common, prefixRfd);
    ReceiverCommonReleaseRfdChain(&Receiver->Common, headRfd);

    return stat;
}

VOID
ReceiverHandleNotification(
    IN  PRECEIVER Receiver
)
/*++
Routine Description:

    Interrupt handler for receive processing
    Put the received packets into an array and call NdisMIndicateReceivePacket
    If we run low on RFDs, allocate another one

Arguments:

    Adapter     Pointer to our adapter

Return Value:

    None
    
--*/
{
    PADAPTER        Adapter = Receiver->Common.Adapter;
    RING_IDX        prod;
    int             more_work;
    PNDIS_PACKET    PacketArray[XENNET_DEF_RFDS];
    NDIS_STATUS     PacketStatus[XENNET_DEF_RFDS];
    UINT            PacketCount;

    if (!RING_HAS_UNCONSUMED_RESPONSES(&Receiver->Common.Ring))
        return;

    NdisDprAcquireSpinLock(&Receiver->Common.Lock);
    if (Receiver->Common.Adapter->media_disconnect) {
        NdisDprReleaseSpinLock(&Receiver->Common.Lock);
        return;
    }

    if (__RING_IDX_DIFFERENCE(Receiver->Common.Ring.req_prod_pvt,
                              Receiver->Common.Ring.sring->rsp_prod) >
        NET_RX_RING_SIZE)
        TraceWarning(("Strange: rsp_prod ahead of req_prod (%d vs %d (s %d))\n",
                      Receiver->Common.Ring.sring->rsp_prod,
                      Receiver->Common.Ring.req_prod_pvt,
                      Receiver->Common.Ring.sring->req_prod));

    PacketCount = 0;

 top:
    prod = Receiver->Common.Ring.sring->rsp_prod;
    XsMemoryBarrier();
    while (!RING_IDXS_EQ(Receiver->Common.Ring.rsp_cons, prod)) {
        PNDIS_PACKET packet;
        ULONG totFrags;
        NDIS_STATUS status;

        status = ReceiverReceivePacket(Receiver, &packet, &totFrags);
        if (status != NDIS_STATUS_SUCCESS)
            continue;

        TraceProfile(("%s(%s, %p)\n", __FUNCTION__, Adapter->XenbusPrefix, packet));

        // See http://msdn.microsoft.com/en-us/library/ms797610.aspx
        if (Receiver->LowResources == 2 ||
            (Receiver->LowResources == 1 && totFrags > 1)) {
            status = NDIS_STATUS_RESOURCES;
            NDIS_SET_PACKET_STATUS(packet, status);
        }

        PacketArray[PacketCount] = packet;
        PacketStatus[PacketCount] = status;
        PacketCount++;

        if (PacketCount == XENNET_DEF_RFDS) {
            ULONG Index;

            Receiver->Common.Frames += PacketCount;
            Receiver->nRxInNdis += PacketCount;

            if (Receiver->nRxInNdis >= Receiver->nRxInNdisMax)
                Receiver->nRxInNdisMax = Receiver->nRxInNdis;

            NdisDprReleaseSpinLock(&Receiver->Common.Lock);
            NdisMIndicateReceivePacket(
                Receiver->Common.Adapter->AdapterHandle,
                PacketArray,
                PacketCount);
            NdisDprAcquireSpinLock(&Receiver->Common.Lock);

            for (Index = 0; Index < PacketCount; Index++) {
                if (PacketStatus[Index] == NDIS_STATUS_RESOURCES) {
                    ReceiverReleasePacket(Receiver, PacketArray[Index]);
                    Receiver->nRxInNdis--;
                } else {
                   XM_ASSERT(PacketStatus[Index] == NDIS_STATUS_SUCCESS);
                }
            }
            PacketCount = 0;

            ReceiverSwizzle(Receiver);
        }
    }
    RING_FINAL_CHECK_FOR_RESPONSES(&Receiver->Common.Ring, more_work);
    if (more_work)
        goto top;

    if (PacketCount != 0) {
        ULONG Index;

        Receiver->Common.Frames += PacketCount;
        Receiver->nRxInNdis += PacketCount;

        if (Receiver->nRxInNdis >= Receiver->nRxInNdisMax)
            Receiver->nRxInNdisMax = Receiver->nRxInNdis;

        NdisDprReleaseSpinLock(&Receiver->Common.Lock);
        NdisMIndicateReceivePacket(
            Receiver->Common.Adapter->AdapterHandle,
            PacketArray,
            PacketCount);
        NdisDprAcquireSpinLock(&Receiver->Common.Lock);

        for (Index = 0; Index < PacketCount; Index++) {
            if (PacketStatus[Index] == NDIS_STATUS_RESOURCES) {
                ReceiverReleasePacket(Receiver, PacketArray[Index]);
                Receiver->nRxInNdis--;
            } else {
                XM_ASSERT(PacketStatus[Index] == NDIS_STATUS_SUCCESS);
            }
        }
        PacketCount = 0;
    }

    // Swizzle unconditionally to make sure we replenish the ring even if
    // nothing was passed to NDIS.
    ReceiverSwizzle(Receiver);

    NdisDprReleaseSpinLock(&Receiver->Common.Lock);
    /* XXX Should maybe adjust size of packet pool from here. */
}

/* Wait for NDIS to return any outstanding packets.  The caller must
   already have taken some appropriate measures to make sure that no
   more packets arrive in the meantime. */
void
ReceiverWaitForPacketReturn(PRECEIVER Receiver)
{
    LARGE_INTEGER interval;

    interval.QuadPart = -100000; /* 100ms in units of 100ns */

    NdisAcquireSpinLock(&Receiver->Common.Lock);
    while (Receiver->nRxInNdis) {
        TraceVerbose (("%d rx.\n", Receiver->nRxInNdis));

        NdisReleaseSpinLock(&Receiver->Common.Lock);
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        NdisAcquireSpinLock(&Receiver->Common.Lock);

        ReceiverSwizzle(Receiver);
    }
    NdisReleaseSpinLock(&Receiver->Common.Lock);
}

void
ReceiverDebugDump(PRECEIVER Receiver)
{
    TraceInternal(("%d/%d RFDs in NDIS current/max since last report (%d pending swizzle, %d max).\n",
                   Receiver->nRxInNdis,
                   Receiver->nRxInNdisMax,
                   Receiver->nPendingSwizzle,
                   Receiver->nPendingSwizzleMax));
    Receiver->nRxInNdisMax = Receiver->nRxInNdis;
    Receiver->nPendingSwizzleMax = Receiver->nPendingSwizzle;

    TraceInternal(("%d remote notifications since last report.\n",
                   Receiver->nRemoteNotifies));
    Receiver->nRemoteNotifies = 0;

    TraceInternal(("rx_csum: udp %d, tcp %d; done %d/%d rx csum offloads/fixups.\n",
                   Receiver->rx_csum_udp_offload,
                   Receiver->rx_csum_tcp_offload,
                   Receiver->nRxCsumOffload,
                   Receiver->nRxCsumFixup));
    TraceInternal(("%d RX discards\n", Receiver->nRxDiscards));

    ReceiverCommonDebugDump(&Receiver->Common);
}
