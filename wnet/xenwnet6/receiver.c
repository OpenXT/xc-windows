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

/* Receiver processing.  Because this is a receiver, and because NDIS6
   is completely insane, all NET_BUFFER_LISTs must contain only a
   single NET_BUFFER.  You can therefore almost identify them. */
#include "common.h"
#ifdef XEN_WIRELESS
#include "wlan.h"
#endif

static NDIS_STATUS
ReceiverInitializeBuffers (
    IN  PRECEIVER   Receiver
    );

static VOID
ReceiverUpdateStatistics (
    IN PRECEIVER        Receiver,
    IN PNET_BUFFER_LIST NetBufferList,
    IN ULONG            Octets
    );

NDIS_STATUS
ReceiverInitialize (
    IN  PRECEIVER   Receiver,
    IN  PADAPTER    Adapter
    )
{
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;

    XM_ASSERT(Receiver != NULL);
    XM_ASSERT(Adapter != NULL);
    XM_ASSERT(Adapter->GrantCache != NULL);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    ndisStatus = ReceiverCommonInitialize(&Receiver->Common, Adapter);
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        goto exit;
    }

    ndisStatus = ReceiverInitializeBuffers(Receiver);
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        goto exit;
    }

exit:
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return ndisStatus;
}

VOID 
ReceiverCleanup (
    IN  PRECEIVER Receiver,
    BOOLEAN TearDown
    )
{
    XM_ASSERT(Receiver != NULL);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (TearDown)
        Receiver->Common.NrFreeIds = MAX_RX_FRAGS;

    ReceiverCommonCleanup(&Receiver->Common);
    ReceiverCommonCleanupBuffers(&Receiver->Common);

    if (Receiver->NetBufferListPool) {
        NdisFreeNetBufferListPool(Receiver->NetBufferListPool);
        Receiver->NetBufferListPool = NULL;
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}

static NDIS_STATUS
ReceiverInitializeBuffers (
    IN  PRECEIVER   Receiver
    )
{
    NDIS_STATUS ndisStatus;
    NET_BUFFER_LIST_POOL_PARAMETERS poolParameters;

    XM_ASSERT(Receiver->Common.Adapter);
    XM_ASSERT(Receiver->Common.Adapter->NdisAdapterHandle);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    NdisZeroMemory(&poolParameters, sizeof(NET_BUFFER_LIST_POOL_PARAMETERS));
    poolParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    poolParameters.Header.Revision =
        NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    poolParameters.Header.Size = sizeof(poolParameters);
    poolParameters.ProtocolId = 0;
    poolParameters.ContextSize = 0;
    poolParameters.fAllocateNetBuffer = TRUE;
    poolParameters.PoolTag = XENNET_TAG;
    Receiver->NetBufferListPool =
        NdisAllocateNetBufferListPool(Receiver->Common.Adapter->NdisAdapterHandle,
                                      &poolParameters);
    if (!Receiver->NetBufferListPool) {
        ndisStatus = NDIS_STATUS_RESOURCES;
        goto exit;
    }

    ndisStatus = ReceiverCommonInitializeBuffers(&Receiver->Common);

exit:
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return ndisStatus;
}

/* Maps to ReceiverReleasePacket() in xennet5 */
static VOID
ReceiverReleaseNetBufferList (
    IN  PRECEIVER           Receiver,
    IN  PNET_BUFFER_LIST    BufferList
    )
{
    NDIS_NET_BUFFER_LIST_8021Q_INFO ndis8021QInfo;
    PNET_BUFFER buffer;
    PMDL mdl;

    ndis8021QInfo.Value = NET_BUFFER_LIST_INFO(BufferList,
                                               Ieee8021QNetBufferListInfo);
    if (ndis8021QInfo.TagHeader.UserPriority != 0) {
        NET_BUFFER_LIST_INFO(BufferList, Ieee8021QNetBufferListInfo) = 0;
        NdisRetreatNetBufferListDataStart(BufferList,
                                          4, /* sizeof(tci_header+protocol) */
                                          0,
                                          NULL,
                                          NULL);
    }

    buffer = NET_BUFFER_LIST_FIRST_NB(BufferList);

    /* We only ever have one netbuffer on each net buffer list. */
    XM_ASSERT3P(NET_BUFFER_NEXT_NB(buffer), ==, NULL);

    /* The net buffer will be automatically released when the net
       buffer list is, but we still need to clean it up. */
    mdl = NET_BUFFER_FIRST_MDL(buffer);
#ifdef USE_V4V
    if ((mdl != Receiver->V4vRxBufMdl) && (mdl->Next != Receiver->V4vRxBufMdl))
#endif
        ReceiverCommonReleaseMdlChain(&Receiver->Common,
                                  NET_BUFFER_FIRST_MDL(buffer));

    NdisFreeNetBufferList(BufferList);
}

/* Maps to MPReturnPacket() in xennet5 */
VOID 
ReceiverReturnNetBufferListList (
    IN  PRECEIVER           Receiver,
    IN  PNET_BUFFER_LIST    NetBufferLists,
    IN  ULONG               ReturnFlags
    )
{
    PNET_BUFFER_LIST Head;
    PNET_BUFFER_LIST Tail;
    PNET_BUFFER_LIST Old;

    UNREFERENCED_PARAMETER(ReturnFlags);

#ifdef XEN_WIRELESS
    WlanReceiveReturnNetBufferLists(Receiver->Common.Adapter, NetBufferLists);
#endif

    Tail = Head = NetBufferLists;
    while (NET_BUFFER_LIST_NEXT_NBL(Tail) != NULL)
        Tail = NET_BUFFER_LIST_NEXT_NBL(Tail);

    do {
        Old = Receiver->ReturnList;
        NET_BUFFER_LIST_NEXT_NBL(Tail) = Old;
    } while (InterlockedCompareExchangePointer(&Receiver->ReturnList, Head, Old) != Old);
}

static void
ReceiverSwizzle(
    IN  PRECEIVER       Receiver
    )
{
    PADAPTER            Adapter = Receiver->Common.Adapter;
    PNET_BUFFER_LIST    *pReturnList = &Receiver->ReturnList;
    PNET_BUFFER_LIST    Buffer;

    Buffer = InterlockedExchangePointer(pReturnList, NULL);
    while (Buffer != NULL) {
        PNET_BUFFER_LIST Next = NET_BUFFER_LIST_NEXT_NBL(Buffer);

        ReceiverReleaseNetBufferList(Receiver, Buffer);

        XM_ASSERT3U(Receiver->nRxInNdis, !=, 0);
        Receiver->nRxInNdis--;

        Buffer = Next;
    }

    if (ReceiverCommonReplenishRxRing(&Receiver->Common)) {
        EvtchnNotifyRemote(Adapter->EvtchnPort);
        Receiver->RemoteNotifies++;
    }
}

/* XXX This can crash if you get a sufficiently malformed ethernet
 * frame. */
/* Remove the 802.1Q tag control information from the frame, and set
   it in the NET_BUFFER_LIST metadata.  The NET_BUFFER_LIST must be of
   length 1. */
static ULONG
ReceiverRemoveTagControlInformation (
    IN  PNET_BUFFER_LIST NetBufferList
    )
{
    UCHAR buffer[12];
    NDIS_NET_BUFFER_LIST_8021Q_INFO ndis8021QInfo;
    PNET_BUFFER netBuffer;
    USHORT protocol;
    ULONG size;
    USHORT tci;

    netBuffer = NET_BUFFER_LIST_FIRST_NB(NetBufferList);

    size = GetNetBufferData(netBuffer, 0, buffer, 12);

    XM_ASSERT3U(size, ==, 12);

    size = GetNetBufferData(netBuffer, 12, &protocol, 2);

    XM_ASSERT3U(size, ==, 2);
    XM_ASSERT3U(protocol, ==, TPID_8021_Q);

    size = GetNetBufferData(netBuffer, 14, &tci, 2);
    tci = ntohs(tci);

    XM_ASSERT3U(size, ==, 2);
    
    NdisAdvanceNetBufferListDataStart(NetBufferList, 4, FALSE, NULL);
    SetNetBufferData(netBuffer, 0, buffer, 12);
    NdisZeroMemory(&ndis8021QInfo, sizeof(ndis8021QInfo));
    UNPACK_TCI(&ndis8021QInfo, tci);
    NET_BUFFER_LIST_INFO(NetBufferList, 
                         Ieee8021QNetBufferListInfo) = ndis8021QInfo.Value;
    return tci;
}

/* This relies on the fact that the ethernet, IP, and {TCP,UDP}
   headers are in the same fragment. */
static void
FixupIpChecksum(PNET_BUFFER_LIST NetBufferList)
{
    PNET_BUFFER netBuffer;
    ULONG bufLength;
    PMDL mdl;
    struct ethhdr *eh;
    struct iphdr *ih;
    uint32_t *ptr;

    netBuffer = NET_BUFFER_LIST_FIRST_NB(NetBufferList);
    mdl = NET_BUFFER_FIRST_MDL(netBuffer);
    NdisQueryMdl(mdl, &eh, &bufLength, NormalPagePriority);
    /* We know it's already mapped, because we allocated the MDL that
       way. */
    XM_ASSERT(eh != NULL);
    if (bufLength < sizeof(*eh))
        return;
    if (eh->proto != TPID_IPV4)
        return;
    ih = (struct iphdr *)(eh + 1);
    bufLength -= sizeof(*eh);
    if (bufLength < sizeof(*ih) ||
        bufLength < (ULONG)(ih->len_version & 0x0f) * 4)
        return;

    ptr = (uint32_t *)ih;
    bufLength = (ih->len_version & 0x0f) * 4;

    ih->check = 0;
    ih->check = compute_ip_csum(ptr, bufLength);
}

static void
FixupTcpUdpChecksum(PNET_BUFFER_LIST NetBufferList, BOOLEAN needPseudoHeaderCsumFixup)
{
    PNET_BUFFER netBuffer;
    ULONG bufLength;
    PMDL mdl;
    struct ethhdr *eh;
    struct iphdr *ih;
    uint32_t csum_accumulator;
    uint32_t *ptr;
    uint16_t *csum_field;
    unsigned len;

    netBuffer = NET_BUFFER_LIST_FIRST_NB(NetBufferList);
    mdl = NET_BUFFER_FIRST_MDL(netBuffer);
    NdisQueryMdl(mdl, &eh, &bufLength, NormalPagePriority);
    /* We know it's already mapped, because we allocated the MDL that
       way. */
    XM_ASSERT(eh != NULL);
    if (bufLength < sizeof(*eh))
        return;
    if (eh->proto != TPID_IPV4)
        return;
    ih = (struct iphdr *)(eh + 1);
    bufLength -= sizeof(*eh);
    if (bufLength < sizeof(*ih) ||
        bufLength < (ULONG)(ih->len_version & 0x0f) * 4)
        return;

    ptr = (uint32_t *)((ULONG_PTR)ih + (ih->len_version & 0x0f) * 4);
    len = htons(ih->tot_len) - (ih->len_version & 0x0f) * 4;

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

        if (*csum_field != csum && !needPseudoHeaderCsumFixup)
            TraceWarning(("invlid pseudo header checksum: expected %04x, found %04x\n", csum, *csum_field));

        *csum_field = csum;
    }

    csum_accumulator = acc_ip_csum(ptr, bufLength, 0);
    len -= bufLength;

    while (len) {
        mdl = NDIS_MDL_LINKAGE(mdl);
        if (mdl == NULL)
            break;
        NdisQueryMdl(mdl, &ptr, &bufLength, NormalPagePriority);

        XM_ASSERT(ptr != NULL);

        if (bufLength > len)
            bufLength = len;

        csum_accumulator = acc_ip_csum(ptr, bufLength, csum_accumulator);
        len -= bufLength;
    }

    *csum_field = ~fold_ip_csum(csum_accumulator);
}

static void
ForceCsumCalculation(PNET_BUFFER_LIST NetBufferList,
                     PNDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO CsumInfo)
{
    struct tcp_pseudo_header tph;
    PNET_BUFFER netBuffer;
    ULONG bufLength;
    PMDL mdl;
    struct ethhdr *eh;
    struct iphdr *ih;
    uint32_t csum_accumulator;
    uint32_t *ptr;
    uint16_t csum;
    unsigned len;

    netBuffer = NET_BUFFER_LIST_FIRST_NB(NetBufferList);
    mdl = NET_BUFFER_FIRST_MDL(netBuffer);
    NdisQueryMdl(mdl, &eh, &bufLength, NormalPagePriority);
    /* We know it's already mapped, because we allocated the MDL that
       way. */
    XM_ASSERT(eh != NULL);
    if (bufLength < sizeof(*eh))
        return;
    if (eh->proto != TPID_IPV4)
        return;
    ih = (struct iphdr *)(eh + 1);
    bufLength -= sizeof(*eh);
    if (bufLength < sizeof(*ih) ||
        bufLength < (ULONG)(ih->len_version & 0x0f) * 4 ||
        ih->proto != IPPROTO_TCP)
        return;

    /* Can't handle fragmented datagrams -> ignore anything with an
       offset, or with flags other than DONT_FRAGMENT set */
    if (ih->off_flags & ~0x40)
        return;

    ptr = (uint32_t *)((ULONG_PTR)ih + (ih->len_version & 0x0f) * 4);
    len = htons(ih->tot_len) - (ih->len_version & 0x0f) * 4;

    bufLength -= (ih->len_version & 0x0f) * 4;
    if (bufLength > len)
        bufLength = len;

    if (bufLength < sizeof(struct tcphdr))
        return;

    tph.saddr = ih->src;
    tph.daddr = ih->dest;
    tph.mbz = 0;
    tph.ptcl = IPPROTO_TCP;
    tph.length = htons((uint16_t)len);

    csum_accumulator = acc_ip_csum(&tph, sizeof(tph), 0);
    csum_accumulator = acc_ip_csum(ptr, bufLength, csum_accumulator);
    len -= bufLength;

    while (len) {
        mdl = NDIS_MDL_LINKAGE(mdl);
        if (mdl == NULL)
            break;
        NdisQueryMdl(mdl, &ptr, &bufLength, NormalPagePriority);

        XM_ASSERT(ptr != NULL);

        if (bufLength > len)
            bufLength = len;

        csum_accumulator = acc_ip_csum(ptr, bufLength, csum_accumulator);
        len -= bufLength;
    }

    csum = ~fold_ip_csum(csum_accumulator);
    if (csum == 0) {
        CsumInfo->Receive.TcpChecksumSucceeded = 1;
    } else {
        CsumInfo->Receive.TcpChecksumFailed = 1;
    }
}

static PNET_BUFFER_LIST
ReceiverMakeNetBufferList(
    IN  PRECEIVER   Receiver,
    IN  PMDL        pMdl,
    IN  USHORT      Flags,
    IN  ULONG       totOctets
    )
{
    struct ethhdr *ethernetHeader;
    PNET_BUFFER netBuffer;
    PNET_BUFFER_LIST netBufferList;
    USHORT contextSize = 0;

#ifdef XEN_WIRELESS
    contextSize = sizeof(XEN_WLAN_SIG);
#endif

    netBufferList =
        NdisAllocateNetBufferAndNetBufferList(Receiver->NetBufferListPool,
                                              contextSize,
                                              0,
                                              pMdl,
                                              0,
                                              totOctets);
    if (netBufferList == NULL)
        return NULL;

    netBufferList->SourceHandle = Receiver->Common.Adapter->NdisAdapterHandle;

    netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);

    ethernetHeader = (struct ethhdr *)pMdl->MappedSystemVa;
    if (ethernetHeader->proto == TPID_8021_Q) {
        ReceiverRemoveTagControlInformation(netBufferList);

        ethernetHeader = (struct ethhdr *)((PUCHAR)ethernetHeader + 4);
    }

    if (ethernetHeader->proto == TPID_IPV4) {
        /* Figure out whether we need to do RX csum offload related
         * work. */
        BOOLEAN needIpHeaderCsumFixup;
        BOOLEAN needPseudoHeaderCsumFixup;
        BOOLEAN needTcpUdpCsumFixup;
        NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO csumInfo;

        csumInfo.Value = 0;

        // We'll have split any GSO packet, thus rendering the IP header and TCP pseudo header
        // checksums invalid.
        needIpHeaderCsumFixup = (Flags & NETRXF_gso_prefix) ? TRUE : FALSE;
        needPseudoHeaderCsumFixup = (Flags & NETRXF_gso_prefix) ? TRUE : FALSE;

        needTcpUdpCsumFixup = (Flags & NETRXF_csum_blank) ? TRUE : FALSE;

        if (Flags & NETRXF_data_validated) {
            struct iphdr *ipHeader;

            ipHeader = (struct iphdr *)(ethernetHeader + 1);
            if (ipHeader->proto == IPPROTO_UDP) {
                if (Receiver->UdpChecksumOffload) {
                    csumInfo.Receive.UdpChecksumSucceeded = 1;
                    Receiver->nRxTcpUdpCsumOffload++;
                    if (Receiver->CsumBlankSafe)
                        needTcpUdpCsumFixup = FALSE;
                }
            } else if (ipHeader->proto == IPPROTO_TCP) {
                if (Receiver->TcpChecksumOffload) {
                    csumInfo.Receive.TcpChecksumSucceeded = 1;
                    Receiver->nRxTcpUdpCsumOffload++;
                    if (Receiver->CsumBlankSafe)
                        needTcpUdpCsumFixup = FALSE;
                }
            }
        }

        if (needIpHeaderCsumFixup)
            FixupIpChecksum(netBufferList);

        if (needTcpUdpCsumFixup) {
            FixupTcpUdpChecksum(netBufferList, needPseudoHeaderCsumFixup);
            Receiver->nRxTcpUdpCsumFixup++;
        }

        if (Receiver->ForceCsum && csumInfo.Value == 0)
            ForceCsumCalculation(netBufferList, &csumInfo);

        NET_BUFFER_LIST_INFO(netBufferList,
                             TcpIpChecksumNetBufferListInfo) =
            (PVOID)(ULONG_PTR)csumInfo.Value;
    }

    ReceiverUpdateStatistics(Receiver, netBufferList, totOctets);

    return netBufferList;

}

#define MIN(x, y) ((x) < (y) ? (x) : (y))

static void
ExtractMdl(
    IN  PUCHAR  ptr,
    IN  PMDL    pMdl,
    IN  ULONG   Offset,
    IN  ULONG   Size
    )
{
    while (Size != 0) {
        ULONG ByteCount;

        XM_ASSERT(pMdl != NULL);
        XM_ASSERT3U(pMdl->ByteCount, >=, Offset);
    
        ByteCount = MIN(pMdl->ByteCount - Offset, Size);

        if (ByteCount != 0) {
            RtlCopyMemory(ptr, (PUCHAR)pMdl->MappedSystemVa + Offset, ByteCount);

            ptr += ByteCount;
            Size -= ByteCount;

            if (Offset != 0)
                RtlMoveMemory((PUCHAR)pMdl->MappedSystemVa + ByteCount, pMdl->MappedSystemVa, Offset);

            pMdl->MappedSystemVa = (PUCHAR)pMdl->MappedSystemVa + ByteCount;
            pMdl->ByteOffset += ByteCount;
            pMdl->ByteCount -= ByteCount;
        }

        pMdl = pMdl->Next;
        Offset = 0;
    }
}

static BOOLEAN
ReceiverCreatePrefix(
    IN  PMDL    pDestMdl,
    IN  PMDL    pSourceMdl,
    IN  ULONG   Size
    )
{
    PUCHAR srcptr;
    PUCHAR dstptr;
    struct ethhdr *ethernetHeader;
    ULONG ethernetHeaderLength;
    struct iphdr *ipHeader;
    ULONG ipHeaderLength;
    struct tcphdr *tcpHeader;
    ULONG tcpHeaderLength;
    ULONG len;
    USHORT id;
    ULONG seq;

    srcptr = pSourceMdl->MappedSystemVa;

    ethernetHeader = (struct ethhdr *)srcptr;
    ethernetHeaderLength = sizeof (struct ethhdr);

    if (ethernetHeader->proto == TPID_8021_Q)
        ethernetHeaderLength += 4;

    srcptr += ethernetHeaderLength;

    ipHeader = (struct iphdr *)srcptr;
    ipHeaderLength = (ipHeader->len_version & 0x0f) * 4;

    srcptr += ipHeaderLength;

    tcpHeader = (struct tcphdr *)srcptr;
    tcpHeaderLength = (tcpHeader->off_and_flags & 0xf0) / 4;

    // We don't handle urgent data
    if (tcpHeader->off_and_flags & TCP_URG) {
        static BOOLEAN urgent_seen = FALSE;

        if (!urgent_seen) {
            TraceWarning(("urgent data in TSO!!\n"));
            urgent_seen = TRUE;
        }

        return FALSE;
    }

    srcptr += tcpHeaderLength;

    // Copy the header
    dstptr = pDestMdl->MappedSystemVa;
    RtlCopyMemory(dstptr, pSourceMdl->MappedSystemVa,
                  ethernetHeaderLength + ipHeaderLength + tcpHeaderLength);

    // Shorten the source packet length
    len = ntohs(ipHeader->tot_len);
    len -= Size;
    ipHeader->tot_len = htons((USHORT)len);

    // Advance the source packet IP id
    id = ntohs(ipHeader->id);
    id++;
    ipHeader->id = htons(id);

    // Advance the source packet TCP sequence number
    seq = ntohl(tcpHeader->seq);

    seq += Size;
    tcpHeader->seq = htonl(seq);

    // Set the destination packet length
    dstptr += ethernetHeaderLength;

    ipHeader = (struct iphdr *)dstptr;
    
    len = ipHeaderLength + tcpHeaderLength + Size;
    ipHeader->tot_len = htons((USHORT)len);

    dstptr += ipHeaderLength;

    // Clear FIN and PSH flags
    tcpHeader = (struct tcphdr *)dstptr;

    tcpHeader->off_and_flags &= ~(TCP_FIN | TCP_PSH);
    
    dstptr += tcpHeaderLength;

    // Extract payload from the source packet into the destination
    ExtractMdl(dstptr, pSourceMdl, ethernetHeaderLength + ipHeaderLength + tcpHeaderLength, Size);
    pDestMdl->ByteCount = ethernetHeaderLength + ipHeaderLength + tcpHeaderLength + Size; 

    return TRUE;
}

static void
ReceiverReceiveBufferList (
    IN  PRECEIVER           Receiver,
    OUT PNET_BUFFER_LIST    *BufferList,
    OUT PNET_BUFFER_LIST    *PrefixBufferList,
    IN BOOLEAN              V4vPacket
    )
{
    //
    // NB: Use of V4vPacket field declared above
    //
    // If the packet was received via V4V, then there won't be the
    // associated ring data structures to worry about (such as the RFD).
    // Also the MDL pointer is not located in the RFD. Use the one in
    // the Receiver struct.
    //
    // See the conditionals below where the handling of a V4V packet is
    // processed differently.
    //
    struct ethhdr *ethernetHeader;
    PMP_RFD prefixRfd = NULL;
    PMP_RFD headRfd = NULL;
    ULONG totOctets=0;
    ULONG totFrags;
    uint16_t Flags=0;
    PMDL buffer;
    UINT buffer_length;
    NDIS_STATUS stat;

    if (!V4vPacket)
    {
        stat = ReceiverCommonReceiveRfdChain(Receiver, &Flags, &prefixRfd,
                                             &headRfd, &totOctets, &totFrags);
        if (stat != NDIS_STATUS_SUCCESS) {
            Receiver->Errors++;
            goto discard;
        }

        XM_ASSERT(headRfd != NULL);
    }

    if (AdapterIsStopped(Receiver->Common.Adapter))
        goto discard;

    /* XXX we rely on the fact that the backend will never put a
       fragment boundary in the first 96 bytes of the packet. */
    if (!V4vPacket)
    {
        buffer = &headRfd->Mdl;
        buffer_length = buffer->ByteCount;
    }
    else
    {
#ifdef USE_V4V
        Flags = 0;  //@@@ This seems like possibly a bad idea...
        buffer = Receiver->V4vRxBufMdl;
        totOctets = Receiver->V4vBytesReceived;
        totFrags = 1;
        buffer_length = Receiver->V4vBytesReceived;
#else
        XM_BUGCHECK_TYPE_ASSERT;
        // Avoid compiler error:
        buffer = &headRfd->Mdl;
#endif
    }
    ethernetHeader = (struct ethhdr *)buffer->MappedSystemVa;
    if (!AdapterIsMacAddressInteresting(Receiver->Common.Adapter, 
                                        ethernetHeader->dest)) {
        Receiver->UninterestingFrames++;
        goto discard;
    }

    if (prefixRfd) {
        ULONG GsoSize = prefixRfd->GsoSize;

        if (ReceiverCreatePrefix(&prefixRfd->Mdl, buffer, GsoSize)) {
            totOctets -= GsoSize;
        } else {
            ReceiverCommonReleaseRfdChain(&Receiver->Common, prefixRfd);
            prefixRfd = NULL;
        }
    }

    *BufferList = ReceiverMakeNetBufferList(Receiver, buffer, Flags, totOctets);
    if (*BufferList == NULL)
        goto discard;

    if (prefixRfd) {
        *PrefixBufferList = ReceiverMakeNetBufferList(Receiver, &prefixRfd->Mdl, Flags, prefixRfd->Mdl.ByteCount);
        if (*PrefixBufferList == NULL)
            goto discard;
    } else {
        *PrefixBufferList = NULL;
    }

    return;

discard:
    if (!V4vPacket)
        ReceiverCommonReleaseRfdChain(&Receiver->Common, prefixRfd);

    *PrefixBufferList = NULL;

    if (!V4vPacket)
        ReceiverCommonReleaseRfdChain(&Receiver->Common, headRfd);

    *BufferList = NULL;
}

#ifdef USE_V4V
VOID
ReceiverHandleV4vPacket (
    IN PRECEIVER Receiver
    )
{
    ULONG netBufferListCount;
    PNET_BUFFER_LIST headNetBufferList=NULL;
    PNET_BUFFER_LIST prefixBufferList;
    PNET_BUFFER_LIST BufferList;

    netBufferListCount = 0;

    if (Receiver->Common.Adapter->Flags &
        (XENNET_ADAPTER_STOPPING | XENNET_ADAPTER_STOPPED))
    {
        TraceWarning(("Received packet while adapter stopped or stopping\n"));
        return;
    }

    if (Receiver->V4vBytesReceived <= 0)
        return;

    Receiver->Interrupts++;
    XennetAcquireSpinLock(&Receiver->Common.Lock, FALSE);

    if (Receiver->PauseState != ReceiverPauseRunning)
        goto done;

    ReceiverReceiveBufferList(Receiver, &BufferList, &prefixBufferList, TRUE);

    if (BufferList)
    {
        netBufferListCount = 1;
        NET_BUFFER_LIST_NEXT_NBL(BufferList) = NULL;
    }

    headNetBufferList = BufferList;

done:
    Receiver->nRxInNdis += netBufferListCount;
    Receiver->Common.Frames += netBufferListCount;
    XennetReleaseSpinLock(&Receiver->Common.Lock, FALSE);

    if (headNetBufferList != NULL) {
#ifdef XEN_WIRELESS
        WlanReceivePrepareNetBufferLists(Receiver->Common.Adapter, headNetBufferList);
#endif
        NdisMIndicateReceiveNetBufferLists(Receiver->Common.Adapter->NdisAdapterHandle,
                                       headNetBufferList,
                                       NDIS_DEFAULT_PORT_NUMBER,
                                       netBufferListCount,
                                       NDIS_RECEIVE_FLAGS_RESOURCES);   // allows us to continue to own the buffer

        //
        // The NDIS_RECEIVE_FLAGS_RESOURCES flag above allows us to return the NBL immediately.
        // This allows the V4V receiver to reuse the buffer right away. Also, we will never get
        // called by NDIS to return the NBL.
        //
        ReceiverReturnNetBufferListList(Receiver, headNetBufferList, 0);
    }

    ReceiverSwizzle(Receiver);

    return;
}
#endif

VOID
ReceiverHandleNotification (
    IN  PRECEIVER Receiver
    )
{
    ULONG moreWork;
    ULONG netBufferListCount;
    PNET_BUFFER_LIST headNetBufferList=NULL;
    PNET_BUFFER_LIST prevNetBufferList;
    RING_IDX producer;

    if (!RING_HAS_UNCONSUMED_RESPONSES(&Receiver->Common.Ring))
        return;

    netBufferListCount = 0;
    prevNetBufferList = NULL;
    headNetBufferList = NULL;

    Receiver->Interrupts++;
    XennetAcquireSpinLock(&Receiver->Common.Lock, TRUE);

    if (Receiver->PauseState != ReceiverPauseRunning)
        goto done;

top:
    producer = Receiver->Common.Ring.sring->rsp_prod;
    XsMemoryBarrier();
    while (!RING_IDXS_EQ(Receiver->Common.Ring.rsp_cons, producer)) {
        PNET_BUFFER_LIST prefixBufferList;
        PNET_BUFFER_LIST BufferList;

        ReceiverReceiveBufferList(Receiver, &BufferList, &prefixBufferList, FALSE);

        if (!BufferList) {
            XM_ASSERT(!prefixBufferList);
            continue;
        }

        if (!prefixBufferList) {
            netBufferListCount++;

            if (prevNetBufferList != NULL) {
                XM_ASSERT(headNetBufferList != NULL);
                NET_BUFFER_LIST_NEXT_NBL(prevNetBufferList) = BufferList;
            }

            if (headNetBufferList == NULL) {
                headNetBufferList = BufferList;
                XM_ASSERT(prevNetBufferList == NULL);
            }
        } else {
            netBufferListCount += 2;

            if (prevNetBufferList != NULL) {
                XM_ASSERT(headNetBufferList != NULL);
                NET_BUFFER_LIST_NEXT_NBL(prevNetBufferList) = prefixBufferList;
            }

            if (headNetBufferList == NULL) {
                headNetBufferList = prefixBufferList;
                XM_ASSERT(prevNetBufferList == NULL);
            }

            NET_BUFFER_LIST_NEXT_NBL(prefixBufferList) = BufferList;
        }

        NET_BUFFER_LIST_NEXT_NBL(BufferList) = NULL;
        prevNetBufferList = BufferList;
    }

    RING_FINAL_CHECK_FOR_RESPONSES(&Receiver->Common.Ring, moreWork);
    if (moreWork)
        goto top;

    ReceiverSwizzle(Receiver);

done:
    Receiver->nRxInNdis += netBufferListCount;
    Receiver->Common.Frames += netBufferListCount;
    XennetReleaseSpinLock(&Receiver->Common.Lock, TRUE);

    if (headNetBufferList != NULL) {
#ifdef XEN_WIRELESS
        WlanReceivePrepareNetBufferLists(Receiver->Common.Adapter, headNetBufferList);
#endif
        NdisMIndicateReceiveNetBufferLists(Receiver->Common.Adapter->NdisAdapterHandle,
                                       headNetBufferList,
                                       NDIS_DEFAULT_PORT_NUMBER,
                                       netBufferListCount,
                                       NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL);
    }
    return;
}


static VOID
ReceiverUpdateStatistics(PRECEIVER Receiver, PNET_BUFFER_LIST netBufferList,
                         ULONG Octets)
{
    PNET_BUFFER netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
    PMDL mdl = NET_BUFFER_CURRENT_MDL(netBuffer);
    PUCHAR buffer;
    ULONG length;

    NdisQueryMdl(mdl, &buffer, &length, NormalPagePriority);
    buffer += NET_BUFFER_CURRENT_MDL_OFFSET(netBuffer);
    if (ETH_IS_BROADCAST(buffer)) {
        Receiver->BroadcastPkts++;
        Receiver->BroadcastOctets += Octets;
    } else if (ETH_IS_MULTICAST(buffer)) {
        Receiver->MulticastPkts++;
        Receiver->MulticastOctets += Octets;
    } else {
        Receiver->UcastPkts++;
        Receiver->UcastOctets += Octets;
    }
}

VOID
ReceiverDebugDump (
    IN PRECEIVER Receiver
    )
{
    TraceInternal(("RX: RFDs in NDIS: %d\n",
                   Receiver->nRxInNdis));

    TraceInternal(("RX: Broadcast: %d octets, %d packets.\n",
                   Receiver->BroadcastOctets,
                   Receiver->BroadcastPkts));

    TraceInternal(("RX: Multicast: %d octets, %d packets.\n",
                   Receiver->MulticastOctets,
                   Receiver->MulticastPkts));

    TraceInternal(("RX: Unicast: %d octets, %d packets.\n",
                   Receiver->UcastOctets,
                   Receiver->UcastPkts));

    TraceInternal(("RX: %d uninteresting frames.\n",
                   Receiver->UninterestingFrames));

    TraceInternal(("RX: %d errors, %d frags, %I64d frames.\n",
                   Receiver->Errors,
                   Receiver->Common.Fragments,
                   Receiver->Common.Frames));

    TraceInternal(("RX: %d interrupts, %d notifies.\n",
                   Receiver->Interrupts,
                   Receiver->RemoteNotifies));

    TraceInternal(("RX: csum offload: TCP %d, UDP %d; done %d/%d offloads/fixups\n",
                   Receiver->TcpChecksumOffload,
                   Receiver->UdpChecksumOffload,
                   Receiver->nRxTcpUdpCsumOffload,
                   Receiver->nRxTcpUdpCsumFixup));
    TraceInternal(("RX: csum offload: BlankSafe: %d ForceCsum: %d\n",
                   Receiver->CsumBlankSafe,
                   Receiver->ForceCsum));

    TraceInternal(("RX: pause state %d\n",
                   Receiver->PauseState));

    ReceiverCommonDebugDump(&Receiver->Common);

    return;
}

/* Wait for NDIS to return any outstanding packets.  The caller must
   already have taken some appropriate measures to make sure that no
   more packets arrive in the meantime. */
VOID
ReceiverWaitForPacketReturn(
    IN  PRECEIVER Receiver,
    IN  BOOLEAN   Locked
    )
{
    LARGE_INTEGER delay1s;

    delay1s.QuadPart = -1000000;

    if (!Locked)
        XennetAcquireSpinLock(&Receiver->Common.Lock, FALSE);

    while (Receiver->nRxInNdis != 0) {
        TraceNotice(("%s: %d outstanding\n", __FUNCTION__, Receiver->nRxInNdis));

        XennetReleaseSpinLock(&Receiver->Common.Lock, FALSE);
        KeDelayExecutionThread(KernelMode, FALSE, &delay1s);
        XennetAcquireSpinLock(&Receiver->Common.Lock, FALSE);

        ReceiverSwizzle(Receiver);
    }

    if (!Locked)
        XennetReleaseSpinLock(&Receiver->Common.Lock, FALSE);
}

void
ReceiverPause(PRECEIVER receiver)
{
    TraceVerbose(("====> %s\n", __FUNCTION__));

    /* Shunt any further receives into the pending-receive list */
    NdisAcquireSpinLock(&receiver->Common.Lock);

    XM_ASSERT3U(receiver->PauseState, ==, ReceiverPauseRunning);
    receiver->PauseState = ReceiverPausePausing;

    ReceiverWaitForPacketReturn(receiver, TRUE);

    receiver->PauseState = ReceiverPausePaused;
    NdisReleaseSpinLock(&receiver->Common.Lock);

    TraceVerbose(("<==== %s\n", __FUNCTION__));
}

void
ReceiverUnpause(PRECEIVER Receiver)
{
    PADAPTER Adapter = Receiver->Common.Adapter;

    TraceVerbose(("====> %s\n", __FUNCTION__));

    NdisAcquireSpinLock(&Receiver->Common.Lock);
    XM_ASSERT3U(Receiver->PauseState, ==, ReceiverPausePaused);
    Receiver->PauseState = ReceiverPauseRunning;
    NdisReleaseSpinLock(&Receiver->Common.Lock);

    // Un-stall the receiver
    EvtchnRaiseLocally(Adapter->EvtchnPort);

    TraceVerbose(("<==== %s\n", __FUNCTION__));
}
