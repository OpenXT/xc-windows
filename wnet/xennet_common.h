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

#ifndef XENNET_COMMON_H__
#define XENNET_COMMON_H__

#include "netif.h"
#include "scsiboot.h"

#define NET_RX_RING_SIZE __RING_SIZE((struct netif_rx_sring *)0, PAGE_SIZE)
#define MAX_RX_FRAGS NET_RX_RING_SIZE

#define TPID_8021_Q 0x0081
#define TPID_IPV4 0x0008

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct ethhdr {
    UCHAR dest[ETH_LENGTH_OF_ADDRESS];
    UCHAR src[ETH_LENGTH_OF_ADDRESS];
    USHORT proto;
};

CASSERT(sizeof(struct ethhdr) == 14);

struct arphdr {
    USHORT hrd_fmt;
    USHORT proto_fmt;
    UCHAR hrd_len;
    UCHAR proto_len;
    USHORT operation;
    UCHAR snd_hrd_addr[ETH_LENGTH_OF_ADDRESS];
    UCHAR snd_proto_addr[4];
    UCHAR tgt_hrd_addr[ETH_LENGTH_OF_ADDRESS];
    UCHAR tgt_proto_addr[4];
};

CASSERT(sizeof(struct arphdr) == 28);

struct iphdr {
    UCHAR len_version;
    UCHAR service;
    USHORT tot_len;
    USHORT id;
    USHORT off_flags;
    UCHAR ttl;
    UCHAR proto;
    USHORT check;
    UINT src;
    UINT dest;
};

CASSERT(sizeof(struct iphdr) == 20);

struct udphdr {
    USHORT source;
    USHORT dest;
    USHORT len;
    USHORT checksum;
};

CASSERT(sizeof(struct udphdr) == 8);

#define	TCP_FIN   0x0100
#define	TCP_SYN   0x0200
#define	TCP_RST   0x0400
#define	TCP_PSH   0x0800
#define	TCP_ACK   0x1000
#define	TCP_URG   0x2000
#define	TCP_ECE   0x4000
#define	TCP_CWR   0x8000

struct tcphdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t off_and_flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};

CASSERT(sizeof(struct tcphdr) == 20);

struct tcp_pseudo_header {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t mbz;
    uint8_t ptcl;
    uint16_t length;
};

CASSERT(sizeof(struct tcp_pseudo_header) == 12);

typedef struct _RECEIVER RECEIVER, *PRECEIVER;

typedef struct _MP_RFD {
    PVOID ReceiveBufferVirt;
    NDIS_PHYSICAL_ADDRESS ReceiveBufferPhys;
    GRANT_REF Gref;
    ULONG GsoSize;
    MDL Mdl;
    PFN_NUMBER MdlPfn; /* This must come immediately after the MDL,
                          with no padding! */
} MP_RFD, *PMP_RFD;

/* Metadata for RX requests which are currently available to the
   backend.  There is one of these for every slot in the ring. */
typedef struct _RX_SHADOW {
    PMP_RFD Rfd;
    BOOLEAN InUse;
    uint16_t Next;
} RX_SHADOW, *PRX_SHADOW;

typedef struct _RECEIVER_COMMON
{
    struct _ADAPTER *Adapter;

    NDIS_SPIN_LOCK Lock;
    ULONGLONG Frames;
    ULONG Gso;
    ULONG Fragments;
    GRANT_REF RingGrantRef;
    netif_rx_front_ring_t Ring;
    netif_rx_sring_t *SharedRing;

    /* Shadows holding metadata for rx ring slots.  Indexed by the
       descriptor ID on the ring. */
    RX_SHADOW Shadows[MAX_RX_FRAGS];
    uint16_t NextFreeId;
    ULONG NrFreeIds;

    struct grant_cache *GrantCache;

    ULONG PendingRfds;

    /* The RFD cache is chained through the MDL entry.  This is a
       pointer to the first MDL in the chain, or NULL if the cache is
       empty. */
    PMDL RfdCacheHead;
    ULONG NumCachedRfds;

    ULONG CurrNumRfd;
    ULONG NumRfdAllocations;
} RECEIVER_COMMON, *PRECEIVER_COMMON;

NTSTATUS ReceiverCommonInitialize(PRECEIVER_COMMON RecvCommon,
                                  struct _ADAPTER *Adapter);
BOOLEAN ReceiverCommonCheckRingGrantRef(PRECEIVER_COMMON RecvCommon);
VOID ReceiverCommonCleanup(PRECEIVER_COMMON Common);
NDIS_STATUS ReceiverCommonInitializeBuffers(PRECEIVER_COMMON RecvCommon);
void ReceiverCommonCleanupBuffers(PRECEIVER_COMMON RecvCommon);

BOOLEAN ReceiverCommonReplenishRxRing(PRECEIVER_COMMON RecvCommon);

void ReceiverCommonRestartEarly(PRECEIVER_COMMON RecvCommon);
void ReceiverCommonRestartLate(PRECEIVER_COMMON RecvCommon);

VOID ReceiverCommonReleaseMdlChain(PRECEIVER_COMMON RecvCommon,
                                   PMDL HeadMdl);
VOID ReceiverCommonReleaseRfdChain(PRECEIVER_COMMON RecvCommon,
                                   PMP_RFD HeadRfd);
VOID ReceiverCommonDebugDump(PRECEIVER_COMMON RecvCommon);

NDIS_STATUS ReceiverCommonReceiveRfdChain(PRECEIVER Receiver,
                                          uint16_t *HeadFlags,
                                          PMP_RFD *PrefixRfd,
                                          PMP_RFD *HeadRfd,
                                          PULONG TotOctets,
                                          PULONG TotFrags);

/* Helpers to deal with internet checksums. */
static __inline uint32_t
acc_ip_csum(const void *buf, unsigned len, uint32_t s)
{
    unsigned x;
    if (len % 2)
        s += ((uint8_t*)buf)[len-1];
    for ( x = 0; x < len / 2; x++ )
        s += ((uint16_t*)buf)[x];
    return s;
}

static __inline uint16_t
fold_ip_csum(uint32_t acc)
{
    acc = ((acc & 0xffff) + (acc >> 16));
    acc += acc >> 16;
    return (uint16_t)acc;
}

static uint16_t
compute_ip_csum(const void *buf, unsigned len)
{
    return ~fold_ip_csum(acc_ip_csum(buf, len, 0));
}

static __inline uint16_t
htons(uint16_t host)
{
    return ((host & 0xff00) >> 8) | ((host & 0x00ff) << 8);
}

#define ntohs(net)  htons(net)

static __inline uint32_t
htonl(uint32_t host)
{
    return ((host & 0xff000000) >> 24) | ((host & 0x00ff0000) >> 8) |
           ((host & 0x0000ff00) << 8) | ((host & 0x000000ff) << 24);
}

#define ntohl(net)  htonl(net)

#endif /* !XENNET_COMMON_H__ */
