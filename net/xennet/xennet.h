//
// xennet.h - General declarations for the xen network device.
//
// Copyright (c) 2006 XenSource, Inc. - All rights reserved.
//

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


#include "xennet_common.h"

#define XENNET_NDIS_50 0x0500
#define XENNET_NDIS_51 0x0501
extern USHORT NdisVersion;

#define NIC_VENDOR_DESC "OpenXT"
#define XENNET_VERSION "1.0"

#define XNET_TAG 'TENX'

#define NET_TX_RING_SIZE __RING_SIZE((struct netif_tx_sring *)0, PAGE_SIZE)

#define MAX_TX_FRAGS NET_TX_RING_SIZE

#define XENNET_MAX_FRAGS_PER_PACKET 18
/* If we try to transmit a packet with more than
   XENNET_MAX_FRAGS_PER_PACKET fragments, we end up having to copy it.
   This is very slow.  XENNET_MAX_USER_DATA_PER_PACKET is supposed to
   be the largest possible value which doesn't lead to it happening
   very often.  The idea is to have one fragment reserved for the
   ethernet header, one for IP, and one for TCP, and then use
   everything else for user data. */
/* The actual safe limit is here is a little bit below 64kB, but going
   higher than this harms performance. */
#define XENNET_MAX_USER_DATA_PER_PACKET (PAGE_SIZE * (XENNET_MAX_FRAGS_PER_PACKET-3))

struct ip_addr {
    unsigned char addr[4];
};

typedef struct _ADAPTER ADAPTER, *PADAPTER;

//
// Driver prototypes
//
NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath
);

//
// Miniport prototypes
//
NDIS_STATUS
MPInitialize(
    OUT PNDIS_STATUS OpenErrorStatus,
    OUT PUINT SelectedMediumIndex,
    IN PNDIS_MEDIUM MediumArray,
    IN UINT MediumArraySize,
    IN NDIS_HANDLE MiniportAdapterHandle,
    IN NDIS_HANDLE WrapperConfigurationContext
);

VOID
MPSendPackets(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN PPNDIS_PACKET PacketArray,
    IN UINT NumberOfPackets
);

NDIS_STATUS
MPQueryInformation(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN NDIS_OID Oid,
    IN PVOID InformationBuffer,
    IN ULONG InformationBufferLength,
    OUT PULONG BytesWritten,
    OUT PULONG BytesNeeded
);

NDIS_STATUS
MPSetInformation(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN NDIS_OID Oid,
    IN PVOID InformationBuffer,
    IN ULONG InformationBufferLength,
    OUT PULONG BytesRead,
    OUT PULONG BytesNeeded
);

VOID
MPReturnPacket(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN PNDIS_PACKET Packet
);

VOID
MPHalt(
    IN NDIS_HANDLE MiniportAdapterContext
);

NDIS_STATUS
MPReset(
    OUT PBOOLEAN AddressingReset,
    IN NDIS_HANDLE MiniportAdapterContext
);

VOID
MPQueryPNPCapabilities(
    OUT PADAPTER MiniportProtocolContext,
    OUT PNDIS_STATUS Status
);


VOID
MPAdapterShutdown(
    IN NDIS_HANDLE MiniportAdapterContext
);

VOID
MPPnPEventNotify(
    IN NDIS_HANDLE  MiniportAdapterContext,
    IN NDIS_DEVICE_PNP_EVENT  PnPEvent,
    IN PVOID  InformationBuffer,
    IN ULONG  InformationBufferLength
);

#define XENNET_PACKET_HDR_SIZE  14
/* Each fragment is limited to PAGE_SIZE, and there's a limit on how
   many you can have per packet.  Also, the backend can't always use
   the whole page in the first fragment, so you can't quite achieve
   that limit.  Knock a whole page off for safety, even though it's
   probably overkill */
#define XENNET_MAX_MTU ((XENNET_MAX_FRAGS_PER_PACKET-1)*PAGE_SIZE)
#define XENNET_DEF_MTU 1514

#define XENNET_MAX_RFDS 256
#define XENNET_DEF_RFDS 16

/* Metadata for in-flight TX requests i.e. we've sent these to dom0
   but not got an acknowledgement back.  There is one of these for
   each tx_request structure on the ring. */
struct tx_shadow {
    GRANT_REF gref;
    netif_tx_id_t next;       /* Next transmit shadow. */
    uint16_t in_use:1;
    uint16_t is_extra:1;
    uint16_t is_fake_arp:1;
    uint16_t nr_reqs_outstanding_packet:13; /* Only in the head shadow
                                               for the packet */
    union {
        PNDIS_PACKET packet; /* Only non-NULL for the last fragment in a
                                packet.  We rely on the fact that the
                                backend always completes fragments in a
                                packet in-order. */
        PVOID fake_arp_buf; /* Release with XmFreeMemory() */
    };
    union {
        netif_tx_request_t req;
        struct netif_extra_info extra;
    };
};

NDIS_STATUS MpSetAdapterSettings(IN PADAPTER Adapter);
NDIS_STATUS MpGetAdvancedSettings(IN PADAPTER Adapter);

/* Minimum to pass WHQL. */
#define NR_MCAST_ADDRESSES 32

typedef struct _RECEIVER
{
    RECEIVER_COMMON Common;

    PNDIS_PACKET ReturnList;
    NDIS_HANDLE RecvPacketPool;

    ULONG LowResources;

    ULONG nRxInNdisMax;
    ULONG nRxCsumOffload;
    ULONG nRxCsumFixup;
    ULONG nRxDiscards;
    ULONG nRxInNdis;
    ULONG nPendingSwizzle;
    ULONG nPendingSwizzleMax;
    ULONG nRemoteNotifies;

    unsigned rx_csum_udp_offload:1; /* NDIS is expecting receive
                                       checksum offload on UDP
                                       packets.  This is only ever
                                       enabled if rx_csum_tcp_offload
                                       is set.*/
    unsigned rx_csum_tcp_offload:1; /* NDIS is expecting receive
                                       checksum offload on UDP
                                       packets. */
} RECEIVER, *PRECEIVER;

typedef struct _TRANSMITTER {
    struct _ADAPTER *Adapter;

    NDIS_SPIN_LOCK SendLock;
    ULONG nTxInFlight; /* Packets */

    struct tx_shadow tx_shadow[MAX_TX_FRAGS];
    netif_tx_id_t next_free_tx_id;
    uint16_t nr_free_tx_ids;
    PVOID bounce_buffer;
    PMDL bounce_buffer_mdl;
    int bounce_buffer_in_use:1;

    /* List of packets for transmission. 

       +-+     +-+  +-+    +-+    +-+  +-+  +-+
       | |     | |  | |    | |    | |  | |  | |
       +-+     +-+  +-+    +-+    +-+  +-+  +-+
        ^       ^           ^                ^
        |       |           |                |
      Head  HeadUntrans HeadUnprep         Tail

      Everything up to but not including HeadUntrans is on the shared
      ring.  [HeadUntrans, HeadUnprep) have been prepared but not
      transmitted.  [HeadUnprep,Tail] haven't been prepared yet.
      Any of these pointers can coincide.

      Head and Tail are NULL iff there are no packets outstanding, and
      they go NULL at the same time.  HeadUntrans is NULL iff only
      packet intended for transmission is on the shared ring, and
      HeadUnprep is NULL iff every packet has been prepared.

      HeadUnprep never moves backwards.  HeadUntrans can move
      backwards when we recover from suspend/resume, because packets
      which were on the old ring will not be on the new one. */
    PNDIS_PACKET HeadTxPacket, HeadUntransPacket, HeadUnprepPacket,
        TailTxPacket;

    /* Linked list of packets which we need to drop.  These have all
       been prepared, and are not on the ring.  The get dropped from
       the late suspend handler.  They are counted in nTxInFlight and
       not in nQueuedPackets. */
    PNDIS_PACKET HeadPacketForDrop;

    struct grant_cache *grant_cache;

    /* Interface to backend */
    GRANT_REF tx_ring_ref;
    netif_tx_front_ring_t tx_ring;
    netif_tx_sring_t *tx_ring_shared;

    ULONG nTxInFlightMax;
    uint16_t min_free_tx_ids;
    ULONG nTxPackets;
    ULONG nTxFrags;
    ULONG nTxCsumOffload;
    ULONG nQueuedPackets, nQueuedPacketsMax;
    ULONG nTxBatches;
    ULONG nTxEvents;
    ULONG nBounced;
    ULONG nLargeSends;

    unsigned tx_csum_tcp_offload:1; /* TCP packets for transmission
                                     * have no csum. */
    unsigned tx_csum_udp_offload:1; /* UDP packets for transmission
                                     * have no csum. */
    unsigned tx_csum_ip_offload:1; /* IP packets for transmission have
                                    * no csum. */
    unsigned tx_csum_offload_safe:1; /* The backend can handle TX csum
                                        offload packets. */
    unsigned tx_seg_offload:1; /* Perform TCP large send segmentation
                                  offload. */
    unsigned tso_avail:1; /* Can the backend handle TCP segmentation
                           * offload? */
} TRANSMITTER, *PTRANSMITTER;

typedef struct _PROPERTIES {
    int ip_csum;
    int tcp_csum;
    int udp_csum;
    int lso;
    int allow_csum_blank;
} PROPERTIES, *PPROPERTIES;

/* SendLock nests inside RecvLock */
typedef struct _ADAPTER
{
    NDIS_HANDLE WrapperConfigurationContext;

    PROPERTIES Properties;

    RECEIVER Receiver;
    TRANSMITTER Transmitter;

    ULONG Shutdown; /* Under the send lock */

    PCHAR XenbusPrefix; /* device/vif/{0,1,2,...} */
    PCHAR backend;

    DOMAIN_ID BackendDomid;

    PDEVICE_OBJECT pdo;

    EVTCHN_DEBUG_CALLBACK debug_cb_handle;

    ULONG CurrentPacketFilter;

    NDIS_HANDLE AdapterHandle;          // NDIS Handle for miniport up-calls

    ULONG mtu;

    /* The MAC address set by xenstore */
    UCHAR PermanentAddress[ETH_LENGTH_OF_ADDRESS];
    /* The MAC address set in the registry. */
    UCHAR CurrentAddress[ETH_LENGTH_OF_ADDRESS];

    struct xenbus_watch_handler *mediaWatch;
    struct xenbus_watch_handler *BackStateWatch;

    struct SuspendHandler *EarlySuspendHandler;
    struct SuspendHandler *LateSuspendHandler;

    /* WHQL requires all network cards to support at least 32
       multicast address.  Our backends don't, but the bridge does a
       good enough job of only sending us the right traffic that we
       can just listen promiscuously and hope for the best, but we
       still need to track what the mcast address is so that we can
       return it when requested. */
    UCHAR MulticastAddress[NR_MCAST_ADDRESSES][ETH_LENGTH_OF_ADDRESS];
    int nrMulticastAddresses;

    //
    // Adapter stats.
    //
    ULONG64 TxGood;
    ULONG64 TxError;
    ULONG64 TxDropped;
    ULONG64 RxGood;
    ULONG64 RxError;
    ULONG64 RxDropped;

    /* Stats which we keep for ourselves */
    ULONG nInterrupts;
    ULONG nDPCs;
    ULONG MacMisdirect;

    EVTCHN_PORT evtchn;

    BOOLEAN RemovalPending;

    /* We keep track of what IP addresses we have bound to us so that
       we can send the gratuitous ARP when we come back from
       suspend/resume. */
    NDIS_SPIN_LOCK address_list_lock; /* nests inside the send lock */
    struct ip_addr * address_list;
    int nr_addresses;

    unsigned ring_disconnected:1; /* The ring is temporarily
                                     disconnected.  Queue incoming
                                     packets rather than trying to
                                     send them immediately. */
    unsigned media_disconnect:1;
} ADAPTER, *PADAPTER;

typedef struct _WORK_ITEM_CONTEXT
{
    PADAPTER Adapter;
    ULONG state;
}
WORK_ITEM_CONTEXT, *PWORK_ITEM_CONTEXT;

NDIS_STATUS ReceiverInitialize(PRECEIVER Receiver, PADAPTER Adapter);
VOID ReceiverCleanup(PRECEIVER receiver);
VOID ReceiverHandleNotification(PRECEIVER Receiver);
void ReceiverWaitForPacketReturn(PRECEIVER Receiver);
void ReceiverDebugDump(PRECEIVER Receiver);

NDIS_STATUS TransmitterInitialize(PTRANSMITTER Transmitter, PADAPTER Adapter);
void TransmitterCleanup(PTRANSMITTER Transmitter);
NDIS_STATUS MpHandleSendInterrupt(PTRANSMITTER Transmitter);
void RestartTransmitterEarly(PTRANSMITTER Transmitter);
void RestartTransmitterLate(PTRANSMITTER Transmitter);
void TransmitterDebugDump(PTRANSMITTER Transmitter);
void TransmitterWaitForIdle(PTRANSMITTER Transmitter);
void TransmitterForceFreePackets(PTRANSMITTER Transmitter);

int MacAddressInteresting(PUCHAR dest, PADAPTER Adapter);

#define mb() XsMemoryBarrier()
#define wmb() XsMemoryBarrier()
#define rmb() XsMemoryBarrier()
