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

#pragma once

#define XENNET_MAX_FRAGS_PER_PACKET     18
#define XENNET_MAX_MTU          \
                        ((XENNET_MAX_FRAGS_PER_PACKET - 1) * PAGE_SIZE)
#define XENNET_MAX_USER_DATA_PER_PACKET \
                        ((XENNET_MAX_FRAGS_PER_PACKET - 3) * PAGE_SIZE)

#define XENNET_BOUNCE_BUFFER_SIZE      65536
#define XENNET_BOUNCE_BUFFER_PAGES     (XENNET_BOUNCE_BUFFER_SIZE / PAGE_SIZE)

#define XENNET_TX_RING_SIZE __RING_SIZE((struct netif_tx_sring *)0, PAGE_SIZE)
#define XENNET_MAX_TX_FRAGS XENNET_TX_RING_SIZE


#define XENNET_GET_NET_BUFFER_RESERVED(nb) \
    (PXENNET_NET_BUFFER_RESERVED)(&(nb)->MiniportReserved[0])

typedef struct _XENNET_NET_BUFFER_LIST_RESERVED XENNET_NET_BUFFER_LIST_RESERVED, *PXENNET_NET_BUFFER_LIST_RESERVED;
typedef struct _XENNET_NET_BUFFER_RESERVED XENNET_NET_BUFFER_RESERVED, *PXENNET_NET_BUFFER_RESERVED;
typedef struct _XENNET_TX_SHADOW XENNET_TX_SHADOW, *PXENNET_TX_SHADOW;
typedef struct _XENNET_TX_SHADOW_INFO XENNET_TX_SHADOW_INFO, *PXENNET_TX_SHADOW_INFO;

//
// Overlays NET_BUFFER_LIST.MiniportReserved.
// Used to link NET_BUFFER_LISTs owned by XENNET.
//
struct _XENNET_NET_BUFFER_LIST_RESERVED {
    LIST_ENTRY ListEntry;
};

CASSERT(sizeof(XENNET_NET_BUFFER_LIST_RESERVED) <= RTL_FIELD_SIZE(NET_BUFFER_LIST, MiniportReserved));

typedef enum {
    Unprepared = 0x1234,
    Prepared,
    Sent,
    Completed,
    Drop
} XennetBufferState;

//
// Overlays NET_BUFFER.MiniportReserved.
//
#define XENNET_BUFFER_MAGIC 0x5A
struct _XENNET_NET_BUFFER_RESERVED {
    USHORT                              Magic:7;
    USHORT                              Bounced:1;
    USHORT                              State; /* Should be a
                                                    XennetBufferState,
                                                    but that won't
                                                    quite fit. */
    PNET_BUFFER_LIST                    NetBufferList;
    USHORT                              PhysicalBufferCount;
    netif_tx_id_t                       TxShadowHeadId;
    ULONG                               TotalSize;
};

CASSERT(sizeof(XENNET_NET_BUFFER_RESERVED) <= RTL_FIELD_SIZE(NET_BUFFER, MiniportReserved));

//
// Contains XENNET specific information about every NET_BUFFER
// to be transmitted.
//
struct _XENNET_TX_SHADOW {
    GRANT_REF   GrantRef;
    BOOLEAN     InUse;
    BOOLEAN     IsExtra;
    BOOLEAN     IsFakeArp;
    BOOLEAN     OwnedByBackend;
    netif_tx_id_t Next;
    uint16_t    Generation:7;
    uint16_t    Reserved:9;
    union {
        PNET_BUFFER Buffer; 
        PVOID       FakeArpBuffer;
    };

    union {
        struct netif_extra_info ExtraInfo;
        netif_tx_request_t      Request;
    };
};

struct _XENNET_TX_SHADOW_INFO {
    ULONG               AvailableShadows;
    netif_tx_id_t       HeadFreeId;
    XENNET_TX_SHADOW    TxShadow[XENNET_MAX_TX_FRAGS];
};

typedef struct _TRANSMITTER {
    PADAPTER                Adapter;
    PUCHAR                  ArpBuffer;
    GRANT_REF               ArpGrantRef;
    PUCHAR                  BounceBuffer;
    BOOLEAN                 BounceBufferInUse;
    PMDL                    BounceBufferMdl;
    ULONG                   BounceCount;
    ULONG                   BroadcastOctets;
    ULONG                   BroadcastPkts;
    ULONGLONG               CompletedFrames;
    ULONG                   DroppedFrames;
    ULONG                   Errors;
    ULONG                   Fragments;
    ULONG                   Interrupts;
    ULONG                   LargeSends;
    NDIS_SPIN_LOCK          Lock;
    ULONG                   MulticastOctets;
    ULONG                   MulticastPkts;
    LIST_ENTRY              QueuedList;
    ULONG                   QueuedCount;
    ULONG                   RemoteNotifies;
    netif_tx_front_ring_t   Ring;
    RING_IDX                LastProdNotify;
    GRANT_REF               RingGrantRef;
    ULONGLONG               SentFrames;
    PNETIF_TX_SHARED_RING   SharedRing;
    XENNET_TX_SHADOW_INFO   TxShadowInfo;
    ULONG                   UcastOctets;
    ULONG                   UcastPkts;
    ULONG                   NrCsumOffloads;
    BOOLEAN                 TcpChecksumOffload;
    BOOLEAN                 UdpChecksumOffload;
    BOOLEAN                 IpChecksumOffload;
    BOOLEAN                 ChecksumOffloadSafe;
    BOOLEAN                 LargeSendOffload;
    BOOLEAN                 LsoAvailable;

    /* The transmitter pause state machine works like this.  When we
     * get a Pause request, we immediately go to state pausing, and we
     * then go to paused as soon as every packet in the queued list at
     * the time of the Pause request is completed.  Packets can only
     * be added to the queued list when we're in state running.
     *
     * Here are some special cases:
     *
     * -- If we get a pause request with an empty queued list, we
     * complete the pause immediately.
     *
     * -- If we get a pause request and a send request at the same
     * time, they race.  If the pause makes the state transition
     * before the the send enqueues the packet, the packet will fail
     * with STATUS_PAUSED.  If the send wins, the pause will be
     * delayed until the packet finishes.
     */
    enum {
        TransmitterPauseRunning,
        TransmitterPausePausing,
        TransmitterPausePaused
    } PauseState;
} TRANSMITTER, *PTRANSMITTER;

VOID
TransmitterDebugDump (
    IN PTRANSMITTER Transmitter
    );

VOID 
TransmitterDelete (
    IN OUT PTRANSMITTER* Transmitter,
    BOOLEAN TearDown
    );

VOID
TransmitterHandleNotification (
    IN  PTRANSMITTER Transmitter
    );

NDIS_STATUS
TransmitterInitialize (
    IN  PTRANSMITTER    Transmitter,
    IN  PADAPTER        Adapter
    );

BOOLEAN
TransmitterCheckRingGrantRef(
    IN  PTRANSMITTER    Transmitter
    );

NDIS_STATUS
TransmitterRestart (
    IN  PTRANSMITTER    Transmitter
    );

VOID
TransmitterResumeEarly (
    IN  PTRANSMITTER    Transmitter
    );

VOID
TransmitterResumeLate (
    IN  PTRANSMITTER    Transmitter
    );

VOID
TransmitterSendFakeArp (
    IN  PTRANSMITTER    Transmitter,
    IN  PUCHAR          CurrentAddress,
    IN  PUCHAR          IpAddress
    );

BOOLEAN
TransmitterSendNetBuffer (
    IN  PTRANSMITTER    Transmitter,
    IN  PNET_BUFFER     NetBuffer
    );

NDIS_STATUS
TransmitterSendNetBufferLists (
    IN  PTRANSMITTER        Transmitter,
    IN  PNET_BUFFER_LIST*   NetBufferList,
    IN  NDIS_PORT_NUMBER    PortNumber,
    IN  ULONG               SendFlags
    );

VOID
TransmitterWaitForIdle (
    PTRANSMITTER    Transmitter,
    BOOLEAN         Locked
    );

VOID
TransmitterForceFreePackets (
    PTRANSMITTER Transmitter
    );

__forceinline
NDIS_STATUS
TransmitterProcessResponseStatus (
    PTRANSMITTER            Transmitter,
    netif_tx_response_t*    Response
    )
{
    NDIS_STATUS ndisStatus;

    switch (Response->status) {
        case NETIF_RSP_OKAY:
            Transmitter->CompletedFrames++;
            ndisStatus = NDIS_STATUS_SUCCESS;
            break;

        case NETIF_RSP_ERROR:
            Transmitter->Errors++;
            ndisStatus = NDIS_STATUS_FAILURE;
            break;

        case NETIF_RSP_DROPPED:
            Transmitter->DroppedFrames++;
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;

        default:
            TraceError(("Bad status %d.\n", Response->status));
            ndisStatus = NDIS_STATUS_FAILURE;
            break;
    };

    return ndisStatus;
}

__forceinline
VOID
XennetInitializeExtraInfo (
    struct netif_extra_info*    ExtraInfo,
    ULONG                       Mss
    )
{
    ExtraInfo->type = XEN_NETIF_EXTRA_TYPE_GSO;
    ExtraInfo->flags = 0;
    ExtraInfo->u.gso.size = (USHORT)Mss;
    ExtraInfo->u.gso.type = XEN_NETIF_GSO_TYPE_TCPV4;
    ExtraInfo->u.gso.pad = 0;
    ExtraInfo->u.gso.features = 0;
    return;
}

void TransmitterPause(PTRANSMITTER Transmitter);
void TransmitterUnpause(PTRANSMITTER Transmitter);
