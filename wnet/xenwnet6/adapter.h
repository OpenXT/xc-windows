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

#pragma once

//
// Number of fake ARPs sent on resume from suspend.
//
#define XENNET_FAKE_ARP_COUNT           3

#define XENNET_INTERFACE_TYPE           NdisInterfaceInternal

#ifndef XEN_WIRELESS
#define XENNET_MEDIA_TYPE               NdisMedium802_3
#else
#define XENNET_MEDIA_TYPE               NdisMediumNative802_11
#endif
#define XENNET_HEADER_SIZE              14
#ifndef XEN_WIRELESS
#define XENNET_MEDIA_MAX_SPEED          2000000000
#else
#define XENNET_MEDIA_MAX_SPEED          54000000
#endif
#define XENNET_MAX_MCAST_LIST           32
#define XENNET_MAX_PACKET_SIZE          (XENNET_MAX_MTU - XENNET_HEADER_SIZE)

#define XENNET_DEF_MTU                  1514

#define XENNET_ADAPTER_STOPPING         0x00000001
#define XENNET_ADAPTER_STOPPED          0x00000002
#define XENNET_ADAPTER_PAUSING          0x00000004
#define XENNET_ADAPTER_PAUSED           0x00000008

#define XENNET_MAC_OPTIONS              (NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA |      \
                                            NDIS_MAC_OPTION_TRANSFERS_NOT_PEND |    \
                                            NDIS_MAC_OPTION_NO_LOOPBACK) 

//#define OID_DOT11_ASSOCIATION_PARAMS \
//         NWF_DEFINE_OID( 159, NWF_OPERATIONAL_OID, NWF_MANDATORY_OID )

typedef struct SuspendHandler* PSUSPEND_HANDLER;
typedef struct grant_cache* PGRANT_CACHE;

typedef struct _ETHERNET_ADDRESS {
    UCHAR Address[ETH_LENGTH_OF_ADDRESS];
} ETHERNET_ADDRESS, *PETHERNET_ADDRESS;

typedef struct _IP_ADDRESS {
    UCHAR Address[4];
} IP_ADDRESS, *PIP_ADDRESS;

typedef struct _IP_ADDRESS_LIST {
    PIP_ADDRESS     Addresses;
    ULONG           Count;
    NDIS_SPIN_LOCK  Lock;
} IP_ADDRESS_LIST, *PIP_ADDRESS_LIST;

typedef struct _PROPERTIES {
    int ip_csum;
    int tcp_csum;
    int udp_csum;
#ifndef XEN_WIRELESS
    int lso;
#endif
    int lro;
    int allow_csum_blank;
    int force_csum;
} PROPERTIES, *PPROPERTIES;

struct _ADAPTER {
    LIST_ENTRY          ListEntry;
    PCHAR               BackendPath;
    DOMAIN_ID           BackendDomid;
    UCHAR               CurrentAddress[ETH_LENGTH_OF_ADDRESS];
    ULONG               CurrentLookahead;
    ULONG               CurrentPacketFilter;
    PSUSPEND_HANDLER    EarlySuspendHandler;
    EVTCHN_PORT         EvtchnPort;
    BOOLEAN             RemovalPending;
    ULONG               Flags;
    PCHAR               FrontendPath;
    PGRANT_CACHE        GrantCache;
    ULONG               Interrupts;
    IP_ADDRESS_LIST     IpAddressList;
    PSUSPEND_HANDLER    LateSuspendHandler;
    NDIS_SPIN_LOCK      Lock;
    ULONG               Mtu;
    ETHERNET_ADDRESS    MulticastAddresses[XENNET_MAX_MCAST_LIST];
    ULONG               MulticastAddressesCount;
    NDIS_HANDLE         NdisAdapterHandle;
    NDIS_HANDLE         NdisDmaHandle;
    UCHAR               PermanentAddress[ETH_LENGTH_OF_ADDRESS];
    BOOLEAN             RingConnected;
    BOOLEAN             MediaConnected;
    PROPERTIES          Properties;
    RECEIVER            Receiver;
    PTRANSMITTER        Transmitter;
    /*XEN_WIRELESS*/
    PVOID               WlanAdapter;
    BOOLEAN             Initialized;
    EVTCHN_DEBUG_CALLBACK DebugCallback;
    struct xenbus_watch_handler *MediaWatch;
    struct xenbus_watch_handler *WlanWatch;
    struct xenbus_watch_handler *BackStateWatch;
};

extern ULONG XennetMacOptions;

VOID
AdapterCancelOidRequest (
    IN  PADAPTER    Adapter,
    IN  PVOID       RequestId
    );

VOID 
AdapterCancelSendNetBufferLists (
    IN  PADAPTER    Adapter,
    IN  PVOID       CancelId
    );

BOOLEAN 
AdapterCheckForHang (
    IN  PADAPTER Adapter
    );

VOID
AdapterDelete (
    IN  OUT PADAPTER* Adapter
    );

VOID 
AdapterHalt (
    IN  PADAPTER            Adapter,
    IN  NDIS_HALT_ACTION    HaltAction
    );

NDIS_STATUS
EnableXenWatchpoints (
    IN PADAPTER Adapter
    );

NDIS_STATUS
DisableXenWatchpoints (
    IN PADAPTER Adapter
    );

NDIS_STATUS 
AdapterInitialize (
    IN  PADAPTER    Adapter,
    IN  NDIS_HANDLE AdapterHandle,
    IN  PCHAR       XenbusPath
    );

BOOLEAN
AdapterIsMacAddressInteresting (
    IN  PADAPTER        Adapter,
    IN  PUCHAR          Mac
    );

NDIS_STATUS 
AdapterOidRequest (
    IN  PADAPTER            Adapter,
    IN  PNDIS_OID_REQUEST   NdisRequest
    );

NDIS_STATUS 
AdapterPause (
    IN  PADAPTER                        Adapter,
    IN  PNDIS_MINIPORT_PAUSE_PARAMETERS MiniportPauseParameters
    );

VOID 
AdapterPnPEventHandler (
    IN  PADAPTER                Adapter,
    IN  PNET_DEVICE_PNP_EVENT   NetDevicePnPEvent
    );

/*XEN_WIRELESS*/
NDIS_STATUS 
AdapterQueryGeneralStatistics (
    IN  PADAPTER                Adapter,
    IN  PNDIS_STATISTICS_INFO   NdisStatisticsInfo
    );

NDIS_STATUS 
AdapterReset (
    IN  NDIS_HANDLE     MiniportAdapterContext,
    OUT PBOOLEAN        AddressingReset
    );

NDIS_STATUS 
AdapterRestart (
    IN  PADAPTER                            Adapter,
    IN  PNDIS_MINIPORT_RESTART_PARAMETERS   MiniportRestartParameters
    );

VOID 
AdapterReturnNetBufferLists (
    IN  PADAPTER            Adapter,
    IN  PNET_BUFFER_LIST    NetBufferLists,
    IN  ULONG               ReturnFlags
    );

VOID 
AdapterSendNetBufferLists (
    IN  PADAPTER            Adapter,
    IN  PNET_BUFFER_LIST    NetBufferList,
    IN  NDIS_PORT_NUMBER    PortNumber,
    IN  ULONG               SendFlags
    );

VOID 
AdapterShutdown (
    IN  PADAPTER                Adapter,
    IN  NDIS_SHUTDOWN_ACTION    ShutdownAction
    );

__forceinline
BOOLEAN
AdapterIsStopped (
    IN  PADAPTER Adapter
    )
{
    return (Adapter->Flags & (XENNET_ADAPTER_STOPPING | XENNET_ADAPTER_STOPPED)) ? TRUE : FALSE;
}

__forceinline
BOOLEAN 
AdapterIs8021PEnabled (
    IN  PADAPTER Adapter
    )
{
    UNREFERENCED_PARAMETER(Adapter);

    return (XennetMacOptions & NDIS_MAC_OPTION_8021P_PRIORITY) ? TRUE : FALSE;
}

VOID
MPPnPEventHandler(
    IN  PADAPTER                Adapter,
    IN  PNET_DEVICE_PNP_EVENT   NetDevicePnPEvent
    );
