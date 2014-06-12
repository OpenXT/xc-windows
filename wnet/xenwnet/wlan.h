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

#pragma once

#define WLAN_MAX_MPDU_LENGTH         1536
#define WLAN_BSSID_MAX_COUNT         8
#define WLAN_PHY_MAX_COUNT           1
#define WLAN_LISTEN_INTERVAL_DEFAULT 3

#define WLAN_ASSIGN_NDIS_OBJECT_HEADER(_header, _type, _revision, _size) \
    (_header).Type = _type; \
    (_header).Revision = _revision; \
    (_header).Size = _size;
#define WLAN_VERIFY_NDIS_OBJECT_HEADER_DEFAULT(_header, _type, _revision, _size) \
    (((_header).Type == _type) && \
     ((_header).Revision == _revision) && \
     ((_header).Size == _size))

#define WLAN_COMPARE_MAC_ADDRESS(_MacAddr1, _MacAddr2)    \
    (RtlCompareMemory(_MacAddr1, _MacAddr2, sizeof(NDIS_802_11_MAC_ADDRESS)) == sizeof(NDIS_802_11_MAC_ADDRESS))

typedef struct _XEN_WLAN_SIG {
    ULONG64 signature;
} XEN_WLAN_SIG, *PXEN_WLAN_SIG;

extern NDIS_OID XennetWlanSupportedOids[];
extern ULONG XennetWlanSupportedOidsSize;



///////////////////////////////////////////////////////////////////////////////////////////////////////////////////


typedef ULONG NDIS_PORT_NUMBER, *PNDIS_PORT_NUMBER;
#define  NDIS_OID_REQUEST_NDIS_RESERVED_SIZE     16
#define  NDIS_OID_REQUEST_REVISION_1             1

typedef struct _NDIS_OID_REQUEST
{
    //
    // Caller must set Header to
    //     Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST
    //     Header.Revision = NDIS_OID_REQUEST_REVISION_1
    //     Header.Size = sizeof(_NDIS_OID_REQUEST)
    //
    NDIS_OBJECT_HEADER          Header;
    NDIS_REQUEST_TYPE           RequestType;
    NDIS_PORT_NUMBER            PortNumber;
    UINT                        Timeout; // in Seconds
    PVOID                       RequestId;
    NDIS_HANDLE                 RequestHandle;

    //
    // OID - Information
    //
    union _REQUEST_DATA
    {
        struct _QUERY
        {
            NDIS_OID    Oid;
            PVOID       InformationBuffer;
            UINT        InformationBufferLength;
            UINT        BytesWritten;
            UINT        BytesNeeded;
        } QUERY_INFORMATION;
    
        struct _SET
        {
            NDIS_OID    Oid;
            PVOID       InformationBuffer;
            UINT        InformationBufferLength;
            UINT        BytesRead;
            UINT        BytesNeeded;
        } SET_INFORMATION;
    
        struct _METHOD
        {
            NDIS_OID            Oid;
            PVOID               InformationBuffer;
            ULONG               InputBufferLength;
            ULONG               OutputBufferLength;
            ULONG               MethodId;
            UINT                BytesWritten;
            UINT                BytesRead;
            UINT                BytesNeeded;
        } METHOD_INFORMATION;
    } DATA;
    //
    // NDIS Reserved
    //
    UCHAR       NdisReserved[NDIS_OID_REQUEST_NDIS_RESERVED_SIZE * sizeof(PVOID)];
    UCHAR       MiniportReserved[2*sizeof(PVOID)];
    UCHAR       SourceReserved[2*sizeof(PVOID)];
    UCHAR       SupportedRevision;
    UCHAR       Reserved1;
    USHORT      Reserved2;

}NDIS_OID_REQUEST, *PNDIS_OID_REQUEST;


#define MAKE_NDIS_OID_REQUEST(NdisReq, OID, INFORMATION_BUFFER, INFORMATION_BUFFER_LEN, BYTES_PROCESSED, BYTES_NEEDED) \
    NdisReq->Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST; \
    NdisReq->Header.Revision = NDIS_OID_REQUEST_REVISION_1; \
    NdisReq->Header.Size = sizeof(NDIS_OID_REQUEST); \
    NdisReq->DATA.QUERY_INFORMATION.Oid = OID; \
    NdisReq->DATA.QUERY_INFORMATION.InformationBuffer = INFORMATION_BUFFER; \
    NdisReq->DATA.QUERY_INFORMATION.InformationBufferLength = INFORMATION_BUFFER_LEN; \
    NdisReq->DATA.QUERY_INFORMATION.BytesWritten = *BYTES_PROCESSED; \
    NdisReq->DATA.QUERY_INFORMATION.BytesNeeded = *BYTES_NEEDED;





////////////////////////////////////////////////
// NetBuffer

//
// NET_BUFFER data structures, APIs and macros
//

typedef struct _NET_BUFFER NET_BUFFER, *PNET_BUFFER;
typedef struct _NET_BUFFER_LIST_CONTEXT NET_BUFFER_LIST_CONTEXT, *PNET_BUFFER_LIST_CONTEXT;
typedef struct _NET_BUFFER_LIST NET_BUFFER_LIST, *PNET_BUFFER_LIST;

typedef union _NET_BUFFER_DATA_LENGTH
{
    ULONG   DataLength;
    SIZE_T  stDataLength;
} NET_BUFFER_DATA_LENGTH, *PNET_BUFFER_DATA_LENGTH;
    
    
typedef struct _NET_BUFFER_DATA
{
    PNET_BUFFER Next;
    PMDL        CurrentMdl;
    ULONG       CurrentMdlOffset;
#ifdef __cplusplus
    NET_BUFFER_DATA_LENGTH NbDataLength;
#else
    NET_BUFFER_DATA_LENGTH;
#endif
    PMDL        MdlChain;
    ULONG       DataOffset;
} NET_BUFFER_DATA, *PNET_BUFFER_DATA;

typedef union _NET_BUFFER_HEADER
{
#ifdef __cplusplus
    NET_BUFFER_DATA NetBufferData;
#else
    NET_BUFFER_DATA;
#endif
    SLIST_HEADER    Link;

} NET_BUFFER_HEADER, *PNET_BUFFER_HEADER;

typedef struct _NET_BUFFER
{

#ifdef __cplusplus
    NET_BUFFER_HEADER NetBufferHeader;
#else
    NET_BUFFER_HEADER;
#endif

    USHORT          ChecksumBias;
    USHORT          Reserved;
    NDIS_HANDLE     NdisPoolHandle;
    DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)PVOID NdisReserved[2];
    DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)PVOID ProtocolReserved[6];
    DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)PVOID MiniportReserved[4];
    NDIS_PHYSICAL_ADDRESS   DataPhysicalAddress;    
}NET_BUFFER, *PNET_BUFFER;

#pragma warning(push)
#pragma warning(disable:4200)   // nonstandard extension used : zero-sized array in struct/union

typedef struct _NET_BUFFER_LIST_CONTEXT
{
    PNET_BUFFER_LIST_CONTEXT    Next;
    USHORT                      Size;
    USHORT                      Offset;
    DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)     UCHAR      ContextData[];
} NET_BUFFER_LIST_CONTEXT, *PNET_BUFFER_LIST_CONTEXT;

#pragma warning(pop)

typedef enum _NDIS_NET_BUFFER_LIST_INFO
{
    TcpIpChecksumNetBufferListInfo,
    TcpOffloadBytesTransferred = TcpIpChecksumNetBufferListInfo,
    IPsecOffloadV1NetBufferListInfo,
    TcpLargeSendNetBufferListInfo,
    TcpReceiveNoPush = TcpLargeSendNetBufferListInfo,
    ClassificationHandleNetBufferListInfo,
    Ieee8021QNetBufferListInfo,
    NetBufferListCancelId,
    MediaSpecificInformation,
    NetBufferListFrameType,
    NetBufferListProtocolId = NetBufferListFrameType,
    NetBufferListHashValue,
    NetBufferListHashInfo,
    WfpNetBufferListInfo,
    MaxNetBufferListInfo
} NDIS_NET_BUFFER_LIST_INFO, *PNDIS_NET_BUFFER_LIST_INFO;

typedef struct _NET_BUFFER_LIST_DATA
{
    PNET_BUFFER_LIST    Next;           // Next NetBufferList in the chain
    PNET_BUFFER         FirstNetBuffer; // First NetBuffer on this NetBufferList
} NET_BUFFER_LIST_DATA, *PNET_BUFFER_LIST_DATA;

typedef union _NET_BUFFER_LIST_HEADER
{
#ifdef __cplusplus
    NET_BUFFER_LIST_DATA NetBufferListData;
#else
    NET_BUFFER_LIST_DATA;
#endif
    SLIST_HEADER            Link;           // used in SLIST of free NetBuffers in the block
} NET_BUFFER_LIST_HEADER, *PNET_BUFFER_LIST_HEADER;


typedef struct _NET_BUFFER_LIST
{

#ifdef __cplusplus
    NET_BUFFER_LIST_HEADER      NetBufferListHeader;
#else
    NET_BUFFER_LIST_HEADER;
#endif

    PNET_BUFFER_LIST_CONTEXT    Context;
    PNET_BUFFER_LIST            ParentNetBufferList;
    NDIS_HANDLE                 NdisPoolHandle;
    DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)PVOID NdisReserved[2];
    DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)PVOID ProtocolReserved[4];
    DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)PVOID MiniportReserved[2];
    PVOID                       Scratch;
    NDIS_HANDLE                 SourceHandle;
    ULONG                       NblFlags;   // public flags
    LONG                        ChildRefCount;
    ULONG                       Flags;      // private flags used by NDIs, protocols, miniport, etc.
    NDIS_STATUS                 Status;
    PVOID                       NetBufferListInfo[MaxNetBufferListInfo];
} NET_BUFFER_LIST, *PNET_BUFFER_LIST;




#ifdef __cplusplus
#define NET_BUFFER_NEXT_NB(_NB)                     ((_NB)->NetBufferHeader.NetBufferData.Next)
#define NET_BUFFER_FIRST_MDL(_NB)                   ((_NB)->NetBufferHeader.NetBufferData.MdlChain)
#define NET_BUFFER_DATA_LENGTH(_NB)                 ((_NB)->NetBufferHeader.NetBufferData.NbDataLength.DataLength)
#define NET_BUFFER_DATA_OFFSET(_NB)                 ((_NB)->NetBufferHeader.NetBufferData.DataOffset)
#define NET_BUFFER_CURRENT_MDL(_NB)                 ((_NB)->NetBufferHeader.NetBufferData.CurrentMdl)
#define NET_BUFFER_CURRENT_MDL_OFFSET(_NB)          ((_NB)->NetBufferHeader.NetBufferData.CurrentMdlOffset)
#else
#define NET_BUFFER_NEXT_NB(_NB)                     ((_NB)->Next)
#define NET_BUFFER_FIRST_MDL(_NB)                   ((_NB)->MdlChain)
#define NET_BUFFER_DATA_LENGTH(_NB)                 ((_NB)->DataLength)
#define NET_BUFFER_DATA_OFFSET(_NB)                 ((_NB)->DataOffset)
#define NET_BUFFER_CURRENT_MDL(_NB)                 ((_NB)->CurrentMdl)
#define NET_BUFFER_CURRENT_MDL_OFFSET(_NB)          ((_NB)->CurrentMdlOffset)
#endif

#define NET_BUFFER_PROTOCOL_RESERVED(_NB)           ((_NB)->ProtocolReserved)
#define NET_BUFFER_MINIPORT_RESERVED(_NB)           ((_NB)->MiniportReserved)
#define NET_BUFFER_CHECKSUM_BIAS(_NB)               ((_NB)->ChecksumBias)

#ifdef __cplusplus
#define NET_BUFFER_LIST_NEXT_NBL(_NBL)              ((_NBL)->NetBufferListHeader.NetBufferListData.Next)
#define NET_BUFFER_LIST_FIRST_NB(_NBL)              ((_NBL)->NetBufferListHeader.NetBufferListData.FirstNetBuffer)
#else
#define NET_BUFFER_LIST_NEXT_NBL(_NBL)              ((_NBL)->Next)
#define NET_BUFFER_LIST_FIRST_NB(_NBL)              ((_NBL)->FirstNetBuffer)
#endif

#define NET_BUFFER_LIST_FLAGS(_NBL)                 ((_NBL)->Flags)
#define NET_BUFFER_LIST_NBL_FLAGS(_NBL)             ((_NBL)->NblFlags)
#define NET_BUFFER_LIST_PROTOCOL_RESERVED(_NBL)     ((_NBL)->ProtocolReserved)
#define NET_BUFFER_LIST_MINIPORT_RESERVED(_NBL)     ((_NBL)->MiniportReserved)
#define NET_BUFFER_LIST_CONTEXT_DATA_START(_NBL)    ((PUCHAR)(((_NBL)->Context)+1)+(_NBL)->Context->Offset)
#define NET_BUFFER_LIST_CONTEXT_DATA_SIZE(_NBL)     (((_NBL)->Context)->Size)

#define NET_BUFFER_LIST_INFO(_NBL, _Id)             ((_NBL)->NetBufferListInfo[(_Id)])
#define NET_BUFFER_LIST_STATUS(_NBL)                ((_NBL)->Status)


#define NDIS_GET_NET_BUFFER_LIST_CANCEL_ID(_NBL)     (NET_BUFFER_LIST_INFO(_NBL, NetBufferListCancelId))
#define NDIS_SET_NET_BUFFER_LIST_CANCEL_ID(_NBL, _CancelId)            \
    NET_BUFFER_LIST_INFO(_NBL, NetBufferListCancelId) = _CancelId


//
//  Per-NBL information for Ieee8021QNetBufferListInfo.
//
typedef struct _NDIS_NET_BUFFER_LIST_8021Q_INFO
{
    union
    {
        struct
        {
            UINT32      UserPriority:3;         // 802.1p priority
            UINT32      CanonicalFormatId:1;    // always 0
            UINT32      VlanId:12;              // VLAN Identification
            UINT32      Reserved:16;            // set to 0 for ethernet
        }TagHeader;
        
        struct
        {
            UINT32      UserPriority:3;         // 802.1p priority
            UINT32      CanonicalFormatId:1;    // always 0
            UINT32      VlanId:12;              // VLAN Identification
            UINT32      WMMInfo:4;              
            UINT32      Reserved:12;            // set to 0 for wireless lan
            
        }WLanTagHeader;

        PVOID  Value;
    };
} NDIS_NET_BUFFER_LIST_8021Q_INFO, *PNDIS_NET_BUFFER_LIST_8021Q_INFO;

typedef struct _NDIS_NET_BUFFER_LIST_MEDIA_SPECIFIC_INFO
{
    union
    {
        PVOID  MediaSpecificInfo;
        PVOID  NativeWifiSpecificInfo;

        PVOID  Value;
    };
    
} NDIS_NET_BUFFER_LIST_MEDIA_SPECIFIC_INFO, *PNDIS_NET_BUFFER_LIST_MEDIA_SPECIFIC_INFO;

typedef struct _NDIS_NBL_MEDIA_MEDIA_SPECIFIC_INFORMATION NDIS_NBL_MEDIA_SPECIFIC_INFORMATION, *PNDIS_NBL_MEDIA_SPECIFIC_INFORMATION;


struct _NDIS_NBL_MEDIA_MEDIA_SPECIFIC_INFORMATION
{
    PNDIS_NBL_MEDIA_SPECIFIC_INFORMATION NextEntry;
    ULONG                                Tag;
    DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) UCHAR  Data[1];
}; 

#define NDIS_NBL_ADD_MEDIA_SPECIFIC_INFO(_NBL, _MediaSpecificInfo)                         \
    {                                                                                      \
        PNDIS_NBL_MEDIA_SPECIFIC_INFORMATION HeadEntry = NULL;                             \
        if (NET_BUFFER_LIST_INFO((_NBL), MediaSpecificInformation) != NULL)                \
        {                                                                                  \
            HeadEntry = (PNDIS_NBL_MEDIA_SPECIFIC_INFORMATION)(NET_BUFFER_LIST_INFO((_NBL), MediaSpecificInformation));           \
        }                                                                                  \
        NET_BUFFER_LIST_INFO((_NBL), MediaSpecificInformation) = (_MediaSpecificInfo);     \
        (_MediaSpecificInfo)->NextEntry = HeadEntry;                                       \
    }            

#define NDIS_NBL_REMOVE_MEDIA_SPECIFIC_INFO(_NBL, _MediaSpecificInfo)                      \
    {                                                                                      \
        PNDIS_NBL_MEDIA_SPECIFIC_INFORMATION *HeadEntry;                                   \
        HeadEntry = (PNDIS_NBL_MEDIA_SPECIFIC_INFORMATION *)&(NET_BUFFER_LIST_INFO((_NBL), MediaSpecificInformation));             \
        for (; *HeadEntry != NULL; HeadEntry = &(*HeadEntry)->NextEntry)                   \
        {                                                                                  \
            if ((*HeadEntry)->Tag == (_MediaSpecificInfo)->Tag)                            \
            {                                                                              \
                *HeadEntry = (*HeadEntry)->NextEntry;                                      \
                break;                                                                     \
            }                                                                              \
        }                                                                                  \
    }                                                                                              

#define NDIS_NBL_GET_MEDIA_SPECIFIC_INFO(_NBL, _Tag, _MediaSpecificInfo)                   \
    {                                                                                      \
        PNDIS_NBL_MEDIA_SPECIFIC_INFORMATION HeadEntry;                                    \
        (_MediaSpecificInfo) = NULL;                                                       \
        HeadEntry = (PNDIS_NBL_MEDIA_SPECIFIC_INFORMATION)(NET_BUFFER_LIST_INFO((_NBL), MediaSpecificInformation));                \
        for (; HeadEntry != NULL; HeadEntry = HeadEntry->NextEntry)                        \
        {                                                                                  \
            if (HeadEntry->Tag == (_Tag))                                                  \
            {                                                                              \
                (_MediaSpecificInfo) = HeadEntry;                                          \
                break;                                                                     \
            }                                                                              \
        }                                                                                  \
    }



//
// Public flags for NDIS_STATUS_INDICATION
//
#define  NDIS_STATUS_INDICATION_FLAGS_MEDIA_CONNECT_TO_CONNECT		0x1000

#define  NDIS_STATUS_INDICATION_REVISION_1             1

typedef struct _NDIS_STATUS_INDICATION 
{
    NDIS_OBJECT_HEADER      Header;
    NDIS_HANDLE             SourceHandle;
    NDIS_PORT_NUMBER        PortNumber;
    NDIS_STATUS             StatusCode;
    ULONG                   Flags;             
    NDIS_HANDLE             DestinationHandle;
    PVOID                   RequestId; 
    PVOID                   StatusBuffer;
    ULONG                   StatusBufferSize;
    GUID                    Guid;               // optional and valid only if StatusCode = NDIS_STATUS_MEDIA_SPECIFIC_INDICATION
    PVOID                   NdisReserved[4];
}NDIS_STATUS_INDICATION, *PNDIS_STATUS_INDICATION;

#define NDIS_SIZEOF_STATUS_INDICATION_REVISION_1      \
        RTL_SIZEOF_THROUGH_FIELD(NDIS_STATUS_INDICATION, NdisReserved)



typedef struct _XEN_BSS_CONFIG {
    ULONG uPhyId;
    NDIS_802_11_CONFIGURATION PhySpecificInfo;
    NDIS_802_11_MAC_ADDRESS BSSID;
    NDIS_802_11_NETWORK_INFRASTRUCTURE BSSType;
    ULONG uLinkQuality;
    BOOLEAN bInRegDomain;
    USHORT usBeaconPeriod;
    ULONGLONG ullTimestamp;
    ULONGLONG ullHostTimestamp;
    USHORT usCapabilityInformation;
    USHORT usBeaconInterval;
    ULONG uBufferLength;
    UCHAR ucBuffer[1];			// Must be the last field.

    ULONG                               Privacy;            // WEP encryption requirement
    NDIS_802_11_RSSI                    Rssi;               // receive signal
                                                            // strength in dBm
    NDIS_802_11_NETWORK_TYPE            NetworkTypeInUse;
    NDIS_802_11_CONFIGURATION           Configuration;
    NDIS_802_11_NETWORK_INFRASTRUCTURE  InfrastructureMode;
    NDIS_802_11_RATES_EX                SupportedRates;

} XEN_BSS_CONFIG, * PXEN_BSS_CONFIG;

typedef struct _XEN_BSS_ENTRY {
    XEN_BSS_CONFIG   Entry;
    NDIS_802_11_SSID SSID;
} XEN_BSS_ENTRY, *PXEN_BSS_ENTRY;


#if 0
//
// structure used in OID_GEN_STATISTICS
//
typedef struct _NDIS_STATISTICS_INFO
{
    NDIS_OBJECT_HEADER          Header;
    ULONG                       SupportedStatistics;
    ULONG64                     ifInDiscards;           // OID_GEN_RCV_ERROR + OID_GEN_RCV_NO_BUFFER = OID_GEN_RCV_DISCARDS
    ULONG64                     ifInErrors;             // OID_GEN_RCV_ERROR
    ULONG64                     ifHCInOctets;           // OID_GEN_BYTES_RCV = OID_GEN_DIRECTED_BYTES_RCV + OID_GEN_MULTICAST_BYTES_RCV + OID_GEN_BROADCAST_BYTES_RCV
    ULONG64                     ifHCInUcastPkts;        // OID_GEN_DIRECTED_FRAMES_RCV
    ULONG64                     ifHCInMulticastPkts;    // OID_GEN_MULTICAST_FRAMES_RCV
    ULONG64                     ifHCInBroadcastPkts;    // OID_GEN_BROADCAST_FRAMES_RCV
    ULONG64                     ifHCOutOctets;          // OID_GEN_BYTES_XMIT = OID_GEN_DIRECTED_BYTES_XMIT + OID_GEN_MULTICAST_BYTES_XMIT + OID_GEN_BROADCAST_BYTES_XMIT
    ULONG64                     ifHCOutUcastPkts;       // OID_GEN_DIRECTED_FRAMES_XMIT
    ULONG64                     ifHCOutMulticastPkts;   // OID_GEN_MULTICAST_FRAMES_XMIT
    ULONG64                     ifHCOutBroadcastPkts;   // OID_GEN_BROADCAST_FRAMES_XMIT
    ULONG64                     ifOutErrors;            // OID_GEN_XMIT_ERROR
    ULONG64                     ifOutDiscards;          // OID_GEN_XMIT_DISCARDS
    ULONG64                     ifHCInUcastOctets;      // OID_GEN_DIRECTED_BYTES_RCV    
    ULONG64                     ifHCInMulticastOctets;  // OID_GEN_MULTICAST_BYTES_RCV
    ULONG64                     ifHCInBroadcastOctets;  // OID_GEN_BROADCAST_BYTES_RCV        
    ULONG64                     ifHCOutUcastOctets;     // OID_GEN_DIRECTED_BYTES_XMIT    
    ULONG64                     ifHCOutMulticastOctets; // OID_GEN_MULTICAST_BYTES_XMIT
    ULONG64                     ifHCOutBroadcastOctets; // OID_GEN_BROADCAST_BYTES_XMIT                
}NDIS_STATISTICS_INFO, *PNDIS_STATISTICS_INFO;

#define NDIS_SIZEOF_STATISTICS_INFO_REVISION_1    \
        RTL_SIZEOF_THROUGH_FIELD(NDIS_STATISTICS_INFO, ifHCOutBroadcastOctets)

#endif







typedef struct _WLAN_ADAPTER {
    BOOLEAN                             RadioOn;
    BOOLEAN                             HiddenNetworks;
    BOOLEAN                             MediaStreaming;
    ULONG                               State;
    ULONG                               RTSThreshold;
    ULONG                               FragThreshold;
    ULONG                               UDThreshold;
    ULONG                               PowerLevel;
    ULONG                               AutoConfig;
    ULONG                               FrameCounter;
    PVOID                               ScanRequestId;
    LARGE_INTEGER                       AssocTime;
//    XEN_BSS_ENTRY                       BSSList[2]; /* Just two for now */
    XEN_BSS_ENTRY                       BSSList[WLAN_BSSID_MAX_COUNT];
    ULONG                               BSSCount;
    ULONG                               BSSIDCount;
//    DOT11_STATISTICS                    Stats;
    ULONG                               DesiredPhyList[WLAN_PHY_MAX_COUNT];
    ULONG                               DesiredPhyCount;
    ULONG                               CurrentPhyId;
    BOOLEAN                             XenConnected;
    NDIS_802_11_MAC_ADDRESS             XenBSSID;
    NDIS_802_11_SSID                    XenSSID;

    BOOLEAN                             Associated;
    NDIS_802_11_NETWORK_INFRASTRUCTURE  NetworkInfrastructure;
    NDIS_802_11_AUTHENTICATION_MODE     AuthenticationMode;
    NDIS_802_11_ENCRYPTION_STATUS       EncryptionMode;
    NDIS_802_11_NETWORK_TYPE            NetworkTypeInUse;
    NDIS_802_11_RATES_EX                SupportedRates;
    ULONG                               ChCenterFrequency;
    ULONG                               BeaconPeriod;
    PVOID                               WepKey[255];
    ULONG                               WepKeySize[255];
    PVOID                               WpaKey[255];
    ULONG                               WpaKeySize[255];

} WLAN_ADAPTER, *PWLAN_ADAPTER;




NDIS_STATUS 
WlanAdapterInitialize (
    IN  PADAPTER            Adapter
    );

VOID 
WlanAdapterDelete (
    IN  PADAPTER            Adapter
    );


NDIS_STATUS
WlanStartScan (
    IN PADAPTER Adapter
    );

ULONG
WlanGetScanListSize (
    NDIS_OID oid,
    IN PADAPTER Adapter
    );

NDIS_STATUS
WlanGetScanList (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanGetRadioConfiguration (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanSetRadioConfiguration (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanGetInfrastructureMode (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanSetInfrastructureMode (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanGetAuthenticationMode (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanSetAuthenticationMode (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanGetEncryptionMode (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanSetEncryptionMode (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanGetRSSI (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanSetBssid(
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanGetBssid(
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanGetSupportedRates(
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

ULONG
WlanGetNetworkTypeListSize (
    NDIS_OID oid,
    IN PADAPTER Adapter
    );

NDIS_STATUS
WlanGetNetworkTypes (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanGetNetworkTypeInUse (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanSetNetworkTypeInUse (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanSetSSID (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanGetSSID (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanDisassociate (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanReloadDefaults (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanAddWep (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanRemoveWep (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanAddKey (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );

NDIS_STATUS
WlanRemoveKey (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    );
