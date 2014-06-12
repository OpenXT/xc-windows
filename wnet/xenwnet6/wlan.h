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

#define WLAN_MAX_MPDU_LENGTH         1536
#define WLAN_BSSID_MAX_COUNT         8
#define WLAN_MAX_CIPHER_COUNT        6
#define WLAN_PHY_MAX_COUNT           1
#define WLAN_LISTEN_INTERVAL_DEFAULT 3

#define WLAN_ASSIGN_NDIS_OBJECT_HEADER(_header, _type, _revision, _size) \
    (_header).Type = _type; \
    (_header).Revision = _revision; \
    (_header).Size = _size;
#define WLAN_VERIFY_NDIS_OBJECT_HEADER_DEFAULT(_header, _type, _revision, _size) \
    (((_header).Type == _type) && \
     ((_header).Revision >= _revision) && \
     ((_header).Size >= _size))

#define WLAN_COMPARE_MAC_ADDRESS(_MacAddr1, _MacAddr2)    \
    (RtlCompareMemory(_MacAddr1, _MacAddr2, sizeof(DOT11_MAC_ADDRESS)) == sizeof(DOT11_MAC_ADDRESS))

typedef struct _XEN_WLAN_SIG {
    ULONG64 signature;
} XEN_WLAN_SIG, *PXEN_WLAN_SIG;

extern NDIS_OID XennetWlanSupportedOids[];
extern ULONG XennetWlanSupportedOidsSize;

NDIS_STATUS 
WlanAdapterInitialize (
    IN  PADAPTER            Adapter
    );

VOID 
WlanAdapterDelete (
    IN  PADAPTER            Adapter
    );

NDIS_STATUS 
WlanAdapterSetInformation (
    IN  PADAPTER            Adapter,
    IN  PNDIS_OID_REQUEST   NdisRequest
    );

NDIS_STATUS 
WlanAdapterQueryInformation (
    IN  PADAPTER            Adapter,
    IN  PNDIS_OID_REQUEST   NdisRequest
    );

NDIS_STATUS
WlanAdapterQuerySetInformation (
    IN  PADAPTER            Adapter,
    IN  PNDIS_OID_REQUEST   NdisRequest
    );

VOID
WlanSendPrepareNetBufferLists (
    IN  PNET_BUFFER_LIST    NetBufferList
    );

VOID
WlanSendNetBufferListsComplete (
    IN  PNET_BUFFER_LIST    NetBufferList
    );

VOID
WlanReceivePrepareNetBufferLists (
    IN  PADAPTER            Adapter,
    IN  PNET_BUFFER_LIST    NetBufferList
    );

VOID
WlanReceiveReturnNetBufferLists (
    IN  PADAPTER            Adapter,
    IN  PNET_BUFFER_LIST    NetBufferList
    );

BOOLEAN
WlanMediaStateChangedCb (
    IN  PADAPTER            Adapter
    );

VOID
WlanPause (
    IN  PADAPTER            Adapter
    );

VOID
WlanRestart (
    IN  PADAPTER            Adapter
    );

VOID
WlanIndicateRssi(
    IN PADAPTER Adapter
    );

char *
WlanReadBackend(PADAPTER Adapter, char *path);

NTSTATUS
WlanV4vSendNetBuffer (
     IN PADAPTER Adapter,
     PNET_BUFFER netBuffer
     );
