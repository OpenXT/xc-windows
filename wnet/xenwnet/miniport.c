//
// miniport.c - Xen network miniport driver support routines.
//
// Copyright (c) 2006, XenSource, Inc. - All rights reserved.
//

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


//
// headers never build W4 very well
//

#pragma warning( push, 3 )

#include "precomp.h"
#include "netif.h"
#include "scsiboot.h"
#include "stdlib.h"
#include "xscompat.h"
#include "ntstrsafe.h"
#include "xennet_common.h"
#ifdef XEN_WIRELESS
#include "..\wnet\xenwnet\wlan.h"
#endif

#pragma warning( pop )

//
// Dont care about unreferenced formal parameters here
//
#pragma warning( disable : 4100 )

//
// XXX: WARNING: NOTE: HACK:
// NdisGetSystemUpTime is depricated in WDK so suppress the warnings. its stupid
// the header sees we are building ndis5.1 but complains anyway. msft bug.
//
#pragma warning( disable : 4996 )

static VOID XennetEvtchnCallback(PVOID Context);
static PADAPTER MpAllocAdapterBlock(NDIS_HANDLE AdapterHandle);
static NDIS_STATUS MpFindAdapter(PADAPTER Adapter, NDIS_HANDLE Context,
                                 SUSPEND_TOKEN token);
static VOID MpIsr(PKDPC pDpc, PVOID pContext, PVOID Arg1, PVOID Arg2);
static VOID RestartNetifLate(VOID *ctxt, SUSPEND_TOKEN token);
static VOID RestartNetifEarly(VOID *ctxt, SUSPEND_TOKEN token);
static char *ReadBackend(const char *prefix, SUSPEND_TOKEN token);
static void ReleaseAdapter(PADAPTER Adapter);
#ifdef XEN_WIRELESS
static void MediaStateChangedCb(PVOID data);
#endif

static VOID
XennetDebugCb(PVOID data)
{
    PADAPTER Adapter = data;

    TraceInternal(("Netif %p\n", data));
    if (Adapter->Shutdown)
        TraceInternal(("Shutting down\n"));
    if (Adapter->XenbusPrefix)
        TraceInternal(("Prefix %s\n", Adapter->XenbusPrefix));
    if (Adapter->backend)
        TraceInternal(("backend %s\n", Adapter->backend));
    TraceInternal(("media_disconnect %d\n", Adapter->media_disconnect));

    TraceInternal(("Filter %lx\n", Adapter->CurrentPacketFilter));
    TraceInternal(("TX: %x:%x good, %x:%x error, %x:%x dropped\n",
               Adapter->TxGood, Adapter->TxError, Adapter->TxDropped));
    TraceInternal(("RX: %x:%x good, %x:%x error, %x:%x dropped\n",
               Adapter->RxGood, Adapter->RxError, Adapter->RxDropped));
    TraceInternal(("%d interrupts, %d DPCs.\n",
                 Adapter->nInterrupts,
                 Adapter->nDPCs));
    Adapter->nInterrupts = Adapter->nDPCs = 0;
    TraceInternal(("%d MAC misdirects.\n", Adapter->MacMisdirect));
    Adapter->MacMisdirect = 0;

    ReceiverDebugDump(&Adapter->Receiver);
    TransmitterDebugDump(&Adapter->Transmitter);
}

static void
MediaStateChangedCb(PVOID data);

static void
AdapterBackendStateChanged(void *_adapter);

NDIS_STATUS
MPInitialize(
    OUT PNDIS_STATUS    OpenErrorStatus,
    OUT PUINT           SelectedMediumIndex,
    IN PNDIS_MEDIUM     MediumArray,
    IN UINT             MediumArraySize,
    IN NDIS_HANDLE      MiniportAdapterHandle,
    IN NDIS_HANDLE      WrapperConfigurationContext
    )
/*++

Routine Description:

    The miniport initialization handler registered with call to
    NdisMRegisterMiniport

    Arguments:

    OpenErrorStatus        Not used by us.
    SelectedMediumIndex    Place-holder for what media we are using
    MediumArray        Array of ndis media passed down to us to pick 
                from
    MediumArraySize        Size of the array
    MiniportAdapterHandle    The handle NDIS uses to refer to us
    WrapperConfigurationContext    For use by NdisOpenConfiguration

    XXX the error paths leak slightly here.

Return Value:

    NDIS_STATUS_SUCCESS unless something goes wrong

--*/
{
    NDIS_STATUS     Status = NDIS_STATUS_FAILURE;
    UINT            i;
    PADAPTER        Adapter = NULL;
    SUSPEND_TOKEN   token;
    char *watch_path;

    TraceInfo(("%s: ====>\n", __FUNCTION__));

    /* Wait for xenbus to come up.  SMP guests sometimes try and
       initialise xennet and xenvbd in parallel when they come back
       from hibernation, and that causes problems. */
    if (!xenbus_await_initialisation()) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

#ifndef XEN_WIRELESS
    xenbus_write(XBT_NIL, "drivers/xennet", XENNET_VERSION);
#else
    xenbus_write(XBT_NIL, "drivers/xenwnet", XENNET_VERSION);
#endif

    /* We only support 802.3 */
    for (i = 0; i < MediumArraySize; i++) {
        if (MediumArray[i] == NdisMedium802_3) {
            *SelectedMediumIndex = i;
            break;
        }
    }
    if (i == MediumArraySize) {
        Status = NDIS_STATUS_UNSUPPORTED_MEDIA;
        goto out;
    }

    //
    // Allocate and initialize the nic-specific control structure
    //

    i = 0;
    do {
        Adapter = MpAllocAdapterBlock(MiniportAdapterHandle);
        if (Adapter == NULL) {
            TraceWarning (("Waiting for backend...\n"));
            NdisMSleep (1000000);   // 1 sec
        }
    } while ((Adapter == NULL) && (++i < 30));
    if (Adapter == NULL) {
        Status = NDIS_STATUS_RESOURCES;
        goto out;
    }

    TraceVerbose (("Device context is %p.\n", Adapter));

    //
    // Set the attributes now. 
    //

    NdisMSetAttributesEx(
        MiniportAdapterHandle,
        Adapter, 
        0,
        NDIS_ATTRIBUTE_DESERIALIZE |
        NDIS_ATTRIBUTE_USES_SAFE_BUFFER_APIS |
        NDIS_ATTRIBUTE_BUS_MASTER |
        NDIS_ATTRIBUTE_SURPRISE_REMOVE_OK |
        NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND,
        NdisInterfaceInternal);

    if (NdisVersion == XENNET_NDIS_51 && !XenPVFeatureEnabled(DEBUG_NIC_NO_DMA)) {
        /* We don't actually use any of the NDIS SG DMA resources, but
           WHQL requires that all miniports call
           NdisMInitializeScatterGatherDma.  We only call it for NDIS
           5.1, because the xenbus DMA controller isn't really clever
           enough to support NDIS 5.0 (and there's not much point
           fixing it, since we never actually do any device DMA). */
        TraceNotice(("DMA stuff enabled.\n"));
        if (NdisMInitializeScatterGatherDma(MiniportAdapterHandle,
                                            TRUE,
                                            XENNET_MAX_USER_DATA_PER_PACKET)
            != NDIS_STATUS_SUCCESS) {
            TraceWarning (("Failed to enable scatter-gather mode\n"));
        }
    } else {
        TraceNotice(("DMA stuff disabled.\n"));
    }

    token = EvtchnAllocateSuspendToken("xennet");
    Status = MpFindAdapter(Adapter, WrapperConfigurationContext, token);
    EvtchnReleaseSuspendToken(token);

    if (!NT_SUCCESS(Status)) {
        ReleaseAdapter(Adapter);
        goto out;
    }

    Adapter->WrapperConfigurationContext = WrapperConfigurationContext;

    Status = MpGetAdvancedSettings(Adapter);

    if (!NT_SUCCESS(Status)) {
        ReleaseAdapter(Adapter);
        goto out;
    }

    Status = MpSetAdapterSettings(Adapter);

    if (!NT_SUCCESS(Status)) {
        ReleaseAdapter(Adapter);
        goto out;
    }

    Adapter->debug_cb_handle = EvtchnSetupDebugCallback(XennetDebugCb,
                                                        Adapter);
#ifdef XEN_WIRELESS
    Status = WlanAdapterInitialize(Adapter);
    if (Status != NDIS_STATUS_SUCCESS) {
        goto out;
    }
    //
    // Fetch the media state from xenstore to start off with
    //
    TraceDebug (("Getting initial media state from xenstore:\n"));
    MediaStateChangedCb(Adapter);
#endif

    watch_path = Xmasprintf("%s/disconnect", Adapter->XenbusPrefix);
    if (watch_path) {
        Adapter->mediaWatch = xenbus_watch_path(watch_path,
                                                MediaStateChangedCb,
                                                Adapter);
        XmFreeMemory(watch_path);
    } else {
        TraceWarning(("Out of memory to watch for media disconnect?\n"));
    }

    watch_path = Xmasprintf("%s/backend-state", Adapter->XenbusPrefix);
    if (watch_path) {
        Adapter->BackStateWatch = xenbus_watch_path(watch_path,
                                                AdapterBackendStateChanged,
                                                Adapter);
        XmFreeMemory(watch_path);
    } else {
        TraceWarning(("Out of memory to watch for backend state?\n"));
    }

 out:

    TraceInfo(("%s: <==== (%p) (%08x)\n", __FUNCTION__, Adapter, Status));

    *OpenErrorStatus = Status;

    return Status;
}


static NDIS_STATUS
GetTransmitBufferSpace(NDIS_OID oid, PADAPTER Adapter, PVOID buf)
{
    *(PULONG)buf = PAGE_SIZE * NET_TX_RING_SIZE;

    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
GetReceiveBufferSpace(NDIS_OID oid, PADAPTER Adapter, PVOID buf)
{
    *(PULONG)buf = Adapter->mtu * Adapter->Receiver.Common.CurrNumRfd;

    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
GetDriverVersion(NDIS_OID oid, PADAPTER Adapter, PVOID buf)
{
    *(USHORT *)buf = NdisVersion;
    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
GetTcpTaskOffload(NDIS_OID oid, PADAPTER Adapter, PVOID buf)
{
    NDIS_TASK_OFFLOAD_HEADER *h = buf;
    NDIS_TASK_OFFLOAD *csum_task, *tso_task;
    NDIS_TASK_TCP_IP_CHECKSUM *csum_task_data;
    NDIS_TASK_TCP_LARGE_SEND *tso_task_data;

    TraceVerbose (("====> '%s'\n", __FUNCTION__));

    if (XenPVFeatureEnabled(DEBUG_HCT_MODE)) {
        /* Don't try to do any task offloads in HCT mode.  The tests
           are just too damn buggy. */
        TraceNotice(("Task offload disabled because we're in HCT mode.\n"));
        goto fail;
    }

    if ( h->Version != NDIS_TASK_OFFLOAD_VERSION ||
         h->Size != sizeof(NDIS_TASK_OFFLOAD_HEADER) ||
         h->EncapsulationFormat.Encapsulation != IEEE_802_3_Encapsulation ||
         !h->EncapsulationFormat.Flags.FixedHeaderSize ||
         h->EncapsulationFormat.EncapsulationHeaderSize != 14) {
        TraceWarning (("Bad tcp task offload header?\n"));
        goto fail;
    }

    h->OffsetFirstTask = sizeof(*h);
    csum_task = (NDIS_TASK_OFFLOAD *)(h + 1);
    csum_task_data = (NDIS_TASK_TCP_IP_CHECKSUM *)csum_task->TaskBuffer;
    tso_task = (NDIS_TASK_OFFLOAD *)(csum_task_data + 1);
    tso_task_data = (NDIS_TASK_TCP_LARGE_SEND *)tso_task->TaskBuffer;

    csum_task->Version = NDIS_TASK_OFFLOAD_VERSION;
    csum_task->Size = sizeof(*csum_task);
    csum_task->Task = TcpIpChecksumNdisTask;
    csum_task->OffsetNextTask =
        (ULONG)((ULONG_PTR)tso_task - (ULONG_PTR)csum_task);
    csum_task->TaskBufferLength = sizeof(*csum_task_data);

    /* Turn the bits I don't understand off. */
    memset(csum_task_data, 0, sizeof(*csum_task_data));

    csum_task_data->V4Transmit.IpChecksum = (Adapter->Properties.ip_csum & 1) ? 1 : 0;
    csum_task_data->V4Transmit.IpOptionsSupported = csum_task_data->V4Transmit.IpChecksum;

    if (Adapter->Transmitter.tx_csum_offload_safe) {
        csum_task_data->V4Transmit.TcpChecksum = (Adapter->Properties.tcp_csum & 1) ? 1 : 0;
        csum_task_data->V4Transmit.TcpOptionsSupported = csum_task_data->V4Transmit.TcpChecksum;

        csum_task_data->V4Transmit.UdpChecksum = (Adapter->Properties.udp_csum & 1) ? 1 : 0;
    }

    TraceVerbose (("TX IP csum offload %s.\n",
                   (csum_task_data->V4Transmit.IpChecksum) ? "available" : "not available"));
    TraceVerbose (("TX TCP csum offload %s.\n",
                   (csum_task_data->V4Transmit.TcpChecksum) ? "available" : "not available"));
    TraceVerbose (("TX UDP csum offload %s.\n",
                   (csum_task_data->V4Transmit.UdpChecksum) ? "available" : "not available"));

    /* We only turn on RX csum offload in fast and loose mode, since
       it leads to bad checksums on interdomain traffic.  If you send
       traffic from a tx-offload interface an rx-offload one, then the
       checksum never gets calculated, since dom0 assumes that it can
       make the receiving domain accept the packet by setting the
       csum-already-done bit, and this ends up being a fair bit
       faster.  This works most of the time, but tends to confuse
       packet sniffers and WHQL. */
    if (XenPVFeatureEnabled(DEBUG_NIC_FAST_AND_LOOSE)) {
        csum_task_data->V4Receive.IpChecksum = 0;
        csum_task_data->V4Receive.IpOptionsSupported = 0;

        csum_task_data->V4Receive.TcpChecksum = (Adapter->Properties.tcp_csum & 2) ? 1 : 0;
        csum_task_data->V4Receive.TcpOptionsSupported = csum_task_data->V4Receive.TcpChecksum;

        csum_task_data->V4Receive.UdpChecksum = (Adapter->Properties.udp_csum & 2) ? 1 : 0;

        TraceVerbose (("RX TCP csum offload %s.\n",
                       (csum_task_data->V4Receive.TcpChecksum) ? "available" : "not available"));
        TraceVerbose (("RX UDP csum offload %s.\n",
                       (csum_task_data->V4Receive.UdpChecksum) ? "available" : "not available"));
    } else {
        TraceVerbose (("RX csum offload not available.\n"));
    }

    if (XenPVFeatureEnabled(DEBUG_NIC_NO_TSO) ||
        !(Adapter->Transmitter.tso_avail && Adapter->Properties.lso)) {
        TraceNotice(("TSO not available.\n"));

        csum_task->OffsetNextTask = 0;
    } else {
        TraceNotice(("TSO available.\n"));

        tso_task->Version = NDIS_TASK_OFFLOAD_VERSION;
        tso_task->Size = sizeof(*tso_task);
        tso_task->Task = TcpLargeSendNdisTask;
        tso_task->OffsetNextTask = 0;
        tso_task->TaskBufferLength = sizeof(*tso_task_data);

        tso_task_data->Version = 0;
        tso_task_data->MaxOffLoadSize = XENNET_MAX_USER_DATA_PER_PACKET;
        tso_task_data->MinSegmentCount = 1;
        tso_task_data->TcpOptions = TRUE;
        tso_task_data->IpOptions = TRUE;
    }

    /* All done */
    TraceVerbose (("<==== '%s'\n", __FUNCTION__));
    return NDIS_STATUS_SUCCESS;

fail:
    TraceVerbose (("<==== '%s'\n", __FUNCTION__));
    return NDIS_STATUS_NOT_SUPPORTED;
}

static ULONG
GetMulticastListSize(NDIS_OID oid, PADAPTER Adapter)
{
    return Adapter->nrMulticastAddresses * ETH_LENGTH_OF_ADDRESS;
}

static NDIS_STATUS
GetMulticastList(NDIS_OID oid, PADAPTER Adapter, PVOID buf)
{
    NdisMoveMemory(buf, Adapter->MulticastAddress,
                   ETH_LENGTH_OF_ADDRESS * Adapter->nrMulticastAddresses);
    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
GetMaxEtherPayload(NDIS_OID oid, PADAPTER Adapter, PVOID buf)
{
    *(ULONG *)buf = Adapter->mtu - XENNET_PACKET_HDR_SIZE;
    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
GetMacOptions(NDIS_OID oid, PADAPTER Adapter, PVOID buf)
{
    RTL_OSVERSIONINFOEXW verInfo;
    static BOOLEAN noted = FALSE;

    XenutilGetVersionInfo(&verInfo);

    *(ULONG *)buf = NDIS_MAC_OPTION_TRANSFERS_NOT_PEND |
                    NDIS_MAC_OPTION_NO_LOOPBACK;

    // See http://msdn.microsoft.com/en-us/library/ms797610.aspx
    if (verInfo.dwMajorVersion == 5) {
        if (verInfo.dwMinorVersion == 0 ||  // 2000
            verInfo.dwMinorVersion == 1 ||  // XP
            (verInfo.dwMinorVersion == 2 &&
             verInfo.wProductType == VER_NT_WORKSTATION)) // XP x64
            if (!noted) {
                TraceNotice(("OID_GEN_MAC_OPTIONS: omitting NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA flag\n"));
                noted = TRUE;
            }
            goto done;
    }

    *(ULONG *)buf |= NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA;

done:
    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
GetMediaState(NDIS_OID oid, PADAPTER pAdapt, PVOID buf)
{
    if (pAdapt->media_disconnect)
        *(PNDIS_MEDIA_STATE)buf = NdisMediaStateDisconnected;
    else
        *(PNDIS_MEDIA_STATE)buf = NdisMediaStateConnected;
    return NDIS_STATUS_SUCCESS;
}

#ifndef XEN_WIRELESS
#define XENNET_LINK_SPEED   (10000000000ull)
#else
#define XENNET_LINK_SPEED   (540000000ull)
#endif

static NDIS_STATUS
GetLinkState(NDIS_OID oid, PADAPTER Adapter, PVOID buf)
{
    PNDIS_LINK_STATE LinkState = buf;

    TraceInfo(("%s (%s)\n", __FUNCTION__, Adapter->XenbusPrefix));

    NdisZeroMemory(LinkState, sizeof(NDIS_LINK_STATE));    

    LinkState->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    LinkState->Header.Revision = NDIS_LINK_STATE_REVISION_1;
    LinkState->Header.Size = NDIS_LINK_STATE_REVISION_1;

    if (Adapter->media_disconnect) {
        TraceInfo(("%s: DISCONNECTED\n", __FUNCTION__));
        LinkState->MediaConnectState = MediaConnectStateDisconnected;
        LinkState->MediaDuplexState = MediaDuplexStateUnknown;
        LinkState->XmitLinkSpeed = LinkState->RcvLinkSpeed = NDIS_LINK_SPEED_UNKNOWN;
        LinkState->PauseFunctions = NdisPauseFunctionsUnknown;
    } else {
        TraceInfo(("%s: CONNECTED\n", __FUNCTION__));
        LinkState->MediaConnectState = MediaConnectStateConnected;
        LinkState->MediaDuplexState = MediaDuplexStateFull;
        LinkState->XmitLinkSpeed = LinkState->RcvLinkSpeed = XENNET_LINK_SPEED;
        LinkState->PauseFunctions = NdisPauseFunctionsUnsupported;
    }

    return NDIS_STATUS_SUCCESS;
}

struct oid_template {
    NDIS_OID oid;
    enum { oid_constant, oid_adapt_off, oid_ptr, oid_cb, oid_int64,
           oid_int64_const, oid_unsupported } type;
    int size;
    union {
        /* Ugliness: you can only use a static initializer for
           the first element in a union, and so it has to be
           something which can represent any of the others. */
        struct {
            ULONG_PTR d1;
            ULONG_PTR d2;
        } hack;
        struct {
            ULONG64 val;
        } constant;
        struct {
            ULONG off;
        } adapt_offset;
        struct {
            PVOID p;
        } ptr;
        struct {
            int (*size_cb)(NDIS_OID oid, PADAPTER adapt);
            NDIS_STATUS (*data_cb)(NDIS_OID oid, PADAPTER adapt,
                                   PVOID buf);
        } cb;
    } u;
};

/* 64 bit integer oids are special because we're expected to cast them
   to 32 bit ones as appropriate. */
#define INT64_OID(oid, field) \
{ OID_ ## oid , oid_int64, -1, { { (ULONG_PTR)(&((PADAPTER)0)->field), 0 } } }
#define CONSTANT_OID(oid, val, size) \
{ OID_ ## oid , oid_constant, (size), { { (val), (val) >> (sizeof(ULONG_PTR)*8) } } }
#define INT64_CONST_OID(oid, val) \
{ OID_ ## oid , oid_int64_const, 0, { { (val), (val) >> (sizeof(ULONG_PTR)*8) } } }
#define PTR_OID(oid, p, size) \
{ OID_ ## oid , oid_ptr, (size), { { (ULONG_PTR)(p), 0 } } }
#define OFFSET_OID(oid, field, size) \
{ OID_ ## oid , oid_adapt_off, (size), { { (ULONG_PTR)(&((PADAPTER)0)->field), 0} }}
#define CB_OID(oid, size, size_cb, data_cb) \
{ OID_ ## oid , oid_cb, (size), { { (ULONG_PTR)(size_cb), (ULONG_PTR)(data_cb) } } }

/* Used for OIDs which we don't support and which we believe to be
   safe, just to shut up the warnings. */
#define UNSUPPORTED_OID(oid) \
{ OID_ ## oid , oid_unsupported }

static ULONG GetSupportedListSize(NDIS_OID oid, PADAPTER Adapter);
static NDIS_STATUS GetSupportedList(NDIS_OID oid, PADAPTER Adapter, PVOID buf);

//
// Suppress shift overflow warning in CONSTANT_OID() for this table
//
#pragma warning( disable : 4293 )

static const struct oid_template
OidHandlers[] = {
    CONSTANT_OID(GEN_HARDWARE_STATUS, NdisHardwareStatusReady,
             sizeof(NDIS_HARDWARE_STATUS)),
    CONSTANT_OID(GEN_MEDIA_SUPPORTED, NdisMedium802_3,
             sizeof(NDIS_MEDIUM)),
    CONSTANT_OID(GEN_MEDIA_IN_USE, NdisMedium802_3, sizeof(NDIS_MEDIUM)),
#ifndef XEN_WIRELESS
    CONSTANT_OID(GEN_PHYSICAL_MEDIUM, NdisPhysicalMediumUnspecified,
                 sizeof(NDIS_PHYSICAL_MEDIUM)),
#else
    CONSTANT_OID(GEN_PHYSICAL_MEDIUM, NdisPhysicalMediumWirelessLan,
                 sizeof(NDIS_PHYSICAL_MEDIUM)),
#endif
    CB_OID(GEN_CURRENT_LOOKAHEAD, sizeof(ULONG), NULL, GetMaxEtherPayload),
    CB_OID(GEN_MAXIMUM_LOOKAHEAD, sizeof(ULONG), NULL, GetMaxEtherPayload),
    CB_OID(GEN_MAXIMUM_FRAME_SIZE, sizeof(ULONG), NULL, GetMaxEtherPayload),
    OFFSET_OID(GEN_MAXIMUM_TOTAL_SIZE, mtu, sizeof(ULONG)),
    CONSTANT_OID(GEN_RECEIVE_BLOCK_SIZE, PAGE_SIZE, sizeof(ULONG)),
    CONSTANT_OID(GEN_TRANSMIT_BLOCK_SIZE, 1, sizeof(ULONG)),
    CB_OID(GEN_MAC_OPTIONS, sizeof (ULONG), NULL, GetMacOptions),
#ifndef XEN_WIRELESS
    CONSTANT_OID(GEN_LINK_SPEED, 2000 * 10000, sizeof(ULONG)),
#else
    CONSTANT_OID(GEN_LINK_SPEED, 54 * 10000, sizeof(ULONG)),
#endif
    CB_OID(GEN_MEDIA_CONNECT_STATUS, sizeof(NDIS_MEDIA_STATE),
           NULL, GetMediaState),
    PTR_OID(GEN_VENDOR_DESCRIPTION, NIC_VENDOR_DESC,
        sizeof(NIC_VENDOR_DESC)),
    CONSTANT_OID(GEN_VENDOR_DRIVER_VERSION, 0x40000, sizeof(ULONG)),
    CB_OID(GEN_DRIVER_VERSION, sizeof(USHORT), NULL, GetDriverVersion),
    CONSTANT_OID(802_3_MAXIMUM_LIST_SIZE, NR_MCAST_ADDRESSES, sizeof(ULONG)),
    /* We're deserialised, so NDIS ignores this OID.  It's still
       documented as being required, though. */
    CONSTANT_OID(GEN_MAXIMUM_SEND_PACKETS, NET_TX_RING_SIZE, sizeof(ULONG)),
    CONSTANT_OID(GEN_VENDOR_ID, 0x5853, 4),
    OFFSET_OID(802_3_PERMANENT_ADDRESS, PermanentAddress,
               ETH_LENGTH_OF_ADDRESS),
    OFFSET_OID(802_3_CURRENT_ADDRESS, CurrentAddress,
               ETH_LENGTH_OF_ADDRESS),
    OFFSET_OID(GEN_CURRENT_PACKET_FILTER, CurrentPacketFilter, sizeof(ULONG)),
    INT64_OID(GEN_XMIT_OK, TxGood),
    INT64_OID(GEN_RCV_OK, RxGood),
    INT64_OID(GEN_XMIT_ERROR, TxError),
    INT64_OID(GEN_RCV_ERROR, RxError),
    INT64_CONST_OID(GEN_RCV_CRC_ERROR, 0),
    INT64_OID(GEN_RCV_NO_BUFFER, RxDropped),
        INT64_CONST_OID(802_3_RCV_ERROR_ALIGNMENT, 0),
        INT64_CONST_OID(802_3_XMIT_ONE_COLLISION, 0),
        INT64_CONST_OID(802_3_XMIT_MORE_COLLISIONS, 0),
    CONSTANT_OID(GEN_TRANSMIT_QUEUE_LENGTH, 0, sizeof(ULONG)),
    CB_OID(GEN_SUPPORTED_LIST, -1, GetSupportedListSize,
           GetSupportedList),
    CB_OID(GEN_TRANSMIT_BUFFER_SPACE, sizeof(ULONG),
           NULL, GetTransmitBufferSpace),
    CB_OID(GEN_RECEIVE_BUFFER_SPACE, sizeof(ULONG),
           NULL, GetReceiveBufferSpace),
    CB_OID(TCP_TASK_OFFLOAD,
           sizeof(NDIS_TASK_OFFLOAD_HEADER) +
           FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer) * 2 +
           sizeof(NDIS_TASK_TCP_IP_CHECKSUM) +
           sizeof(NDIS_TASK_TCP_LARGE_SEND),
           NULL, GetTcpTaskOffload),
    CB_OID(802_3_MULTICAST_LIST, -1, GetMulticastListSize,
           GetMulticastList),

    /* Chimney OIDs which Vista queries even if you don't support
       chimney offload. */
    UNSUPPORTED_OID(IP6_OFFLOAD_STATS),
    UNSUPPORTED_OID(IP4_OFFLOAD_STATS),

    /* Other OIDs which we don't support and which we don't think we
       need to support. */
#ifndef XEN_WIRELESS
    UNSUPPORTED_OID(802_11_CAPABILITY),
    UNSUPPORTED_OID(802_11_INFRASTRUCTURE_MODE),
    UNSUPPORTED_OID(802_11_BSSID),
    UNSUPPORTED_OID(802_11_CONFIGURATION),
#endif
    UNSUPPORTED_OID(GEN_MEDIA_CAPABILITIES),
    UNSUPPORTED_OID(GEN_SUPPORTED_GUIDS),
    UNSUPPORTED_OID(FFP_SUPPORT),
    UNSUPPORTED_OID(PNP_CAPABILITIES),

#ifdef XEN_WIRELESS
    CB_OID(802_11_BSSID_LIST, -1, WlanGetScanListSize, WlanGetScanList),
    CB_OID(802_11_INFRASTRUCTURE_MODE, sizeof(NDIS_802_11_NETWORK_INFRASTRUCTURE), NULL, WlanGetInfrastructureMode),
    CB_OID(802_11_AUTHENTICATION_MODE, sizeof(NDIS_802_11_AUTHENTICATION_MODE), NULL, WlanGetAuthenticationMode),
    CB_OID(802_11_ENCRYPTION_STATUS, sizeof(NDIS_802_11_ENCRYPTION_STATUS), NULL, WlanGetEncryptionMode),
    CB_OID(802_11_SSID, sizeof(NDIS_802_11_SSID), NULL, WlanGetSSID),
    CB_OID(802_11_NETWORK_TYPE_IN_USE, sizeof(NDIS_802_11_NETWORK_TYPE), NULL, WlanGetNetworkTypeInUse),
    CB_OID(802_11_BSSID, sizeof(NDIS_802_11_MAC_ADDRESS), NULL, WlanGetBssid),
    CB_OID(802_11_RSSI, sizeof(NDIS_802_11_RSSI), NULL, WlanGetRSSI),
    CB_OID(802_11_SUPPORTED_RATES, sizeof(NDIS_802_11_RATES), NULL, WlanGetSupportedRates),
    CB_OID(802_11_CONFIGURATION, sizeof(NDIS_802_11_CONFIGURATION), NULL, WlanGetRadioConfiguration),

    // Mandatory for WPA/2
    UNSUPPORTED_OID(802_11_ASSOCIATION_INFORMATION),
    UNSUPPORTED_OID(802_11_CAPABILITY),
    UNSUPPORTED_OID(802_11_PMKID),

    // Recommended
    CB_OID(802_11_NETWORK_TYPES_SUPPORTED, -1, WlanGetNetworkTypeListSize, WlanGetNetworkTypes),
    UNSUPPORTED_OID(802_11_STATISTICS),
    UNSUPPORTED_OID(802_11_POWER_MODE),
    UNSUPPORTED_OID(802_11_MEDIA_STREAM_MODE),

    //Optional
    UNSUPPORTED_OID(802_11_TX_POWER_LEVEL),
    UNSUPPORTED_OID(802_11_RSSI_TRIGGER),
    UNSUPPORTED_OID(802_11_FRAGMENTATION_THRESHOLD),
    UNSUPPORTED_OID(802_11_RTS_THRESHOLD),
    UNSUPPORTED_OID(802_11_NUMBER_OF_ANTENNAS),
    UNSUPPORTED_OID(802_11_RX_ANTENNA_SELECTED),
    UNSUPPORTED_OID(802_11_TX_ANTENNA_SELECTED),
    UNSUPPORTED_OID(802_11_DESIRED_RATES),
    UNSUPPORTED_OID(802_11_PRIVACY_FILTER),
#endif

    /* Only in NDIS 6.0, but Windows queries it anyway. */
#ifndef OID_GEN_RECEIVE_SCALE_CAPABILITIES
#define OID_GEN_RECEIVE_SCALE_CAPABILITIES 0x00010203
#endif
#ifndef OID_GEN_INTERRUPT_MODERATION
#define OID_GEN_INTERRUPT_MODERATION 0x00010209
#endif

    UNSUPPORTED_OID(GEN_RECEIVE_SCALE_CAPABILITIES),
    UNSUPPORTED_OID(GEN_INTERRUPT_MODERATION),
    UNSUPPORTED_OID(TCP_OFFLOAD_HARDWARE_CAPABILITIES),

    // NdisTest.net queries this, even for NDIS5 drivers, and uses the
    // TX link speed to determine whether WoL magic packet support is
    // required. If link speed is 10G or more then it's not required, so
    // say we're 10G!
    CB_OID(GEN_LINK_STATE, sizeof (NDIS_LINK_STATE), NULL, GetLinkState)
};
#pragma warning( default : 4293 )

static ULONG
GetSupportedListSize(NDIS_OID oid, PADAPTER Adapter)
{
    int i;
    ULONG count = 0;

    for (i = 0; i < sizeof(OidHandlers)/sizeof(OidHandlers[0]); i++) {
        if (OidHandlers[i].type != oid_unsupported)
            count++;
    }
    return count * sizeof(NDIS_OID);
}

static NDIS_STATUS
GetSupportedList(NDIS_OID oid, PADAPTER Adapter, PVOID buf)
{
    PNDIS_OID p = buf;
    int i, j;
    for (i = j = 0; i < sizeof(OidHandlers)/sizeof(OidHandlers[0]); i++) {
        if (OidHandlers[i].type != oid_unsupported) {
            p[j] = OidHandlers[i].oid;
            j++;
        }
    }
    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
MPQueryInformation(
    IN  NDIS_HANDLE  MiniportAdapterContext,
    IN  NDIS_OID     Oid,
    IN  PVOID        InformationBuffer,
    IN  ULONG        InformationBufferLength,
    OUT PULONG       BytesWritten,
    OUT PULONG       BytesNeeded
    )
/*++
Routine Description:

    MiniportQueryInformation handler            

Arguments:

    MiniportAdapterContext  Pointer to the adapter structure
    Oid                     Oid for this query
    InformationBuffer       Buffer for information
    InformationBufferLength Size of this buffer
    BytesWritten            Specifies how much info is written
    BytesNeeded             In case the buffer is smaller than what we need, tell them how much is needed
    
Return Value:
    
    NDIS_STATUS_SUCCESS
    NDIS_STATUS_NOT_SUPPORTED
    NDIS_STATUS_BUFFER_TOO_SHORT
    
--*/
{
    PADAPTER                    Adapter;
    ULONG                       i;
    ULONG                       bytes_avail;
    const void                 *source_buf = NULL;
    NDIS_STATUS                 res;

    Adapter = (PADAPTER) MiniportAdapterContext;

    if (Adapter->RemovalPending) {
        TraceVerbose(("Query while pending removal, oid 0x%08x.\n", Oid));
        return NDIS_STATUS_NOT_ACCEPTED;
    }

    for (i = 0; i < sizeof(OidHandlers)/sizeof(OidHandlers[0]); i++) {
        if (OidHandlers[i].oid == Oid)
            break;
    }
    if (i == sizeof(OidHandlers)/sizeof(OidHandlers[0])) {
        TraceWarning(("No handler for oid 0x%08x.\n", Oid));
        return NDIS_STATUS_NOT_SUPPORTED;
    }
    /* Note that we return for callback oids, and break out of the
       switch for other types. */
    bytes_avail = OidHandlers[i].size;
    switch (OidHandlers[i].type) {
    case oid_unsupported:
        return NDIS_STATUS_NOT_SUPPORTED;
    case oid_constant:
        source_buf = &OidHandlers[i].u.constant.val;
        break;
    case oid_adapt_off:
        source_buf =
            (PVOID)((char *)Adapter +
                OidHandlers[i].u.adapt_offset.off);
        break;
    case oid_int64:
    case oid_int64_const:
        if (OidHandlers[i].type == oid_int64)
            source_buf =
                (PVOID)((char *)Adapter +
                        OidHandlers[i].u.adapt_offset.off);
        else
            source_buf =
                (PVOID)(&OidHandlers[i].u.constant.val);
        *BytesNeeded = 8;
        if (InformationBufferLength >= 8) {
            *(ULONG64 *)InformationBuffer = *(ULONG64 *)source_buf;
            *BytesWritten = 8;
/**/        return NDIS_STATUS_SUCCESS;
        } else if (InformationBufferLength == 4) {
            *(unsigned *)InformationBuffer = *(unsigned *)source_buf;
            *BytesWritten = 4;
/**/        return NDIS_STATUS_SUCCESS;
        } else {
            *BytesWritten = 0;
/**/        return NDIS_STATUS_BUFFER_TOO_SHORT;
        }
    case oid_ptr:
        source_buf = OidHandlers[i].u.ptr.p;
        break;
    case oid_cb:
        if (bytes_avail == -1)
            bytes_avail = OidHandlers[i].u.cb.size_cb(Oid, Adapter);
        *BytesNeeded = bytes_avail;
        if (bytes_avail <= InformationBufferLength) {
            res = OidHandlers[i].u.cb.data_cb(Oid, Adapter,
                        InformationBuffer);
            *BytesWritten = bytes_avail;
/**/        return res;
        } else {
            *BytesWritten = 0;
/**/            return NDIS_STATUS_BUFFER_TOO_SHORT;
        }
        break;
    default:
        TraceCritical (("Bad oid type %d.\n", OidHandlers[i].type));
        ASSERT(FALSE);
    }

    *BytesNeeded = bytes_avail;
    if (bytes_avail <= InformationBufferLength) {
        NdisMoveMemory(InformationBuffer, source_buf, bytes_avail);
        *BytesWritten = bytes_avail;
        return NDIS_STATUS_SUCCESS;
    } else {
        *BytesWritten = 0;
        return NDIS_STATUS_BUFFER_TOO_SHORT;
    }
}

static NDIS_STATUS
SetTcpTaskOffload(PVOID data, ULONG avail,
                  PULONG BytesRead, PULONG BytesNeeded,
                  PADAPTER Adapter)
{
    PNDIS_TASK_OFFLOAD_HEADER h;
    PNDIS_TASK_OFFLOAD task;
    PNDIS_TASK_TCP_IP_CHECKSUM csum_task = NULL;
    PNDIS_TASK_TCP_LARGE_SEND tso_task = NULL;
    ULONG tmp1;
    NTSTATUS status;

    TraceVerbose (("====> '%s'\n", __FUNCTION__));

    status = NDIS_STATUS_NOT_SUPPORTED;
    if (XenPVFeatureEnabled(DEBUG_HCT_MODE))
        goto fail;

    /* Validate that the offload request is actually valid. */
    h = data;
    *BytesRead = 0;
    *BytesNeeded = sizeof(*h);
    
    status = NDIS_STATUS_INVALID_LENGTH;
    if ( *BytesNeeded > avail ) {
        TraceWarning (("NDIS tried to enable task offload with a buffer too small for a task offload header?\n"));
        goto fail;
    }
    *BytesRead = sizeof(*h);

    status = NDIS_STATUS_INVALID_DATA;
    if ( h->Version != NDIS_TASK_OFFLOAD_VERSION ||
         h->Size != sizeof(NDIS_TASK_OFFLOAD_HEADER) ) {
        TraceWarning (("Bad tcp task offload header?\n"));
        TraceWarning (("Version %d.%d, size %d.%d\n",
                       h->Version, NDIS_TASK_OFFLOAD_VERSION,
                       h->Size, sizeof(NDIS_TASK_OFFLOAD_HEADER)));
        goto fail;
    }
    if ( h->OffsetFirstTask == 0 ) {
        /* Disable all offload */
        TraceInfo (("Disable all task offload.\n"));
        if (Adapter->Receiver.rx_csum_tcp_offload) {
            status = xenbus_write_feature_flag(XBT_NIL, Adapter->XenbusPrefix,
                                               "feature-no-csum-offload",
                                               TRUE);
            if (!NT_SUCCESS(status)) {
                TraceWarning(("Failed to disable checksum offload!\n"));
                goto fail;
            }
        }

        Adapter->Transmitter.tx_csum_tcp_offload = 0;
        Adapter->Transmitter.tx_csum_udp_offload = 0;
        Adapter->Transmitter.tx_csum_ip_offload = 0;
        Adapter->Receiver.rx_csum_udp_offload = 0;
        Adapter->Receiver.rx_csum_tcp_offload = 0;
        Adapter->Transmitter.tx_seg_offload = 0;
        goto done;
    }

    status = NDIS_STATUS_INVALID_DATA;
    if (h->EncapsulationFormat.Encapsulation != IEEE_802_3_Encapsulation ||
        !h->EncapsulationFormat.Flags.FixedHeaderSize ||
        h->EncapsulationFormat.EncapsulationHeaderSize != 14 ||
        h->OffsetFirstTask != sizeof(*h) ) {
        TraceWarning (("Bad tcp task offload header?\n"));
        TraceWarning (("Encap format %d.%d, header size %d.14, offset first %d.%d.\n",
                       h->EncapsulationFormat.Encapsulation,
                       IEEE_802_3_Encapsulation,
                       h->EncapsulationFormat.EncapsulationHeaderSize,
                       h->OffsetFirstTask, sizeof(*h)));
        goto fail;
    }

    *BytesNeeded = h->OffsetFirstTask;
    *BytesRead   = h->OffsetFirstTask;
    task = (NDIS_TASK_OFFLOAD *)((ULONG_PTR)data + *BytesRead);

    while (1) {
        tmp1 = *BytesRead;
        *BytesNeeded += FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer);
        if ( *BytesNeeded > avail ) {
            TraceWarning (("Bad tcp task offload: not enough data for task.\n"));
            return NDIS_STATUS_INVALID_LENGTH;
        }
        *BytesRead += FIELD_OFFSET(NDIS_TASK_OFFLOAD, TaskBuffer);

        /* Surprise!  NDIS only bothers to set task->Version and
           task->Size for the *first* offload task, despite what the
           documentation may think (at least on w2k3sp2 with ndis
           5.1).  It's not worth trying to validate these fields. */
#if 0
        status = NDIS_STATUS_INVALID_DATA;
        if ( task->Version != NDIS_TASK_OFFLOAD_VERSION ||
             task->Size != sizeof(*task) ) {
            TraceWarning (("Bad tcp task offload: task structure invalid (version %d, should be %d, size %d, should be %d, avail %d - %d).\n",
                           task->Version, NDIS_TASK_OFFLOAD_VERSION,
                           task->Size, sizeof(*task),
                           avail, *BytesNeeded));
            goto fail;
        }
#endif

        switch (task->Task) {
        case TcpIpChecksumNdisTask:
            *BytesNeeded += sizeof(*csum_task);

            status = NDIS_STATUS_INVALID_LENGTH;
            if ( *BytesNeeded > avail ) {
                TraceWarning (("Bad tcp task offload: not enough data for checksum task.\n"));
                goto fail;
            }

            status = NDIS_STATUS_INVALID_DATA;
            if ( task->TaskBufferLength != sizeof(*csum_task) ) {
                TraceWarning (("Bad tcp task offload: not enough data for checksum offload.\n"));
                goto fail;
            }
            *BytesRead += sizeof(*csum_task);

            csum_task = (NDIS_TASK_TCP_IP_CHECKSUM *)task->TaskBuffer;

            status = NDIS_STATUS_NOT_SUPPORTED;

            if ( csum_task->V4Receive.IpChecksum ||
                 csum_task->V4Receive.IpOptionsSupported ||
                 csum_task->V6Receive.IpOptionsSupported ||
                 csum_task->V6Receive.TcpOptionsSupported ||
                 csum_task->V6Receive.TcpChecksum ||
                 csum_task->V6Receive.UdpChecksum ||
                 csum_task->V6Transmit.IpOptionsSupported ||
                 csum_task->V6Transmit.TcpOptionsSupported ||
                 csum_task->V6Transmit.TcpChecksum ||
                 csum_task->V6Transmit.UdpChecksum ) {
                TraceWarning (("Rejecting bad checksum offload request.\n"));
                goto fail;
            }

            if ( csum_task->V4Transmit.IpChecksum &&
                 !(Adapter->Transmitter.tx_csum_offload_safe && (Adapter->Properties.ip_csum & 1))) {
                TraceWarning (("NDIS tried to enable TX IP csum offload even though we don't support it.\n"));
                goto fail;
            }

            if ( (csum_task->V4Transmit.TcpChecksum || csum_task->V4Transmit.TcpOptionsSupported) &&
                 !(Adapter->Transmitter.tx_csum_offload_safe && (Adapter->Properties.tcp_csum & 1))) {
                TraceWarning (("NDIS tried to enable TX TCP csum offload even though we don't support it.\n"));
                goto fail;
            }

            if ( csum_task->V4Transmit.UdpChecksum &&
                 !(Adapter->Transmitter.tx_csum_offload_safe && (Adapter->Properties.udp_csum & 1))) {
                TraceWarning (("NDIS tried to enable TX UDP csum offload even though we don't support it.\n"));
                goto fail;
            }

            if ( (csum_task->V4Receive.TcpChecksum || csum_task->V4Receive.TcpOptionsSupported) &&
                 !(Adapter->Properties.tcp_csum & 2)) {
                TraceWarning (("NDIS tried to enable RX TCP csum offload even though we don't support it.\n"));
                goto fail;
            }

            if ( csum_task->V4Receive.UdpChecksum &&
                 !(Adapter->Properties.tcp_csum & 2)) {
                TraceWarning (("NDIS tried to enable RX TCP csum offload even though we don't support it.\n"));
                goto fail;
            }

            TraceVerbose (("NDIS provided a valid checksum offload descriptor.\n"));
            break;

        case TcpLargeSendNdisTask:
            *BytesNeeded += sizeof(*tso_task);

            status = NDIS_STATUS_INVALID_LENGTH;
            if ( *BytesNeeded > avail ) {
                TraceWarning (("Bad tcp task offload: not enough data for segmentation task.\n"));
                goto fail;
            }

            status = NDIS_STATUS_INVALID_DATA;
            if ( task->TaskBufferLength != sizeof(*tso_task) ) {
                TraceWarning (("Bad tcp task offload: not enough data for segmentation offload.\n"));
                goto fail;
            }

            *BytesRead += sizeof(*tso_task);

            tso_task = (NDIS_TASK_TCP_LARGE_SEND *)task->TaskBuffer;

            status = NDIS_STATUS_NOT_SUPPORTED;

            if ( !(Adapter->Transmitter.tso_avail && Adapter->Properties.lso) &&
                 tso_task->MaxOffLoadSize != 0 ) {
                TraceWarning (("NDIS tried to enable large send offload even though we don't support it.\n"));
                goto fail;
            }

            if ( tso_task->Version != 0 ||
                 tso_task->MaxOffLoadSize > XENNET_MAX_USER_DATA_PER_PACKET ||
                 tso_task->MinSegmentCount == 0 ) {
                TraceWarning (("NDIS tried to enable invalid segmentation offload.\n"));
                goto fail;
            }

            TraceVerbose(("NDIS provided a good tso descriptor structure, max size %d.\n",
                          tso_task->MaxOffLoadSize));
           break;

        default:
            status = NDIS_STATUS_NOT_SUPPORTED;
            TraceWarning (("NDIS tried to enable an unknown task offload %d.\n",
                           task->Task));
            goto fail;
        }

        if (task->OffsetNextTask == 0)
            break;
        *BytesNeeded = *BytesRead = tmp1 + task->OffsetNextTask;
        task = (PNDIS_TASK_OFFLOAD)((ULONG_PTR)data + *BytesRead);
    }

    /* We now know that we can accept the offload request.  This
       should really by synchronised with SendPackets, but that
       doesn't seem to be possible within the confines of the NDIS
       API.  Hopefully, NDIS is clever enough to stop transmitting
       while it's changing these flag.  If it isn't then there isn't
       really anything we can do about it. */
    /* (Just acquiring the send lock here isn't enough, because you
       can get a race where NDIS starts submitting a packet with
       offload enabled, then we get in and turn offload off, and then
       SendPackets acquires the lock.  It'll then get very confused
       and transmit packets with bogus checksums and so forth.) */

    if ( csum_task ) {
        /* We have to do rx csum offload first, so that if we fail
           talking to the backend we can back out easily without
           leaving the operation half-applied. */
        if ( csum_task->V4Receive.TcpChecksum ) {
            TraceInfo (("RX csum offload enabled: %d/%d.\n",
                        csum_task->V4Receive.TcpChecksum,
                        csum_task->V4Receive.UdpChecksum));
            /* Tell the backend that we can now handle CSUM_BLANK
             * receives.  If this fails, the worst that can happen is
             * that CSUM_BLANK doesn't get set in a few places where
             * it would be safe, which only hurts performance rather
             * than correctness, so ignore the return value. */
            xenbus_write_feature_flag(XBT_NIL, Adapter->XenbusPrefix,
                                      "feature-no-csum-offload",
                                      FALSE);
            Adapter->Receiver.rx_csum_tcp_offload = 1;
            Adapter->Receiver.rx_csum_udp_offload = csum_task->V4Receive.UdpChecksum;
        } else {
            TraceInfo (("RX csum offload disabled.\n"));
            /* Stop the backend sending CSUM_BLANK receives.  This
               isn't synchronised with anything, so we might end up
               with a few arriving anyway, and they'll just get
               dropped.  Oh well, nothing we can do.*/
            if (Adapter->Receiver.rx_csum_tcp_offload) {
                status = xenbus_write_feature_flag(XBT_NIL,
                                                   Adapter->XenbusPrefix,
                                                   "feature-no-csum-offload",
                                                   TRUE);
                if (!NT_SUCCESS(status)) {
                    TraceWarning(("Failed to turn off rx csum offload!\n"));
                    goto fail;
                }
            }
            Adapter->Receiver.rx_csum_udp_offload = 0;
            Adapter->Receiver.rx_csum_tcp_offload = 0;
        }

        if (csum_task->V4Transmit.TcpChecksum) {
            TraceInfo (("TX TCP csum offload enabled.\n"));
            Adapter->Transmitter.tx_csum_tcp_offload = 1;
        } else {
            TraceInfo (("TX TCP csum offload disabled.\n"));
            Adapter->Transmitter.tx_csum_tcp_offload = 0;
        }
        if (csum_task->V4Transmit.UdpChecksum) {
            TraceInfo (("TX UDP csum offload enabled.\n"));
            Adapter->Transmitter.tx_csum_udp_offload = 1;
        } else {
            TraceInfo (("TX UDP csum offload disabled.\n"));
            Adapter->Transmitter.tx_csum_udp_offload = 0;
        }
        if (csum_task->V4Transmit.IpChecksum) {
            TraceInfo (("TX IP csum offload enabled.\n"));
            Adapter->Transmitter.tx_csum_ip_offload = 1;
        } else {
            TraceInfo (("TX IP csum offload disabled.\n"));
            Adapter->Transmitter.tx_csum_ip_offload = 0;
        }
    } else {
        TraceInfo (("All csum offload disabled.\n"));
        if (Adapter->Receiver.rx_csum_tcp_offload) {
            status = xenbus_write_feature_flag(XBT_NIL, Adapter->XenbusPrefix,
                                               "feature-no-csum-offload",
                                               TRUE);
            if (!NT_SUCCESS(status)) {
                TraceWarning(("Failed to disable RX csum offload!\n"));
                return status;
            }
        }
        Adapter->Receiver.rx_csum_tcp_offload = 0;
        Adapter->Receiver.rx_csum_udp_offload = 0;
        Adapter->Transmitter.tx_csum_tcp_offload = 0;
        Adapter->Transmitter.tx_csum_udp_offload = 0;
        Adapter->Transmitter.tx_csum_ip_offload = 0;
    }

    if (tso_task && tso_task->MaxOffLoadSize) {
        TraceInfo (("TSO enabled.\n"));
        Adapter->Transmitter.tx_seg_offload = 1;
    } else {
        TraceInfo (("TSO disabled.\n"));
        Adapter->Transmitter.tx_seg_offload = 0;
    }

done:
    TraceVerbose (("<==== '%s'\n", __FUNCTION__));

    return NDIS_STATUS_SUCCESS;

fail:
    TraceVerbose (("<==== '%s'\n", __FUNCTION__));

    return status;
}

NDIS_STATUS
MPSetInformation(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN NDIS_OID Oid,
    IN PVOID InformationBuffer,
    IN ULONG InformationBufferLength,
    OUT PULONG BytesRead,
    OUT PULONG BytesNeeded
    )
/*++
Routine Description:

    This is the handler for an OID set operation.  The only operations
    that really change the configuration of the adapter are set
    PACKET_FILTER, and SET_MULTICAST.
    
Arguments:
    
    MiniportAdapterContext  Pointer to the adapter structure
    Oid                     Oid for this query
    InformationBuffer       Buffer for information
    InformationBufferLength Size of this buffer
    BytesRead               Specifies how much info is read
    BytesNeeded             In case the buffer is smaller than what we need, tell them how much is needed
    
Return Value:

    NDIS_STATUS_SUCCESS        
    NDIS_STATUS_INVALID_LENGTH 
    NDIS_STATUS_INVALID_OID    
    NDIS_STATUS_NOT_SUPPORTED  
    NDIS_STATUS_NOT_ACCEPTED   
    
--*/
{
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
    PADAPTER Adapter = (PADAPTER) MiniportAdapterContext;

    TraceDebug (("====> '%s'\n", __FUNCTION__));

    if (Adapter->RemovalPending) {
        TraceVerbose(("Set while pending removal, oid 0x%08x.\n", Oid));
        return NDIS_STATUS_NOT_ACCEPTED;
    }

    *BytesRead = 0;
    *BytesNeeded = 0;

    Status = NDIS_STATUS_SUCCESS;
    switch(Oid)
    {
    case OID_GEN_CURRENT_LOOKAHEAD:
        if (InformationBufferLength != 4)
            return NDIS_STATUS_INVALID_LENGTH;
        TraceVerbose (("Trying to set lookahead -> ignore but report success (%x).\n",
                       *(PULONG)InformationBuffer));
        *BytesRead = 4;
        break;

    case OID_GEN_CURRENT_PACKET_FILTER:
        if (InformationBufferLength != 4) {
            Status = NDIS_STATUS_BUFFER_TOO_SHORT;
            *BytesRead = 0;
        } else {
            Adapter->CurrentPacketFilter = *(PULONG)InformationBuffer;
            *BytesRead = 4;
        }
        break;

    case OID_802_3_MULTICAST_LIST:
        if (InformationBufferLength % ETH_LENGTH_OF_ADDRESS != 0 ||
            (InformationBufferLength / ETH_LENGTH_OF_ADDRESS >
             NR_MCAST_ADDRESSES)) {
            Status = NDIS_STATUS_INVALID_LENGTH;
        } else {
            Adapter->nrMulticastAddresses =
                InformationBufferLength / ETH_LENGTH_OF_ADDRESS;
            NdisMoveMemory(Adapter->MulticastAddress,
                           InformationBuffer,
                           InformationBufferLength);
            *BytesRead = InformationBufferLength;
        }
        break;

        /* Maintaining the list of network addresses is inherently
           racy, since you could have something like this:

           -- TCP/IP assigns an address
           -- We suspend/resume
           -- TCP/IP sends this OID.

           If that happens, we send the gratuitous ARP with the old IP
           address.  There's nothing we can do about that, not without
           more help from NDIS than it seems willing to give, so just
           hope for the best. */
    case OID_GEN_NETWORK_LAYER_ADDRESSES: {
        PNETWORK_ADDRESS_LIST nal = InformationBuffer;
        int i, j;
        PNETWORK_ADDRESS na;
        int cntr;

        if (InformationBufferLength <
            (ULONG)(ULONG_PTR)&((PNETWORK_ADDRESS_LIST)0)->Address[0]) {
            TraceInfo(("Set network addresses with very small buffer.\n"));
            Status = NDIS_STATUS_INVALID_LENGTH;
            break;
        }
        NdisAcquireSpinLock(&Adapter->address_list_lock);
        if (nal->AddressCount == 0) {
            if (nal->AddressType == NDIS_PROTOCOL_ID_TCP_IP) {
                XmFreeMemory(Adapter->address_list);
                Adapter->address_list = NULL;
                Adapter->nr_addresses = 0;
            }
        } else {
            na = nal->Address;
            i = 0;
            cntr = 0;
            /* First pass: validate the buffer and count the addresses
               we're interested in. */
            while (i < nal->AddressCount) {
                if (InformationBufferLength <
                    (ULONG)((ULONG_PTR)na->Address -
                            (ULONG_PTR)InformationBuffer)) {
                    TraceInfo(("Fell off end of network address list.\n"));
                    Status = NDIS_STATUS_INVALID_LENGTH;
                    break;
                }
                if (InformationBufferLength <
                    (ULONG)((ULONG_PTR)na->Address + na->AddressLength -
                            (ULONG_PTR)InformationBuffer)) {
                    TraceInfo(("invalid naddr length.\n"));
                    Status = NDIS_STATUS_INVALID_LENGTH;
                    break;
                }
                if (na->AddressType == NDIS_PROTOCOL_ID_TCP_IP &&
                    na->AddressLength == 16)
                    cntr++;
                i++;
                na =
                    (PNETWORK_ADDRESS)((ULONG_PTR)&na->Address[0] +
                                       na->AddressLength);
            }
            if (Status == NDIS_STATUS_SUCCESS) {
                /* Allocate the buffer. */
                PVOID new;

                new =
                    XmAllocateMemory(sizeof(Adapter->address_list[0]) * cntr);
                if (new) {
                    XmFreeMemory(Adapter->address_list);
                    Adapter->address_list = new;
                    Adapter->nr_addresses = cntr;
                } else {
                    Status = NDIS_STATUS_RESOURCES;
                }
            }
            if (Status == NDIS_STATUS_SUCCESS) {
                /* Second pass: collect them up */
                na = nal->Address;
                i = 0;
                j = 0;
                while (i < nal->AddressCount) {
                    /* For reasons which aren't immediately obvious,
                       Windows pokes down a 16 byte structure with the
                       IP address in bytes [4,8) and every other byte
                       set to 0.  Extract the relevant bits. */
                    if (na->AddressType == NDIS_PROTOCOL_ID_TCP_IP &&
                        na->AddressLength == 16) {
                        XM_ASSERT3U(j, <, cntr);
                        memcpy(&Adapter->address_list[j],
                               na->Address + 4,
                               4);
                        j++;
                    }
                    i++;
                    na =
                        (PNETWORK_ADDRESS)((ULONG_PTR)&na->Address[0] +
                                           na->AddressLength);
                }
                XM_ASSERT3U(j, ==, cntr);
            }
        }
        NdisReleaseSpinLock(&Adapter->address_list_lock);
        break;
    }

    case OID_TCP_TASK_OFFLOAD:
        Status = SetTcpTaskOffload(InformationBuffer,
                                   InformationBufferLength,
                                   BytesRead, BytesNeeded,
                                   MiniportAdapterContext);
        XM_ASSERT3U(*BytesRead, <=, *BytesNeeded);
        XM_ASSERT3U(*BytesRead, <=, InformationBufferLength);
        break;

#ifdef XEN_WIRELESS
    // Mandatory
    case OID_802_11_BSSID_LIST_SCAN:
        Status = WlanStartScan(Adapter);
        break;

    case OID_802_11_SSID:
        Status = WlanSetSSID (Oid, Adapter, InformationBuffer);
        break;

    case OID_802_11_INFRASTRUCTURE_MODE:
        Status = WlanSetInfrastructureMode(Oid, Adapter, InformationBuffer);
        break;

    case OID_802_11_NETWORK_TYPE_IN_USE:
        Status = WlanSetNetworkTypeInUse(Oid, Adapter, InformationBuffer);
        break;

    case OID_802_11_AUTHENTICATION_MODE:
        Status = WlanSetAuthenticationMode(Oid, Adapter, InformationBuffer);
        break;

    case OID_802_11_ENCRYPTION_STATUS:
        Status = WlanSetEncryptionMode(Oid, Adapter, InformationBuffer);
        break;

    case OID_802_11_BSSID:
        Status = WlanSetBssid(Oid, Adapter, InformationBuffer);
        break;

    case OID_802_11_CONFIGURATION:
        Status = WlanSetRadioConfiguration(Oid, Adapter, InformationBuffer);
        break;

    case OID_802_11_DISASSOCIATE:
        Status = WlanDisassociate(Oid, Adapter, InformationBuffer);
        break;

    case OID_802_11_RELOAD_DEFAULTS:
        Status = WlanReloadDefaults(Oid, Adapter, InformationBuffer);
        break;

    case OID_802_11_ADD_WEP:
        Status = WlanAddWep(Oid, Adapter, InformationBuffer);
        break;

    case OID_802_11_REMOVE_WEP:
        Status = WlanRemoveWep(Oid, Adapter, InformationBuffer);
        break;

    case OID_802_11_ADD_KEY:
        Status = WlanAddKey(Oid, Adapter, InformationBuffer);
        break;
    case OID_802_11_REMOVE_KEY:
        Status = WlanRemoveKey(Oid, Adapter, InformationBuffer);
        break;

    // Recommended
    case OID_802_11_POWER_MODE:
    case OID_802_11_MEDIA_STREAM_MODE:

    // Optional
    case OID_802_11_TX_POWER_LEVEL:
    case OID_802_11_RSSI_TRIGGER:
    case OID_802_11_FRAGMENTATION_THRESHOLD:
    case OID_802_11_RTS_THRESHOLD:
    case OID_802_11_RX_ANTENNA_SELECTED:
    case OID_802_11_TX_ANTENNA_SELECTED:
    case OID_802_11_DESIRED_RATES:
    case OID_802_11_PRIVACY_FILTER:
    case OID_802_11_TEST:
    case OID_802_11_PMKID:
        Status = NDIS_STATUS_NOT_SUPPORTED;
        TraceWarning(("Set of unknown OID %x\n", Oid));
        break;
#endif

    default:
        TraceWarning(("Set of unknown OID %x\n", Oid));
    case OID_GEN_MACHINE_NAME:
    case OID_GEN_TRANSPORT_HEADER_OFFSET:
    case OID_PNP_REMOVE_WAKE_UP_PATTERN:
    case OID_PNP_ADD_WAKE_UP_PATTERN:
    case OID_GEN_RECEIVE_HASH:
        Status = NDIS_STATUS_NOT_SUPPORTED;
        break;
    }

    if (Status == NDIS_STATUS_SUCCESS)
        *BytesRead = InformationBufferLength;

    TraceDebug (("<===='%s' OID=0x%08x, Status=%x\n", __FUNCTION__, Oid, Status));

    return(Status);
}

/* Tell the backend that it should disconnect and wait for it to shut
   down. */
static VOID
XenbusDisconnect(PADAPTER Adapter, SUSPEND_TOKEN token)
{
    const PCHAR backend = Adapter->backend;
    XENBUS_STATE frontend_state;
    XENBUS_STATE backend_state;

    if (!backend) {
        TraceError (("Shutting down an adapter which wasn't properly created? (%p)\n",
                     backend));
        /* We're clearly not connected to the backend here, so don't
           confuse ourselves by trying to disconnect. */
        return;
    }

    // Wait for the backend to stabilise before we close it
    backend_state = null_XENBUS_STATE();
    do {
        backend_state = XenbusWaitForBackendStateChange(backend, backend_state,
                                                        NULL, token);
    } while (same_XENBUS_STATE(backend_state, XENBUS_STATE_INITIALISING));

    // Now close the frontend
    frontend_state = XENBUS_STATE_CLOSING;
    while (!same_XENBUS_STATE(backend_state, XENBUS_STATE_CLOSING) &&
           !same_XENBUS_STATE(backend_state, XENBUS_STATE_CLOSED) &&
           !is_null_XENBUS_STATE(backend_state)) {
        xenbus_change_state(XBT_NIL, Adapter->XenbusPrefix, "state",
                            frontend_state);
        backend_state = XenbusWaitForBackendStateChange(backend, backend_state,
                                                        NULL, token);
    }

    frontend_state = XENBUS_STATE_CLOSED;
    while (!same_XENBUS_STATE(backend_state, XENBUS_STATE_CLOSED) &&
           !is_null_XENBUS_STATE(backend_state)) {
        xenbus_change_state(XBT_NIL, Adapter->XenbusPrefix, "state",
                            frontend_state);
        backend_state = XenbusWaitForBackendStateChange(backend, backend_state,
                                                        NULL, token);
    }
}

/* Do the actual shutdown work required for MPHalt or PnP removal */
static VOID
MpInitialShutdown(PADAPTER Adapter, BOOLEAN SurpiseRemoval)
{
    char *backend;

    /* Turn off the watchpoints immediately. Want to prevent indicating NDIS media
     * status changes during a surprise remove or while halting.
     */
    if (Adapter->BackStateWatch)
        xenbus_unregister_watch(Adapter->BackStateWatch);
    Adapter->BackStateWatch = NULL;

    if (Adapter->mediaWatch)
        xenbus_unregister_watch(Adapter->mediaWatch);
    Adapter->mediaWatch = NULL;

    /* Update the backend field in the adapter struct since
     * it may have changed in xenstore.
     * Note also that the last parameter in the following call
     * is ignored!!
     */
    backend = ReadBackend(Adapter->XenbusPrefix, null_SUSPEND_TOKEN());
    if (!backend)
    {
        TraceError(("Backend node gone from %s\n", Adapter->XenbusPrefix));
    }
    if (Adapter->backend)
        XmFreeMemory(Adapter->backend);
    Adapter->backend = backend;

    NdisAcquireSpinLock(&Adapter->Receiver.Common.Lock);
    NdisAcquireSpinLock(&Adapter->Transmitter.SendLock);
    if (Adapter->Shutdown) {
        TraceBugCheck(("Tried to shut the adapter down several times (%x)?\n",
                       Adapter->Shutdown));
    }
    Adapter->Shutdown = 1;
    NdisReleaseSpinLock(&Adapter->Transmitter.SendLock);
    NdisReleaseSpinLock(&Adapter->Receiver.Common.Lock);

    /* Transmitter shutdown above, wait for or force free all outstanding packets. */
    if (!SurpiseRemoval)
        TransmitterWaitForIdle(&Adapter->Transmitter);
    else
        TransmitterForceFreePackets(&Adapter->Transmitter);
}

VOID
MPPnPEventNotify(
    IN NDIS_HANDLE  MiniportAdapterContext,
    IN NDIS_DEVICE_PNP_EVENT  PnPEvent,
    IN PVOID  InformationBuffer,
    IN ULONG  InformationBufferLength
)
{
    PADAPTER Adapter = (PADAPTER)MiniportAdapterContext;

    TraceInfo(("%s: ====> (%p) Event: %d\n", __FUNCTION__, Adapter, PnPEvent));

    if (PnPEvent == NdisDevicePnPEventRemoved) {
        TraceInfo(("PnP NdisDevicePnPEventRemoved notification\n"));
        Adapter->RemovalPending = TRUE;
    }
    else if (PnPEvent == NdisDevicePnPEventSurpriseRemoved) {
        TraceInfo(("PnP NdisDevicePnPEventSurpriseRemoved notification\n"));
        Adapter->RemovalPending = TRUE;
    }

    /* During a surprise removal due to a PnP unplug, a number of things need to be
     * cleaned up here or MPHalt will never get called leading to doom and misery.
     */
    if (Adapter->RemovalPending) {
        TraceVerbose(("Outstanding Tx count after surprise removal: %d\n", Adapter->Transmitter.nTxInFlight));
        MpInitialShutdown(Adapter, TRUE);
    }

    TraceInfo(("%s: <==== (%p)\n", __FUNCTION__, Adapter));
}

VOID
MPHalt(
    IN NDIS_HANDLE MiniportAdapterContext
)
/*++

Routine Description:

    Halt handler. All the hard-work for clean-up is done here.

Arguments:

    MiniportAdapterContext  Pointer to the Adapter

Return Value:

    None.

--*/
{
    PADAPTER        Adapter = (PADAPTER)MiniportAdapterContext;
    SUSPEND_TOKEN   token;    

    TraceInfo(("%s: ====> (%p)\n", __FUNCTION__, Adapter));

    /* During a normal (non-surprise PnP) shutdown the cleanup happens here. */
    if (!Adapter->RemovalPending)
        MpInitialShutdown(Adapter, FALSE); 

#ifdef XEN_WIRELESS
    WlanAdapterDelete(Adapter);
#endif

    /* We are guaranteed that when this returns all of our DPCs have
       finished firing. */
    EvtchnPortStop(Adapter->evtchn);

    ReceiverWaitForPacketReturn(&Adapter->Receiver);

    /* There are no packets currently in NDIS, and no way for the DPC
       to run again and deliver some more, so the RX path is now shut
       down.  It's therefore safe to tear down the adapter control
       structure. */

    EvtchnReleaseDebugCallback(Adapter->debug_cb_handle);
    Adapter->debug_cb_handle = null_EVTCHN_DEBUG_CALLBACK();

    token = EvtchnAllocateSuspendToken("xennet disconnect");
    XenbusDisconnect(Adapter, token);
    EvtchnReleaseSuspendToken(token);

    TraceVerbose(("Halted adapter.\n"));

    ReleaseAdapter(Adapter);

    TraceVerbose(("Released adapter.\n"));

    TraceInfo(("%s: <==== (%p)\n", __FUNCTION__, Adapter));
}

static void
ReleaseAdapter(PADAPTER Adapter)
{
    if (Adapter->LateSuspendHandler != NULL)
        EvtchnUnregisterSuspendHandler(Adapter->LateSuspendHandler);

    if (Adapter->EarlySuspendHandler != NULL)
        EvtchnUnregisterSuspendHandler(Adapter->EarlySuspendHandler);

    if (!is_null_EVTCHN_PORT(Adapter->evtchn))
        EvtchnClose(Adapter->evtchn);

    if (Adapter->backend)
        XmFreeMemory(Adapter->backend);

    TraceDebug (("Releasing prefix.\n"));
    XmFreeMemory(Adapter->XenbusPrefix);

    TraceVerbose(("Cleaning receiver.\n"));
    ReceiverCleanup(&Adapter->Receiver);

    TraceVerbose(("Cleaning transmitter.\n"));
    TransmitterCleanup(&Adapter->Transmitter);

    TraceVerbose(("Releasing adapter.\n"));
    NdisFreeMemory(Adapter, sizeof(ADAPTER), 0);
}

NDIS_STATUS
MPReset(
    OUT PBOOLEAN AddressingReset,
    IN NDIS_HANDLE MiniportAdapterContext
)
/*++

Routine Description:

    Reset Handler. We just don't do anything.

Arguments:

    AddressingReset         To let NDIS know whether we need help from it with our reset
    MiniportAdapterContext  Pointer to our adapter

Return Value:


--*/
{
    PADAPTER        Adapter = (PADAPTER)MiniportAdapterContext;

    *AddressingReset = FALSE;

    TraceInfo(("%s: <===> (%p)\n", __FUNCTION__, Adapter));

    return(NDIS_STATUS_SUCCESS);
}

VOID
MPAdapterShutdown(
    IN NDIS_HANDLE MiniportAdapterContext
)
/*++

Routine Description:

    This is one of those pointless routines which the windows DDK
    insists that you implement but which don't actually do anything.
    It's supposed to do whatever is needed before removing power from
    the NIC in the case where you don't want to preserve any
    information.  Any NIC which actually needs this will be bricked by
    a power failure, so you might suppose it was pretty obscure, but
    driver verifier bugchecks if it isn't present.

    Even better, you get called at arbitrary IRQL holding an unknown
    set of locks, and you're not allowed to call into any NDIS library
    functions, so even if you do need to do something from here you're
    pretty much screwed.

Arguments:

    MiniportAdapterContext  pointer to ADAPTER structure

Return Value:

    None
--*/
{
    PADAPTER        Adapter = (PADAPTER)MiniportAdapterContext;

    TraceInfo(("%s: <===> (%p)\n", __FUNCTION__, Adapter));
}

static void
MediaStateChangedCb(PVOID data);

static void
AdapterBackendStateChanged(void *_adapter)
{
    PADAPTER Adapter = _adapter;
    NTSTATUS status;
    XENBUS_STATE state;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    status = xenbus_read_state (XBT_NIL,
                                Adapter->XenbusPrefix,
                                "backend-state",
                                &state);

    if (!NT_SUCCESS(status))
    {
        TraceWarning (("Backend-state node gone: Ignoring notification & setting link-down status\n"));
        xenbus_write_feature_flag(XBT_NIL, Adapter->XenbusPrefix, "disconnect", TRUE);
    }
    else
    {
        if (Adapter->media_disconnect && same_XENBUS_STATE(state, XENBUS_STATE_CONNECTED))
        {
            //
            // Changed per Jed/Tomasz conversation. The toolstack will now update this field
            // so we don't need to update it.
            //
            //TraceWarning (("Backend-state present and connected; restoring link state\n"));
            //xenbus_write_feature_flag(XBT_NIL, Adapter->XenbusPrefix, "disconnect", FALSE);
            TraceWarning (("Backend-state present and connected; backend-state == CONNECTED; Leaving disconnect node\n"));
        }
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}

static void
MediaStateChangedCb(PVOID data)
{
    PADAPTER pAdapt = (PADAPTER)data;
    BOOLEAN disconnected;
    NTSTATUS status;
    char *path;
    xenbus_transaction_t xbt;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    disconnected = FALSE;

    xenbus_transaction_start(&xbt);
    path = Xmasprintf("%s/backend", pAdapt->XenbusPrefix);
    if (!path)
    {
        TraceError (("Failure allocating memory to read backend node %s/backend\n", pAdapt->XenbusPrefix));
        disconnected = TRUE;
    }
    else
    {
        char *tmp;
        status = xenbus_read(xbt, path, &tmp);
        if (!NT_SUCCESS(status))
        {
            TraceDebug (("%s node missing; assuming media disconnected\n", path));
            disconnected = TRUE;
        }
        XmFreeMemory(path);
    }

    if (!disconnected)
    {
        status = xenbus_read_feature_flag(xbt,
                                          pAdapt->XenbusPrefix,
                                          "disconnect",
                                          &disconnected);
        if (!NT_SUCCESS(status))
            disconnected = TRUE;

    }
    xenbus_transaction_end (xbt, 0);

    if (disconnected) {
        if (!pAdapt->media_disconnect) {
            TraceNotice(("Media disconnected!\n"));
            NdisAcquireSpinLock(&pAdapt->Receiver.Common.Lock);
            NdisAcquireSpinLock(&pAdapt->Transmitter.SendLock);
            pAdapt->media_disconnect = 1;
            NdisReleaseSpinLock(&pAdapt->Transmitter.SendLock);
            NdisReleaseSpinLock(&pAdapt->Receiver.Common.Lock);
            NdisMIndicateStatus(pAdapt->AdapterHandle,
                                NDIS_STATUS_MEDIA_DISCONNECT,
                                NULL,
                                0);
            NdisMIndicateStatusComplete(pAdapt->AdapterHandle);
        }
    } else {
        if (pAdapt->media_disconnect) {
            TraceNotice(("Media connected!\n"));
            NdisAcquireSpinLock(&pAdapt->Receiver.Common.Lock);
            NdisAcquireSpinLock(&pAdapt->Transmitter.SendLock);
            pAdapt->media_disconnect = 0;
            NdisReleaseSpinLock(&pAdapt->Transmitter.SendLock);
            NdisReleaseSpinLock(&pAdapt->Receiver.Common.Lock);
            NdisMIndicateStatus(pAdapt->AdapterHandle,
                                NDIS_STATUS_MEDIA_CONNECT,
                                NULL,
                                0);
            NdisMIndicateStatusComplete(pAdapt->AdapterHandle);
            /* Kick to try and unstall the receive ring. */
            EvtchnRaiseLocally(pAdapt->evtchn);
        }
    }
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
}

//
// Allocate an adapter-specific control block.
//
static PADAPTER
MpAllocAdapterBlock(NDIS_HANDLE AdapterHandle)
{
    PADAPTER Adapter;
    NDIS_STATUS status;

    TraceDebug (("==>\n"));

    NdisAllocateMemoryWithTag (&Adapter, sizeof(ADAPTER), 'xnet');
    if (Adapter == NULL)
        return NULL;
    NdisZeroMemory(Adapter, sizeof(ADAPTER));

    Adapter->ring_disconnected = 1;

    Adapter->AdapterHandle = AdapterHandle;

    NdisMGetDeviceProperty(AdapterHandle, &Adapter->pdo, NULL, NULL, NULL,
                           NULL);

    NdisAllocateSpinLock(&Adapter->address_list_lock);

    // Which card are we supposed to attach to?
    Adapter->XenbusPrefix = xenbus_find_frontend(Adapter->pdo);
    if (!Adapter->XenbusPrefix)
    {
        NdisFreeMemory(Adapter, sizeof(ADAPTER), 0);
        goto no_memory;
    }

    status = xenbus_read_domain_id(XBT_NIL, Adapter->XenbusPrefix,
                                   "backend-id", &Adapter->BackendDomid);
    if (!NT_SUCCESS(status)) {
        TraceError(("Failed to read backend id from %s (%x)\n",
                    Adapter->XenbusPrefix, status));
        Adapter->BackendDomid = DOMAIN_ID_0();
    }

    status = TransmitterInitialize(&Adapter->Transmitter, Adapter);
    if (status != NDIS_STATUS_SUCCESS)
    {
        XmFreeMemory(Adapter->XenbusPrefix);
        NdisFreeMemory(Adapter, sizeof(ADAPTER), 0);
        goto no_memory;
    }

    status = ReceiverInitialize(&Adapter->Receiver, Adapter);
    if (status != NDIS_STATUS_SUCCESS)
    {
        TransmitterCleanup(&Adapter->Transmitter);
        XmFreeMemory(Adapter->XenbusPrefix);
        NdisFreeMemory(Adapter, sizeof(ADAPTER), 0);
        goto no_memory;
    }

    TraceVerbose(("Rx ref %d, tx ref %d.\n",
                  xen_GRANT_REF(Adapter->Receiver.Common.RingGrantRef),
                  xen_GRANT_REF(Adapter->Transmitter.tx_ring_ref)));
    Adapter->evtchn =
        EvtchnAllocUnboundDpc(Adapter->BackendDomid, XennetEvtchnCallback, Adapter);
    if (is_null_EVTCHN_PORT(Adapter->evtchn))
    {
        ReceiverCleanup(&Adapter->Receiver);
        TransmitterCleanup(&Adapter->Transmitter);
        XmFreeMemory(Adapter->XenbusPrefix);
        NdisFreeMemory(Adapter, sizeof(ADAPTER), 0);
        goto no_memory;
    }

    Adapter->EarlySuspendHandler =
        EvtchnRegisterSuspendHandler(RestartNetifEarly, Adapter,
                                     "RestartNetifEarly",
                                     SUSPEND_CB_EARLY);
    if (Adapter->EarlySuspendHandler == NULL)
    {
        EvtchnClose(Adapter->evtchn);
        ReceiverCleanup(&Adapter->Receiver);
        TransmitterCleanup(&Adapter->Transmitter);
        XmFreeMemory(Adapter->XenbusPrefix);
        NdisFreeMemory(Adapter, sizeof(ADAPTER), 0);
        goto no_memory;
    }

    Adapter->LateSuspendHandler =
        EvtchnRegisterSuspendHandler(RestartNetifLate, Adapter,
                                     "RestartNetifLate",
                                     SUSPEND_CB_LATE);
    if (Adapter->LateSuspendHandler == NULL)
    {
        EvtchnUnregisterSuspendHandler(Adapter->EarlySuspendHandler);
        EvtchnClose(Adapter->evtchn);
        ReceiverCleanup(&Adapter->Receiver);
        TransmitterCleanup(&Adapter->Transmitter);
        XmFreeMemory(Adapter->XenbusPrefix);
        NdisFreeMemory(Adapter, sizeof(ADAPTER), 0);
        goto no_memory;
    }

    return Adapter;

no_memory:
    return NULL;
}

static int
HexCharToInt(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    else
        ASSERT(FALSE);
    return -1;
}

static NDIS_STATUS
ReadMacFromRegistry(NDIS_HANDLE Context, PUCHAR outbuf)
{
    NDIS_STATUS Status;
    NDIS_HANDLE configHandle;
    UINT len;
    PVOID tmp;

    NdisOpenConfiguration(&Status, &configHandle, Context);
    if (Status == NDIS_STATUS_SUCCESS) {
        NdisReadNetworkAddress(&Status, &tmp,
                               &len, configHandle);
        if (Status == NDIS_STATUS_SUCCESS) {
            if (len == 6) {
                memcpy(outbuf, tmp, len);
                if (outbuf[0] & 0x1) {
                    TraceWarning(("Our address was set to a multicast address in the registry?\n"));
                    Status = STATUS_UNSUCCESSFUL;
                }
            } else {
                TraceWarning(("MAC address in registry was the wrong length?\n"));
                Status = STATUS_UNSUCCESSFUL;
            }
        }
        NdisCloseConfiguration(configHandle);
    }

    return Status;
}

static NDIS_STATUS
ReadMacFromXenstore(PADAPTER Adapter, PUCHAR outbuf, BOOLEAN from_backend)
{
    char *tmp;
    NTSTATUS Stat;
    int x;

    if (from_backend) {
        Stat = xenbus_read_backend(XBT_NIL, Adapter->pdo, "mac", &tmp);
    } else {
        char *path;
        path = Xmasprintf("%s/mac", Adapter->XenbusPrefix);
        if (!path)
            return NDIS_STATUS_RESOURCES;
        Stat = xenbus_read(XBT_NIL, path, &tmp);
        XmFreeMemory(path);
    }
    if (NT_SUCCESS(Stat)) {
        TraceDebug (("mac: %s -> %s.\n", Adapter->XenbusPrefix, tmp));
        for (x = 0; x < ETH_LENGTH_OF_ADDRESS; x++) {
            outbuf[x] = (unsigned char)HexCharToInt(tmp[x*3]) * 16 +
                (unsigned char)HexCharToInt(tmp[x*3+1]);
        }
        XmFreeMemory(tmp);
    }
    return (NDIS_STATUS)Stat;
}

static char *
ReadBackend(const char *prefix, SUSPEND_TOKEN token)
{
    NTSTATUS stat;
    char *path;
    size_t l1 = strlen(prefix);
    char *res;

    UNREFERENCED_PARAMETER(token);

    path = ExAllocatePoolWithTag(NonPagedPool,
                     l1 + 9,
                     XNET_TAG);
    if (!path)
        return NULL;
    memcpy(path, prefix, l1);
    path[l1] = '/';
    memcpy(path + l1 + 1, "backend", 8);
    stat = xenbus_read(XBT_NIL, path, &res);
    if (NT_SUCCESS(stat)) {
        TraceDebug (("backend: %s -> %s.\n", path, res));
        ExFreePoolWithTag(path, XNET_TAG);
        return res;
    } else {
        ExFreePoolWithTag(path, XNET_TAG);
        return NULL;
    }
}

/* Assume the adapter has been completely configured on the frontend
   side.  Tell the backend that we're here. */
static NDIS_STATUS
ConnectXenbus(PADAPTER Adapter, SUSPEND_TOKEN token)
{
    char *prefix = Adapter->XenbusPrefix;
    NTSTATUS stat;
    xenbus_transaction_t xbt;
    XENBUS_STATE state;

    do {
        xenbus_transaction_start(&xbt);
        xenbus_write_grant_ref(xbt, prefix, "tx-ring-ref",
                               Adapter->Transmitter.tx_ring_ref);
        xenbus_write_grant_ref(xbt, prefix, "rx-ring-ref",
                               Adapter->Receiver.Common.RingGrantRef);
        xenbus_write_evtchn_port(xbt, prefix, "event-channel",
                                 Adapter->evtchn);
        xenbus_write_feature_flag(xbt, prefix, "request-rx-copy", TRUE);
        xenbus_write_feature_flag(xbt, prefix, "feature-sg", TRUE);
        xenbus_write_feature_flag(xbt, prefix, "feature-rx-notify", TRUE);

        if (Adapter->Receiver.rx_csum_tcp_offload)
            xenbus_write_feature_flag(xbt, prefix, "feature-no-csum-offload",
                                      FALSE);
        else
            xenbus_write_feature_flag(xbt, prefix, "feature-no-csum-offload",
                                      TRUE);

        xenbus_change_state(xbt, prefix, "state", XENBUS_STATE_CONNECTED);
        stat = xenbus_transaction_end(xbt, 0);
    } while (stat == STATUS_RETRY);

    if (stat != STATUS_SUCCESS) {
        TraceError (("Failed to end transaction, %x.\n",
                     stat));
        return NDIS_STATUS_FAILURE;
    }

    state = null_XENBUS_STATE();
    for (;;) {
        state = XenbusWaitForBackendStateChange(Adapter->backend, state, NULL,
                                                token);
        if (is_null_XENBUS_STATE(state) ||
            same_XENBUS_STATE(state, XENBUS_STATE_CLOSING) ||
            same_XENBUS_STATE(state, XENBUS_STATE_CLOSED))
            return NDIS_STATUS_FAILURE;
        if (same_XENBUS_STATE(state, XENBUS_STATE_CONNECTED))
            return NDIS_STATUS_SUCCESS;
    }
}

//
// Probe the Xenbus, find the adapter and store away any
// info we'll need later to communicate with the device.
//
static NDIS_STATUS
MpFindAdapter(
    IN PADAPTER Adapter,
    IN NDIS_HANDLE Context,
    IN SUSPEND_TOKEN token
    )
{
    BOOLEAN copying, have_tx_csum_offload, have_tx_seg_offload;
    NTSTATUS stat;
    XENBUS_STATE state;
    char *backend;
    ULONG64 mtu64;

    backend = ReadBackend(Adapter->XenbusPrefix, token);
    if (!backend) {
        TraceError(("Could not find backend for %s!\n", Adapter->XenbusPrefix));
        return NDIS_STATUS_RESOURCES;
    }
    if (Adapter->backend)
        XmFreeMemory(Adapter->backend);
    Adapter->backend = backend;

    if (!Adapter->ring_disconnected)
        return STATUS_SUCCESS;

    /* Wait for the backend to report readiness. */
    xenbus_change_state(XBT_NIL, Adapter->XenbusPrefix, "state",
                        XENBUS_STATE_INITIALISING);
    state = null_XENBUS_STATE();
    for (;;) {
        state = XenbusWaitForBackendStateChange(Adapter->backend, state,
                                                NULL, token);
        if (same_XENBUS_STATE(state, XENBUS_STATE_INITWAIT))
            break;
        if (same_XENBUS_STATE(state, XENBUS_STATE_CLOSING) ||
            is_null_XENBUS_STATE(state)) {
            TraceWarning (("Backend went away before we could connect to it?\n"));
            return NDIS_STATUS_FAILURE;
        }
    }
    stat = xenbus_read_backend_feature_flag(XBT_NIL, Adapter->pdo,
                                            "feature-rx-copy", &copying);
    if (!copying) {
        TraceError (("Bad adapter!\n"));
        return NDIS_STATUS_NOT_SUPPORTED;
    }

    if (XenPVFeatureEnabled(DEBUG_HCT_MODE)) {
        Adapter->Transmitter.tx_csum_offload_safe = 0;
        Adapter->Transmitter.tso_avail = 0;
    } else {
        /* NDIS occasionally generates packets which have the TCP and
           IP headers in different fragments, and once it's done so it
           tends to do the same thing on retransmissions of that
           packet as well.  This interacts with a bug in old versions
           of Linux netback, and so we can't safely enable TX csum
           offload on those versions. */
        stat = xenbus_read_backend_feature_flag(XBT_NIL, Adapter->pdo,
                                                "feature-tx-csum-split-header",
                                                &have_tx_csum_offload);
        if (have_tx_csum_offload)
            Adapter->Transmitter.tx_csum_offload_safe = 1;
        else
            Adapter->Transmitter.tx_csum_offload_safe = 0;

        if (XenPVFeatureEnabled(DEBUG_NIC_NO_TSO)) {
            Adapter->Transmitter.tso_avail = 0;
            TraceNotice(("Not reporting TSO.\n"));
        } else {
            stat = xenbus_read_backend_feature_flag(XBT_NIL, Adapter->pdo,
                                                    "feature-gso-tcpv4",
                                                    &have_tx_seg_offload);
            if (have_tx_seg_offload)
                Adapter->Transmitter.tso_avail = 1;
            else
                Adapter->Transmitter.tso_avail = 0;
        }
    }

    if (Context != INVALID_HANDLE_VALUE) {
        stat = ReadMacFromXenstore(Adapter, Adapter->PermanentAddress,
                                   FALSE);
        if (stat != NDIS_STATUS_SUCCESS) {
            // Different versions of dom0 and the tools put the mac
            // address in different places.  Work around this by checking
            // the backend area as well when it's not present in the
            // frontend area.
            stat = ReadMacFromXenstore(Adapter, Adapter->PermanentAddress,
                                       TRUE);
        }
        if (stat != NDIS_STATUS_SUCCESS) {
            TraceError (("Cannot read mac from %s or %s.\n", Adapter->XenbusPrefix,
                         Adapter->backend));
            return stat;
        }
        /* See if the registry wants to override our MAC address. */
        if (ReadMacFromRegistry(Context, Adapter->CurrentAddress) !=
            NDIS_STATUS_SUCCESS) {
            /* Nope */
            memcpy(Adapter->CurrentAddress, Adapter->PermanentAddress,
                   ETH_LENGTH_OF_ADDRESS);
        }
    }

    stat = xenbus_read_int(XBT_NIL, Adapter->XenbusPrefix, "mtu",
                           &mtu64);
    if (!NT_SUCCESS(stat) || mtu64 > XENNET_MAX_MTU)
        Adapter->mtu = XENNET_DEF_MTU;
    else
        Adapter->mtu = (int)mtu64;

    stat = ConnectXenbus(Adapter, token);
    if (stat == NDIS_STATUS_SUCCESS)
        Adapter->ring_disconnected = 0;

    return stat;
}

/* Called early following a resume from save/restore while the rest of
   the system is quiescent */
static VOID
RestartNetifEarly(VOID *ctxt, SUSPEND_TOKEN token)
{
    PADAPTER Adapter = ctxt;

    UNREFERENCED_PARAMETER(token);

    Adapter->ring_disconnected = 1;

    RestartTransmitterEarly(&Adapter->Transmitter);
    ReceiverCommonRestartEarly(&Adapter->Receiver.Common);
}

/* Called shortly after a resume from save/restore holding no
 * locks. */
static VOID
RestartNetifLate(VOID *ctxt, SUSPEND_TOKEN token)
{
    PADAPTER Adapter = ctxt;

    TraceInfo(("Finding adapter...\n"));
    if (MpFindAdapter(Adapter, INVALID_HANDLE_VALUE, token) ==
        NDIS_STATUS_SUCCESS) {
        TraceInfo(("Found adapter.\n"));

        RestartTransmitterLate(&Adapter->Transmitter);
        ReceiverCommonRestartLate(&Adapter->Receiver.Common);
        EvtchnNotifyRemote(Adapter->evtchn);

        TraceInfo(("Retransmitted queue.\n"));
    } else {
        TraceError(("Failed to find adapter!\n"));
    }
}


/****************************************************************************
 * DATA PATH OPERATIONS                                                     *
 ****************************************************************************/

int
MacAddressInteresting(PUCHAR dest, PADAPTER Adapter)
{
    int x;

    if ( Adapter->CurrentPacketFilter & NDIS_PACKET_TYPE_PROMISCUOUS )
        return 1;

    if (dest[0] & 1) {
        /* Multicast */
        if ( Adapter->CurrentPacketFilter & NDIS_PACKET_TYPE_ALL_MULTICAST )
            return 1;
        if ( (dest[0] & ~2) == 0xfd &&
             dest[1] == 0xff &&
             dest[2] == 0xff &&
             dest[3] == 0xff &&
             dest[4] == 0xff &&
             dest[5] == 0xff ) {
            /* Broadcast */
            return Adapter->CurrentPacketFilter & NDIS_PACKET_TYPE_BROADCAST;
        }
        if ( !(Adapter->CurrentPacketFilter & NDIS_PACKET_TYPE_MULTICAST) )
            return 0;
        for ( x = 0; x < Adapter->nrMulticastAddresses; x++ )
            if ( !memcmp(dest, Adapter->MulticastAddress[x], 6) )
                return 1;
        return 0;
    } else {
        /* Unicast */
        if ( !(Adapter->CurrentPacketFilter & NDIS_PACKET_TYPE_DIRECTED) ) {
            return 0;
        }
        return !memcmp(dest, Adapter->CurrentAddress, 6);
    }
}

static VOID
XennetEvtchnCallback(PVOID Context)
{
    PADAPTER Adapter = (PADAPTER) Context;

    Adapter->nDPCs++;
    MpHandleSendInterrupt(&Adapter->Transmitter);
    ReceiverHandleNotification(&Adapter->Receiver);
}
