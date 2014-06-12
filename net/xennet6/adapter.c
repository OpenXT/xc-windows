/*
 * Copyright (c) 2014 Citrix Systems, Inc.
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

//
// List of supported OIDs.
//

static NDIS_STATUS
AdapterDisconnectBackend (
    IN  PADAPTER    Adapter
    );

static VOID
AdapterCleanupIpAddressList (
    IN  PADAPTER Adapter
    );

static NDIS_STATUS
AdapterStop (
    IN  PADAPTER    Adapter
    );

static NDIS_STATUS
AdapterInitializeBackend (
    IN  PADAPTER        Adapter,
    IN  NDIS_HANDLE     Context,
    IN  SUSPEND_TOKEN   Token
    );

static NDIS_STATUS
AdapterSetRegistrationAttributes (
    IN  PADAPTER Adapter
    );

static NDIS_STATUS
AdapterSetGeneralAttributes (
    IN  PADAPTER Adapter
    );

static NDIS_STATUS
AdapterSetOffloadAttributes (
    IN  PADAPTER Adapter
    );

static VOID
AdapterProcessSGList (
    IN PDEVICE_OBJECT       DeviceObject,
    IN PVOID                Reserved,
    IN PSCATTER_GATHER_LIST SGL,
    IN PVOID                Context
    );

static VOID
AdapterRegisterSuspendHandlers (
    IN  PADAPTER Adapter
    );

static PCHAR
AdapterReadBackendPath (
    PCHAR           XenbusPath, 
    SUSPEND_TOKEN   Token
    );

static char *
ReadBackend (
    const char *prefix,
    SUSPEND_TOKEN token
    );

static NDIS_STATUS
AdapterReadMacFromXenstore (
    IN  PCHAR   XenbusPath,
    IN  PUCHAR  Mac
    );

static NDIS_STATUS
AdapterReadMacFromRegistry (
    IN  NDIS_HANDLE NdisHandle, 
    IN  PUCHAR      Mac
    );

static NDIS_STATUS
AdapterSetInformation (
    IN  PADAPTER            Adapter,
    IN  PNDIS_OID_REQUEST   NdisRequest
    );

static NDIS_STATUS
AdapterQueryInformation (
    IN  PADAPTER            Adapter,
    IN  PNDIS_OID_REQUEST   NdisRequest
    );

static VOID
AdapterResumeEarly (
    IN  PADAPTER        Adapter,
    IN  SUSPEND_TOKEN   Token
    );

static VOID
AdapterResumeLate (
    IN  PADAPTER        Adapter,
    IN  SUSPEND_TOKEN   Token
    );

static NDIS_STATUS
AdapterSetNetworkLayerAddresses (
    IN  PADAPTER                Adapter,
    IN  PNETWORK_ADDRESS_LIST   NetworkAddressList,
    IN  ULONG                   NetworkAddressListSize
    );

static NDIS_OID XennetSupportedOids[] =
{
    OID_GEN_SUPPORTED_LIST,
    OID_GEN_HARDWARE_STATUS,
    OID_GEN_MEDIA_SUPPORTED,
    OID_GEN_MEDIA_IN_USE,
    OID_GEN_PHYSICAL_MEDIUM,
    OID_GEN_CURRENT_LOOKAHEAD,
    OID_GEN_MAXIMUM_LOOKAHEAD,
    OID_GEN_MAXIMUM_FRAME_SIZE,
    OID_GEN_MAXIMUM_TOTAL_SIZE,
    OID_GEN_RECEIVE_BLOCK_SIZE,
    OID_GEN_TRANSMIT_BLOCK_SIZE,
    OID_GEN_MAC_OPTIONS,
    OID_GEN_LINK_SPEED,
    OID_GEN_MEDIA_CONNECT_STATUS,
    OID_GEN_VENDOR_DESCRIPTION,
    OID_GEN_VENDOR_DRIVER_VERSION,
    OID_GEN_DRIVER_VERSION,
    OID_GEN_MAXIMUM_SEND_PACKETS,
    OID_GEN_VENDOR_ID,
    OID_GEN_CURRENT_PACKET_FILTER,
    OID_GEN_XMIT_OK,
    OID_GEN_RCV_OK,
    OID_GEN_XMIT_ERROR,
    OID_GEN_RCV_ERROR,
    OID_GEN_RCV_CRC_ERROR,
    OID_GEN_RCV_NO_BUFFER,
    OID_GEN_TRANSMIT_QUEUE_LENGTH,
    OID_GEN_TRANSMIT_BUFFER_SPACE,
    OID_GEN_RECEIVE_BUFFER_SPACE,
    OID_GEN_NETWORK_LAYER_ADDRESSES,
    OID_GEN_STATISTICS,
    OID_GEN_DIRECTED_BYTES_XMIT,
    OID_GEN_DIRECTED_FRAMES_XMIT,
    OID_GEN_MULTICAST_BYTES_XMIT,
    OID_GEN_MULTICAST_FRAMES_XMIT,
    OID_GEN_BROADCAST_BYTES_XMIT,
    OID_GEN_BROADCAST_FRAMES_XMIT,
    OID_GEN_DIRECTED_BYTES_RCV,
    OID_GEN_DIRECTED_FRAMES_RCV,
    OID_GEN_MULTICAST_BYTES_RCV,
    OID_GEN_MULTICAST_FRAMES_RCV,
    OID_GEN_BROADCAST_BYTES_RCV,
    OID_GEN_BROADCAST_FRAMES_RCV,
    OID_GEN_INTERRUPT_MODERATION,
    OID_802_3_RCV_ERROR_ALIGNMENT,
    OID_802_3_XMIT_ONE_COLLISION,
    OID_802_3_XMIT_MORE_COLLISIONS,
    OID_OFFLOAD_ENCAPSULATION,
    OID_TCP_OFFLOAD_PARAMETERS,
};

ULONG XennetMacOptions = XENNET_MAC_OPTIONS;

#define INITIALIZE_NDIS_OBJ_HEADER(obj, type) do {               \
    (obj).Header.Type = NDIS_OBJECT_TYPE_ ## type ;              \
    (obj).Header.Revision = NDIS_ ## type ## _REVISION_1;        \
    (obj).Header.Size = sizeof(obj);                             \
} while (0)

//
// Scatter gather allocate handler callback.
// Should never get called.
//
static VOID
AdapterAllocateComplete (
    IN NDIS_HANDLE              MiniportAdapterContext,
    IN PVOID                    VirtualAddress,
    IN PNDIS_PHYSICAL_ADDRESS   PhysicalAddress,
    IN ULONG                    Length,
    IN PVOID                    Context
    )
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Context);

    XM_BUG();

    return;
}

//
// Required NDIS6 handler.
// Should never get called.
//
VOID
AdapterCancelOidRequest (
    IN  PADAPTER    Adapter,
    IN  PVOID       RequestId
    )
{
    UNREFERENCED_PARAMETER(Adapter);
    UNREFERENCED_PARAMETER(RequestId);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    XM_BUG();

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}

//
// Required NDIS6 handler.
// Should never get called.
//

VOID 
AdapterCancelSendNetBufferLists (
    IN  PADAPTER    Adapter,
    IN  PVOID       CancelId
    )
{
    UNREFERENCED_PARAMETER(Adapter);
    UNREFERENCED_PARAMETER(CancelId);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}

BOOLEAN 
AdapterCheckForHang (
    IN  PADAPTER Adapter
    )
{
    UNREFERENCED_PARAMETER(Adapter);

    return FALSE;
}

//
// Frees resources obtained by AdapterInitialize.
//
static VOID
AdapterCleanup (
    IN  PADAPTER Adapter
    )
{
    BOOLEAN TearDown = FALSE;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (Adapter->BackStateWatch)
        xenbus_unregister_watch(Adapter->BackStateWatch);
    Adapter->BackStateWatch = NULL;

    if (Adapter->MediaWatch)
        xenbus_unregister_watch(Adapter->MediaWatch);
    Adapter->MediaWatch = NULL;

    EvtchnReleaseDebugCallback(Adapter->DebugCallback);
    Adapter->DebugCallback = null_EVTCHN_DEBUG_CALLBACK();

    if (Adapter->BackendPath)
        TearDown = (BOOLEAN)(AdapterDisconnectBackend(Adapter) == NDIS_STATUS_ADAPTER_NOT_READY);
    else
        TearDown = TRUE;

    if (Adapter->LateSuspendHandler != NULL) {
        EvtchnUnregisterSuspendHandler(Adapter->LateSuspendHandler);
    }

    if (Adapter->EarlySuspendHandler != NULL) {
        EvtchnUnregisterSuspendHandler(Adapter->EarlySuspendHandler);
    }

    if (!is_null_EVTCHN_PORT(Adapter->EvtchnPort)) {
        EvtchnPortStop(Adapter->EvtchnPort);
        EvtchnClose(Adapter->EvtchnPort);
    }

    if (Adapter->Transmitter)
        TransmitterDelete(&Adapter->Transmitter, TearDown);
    if (&Adapter->Receiver)
        ReceiverCleanup(&Adapter->Receiver, TearDown);
    if (Adapter->GrantCache)
        GnttabFreeCache(Adapter->GrantCache);
    if (&Adapter->Lock)
        NdisFreeSpinLock(&Adapter->Lock);
    if (Adapter->BackendPath)
        XmFreeMemory(Adapter->BackendPath);
    if (Adapter->FrontendPath)
        XmFreeMemory(Adapter->FrontendPath);
    AdapterCleanupIpAddressList(Adapter);
    if (&Adapter->IpAddressList.Lock)
        NdisFreeSpinLock(&Adapter->IpAddressList.Lock);
    if (Adapter->NdisDmaHandle != NULL) {
        NdisMDeregisterScatterGatherDma(Adapter->NdisDmaHandle);
    }

    nbl_hash_deinit();

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}

//
// Frees resources for IP address list in the adapter.
//
static VOID
AdapterCleanupIpAddressList (
    IN  PADAPTER Adapter
    )
{
    PIP_ADDRESS ip;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    NdisAcquireSpinLock(&Adapter->IpAddressList.Lock);
    ip = Adapter->IpAddressList.Addresses;
    if (ip) {
        Adapter->IpAddressList.Addresses = NULL;
        Adapter->IpAddressList.Count = 0;
    }

    NdisReleaseSpinLock(&Adapter->IpAddressList.Lock);
    if (ip) {
        XmFreeMemory(ip);
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}

//
// Establishes connection to netback.
//
static NDIS_STATUS
AdapterConnectBackend (
    IN  PADAPTER    Adapter,
    SUSPEND_TOKEN   Token
    )
{
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    XENBUS_STATE state;
    NTSTATUS status;
    xenbus_transaction_t xbt;
    PCHAR frontendPath;

    XM_ASSERT(Adapter != NULL);
    XM_ASSERT(Adapter->Transmitter != NULL);
    XM_ASSERT(!is_null_EVTCHN_PORT(Adapter->EvtchnPort));

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    //
    // Communicate configuration to backend.
    //

    frontendPath = Adapter->FrontendPath;
    do {
        xenbus_transaction_start(&xbt);
        xenbus_write_grant_ref(xbt, frontendPath, "tx-ring-ref",
                               Adapter->Transmitter->RingGrantRef);

        xenbus_write_grant_ref(xbt, frontendPath, "rx-ring-ref",
                               Adapter->Receiver.Common.RingGrantRef);

        xenbus_write_evtchn_port(xbt, frontendPath, "event-channel",
                                 Adapter->EvtchnPort);

        xenbus_write_feature_flag(xbt, frontendPath, "request-rx-copy", TRUE);
        xenbus_write_feature_flag(xbt, frontendPath, "feature-sg", TRUE);
        xenbus_write_feature_flag(xbt, frontendPath, "feature-rx-notify", TRUE);
        if (Adapter->Receiver.TcpChecksumOffload)
            xenbus_write_feature_flag(xbt, frontendPath,
                                      "feature-no-csum-offload", FALSE);
        else
            xenbus_write_feature_flag(xbt, frontendPath,
                                      "feature-no-csum-offload", TRUE);

        xenbus_change_state(xbt, frontendPath, "state",
                            XENBUS_STATE_CONNECTED);
        status = xenbus_transaction_end(xbt, 0);

    } while (status == STATUS_RETRY);

    if (status != STATUS_SUCCESS) {
        TraceError(("Failed to end transaction, 0x%08x.\n", ndisStatus));
        ndisStatus = NDIS_STATUS_FAILURE;
        goto exit;
    }

    //
    // Wait for backend to accept configuration and complete initialization.
    //

    state = null_XENBUS_STATE();
    for (;;) {
        state = XenbusWaitForBackendStateChange(Adapter->BackendPath, state, NULL,
                                                Token);

        if (is_null_XENBUS_STATE(state) ||
            same_XENBUS_STATE(state, XENBUS_STATE_CLOSING) ||
            same_XENBUS_STATE(state, XENBUS_STATE_CLOSED)) {

            TraceError(("Failed to connected '%s' <-> '%s'.\n", 
                        Adapter->FrontendPath, 
                        Adapter->BackendPath));

            ndisStatus = NDIS_STATUS_FAILURE;
            break;
        }

        if (same_XENBUS_STATE(state, XENBUS_STATE_CONNECTED)) {
            NdisAcquireSpinLock(&Adapter->Transmitter->Lock);
            Adapter->RingConnected = TRUE;
            NdisReleaseSpinLock(&Adapter->Transmitter->Lock);

            TraceNotice(("Connected '%s' <-> '%s'.\n", 
                         Adapter->FrontendPath, 
                         Adapter->BackendPath));
            break;
        }
    } 

exit:
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return ndisStatus;
}

//
// Dumps adapter state for debugging.
//
static VOID
AdapterDebugDump (
    IN  PADAPTER Adapter
    )
{
    if (Adapter->BackendPath) {
        TraceInternal(("Backend path %s\n", Adapter->BackendPath));
    }

    if (Adapter->FrontendPath) {
        TraceInternal(("Frontend path %s\n", Adapter->FrontendPath));
    }

    TraceInternal(("Filter %x, flags %x, mtu %d, %d mcast addresses, connected %d\n",
                 Adapter->CurrentPacketFilter,
                 Adapter->Flags,
                 Adapter->Mtu,
                 Adapter->MulticastAddressesCount,
                 Adapter->MediaConnected));

    TraceInternal(("%d interrupts\n", Adapter->Interrupts));

    ReceiverDebugDump(&Adapter->Receiver);

    if (Adapter->Transmitter) {
        TransmitterDebugDump(Adapter->Transmitter);
    }

    return;
}

//
// Frees adapter storage.
//
VOID
AdapterDelete (
    IN  OUT PADAPTER* Adapter
    )
{
    XM_ASSERT(Adapter != NULL);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (*Adapter) {
        AdapterCleanup(*Adapter);
        XmFreeMemory(*Adapter);
        *Adapter = NULL;
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}

//
// Disconnects from netback.
//
static NDIS_STATUS
AdapterDisconnectBackend (
    IN  PADAPTER    Adapter
    )
{
    PCHAR frontendPath;
    PCHAR backendPath;
    XENBUS_STATE frontendState;
    XENBUS_STATE backendState;
    NDIS_STATUS ndisStatus;
    SUSPEND_TOKEN token;

    ndisStatus = NDIS_STATUS_SUCCESS;
    token = EvtchnAllocateSuspendToken("xennet disconnect");
    backendPath = Adapter->BackendPath;
    if (!backendPath) {
        TraceError(("Shutting down an adapter %s which wasn't properly created?\n",
                      Adapter->FrontendPath));

        ndisStatus = NDIS_STATUS_ADAPTER_NOT_READY;
        goto exit;
    }

    // Wait for the backend to stabilise before we close it
    backendState = null_XENBUS_STATE();
    do {
        backendState = XenbusWaitForBackendStateChange(backendPath, backendState,
                                                       NULL, token);
    } while (same_XENBUS_STATE(backendState, XENBUS_STATE_INITIALISING));

    NdisAcquireSpinLock(&Adapter->Transmitter->Lock);
    Adapter->RingConnected = FALSE;
    NdisReleaseSpinLock(&Adapter->Transmitter->Lock);

    // Now close the frontend
    frontendPath = Adapter->FrontendPath;
    frontendState = XENBUS_STATE_CLOSING;
    while (!same_XENBUS_STATE(backendState, XENBUS_STATE_CLOSING) &&
           !same_XENBUS_STATE(backendState, XENBUS_STATE_CLOSED) &&
           !is_null_XENBUS_STATE(backendState)) {
        xenbus_change_state(XBT_NIL, frontendPath, "state",
                            frontendState);
        backendState = XenbusWaitForBackendStateChange(backendPath, backendState,
                                                       NULL, token);
    }

    frontendState = XENBUS_STATE_CLOSED;
    while (!same_XENBUS_STATE(backendState, XENBUS_STATE_CLOSED) &&
           !is_null_XENBUS_STATE(backendState)) {
        xenbus_change_state(XBT_NIL, frontendPath, "state",
                            frontendState);
        backendState = XenbusWaitForBackendStateChange(backendPath, backendState,
                                                       NULL, token);
    }

    XmFreeMemory(Adapter->BackendPath);
    Adapter->BackendPath = NULL;

exit:
    EvtchnReleaseSuspendToken(token);
    return ndisStatus;
}


//
// Netfront DPC routine.
//
static VOID 
AdapterEventChannelCallback(
    IN  PADAPTER Adapter
    )
{
    Adapter->Interrupts++;
    ReceiverHandleNotification(&Adapter->Receiver);
    TransmitterHandleNotification(Adapter->Transmitter);
}

/* Do the actual shutdown work required for MPHalt or PnP removal */
static VOID
MpInitialShutdown(PADAPTER Adapter, BOOLEAN SurpiseRemoval)
{
    char *backend;

    //
    // Mark adapter so no new buffers are transmitted
    // in paused state.
    //
    NdisAcquireSpinLock(&Adapter->Lock);
    if (Adapter->Flags & XENNET_ADAPTER_STOPPING) {
        TraceBugCheck(("Tried to shut the adapter down several times?\n"));
    }
    Adapter->Flags |= XENNET_ADAPTER_STOPPING;
    NdisReleaseSpinLock(&Adapter->Lock);

    /* Turn off the watchpoints immediately. Want to prevent indicating NDIS media
     * status changes during a surprise remove or while halting.
     */
    if (Adapter->BackStateWatch)
        xenbus_unregister_watch(Adapter->BackStateWatch);
    Adapter->BackStateWatch = NULL;

    if (Adapter->MediaWatch)
        xenbus_unregister_watch(Adapter->MediaWatch);
    Adapter->MediaWatch = NULL;


    /* Update the backend field in the adapter struct since
     * it may have changed in xenstore.
     * Note also that the last parameter in the following call
     * is ignored!!
     */
    backend = ReadBackend(Adapter->FrontendPath, null_SUSPEND_TOKEN());
    if (!backend)
    {
        TraceError(("Backend node gone from %s\n", Adapter->FrontendPath));
    }
    if (Adapter->BackendPath)
        XmFreeMemory(Adapter->BackendPath);
    Adapter->BackendPath = backend;

    /* Transmitter shutdown above, wait for or force free all outstanding packets. */
    if (!SurpiseRemoval)
        TransmitterWaitForIdle(Adapter->Transmitter, FALSE);
    else
    {
        TransmitterForceFreePackets(Adapter->Transmitter);
        TraceVerbose(("Outstanding Tx count after ForceFreePackets: %d\n",
            Adapter->Transmitter->QueuedCount));
        TransmitterWaitForIdle(Adapter->Transmitter, FALSE);
    }
}

VOID
MPPnPEventHandler(
    IN  PADAPTER                Adapter,
    IN  PNET_DEVICE_PNP_EVENT   NetDevicePnPEvent
)
{
    TraceInfo(("%s: ====> (%p) Event: %d\n", __FUNCTION__, Adapter, NetDevicePnPEvent->DevicePnPEvent));

    if (NetDevicePnPEvent->DevicePnPEvent == NdisDevicePnPEventRemoved) {
        TraceInfo(("PnP NdisDevicePnPEventRemoved notification\n"));
        Adapter->RemovalPending = TRUE;
    }
    else if (NetDevicePnPEvent->DevicePnPEvent == NdisDevicePnPEventSurpriseRemoved) {
        TraceInfo(("PnP NdisDevicePnPEventSurpriseRemoved notification\n"));
        Adapter->RemovalPending = TRUE;
    }

    /* During a surprise removal due to a PnP unplug, a number of things need to be
     * cleaned up here or MPHalt will never get called leading to doom and misery.
     */
    if (Adapter->RemovalPending) {
        TraceVerbose(("Outstanding Tx count after surprise removal: %d\n",
            Adapter->Transmitter->QueuedCount));
        MpInitialShutdown(Adapter, TRUE);
    }

    TraceInfo(("%s: <==== (%p)\n", __FUNCTION__, Adapter));
}

//
// Stops adapter and frees all resources.
//
VOID 
AdapterHalt (
    IN  PADAPTER                Adapter,
    IN  NDIS_HALT_ACTION        HaltAction
    )
{
    NDIS_STATUS ndisStatus;

    UNREFERENCED_PARAMETER(HaltAction);

    TraceInfo(("====> '%s'(%s).\n", __FUNCTION__,
               Adapter->FrontendPath));

    ndisStatus = AdapterStop(Adapter);
    if (ndisStatus == NDIS_STATUS_SUCCESS) {
        AdapterDelete(&Adapter);
    }

    TraceInfo(("<==== '%s'.\n", __FUNCTION__));
    return;
}

//
// Reports full duplex, connected state.
//
static VOID
AdapterIndicateLinkState (
    IN  PADAPTER Adapter
    )
{   
    NDIS_LINK_STATE linkState;
    NDIS_STATUS_INDICATION statusIndication;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    TraceNotice(("Media state changed to %s.\n",
                 Adapter->MediaConnected ? "connected" : "disconnected"));
    NdisZeroMemory(&linkState, sizeof(NDIS_LINK_STATE));    
    NdisZeroMemory(&statusIndication, sizeof(NDIS_STATUS_INDICATION));
    linkState.Header.Revision = NDIS_LINK_STATE_REVISION_1;
    linkState.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    linkState.Header.Size = sizeof(NDIS_LINK_STATE);
    if (Adapter->MediaConnected) {
        linkState.MediaConnectState = MediaConnectStateConnected;
        linkState.MediaDuplexState = MediaDuplexStateFull;
        linkState.XmitLinkSpeed = linkState.RcvLinkSpeed = XENNET_MEDIA_MAX_SPEED;
    } else {
        linkState.MediaConnectState = MediaConnectStateDisconnected;
        linkState.MediaDuplexState = MediaDuplexStateUnknown;
        linkState.XmitLinkSpeed = linkState.RcvLinkSpeed = NDIS_LINK_SPEED_UNKNOWN;
    }
    statusIndication.Header.Type = NDIS_OBJECT_TYPE_STATUS_INDICATION;
    statusIndication.Header.Revision = NDIS_STATUS_INDICATION_REVISION_1;
    statusIndication.Header.Size = sizeof(NDIS_STATUS_INDICATION);
    statusIndication.SourceHandle = Adapter->NdisAdapterHandle;
    statusIndication.StatusCode = NDIS_STATUS_LINK_STATE;
    statusIndication.StatusBuffer = &linkState;
    statusIndication.StatusBufferSize = sizeof(linkState);
    NdisMIndicateStatusEx(Adapter->NdisAdapterHandle, &statusIndication);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}

static void
MediaStateChangedCb(void *_adapter)
{
    PADAPTER pAdapt = _adapter;
    BOOLEAN disconnected = TRUE;
    NTSTATUS status;
    xenbus_transaction_t xbt;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    xenbus_transaction_start(&xbt);
    status = xenbus_read_feature_flag(xbt,
	                                  pAdapt->FrontendPath,
                                      "disconnect",
                                      &disconnected);
	if (!NT_SUCCESS(status))
		disconnected = TRUE;
    xenbus_transaction_end (xbt, 0);

    if (disconnected) {
        if (pAdapt->MediaConnected) {
            TraceNotice(("Media disconnected!\n"));
            NdisAcquireSpinLock(&pAdapt->Receiver.Common.Lock);
            NdisAcquireSpinLock(&pAdapt->Transmitter->Lock);
            pAdapt->MediaConnected = 0;
            NdisReleaseSpinLock(&pAdapt->Transmitter->Lock);
            NdisReleaseSpinLock(&pAdapt->Receiver.Common.Lock);
            AdapterIndicateLinkState(pAdapt);
        }
    } else {
        if (!pAdapt->MediaConnected) {
            TraceNotice(("Media connected!\n"));
            NdisAcquireSpinLock(&pAdapt->Receiver.Common.Lock);
            NdisAcquireSpinLock(&pAdapt->Transmitter->Lock);
            pAdapt->MediaConnected = TRUE;
            NdisReleaseSpinLock(&pAdapt->Transmitter->Lock);
            NdisReleaseSpinLock(&pAdapt->Receiver.Common.Lock);
            AdapterIndicateLinkState(pAdapt);
            /* Kick to try and unstall the receive ring. */
            EvtchnRaiseLocally(pAdapt->EvtchnPort);
        }
    }
    TraceVerbose(("<==== '%s'\n", __FUNCTION__));
}

static void
AdapterBackendStateChanged(void *_adapter)
{
	(void*)_adapter;
}

static void
AdapterSetLro(
    IN  PADAPTER Adapter
    )
{
    TraceVerbose(("====> '%s'.\n", __FUNCTION__));
    xenbus_write_feature_flag(XBT_NIL, Adapter->FrontendPath,
                              "feature-gso-tcpv4-prefix",
                              (BOOLEAN)(Adapter->Properties.lro != 0));
    TraceNotice(("LRO %s\n", (Adapter->Properties.lro != 0) ? "ON" : "OFF"));
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
}

//
// Initializes adapter by allocating required resources and connects to 
// netback.
//
NDIS_STATUS 
AdapterInitialize (
    IN  PADAPTER    Adapter,
    IN  NDIS_HANDLE AdapterHandle,
    IN  PCHAR       FrontendPath
    )
{
    NDIS_SG_DMA_DESCRIPTION dmaDescription;
    NDIS_STATUS ndisStatus;
    SUSPEND_TOKEN token;
    char *watch_path;

    TraceInfo(("====> '%s'.\n", __FUNCTION__));

    nbl_hash_init();

    token = EvtchnAllocateSuspendToken("xennet");
    if (is_null_SUSPEND_TOKEN(token)) {
        ndisStatus = NDIS_STATUS_RESOURCES;
        goto exit;
    }

    Adapter->RingConnected = FALSE;
////////////    Adapter->MediaConnected = TRUE;
    Adapter->MediaConnected = FALSE;
    Adapter->NdisAdapterHandle = AdapterHandle;
    Adapter->FrontendPath = FrontendPath;
    Adapter->GrantCache = GnttabAllocCache(0);
    if (!Adapter->GrantCache) {
        ndisStatus = NDIS_STATUS_RESOURCES;
        goto exit;
    }

    Adapter->Transmitter = XmAllocateZeroedMemory(sizeof(TRANSMITTER));
    if (!Adapter->Transmitter) {
        ndisStatus = NDIS_STATUS_RESOURCES;
        goto exit;
    }

    ndisStatus = AdapterInitializeBackend(Adapter, AdapterHandle, token);
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        goto exit;
    }

    ndisStatus = ReceiverInitialize(&Adapter->Receiver, Adapter);
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        goto exit;
    }

    ndisStatus = TransmitterInitialize(Adapter->Transmitter, Adapter);
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        goto exit;
    }

    NdisAllocateSpinLock(&Adapter->Lock);
    NdisAllocateSpinLock(&Adapter->IpAddressList.Lock);
    Adapter->EvtchnPort =
        EvtchnAllocUnboundDpc(Adapter->BackendDomid, AdapterEventChannelCallback,
                              Adapter);

    if (is_null_EVTCHN_PORT(Adapter->EvtchnPort)) {
        ndisStatus = NDIS_STATUS_RESOURCES;
        goto exit;
    }

    ndisStatus = MpSetAdapterSettings(Adapter);
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        goto exit;
    }

    ndisStatus = MpGetAdvancedSettings(Adapter);
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        goto exit;
    }

    AdapterSetLro(Adapter);

    ndisStatus = AdapterConnectBackend(Adapter, token);
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        goto exit;

    XM_ASSERT(Adapter->BackendPath != NULL);

    ndisStatus = AdapterSetRegistrationAttributes(Adapter);
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        goto exit;
    }

    ndisStatus = AdapterSetGeneralAttributes(Adapter);
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        goto exit;
    }

    ndisStatus = AdapterSetOffloadAttributes(Adapter);
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        goto exit;
    }

    if (!XenPVFeatureEnabled(DEBUG_NIC_NO_DMA)) {
        NdisZeroMemory(&dmaDescription, sizeof(dmaDescription));
        dmaDescription.Header.Type = NDIS_OBJECT_TYPE_SG_DMA_DESCRIPTION;
        dmaDescription.Header.Revision = NDIS_SG_DMA_DESCRIPTION_REVISION_1;
        dmaDescription.Header.Size = sizeof(NDIS_SG_DMA_DESCRIPTION);
        dmaDescription.Flags = NDIS_SG_DMA_64_BIT_ADDRESS;
        dmaDescription.MaximumPhysicalMapping = XENNET_MAX_PACKET_SIZE;    
        dmaDescription.ProcessSGListHandler = AdapterProcessSGList;
        dmaDescription.SharedMemAllocateCompleteHandler = AdapterAllocateComplete;
        ndisStatus = NdisMRegisterScatterGatherDma(
                        Adapter->NdisAdapterHandle,
                        &dmaDescription,
                        &Adapter->NdisDmaHandle);

        if (ndisStatus != NDIS_STATUS_SUCCESS) {
            TraceError(("Failed 0x%08x NdisMRegisterScatterGatherDma.\n", ndisStatus));
            goto exit;
        }
    }

    AdapterRegisterSuspendHandlers(Adapter);
    AdapterIndicateLinkState(Adapter);

    Adapter->DebugCallback = EvtchnSetupDebugCallback(AdapterDebugDump,
                                                      Adapter);

    watch_path = Xmasprintf("%s/disconnect", FrontendPath);
    if (watch_path) {
        Adapter->MediaWatch = xenbus_watch_path(watch_path,
                                                MediaStateChangedCb,
                                                Adapter);
        XmFreeMemory(watch_path);
    }

    watch_path = Xmasprintf("%s/backend-state", FrontendPath);
    if (watch_path) {
        Adapter->BackStateWatch = xenbus_watch_path(watch_path,
                                                AdapterBackendStateChanged,
                                                Adapter);
        XmFreeMemory(watch_path);
    }

exit:
    if (!is_null_SUSPEND_TOKEN(token)) {
        EvtchnReleaseSuspendToken(token);
    }

    TraceInfo(("<==== '%s'.\n", __FUNCTION__));
    return ndisStatus;
}

//
// Initializes netback for the adapter.
//
static NDIS_STATUS
AdapterInitializeBackend (
    IN  PADAPTER        Adapter,
    IN  NDIS_HANDLE     Context,
    IN  SUSPEND_TOKEN   Token
    )
{
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    BOOLEAN rxCopy;
    NTSTATUS status;
    XENBUS_STATE state;
    BOOLEAN lsoAvailable;
    BOOLEAN txCsumOffload;
    ULONG64 mtu64;

    XM_ASSERT(Adapter != NULL);
    XM_ASSERT(Adapter->Transmitter != NULL);
    XM_ASSERT(Adapter->FrontendPath != NULL);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    XmFreeMemory(Adapter->BackendPath);
    Adapter->BackendPath = AdapterReadBackendPath(Adapter->FrontendPath, 
                                                  Token);

    if (!Adapter->BackendPath) {
        TraceError(("Could not find backend for '%s'!\n", Adapter->FrontendPath));
        ndisStatus = NDIS_STATUS_RESOURCES;
        goto exit;
    }

    //
    // Wait for backend to get ready for initialization.
    //

    xenbus_change_state(XBT_NIL, 
                        Adapter->FrontendPath, 
                        "state",
                        XENBUS_STATE_INITIALISING);

    state = null_XENBUS_STATE();
    for (;;) {
        state = XenbusWaitForBackendStateChange(Adapter->BackendPath, 
                                                state,
                                                NULL, 
                                                Token);

        if (same_XENBUS_STATE(state, XENBUS_STATE_INITWAIT)) {
            break;
        }

        if (same_XENBUS_STATE(state, XENBUS_STATE_CLOSING) ||
            is_null_XENBUS_STATE(state)) {

            TraceWarning(("Backend '%s' went away before we could connect to it?\n", 
                            Adapter->BackendPath));

            ndisStatus = NDIS_STATUS_FAILURE;
            goto exit;
        }
    }

    status = xenbus_read_domain_id(XBT_NIL, Adapter->FrontendPath,
                                   "backend-id", &Adapter->BackendDomid);
    if (!NT_SUCCESS(status)) {
        TraceError(("Failed to read backend id from %s (%x)\n",
                    Adapter->FrontendPath, status));
        Adapter->BackendDomid = DOMAIN_ID_0();
    }

    status = xenbus_read_feature_flag(XBT_NIL, 
                                      Adapter->BackendPath,
                                      "feature-rx-copy", 
                                      &rxCopy);

    if (!NT_SUCCESS(status) || !rxCopy) {
        TraceError(("Bad adapter '%s'!\n", Adapter->FrontendPath));
        ndisStatus = NDIS_STATUS_NOT_SUPPORTED;
        goto exit;
    }

    //
    // NDIS occasionally generates packets which have the TCP and IP
    // headers in different fragments, and once it's done so it tends
    // to do the same thing on retransmissions of that packet as well.
    // This interacts with a bug in old versions of Linux netback, and
    // so we can't safely enable TX csum offload on those versions.
    //

    status = xenbus_read_feature_flag(XBT_NIL, 
                                      Adapter->BackendPath,
                                      "feature-tx-csum-split-header",
                                      &txCsumOffload);

    if (XenPVFeatureEnabled(DEBUG_HCT_MODE))
        txCsumOffload = FALSE;

    if (NT_SUCCESS(status) && txCsumOffload) {
        TraceVerbose(("TX checksum offload allowed by backend.\n"));
        Adapter->Transmitter->ChecksumOffloadSafe = TRUE;

        /* XXX: The NDIS documentation claims that offloads should
           default disable until you the encapsulation is set, which
           is true for a normal boot but not for
           resume-from-hibernation.  In that case, NDIS assumes that
           offloads have the same values as they did before the
           hibernation.  Unfortunately, we have nowhere to stash data
           across hibernate/resume.  It's safer to turn on csum
           offload when it's supposed to be off than to turn it off
           when it's on (because if it's supposed to be off NDIS won't
           set the per-packet bit), so just go with that. */
        Adapter->Transmitter->TcpChecksumOffload = TRUE;
        Adapter->Transmitter->UdpChecksumOffload = TRUE;
    } else {
        TraceVerbose(("TX checksum offload disallowed by backend.\n"));
        Adapter->Transmitter->ChecksumOffloadSafe = FALSE;
    }

    if (!XenPVFeatureEnabled(DEBUG_NIC_NO_TSO) &&
        !XenPVFeatureEnabled(DEBUG_HCT_MODE)) {
        status = xenbus_read_feature_flag(XBT_NIL, 
                                          Adapter->BackendPath,
                                          "feature-gso-tcpv4",
                                          &lsoAvailable);

        if (NT_SUCCESS(status) && lsoAvailable) {
            TraceVerbose(("TCP segmentation offload available in backend.\n"));
            Adapter->Transmitter->LsoAvailable = TRUE;
        } else {
            TraceVerbose(("TCP segmentation offload not available in backend.\n"));
            Adapter->Transmitter->LsoAvailable = FALSE;
        }
    } else {
        TraceNotice(("TSO disabled.\n"));
        Adapter->Transmitter->LsoAvailable = FALSE;
    }

    if (Context != INVALID_HANDLE_VALUE) {
        status = AdapterReadMacFromXenstore(Adapter->FrontendPath,
                                            Adapter->PermanentAddress);

        if (status != NDIS_STATUS_SUCCESS) {
            
            //
            // Different versions of dom0 and the tools put the MAC
            // address in different places.  Work around this by checking
            // the backend area as well when it's not present in the
            // frontend area.
            //

            status = AdapterReadMacFromXenstore(Adapter->BackendPath,
                                                Adapter->PermanentAddress);
        }

        if (status != NDIS_STATUS_SUCCESS) {
            TraceError(("Cannot read MAC from '%s' or '%s'.\n", 
                         Adapter->FrontendPath,
                         Adapter->BackendPath));

            ndisStatus = status;
            goto exit;
        }

        //
        // Check for registry override of the MAC address.
        //

        status = AdapterReadMacFromRegistry(Context, 
                                            Adapter->CurrentAddress);

        if (status != NDIS_STATUS_SUCCESS) {
            memcpy(Adapter->CurrentAddress, 
                   Adapter->PermanentAddress,
                   ETH_LENGTH_OF_ADDRESS);
        }
    }

    status = xenbus_read_int(XBT_NIL, Adapter->FrontendPath, "mtu",
                             &mtu64);
    if (!NT_SUCCESS(status) || mtu64 > XENNET_MAX_MTU) {
        Adapter->Mtu = XENNET_DEF_MTU;
        TraceVerbose(("Using default MTU %d.\n", Adapter->Mtu));
    } else {
        Adapter->Mtu = (ULONG)mtu64;
        TraceVerbose(("MTU %d specified by backend.\n", Adapter->Mtu));
    }

exit:
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return ndisStatus;
}

//
// Checks specified MAC address against current packet filter to see if
// packet is interesting to NDIS6.
//
BOOLEAN
AdapterIsMacAddressInteresting (
    IN  PADAPTER        Adapter,
    IN  PUCHAR          Mac
    )
{
    ULONG i;
    BOOLEAN result = FALSE;

    if (Adapter->CurrentPacketFilter & NDIS_PACKET_TYPE_PROMISCUOUS) {
        result = TRUE;
        goto exit;
    }

    if (!(Mac[0] & 1)) {

        if (!(Adapter->CurrentPacketFilter & NDIS_PACKET_TYPE_DIRECTED)) {
            goto exit;
        }

        if (!memcmp(Mac, Adapter->CurrentAddress, 6)) {
            result = TRUE;
        }

        goto exit;
    }

    if (Adapter->CurrentPacketFilter & NDIS_PACKET_TYPE_ALL_MULTICAST) {
        result = TRUE;
        goto exit;
    }

    if ((Mac[0] & ~2) == 0xFD &&
         Mac[1] == 0xFF &&
         Mac[2] == 0xFF &&
         Mac[3] == 0xFF &&
         Mac[4] == 0xFF &&
         Mac[5] == 0xFF ) {

        if (Adapter->CurrentPacketFilter & NDIS_PACKET_TYPE_BROADCAST) {
            result = TRUE;
        }

        goto exit;
    }

    if (!(Adapter->CurrentPacketFilter & NDIS_PACKET_TYPE_MULTICAST)) {
        goto exit;
    }

    for (i = 0; i < Adapter->MulticastAddressesCount; i++) {
        if (!memcmp(Mac, &Adapter->MulticastAddresses[i], 6)) {
            result = TRUE;
            goto exit;
        }
    }

exit:
    return result;
}

//
// Scatter gather process handler callback.
// Should never get called.
//
static VOID
AdapterProcessSGList (
    IN PDEVICE_OBJECT       DeviceObject,
    IN PVOID                Reserved,
    IN PSCATTER_GATHER_LIST SGL,
    IN PVOID                Context
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Reserved);
    UNREFERENCED_PARAMETER(SGL);
    UNREFERENCED_PARAMETER(Context);

    XM_BUG();

    return;
}

static void
AdapterEnableRxCsumOffload(
    IN  PADAPTER Adapter
    )
{
    TraceVerbose(("====> '%s'.\n", __FUNCTION__));
    xenbus_write_feature_flag(XBT_NIL, Adapter->FrontendPath,
                              "feature-no-csum-offload", FALSE);
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
}

static void
AdapterDisableRxCsumOffload(
    IN  PADAPTER Adapter
    )
{
    TraceVerbose(("====> '%s'.\n", __FUNCTION__));
    xenbus_write_feature_flag(XBT_NIL, Adapter->FrontendPath,
                              "feature-no-csum-offload", TRUE);
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
}

//
// Get\Set OID handler.
//
NDIS_STATUS 
AdapterOidRequest (
    IN  PADAPTER            Adapter,
    IN  PNDIS_OID_REQUEST   NdisRequest
    )
{
    NDIS_STATUS ndisStatus;

    UNREFERENCED_PARAMETER(Adapter);
    UNREFERENCED_PARAMETER(NdisRequest);
    
    switch (NdisRequest->RequestType) {
        case NdisRequestSetInformation:            
            ndisStatus = AdapterSetInformation(Adapter, NdisRequest);
            break;
                
        case NdisRequestQueryInformation:
        case NdisRequestQueryStatistics:
            ndisStatus = AdapterQueryInformation(Adapter, NdisRequest);
            break;

        default:
            TraceError(("'%s': unknown OID request type 0x%08X!\n", 
                        __FUNCTION__, 
                        NdisRequest->RequestType));

            ndisStatus = NDIS_STATUS_NOT_SUPPORTED;
            break;
    };

    return ndisStatus;
}

//
// Temporarily pauses adapter.
//
NDIS_STATUS
AdapterPause (
    IN  PADAPTER                        Adapter,
    IN  PNDIS_MINIPORT_PAUSE_PARAMETERS MiniportPauseParameters
    )
{
    UNREFERENCED_PARAMETER(MiniportPauseParameters);

    TraceInfo(("====> '%s'(%s).\n", __FUNCTION__,
               Adapter->FrontendPath));

    NdisAcquireSpinLock(&Adapter->Lock);
    XM_ASSERT(!(Adapter->Flags & XENNET_ADAPTER_PAUSING));
    XM_ASSERT(!(Adapter->Flags & XENNET_ADAPTER_PAUSED));
    Adapter->Flags |= XENNET_ADAPTER_PAUSING;
    NdisReleaseSpinLock(&Adapter->Lock);

    ReceiverPause(&Adapter->Receiver);
    TransmitterPause(Adapter->Transmitter);

    NdisAcquireSpinLock(&Adapter->Lock);
    Adapter->Flags |= XENNET_ADAPTER_PAUSED;
    Adapter->Flags &= ~XENNET_ADAPTER_PAUSING;
    NdisReleaseSpinLock(&Adapter->Lock);

    TraceInfo(("<==== '%s'.\n", __FUNCTION__));
    return NDIS_STATUS_SUCCESS;
}

//
// Handles PNP and Power events. NOP.
//
VOID 
AdapterPnPEventHandler (
    IN  PADAPTER                Adapter,
    IN  PNET_DEVICE_PNP_EVENT   NetDevicePnPEvent
    )
{
    UNREFERENCED_PARAMETER(Adapter);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    switch (NetDevicePnPEvent->DevicePnPEvent) {
        case NdisDevicePnPEventQueryRemoved:
            TraceVerbose(("'%s': NdisDevicePnPEventQueryRemoved.\n", __FUNCTION__));
            break;

        case NdisDevicePnPEventRemoved:
            TraceVerbose(("%: NdisDevicePnPEventRemoved.\n", __FUNCTION__));
            break;       

        case NdisDevicePnPEventSurpriseRemoved:
            TraceVerbose(("'%s': NdisDevicePnPEventSurpriseRemoved.\n", __FUNCTION__));
            break;

        case NdisDevicePnPEventQueryStopped:
            TraceVerbose(("'%s': NdisDevicePnPEventQueryStopped.\n", __FUNCTION__));
            break;

        case NdisDevicePnPEventStopped:
            TraceVerbose(("'%s': NdisDevicePnPEventStopped.\n", __FUNCTION__));
            break;      
            
        case NdisDevicePnPEventPowerProfileChanged:
            TraceVerbose(("'%s': NdisDevicePnPEventPowerProfileChanged.\n", __FUNCTION__));
            break;      
            
        default:
            TraceError(("'%s': unknown PnP event 0x%08X!\n", __FUNCTION__, NetDevicePnPEvent->DevicePnPEvent));
            break;         
    };

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}

//
// Reports general statistics to NDIS.
//
static NDIS_STATUS 
AdapterQueryGeneralStatistics (
    IN  PADAPTER                Adapter,
    IN  PNDIS_STATISTICS_INFO   NdisStatisticsInfo
    )
{
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PRECEIVER receiver = &Adapter->Receiver;
    PTRANSMITTER transmitter = Adapter->Transmitter;

    NdisZeroMemory(NdisStatisticsInfo, sizeof(NDIS_STATISTICS_INFO));
    NdisStatisticsInfo->Header.Revision = NDIS_OBJECT_REVISION_1;
    NdisStatisticsInfo->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    NdisStatisticsInfo->Header.Size = sizeof(NDIS_STATISTICS_INFO);

    NdisStatisticsInfo->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_RCV_ERROR;
    NdisStatisticsInfo->ifInErrors = receiver->Errors;

    NdisStatisticsInfo->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_RCV_DISCARDS;
    NdisStatisticsInfo->ifInDiscards = receiver->Errors + receiver->UninterestingFrames;

    NdisStatisticsInfo->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_BYTES_RCV;
    NdisStatisticsInfo->ifHCInOctets = receiver->BroadcastOctets + 
                                        receiver->MulticastOctets + 
                                        receiver->UcastOctets;         

    NdisStatisticsInfo->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_RCV;
    NdisStatisticsInfo->ifHCInUcastOctets = receiver->UcastOctets;

    NdisStatisticsInfo->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_RCV;
    NdisStatisticsInfo->ifHCInUcastPkts = receiver->UcastPkts;

    NdisStatisticsInfo->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_RCV;
    NdisStatisticsInfo->ifHCInMulticastOctets = receiver->MulticastOctets;  

    NdisStatisticsInfo->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_RCV;
    NdisStatisticsInfo->ifHCInMulticastPkts = receiver->MulticastPkts;  

    NdisStatisticsInfo->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_RCV;
    NdisStatisticsInfo->ifHCInBroadcastOctets = receiver->BroadcastOctets;  

    NdisStatisticsInfo->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_RCV;
    NdisStatisticsInfo->ifHCInBroadcastPkts = receiver->BroadcastPkts;  

    NdisStatisticsInfo->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_XMIT_ERROR;
    NdisStatisticsInfo->ifOutErrors = transmitter->Errors;

    NdisStatisticsInfo->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_BYTES_XMIT;
    NdisStatisticsInfo->ifHCOutOctets = transmitter->MulticastOctets + 
                                            transmitter->BroadcastOctets + 
                                            transmitter->UcastOctets;        

    NdisStatisticsInfo->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_XMIT;
    NdisStatisticsInfo->ifHCOutUcastOctets = transmitter->UcastOctets;     

    NdisStatisticsInfo->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_XMIT;
    NdisStatisticsInfo->ifHCOutUcastPkts = transmitter->UcastPkts;     

    NdisStatisticsInfo->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_XMIT;    
    NdisStatisticsInfo->ifHCOutMulticastOctets = transmitter->MulticastOctets; 

    NdisStatisticsInfo->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_XMIT;    
    NdisStatisticsInfo->ifHCOutMulticastPkts = transmitter->MulticastPkts; 

    NdisStatisticsInfo->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_XMIT;
    NdisStatisticsInfo->ifHCOutBroadcastPkts = transmitter->BroadcastPkts; 

    NdisStatisticsInfo->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_XMIT;
    NdisStatisticsInfo->ifHCOutBroadcastOctets = transmitter->BroadcastOctets; 

    NdisStatisticsInfo->SupportedStatistics |= NDIS_STATISTICS_FLAGS_VALID_XMIT_DISCARDS;
    NdisStatisticsInfo->ifOutDiscards = 0;

    return ndisStatus;
}

//
// Handles OID queries.
//
static NDIS_STATUS 
AdapterQueryInformation (
    IN  PADAPTER            Adapter,
    IN  PNDIS_OID_REQUEST   NdisRequest
    )
{
    ULONG bytesAvailable = 0;
    ULONG bytesNeeded = 0;
    ULONG bytesWritten = 0;
    BOOLEAN doCopy = TRUE;
    PVOID info = NULL;
    ULONGLONG infoData;
    ULONG infoLength = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    NDIS_INTERRUPT_MODERATION_PARAMETERS intModParams;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    NDIS_OID oid;

    if (Adapter->RemovalPending) {
        TraceVerbose(("Query while pending removal, oid 0x%08x.\n", 
            NdisRequest->DATA.QUERY_INFORMATION.Oid));
        return NDIS_STATUS_NOT_ACCEPTED;
    }

    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;
    oid = NdisRequest->DATA.QUERY_INFORMATION.Oid;
    switch (oid) {
        case OID_GEN_SUPPORTED_LIST:
            info = &XennetSupportedOids[0];
            bytesAvailable = infoLength  = sizeof(XennetSupportedOids);
            break;

        case OID_GEN_HARDWARE_STATUS:
            infoData = NdisHardwareStatusReady;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_MEDIA_SUPPORTED:
        case OID_GEN_MEDIA_IN_USE:
            infoData = XENNET_MEDIA_TYPE;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_MAXIMUM_LOOKAHEAD:
            infoData = XENNET_MAX_PACKET_SIZE - XENNET_HEADER_SIZE;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_TRANSMIT_BUFFER_SPACE:
            infoData = XENNET_MAX_PACKET_SIZE * 
                            Adapter->Transmitter->TxShadowInfo.AvailableShadows;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_RECEIVE_BUFFER_SPACE:
            infoData = XENNET_MAX_PACKET_SIZE * Adapter->Receiver.Common.CurrNumRfd;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_VENDOR_DESCRIPTION:
            info = "OpenXT";
            bytesAvailable = infoLength = (ULONG)strlen(info) + 1;
            break;

        case OID_GEN_VENDOR_DRIVER_VERSION:
            infoData = ((XENNET_MAJOR_DRIVER_VERSION << 8) | XENNET_MINOR_DRIVER_VERSION) << 8;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_DRIVER_VERSION:
            infoData = (XENNET_NDIS_MAJOR_VERSION << 8) | XENNET_NDIS_MINOR_VERSION;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_MAC_OPTIONS:
            infoData = XennetMacOptions;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;
        
        case OID_GEN_STATISTICS:
            bytesAvailable = infoLength = sizeof(NDIS_STATISTICS_INFO);
            if (informationBufferLength >= sizeof(NDIS_STATISTICS_INFO)) {
                doCopy = FALSE;
                ndisStatus = AdapterQueryGeneralStatistics(Adapter, 
                                                           informationBuffer);

            } else {
                infoData = 0;
                info = &infoData;
            }

            break;

        case OID_802_3_PERMANENT_ADDRESS:
            info = Adapter->PermanentAddress;
            bytesAvailable = infoLength = ETH_LENGTH_OF_ADDRESS;
            break;

        case OID_802_3_CURRENT_ADDRESS:
            info = Adapter->CurrentAddress;
            bytesAvailable = infoLength = ETH_LENGTH_OF_ADDRESS;
            break;

        case OID_GEN_MAXIMUM_FRAME_SIZE:
            infoData = Adapter->Mtu - XENNET_HEADER_SIZE;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_MAXIMUM_TOTAL_SIZE:
            info = &Adapter->Mtu;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_TRANSMIT_BLOCK_SIZE:
        case OID_GEN_RECEIVE_BLOCK_SIZE:
            infoData = XENNET_MAX_PACKET_SIZE;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_CURRENT_LOOKAHEAD:
            infoData = Adapter->CurrentLookahead;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_VENDOR_ID:
            infoData = 0x5853;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_LINK_SPEED:
            infoData = XENNET_MEDIA_MAX_SPEED / 100;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            AdapterIndicateLinkState(Adapter);
            break;

        case OID_GEN_MEDIA_CONNECT_STATUS:            
            infoData = NdisMediaStateConnected;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            AdapterIndicateLinkState(Adapter);
            break;

        case OID_GEN_MAXIMUM_SEND_PACKETS:
            infoData = 16;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_CURRENT_PACKET_FILTER:
            info = &Adapter->CurrentPacketFilter;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_XMIT_OK:
            info = &Adapter->Transmitter->CompletedFrames;
            bytesAvailable = infoLength = sizeof(ULONGLONG);
            break;

        case OID_GEN_RCV_OK:
            info = &Adapter->Receiver.Common.Frames;
            bytesAvailable = infoLength = sizeof(ULONGLONG);
            break;

        case OID_GEN_XMIT_ERROR:
            info = &Adapter->Transmitter->Errors;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_RCV_ERROR:
            info = &Adapter->Receiver.Errors;;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_802_3_MULTICAST_LIST:
            info = &Adapter->MulticastAddresses[0];
            bytesAvailable = infoLength = 
                Adapter->MulticastAddressesCount * sizeof(ETHERNET_ADDRESS);

            break;

        case OID_GEN_RCV_NO_BUFFER:
        case OID_GEN_TRANSMIT_QUEUE_LENGTH:
            infoData = 0;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_802_3_MAXIMUM_LIST_SIZE:
            infoData = XENNET_MAX_MCAST_LIST;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_IP4_OFFLOAD_STATS:
        case OID_IP6_OFFLOAD_STATS:
        case OID_GEN_SUPPORTED_GUIDS:
            ndisStatus = NDIS_STATUS_NOT_SUPPORTED;
            break;

        case OID_GEN_RCV_CRC_ERROR:
            infoData = 0;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_802_3_RCV_ERROR_ALIGNMENT:
        case OID_802_3_XMIT_ONE_COLLISION:
        case OID_802_3_XMIT_MORE_COLLISIONS:
            infoData = 0;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_DIRECTED_BYTES_XMIT:
            info = &Adapter->Transmitter->UcastOctets;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_DIRECTED_FRAMES_XMIT:
            info = &Adapter->Transmitter->UcastPkts;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_MULTICAST_BYTES_XMIT:
            info = &Adapter->Transmitter->MulticastOctets;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_MULTICAST_FRAMES_XMIT:
            info = &Adapter->Transmitter->MulticastPkts;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_BROADCAST_BYTES_XMIT:
            info = &Adapter->Transmitter->BroadcastOctets;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_BROADCAST_FRAMES_XMIT:
            info = &Adapter->Transmitter->BroadcastPkts;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_DIRECTED_BYTES_RCV:
            info = &Adapter->Receiver.UcastOctets;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_DIRECTED_FRAMES_RCV:
            info = &Adapter->Receiver.UcastPkts;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_MULTICAST_BYTES_RCV:
            info = &Adapter->Receiver.MulticastOctets;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_MULTICAST_FRAMES_RCV:
            info = &Adapter->Receiver.MulticastPkts;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_BROADCAST_BYTES_RCV:
            info = &Adapter->Receiver.BroadcastOctets;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_BROADCAST_FRAMES_RCV:
            info = &Adapter->Receiver.BroadcastPkts;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;

        case OID_GEN_INTERRUPT_MODERATION:
            intModParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
            intModParams.Header.Revision = NDIS_INTERRUPT_MODERATION_PARAMETERS_REVISION_1;
            intModParams.Header.Size = sizeof(NDIS_INTERRUPT_MODERATION_PARAMETERS);
            intModParams.Flags = 0;
            intModParams.InterruptModeration = NdisInterruptModerationNotSupported;
            info = &intModParams;
            bytesAvailable = infoLength = sizeof(intModParams);
            break;

        default:
            TraceError(("'%s': Unsupported query information OID 0x%08X!\n", __FUNCTION__, oid));
            ndisStatus = NDIS_STATUS_NOT_SUPPORTED;
            break;
    };

    if (ndisStatus == NDIS_STATUS_SUCCESS) {
        if (infoLength <= informationBufferLength) {
            bytesNeeded = bytesAvailable;
            bytesWritten = infoLength;

        } else {
            bytesNeeded = infoLength;
            bytesWritten = informationBufferLength;
            ndisStatus = NDIS_STATUS_BUFFER_TOO_SHORT;
        }

        if (bytesWritten && doCopy) {
            NdisMoveMemory(informationBuffer, info, bytesWritten);
            if ((oid == OID_GEN_XMIT_OK) || (oid == OID_GEN_RCV_OK) &&
                bytesWritten) {

                ndisStatus = NDIS_STATUS_SUCCESS;
            }
        }
    }
    
    NdisRequest->DATA.QUERY_INFORMATION.BytesWritten = bytesWritten;
    NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded = bytesNeeded;
    return ndisStatus;
}

//
// Reads and returns netback path. Caller should free memory when done.
//
static PCHAR
AdapterReadBackendPath (
    PCHAR           XenbusPath, 
    SUSPEND_TOKEN   Token
    )
{
    ULONG length;
    PCHAR path;
    PCHAR res;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Token);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    res = NULL;
    length = (ULONG)strlen(XenbusPath);
    path = XmAllocateMemory(length + 9);
    if (!path) {
        goto exit;
    }

    memcpy(path, XenbusPath, length);
    path[length] = '/';
    memcpy(path + length + 1, "backend", 8);
    res = NULL;
    status = xenbus_read(XBT_NIL, path, &res);
    if (NT_SUCCESS(status)) {
        TraceDebug(("Found '%s' <- '%s'.\n", res, XenbusPath));
    }

exit:
    XmFreeMemory(path);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return res;    
}

//
// Reads MAC override from registry.
//
static NDIS_STATUS
AdapterReadMacFromRegistry (
    IN  NDIS_HANDLE NdisHandle, 
    IN  PUCHAR      Mac
    )
{
    NDIS_STATUS ndisStatus;
    NDIS_HANDLE configHandle;
    UINT length;
    NDIS_CONFIGURATION_OBJECT configObject;
    PVOID tmp;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    configObject.Header.Type = NDIS_OBJECT_TYPE_CONFIGURATION_OBJECT;
    configObject.Header.Revision = NDIS_CONFIGURATION_OBJECT_REVISION_1;
    configObject.Header.Size = sizeof(NDIS_CONFIGURATION_OBJECT);
    configObject.NdisHandle = NdisHandle;
    configObject.Flags = 0;
    ndisStatus = NdisOpenConfigurationEx(&configObject, &configHandle);
    if (ndisStatus == NDIS_STATUS_SUCCESS) {
        NdisReadNetworkAddress(&ndisStatus, 
                               &tmp,
                               &length, 
                               configHandle);

        if (ndisStatus == NDIS_STATUS_SUCCESS) {
            if (length == 6) {
                memcpy(Mac, tmp, length);
                TraceInfo(("MAC address override -> %02X:%02X:%02X:%02X:%02X:%02X.\n",                    
                             Mac[0],
                             Mac[1],
                             Mac[2],
                             Mac[3],
                             Mac[4],
                             Mac[5]));

                if (Mac[0] & 0x1) {
                    TraceWarning(("MAC address was set to a multicast address in the registry?\n"));
                    ndisStatus = STATUS_UNSUCCESSFUL;
                }

            } else {
                TraceWarning(("MAC address in registry was the wrong length %d!\n", length));
                ndisStatus = STATUS_UNSUCCESSFUL;
            }
        }
        
        NdisCloseConfiguration(configHandle);
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return ndisStatus;
}

static char *
ReadBackend(const char *prefix, SUSPEND_TOKEN token)
{
    NTSTATUS stat;
    char *path;
    char *res;

    UNREFERENCED_PARAMETER(token);

    path = Xmasprintf("%s/backend", prefix);

    if (!path)
        return NULL;
    stat = xenbus_read(XBT_NIL, path, &res);
    if (NT_SUCCESS(stat)) {
        TraceDebug (("backend: %s -> %s.\n", path, res));
        XmFreeMemory(path);
        return res;
    } else {
        XmFreeMemory(path);
        return NULL;
    }
}

//
// Reads adapter MAC address from XenStore.
//
static NDIS_STATUS
AdapterReadMacFromXenstore (
    IN  PCHAR   XenbusPath,
    IN  PUCHAR  Mac
    )
{
    PCHAR tmp;
    NTSTATUS status;
    PCHAR path = NULL;
    ULONG x;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    path = Xmasprintf("%s/mac", XenbusPath);
    if (!path) {
        status = NDIS_STATUS_RESOURCES;
        goto exit;
    }

    status = xenbus_read(XBT_NIL, path, &tmp);
    if (NT_SUCCESS(status)) {
        TraceDebug (("MAC address for '%s' -> '%s'.\n", XenbusPath, tmp));
        for (x = 0; x < ETH_LENGTH_OF_ADDRESS; x++) {
            Mac[x] = (UCHAR)HexCharToInt(tmp[x*3]) * 16 +
                        (UCHAR)HexCharToInt(tmp[x*3+1]);
        }

        XmFreeMemory(tmp);
    }

exit:
    XmFreeMemory(path);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return (NDIS_STATUS)status;
}

//
// Registers suspend handlers. These are used to reinitialize netfront on 
// return from VM suspend.
//
static VOID
AdapterRegisterSuspendHandlers (
    IN  PADAPTER Adapter
    )
{
    SUSPEND_TOKEN token;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    token = EvtchnAllocateSuspendToken("xennet");
    if (!is_null_SUSPEND_TOKEN(token)) {
        Adapter->EarlySuspendHandler =
            EvtchnRegisterSuspendHandler(AdapterResumeEarly, 
                                         Adapter,
                                         "RestartNetifEarly",
                                         SUSPEND_CB_EARLY);

        if (Adapter->EarlySuspendHandler == NULL) {
            TraceError(("Failed to register AdapterResumeEarly.\n"));
        }

        Adapter->LateSuspendHandler =
            EvtchnRegisterSuspendHandler(AdapterResumeLate, 
                                         Adapter,
                                         "RestartNetifLate",
                                         SUSPEND_CB_LATE);

        if (Adapter->LateSuspendHandler == NULL) {
            TraceError(("Failed to register AdapterResumeLate.\n"));
        }

        EvtchnReleaseSuspendToken(token);

    } else {
        TraceError(("Failed to allocate suspend token.\n"));
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}


NDIS_STATUS 
AdapterReset (
    IN  NDIS_HANDLE     MiniportAdapterContext,
    OUT PBOOLEAN        AddressingReset
    )
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    *AddressingReset = FALSE;

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return NDIS_STATUS_SUCCESS;
}

//
// Restarts a paused adapter.
//
NDIS_STATUS
AdapterRestart (
    IN  PADAPTER                            Adapter,
    IN  PNDIS_MINIPORT_RESTART_PARAMETERS   MiniportRestartParameters
    )
{
    UNREFERENCED_PARAMETER(MiniportRestartParameters);

    TraceInfo(("====> '%s'(%s).\n", __FUNCTION__,
               Adapter->FrontendPath));

    NdisAcquireSpinLock(&Adapter->Lock);
    XM_ASSERT(!(Adapter->Flags & XENNET_ADAPTER_PAUSING));
    if (!(Adapter->Flags & XENNET_ADAPTER_PAUSED)) {
        NdisReleaseSpinLock(&Adapter->Lock);
        goto done;
    }
    NdisReleaseSpinLock(&Adapter->Lock);

    ReceiverUnpause(&Adapter->Receiver);
    TransmitterUnpause(Adapter->Transmitter);

    NdisAcquireSpinLock(&Adapter->Lock);
    Adapter->Flags &= ~XENNET_ADAPTER_PAUSED;
    NdisReleaseSpinLock(&Adapter->Lock);

done:
    TraceInfo(("<==== '%s'.\n", __FUNCTION__));
    return NDIS_STATUS_SUCCESS;
}

static VOID
AdapterResumeEarly (
    IN  PADAPTER        Adapter,
    IN  SUSPEND_TOKEN   Token
    )
{
    ULONG i;
    PIP_ADDRESS ipAddress;

    UNREFERENCED_PARAMETER(Token);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    Adapter->RingConnected = FALSE;

    TransmitterResumeEarly(Adapter->Transmitter);
    ReceiverCommonRestartEarly(&Adapter->Receiver.Common);
    
    ipAddress = Adapter->IpAddressList.Addresses;
    if (ipAddress) {
        for (i = 0; i < XENNET_FAKE_ARP_COUNT; i++) {
            TransmitterSendFakeArp(Adapter->Transmitter,
                                   Adapter->CurrentAddress,
                                   ipAddress->Address);
        }

        TraceNotice(("Sent %d fake ARPs on resume.\n", i));
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}

static VOID
AdapterResumeLate (
    IN  PADAPTER        Adapter,
    IN  SUSPEND_TOKEN   Token
    )
{
    NDIS_STATUS ndisStatus;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    ndisStatus = AdapterInitializeBackend(Adapter, 
                                          INVALID_HANDLE_VALUE, 
                                          Token);

    if (ndisStatus == NDIS_STATUS_SUCCESS)
        ndisStatus = AdapterConnectBackend(Adapter, Token);
    if (ndisStatus == NDIS_STATUS_SUCCESS) {
        TransmitterResumeLate(Adapter->Transmitter);
        ReceiverCommonRestartLate(&Adapter->Receiver.Common);
        EvtchnNotifyRemote(Adapter->EvtchnPort);
    } else {
        TraceError(("Failed 0x%08x to initialize backend on resume.\n", ndisStatus));
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}

//
// Recycle of received net buffer lists.
//
VOID 
AdapterReturnNetBufferLists (
    IN  PADAPTER            Adapter,
    IN  PNET_BUFFER_LIST    NetBufferLists,
    IN  ULONG               ReturnFlags
    )
{
    UNREFERENCED_PARAMETER(Adapter);
    UNREFERENCED_PARAMETER(NetBufferLists);
    UNREFERENCED_PARAMETER(ReturnFlags);

    ReceiverReturnNetBufferListList(&Adapter->Receiver,
                                    NetBufferLists,
                                    ReturnFlags);

    return;
}

//
// Used to send net buffer lists.
//
VOID 
AdapterSendNetBufferLists (
    IN  PADAPTER            Adapter,
    IN  PNET_BUFFER_LIST    NetBufferList,
    IN  NDIS_PORT_NUMBER    PortNumber,
    IN  ULONG               SendFlags
    )
{
    PNET_BUFFER_LIST initialNetBufferList = NetBufferList;
    PNET_BUFFER_LIST currNetBufferList;
    NDIS_STATUS ndisStatus = NDIS_STATUS_PENDING;
    PNET_BUFFER_LIST nextNetBufferList;
    ULONG sendCompleteFlags = 0;

    nbl_log(NetBufferList, NBL_ADAPTER_SEND);
    ndisStatus = TransmitterSendNetBufferLists(Adapter->Transmitter,
                                               &NetBufferList,
                                               PortNumber,
                                               SendFlags);
    nbl_log(initialNetBufferList, NBL_ADAPTER_SEND_RES, ndisStatus);

    if (ndisStatus != NDIS_STATUS_PENDING) {
        TraceWarning(("%s: %08x -> completing immediately\n", __FUNCTION__, ndisStatus));

        for (currNetBufferList = NetBufferList;
             currNetBufferList != NULL;
             currNetBufferList = nextNetBufferList) {

            nextNetBufferList = NET_BUFFER_LIST_NEXT_NBL(currNetBufferList);
            NET_BUFFER_LIST_STATUS(currNetBufferList) = ndisStatus;
        }

        if (NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendFlags)) {
            NDIS_SET_SEND_COMPLETE_FLAG(sendCompleteFlags, 
                                        NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
        }

        NdisMSendNetBufferListsComplete(Adapter->NdisAdapterHandle,
                                        NetBufferList,
                                        sendCompleteFlags);
    }

    return;
}

//
// Sets general adapter attributes. 
//
static NDIS_STATUS
AdapterSetGeneralAttributes (
    IN  PADAPTER Adapter
    )
{
    PNDIS_MINIPORT_ADAPTER_ATTRIBUTES adapterAttributes;
    NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES generalAttributes;
    NDIS_STATUS ndisStatus;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    NdisZeroMemory(&generalAttributes, 
                   sizeof(NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES));

    generalAttributes.Header.Type = 
                    NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES;

    generalAttributes.Header.Revision = 
                    NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_1;

    generalAttributes.Header.Size = 
                    sizeof(NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES);

    generalAttributes.MediaType = XENNET_MEDIA_TYPE;
    generalAttributes.MtuSize = XENNET_DEF_MTU - XENNET_HEADER_SIZE;
    generalAttributes.MaxXmitLinkSpeed = XENNET_MEDIA_MAX_SPEED;
    generalAttributes.MaxRcvLinkSpeed = XENNET_MEDIA_MAX_SPEED;
    generalAttributes.XmitLinkSpeed = XENNET_MEDIA_MAX_SPEED;
    generalAttributes.RcvLinkSpeed = XENNET_MEDIA_MAX_SPEED;
    generalAttributes.MediaConnectState = MediaConnectStateConnected;
    generalAttributes.MediaDuplexState = MediaDuplexStateFull;
    generalAttributes.LookaheadSize = XENNET_MAX_PACKET_SIZE - XENNET_HEADER_SIZE;
    generalAttributes.PowerManagementCapabilities = NULL;
    generalAttributes.MacOptions = XennetMacOptions;

    generalAttributes.SupportedPacketFilters = NDIS_PACKET_TYPE_DIRECTED |
                                               NDIS_PACKET_TYPE_MULTICAST |
                                               NDIS_PACKET_TYPE_ALL_MULTICAST |
                                               NDIS_PACKET_TYPE_BROADCAST;
        
    generalAttributes.MaxMulticastListSize = XENNET_MAX_MCAST_LIST;
    generalAttributes.MacAddressLength = ETH_LENGTH_OF_ADDRESS;
    NdisMoveMemory(generalAttributes.PermanentMacAddress,
                   Adapter->PermanentAddress,
                   ETH_LENGTH_OF_ADDRESS);

    NdisMoveMemory(generalAttributes.CurrentMacAddress,
                   Adapter->CurrentAddress,
                   ETH_LENGTH_OF_ADDRESS);
        
    generalAttributes.PhysicalMediumType = NdisPhysicalMedium802_3;
    generalAttributes.RecvScaleCapabilities = NULL;
    generalAttributes.AccessType = NET_IF_ACCESS_BROADCAST;
    generalAttributes.DirectionType = NET_IF_DIRECTION_SENDRECEIVE;
    generalAttributes.ConnectionType = NET_IF_CONNECTION_DEDICATED;
    generalAttributes.IfType = IF_TYPE_ETHERNET_CSMACD; 
    generalAttributes.IfConnectorPresent = TRUE;

    generalAttributes.SupportedStatistics = NDIS_STATISTICS_XMIT_OK_SUPPORTED |
                                            NDIS_STATISTICS_XMIT_ERROR_SUPPORTED |
                                            NDIS_STATISTICS_DIRECTED_BYTES_XMIT_SUPPORTED |
                                            NDIS_STATISTICS_DIRECTED_FRAMES_XMIT_SUPPORTED |
                                            NDIS_STATISTICS_MULTICAST_BYTES_XMIT_SUPPORTED |
                                            NDIS_STATISTICS_MULTICAST_FRAMES_XMIT_SUPPORTED |
                                            NDIS_STATISTICS_BROADCAST_BYTES_XMIT_SUPPORTED |
                                            NDIS_STATISTICS_BROADCAST_FRAMES_XMIT_SUPPORTED |
                                            NDIS_STATISTICS_RCV_OK_SUPPORTED |
                                            NDIS_STATISTICS_RCV_ERROR_SUPPORTED |
                                            NDIS_STATISTICS_DIRECTED_BYTES_RCV_SUPPORTED |
                                            NDIS_STATISTICS_DIRECTED_FRAMES_RCV_SUPPORTED |
                                            NDIS_STATISTICS_MULTICAST_BYTES_RCV_SUPPORTED |
                                            NDIS_STATISTICS_MULTICAST_FRAMES_RCV_SUPPORTED |
                                            NDIS_STATISTICS_BROADCAST_BYTES_RCV_SUPPORTED |
                                            NDIS_STATISTICS_BROADCAST_FRAMES_RCV_SUPPORTED |
                                            NDIS_STATISTICS_GEN_STATISTICS_SUPPORTED;
                      
    generalAttributes.SupportedOidList = XennetSupportedOids;
    generalAttributes.SupportedOidListLength = sizeof(XennetSupportedOids);
    adapterAttributes = 
                (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&generalAttributes;

    ndisStatus = NdisMSetMiniportAttributes(Adapter->NdisAdapterHandle,
                                            adapterAttributes);

    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        TraceError(("Failed (0x%08X) to set adapter registration attributes!\n", 
                      ndisStatus));
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return ndisStatus;
}

static NDIS_STATUS
AdapterSetOffloadAttributes(
    IN  PADAPTER Adapter
    )
{
    PNDIS_MINIPORT_ADAPTER_ATTRIBUTES adapterAttributes;
    NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES offloadAttributes;
    NDIS_OFFLOAD offload;
    NDIS_STATUS ndisStatus;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (XenPVFeatureEnabled(DEBUG_HCT_MODE)) {
        TraceNotice(("Task offload disabled for HCT mode.\n"));
        return NDIS_STATUS_SUCCESS;
    }

    NdisZeroMemory(&offloadAttributes, sizeof(offloadAttributes));
    NdisZeroMemory(&offload, sizeof(offload));

    offload.Header.Type = NDIS_OBJECT_TYPE_OFFLOAD;
    offload.Header.Revision = NDIS_OFFLOAD_REVISION_1;
    offload.Header.Size = sizeof(offload);

    offload.Checksum.IPv4Receive.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;

    if (XenPVFeatureEnabled(DEBUG_NIC_FAST_AND_LOOSE)) {
        offload.Checksum.IPv4Receive.IpChecksum = 0;
        offload.Checksum.IPv4Receive.IpOptionsSupported = 0;

        offload.Checksum.IPv4Receive.TcpChecksum = (Adapter->Properties.tcp_csum & 2) ? 1 : 0;
        offload.Checksum.IPv4Receive.TcpOptionsSupported = offload.Checksum.IPv4Receive.TcpChecksum;

        offload.Checksum.IPv4Receive.UdpChecksum = (Adapter->Properties.udp_csum & 2) ? 1 : 0;
    }

    TraceVerbose (("RX TCP csum offload %s.\n",
                   (offload.Checksum.IPv4Receive.TcpChecksum) ? "available" : "not available"));
    TraceVerbose (("RX UDP csum offload %s.\n",
                   (offload.Checksum.IPv4Receive.UdpChecksum) ? "available" : "not available"));

    offload.Checksum.IPv4Transmit.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;

    offload.Checksum.IPv4Transmit.IpChecksum = (Adapter->Properties.ip_csum & 1) ? 1 : 0;
    offload.Checksum.IPv4Transmit.IpOptionsSupported = offload.Checksum.IPv4Transmit.IpChecksum;

    if (Adapter->Transmitter->ChecksumOffloadSafe) {
        offload.Checksum.IPv4Transmit.TcpChecksum = (Adapter->Properties.tcp_csum & 1) ? 1 : 0;
        offload.Checksum.IPv4Transmit.TcpOptionsSupported = offload.Checksum.IPv4Transmit.TcpChecksum;

        offload.Checksum.IPv4Transmit.UdpChecksum = (Adapter->Properties.udp_csum & 1) ? 1 : 0;
    }

    TraceVerbose (("TX IP csum offload %s.\n",
                   (offload.Checksum.IPv4Transmit.IpChecksum) ? "available" : "not available"));
    TraceVerbose (("TX TCP csum offload %s.\n",
                   (offload.Checksum.IPv4Transmit.TcpChecksum) ? "available" : "not available"));
    TraceVerbose (("TX UDP csum offload %s.\n",
                   (offload.Checksum.IPv4Transmit.UdpChecksum) ? "available" : "not available"));

    offload.LsoV1.IPv4.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;

    if (Adapter->Transmitter->LsoAvailable && Adapter->Properties.lso) {
        TraceVerbose(("TSO available.\n"));

        offload.LsoV1.IPv4.MaxOffLoadSize = XENNET_MAX_USER_DATA_PER_PACKET;
        offload.LsoV1.IPv4.MinSegmentCount = 2;
        offload.LsoV1.IPv4.TcpOptions = NDIS_OFFLOAD_SUPPORTED;
        offload.LsoV1.IPv4.IpOptions = NDIS_OFFLOAD_SUPPORTED;
    } else {
        TraceVerbose(("TSO not available.\n"));
    }

    offloadAttributes.Header.Type =
        NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES;
    offloadAttributes.Header.Revision =
        NDIS_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES_REVISION_1;
    offloadAttributes.Header.Size = sizeof(offloadAttributes);
    offloadAttributes.DefaultOffloadConfiguration = &offload;
    offloadAttributes.HardwareOffloadCapabilities = &offload;

    adapterAttributes =
        (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&offloadAttributes;
    ndisStatus = NdisMSetMiniportAttributes(Adapter->NdisAdapterHandle,
                                            adapterAttributes);
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        TraceError(("Failed (0x%08X) to set adapter offload attributes!\n",
                    ndisStatus));
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return ndisStatus;
}

static void
AdapterIndicateOffloadChanged (
    IN  PADAPTER Adapter
    )
{
    NDIS_STATUS_INDICATION indication;
    NDIS_OFFLOAD offload;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    NdisZeroMemory(&offload, sizeof(offload));
    INITIALIZE_NDIS_OBJ_HEADER(offload, OFFLOAD);

    offload.Checksum.IPv4Receive.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;

    if (Adapter->Receiver.UdpChecksumOffload)
        offload.Checksum.IPv4Receive.UdpChecksum = 1;
    if (Adapter->Receiver.TcpChecksumOffload) {
        offload.Checksum.IPv4Receive.TcpChecksum = 1;
        offload.Checksum.IPv4Receive.TcpOptionsSupported = 1;
    }

    TraceVerbose (("RX TCP csum offload %s.\n",
                   (offload.Checksum.IPv4Receive.TcpChecksum) ? "enabled" : "disabled"));
    TraceVerbose (("RX UDP csum offload %s.\n",
                   (offload.Checksum.IPv4Receive.UdpChecksum) ? "enabled" : "disabled"));

    offload.Checksum.IPv4Transmit.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;

    if (Adapter->Transmitter->UdpChecksumOffload)
        offload.Checksum.IPv4Transmit.UdpChecksum = 1;
    if (Adapter->Transmitter->TcpChecksumOffload) {
        offload.Checksum.IPv4Transmit.TcpChecksum = 1;
        offload.Checksum.IPv4Transmit.TcpOptionsSupported = 1;
    }
    if (Adapter->Transmitter->IpChecksumOffload) {
        offload.Checksum.IPv4Transmit.IpChecksum = 1;
        offload.Checksum.IPv4Transmit.IpOptionsSupported = 1;
    }

    TraceVerbose (("TX IP csum offload %s.\n",
                   (offload.Checksum.IPv4Transmit.IpChecksum) ? "enabled" : "disabled"));
    TraceVerbose (("TX TCP csum offload %s.\n",
                   (offload.Checksum.IPv4Transmit.TcpChecksum) ? "enabled" : "disabled"));
    TraceVerbose (("TX UDP csum offload %s.\n",
                   (offload.Checksum.IPv4Transmit.UdpChecksum) ? "enabled" : "disabled"));

    offload.LsoV1.IPv4.Encapsulation = NDIS_ENCAPSULATION_IEEE_802_3;

    if (Adapter->Transmitter->LargeSendOffload) {
        TraceVerbose(("TSO enabled.\n"));

        offload.LsoV1.IPv4.MaxOffLoadSize = XENNET_MAX_USER_DATA_PER_PACKET;
        offload.LsoV1.IPv4.MinSegmentCount = 2;
        offload.LsoV1.IPv4.TcpOptions = NDIS_OFFLOAD_SUPPORTED;
        offload.LsoV1.IPv4.IpOptions = NDIS_OFFLOAD_SUPPORTED;
    } else {
        TraceVerbose(("TSO disabled.\n"));
    }

    NdisZeroMemory(&indication, sizeof(indication));
    INITIALIZE_NDIS_OBJ_HEADER(indication, STATUS_INDICATION);
    indication.SourceHandle = Adapter->NdisAdapterHandle;
    indication.StatusCode = NDIS_STATUS_TASK_OFFLOAD_CURRENT_CONFIG;
    indication.StatusBuffer = &offload;
    indication.StatusBufferSize = sizeof(offload);

    NdisMIndicateStatusEx(Adapter->NdisAdapterHandle, &indication);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
}

//
// Set OID handler.
//
static NDIS_STATUS 
AdapterSetInformation (
    IN  PADAPTER            Adapter,
    IN  PNDIS_OID_REQUEST   NdisRequest
    )
{
    ULONG addressCount;
    ULONG bytesNeeded = 0;
    ULONG bytesRead = 0;
    PVOID informationBuffer;
    ULONG informationBufferLength;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    NDIS_OID oid;
    PNDIS_OFFLOAD_ENCAPSULATION offloadEncapsulation;
    PNDIS_OFFLOAD_PARAMETERS offloadParameters;
    BOOLEAN offloadChanged;
    BOOLEAN rxBackendEnabled;

    if (Adapter->RemovalPending) {
        TraceVerbose(("Set while pending removal, oid 0x%08x.\n",
            NdisRequest->DATA.QUERY_INFORMATION.Oid));
        return NDIS_STATUS_NOT_ACCEPTED;
    }

    informationBuffer = NdisRequest->DATA.SET_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.SET_INFORMATION.InformationBufferLength;
    oid = NdisRequest->DATA.QUERY_INFORMATION.Oid;
    switch (oid) {
        case OID_GEN_MACHINE_NAME:
            ndisStatus = NDIS_STATUS_NOT_SUPPORTED;
            break;

        case OID_GEN_CURRENT_LOOKAHEAD:
            bytesNeeded = sizeof(ULONG);
            Adapter->CurrentLookahead = 0;
            if (informationBufferLength == sizeof(ULONG)) {
                Adapter->CurrentLookahead = *(PULONG)informationBuffer;
                TraceVerbose(("Setting current lookahead 0x%08x.\n",
                              Adapter->CurrentLookahead));

                bytesRead = sizeof(ULONG);
            }

            break;

        case OID_GEN_CURRENT_PACKET_FILTER:
            bytesNeeded = sizeof(ULONG);
            if (informationBufferLength == sizeof(ULONG)) {
                Adapter->CurrentPacketFilter = *(PULONG)informationBuffer;
                bytesRead = sizeof(ULONG);
            }

            break;

        case OID_802_3_MULTICAST_LIST:
            bytesNeeded = ETH_LENGTH_OF_ADDRESS;
            addressCount = informationBufferLength / ETH_LENGTH_OF_ADDRESS;
            if ((informationBufferLength % ETH_LENGTH_OF_ADDRESS == 0) && 
                (informationBufferLength >= bytesNeeded) &&
                (addressCount <= XENNET_MAX_MCAST_LIST)) {

                bytesRead = informationBufferLength;
                Adapter->MulticastAddressesCount = addressCount;
                NdisMoveMemory(&Adapter->MulticastAddresses[0],
                               informationBuffer,
                               informationBufferLength);

            } else {
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
            }

            break;

        case OID_GEN_NETWORK_LAYER_ADDRESSES:
            bytesNeeded = sizeof(NETWORK_ADDRESS_LIST);
            if (informationBufferLength >= bytesNeeded) {
                bytesRead = informationBufferLength;
                ndisStatus = 
                    AdapterSetNetworkLayerAddresses(Adapter, 
                                                    informationBuffer, 
                                                    informationBufferLength);

            } else {
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
            }

            break;

        case OID_GEN_INTERRUPT_MODERATION:
            ndisStatus = NDIS_STATUS_INVALID_DATA;
            break;

        case OID_OFFLOAD_ENCAPSULATION:
            if (XenPVFeatureEnabled(DEBUG_HCT_MODE)) {
                ndisStatus = NDIS_STATUS_NOT_SUPPORTED;
                break;
            }

            bytesNeeded = sizeof(*offloadEncapsulation);
            if (informationBufferLength >= bytesNeeded) {
                bytesRead = bytesNeeded;
                offloadEncapsulation = informationBuffer;
                if ((offloadEncapsulation->IPv4.Enabled == NDIS_OFFLOAD_SET_ON &&
                     (offloadEncapsulation->IPv4.EncapsulationType != NDIS_ENCAPSULATION_IEEE_802_3 ||
                      offloadEncapsulation->IPv4.HeaderSize != sizeof(struct ethhdr))) ||
                    offloadEncapsulation->IPv6.Enabled == NDIS_OFFLOAD_SET_ON) {
                    ndisStatus = NDIS_STATUS_INVALID_PARAMETER;
                } else {
                    ndisStatus = NDIS_STATUS_SUCCESS;
                    if (XenPVFeatureEnabled(DEBUG_NIC_FAST_AND_LOOSE)) {
                        Adapter->Receiver.TcpChecksumOffload = (BOOLEAN)(Adapter->Properties.tcp_csum & 2);
                        Adapter->Receiver.UdpChecksumOffload = (BOOLEAN)(Adapter->Properties.tcp_csum & 2);

                        if (Adapter->Receiver.TcpChecksumOffload ||
                            Adapter->Receiver.UdpChecksumOffload)
                            AdapterEnableRxCsumOffload(Adapter);
                    }

                    Adapter->Transmitter->IpChecksumOffload = (BOOLEAN)(Adapter->Properties.ip_csum & 1);

                    if (Adapter->Transmitter->ChecksumOffloadSafe) {
                        Adapter->Transmitter->TcpChecksumOffload = (BOOLEAN)(Adapter->Properties.tcp_csum & 1);
                        Adapter->Transmitter->UdpChecksumOffload = (BOOLEAN)(Adapter->Properties.udp_csum & 1);
                    }

                    Adapter->Transmitter->LargeSendOffload = (BOOLEAN)(Adapter->Transmitter->LsoAvailable &&
                                                                       Adapter->Properties.lso);

                    AdapterIndicateOffloadChanged(Adapter);
                }
            }
            break;

        case OID_TCP_OFFLOAD_PARAMETERS:
            if (XenPVFeatureEnabled(DEBUG_HCT_MODE)) {
                ndisStatus = NDIS_STATUS_NOT_SUPPORTED;
                break;
            }

            bytesNeeded = sizeof(*offloadParameters);
            if (informationBufferLength >= bytesNeeded) {
                bytesRead = bytesNeeded;
                offloadParameters = informationBuffer;
                ndisStatus = NDIS_STATUS_SUCCESS;
                /* We don't do csum offload for every protocol. */
#define unsupported(x)                                         \
                if (offloadParameters-> x !=                   \
                    NDIS_OFFLOAD_PARAMETERS_NO_CHANGE &&       \
                    offloadParameters-> x !=                   \
                    NDIS_OFFLOAD_PARAMETERS_TX_RX_DISABLED)    \
                    ndisStatus = NDIS_STATUS_INVALID_PARAMETER
                unsupported(TCPIPv6Checksum);
                unsupported(UDPIPv6Checksum);
#undef unsupported
                /* Various other features which aren't supported. */
#define unsupported(x)                                          \
                if (offloadParameters-> x !=                    \
                    NDIS_OFFLOAD_PARAMETERS_NO_CHANGE)          \
                    ndisStatus = NDIS_STATUS_INVALID_PARAMETER
                unsupported(IPsecV1);
                unsupported(LsoV2IPv4);
                unsupported(LsoV2IPv6);
                unsupported(TcpConnectionIPv4);
                unsupported(TcpConnectionIPv6);
#undef unsupported

                /* Can't do LSO without backend support. */
                if (offloadParameters->LsoV1 == NDIS_OFFLOAD_PARAMETERS_LSOV1_ENABLED &&
                    (!(Adapter->Transmitter->LsoAvailable) ||
                     !(Adapter->Properties.lso)))
                    ndisStatus = NDIS_STATUS_INVALID_PARAMETER;

#define rx_enabled(x) ((x) == NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED ||       \
                       (x) == NDIS_OFFLOAD_PARAMETERS_RX_ENABLED_TX_DISABLED)
#define tx_enabled(x) ((x) == NDIS_OFFLOAD_PARAMETERS_TX_RX_ENABLED ||       \
                       (x) == NDIS_OFFLOAD_PARAMETERS_TX_ENABLED_RX_DISABLED)
#define rx_proto(p) rx_enabled(offloadParameters-> p ## IPv4Checksum )
#define tx_proto(p) tx_enabled(offloadParameters-> p ## IPv4Checksum )

                /* Don't let Windows turn on TX csum offload if the
                   backend can't handle it or it is disabled. */
                if (tx_enabled(offloadParameters->IPv4Checksum) &&
                    !(Adapter->Properties.ip_csum & 1)) {
                    ndisStatus = NDIS_STATUS_INVALID_PARAMETER;
                }

                if (tx_proto(TCP) &&
                    (!(Adapter->Properties.tcp_csum & 1) ||
                     !(Adapter->Transmitter->ChecksumOffloadSafe))) {
                    ndisStatus = NDIS_STATUS_INVALID_PARAMETER;
                }

                if (tx_proto(UDP) &&
                    (!(Adapter->Properties.udp_csum & 1) ||
                     !(Adapter->Transmitter->ChecksumOffloadSafe))) {
                    ndisStatus = NDIS_STATUS_INVALID_PARAMETER;
                }

                if (rx_enabled(offloadParameters->IPv4Checksum)) {
                    ndisStatus = NDIS_STATUS_INVALID_PARAMETER;
                }

                if (rx_proto(TCP) &&
                    (!(Adapter->Properties.tcp_csum & 2) ||
                     !XenPVFeatureEnabled(DEBUG_NIC_FAST_AND_LOOSE))) {
                    ndisStatus = NDIS_STATUS_INVALID_PARAMETER;
                }

                if (rx_proto(UDP) &&
                    (!(Adapter->Properties.udp_csum & 2) ||
                     !XenPVFeatureEnabled(DEBUG_NIC_FAST_AND_LOOSE))) {
                    ndisStatus = NDIS_STATUS_INVALID_PARAMETER;
                }

                if (ndisStatus != NDIS_STATUS_SUCCESS)
                    TraceWarning(("NDIS tried to enable an unsupported offload!\n"));

                if (ndisStatus == NDIS_STATUS_SUCCESS) {
                    /* Figure out if we need to enable or disable RX
                       csum offload at the backend, and do so if
                       necessary. */
                    rxBackendEnabled =
                        Adapter->Receiver.TcpChecksumOffload ||
                        Adapter->Receiver.UdpChecksumOffload;
                    if ( (rx_proto(TCP) || rx_proto(UDP)) &&
                         !rxBackendEnabled ) {
                        AdapterEnableRxCsumOffload(Adapter);
                    } else if ( !(rx_proto(TCP) || rx_proto(UDP)) &&
                                rxBackendEnabled ) {
                        AdapterDisableRxCsumOffload(Adapter);
                    }

                    /* Set the various flags in the receiver and
                       transmitter structures, and figure out whether
                       we need to indicate a change. */
                    offloadChanged = FALSE;
#define update(a, b)                                                         \
                    do {                                                     \
                        BOOLEAN __tmp = (b);                                 \
                        if ( (a) != __tmp )                                  \
                            offloadChanged = TRUE;                           \
                        (a) = __tmp;                                         \
                    } while (0)

                    if (offloadParameters->UDPIPv4Checksum !=
                        NDIS_OFFLOAD_PARAMETERS_NO_CHANGE) {
                        update(Adapter->Transmitter->UdpChecksumOffload,
                               tx_proto(UDP));
                        update(Adapter->Receiver.UdpChecksumOffload,
                               rx_proto(UDP));
                    }
                    if (offloadParameters->TCPIPv4Checksum !=
                        NDIS_OFFLOAD_PARAMETERS_NO_CHANGE) {
                        update(Adapter->Transmitter->TcpChecksumOffload,
                               tx_proto(TCP));
                        update(Adapter->Receiver.UdpChecksumOffload,
                               rx_proto(TCP));
                    }
                    if (offloadParameters->IPv4Checksum !=
                        NDIS_OFFLOAD_PARAMETERS_NO_CHANGE) {
                        update(Adapter->Transmitter->IpChecksumOffload,
                               tx_enabled(offloadParameters->IPv4Checksum));
                    }
#undef update

                    if (offloadParameters->LsoV1 ==
                        NDIS_OFFLOAD_PARAMETERS_LSOV1_ENABLED) {
                        if (!Adapter->Transmitter->LargeSendOffload)
                            offloadChanged = TRUE;
                        Adapter->Transmitter->LargeSendOffload = TRUE;
                    } else if (offloadParameters->LsoV1 ==
                               NDIS_OFFLOAD_PARAMETERS_LSOV1_DISABLED) {
                        if (Adapter->Transmitter->LargeSendOffload)
                            offloadChanged = TRUE;
                        Adapter->Transmitter->LargeSendOffload = FALSE;
                    }

                    if (Adapter->Transmitter->LargeSendOffload &&
                        (!Adapter->Transmitter->IpChecksumOffload ||
                         !Adapter->Transmitter->TcpChecksumOffload)) {
                        TraceWarning(("LSO enabled without csum offload? (%d, %d, %d)\n",
                                      Adapter->Transmitter->LargeSendOffload,
                                      Adapter->Transmitter->IpChecksumOffload,
                                      Adapter->Transmitter->TcpChecksumOffload));
                    }

                    if (offloadChanged)
                        AdapterIndicateOffloadChanged(Adapter);
                }
#undef tx_proto
#undef rx_proto
#undef tx_enabled
#undef rx_enabled
            }
            break;

        default:
            TraceError(("'%s': unsupported set information OID 0x%08X!\n", 
                            __FUNCTION__, 
                            oid));

            ndisStatus = NDIS_STATUS_NOT_SUPPORTED;
            break;
    };

    NdisRequest->DATA.SET_INFORMATION.BytesNeeded = bytesNeeded;
    if (ndisStatus == NDIS_STATUS_SUCCESS) {
        NdisRequest->DATA.SET_INFORMATION.BytesRead = bytesRead;
    }

    return ndisStatus;
}

//
// Handles OID_GEN_NETWORK_LAYER_ADDRESSES.
// 
static NDIS_STATUS
AdapterSetNetworkLayerAddresses (
    IN  PADAPTER                Adapter,
    IN  PNETWORK_ADDRESS_LIST   NetworkAddressList,
    IN  ULONG                   NetworkAddressListSize
    )
{
    ULONG count;
    ULONG i;
    PIP_ADDRESS ip;
    ULONG j;
    PNETWORK_ADDRESS na;
    PUCHAR networkAddressListEnd = (PUCHAR)NetworkAddressList + NetworkAddressListSize;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (NetworkAddressList->AddressCount) {
        na = NetworkAddressList->Address;
        count = 0;
        for (i = 0; i < (ULONG)NetworkAddressList->AddressCount; i++) {
            if ((PUCHAR)na->Address > networkAddressListEnd) {
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
                goto exit;
            }

            if (((PUCHAR)na->Address + na->AddressLength) > 
                            networkAddressListEnd) {

                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
                goto exit;
            }

            if ((na->AddressType == NDIS_PROTOCOL_ID_TCP_IP) &&
                (na->AddressLength == 16)) {

                count++;
            }
            
            na = (PNETWORK_ADDRESS)((ULONG_PTR)&na->Address[0] + 
                                                    na->AddressLength);
        }

        if (count) {
            ip = XmAllocateMemory(sizeof(NETWORK_ADDRESS) * count);
            if (!ip) {
                ndisStatus = NDIS_STATUS_RESOURCES;
                goto exit;
            }

            na = NetworkAddressList->Address;
            for (i = 0, j = 0; i < (ULONG)NetworkAddressList->AddressCount; i++) {
                if ((na->AddressType == NDIS_PROTOCOL_ID_TCP_IP) &&
                    (na->AddressLength == 16)) {

                    memcpy(&ip[j],
                           na->Address + 4,
                           4);
                    j++;
                }
                
                na = (PNETWORK_ADDRESS)((ULONG_PTR)&na->Address[0] + 
                                                        na->AddressLength);
            }

            XM_ASSERT3U(j, ==, count);

            AdapterCleanupIpAddressList(Adapter);
            NdisAcquireSpinLock(&Adapter->IpAddressList.Lock);
            Adapter->IpAddressList.Addresses = ip;
            Adapter->IpAddressList.Count = count;
            NdisReleaseSpinLock(&Adapter->IpAddressList.Lock);
        }

    } else {
        if (NetworkAddressList->AddressType == NDIS_PROTOCOL_ID_TCP_IP) {
            AdapterCleanupIpAddressList(Adapter);
        }
    }

exit:
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return ndisStatus;
}

//
// Sets miniport registration attributes.
//
static NDIS_STATUS
AdapterSetRegistrationAttributes (
    IN  PADAPTER Adapter
    )
{
    PNDIS_MINIPORT_ADAPTER_ATTRIBUTES adapterAttributes;
    NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES registrationAttributes;
    NDIS_STATUS ndisStatus;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    NdisZeroMemory(&registrationAttributes, 
                   sizeof(NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES));

    registrationAttributes.Header.Type = 
                NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES;

    registrationAttributes.Header.Revision = 
                NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;

    registrationAttributes.Header.Size = 
                sizeof(NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES);

    registrationAttributes.MiniportAdapterContext = (NDIS_HANDLE)Adapter;
    registrationAttributes.AttributeFlags = 
                NDIS_MINIPORT_ATTRIBUTES_SURPRISE_REMOVE_OK | 
                NDIS_MINIPORT_ATTRIBUTES_BUS_MASTER;
    
    registrationAttributes.CheckForHangTimeInSeconds = 0;
    registrationAttributes.InterfaceType = XENNET_INTERFACE_TYPE;

    adapterAttributes = 
                (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&registrationAttributes;

    ndisStatus = NdisMSetMiniportAttributes(Adapter->NdisAdapterHandle,
                                            adapterAttributes);

    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        TraceError(("Failed (0x%08X) to set adapter registration attributes!\n", 
                      ndisStatus));
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return ndisStatus;
}

//
// Shuts down adapter.
//
VOID 
AdapterShutdown (
    IN  PADAPTER                Adapter,
    IN  NDIS_SHUTDOWN_ACTION    ShutdownAction
    )
{
    UNREFERENCED_PARAMETER(ShutdownAction);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (ShutdownAction != NdisShutdownBugCheck)
        AdapterStop(Adapter);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}

//
// Stops adapter. Waits for currently transmitted packets to complete.
// Stops transmission of new packets.
// Stops received packet indication to NDIS.
//
static NDIS_STATUS
AdapterStop (
IN  PADAPTER    Adapter
)
{
    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (Adapter->Flags & XENNET_ADAPTER_STOPPED) {
        goto exit;
    }

    /* During a normal (non-surprise PnP) shutdown the cleanup happens here. */
    if (!Adapter->RemovalPending)
        MpInitialShutdown(Adapter, FALSE);

    //
    // Wait until stack returns buffers we've passed up.
    //
    ReceiverWaitForPacketReturn(&Adapter->Receiver, FALSE);

    NdisAcquireSpinLock(&Adapter->Lock);
    Adapter->Flags |= XENNET_ADAPTER_STOPPED;
    Adapter->Flags &= ~XENNET_ADAPTER_STOPPING;
    NdisReleaseSpinLock(&Adapter->Lock);

exit:
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return NDIS_STATUS_SUCCESS;
}
