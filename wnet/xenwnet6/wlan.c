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

#include "common.h"
#include "transmitter.h"
#include "wlan.h"
#include "v4vkapi.h"
#include "wlan_defs.h"
#include <stdlib.h>     // for atoi() and atol()

#ifdef DBG

/*
    Functions to dump data blobs in a formatted
    print statement.
*/

static VOID
Dump (PVOID *ptr, int len)
{
    int i, j, offs;
    UCHAR *buf = (UCHAR *)ptr;
    char line[128];

    for (i=0; i < len; i+= 16)
    {
        RtlStringCbPrintf (line, sizeof(line), "%04x: ", i);
        offs = (int)strlen(line);
        for (j=0; (j < 16) && (i + j < len); j++)
        {
            RtlStringCbPrintf (&line[offs], sizeof(line)-offs, "%02x ", buf[i+j]);
            offs += 3;
            if (j == 7)
            {
                RtlStringCbPrintf (&line[offs], sizeof(line)-offs, "- ");
                offs += 2;
            }
        }
        TraceNotice (("%s\n", line));
    }
}

static VOID
DumpNbl (PNET_BUFFER_LIST NetBufferList)
{
    PNET_BUFFER netBuffer;
    ULONG bufLength;
    static UCHAR ptr[256];

    netBuffer = NET_BUFFER_LIST_FIRST_NB(NetBufferList);

    while (netBuffer != NULL) 
    {
        bufLength = min(sizeof(ptr), NET_BUFFER_DATA_LENGTH(netBuffer));
        GetNetBufferData (netBuffer, 0, ptr, bufLength);

        Dump ((PVOID)ptr, bufLength);

        netBuffer = NET_BUFFER_NEXT_NB(netBuffer);
    }
}
#else
#define Dump(p, l) 
#define DumpNbl(Nbl)
#endif

int bitCount(unsigned long n)
{
  // This is for 32 bit numbers.  Need to adjust for 64 bits
  unsigned int tmp;

  tmp = n - ((n >> 1) & 033333333333) - ((n >> 2) & 011111111111);

  return ((tmp + (tmp >> 3)) & 030707070707) % 63;
}

void
WlanPrintKey(
    IN  PCHAR               Operation,
    IN  PVOID               Buffer
    )
{
    /* scratch big enough for a 104 bit key, in ascii, plus null */
    CHAR    scratch[((104/8)*2)+1];
    PDOT11_CIPHER_DEFAULT_KEY_VALUE keyValue = 
        (PDOT11_CIPHER_DEFAULT_KEY_VALUE)Buffer;
    ULONG i;
    ULONG len;
    PCHAR c = scratch;
    UCHAR n;

    /* We're not called unless the buffer is big enough to contain
     * the key.  But, validate that the key will fit in our scratch
     * space.
     */

    len = keyValue->usKeyLength;
    if (len*2 >= sizeof(scratch))
        len = (sizeof(scratch)*2)-1;

    for (i = 0; i < len; i++) {
        CHAR b = keyValue->ucKey[i];
        n = (b >> 4) & 0xf;
        *c++ = n < 10 ? n + '0' : n - 10 + 'a';
        n = b & 0xf;
        *c++ = n < 10 ? n + '0' : n - 10 + 'a';
    }
    *c = 0;

    TraceNotice(("%s: key %s\n", Operation, scratch));
}

static VOID
WlanCopyScannedBss (
    PADAPTER Adapter,
    PXEN_BSS_ENTRY dest,
    PXEN_BSS_ENTRY src
    )
{
    if (dest->WpaInformationElement)
        NdisFreeMemory (dest->WpaInformationElement, dest->WpaInfoElementLen, 0);

    NdisMoveMemory (dest, src, sizeof(XEN_BSS_ENTRY));

    dest->WpaInformationElement = NdisAllocateMemoryWithTagPriority (
        Adapter->NdisAdapterHandle,
        src->WpaInfoElementLen, 'apwX', NormalPoolPriority);
    if (dest->WpaInformationElement == NULL)
    {
        TraceError (("Failed to allocate IE memory for copied BSS\n"));
        dest->WpaInfoElementLen = 0;
    }
    else
    {
        NdisMoveMemory (dest->WpaInformationElement, src->WpaInformationElement, src->WpaInfoElementLen);
        dest->WpaInfoElementLen = src->WpaInfoElementLen;
    }
}

static VOID
WlanClearBss (
    PXEN_BSS_ENTRY src
    )
{
    if (src->WpaInformationElement)
        NdisFreeMemory (src->WpaInformationElement, src->WpaInfoElementLen, 0);
    NdisZeroMemory (src, sizeof(XEN_BSS_ENTRY));
}

static BOOLEAN
WlanFindBss (
    PADAPTER Adapter
    )
{
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    int i;
    for (i=0; i < WLAN_BSSID_MAX_COUNT; i++)
    {
        PVOID p1, p2;
        SIZE_T len;
        if (pwa->DesiredBss.SSID.uSSIDLength)
        {
            p1 = &pwa->ScannedBss[i].SSID.ucSSID;
            p2 = &pwa->DesiredBss.SSID.ucSSID;
            len = pwa->DesiredBss.SSID.uSSIDLength;
        }
        else
        {
            p1 = &pwa->ScannedBss[i].Entry.dot11BSSID[0];
            p2 = &pwa->DesiredBss.Entry.dot11BSSID[0];
            len = sizeof(DOT11_MAC_ADDRESS);
        }
        if (RtlCompareMemory(p1, p2, len) == len)
        {
            WlanCopyScannedBss (Adapter, &pwa->DesiredBss, &pwa->ScannedBss[i]);
            return TRUE;
        }
    }
    return FALSE;
}

#if DBG
PSTR
WlanGetStatusTypeString(
    ULONG StatusType
    )
{
    PSTR pszString = NULL;
    
    switch (StatusType)
    {
        case NDIS_STATUS_DOT11_SCAN_CONFIRM:
            pszString = "Scan Confirm";
            break;
        case NDIS_STATUS_DOT11_MPDU_MAX_LENGTH_CHANGED:
            pszString = "MPDU max length changed";
            break;
        case NDIS_STATUS_DOT11_ASSOCIATION_START:
            pszString = "Association start";
            break;
        case NDIS_STATUS_DOT11_ASSOCIATION_COMPLETION:
            pszString = "Association complete";
            break;
        case NDIS_STATUS_DOT11_CONNECTION_START:
            pszString = "Connection start";
            break;
        case NDIS_STATUS_DOT11_CONNECTION_COMPLETION:
            pszString = "Connection complete";
            break;
        case NDIS_STATUS_DOT11_ROAMING_START:
            pszString = "Roaming start";
            break;
        case NDIS_STATUS_DOT11_ROAMING_COMPLETION:
            pszString = "Roaming complete";
            break;
        case NDIS_STATUS_DOT11_DISASSOCIATION:
            pszString = "Disassociation";
            break;
        case NDIS_STATUS_DOT11_TKIPMIC_FAILURE:
            pszString = "TKIP MIC failure";
            break;
        case NDIS_STATUS_DOT11_PMKID_CANDIDATE_LIST:
            pszString = "PMKID candidate list";
            break;
        case NDIS_STATUS_DOT11_PHY_STATE_CHANGED:
            pszString = "Phy state changed";
            break;
        case NDIS_STATUS_DOT11_LINK_QUALITY:
            pszString = "Link quality";
            break;
#if 0
        case NDIS_STATUS_DOT11_INCOMING_ASSOC_STARTED:
            pszString = "Incoming association started";
            break;
        case NDIS_STATUS_DOT11_INCOMING_ASSOC_REQUEST_RECEIVED:
            pszString = "Incoming association request received";
            break;
        case NDIS_STATUS_DOT11_INCOMING_ASSOC_COMPLETION:
            pszString = "Incoming association completed";
            break;
        case NDIS_STATUS_DOT11_STOP_AP:
            pszString = "Stop AP";
            break;
        case NDIS_STATUS_DOT11_PHY_FREQUENCY_ADOPTED:
            pszString = "Phy frequency adopted";
            break;
#endif
        default:
            pszString = "Unknown";
            break;
    };

    return pszString;
}
#endif

static VOID
WlanIndicateStatus(
    IN  PADAPTER        Adapter,
    IN  NDIS_STATUS     StatusCode,
    IN  PVOID           RequestID,
    IN  PVOID           StatusBuffer,
    IN  ULONG           StatusBufferSize
    )
{
    NDIS_STATUS_INDICATION statusIndication;
    
    NdisZeroMemory(&statusIndication, sizeof(NDIS_STATUS_INDICATION));
    
    statusIndication.Header.Type = NDIS_OBJECT_TYPE_STATUS_INDICATION;
    statusIndication.Header.Revision = NDIS_STATUS_INDICATION_REVISION_1;
    statusIndication.Header.Size = sizeof(NDIS_STATUS_INDICATION);

    statusIndication.StatusCode = StatusCode;
    statusIndication.SourceHandle = Adapter->NdisAdapterHandle;
    statusIndication.DestinationHandle = NULL;
    statusIndication.RequestId = RequestID;
    
    statusIndication.StatusBuffer = StatusBuffer;
    statusIndication.StatusBufferSize = StatusBufferSize;

#if DBG
    TraceNotice (("Indicating status: %s (0x%08x)\n", WlanGetStatusTypeString(StatusCode), StatusCode));
#endif
    NdisMIndicateStatusEx(Adapter->NdisAdapterHandle, &statusIndication);
}

static VOID
WlanAdapterDefaults (
    IN  PWLAN_ADAPTER WlanAdapter
    )
{
    /* Set the default MIB values at start time and when a reset occurs */
    WlanAdapter->RTSThreshold = WLAN_MAX_MPDU_LENGTH + 1;
    WlanAdapter->FragThreshold = WLAN_MAX_MPDU_LENGTH;
    WlanAdapter->UDThreshold = 2000;
    WlanAdapter->BSSType = dot11_BSS_type_infrastructure;
    WlanAdapter->MediaStreaming = FALSE;
    WlanAdapter->AutoConfig = (DOT11_PHY_AUTO_CONFIG_ENABLED_FLAG|DOT11_MAC_AUTO_CONFIG_ENABLED_FLAG);
    WlanAdapter->FrameCounter = 0;
    WlanAdapter->CurrentChannel = 0x6;  //something interesting...
    WlanAdapter->PMKIDCount = 0;

    /* Rate setup */
    SetSupportedDataRates(WlanAdapter, 11000);

    /* Registration domain setup */
    NdisZeroMemory(&WlanAdapter->RegDomains, sizeof(DOT11_REG_DOMAINS_SUPPORT_VALUE));
    WlanAdapter->RegDomains.uNumOfEntries = 1;
    WlanAdapter->RegDomains.uTotalNumOfEntries  = 1;
    WlanAdapter->RegDomains.dot11RegDomainValue[0].uRegDomainsSupportValue = DOT11_REG_DOMAIN_OTHER;

    /* Setup desired phy list */
    WlanAdapter->DesiredPhyCount = 1;
    WlanAdapter->DesiredPhyList[0] = DOT11_PHY_ID_ANY;

    /* Setup very basic auth cipher pair */
    WlanAdapter->AuthAlgorithm = DOT11_AUTH_ALGO_80211_OPEN;
    WlanAdapter->UnicastCipherAlgorithm = DOT11_CIPHER_ALGO_NONE;
    WlanAdapter->MulticastCipherAlgorithm = DOT11_CIPHER_ALGO_NONE;

    /* Statistics setup */
    NdisZeroMemory(&WlanAdapter->Stats, sizeof(DOT11_STATISTICS));
    WLAN_ASSIGN_NDIS_OBJECT_HEADER(WlanAdapter->Stats.Header, 
                                   NDIS_OBJECT_TYPE_DEFAULT,
                                   DOT11_STATISTICS_REVISION_1,
                                   sizeof(DOT11_STATISTICS));
}

#ifdef USE_V4V
NTSTATUS
WlanV4vConnect(
    IN PADAPTER Adapter
    )
{
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    NTSTATUS status;
    int pass;

    //
    // Bring up the V4V connection
    //
    pwa->V4vConfig = XmAllocateZeroedMemory(sizeof(V4V_CONFIG));
    if (pwa->V4vConfig == NULL)
    {
        return NDIS_STATUS_RESOURCES;
    }
    pwa->V4vConfig->V4v = XmAllocateZeroedMemory(sizeof(XEN_V4V));
    if (pwa->V4vConfig->V4v == NULL)
    {
        XmFreeMemory(pwa->V4vConfig);
        return NDIS_STATUS_RESOURCES;
    }
    pwa->V4vConfig->rxBuf = XmAllocateZeroedMemory(V4V_RX_BUF_SIZE + sizeof(V4V_DATAGRAM));
    if (pwa->V4vConfig->rxBuf == NULL)
    {
        XmFreeMemory(pwa->V4vConfig->V4v);
        XmFreeMemory(pwa->V4vConfig);
        return NDIS_STATUS_RESOURCES;
    }
    pwa->V4vConfig->txBuf = XmAllocateZeroedMemory(V4V_TX_BUF_SIZE + sizeof(V4V_DATAGRAM));
    if (pwa->V4vConfig->txBuf == NULL)
    {
        XmFreeMemory(pwa->V4vConfig->rxBuf);
        XmFreeMemory(pwa->V4vConfig->V4v);
        XmFreeMemory(pwa->V4vConfig);
        return NDIS_STATUS_RESOURCES;
    }
    pwa->V4vConfig->controlEvent = 
        XenV4VCreateKEvent (&pwa->V4vConfig->controlEventHandle);

    pass = 0;
    do
    {
        status = XenV4VOpenDgramPort (
            pwa->V4vConfig->V4v, V4V_RX_BUF_SIZE + V4V_TX_BUF_SIZE,
            (domid_t)(unwrap_DOMAIN_ID(Adapter->BackendDomid)), XENWNET_V4V_RING_PORT);
        if (!NT_SUCCESS(status))
        {
            TraceWarning (("[V4VDG]: Call to XenV4VOpenDgramPort() failed (0x%08X)\n", status));
            NdisMSleep (1000000);   // 1 seconds
            TraceNotice (("[V4VDG]: Retrying XenV4VOpenDgramPort()...\n"));
        }
    }
    while (!NT_SUCCESS(status) && pass++ < 5);

    if (!NT_SUCCESS(status))
    {
        TraceError (("[V4VDG]: Failed to open V4V datagram port\n"));

        //
        // We are only using V4V for EAP traffic, so don't declare the
        // link "dead" anymore...it can still be used.
        //
//@@@        pwa->RadioOn = FALSE;

        ZwClose (pwa->V4vConfig->controlEventHandle);
        pwa->V4vConfig->controlEventHandle = NULL;
        XmFreeMemory(pwa->V4vConfig->txBuf);
        pwa->V4vConfig->txBuf = NULL;
        XmFreeMemory(pwa->V4vConfig->rxBuf);
        pwa->V4vConfig->rxBuf = NULL;
        XmFreeMemory(pwa->V4vConfig->V4v);
        pwa->V4vConfig->V4v = NULL;
        XmFreeMemory(pwa->V4vConfig);
        pwa->V4vConfig = NULL;
        return NDIS_STATUS_FAILURE;
    }
    //
    // The two events are created in the signalled state.
    // So call KeWaitForSingleObject() to clear them.
    //
    KeWaitForSingleObject (pwa->V4vConfig->controlEvent, Executive, KernelMode, TRUE, NULL);
    KeWaitForSingleObject (pwa->V4vConfig->V4v->ctx.recvEvent, Executive, KernelMode, TRUE, NULL);
    KeInitializeEvent (&pwa->V4vShutdownComplete, NotificationEvent, FALSE);

    TraceNotice (("[V4VDG]: Opened V4V datagram port\n"));
    pwa->V4vConfig->ringSize = V4V_RX_BUF_SIZE + V4V_TX_BUF_SIZE;
    pwa->V4vConfig->rxSize = V4V_RX_BUF_SIZE;
    pwa->V4vConfig->txSize = V4V_TX_BUF_SIZE;
    Adapter->Receiver.V4vRxBufMdl =
        IoAllocateMdl (
            &pwa->V4vConfig->rxBuf[sizeof(V4V_DATAGRAM)],
            pwa->V4vConfig->rxSize - sizeof(V4V_DATAGRAM),
            FALSE, FALSE, NULL);
    MmBuildMdlForNonPagedPool(Adapter->Receiver.V4vRxBufMdl);
    Adapter->Transmitter->V4vTxBufMdl =
        IoAllocateMdl (
            &pwa->V4vConfig->txBuf[sizeof(V4V_DATAGRAM)],
            pwa->V4vConfig->txSize - sizeof(V4V_DATAGRAM),
            FALSE, FALSE, NULL);
    MmBuildMdlForNonPagedPool(Adapter->Transmitter->V4vTxBufMdl);

    return STATUS_SUCCESS;
}

NTSTATUS
WlanV4vSendNetBuffer (
     IN PADAPTER Adapter,
     PNET_BUFFER netBuffer
     )
{
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    NTSTATUS status;
    V4V_CONFIG *cfg;
    V4V_DATAGRAM *dg;
    PUCHAR buf;
    PUCHAR src;
    ULONG bufLength;
    PMDL mdl;
    IO_STATUS_BLOCK iosb;
    ULONG bytes_copied;
    ULONG bytes_to_copy;

    if (!NT_SUCCESS(pwa->V4vStartupStatus))
    {
        TraceWarning (("Attempting to send EAP packet while V4V not connected\n"));
        return NDIS_STATUS_FAILURE;
    }
    //
    // Get pointers to V4V config, V4V DG header and payload buffer
    //
    cfg = (V4V_CONFIG *)pwa->V4vConfig;
    dg = (V4V_DATAGRAM *)cfg->txBuf;
    buf = cfg->txBuf + sizeof(V4V_DATAGRAM);
    //
    // Get the byte count of the payload
    //
    bufLength = min((V4V_TX_BUF_SIZE - sizeof(V4V_DATAGRAM)), NET_BUFFER_DATA_LENGTH(netBuffer));

    //
    // Move data from net buffer to the V4V transmit buffer
    //
    bytes_copied = 0;
    bytes_to_copy = 0;
    mdl = NET_BUFFER_CURRENT_MDL(netBuffer);
    while ((mdl) && (bytes_copied < bufLength) && (bytes_copied < V4V_TX_BUF_SIZE))
    {
        bytes_to_copy = mdl->ByteCount;
        src = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
        NdisMoveMemory (&buf[bytes_copied], src, bytes_to_copy);
        mdl = mdl->Next;
        bytes_copied += bytes_to_copy;
    }
    //
    // Set up the V4V destination info
    //
    dg->addr.domain = (domid_t)(unwrap_DOMAIN_ID(Adapter->BackendDomid));
    dg->addr.port = XENWNET_V4V_RING_PORT;

    //
    // Send the data via V4V
    //
    //TraceNotice (("V4VDG-X Sending %d byte packet to %d::%d\n", bufLength, dg->addr.domain, dg->addr.port));
    //Dump ((PVOID)buf, bufLength);
    status = XenV4VWrite(cfg->V4v, (void*)dg, (ULONG)bufLength + sizeof(V4V_DATAGRAM), &iosb);
    if (!NT_SUCCESS(status))
    {
        TraceWarning (("V4VDG-X Data sent (status = 0x%08x, iosb.Information = %d)\n", status, iosb.Information));
    }

    return status;
}

static VOID
WlanV4vWorkItem (
    IN PVOID            Context
    )
{
    PADAPTER Adapter = (PADAPTER)Context;
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    V4V_CONFIG *cfg;
    HANDLE harr[2];
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;

//    Adapter->Flags |= XENNET_ADAPTER_STOPPED;
    pwa->V4vStartupStatus = WlanV4vConnect(Adapter);
    if (!NT_SUCCESS(pwa->V4vStartupStatus))
    {
        PsTerminateSystemThread(pwa->V4vStartupStatus);
        pwa->V4vThread = NULL;
        return;
    }
//    Adapter->Flags &= ~XENNET_ADAPTER_STOPPED;

    cfg = (V4V_CONFIG*)pwa->V4vConfig;

    TraceNotice (("V4VDG START asynchronous datagram receiver...\n"));

    harr[0] = cfg->V4v->ctx.recvEvent;
    harr[1] = cfg->controlEvent;

    do {
        //TraceVerbose (("V4VDG Waiting for event...\n"));
        Adapter->Receiver.V4vBytesReceived = 0;
        status = KeWaitForMultipleObjects(
            2, harr, WaitAny, Executive,
            KernelMode, FALSE, NULL, NULL);
        if (status == STATUS_WAIT_0)
        {
            //TraceVerbose (("V4VDG data arrival event signaled\n"));
            //
            // Issue a blocking read to wait for data
            //
            status = XenV4VRead(cfg->V4v, cfg->rxBuf, cfg->rxSize, &iosb);
            if (!NT_SUCCESS(status))
            {
                TraceError (("V4VDG XenV4VRead() failed: 0x%08x\n", status));
            }
            else
            {
                iosb.Information -= sizeof(V4V_DATAGRAM);
                //TraceNotice (("V4VDG packet received (0x%x bytes):\n", (int)iosb.Information));
                //Dump ((PVOID)&cfg->rxBuf[sizeof(V4V_DATAGRAM)], (int)(iosb.Information));
                Adapter->Receiver.V4vBytesReceived = (int)(iosb.Information);
                ReceiverHandleV4vPacket (&Adapter->Receiver);
            }
        }
        else if (status == STATUS_WAIT_0 + 1)
        {
            TraceNotice (("V4VDG shutdown signaled, exiting\n"));
            break;
        }
        else
        {
            TraceError (("V4VDG critical failure - unexpected wait status (0x%08x); exiting\n", status));
            break;
        }
    } while (TRUE);

    TraceInfo (("V4VDG freeing resources\n"));
    if (pwa->V4vConfig->controlEventHandle) ZwClose (pwa->V4vConfig->controlEventHandle);
    pwa->V4vConfig->controlEventHandle = NULL;
    if (pwa->V4vConfig->txBuf) XmFreeMemory(pwa->V4vConfig->txBuf);
    pwa->V4vConfig->txBuf = NULL;
    if (pwa->V4vConfig->rxBuf) XmFreeMemory(pwa->V4vConfig->rxBuf);
    pwa->V4vConfig->rxBuf = NULL;
    if (pwa->V4vConfig->V4v) XenV4VClose (pwa->V4vConfig->V4v);
    pwa->V4vConfig->V4v = NULL;
    if (pwa->V4vConfig) XmFreeMemory(pwa->V4vConfig);
    pwa->V4vConfig = NULL;
    IoFreeMdl (Adapter->Receiver.V4vRxBufMdl);
    IoFreeMdl (Adapter->Transmitter->V4vTxBufMdl);

    KeSetEvent (&pwa->V4vShutdownComplete, IO_NO_INCREMENT, FALSE);

    TraceNotice (("V4VDG asynchronous datagram receiver exit\n"));
    PsTerminateSystemThread(STATUS_SUCCESS);
}
#endif

NDIS_STATUS 
WlanAdapterInitialize (
    IN  PADAPTER            Adapter
    )
{
    PWLAN_ADAPTER pwa = NULL;
    //NDIS_STATUS ndisStatus;

    pwa = XmAllocateZeroedMemory(sizeof(WLAN_ADAPTER));
    if (pwa == NULL) {
        return NDIS_STATUS_RESOURCES;
    }
    Adapter->WlanAdapter = pwa;

    TraceNotice(("WLAN adapter '%p' for adapter '%p'.\n", pwa, Adapter));

    NdisZeroMemory(pwa, sizeof(WLAN_ADAPTER));
    NdisAllocateSpinLock(&pwa->Lock);

    pwa->WorkItem = NdisAllocateIoWorkItem(Adapter->NdisAdapterHandle);
    if (pwa->WorkItem == NULL) {
        TraceError(("Failed to allocate scan work item.\n"));
        NdisFreeSpinLock(&pwa->Lock);
        return NDIS_STATUS_RESOURCES;
    }

    /* Set the default values */
    WlanAdapterDefaults(pwa);

    /* Basic WLAN values */    
    pwa->RadioOn = TRUE; /* say it is on when we start */
    pwa->PhyEnabled = TRUE;
    pwa->HiddenNetworks = FALSE;
    pwa->PowerLevel = DOT11_POWER_SAVING_NO_POWER_SAVING;
    pwa->PrivacyExemptionList = NULL;
    pwa->CurrentChannel = 0x6;

    /* Setup single PHY */
    pwa->SupportedPhyTypes.uNumOfEntries = 1;
    pwa->SupportedPhyTypes.uTotalNumOfEntries = 1;
    pwa->SupportedPhyTypes.dot11PHYType[0] = dot11_phy_type_erp;
    pwa->CurrentPhyId = 0;

    /* Setup data rate values, have to support a minimum of one */
    NdisZeroMemory(&pwa->SupportedDataRatesValue, sizeof(DOT11_SUPPORTED_DATA_RATES_VALUE_V2));
    pwa->SupportedDataRatesValue.ucSupportedTxDataRatesValue[0] = 2;
    pwa->SupportedDataRatesValue.ucSupportedRxDataRatesValue[0] = 2;    

    /* Setup the operations mode caps */
    pwa->OperationModeCapability.uReserved = 0;
    pwa->OperationModeCapability.uMajorVersion = 2;
    pwa->OperationModeCapability.uMinorVersion = 0;
    pwa->OperationModeCapability.uNumOfTXBuffers = 0;
    pwa->OperationModeCapability.uNumOfRXBuffers = 64;
    pwa->OperationModeCapability.uOpModeCapability = DOT11_OPERATION_MODE_EXTENSIBLE_STATION | DOT11_OPERATION_MODE_NETWORK_MONITOR;

#ifdef USE_V4V
    //
    // V4V stuff
    //
    pwa->V4vThread = NULL;
    PsCreateSystemThread (&pwa->V4vThread, THREAD_ALL_ACCESS, NULL,
                            INVALID_HANDLE_VALUE, NULL,
                            WlanV4vWorkItem, Adapter);
    //
#endif

    /* Setup the main 802.11 attributes */
    return WlanSet80211Attributes(Adapter);
}

VOID 
WlanAdapterDelete (
    IN  PADAPTER            Adapter
    )
{
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    int i;

    /* Can be called before WLAN parts are initialized if miniport 
       initialization fails */
    if (pwa == NULL) {
        return;
    }

#ifdef USE_V4V
    //
    // V4V stuff
    //
    TraceNotice (("[V4VDG]: Telling V4VDG work item to exit...\n"));
    if (NT_SUCCESS(pwa->V4vStartupStatus))
    {
        KeSetEvent(pwa->V4vConfig->controlEvent, IO_NO_INCREMENT, TRUE);
        KeWaitForSingleObject (&pwa->V4vShutdownComplete, Executive, KernelMode, TRUE, NULL);
    }
    if (pwa->V4vThread) ZwClose (pwa->V4vThread); pwa->V4vThread = NULL;
    TraceNotice (("[V4VDG]: V4VDG work item has cleaned up and exited\n"));
    //
#endif

    do {
        NdisAcquireSpinLock(&(pwa->Lock));
        pwa->State |= WLAN_STATE_DELETING;
        if ((pwa->State & WLAN_STATE_SCANNING) == 0) {
            /* Done, no pending work items */
            NdisReleaseSpinLock(&(pwa->Lock));
            break;
        }
        NdisReleaseSpinLock(&(pwa->Lock));

        /* Wait a tiny bit for the last work item to run and finish */
        NdisMSleep(250000);
    } while (TRUE);
    
    if (pwa->PrivacyExemptionList != NULL) {
        NdisFreeMemory(pwa->PrivacyExemptionList, 0, 0);
    }

    WlanClearBss (&pwa->AssociatedBss);
    WlanClearBss (&pwa->DesiredBss);
    for (i=0; i < WLAN_BSSID_MAX_COUNT; i++)
        WlanClearBss (&pwa->ScannedBss[i]);

    if (pwa->WorkItem != NULL) {
        NdisFreeIoWorkItem(pwa->WorkItem);
    }

    //@@@NdisReleaseSpinLock(&pwa->Lock);
    NdisFreeSpinLock(&pwa->Lock);
    XmFreeMemory(Adapter->WlanAdapter);
    Adapter->WlanAdapter = NULL;
}

VOID
WlanIndicateRssi(
    IN PADAPTER Adapter
    )
{
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    char *tmp;
    char path[32];
    NTSTATUS status;
    UCHAR buffer[sizeof(DOT11_LINK_QUALITY_PARAMETERS) + sizeof(DOT11_LINK_QUALITY_ENTRY)];
    ULONG bufferLength = sizeof(buffer);
    PDOT11_LINK_QUALITY_PARAMETERS pLinkQualityParams;
    PDOT11_LINK_QUALITY_ENTRY pEntry;

    if (!(pwa->State & WLAN_STATE_CONNECTED))
        return;

    pLinkQualityParams = (DOT11_LINK_QUALITY_PARAMETERS*)&buffer[0];
    pEntry = (DOT11_LINK_QUALITY_ENTRY*)&buffer[sizeof(DOT11_LINK_QUALITY_PARAMETERS)];

    if (pwa->State & WLAN_STATE_CONNECTED)
        Xmsnprintf (path, sizeof(path), "wlan/%d/quality", pwa->AssociatedBss.XenStoreEntry);
    else
        Xmsnprintf (path, sizeof(path), "wlan/0/quality");

    //
    // Initialize indication buffer
    //
    NdisZeroMemory(&buffer[0], bufferLength);

    MP_ASSIGN_NDIS_OBJECT_HEADER(pLinkQualityParams->Header, 
                                 NDIS_OBJECT_TYPE_DEFAULT,
                                 DOT11_LINK_QUALITY_PARAMETERS_REVISION_1,
                                 sizeof(DOT11_LINK_QUALITY_PARAMETERS));

    pLinkQualityParams->uLinkQualityListSize = 1;
    pLinkQualityParams->uLinkQualityListOffset = sizeof(DOT11_LINK_QUALITY_PARAMETERS);

    //
    // Previous NdisZeroMemory already set pEntry->PeerMacAddr to all 0x00, which
    // means the link quality is for current network
    //

//    TraceDebug (("WLAN signal strength changed\n"));
    status = xenbus_read(XBT_NIL, path, &tmp);
    if (NT_SUCCESS(status))
    {
        pEntry->ucLinkQuality = (UCHAR)atoi(tmp);
//        TraceDebug (("Reading RSSI from : '%s' = %d\n", path, pEntry->ucLinkQuality));
        XmFreeMemory(tmp);
    }
    else
    {
        TraceNotice (("Failure reading RSSI from : %s\n", path));
        //
        // Assume 50% since we really don't know, but dom0 is connected to something.
        //
        pEntry->ucLinkQuality = 50;
    }

    if (pwa->State & WLAN_STATE_CONNECTED)
        NdisMoveMemory(&pEntry->PeerMacAddr[0], &pwa->AssociatedBss.Entry.dot11BSSID[0], sizeof(DOT11_MAC_ADDRESS));
    // Otherwise, leave as all 0's

    pwa->AssociatedBss.Entry.uLinkQuality = pEntry->ucLinkQuality;

    WlanIndicateStatus (
        Adapter,
        NDIS_STATUS_DOT11_LINK_QUALITY,
        NULL,
        &buffer[0],
        bufferLength); 
}

VOID
WlanIndicatePhyPowerState(
    IN PADAPTER Adapter
    )
{
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    DOT11_PHY_STATE_PARAMETERS phyStateParams;

    NdisZeroMemory(&phyStateParams, sizeof(DOT11_PHY_STATE_PARAMETERS));

    //
    // Fill in object headers
    //
    phyStateParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    phyStateParams.Header.Revision = DOT11_PHY_STATE_PARAMETERS_REVISION_1;
    phyStateParams.Header.Size = sizeof(DOT11_PHY_STATE_PARAMETERS);

    //
    // Phy state buffer
    //
    phyStateParams.uPhyId = pwa->CurrentPhyId;
    phyStateParams.bHardwarePhyState = pwa->PhyEnabled;
    phyStateParams.bSoftwarePhyState = pwa->RadioOn;
   
    WlanIndicateStatus (
        Adapter,
        NDIS_STATUS_DOT11_PHY_STATE_CHANGED,
        NULL,
        &phyStateParams,
        sizeof(DOT11_PHY_STATE_PARAMETERS)); 
}

BOOLEAN
WlanMediaStateChangedCb (
    IN  PADAPTER            Adapter
    )
{
    char *tmp;
    char *path;
    BOOLEAN disconnected;
    NTSTATUS status;
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    DOT11_ASSOC_STATUS DiscReason = DOT11_DISASSOC_REASON_OS;
    xenbus_transaction_t xbt;

    NdisAcquireSpinLock(&pwa->Lock);

    disconnected = FALSE;
    //
    // If the "disconnect" node does not exist,
    // assume we do not have a valid connection.
    //
    xenbus_transaction_start(&xbt);
    path = Xmasprintf("%s/backend", Adapter->FrontendPath);
    if (!path)
    {
        TraceError (("Failure allocating memory to read backend node %s/backend\n", Adapter->FrontendPath));
        DiscReason = DOT11_DISASSOC_REASON_PHY_DISABLED;
        pwa->PhyEnabled = FALSE;
        disconnected = TRUE; // See comment below
    }
    else
    {
        status = xenbus_read(xbt, path, &tmp);
        if (!NT_SUCCESS(status))
        {
            TraceDebug (("%s node missing; assuming media disconnected\n", path));
            DiscReason = DOT11_DISASSOC_REASON_PHY_DISABLED;
            pwa->PhyEnabled = FALSE;
            disconnected = TRUE;
        }
        else
        {
            XmFreeMemory(tmp);
        }
        XmFreeMemory(path);
    }

    //
    // Disconnected == TRUE means that we failed to read from the "backend" node above.
    // FALSE means we read it successfully.
    //
    if (!disconnected)
    {
        ULONG64 xs_disc;
        status = xenbus_read_int(xbt,
                                 Adapter->FrontendPath,
                                 "disconnect",
                                 &xs_disc);

        if (!NT_SUCCESS(status))
        {
            disconnected = TRUE;
            DiscReason = DOT11_DISASSOC_REASON_PHY_DISABLED;
            pwa->PhyEnabled = FALSE;
        }
        else
        {
            //
            // We got a value from xenstore...therefore, use it. If it's 0, we
            // are not disconnected...anything else and we are.
            //
            if (xs_disc == 0)
                disconnected = FALSE;
            else
            {
                disconnected = TRUE;
                if (xs_disc == 1)
                    DiscReason = DOT11_DISASSOC_REASON_PEER_UNREACHABLE;
                if (xs_disc == 2)
                    DiscReason = DOT11_DISASSOC_REASON_OS;
                if (xs_disc == 3)
                {
                    DiscReason = DOT11_DISASSOC_REASON_PHY_DISABLED;
                    pwa->PhyEnabled = FALSE;
                }
                if (xs_disc == 4)
                {
                    DiscReason = DOT11_DISASSOC_REASON_RADIO_OFF;
                    pwa->RadioOn = FALSE;
                }
            }
        }
    }
    xenbus_transaction_end (xbt, 0);

    if ((!disconnected) && (Adapter->MediaConnected != TRUE)) //((pwa->State & WLAN_STATE_CONNECTED) == 0))
    {
        TraceNotice(("WLAN available!\n"));
        NdisAcquireSpinLock(&Adapter->Receiver.Common.Lock);
        NdisAcquireSpinLock(&Adapter->Transmitter->Lock);
        
        pwa->PhyEnabled = TRUE;
        pwa->RadioOn = TRUE;
        Adapter->MediaConnected = TRUE;
        WlanIndicatePhyPowerState(Adapter);

        NdisReleaseSpinLock(&Adapter->Transmitter->Lock);
        NdisReleaseSpinLock(&Adapter->Receiver.Common.Lock);
        NdisReleaseSpinLock(&pwa->Lock);

        return TRUE;
    }

    if ((disconnected) && (Adapter->MediaConnected != FALSE)) //(pwa->State & WLAN_STATE_CONNECTED))
    {
        TraceNotice(("WLAN unavailable!\n"));

        NdisAcquireSpinLock(&Adapter->Receiver.Common.Lock);
        NdisAcquireSpinLock(&Adapter->Transmitter->Lock);

        Adapter->MediaConnected = FALSE;
        WlanIndicatePhyPowerState(Adapter);

        NdisReleaseSpinLock(&Adapter->Transmitter->Lock);
        NdisReleaseSpinLock(&Adapter->Receiver.Common.Lock);

        WlanDisconnectRequest(Adapter, DiscReason);
        NdisReleaseSpinLock(&pwa->Lock);

        return TRUE;
    }

    NdisReleaseSpinLock(&pwa->Lock);

    return FALSE;
}

VOID
WlanPause (
    IN  PADAPTER            Adapter
    )
{
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;

    /* NOTE outer MP pause routine should drop all sends - it doesn't */

    NdisAcquireSpinLock(&(pwa->Lock));
    pwa->State |= WLAN_STATE_PAUSED;
    NdisReleaseSpinLock(&(pwa->Lock));

    DisableXenWatchpoints (Adapter);
}

VOID
WlanRestart (
    IN  PADAPTER            Adapter
    )
{
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;

    NdisAcquireSpinLock(&(pwa->Lock));
    pwa->State &= ~WLAN_STATE_PAUSED;
    NdisReleaseSpinLock(&(pwa->Lock));

    EnableXenWatchpoints (Adapter);
}

static NDIS_STATUS
WlanValidateScanRequest (
    PDOT11_SCAN_REQUEST_V2 ScanRequest
    )
{
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_PHY_TYPE_INFO phyTypeInfo;
    ULONG i, bytesParsed = 0;
    PDOT11_SSID ssid;
    
    do {
        if (ScanRequest->uNumOfdot11SSIDs == 0) {
            TraceError(("No SSID found in the scan data\n"));
            ndisStatus = NDIS_STATUS_INVALID_DATA;
            break;
        }
        
        for (i = 0; i < ScanRequest->uNumOfdot11SSIDs; i++) {
            ssid = (PDOT11_SSID) (ScanRequest->ucBuffer + ScanRequest->udot11SSIDsOffset + bytesParsed);
            if (ssid->uSSIDLength > DOT11_SSID_MAX_LENGTH) {
                TraceError(("The SSID length provided (%d) is greater than max SSID length (%d)\n",
                    ssid->uSSIDLength, DOT11_SSID_MAX_LENGTH));
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
                break;
            }
            bytesParsed += sizeof(DOT11_SSID);
        }
        
        if ((ScanRequest->dot11BSSType != dot11_BSS_type_infrastructure)&&
            (ScanRequest->dot11BSSType != dot11_BSS_type_independent)&&
            (ScanRequest->dot11BSSType != dot11_BSS_type_any)) {
            TraceError(("BSS Type %d not supported\n", ScanRequest->dot11BSSType));
            ndisStatus = NDIS_STATUS_NOT_SUPPORTED;
            break;
        }

        switch (ScanRequest->dot11ScanType) {
            case dot11_scan_type_active:
            case dot11_scan_type_active | dot11_scan_type_forced:
            case dot11_scan_type_passive:
            case dot11_scan_type_passive | dot11_scan_type_forced:
            case dot11_scan_type_auto:
            case dot11_scan_type_auto | dot11_scan_type_forced:
                break;

            default:
                TraceError(("Dot11 scan type %d not supported\n", ScanRequest->dot11ScanType));
                ndisStatus = NDIS_STATUS_NOT_SUPPORTED;
                break;
        }

        bytesParsed = 0;
        
        for (i = 0; i < ScanRequest->uNumOfPhyTypeInfos; i++) {
            phyTypeInfo = (PDOT11_PHY_TYPE_INFO) 
                (ScanRequest->ucBuffer + ScanRequest->uPhyTypeInfosOffset + bytesParsed);

            // ExtSTA mode, the OS does not control PHY specific parameters
            XM_ASSERT(phyTypeInfo->bUseParameters == FALSE);
            bytesParsed += (FIELD_OFFSET(DOT11_PHY_TYPE_INFO, ucChannelListBuffer) + phyTypeInfo->uChannelListSize);
        }
    } while (FALSE);

    return ndisStatus;
}

static VOID
WlanScanWorkItem (
    IN PVOID            Context,
    IN NDIS_HANDLE      NdisIoWorkItemHandle
    )
{
    PADAPTER pa = Context;
    PWLAN_ADAPTER pwa = pa->WlanAdapter;
    PVOID requestId;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(NdisIoWorkItemHandle);

    NdisAcquireSpinLock(&(pwa->Lock));

    pwa->State &= ~WLAN_STATE_SCANNING;
    requestId = pwa->ScanRequestId;
    pwa->ScanRequestId = NULL;

    if ((pwa->State & (WLAN_STATE_PAUSED|WLAN_STATE_DELETING|WLAN_STATE_STOPSCAN)) != 0) {
        pwa->State &= ~WLAN_STATE_STOPSCAN;
        /* Bail out right here, forget the scan */        
        NdisReleaseSpinLock(&(pwa->Lock));
        return;
    }
    
    /* Send the scan complete status */
    WlanIndicateStatus(pa, NDIS_STATUS_DOT11_SCAN_CONFIRM, requestId, &ndisStatus, sizeof(NDIS_STATUS));
    NdisReleaseSpinLock(&(pwa->Lock));
}

//
// Read data from Xenstore
//
char *
WlanReadBackend(PADAPTER Adapter, char *path)
{
    char *tmp;

    UNREFERENCED_PARAMETER(Adapter);

    if (!NT_SUCCESS(xenbus_read(XBT_NIL, path, &tmp)))
        return NULL;

    return tmp;
}

static VOID
ConvertMacAddr (
    char *tmp,
    DOT11_MAC_ADDRESS *mac
    )
{
    int x;

//////    TraceDebug (("mac: %s -> %s.\n", Adapter->FrontendPath, tmp));
    for (x = 0; x < ETH_LENGTH_OF_ADDRESS; x++) {
        (*mac)[x] = (unsigned char)HexCharToInt(tmp[x*3]) * 16 +
            (unsigned char)HexCharToInt(tmp[x*3+1]);
    }
}


static VOID
SetSupportedDataRates (
    IN PWLAN_ADAPTER WlanAdapter,
    ULONG DataRate
    )
{
    UCHAR count=0;

    /* Rate setup */
    NdisZeroMemory(&WlanAdapter->OperationalRateSet, sizeof(DOT11_RATE_SET));
    NdisZeroMemory(&WlanAdapter->OperationalRateMap, sizeof(DOT11_DATA_RATE_MAPPING_TABLE));

    WLAN_ASSIGN_NDIS_OBJECT_HEADER(
        WlanAdapter->OperationalRateMap.Header,
        NDIS_OBJECT_TYPE_DEFAULT,
        DOT11_DATA_RATE_MAPPING_TABLE_REVISION_1,
        sizeof(DOT11_DATA_RATE_MAPPING_TABLE));

    if (DataRate >= 1000)
    {
        WlanAdapter->OperationalRateSet.ucRateSet[count] = 0x80 | 0x2;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateIndex = count;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].usDataRateValue = 
            WlanAdapter->OperationalRateSet.ucRateSet[count];
        count++;
    }
    if (DataRate >= 2000)
    {
        WlanAdapter->OperationalRateSet.ucRateSet[count] = 0x80 | 0x4;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateIndex = count;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].usDataRateValue = 
            WlanAdapter->OperationalRateSet.ucRateSet[count];
        count++;
    }
    if (DataRate >= 5500)
    {
        WlanAdapter->OperationalRateSet.ucRateSet[count] = 0x80 | 0xb;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateIndex = count;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].usDataRateValue = 
            WlanAdapter->OperationalRateSet.ucRateSet[count];
        count++;
    }
    if (DataRate >= 6000)
    {
        WlanAdapter->OperationalRateSet.ucRateSet[count] = 0xc;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateIndex = count;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateFlag = DOT11_DATA_RATE_NON_STANDARD;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].usDataRateValue = 
            WlanAdapter->OperationalRateSet.ucRateSet[count];
        count++;
    }
    if (DataRate >= 9000)
    {
        WlanAdapter->OperationalRateSet.ucRateSet[count] = 0x12;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateIndex = count;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateFlag = DOT11_DATA_RATE_NON_STANDARD;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].usDataRateValue = 
            WlanAdapter->OperationalRateSet.ucRateSet[count];
        count++;
    }
    if (DataRate >= 11000)
    {
        WlanAdapter->OperationalRateSet.ucRateSet[count] = 0x80 | 0x16;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateIndex = count;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].usDataRateValue = 
            WlanAdapter->OperationalRateSet.ucRateSet[count];
        count++;
    }
    if (DataRate >= 12000)
    {
        WlanAdapter->OperationalRateSet.ucRateSet[count] = 0x18;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateIndex = count;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateFlag = DOT11_DATA_RATE_NON_STANDARD;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].usDataRateValue = 
            WlanAdapter->OperationalRateSet.ucRateSet[count];
        count++;
    }
    if (DataRate >= 18000)
    {
        WlanAdapter->OperationalRateSet.ucRateSet[count] = 0x24;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateIndex = count;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateFlag = DOT11_DATA_RATE_NON_STANDARD;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].usDataRateValue = 
            WlanAdapter->OperationalRateSet.ucRateSet[count];
        count++;
    }
    if (DataRate >= 24000)
    {
        WlanAdapter->OperationalRateSet.ucRateSet[count] = 0x30;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateIndex = count;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateFlag = DOT11_DATA_RATE_NON_STANDARD;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].usDataRateValue = 
            WlanAdapter->OperationalRateSet.ucRateSet[count];
        count++;
    }
    if (DataRate >= 48000)
    {
        WlanAdapter->OperationalRateSet.ucRateSet[count] = 0x60;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateIndex = count;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateFlag = DOT11_DATA_RATE_NON_STANDARD;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].usDataRateValue = 
            WlanAdapter->OperationalRateSet.ucRateSet[count];
        count++;
    }
    if (DataRate >= 54000)
    {
        WlanAdapter->OperationalRateSet.ucRateSet[count] = 0x6c;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateIndex = count;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateFlag = DOT11_DATA_RATE_NON_STANDARD;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].usDataRateValue = 
            WlanAdapter->OperationalRateSet.ucRateSet[count];
        count++;
    }
    if (DataRate >= 108000)
    {
        WlanAdapter->OperationalRateSet.ucRateSet[count] = 0xd8;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateIndex = count;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].ucDataRateFlag = DOT11_DATA_RATE_NON_STANDARD;
        WlanAdapter->OperationalRateMap.DataRateMappingEntries[count].usDataRateValue = 
            WlanAdapter->OperationalRateSet.ucRateSet[count];
        count++;
    }

    WlanAdapter->OperationalRateMap.uDataRateMappingLength = count;
    WlanAdapter->OperationalRateSet.uRateSetLength = count;
}

static int
WlanMakeRsnIe(
    PWLAN_ADAPTER pwa,
    int idx,
    UCHAR *buf,
    size_t len,
    const UCHAR *pmkid
    )
{
    RSN_IE_HDR *hdr;
    int num_suites;
    UCHAR *pos, *count;
    USHORT capab;

////////////    TraceVerbose (("Building RSN InformationElement\n"));

    hdr = (RSN_IE_HDR *) buf;
    hdr->elem_id = (UCHAR)WLAN_EID_RSN;
    WPA_PUT_LE16(hdr->version, RSN_VERSION);
    pos = (UCHAR *) (hdr + 1);

    if (pwa->ScannedBss[idx].GroupCipher.Ccmp) {
        RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_CCMP);
        pos += RSN_SELECTOR_LEN;
    } else if (pwa->ScannedBss[idx].GroupCipher.Tkip) {
        RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_TKIP);
        pos += RSN_SELECTOR_LEN;
    } else if (pwa->ScannedBss[idx].GroupCipher.Wep104) {
        RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_WEP104);
        pos += RSN_SELECTOR_LEN;
    } else if (pwa->ScannedBss[idx].GroupCipher.Wep40) {
        RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_WEP40);
        pos += RSN_SELECTOR_LEN;
    } else {
        TraceError (("Invalid group cipher (0x%x)\n", pwa->ScannedBss[idx].GroupCipher.Value));
        //@@@return -1;
    }

    num_suites = 0;
    count = pos;
    pos += 2;

    if (pwa->ScannedBss[idx].Cipher.Ccmp)
    {
        RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_CCMP);
        pos += RSN_SELECTOR_LEN;
        num_suites++;
    }
    if (pwa->ScannedBss[idx].Cipher.Tkip)
    {
        RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_TKIP);
        pos += RSN_SELECTOR_LEN;
        num_suites++;
    }
    if (pwa->ScannedBss[idx].Cipher.Wep40)
    {
        RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_WEP40);
        pos += RSN_SELECTOR_LEN;
        num_suites++;
    }
    if (pwa->ScannedBss[idx].Cipher.Wep104)
    {
        RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_WEP104);
        pos += RSN_SELECTOR_LEN;
        num_suites++;
    }

    if (num_suites == 0)
    {
        TraceError (("Invalid pairwise cipher (0x%x)\n", pwa->ScannedBss[idx].Cipher.Value));
        //@@@return -1;
    }
    if (num_suites)
        WPA_PUT_LE16(count, num_suites);

    num_suites = 0;
    count = pos;
    pos += 2;

    if (pwa->ScannedBss[idx].SecAttribs.wpa_key_mgmt & WPA_KEY_MGMT_IEEE8021X)
    {
        RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_UNSPEC_802_1X);
        pos += RSN_SELECTOR_LEN;
        num_suites++;
    }
    if (pwa->ScannedBss[idx].SecAttribs.wpa_key_mgmt & WPA_KEY_MGMT_PSK)
    {
        RSN_SELECTOR_PUT(pos, RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X);
        pos += RSN_SELECTOR_LEN;
        num_suites++;
    }

    if (num_suites == 0)
    {
        TraceError (("Invalid key management type (0x%x)\n", pwa->ScannedBss[idx].SecAttribs.wpa_key_mgmt));
        //@@@return -1;
    }
    if (num_suites)
        WPA_PUT_LE16(count, num_suites);

    /* RSN Capabilities */
    capab = 0;
    if (pwa->ScannedBss[idx].SecAttribs.rsn_preauth)
        capab |= WPA_CAPABILITY_PREAUTH;
    if (pwa->ScannedBss[idx].SecAttribs.peerkey)
        capab |= WPA_CAPABILITY_PEERKEY_ENABLED;
    if (pwa->ScannedBss[idx].SecAttribs.wmm_enabled)
    {
        /* 4 PTKSA replay counters when using WMM */
        capab |= (RSN_NUM_REPLAY_COUNTERS_16 << 2);
    }
    WPA_PUT_LE16(pos, capab);
    pos += 2;

    UNREFERENCED_PARAMETER (pmkid);
    UNREFERENCED_PARAMETER (len);
    //if (pmkid)
    //{
    //    if (pos + 2 + PMKID_LEN > buf + len)
    //        return -1;
    //    /* PMKID Count */
    //    WPA_PUT_LE16(pos, 1);
    //    pos += 2;
    //    memcpy(pos, pmkid, PMKID_LEN);
    //    pos += PMKID_LEN;
    //}
    //else
    //{
    //    WPA_PUT_LE16(pos, 0);
    //    pos += 2;
    //}

    hdr->len = (UCHAR)((pos - buf) - 2);  // -2 because the len does not incl id & len fields

///////////////    TraceVerbose (("RSN IE length: %d\n", hdr->len));

    return (int)(pos - buf);
}

static ULONG WlanMakeWpaIe(
    PWLAN_ADAPTER pwa,
    ULONG idx,
    UCHAR *buf,
    size_t len
    )
{
    WPA_IE_HDR *hdr;
    ULONG num_suites;
    UCHAR *pos, *count;

    UNREFERENCED_PARAMETER(len);

//////////////////    TraceVerbose (("Building WPA InformationElement\n"));

    hdr = (WPA_IE_HDR *) buf;
    hdr->elem_id = (UCHAR)WLAN_EID_VENDOR_SPECIFIC;
    RSN_SELECTOR_PUT(hdr->oui, WPA_OUI_TYPE);
    WPA_PUT_LE16(hdr->version, WPA_VERSION);
    pos = (UCHAR *) (hdr + 1);

    if (pwa->ScannedBss[idx].GroupCipher.Ccmp) {
        RSN_SELECTOR_PUT(pos, WPA_CIPHER_SUITE_CCMP);
    } else if (pwa->ScannedBss[idx].GroupCipher.Tkip) {
        RSN_SELECTOR_PUT(pos, WPA_CIPHER_SUITE_TKIP);
    } else if (pwa->ScannedBss[idx].GroupCipher.Wep104) {
        RSN_SELECTOR_PUT(pos, WPA_CIPHER_SUITE_WEP104);
    } else if (pwa->ScannedBss[idx].GroupCipher.Wep40) {
        RSN_SELECTOR_PUT(pos, WPA_CIPHER_SUITE_WEP40);
    } else {
        TraceError (("Invalid group cipher (%d)\n", pwa->ScannedBss[idx].GroupCipher.Value));
        //@@@return -1;
    }
    pos += WPA_SELECTOR_LEN;

    num_suites = 0;
    count = pos;
    pos += 2;

    if (pwa->ScannedBss[idx].Cipher.Ccmp) {
        RSN_SELECTOR_PUT(pos, WPA_CIPHER_SUITE_CCMP);
        pos += WPA_SELECTOR_LEN;
        num_suites++;
    }
    if (pwa->ScannedBss[idx].Cipher.Tkip) {
        RSN_SELECTOR_PUT(pos, WPA_CIPHER_SUITE_TKIP);
        pos += WPA_SELECTOR_LEN;
        num_suites++;
    }
    if (pwa->ScannedBss[idx].Cipher.Wep40) {
        RSN_SELECTOR_PUT(pos, WPA_CIPHER_SUITE_WEP40);
        pos += WPA_SELECTOR_LEN;
        num_suites++;
    }
    if (pwa->ScannedBss[idx].Cipher.Wep104) {
        RSN_SELECTOR_PUT(pos, WPA_CIPHER_SUITE_WEP104);
        pos += WPA_SELECTOR_LEN;
        num_suites++;
    }

    if (num_suites == 0) {
        TraceError (("Invalid pairwise cipher (%d)\n", pwa->ScannedBss[idx].Cipher.Value));
        //@@@return -1;
    }
    if (num_suites)
        WPA_PUT_LE16(count, num_suites);

    //
    // Authentication method
    //
    num_suites = 0;
    count = pos;
    pos += 2;

    if (pwa->ScannedBss[idx].SecAttribs.wpa_key_mgmt & WPA_KEY_MGMT_IEEE8021X) {
        RSN_SELECTOR_PUT(pos, WPA_AUTH_KEY_MGMT_UNSPEC_802_1X);
        pos += WPA_SELECTOR_LEN;
        num_suites++;
    }
    if (pwa->ScannedBss[idx].SecAttribs.wpa_key_mgmt & WPA_KEY_MGMT_PSK) {
        RSN_SELECTOR_PUT(pos, WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X);
        pos += WPA_SELECTOR_LEN;
        num_suites++;
    }

    if (num_suites == 0) {
        TraceError (("Invalid key management type (%d)\n", pwa->ScannedBss[idx].SecAttribs.wpa_key_mgmt));
        //@@@return -1;
    }
    if (num_suites)
        WPA_PUT_LE16(count, num_suites);

    hdr->len = (UCHAR)((pos - buf) - 2);  // -2 because the len does not incl id & len fields

////////////////    TraceVerbose (("WPA IE length: %d\n", hdr->len));

    return (ULONG)(pos - buf);
}

PUCHAR
WlanUpdateDataRatesIE (
    PWLAN_ADAPTER pwa,
    PUCHAR ptr,
    BOOLEAN SupportedRateSets
    )
{
    ULONG i;
    PUCHAR pos = ptr;
    PUCHAR cnt;
    UCHAR rate_cnt;

    if (SupportedRateSets)
    {
        rate_cnt = 0;
        *pos = 0x01;    // supported data rates
        pos++;
        cnt = pos;
        pos++;
        for (i=0; i < pwa->OperationalRateSet.uRateSetLength; i++)
        {
            if (pwa->OperationalRateMap.DataRateMappingEntries[i].ucDataRateFlag != DOT11_DATA_RATE_NON_STANDARD)
            {
                *pos = pwa->OperationalRateSet.ucRateSet[i];
                pos++;
                rate_cnt++;
            }
        }
        *cnt = rate_cnt;
    }
    else    // Extended data rates
    {
        rate_cnt = 0;
        *pos = 0x32;    // extended data rates
        pos++;
        cnt = pos;
        pos++;
        for (i=0; i < pwa->OperationalRateSet.uRateSetLength; i++)
        {
            if (pwa->OperationalRateMap.DataRateMappingEntries[i].ucDataRateFlag == DOT11_DATA_RATE_NON_STANDARD)
            {
                *pos = pwa->OperationalRateSet.ucRateSet[i];
                pos++;
                rate_cnt++;
            }
        }
        *cnt = rate_cnt;
    }

    return pos;
}

static VOID
WlanUpdateWpaIE (
    IN PADAPTER Adapter,
    ULONG idx
    )
{
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    UCHAR *pos, buf[256];
    PDOT11_SSID pSSID;

    pSSID = &pwa->ScannedBss[idx].SSID;

    pos = buf;

    *pos = 0x00;    //SSID
    pos++;
    *pos = (UCHAR)pSSID->uSSIDLength;
    pos++;
    memcpy (pos, pSSID->ucSSID, pSSID->uSSIDLength);
    pos += pSSID->uSSIDLength;

    // Supported data rates
    pos = WlanUpdateDataRatesIE(pwa, pos, TRUE);

    *pos = 0x03;    // Current channel
    pos++;
    *pos = 0x01;    // Channel field length
    pos++;
    *pos = (UCHAR)pwa->CurrentChannel;
    pos++;

    memcpy (pos, WLAN_IE_VALUES6, sizeof(WLAN_IE_VALUES6));
    pos += sizeof(WLAN_IE_VALUES6);

    // Extendeded data rates
    pos = WlanUpdateDataRatesIE(pwa, pos, FALSE);

    if (pwa->ScannedBss[idx].Auth.Rsna)
    {
        int res;

        res = WlanMakeRsnIe(pwa, idx, pos, buf + sizeof(buf) - pos, NULL);
        if (res < 0)
        {
            TraceWarning (("WlanUpdateWpaIE : WlanMakeRsnIe failed: %d\n", res)); //return res;
        }
        else
        {
            pos += res;
        }
    }

    else if (pwa->ScannedBss[idx].Auth.RsnaPsk)
    {
        int res;

        res = WlanMakeRsnIe(pwa, idx, pos, buf + sizeof(buf) - pos, NULL);
        if (res < 0)
        {
            TraceWarning (("WlanUpdateWpaIE : WlanMakeRsnIe failed: %d\n", res)); //return res;
        }
        else
        {
            pos += res;
        }
        res = WlanMakeWpaIe(pwa, idx, pos, buf + sizeof(buf) - pos);
        if (res < 0)
        {
            TraceWarning (("WlanUpdateWpaIE : WlanMakeWpaIe failed: %d\n", res)); //return res;
        }
        else
        {
            pos += res;
        }
    }

    else if ((pwa->ScannedBss[idx].Auth.Wpa) ||
        (pwa->ScannedBss[idx].Auth.WpaPsk))
    {
        int res;

        res = WlanMakeWpaIe(pwa, idx, pos, buf + sizeof(buf) - pos);
        if (res < 0)
        {
            TraceWarning (("WlanUpdateWpaIE : WlanMakeWpaIe failed: %d\n", res)); //return res;
        }
        else
        {
            pos += res;
        }
    }

    if (pwa->ScannedBss[idx].WpaInformationElement)
        NdisFreeMemory(pwa->ScannedBss[idx].WpaInformationElement, 0, 0);
    pwa->ScannedBss[idx].WpaInformationElement = NULL;
    pwa->ScannedBss[idx].WpaInfoElementLen = 0;

    //
    // Did we generate any info in the IE?
    //
    if (pos != buf)
    {
        pwa->ScannedBss[idx].WpaInformationElement = NdisAllocateMemoryWithTagPriority (
            Adapter->NdisAdapterHandle,
            (int)(pos - buf), 'apwX', NormalPoolPriority);
        if (pwa->ScannedBss[idx].WpaInformationElement == NULL)
        {
            TraceError (("Failed to allocate memory for InformationElement: SSID \"%s\"\n",
                pwa->ScannedBss[idx].SSID.ucSSID));
            return;
        }
        NdisMoveMemory (pwa->ScannedBss[idx].WpaInformationElement, buf, pos - buf);
        pwa->ScannedBss[idx].WpaInfoElementLen = (ULONG)(pos - buf);
        //TraceNotice (("Copied %d bytes of IE to adapter extension #%d\n", pwa->WpaInfoElementLen[idx], idx));
        //Dump (pwa->ScannedBss[idx].WpaInformationElement, pwa->ScannedBss[idx].WpaInfoElementLen);
    }
}

static VOID
TranslateWlanAuth (
    PWLAN_ADAPTER WlanAdapter,
    int idx,
    char *str
    )
{
    WlanAdapter->ScannedBss[idx].SecAttribs.wpa_key_mgmt = 0;
    if (memcmp (str, "open", 4) == 0)
    {
        WlanAdapter->ScannedBss[idx].Auth.Open = 1;
    }
    else if (memcmp (str, "shared-key", 10) == 0)
    {
        WlanAdapter->ScannedBss[idx].Auth.SharedKey = 1;
        WlanAdapter->ScannedBss[idx].SecAttribs.wpa_key_mgmt |= WPA_KEY_MGMT_PSK;
    }
    else if (memcmp (str, "wpa-psk", 7) == 0)
    {
        WlanAdapter->ScannedBss[idx].Auth.WpaPsk = 1;
        WlanAdapter->ScannedBss[idx].SecAttribs.wpa_key_mgmt |= WPA_KEY_MGMT_PSK;
    }
    else if (memcmp (str, "wpa", 3) == 0)
    {
        WlanAdapter->ScannedBss[idx].Auth.Wpa = 1;
        WlanAdapter->ScannedBss[idx].SecAttribs.wpa_key_mgmt |= WPA_KEY_MGMT_IEEE8021X;
    }
    else if (memcmp (str, "rsna-psk", 8) == 0)
    {
        WlanAdapter->ScannedBss[idx].Auth.RsnaPsk = 1;
        WlanAdapter->ScannedBss[idx].SecAttribs.wpa_key_mgmt |= WPA_KEY_MGMT_PSK;
    }
    else if (memcmp (str, "rsna", 4) == 0)
    {
        WlanAdapter->ScannedBss[idx].Auth.Rsna = 1;
        WlanAdapter->ScannedBss[idx].SecAttribs.wpa_key_mgmt |= WPA_KEY_MGMT_IEEE8021X;
    }
}

static VOID
TranslateWlanCipher (
    PWLAN_ADAPTER WlanAdapter,
    int idx,
    char *str
    )
{
    if (memcmp (str, "none", 4) == 0)
    {
        WlanAdapter->ScannedBss[idx].Cipher.None = 1;
    }
    else if (memcmp (str, "wep104", 6) == 0)
    {
        WlanAdapter->ScannedBss[idx].Cipher.Wep104 = 1;
    }
    else if (memcmp (str, "wep40", 5) == 0)
    {
        WlanAdapter->ScannedBss[idx].Cipher.Wep40 = 1;
    }
    else if (memcmp (str, "wep", 3) == 0)
    {
        WlanAdapter->ScannedBss[idx].Cipher.Wep = 1;
        //WlanAdapter->UnicastCipherAlgorithm = DOT11_CIPHER_ALGO_WEP;
        //WlanAdapter->MulticastCipherAlgorithm = DOT11_CIPHER_ALGO_WEP;
    }
    else if (memcmp (str, "tkip", 4) == 0)
    {
        WlanAdapter->ScannedBss[idx].Cipher.Tkip = 1;
    }
    else if (memcmp (str, "ccmp", 4) == 0)
    {
        WlanAdapter->ScannedBss[idx].Cipher.Ccmp = 1;
    }
}

static VOID
TranslateWlanGroupCipher (
    PWLAN_ADAPTER WlanAdapter,
    int idx,
    char *str
    )
{
    if (memcmp (str, "none", 4) == 0)
    {
        WlanAdapter->ScannedBss[idx].GroupCipher.None = 1;
    }
    else if (memcmp (str, "wep104", 6) == 0)
    {
        WlanAdapter->ScannedBss[idx].GroupCipher.Wep104 = 1;
    }
    else if (memcmp (str, "wep40", 5) == 0)
    {
        WlanAdapter->ScannedBss[idx].GroupCipher.Wep40 = 1;
    }
    else if (memcmp (str, "wep", 3) == 0)
    {
        WlanAdapter->ScannedBss[idx].GroupCipher.Wep = 1;
        //WlanAdapter->UnicastCipherAlgorithm = DOT11_CIPHER_ALGO_WEP;
        //WlanAdapter->MulticastCipherAlgorithm = DOT11_CIPHER_ALGO_WEP;
    }
    else if (memcmp (str, "tkip", 4) == 0)
    {
        WlanAdapter->ScannedBss[idx].GroupCipher.Tkip = 1;
    }
    else if (memcmp (str, "ccmp", 4) == 0)
    {
        WlanAdapter->ScannedBss[idx].GroupCipher.Ccmp = 1;
    }
}

NDIS_STATUS
WlanPerformScan (
    IN PADAPTER Adapter
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    char *str;
    int i, j;
    char path[256];
    int k;
    LARGE_INTEGER ts, hts;
    PDOT11_BSS_ENTRY pEntry;
    PDOT11_SSID pSSID;
    PSEC_ATTRIBUTES pSecAtt;
    DOT11_CAPABILITY Capability;

    //
    // Read from Xenstore the list of BSSIDs and cache them in the
    // adapter extension.
    //

    i = 0;
    j = 0;
    do
    {
        NdisGetCurrentSystemTime(&ts);

//        NdisZeroMemory(&WlanAdapter->ScannedBss[j], sizeof(XEN_BSS_ENTRY));
        WlanClearBss (&WlanAdapter->ScannedBss[j]);

        pEntry = &WlanAdapter->ScannedBss[j].Entry;
        pSSID = &WlanAdapter->ScannedBss[j].SSID;
        pSecAtt = &WlanAdapter->ScannedBss[j].SecAttribs;

        //
        // Initialize the Capabilities field
        //
        Capability.usValue = 0;
        Capability.ShortSlotTime = 1;
        Capability.ESS = 1;
        //
        // Always set Open and None in the "available auth/cipher" bit fields
        //
        WlanAdapter->ScannedBss[j].Auth.Open = 1;
        WlanAdapter->ScannedBss[j].Cipher.None = 1;
        WlanAdapter->ScannedBss[j].GroupCipher.None = 1;

        //
        // Start reading all the xenstore entries that describe the
        // available SSIDs.
        //
        Xmsnprintf (path, sizeof(path), "wlan/%d", i);
        str = WlanReadBackend(Adapter, path);
        if (!str)
            continue;
        XmFreeMemory(str);

        WlanAdapter->ScannedBss[j].XenStoreEntry = i;

        Xmsnprintf (path, sizeof(path), "wlan/%d/mac", i);
        str = WlanReadBackend(Adapter, path);
        if (str)
        {
            ConvertMacAddr (str, &pEntry->dot11BSSID);
            XmFreeMemory(str);
        }
        Xmsnprintf (path, sizeof(path), "wlan/%d/essid", i);
        str = WlanReadBackend(Adapter, path);
        if (str)
        {
            pSSID->uSSIDLength = (ULONG)min (NDIS_802_11_LENGTH_SSID, strlen(str));
            NdisMoveMemory(&pSSID->ucSSID, str, pSSID->uSSIDLength);
            XmFreeMemory(str);
        }
        Xmsnprintf (path, sizeof(path), "wlan/%d/quality", i);
        str = WlanReadBackend(Adapter, path);
        if (str)
        {
            int quality;
            quality = atoi(str);
            pEntry->lRSSI = (ULONG)((double)quality * 0.81) - 101;
            pEntry->uLinkQuality = quality;
            XmFreeMemory(str);
        }
        Xmsnprintf (path, sizeof(path), "wlan/%d/frequency", i);
        str = WlanReadBackend(Adapter, path);
        if (str)
        {
            pEntry->PhySpecificInfo.uChCenterFrequency = atol(str) / 1000;
            XmFreeMemory(str);
        }
        Xmsnprintf (path, sizeof(path), "wlan/%d/auth", i);
        str = WlanReadBackend(Adapter, path);
        if (str)
        {
            TranslateWlanAuth(WlanAdapter, j, str);
            XmFreeMemory(str);
        }
        Xmsnprintf (path, sizeof(path), "wlan/%d/cipher", i);
        str = WlanReadBackend(Adapter, path);
        if ((str) && (strlen(str)))
        {
            // Old style...
            //////////////////TraceVerbose(("Read from Xenstore/cipher: %s\n", str));
            TranslateWlanCipher(WlanAdapter, j, str);
            XmFreeMemory(str);
        }
        else
        {
            // Just in case we read a null string up above
            if (str) XmFreeMemory(str);

            k = 0;
            do 
            {
                Xmsnprintf (path, sizeof(path), "wlan/%d/cipher/%d", i, k);
                str = WlanReadBackend(Adapter, path);
                if (str)
                {
///////////                    TraceVerbose(("Read from Xenstore/cipher/%d: %s\n", k, str));
                    TranslateWlanCipher(WlanAdapter, j, str);
                    XmFreeMemory(str);
                }
            }
            while (++k < WLAN_MAX_CIPHER_COUNT);
        }
        Xmsnprintf (path, sizeof(path), "wlan/%d/group-cipher", i);
        str = WlanReadBackend(Adapter, path);
        if (str)
        {
            // For the null string we read up above
            XmFreeMemory(str);

            k = 0;
            do 
            {
                Xmsnprintf (path, sizeof(path), "wlan/%d/group-cipher/%d", i, k);
                str = WlanReadBackend(Adapter, path);
                if (str)
                {
                    TranslateWlanGroupCipher(WlanAdapter, j, str);
                    XmFreeMemory(str);
                }
            }
            while (++k < WLAN_MAX_CIPHER_COUNT);
        }
        Xmsnprintf (path, sizeof(path), "wlan/%d/maxbitrate", i);
        str = WlanReadBackend(Adapter, path);
        if (str)
        {
            SetSupportedDataRates(WlanAdapter, atol(str));
            XmFreeMemory(str);
        }

        //
        // Set the Privacy flag appropriately
        //
        Capability.Privacy = WlanAdapter->ScannedBss[j].Cipher.Wep |
            WlanAdapter->ScannedBss[j].Cipher.Ccmp |
            WlanAdapter->ScannedBss[j].Cipher.Tkip |
            WlanAdapter->ScannedBss[j].Cipher.Wep104 |
            WlanAdapter->ScannedBss[j].Cipher.Wep40;

        //
        // Fill in all the attributes of the beacon frame
        //
        pEntry->dot11BSSType = dot11_BSS_type_infrastructure;
        pEntry->uPhyId = WlanAdapter->CurrentPhyId;
        pEntry->bInRegDomain = TRUE;
        pEntry->usBeaconPeriod = 0x64;
        NdisGetCurrentSystemTime(&hts);
        pEntry->ullTimestamp = ts.QuadPart;
        pEntry->ullHostTimestamp = hts.QuadPart;
        pEntry->usCapabilityInformation = Capability.usValue;
        //
        // Generate the IE for the WLAN
        //
        WlanUpdateWpaIE(Adapter, j);
        pEntry->uBufferLength = WlanAdapter->ScannedBss[j].WpaInfoElementLen;

        j++;
    }
    while (i++ < 16 && j < WLAN_BSSID_MAX_COUNT);

    WlanAdapter->ScannedBssCount = j;

    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS
WlanScanRequest (
    PADAPTER          Adapter,
    PNDIS_OID_REQUEST NdisRequest    
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesRead = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_SCAN_REQUEST_V2 scanRequest;
    BOOLEAN queueWork = FALSE;

    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;

    do {
        bytesNeeded = sizeof(DOT11_SCAN_REQUEST_V2);
        if (informationBufferLength < sizeof(DOT11_SCAN_REQUEST_V2)) {
            bytesRead = informationBufferLength;
            TraceError(("Bad length provided for scan. Length needed: %d, Length provided: %d\n", bytesNeeded, informationBufferLength));                
            ndisStatus = NDIS_STATUS_INVALID_LENGTH;                
            break;
        }
        scanRequest = (PDOT11_SCAN_REQUEST_V2)informationBuffer;
        bytesRead = bytesNeeded;

        ndisStatus = WlanValidateScanRequest(scanRequest);
        if (ndisStatus != NDIS_STATUS_SUCCESS) {
            break;
        }

        if (!pwa->RadioOn) {
            TraceError(("Cannot perform scan - NIC is turned off\n"));
            ndisStatus = NDIS_STATUS_DOT11_POWER_STATE_INVALID;
            break;
        }
        
        if (!pwa->PhyEnabled) {
            TraceError(("Cannot perform scan - PHY layer disabled\n"));
            ndisStatus = NDIS_STATUS_DOT11_POWER_STATE_INVALID;
            break;
        }

        NdisAcquireSpinLock(&(pwa->Lock));
        if ((pwa->State & (WLAN_STATE_DELETING|WLAN_STATE_PAUSED|WLAN_STATE_SCANNING)) != 0) {
            NdisReleaseSpinLock(&(pwa->Lock));
            TraceError(("Cannot perform scan - NIC state invalid: 0x%x\n", pwa->State));
            ndisStatus = NDIS_STATUS_DOT11_MEDIA_IN_USE;
            break;
        }

        pwa->State |= WLAN_STATE_SCANNING;

        /* This particular request is pended - the RequestID is used during completion */
        pwa->ScanRequestId = NdisRequest->RequestId;
        NdisReleaseSpinLock(&(pwa->Lock));

        /* So the basic idea is to pretend to do a scan. We will build the BSS list from
         * backend values from XenStore. For now, this is just a single BSSID and SSID
         * for whatever is connected. If we are not connected in the backend then the
         * scan list will be empty. The call to WlanEnumerateBSSList() will return the
         * BSS list built here. The completion and sending of NDIS_STATUS_DOT11_SCAN_CONFIRM 
         * will be done in a work item asynchronously.
         */
        pwa->ScannedBssCount = 0;
        queueWork = TRUE;

        /* Test for cases where there are no scan results */
        //if (!pwa->XenConnected) {
        //    break;
        //}

        /* If scanning for ANY (wildcard) or for our specific BSSID, fill in the
         * response.  For any other BSSID return no results.
         */
        if (!WLAN_COMPARE_MAC_ADDRESS(&WLAN_BSSID_WILDCARD[0], &scanRequest->dot11BSSID[0])) {
            if (!WLAN_COMPARE_MAC_ADDRESS(&pwa->DesiredBss.Entry.dot11BSSID[0], &scanRequest->dot11BSSID[0])) {
                break;
            }
        }

        // Go off and read xenstore to get a list of wireless networks
        WlanPerformScan (Adapter);

        /* Now just return success and queue the work item */
    } while(FALSE);

    if (queueWork) {
        NdisQueueIoWorkItem(pwa->WorkItem, WlanScanWorkItem, Adapter);
    }
    
    NdisRequest->DATA.SET_INFORMATION.BytesNeeded = bytesNeeded;
    NdisRequest->DATA.SET_INFORMATION.BytesRead = bytesRead;

    return ndisStatus;
}

static NDIS_STATUS
WlanResetRequest (
    PADAPTER          Adapter,
    PNDIS_OID_REQUEST NdisRequest
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesRead = 0;
    PVOID informationBuffer;
    ULONG inputBufferLength;
    ULONG outputBufferLength;
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_RESET_REQUEST request;
    PDOT11_STATUS_INDICATION indication;

    informationBuffer = NdisRequest->DATA.METHOD_INFORMATION.InformationBuffer;
    inputBufferLength = NdisRequest->DATA.METHOD_INFORMATION.InputBufferLength;
    outputBufferLength = NdisRequest->DATA.METHOD_INFORMATION.OutputBufferLength;

    do {
        if (outputBufferLength < sizeof(DOT11_STATUS_INDICATION)) {
            bytesNeeded = sizeof(DOT11_STATUS_INDICATION);
            ndisStatus = NDIS_STATUS_INVALID_LENGTH;
            break;
        }
        if (inputBufferLength < sizeof(DOT11_RESET_REQUEST)) {
            bytesNeeded = sizeof(DOT11_RESET_REQUEST);
            ndisStatus = NDIS_STATUS_INVALID_LENGTH;
            break;
        }
        request = (PDOT11_RESET_REQUEST)informationBuffer;

#if DBG
        if (request->dot11ResetType == dot11_reset_type_phy)
            TraceNotice (("Reset PHY\n"));
        else if (request->dot11ResetType == dot11_reset_type_mac)
            TraceNotice (("Reset MAC\n"));
        else if (request->dot11ResetType == dot11_reset_type_phy_and_mac)
            TraceNotice (("Reset PHY and MAC\n"));
        else
            TraceNotice (("Unknown reset type\n"));
#endif

        if ((request->dot11ResetType != dot11_reset_type_phy)&&
            (request->dot11ResetType != dot11_reset_type_mac)&&
            (request->dot11ResetType != dot11_reset_type_phy_and_mac)) {
            ndisStatus = NDIS_STATUS_INVALID_DATA;
            break;
        }

        bytesRead = sizeof(DOT11_RESET_REQUEST);
        /* NOTE do no set bytesWritten */

        /* Stop any running scan */
        NdisAcquireSpinLock(&(pwa->Lock));
        if (pwa->State & WLAN_STATE_SCANNING) {
            pwa->State |= WLAN_STATE_STOPSCAN;
        }

        if (pwa->State & WLAN_STATE_CONNECTED)
            // Called while lock held...
            WlanDisconnectRequest (Adapter, DOT11_DISASSOC_REASON_OS);

        NdisReleaseSpinLock(&(pwa->Lock));

        if (pwa->PrivacyExemptionList != NULL) {
            NdisFreeMemory(pwa->PrivacyExemptionList, 0, 0);
            pwa->PrivacyExemptionList = NULL;
        }

        /* Reset all default MIB values */
        WlanAdapterDefaults(pwa);

        /* NOTE the MiniportReset function doesn't do too much in the way of 
         * disabling traffic flow or masking the event channels. Perhaps there
         * is not much more to do here either.
         */

        /* Now, try to just indicate success though we didn't do anything - TODO will this cut it? */
        indication = (PDOT11_STATUS_INDICATION)informationBuffer;
        indication->uStatusType = DOT11_STATUS_RESET_CONFIRM;
        indication->ndisStatus = NDIS_STATUS_SUCCESS;
    } while (FALSE);

    NdisRequest->DATA.SET_INFORMATION.BytesNeeded = bytesNeeded;
    NdisRequest->DATA.SET_INFORMATION.BytesRead = bytesRead; 

    return ndisStatus;
}

static NDIS_STATUS
WlanEnumerateBSSList (
    PADAPTER          Adapter, 
    PNDIS_OID_REQUEST NdisRequest
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesRead = 0;
    ULONG bytesWritten = 0;
    PVOID informationBuffer;
    ULONG inputBufferLength;
    ULONG outputBufferLength;
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_BYTE_ARRAY byteArray;
    PDOT11_BSS_ENTRY pEntry;
    PUCHAR ptr, pCurrPtr;
    int i;

    informationBuffer = NdisRequest->DATA.METHOD_INFORMATION.InformationBuffer;
    inputBufferLength = NdisRequest->DATA.METHOD_INFORMATION.InputBufferLength;
    outputBufferLength = NdisRequest->DATA.METHOD_INFORMATION.OutputBufferLength;

    do {
        if (outputBufferLength < FIELD_OFFSET(DOT11_BYTE_ARRAY, ucBuffer))
        {
            bytesNeeded = sizeof(DOT11_BYTE_ARRAY);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        byteArray = (PDOT11_BYTE_ARRAY)informationBuffer;

        WLAN_ASSIGN_NDIS_OBJECT_HEADER(byteArray->Header, 
                                       NDIS_OBJECT_TYPE_DEFAULT,
                                       DOT11_BSS_ENTRY_BYTE_ARRAY_REVISION_1,
                                       sizeof(DOT11_BYTE_ARRAY));

        byteArray->uNumOfBytes = 0;
        byteArray->uTotalNumOfBytes = 0;

        /* Do we have nothing to return? */
        if (pwa->ScannedBssCount == 0)
        {
            bytesWritten = FIELD_OFFSET(DOT11_BYTE_ARRAY, ucBuffer);
            bytesNeeded = FIELD_OFFSET(DOT11_BYTE_ARRAY, ucBuffer);            
            break;
        }

        pCurrPtr = byteArray->ucBuffer;
        for (i=0; i < (int)pwa->ScannedBssCount; i++)
        {
            ptr = pCurrPtr;

            pEntry = &pwa->ScannedBss[i].Entry;

            byteArray->uTotalNumOfBytes += FIELD_OFFSET(DOT11_BSS_ENTRY, ucBuffer) + pEntry->uBufferLength;

            /* Want to write a single BSS entry and one IE with the SSID */
            if (outputBufferLength < byteArray->uTotalNumOfBytes)
            {
                bytesWritten = FIELD_OFFSET(DOT11_BYTE_ARRAY, ucBuffer);
                bytesNeeded = byteArray->uTotalNumOfBytes;
                ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
                continue;
            }

            /* Enough room, copy it all in */
            NdisMoveMemory(ptr, pEntry, FIELD_OFFSET(DOT11_BSS_ENTRY, ucBuffer));
            ptr += FIELD_OFFSET(DOT11_BSS_ENTRY, ucBuffer);

            NdisMoveMemory(ptr, pwa->ScannedBss[i].WpaInformationElement, pwa->ScannedBss[i].WpaInfoElementLen);
            byteArray->uNumOfBytes = byteArray->uTotalNumOfBytes;

            pCurrPtr += FIELD_OFFSET(DOT11_BSS_ENTRY, ucBuffer) + pEntry->uBufferLength;
        } // for

        bytesWritten = byteArray->uNumOfBytes + FIELD_OFFSET(DOT11_BYTE_ARRAY, ucBuffer);
        bytesNeeded = byteArray->uTotalNumOfBytes + FIELD_OFFSET(DOT11_BYTE_ARRAY, ucBuffer);

    } while (FALSE);

    NdisRequest->DATA.METHOD_INFORMATION.BytesNeeded = bytesNeeded;
    NdisRequest->DATA.METHOD_INFORMATION.BytesRead = bytesRead;
    NdisRequest->DATA.METHOD_INFORMATION.BytesWritten = bytesWritten;

    return ndisStatus;
}

BOOLEAN
WpaOrRsnaAuth (
    DOT11_AUTH_ALGORITHM Auth
    )
{
    if (Auth == DOT11_AUTH_ALGO_RSNA)
        return TRUE;
    else if (Auth == DOT11_AUTH_ALGO_RSNA_PSK)
        return TRUE;
    else if (Auth == DOT11_AUTH_ALGO_WPA)
        return TRUE;
    else if (Auth == DOT11_AUTH_ALGO_WPA_PSK)
        return TRUE;
    else
        return FALSE;
}

static VOID
WlanConnectFailed (
    PADAPTER  Adapter
    )
{
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    DOT11_ASSOCIATION_COMPLETION_PARAMETERS assocComplParams;
    DOT11_CONNECTION_COMPLETION_PARAMETERS connComplParams;

    TraceError (("Indicating failed connect attempt\n"));

    /* First the association complete parameters */
    NdisZeroMemory(&assocComplParams, sizeof(DOT11_ASSOCIATION_COMPLETION_PARAMETERS));
    WLAN_ASSIGN_NDIS_OBJECT_HEADER(assocComplParams.Header, 
                                   NDIS_OBJECT_TYPE_DEFAULT,
                                   DOT11_ASSOCIATION_COMPLETION_PARAMETERS_REVISION_1,
                                   sizeof(DOT11_ASSOCIATION_COMPLETION_PARAMETERS));

    NdisMoveMemory(assocComplParams.MacAddr,
        &pwa->DesiredBss.Entry.dot11BSSID[0],
        sizeof(DOT11_MAC_ADDRESS));

    assocComplParams.uStatus = DOT11_ASSOC_STATUS_CANDIDATE_LIST_EXHAUSTED;

    WlanIndicateStatus(Adapter, NDIS_STATUS_DOT11_ASSOCIATION_COMPLETION, NULL,
        &assocComplParams, sizeof(DOT11_ASSOCIATION_COMPLETION_PARAMETERS));

    /* Finally the connection complete parameters */
    NdisZeroMemory(&connComplParams, sizeof(DOT11_CONNECTION_COMPLETION_PARAMETERS));
    WLAN_ASSIGN_NDIS_OBJECT_HEADER(connComplParams.Header, 
                                   NDIS_OBJECT_TYPE_DEFAULT,
                                   DOT11_CONNECTION_COMPLETION_PARAMETERS_REVISION_1,
                                   sizeof(DOT11_CONNECTION_COMPLETION_PARAMETERS));
    connComplParams.uStatus = DOT11_CONNECTION_STATUS_CANDIDATE_LIST_EXHAUSTED;

    WlanIndicateStatus(Adapter, NDIS_STATUS_DOT11_CONNECTION_COMPLETION, NULL,
        &connComplParams, sizeof(DOT11_CONNECTION_COMPLETION_PARAMETERS));

    WlanClearBss (&pwa->AssociatedBss);

    /* Clear flag indicating we are connected */
    NdisAcquireSpinLock(&(pwa->Lock));
    pwa->State &= ~WLAN_STATE_CONNECTED;
    NdisReleaseSpinLock(&(pwa->Lock));
}

static VOID
WlanConnectWorkItem (
    IN PVOID            Context,
    IN NDIS_HANDLE      NdisIoWorkItemHandle
    )
{
    PADAPTER pa = Context;
    PWLAN_ADAPTER pwa = pa->WlanAdapter;
    PDOT11_ASSOCIATION_COMPLETION_PARAMETERS assocComplParams;
    DOT11_CONNECTION_COMPLETION_PARAMETERS connComplParams;
    DOT11_BEACON_FRAME UNALIGNED *beaconFrame;
    ULONG BufferLength;
    PULONG ptr;
    DOT11_ASSOC_REQUEST_FRAME UNALIGNED *reqFrame;
    DOT11_ASSOC_RESPONSE_FRAME UNALIGNED *respFrame;
    PUCHAR pos;

    UNREFERENCED_PARAMETER(NdisIoWorkItemHandle);

    NdisGetCurrentSystemTime(&pwa->AssocTime);

    BufferLength = sizeof(DOT11_ASSOCIATION_COMPLETION_PARAMETERS) +
        sizeof(DOT11_BEACON_FRAME) + pwa->DesiredBss.WpaInfoElementLen +
        sizeof(ULONG);                                   // PHYID

    if (WpaOrRsnaAuth(pwa->AuthAlgorithm))
    {
        BufferLength += 
            sizeof(DOT11_ASSOC_REQUEST_FRAME) + pwa->DesiredBss.WpaInfoElementLen + sizeof(WLAN_HT_CAPA) + 
            sizeof(DOT11_ASSOC_RESPONSE_FRAME) + pwa->DesiredBss.WpaInfoElementLen + sizeof(WLAN_HT_CAPA) + sizeof(WLAN_HT_INFO);
    }

    assocComplParams = 
        NdisAllocateMemoryWithTagPriority(pa->NdisAdapterHandle, BufferLength, '_nwx', NormalPoolPriority);

    if (assocComplParams == NULL)
    {
        TraceError (("Failed to allocate association completion buffer\n"));
        WlanConnectFailed (pa);
        return;
    }

    /* First the association complete parameters */
    NdisZeroMemory(assocComplParams, sizeof(DOT11_ASSOCIATION_COMPLETION_PARAMETERS));
    WLAN_ASSIGN_NDIS_OBJECT_HEADER(assocComplParams->Header, 
                                   NDIS_OBJECT_TYPE_DEFAULT,
                                   DOT11_ASSOCIATION_COMPLETION_PARAMETERS_REVISION_1,
                                   sizeof(DOT11_ASSOCIATION_COMPLETION_PARAMETERS));

    TraceVerbose (("Connecting to SSID %s\n", pwa->DesiredBss.SSID.ucSSID));

    NdisMoveMemory(&assocComplParams->MacAddr,
        &pwa->DesiredBss.Entry.dot11BSSID,
        sizeof(DOT11_MAC_ADDRESS));

    assocComplParams->uStatus = DOT11_ASSOC_STATUS_SUCCESS;

    /* Fill success state parameters */
    assocComplParams->AuthAlgo = pwa->AuthAlgorithm;
    assocComplParams->UnicastCipher = pwa->UnicastCipherAlgorithm;
    assocComplParams->MulticastCipher = pwa->MulticastCipherAlgorithm;
    assocComplParams->bFourAddressSupported = FALSE;
    assocComplParams->bPortAuthorized = WpaOrRsnaAuth(assocComplParams->AuthAlgo);
    assocComplParams->DSInfo = DOT11_DS_UNKNOWN;
    assocComplParams->uEncapTableOffset = 0;
    assocComplParams->uEncapTableSize = 0;
    assocComplParams->bReAssocReq = FALSE;
    assocComplParams->bReAssocResp = FALSE;
    assocComplParams->uIHVDataOffset = 0;
    assocComplParams->uIHVDataSize = 0;

    //
    // Update the fictitious association ID counter.
    // Used in the response packet below.
    //
    ++pwa->CurrentAssocID;

    ptr = (PULONG)((PUCHAR)(assocComplParams) + sizeof(DOT11_ASSOCIATION_COMPLETION_PARAMETERS));

    //
    // Append the beacon information of this beaconing station.
    //
    beaconFrame = (DOT11_BEACON_FRAME UNALIGNED *)ptr;
    beaconFrame->Timestamp = pwa->AssocTime.QuadPart;
    beaconFrame->BeaconInterval = pwa->DesiredBss.Entry.usBeaconPeriod;
    beaconFrame->Capability.usValue = pwa->DesiredBss.Entry.usCapabilityInformation;
    ptr = (PULONG)((PUCHAR)ptr + sizeof(DOT11_BEACON_FRAME));
    NdisMoveMemory(ptr,
                  pwa->DesiredBss.WpaInformationElement,
                  pwa->DesiredBss.WpaInfoElementLen);
    assocComplParams->uBeaconOffset = sizeof(DOT11_ASSOCIATION_COMPLETION_PARAMETERS);
    assocComplParams->uBeaconSize = sizeof(DOT11_BEACON_FRAME) + pwa->DesiredBss.WpaInfoElementLen;
    ptr = (PULONG)((PUCHAR)ptr + pwa->DesiredBss.WpaInfoElementLen);

    //
    // Append PHY identifier
    //
    assocComplParams->uActivePhyListOffset = assocComplParams->uBeaconOffset + assocComplParams->uBeaconSize;
    assocComplParams->uActivePhyListSize = sizeof(ULONG);
    *ptr = pwa->CurrentPhyId;
    ptr = (PULONG)((PUCHAR)ptr + assocComplParams->uActivePhyListSize);


    if (WpaOrRsnaAuth(assocComplParams->AuthAlgo))
    {
        //
        // Append a madeup association request packet
        //
        reqFrame = (DOT11_ASSOC_REQUEST_FRAME UNALIGNED *)ptr;
        reqFrame->Capability.usValue = pwa->DesiredBss.Entry.usCapabilityInformation;
        reqFrame->usListenInterval = pwa->DesiredBss.Entry.usBeaconPeriod;
        pos = (PUCHAR)ptr + sizeof(DOT11_ASSOC_REQUEST_FRAME);
        NdisMoveMemory (pos, pwa->DesiredBss.WpaInformationElement, pwa->DesiredBss.WpaInfoElementLen);
        pos += pwa->DesiredBss.WpaInfoElementLen;
        NdisMoveMemory (pos, WLAN_HT_CAPA, sizeof(WLAN_HT_CAPA));
        pos += sizeof(WLAN_HT_CAPA);
        assocComplParams->uAssocReqOffset = assocComplParams->uActivePhyListOffset + assocComplParams->uActivePhyListSize;
        assocComplParams->uAssocReqSize = (ULONG)(pos - (PUCHAR)ptr);
        ptr = (PULONG)pos;
     
     
        //
        // Append a madeup association respone packet
        //
        respFrame = (DOT11_ASSOC_RESPONSE_FRAME UNALIGNED *)ptr;
        respFrame->Capability = reqFrame->Capability;
        respFrame->usStatusCode = DOT11_ASSOC_STATUS_SUCCESS;
        respFrame->usAID = pwa->CurrentAssocID | 0xc000;
        pos = (PUCHAR)ptr + sizeof(DOT11_ASSOC_RESPONSE_FRAME);
        NdisMoveMemory (pos, pwa->DesiredBss.WpaInformationElement, pwa->DesiredBss.WpaInfoElementLen);
        pos += pwa->DesiredBss.WpaInfoElementLen;
        NdisMoveMemory (pos, WLAN_HT_CAPA, sizeof(WLAN_HT_CAPA));
        pos += sizeof(WLAN_HT_CAPA);
        NdisMoveMemory (pos, WLAN_HT_INFO, sizeof(WLAN_HT_INFO));
        pos += sizeof(WLAN_HT_INFO);
        assocComplParams->uAssocRespOffset = assocComplParams->uAssocReqOffset + assocComplParams->uAssocReqSize;
        assocComplParams->uAssocRespSize = (ULONG)(pos - (PUCHAR)ptr);
        ptr = (PULONG)pos;
    }

    WlanIndicateStatus(pa, NDIS_STATUS_DOT11_ASSOCIATION_COMPLETION, NULL,
        assocComplParams, (ULONG)((PUCHAR)ptr - (PUCHAR)assocComplParams));

    NdisFreeMemory(assocComplParams, BufferLength, 0);

    // Copy the desired BSS entry into the associated
    WlanCopyScannedBss (pa, &pwa->AssociatedBss, &pwa->DesiredBss);

    /* Finally the connection complete parameters */
    NdisZeroMemory(&connComplParams, sizeof(DOT11_CONNECTION_COMPLETION_PARAMETERS));
    WLAN_ASSIGN_NDIS_OBJECT_HEADER(connComplParams.Header, 
                                   NDIS_OBJECT_TYPE_DEFAULT,
                                   DOT11_CONNECTION_COMPLETION_PARAMETERS_REVISION_1,
                                   sizeof(DOT11_CONNECTION_COMPLETION_PARAMETERS));
    connComplParams.uStatus = DOT11_CONNECTION_STATUS_SUCCESS;

    WlanIndicateStatus(pa, NDIS_STATUS_DOT11_CONNECTION_COMPLETION, NULL,
        &connComplParams, sizeof(DOT11_CONNECTION_COMPLETION_PARAMETERS));


    /* Set our flag indicating we are connected */
    NdisAcquireSpinLock(&(pwa->Lock));
    pwa->State |= WLAN_STATE_CONNECTED;
    NdisReleaseSpinLock(&(pwa->Lock));

    // Send a link quality notification of the current WLAN
    WlanIndicateRssi (pa);
}

static VOID
WlanConnectRequest (
    PADAPTER          Adapter
    )
{
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    DOT11_CONNECTION_START_PARAMETERS connStartParams;
    DOT11_ASSOCIATION_START_PARAMETERS assocStartParams;

    /* First, make an indication that we are connecting */
    NdisZeroMemory(&connStartParams, sizeof(DOT11_CONNECTION_START_PARAMETERS));
    WLAN_ASSIGN_NDIS_OBJECT_HEADER(connStartParams.Header, 
                                   NDIS_OBJECT_TYPE_DEFAULT,
                                   DOT11_CONNECTION_START_PARAMETERS_REVISION_1,
                                   sizeof(DOT11_CONNECTION_START_PARAMETERS));
    connStartParams.BSSType = pwa->BSSType;
    WlanIndicateStatus(Adapter, NDIS_STATUS_DOT11_CONNECTION_START, NULL, 
        &connStartParams, sizeof(DOT11_CONNECTION_START_PARAMETERS));

    /* Next, make an indication that we are associating */
    NdisZeroMemory(&assocStartParams, sizeof(DOT11_ASSOCIATION_START_PARAMETERS));
    WLAN_ASSIGN_NDIS_OBJECT_HEADER(assocStartParams.Header, 
                                   NDIS_OBJECT_TYPE_DEFAULT,
                                   DOT11_ASSOCIATION_START_PARAMETERS_REVISION_1,
                                   sizeof(DOT11_ASSOCIATION_START_PARAMETERS));
    assocStartParams.uIHVDataOffset = 0;
    assocStartParams.uIHVDataSize = 0;

    if (!WlanFindBss(Adapter))
    {
        TraceError (("Failed to find BSS that matches - Failing connect request\n"));
        //
        // Issue an Association Start to match the Assoc Completed in the 
        // WlanConnectFailed() call below.
        //
        WlanIndicateStatus(Adapter, NDIS_STATUS_DOT11_ASSOCIATION_START, NULL, 
            &assocStartParams, sizeof(DOT11_ASSOCIATION_START_PARAMETERS));
        //
        // Fail the association attempt
        //
        WlanConnectFailed(Adapter);
        return;
    }

    /* Our Xen backend SSID */
    NdisMoveMemory(&(assocStartParams.SSID), &pwa->DesiredBss.SSID, sizeof(DOT11_SSID));
    NdisMoveMemory(&(assocStartParams.MacAddr), &pwa->DesiredBss.Entry.dot11BSSID[0], sizeof(DOT11_MAC_ADDRESS));

    WlanIndicateStatus(Adapter, NDIS_STATUS_DOT11_ASSOCIATION_START, NULL, 
        &assocStartParams, sizeof(DOT11_ASSOCIATION_START_PARAMETERS));

    /* Asynchronously complete the associate and connect */
    NdisQueueIoWorkItem(pwa->WorkItem, WlanConnectWorkItem, Adapter);
}


static VOID
WlanDisconnectRequest (
    PADAPTER          Adapter,
    DOT11_ASSOC_STATUS DiscReason
    )
{
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    DOT11_DISASSOCIATION_PARAMETERS disassocParameters;

    // Called with pwa->Lock held

    NdisZeroMemory(&disassocParameters, sizeof(DOT11_DISASSOCIATION_PARAMETERS));    

    MP_ASSIGN_NDIS_OBJECT_HEADER(disassocParameters.Header, 
                                 NDIS_OBJECT_TYPE_DEFAULT,
                                 DOT11_DISASSOCIATION_PARAMETERS_REVISION_1,
                                 sizeof(DOT11_DISASSOCIATION_PARAMETERS));
    disassocParameters.uIHVDataOffset = 0;
    disassocParameters.uIHVDataSize = 0;
    disassocParameters.uReason = DiscReason;

    NdisMoveMemory(&(disassocParameters.MacAddr), &WLAN_BSSID_WILDCARD[0], sizeof(DOT11_MAC_ADDRESS));

    WlanIndicateStatus (
        Adapter,
        NDIS_STATUS_DOT11_DISASSOCIATION,
        NULL,
        &disassocParameters,
        sizeof(DOT11_DISASSOCIATION_PARAMETERS)); 

    WlanClearBss (&pwa->AssociatedBss);

    pwa->State &= ~WLAN_STATE_CONNECTED;
}


static NDIS_STATUS
WlanQueryDesiredSSIDList (
    PNDIS_OID_REQUEST NdisRequest,
    PDOT11_SSID       SSID
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesWritten = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_SSID_LIST ssidList;
    
    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;

    do {        
        if (informationBufferLength < sizeof(DOT11_SSID_LIST)) {
            bytesNeeded = sizeof(DOT11_SSID_LIST);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }
        NdisZeroMemory(informationBuffer, informationBufferLength);

        ssidList = (PDOT11_SSID_LIST)informationBuffer;
        WLAN_ASSIGN_NDIS_OBJECT_HEADER(ssidList->Header, 
                                       NDIS_OBJECT_TYPE_DEFAULT,
                                       DOT11_SSID_LIST_REVISION_1,
                                       sizeof(DOT11_SSID_LIST));
        ssidList->uNumOfEntries = 0;
        ssidList->uTotalNumOfEntries = 0;
        
        if (informationBufferLength < 
            (FIELD_OFFSET(DOT11_SSID_LIST, SSIDs) + 1 * sizeof(DOT11_SSID))) {
            ssidList->uNumOfEntries = 0;
            ssidList->uTotalNumOfEntries = 1;
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;            
        }
        else {
            NdisMoveMemory(ssidList->SSIDs, SSID, sizeof(DOT11_SSID));
            ssidList->uNumOfEntries = 1;
            ssidList->uTotalNumOfEntries = 1;
        }
          
        bytesWritten = ssidList->uNumOfEntries * sizeof(DOT11_SSID) + FIELD_OFFSET(DOT11_SSID_LIST, SSIDs);
        bytesNeeded = ssidList->uTotalNumOfEntries * sizeof(DOT11_SSID) + FIELD_OFFSET(DOT11_SSID_LIST, SSIDs);        
    } while (FALSE);

    NdisRequest->DATA.QUERY_INFORMATION.BytesWritten = bytesWritten;
    NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded = bytesNeeded;
    return ndisStatus;
}

static NDIS_STATUS
WlanSetDesiredSSIDList (
    PWLAN_ADAPTER pwa,
    PNDIS_OID_REQUEST NdisRequest
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesRead = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_SSID_LIST ssidList = NULL;

    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;    
    
    do {        
        if (informationBufferLength < FIELD_OFFSET(DOT11_SSID_LIST, SSIDs)) {
            bytesNeeded = FIELD_OFFSET(DOT11_SSID_LIST, SSIDs);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        ssidList = (PDOT11_SSID_LIST)informationBuffer;
        if (!WLAN_VERIFY_NDIS_OBJECT_HEADER_DEFAULT(ssidList->Header, 
                                                    NDIS_OBJECT_TYPE_DEFAULT,
                                                    DOT11_SSID_LIST_REVISION_1,
                                                    sizeof(DOT11_SSID_LIST))) {
            ndisStatus = NDIS_STATUS_INVALID_DATA;
            break;
        }

        /* Should be just one one SSID in the list */
        if (ssidList->uNumOfEntries != 1) {
            TraceError (("WlanSetDesiredSSIDList: ssid list has too many entries (%d)\n",
                ssidList->uNumOfEntries));
            ndisStatus = NDIS_STATUS_INVALID_DATA;
            break;
        }

        // Verify length/number of entries match up
        bytesNeeded = ssidList->uNumOfEntries * sizeof(DOT11_SSID) + FIELD_OFFSET(DOT11_SSID_LIST, SSIDs);

        if (informationBufferLength < bytesNeeded) {
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        NdisMoveMemory(&pwa->DesiredBss.SSID, &(ssidList->SSIDs[0]), sizeof(DOT11_SSID));

        bytesRead =  FIELD_OFFSET(DOT11_SSID_LIST, SSIDs) + 1 * sizeof(DOT11_SSID);
        
    } while (FALSE);

    NdisRequest->DATA.SET_INFORMATION.BytesNeeded = bytesNeeded;
    NdisRequest->DATA.SET_INFORMATION.BytesRead = bytesRead;

    return ndisStatus;
}

static NDIS_STATUS
WlanQueryDesiredBSSIDList (
    PNDIS_OID_REQUEST NdisRequest,
    PWLAN_ADAPTER     WlanAdapter
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesWritten = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_BSSID_LIST bssidList;
    
    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;

    do
    {
        if (informationBufferLength < sizeof(DOT11_BSSID_LIST)) {
            bytesNeeded = sizeof(DOT11_BSSID_LIST);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }
        NdisZeroMemory(informationBuffer, informationBufferLength);

        bssidList = (PDOT11_BSSID_LIST)informationBuffer;        
        WLAN_ASSIGN_NDIS_OBJECT_HEADER(bssidList->Header, 
                                       NDIS_OBJECT_TYPE_DEFAULT,
                                       DOT11_BSSID_LIST_REVISION_1,
                                       sizeof(DOT11_BSSID_LIST));
        bssidList->uNumOfEntries = 0;
        bssidList->uTotalNumOfEntries = 0;
                        
        if (informationBufferLength < (sizeof(DOT11_MAC_ADDRESS)
                                       + FIELD_OFFSET(DOT11_BSSID_LIST, BSSIDs))) {
            bssidList->uNumOfEntries = 0;
            bssidList->uTotalNumOfEntries = 1;
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;            
        }
        else {
            NdisMoveMemory(bssidList->BSSIDs, &WlanAdapter->DesiredBss.Entry.dot11BSSID[0],
                           sizeof(DOT11_MAC_ADDRESS));
            bssidList->uNumOfEntries = 1;
            bssidList->uTotalNumOfEntries = 1;
        }
            
        bytesWritten = bssidList->uNumOfEntries * sizeof(DOT11_MAC_ADDRESS)
                        + FIELD_OFFSET(DOT11_BSSID_LIST, BSSIDs);
        bytesNeeded = bssidList->uTotalNumOfEntries * sizeof(DOT11_MAC_ADDRESS)
                        + FIELD_OFFSET(DOT11_BSSID_LIST, BSSIDs);
        
    } while(FALSE);

    NdisRequest->DATA.QUERY_INFORMATION.BytesWritten = bytesWritten;
    NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded = bytesNeeded;
    return ndisStatus;
}

static NDIS_STATUS
WlanSetDesiredBSSIDList (
    PNDIS_OID_REQUEST NdisRequest,
    PWLAN_ADAPTER     WlanAdapter
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesRead = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_BSSID_LIST bssidList = NULL;

    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;    

    do {
        if (informationBufferLength < FIELD_OFFSET(DOT11_BSSID_LIST, BSSIDs)) {
            bytesNeeded = FIELD_OFFSET(DOT11_BSSID_LIST, BSSIDs);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        bssidList = (PDOT11_BSSID_LIST)informationBuffer;
        if (!WLAN_VERIFY_NDIS_OBJECT_HEADER_DEFAULT(bssidList->Header, 
                                                    NDIS_OBJECT_TYPE_DEFAULT,
                                                    DOT11_BSSID_LIST_REVISION_1,
                                                    sizeof(DOT11_BSSID_LIST))) {
            ndisStatus = NDIS_STATUS_INVALID_DATA;
            break;
        }
        
        if (bssidList->uNumOfEntries > 0) {            
            bytesNeeded = bssidList->uNumOfEntries * sizeof(DOT11_MAC_ADDRESS) +
                            FIELD_OFFSET(DOT11_BSSID_LIST, BSSIDs);
            if (informationBufferLength < bytesNeeded) {
                ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
                break;
            }
        }

        if (bssidList->uNumOfEntries > 1) {
            ndisStatus = NDIS_STATUS_INVALID_LENGTH;
            break;
        }

        /* Should only be one set */
        NdisMoveMemory(&WlanAdapter->DesiredBss.Entry.dot11BSSID[0], &(bssidList->BSSIDs[0]),
                       bssidList->uNumOfEntries * sizeof(DOT11_MAC_ADDRESS));

        /* TODO deal with this?
        pStation->Config.AcceptAnyBSSID = TRUE;*/

        bytesRead =  FIELD_OFFSET(DOT11_BSSID_LIST, BSSIDs) + bssidList->uNumOfEntries * sizeof(DOT11_MAC_ADDRESS);
    } while (FALSE);

    NdisRequest->DATA.SET_INFORMATION.BytesNeeded = bytesNeeded;
    NdisRequest->DATA.SET_INFORMATION.BytesRead = bytesRead;
    return ndisStatus;
}


static NDIS_STATUS
WlanQueryPmkidList (
    PWLAN_ADAPTER     pwa,
    PNDIS_OID_REQUEST NdisRequest
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesWritten = 0;
    ULONG InformationBufferLength;
    PVOID InformationBuffer;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_PMKID_LIST PMKIDList;
    
    InformationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    InformationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;

    do
    {
        bytesWritten = 0;
        bytesNeeded = 0;

        NdisZeroMemory(InformationBuffer, InformationBufferLength);

        PMKIDList = (PDOT11_PMKID_LIST)InformationBuffer;

        WLAN_ASSIGN_NDIS_OBJECT_HEADER(PMKIDList->Header, 
            NDIS_OBJECT_TYPE_DEFAULT,
            DOT11_PMKID_LIST_REVISION_1,
            sizeof(DOT11_PMKID_LIST));
            
        PMKIDList->uTotalNumOfEntries = pwa->PMKIDCount;

        // Integer overflow
        if (FIELD_OFFSET(DOT11_PMKID_LIST, PMKIDs) > 
                FIELD_OFFSET(DOT11_PMKID_LIST, PMKIDs) + 
                pwa->PMKIDCount * sizeof(DOT11_PMKID_ENTRY))
        {
            ndisStatus = NDIS_STATUS_FAILURE;
            PMKIDList->uNumOfEntries = 0;
            break;
        }

        //
        // If the buffer is not big enough, simply return error.
        //
        if (InformationBufferLength < (FIELD_OFFSET(DOT11_PMKID_LIST, PMKIDs) 
                + pwa->PMKIDCount * sizeof(DOT11_PMKID_ENTRY)))
        {
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            PMKIDList->uNumOfEntries = 0;
            break;
        }

        //
        // Copy the PMKID list.
        //
        PMKIDList->uNumOfEntries = pwa->PMKIDCount;
        NdisMoveMemory(PMKIDList->PMKIDs,
                       &pwa->PMKIDList,
                       pwa->PMKIDCount * sizeof(DOT11_PMKID_ENTRY));

    } while (FALSE);

    bytesWritten = PMKIDList->uNumOfEntries * sizeof(DOT11_PMKID_ENTRY) + 
                    FIELD_OFFSET(DOT11_PHY_ID_LIST, dot11PhyId);
        
    bytesNeeded = PMKIDList->uTotalNumOfEntries * sizeof(DOT11_PMKID_ENTRY) +
                   FIELD_OFFSET(DOT11_PHY_ID_LIST, dot11PhyId);

    NdisRequest->DATA.QUERY_INFORMATION.BytesWritten = bytesWritten;
    NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded = bytesNeeded;
    return ndisStatus;
}

static VOID
WlanPopulateAvailableAuthAlogrithms(
    PWLAN_ADAPTER pwa,
    int idx,
    PDOT11_AUTH_ALGORITHM AlgorithmIds
    )
{
    int cnt = 0;

    if (pwa->ScannedBss[idx].Auth.Open)
        AlgorithmIds[cnt++] = DOT11_AUTH_ALGO_80211_OPEN;
    if (pwa->ScannedBss[idx].Auth.SharedKey)
        AlgorithmIds[cnt++] = DOT11_AUTH_ALGO_80211_SHARED_KEY;
    if (pwa->ScannedBss[idx].Auth.RsnaPsk)
        AlgorithmIds[cnt++] = DOT11_AUTH_ALGO_RSNA_PSK;
    if (pwa->ScannedBss[idx].Auth.Rsna)
        AlgorithmIds[cnt++] = DOT11_AUTH_ALGO_RSNA;
    if (pwa->ScannedBss[idx].Auth.Wpa)
        AlgorithmIds[cnt++] = DOT11_AUTH_ALGO_WPA;
    if (pwa->ScannedBss[idx].Auth.WpaPsk)
        AlgorithmIds[cnt++] = DOT11_AUTH_ALGO_WPA_PSK;
}

static NDIS_STATUS
WlanQueryEnabledAuthenticationAlgorithm (
    PNDIS_OID_REQUEST  NdisRequest,
    PWLAN_ADAPTER      WlanAdapter
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesWritten = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_AUTH_ALGORITHM_LIST pAuthAlgoList = NULL;
    ULONG AuthCount;

/////////////    AuthCount = bitCount((ULONG)WlanAdapter->AvailableAuthAlgorithms[idx].Value);
    AuthCount = 1;

    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;

    do {
        if (informationBufferLength < sizeof(DOT11_AUTH_ALGORITHM_LIST) * AuthCount) {
            TraceWarning(("WlanQueryEnabledAuthenticationAlgorithm: Buffer too small\n"));
            bytesNeeded = sizeof(DOT11_AUTH_ALGORITHM_LIST) * AuthCount;
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }
        NdisZeroMemory(informationBuffer, informationBufferLength);

        pAuthAlgoList = (PDOT11_AUTH_ALGORITHM_LIST)informationBuffer;
        WLAN_ASSIGN_NDIS_OBJECT_HEADER(pAuthAlgoList->Header, 
                                       NDIS_OBJECT_TYPE_DEFAULT,
                                       DOT11_AUTH_ALGORITHM_LIST_REVISION_1,
                                       sizeof(DOT11_AUTH_ALGORITHM_LIST));
        pAuthAlgoList->uNumOfEntries = 0;  
        pAuthAlgoList->uTotalNumOfEntries = 0;

        if (informationBufferLength < (FIELD_OFFSET(DOT11_AUTH_ALGORITHM_LIST, AlgorithmIds)
                                        + AuthCount * sizeof(DOT11_AUTH_ALGORITHM))) {
            TraceWarning(("WlanQueryEnabledAuthenticationAlgorithm(2): Buffer too small\n"));
            pAuthAlgoList->uNumOfEntries = 0;
            pAuthAlgoList->uTotalNumOfEntries =  AuthCount;
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
        }
        else {
            pAuthAlgoList->uNumOfEntries = AuthCount;
            pAuthAlgoList->uTotalNumOfEntries = AuthCount;
//            WlanPopulateAvailableAuthAlogrithms(WlanAdapter, pAuthAlgoList->AlgorithmIds);
            pAuthAlgoList->AlgorithmIds[0] = WlanAdapter->AuthAlgorithm;
        }
        bytesWritten = pAuthAlgoList->uNumOfEntries * sizeof(DOT11_AUTH_ALGORITHM) + 
            FIELD_OFFSET(DOT11_AUTH_ALGORITHM_LIST, AlgorithmIds);            
        bytesNeeded = pAuthAlgoList->uTotalNumOfEntries * sizeof(DOT11_AUTH_ALGORITHM) +
            FIELD_OFFSET(DOT11_AUTH_ALGORITHM_LIST, AlgorithmIds);
    } while(FALSE);

    NdisRequest->DATA.QUERY_INFORMATION.BytesWritten = bytesWritten;
    NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded = bytesNeeded;
    return ndisStatus;
}


//BOOLEAN
//IsAuthMethodSupported (
//    PWLAN_ADAPTER WlanAdapter,
//    int idx,
//    DOT11_AUTH_ALGORITHM AlgorithmId
//    )
//{
//    switch (AlgorithmId)
//    {
//    case DOT11_AUTH_ALGO_80211_OPEN:
//        return (BOOLEAN)WlanAdapter->AvailableAuthAlgorithms[idx].Open;
//        break;
//    case DOT11_AUTH_ALGO_80211_SHARED_KEY:
//        return (BOOLEAN)WlanAdapter->AvailableAuthAlgorithms[idx].SharedKey;
//        break;
//    case DOT11_AUTH_ALGO_RSNA_PSK:
//        return (BOOLEAN)WlanAdapter->AvailableAuthAlgorithms[idx].RsnaPsk;
//        break;
//    case DOT11_AUTH_ALGO_RSNA:
//        return (BOOLEAN)WlanAdapter->AvailableAuthAlgorithms[idx].Rsna;
//        break;
//    case DOT11_AUTH_ALGO_WPA_PSK:
//        return (BOOLEAN)WlanAdapter->AvailableAuthAlgorithms[idx].WpaPsk;
//        break;
//    case DOT11_AUTH_ALGO_WPA:
//        return (BOOLEAN)WlanAdapter->AvailableAuthAlgorithms[idx].Wpa;
//        break;
//    default:
//        return FALSE;
//    }
//}

static NDIS_STATUS
WlanSetEnabledAuthenticationAlgorithm (
    PNDIS_OID_REQUEST  NdisRequest,
    PWLAN_ADAPTER      WlanAdapter
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesRead = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_AUTH_ALGORITHM_LIST pAuthAlgoList = NULL;

    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;    
    
    do {
        if (informationBufferLength < FIELD_OFFSET(DOT11_AUTH_ALGORITHM_LIST, AlgorithmIds)) {
            bytesNeeded = FIELD_OFFSET(DOT11_AUTH_ALGORITHM_LIST, AlgorithmIds);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        pAuthAlgoList = (PDOT11_AUTH_ALGORITHM_LIST)informationBuffer;

        if (!WLAN_VERIFY_NDIS_OBJECT_HEADER_DEFAULT(pAuthAlgoList->Header, 
                                                    NDIS_OBJECT_TYPE_DEFAULT,
                                                    DOT11_AUTH_ALGORITHM_LIST_REVISION_1,
                                                    sizeof(DOT11_AUTH_ALGORITHM_LIST))) {
            TraceWarning(("WlanSetEnabledAuthenticationAlgorithm: Invalid header\n"));
            ndisStatus = NDIS_STATUS_INVALID_DATA;
            break;
        }

        /* Only support one entry in the list */
        if (pAuthAlgoList->uNumOfEntries != 1) {
            TraceWarning(("WlanSetEnabledAuthenticationAlgorithm: Invalid auth method count specified\n"));
            ndisStatus = NDIS_STATUS_INVALID_DATA;
            break;
        }

        /* Verify length/number of entries match up */
        bytesNeeded = pAuthAlgoList->uNumOfEntries * sizeof(DOT11_AUTH_ALGORITHM) +
                            FIELD_OFFSET(DOT11_AUTH_ALGORITHM_LIST, AlgorithmIds);
        if (informationBufferLength < bytesNeeded) {
            TraceWarning(("WlanSetEnabledAuthenticationAlgorithm: Buffer too small\n"));
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        //if (!IsAuthMethodSupported(WlanAdapter, pAuthAlgoList->AlgorithmIds[0]))
        //{
        //    TraceWarning(("WlanSetEnabledAuthenticationAlgorithm: Invalid auth method specified\n"));
        //    ndisStatus = NDIS_STATUS_INVALID_DATA;
        //    break;
        //}

        /* This may seem a little silly to do all this for one algorithm but it may be
         * useful later or if we are forced to pretend to support other algorithms.
         */
        WlanAdapter->AuthAlgorithm = pAuthAlgoList->AlgorithmIds[0];
        
        bytesRead = FIELD_OFFSET(DOT11_AUTH_ALGORITHM_LIST, AlgorithmIds) + 1 * sizeof(DOT11_AUTH_ALGORITHM);
    } while (FALSE);

    NdisRequest->DATA.SET_INFORMATION.BytesNeeded = bytesNeeded;
    NdisRequest->DATA.SET_INFORMATION.BytesRead = bytesRead;
    return ndisStatus;
}

static NDIS_STATUS
WlanQueryEnabledCipherAlgorithm (
    PNDIS_OID_REQUEST  NdisRequest,
    PWLAN_ADAPTER      WlanAdapter,
    BOOLEAN            Unicast
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesWritten = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_CIPHER_ALGORITHM_LIST pAuthCipherList;
    
    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;

    do {
        if (informationBufferLength < sizeof(DOT11_CIPHER_ALGORITHM_LIST)) {
            bytesNeeded = sizeof(DOT11_CIPHER_ALGORITHM_LIST);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }
        NdisZeroMemory(informationBuffer, informationBufferLength);

        pAuthCipherList = (PDOT11_CIPHER_ALGORITHM_LIST)informationBuffer;

        WLAN_ASSIGN_NDIS_OBJECT_HEADER(pAuthCipherList->Header, 
                                       NDIS_OBJECT_TYPE_DEFAULT,
                                       DOT11_CIPHER_ALGORITHM_LIST_REVISION_1,
                                       sizeof(DOT11_CIPHER_ALGORITHM_LIST));
        pAuthCipherList->uNumOfEntries = 0;      
        pAuthCipherList->uTotalNumOfEntries = 0;     
        
        if (informationBufferLength < (FIELD_OFFSET(DOT11_CIPHER_ALGORITHM_LIST, AlgorithmIds) +
                           1 * sizeof(DOT11_CIPHER_ALGORITHM))) {
            pAuthCipherList->uNumOfEntries = 0;
            pAuthCipherList->uTotalNumOfEntries = 1;
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;            
        }
        else {
            pAuthCipherList->uNumOfEntries = 1;
            pAuthCipherList->uTotalNumOfEntries = 1;
            pAuthCipherList->AlgorithmIds[0] = 
                (Unicast ? WlanAdapter->UnicastCipherAlgorithm : WlanAdapter->MulticastCipherAlgorithm);
        }

        bytesWritten = pAuthCipherList->uNumOfEntries * sizeof(DOT11_CIPHER_ALGORITHM) + 
            FIELD_OFFSET(DOT11_CIPHER_ALGORITHM_LIST, AlgorithmIds);
            
        bytesNeeded = pAuthCipherList->uTotalNumOfEntries * sizeof(DOT11_CIPHER_ALGORITHM) +
            FIELD_OFFSET(DOT11_CIPHER_ALGORITHM_LIST, AlgorithmIds);
    } while (FALSE);

    NdisRequest->DATA.QUERY_INFORMATION.BytesWritten = bytesWritten;
    NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded = bytesNeeded;
    return ndisStatus;
}


NDIS_STATUS
WlanQuerySupportedUnicastAlgorithmPair(
    __in PWLAN_ADAPTER pwa,
    __out_bcount(TotalLength) PDOT11_AUTH_CIPHER_PAIR_LIST AuthCipherList,
    __in __range(sizeof(DOT11_AUTH_CIPHER_PAIR_LIST) - sizeof(DOT11_AUTH_CIPHER_PAIR), ULONG_MAX) ULONG TotalLength,
    __in BOOLEAN            Unicast
    )
{
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    ULONG bytesNeeded = 0;
    ULONG count;

    Unicast;
    pwa;

    do
    {
        count = sizeof(InfraAnycastAlgorithmPairs)/sizeof(DOT11_AUTH_CIPHER_PAIR);

        // Ensure enough space for one entry (though this would
        // get saved as part of the DOT11_AUTH_CIPHER_PAIR_LIST structure
        // itself)
        bytesNeeded = FIELD_OFFSET(DOT11_AUTH_CIPHER_PAIR_LIST, AuthCipherPairs) +
                      count * sizeof(DOT11_AUTH_CIPHER_PAIR);
        
        AuthCipherList->uNumOfEntries = 0;
        AuthCipherList->uTotalNumOfEntries = count;

        if (TotalLength < bytesNeeded)
        {
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;            
            break;
        }

        AuthCipherList->uNumOfEntries = count;

        NdisMoveMemory (AuthCipherList->AuthCipherPairs, InfraAnycastAlgorithmPairs, sizeof(InfraAnycastAlgorithmPairs));

    } while(FALSE);

    return ndisStatus;
}


static NDIS_STATUS
WlanQuerySupportedAlgorithmPair (
    PNDIS_OID_REQUEST  NdisRequest,
    PWLAN_ADAPTER      WlanAdapter,
    BOOLEAN            Unicast
    )
{
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_AUTH_CIPHER_PAIR_LIST authCipherList = NULL;
    ULONG BytesNeeded = 0;
    ULONG BytesWritten = 0;
    ULONG InformationBufferLength;
    PVOID InformationBuffer;
    
    InformationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    InformationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;

    do
    {
        if (InformationBufferLength < sizeof(DOT11_AUTH_CIPHER_PAIR_LIST)) {
            BytesNeeded = sizeof(DOT11_AUTH_CIPHER_PAIR_LIST);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        NdisZeroMemory(InformationBuffer, InformationBufferLength);

        authCipherList = (PDOT11_AUTH_CIPHER_PAIR_LIST)InformationBuffer;

        MP_ASSIGN_NDIS_OBJECT_HEADER(authCipherList->Header, 
            NDIS_OBJECT_TYPE_DEFAULT,
            DOT11_AUTH_CIPHER_PAIR_LIST_REVISION_1,
            sizeof(DOT11_AUTH_CIPHER_PAIR_LIST));

        authCipherList->uNumOfEntries = 0;
        authCipherList->uTotalNumOfEntries = 0;

        ndisStatus = WlanQuerySupportedUnicastAlgorithmPair(
                        WlanAdapter,
                        authCipherList, 
                        InformationBufferLength,
                        Unicast
                        );

        BytesWritten = authCipherList->uNumOfEntries * sizeof(DOT11_AUTH_CIPHER_PAIR) + 
            FIELD_OFFSET(DOT11_AUTH_CIPHER_PAIR_LIST, AuthCipherPairs);
            
        BytesNeeded = authCipherList->uTotalNumOfEntries * sizeof(DOT11_AUTH_CIPHER_PAIR) +
            FIELD_OFFSET(DOT11_AUTH_CIPHER_PAIR_LIST, AuthCipherPairs);

    } while(FALSE);

    NdisRequest->DATA.QUERY_INFORMATION.BytesWritten = BytesWritten;
    NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded = BytesNeeded;

    return ndisStatus;
}


static NDIS_STATUS
WlanSetEnabledCipherAlgorithm (
    PNDIS_OID_REQUEST  NdisRequest,
    PWLAN_ADAPTER      WlanAdapter,
    BOOLEAN            Unicast
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesRead = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_CIPHER_ALGORITHM_LIST pCipherAlgoList;

    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;    
    
    do {
        if (informationBufferLength < FIELD_OFFSET(DOT11_CIPHER_ALGORITHM_LIST, AlgorithmIds)) {
            bytesNeeded = FIELD_OFFSET(DOT11_CIPHER_ALGORITHM_LIST, AlgorithmIds);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        pCipherAlgoList = (PDOT11_CIPHER_ALGORITHM_LIST)informationBuffer;

        if (!WLAN_VERIFY_NDIS_OBJECT_HEADER_DEFAULT(pCipherAlgoList->Header, 
                                                    NDIS_OBJECT_TYPE_DEFAULT,
                                                    DOT11_CIPHER_ALGORITHM_LIST_REVISION_1,
                                                    sizeof(DOT11_CIPHER_ALGORITHM_LIST))) {
            ndisStatus = NDIS_STATUS_INVALID_DATA;
            break;
        }

        // Verify length/number of entries match up
        bytesNeeded = pCipherAlgoList->uNumOfEntries * sizeof(DOT11_CIPHER_ALGORITHM) +
                            FIELD_OFFSET(DOT11_CIPHER_ALGORITHM_LIST, AlgorithmIds);

        if (informationBufferLength < bytesNeeded) {
            TraceWarning(("WlanSetEnabledCipherAlgorithm: Buffer too small\n"));
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        if (Unicast) {
            WlanAdapter->UnicastCipherAlgorithm = pCipherAlgoList->AlgorithmIds[0];
        } else {
            WlanAdapter->MulticastCipherAlgorithm = pCipherAlgoList->AlgorithmIds[0];
        }        
        bytesRead = FIELD_OFFSET(DOT11_CIPHER_ALGORITHM_LIST, AlgorithmIds) + 1 * sizeof(DOT11_CIPHER_ALGORITHM);
    } while (FALSE);

    NdisRequest->DATA.SET_INFORMATION.BytesNeeded = bytesNeeded;
    NdisRequest->DATA.SET_INFORMATION.BytesRead = bytesRead;
    return ndisStatus;
}

static NDIS_STATUS
WlanQueryAssociationInfo (
    PADAPTER          Adapter, 
    PNDIS_OID_REQUEST NdisRequest
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesWritten = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_ASSOCIATION_INFO_LIST pAssocInfoList;
    PDOT11_ASSOCIATION_INFO_EX pAssocInfo;
    LARGE_INTEGER assocTime;
    BOOLEAN associated = FALSE;
      
    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;

    do {
        if (informationBufferLength < sizeof(DOT11_ASSOCIATION_INFO_LIST)) {
            bytesNeeded = sizeof(DOT11_ASSOCIATION_INFO_LIST);
            ndisStatus = NDIS_STATUS_INVALID_STATE;
            break;
        }
        NdisZeroMemory(informationBuffer, informationBufferLength);

        pAssocInfoList = (PDOT11_ASSOCIATION_INFO_LIST)informationBuffer;
        WLAN_ASSIGN_NDIS_OBJECT_HEADER(pAssocInfoList->Header,
                                       NDIS_OBJECT_TYPE_DEFAULT,
                                       DOT11_ASSOCIATION_INFO_LIST_REVISION_1,
                                       sizeof(DOT11_ASSOCIATION_INFO_LIST));

        assocTime.QuadPart = 0;
        NdisAcquireSpinLock(&(pwa->Lock));
        if (pwa->State & WLAN_STATE_CONNECTED) {
            associated = TRUE;
            assocTime.QuadPart = pwa->AssocTime.QuadPart;
        }
        NdisReleaseSpinLock(&(pwa->Lock));
        
        /* TODO this needs more work */
        if (associated) {
            pAssocInfo = &(pAssocInfoList->dot11AssocInfo[0]);
            NdisZeroMemory(pAssocInfo, sizeof(DOT11_ASSOCIATION_INFO_EX));

            NdisMoveMemory(&pAssocInfo->PeerMacAddress[0], &pwa->AssociatedBss.Entry.dot11BSSID[0], sizeof(DOT11_MAC_ADDRESS));
            NdisMoveMemory(&pAssocInfo->BSSID[0], &pwa->AssociatedBss.Entry.dot11BSSID[0], sizeof(DOT11_MAC_ADDRESS));

            pAssocInfo->dot11AssociationState = dot11_assoc_state_auth_assoc;
            pAssocInfo->liAssociationUpTime.QuadPart = assocTime.QuadPart;
            pAssocInfo->usCapabilityInformation = pwa->AssociatedBss.Entry.usCapabilityInformation;
            pAssocInfo->usListenInterval = WLAN_LISTEN_INTERVAL_DEFAULT;
            NdisMoveMemory (pAssocInfo->ucPeerSupportedRates, pwa->OperationalRateSet.ucRateSet, pwa->OperationalRateSet.uRateSetLength);
            pAssocInfo->usAssociationID = pwa->CurrentAssocID | 0xc000;
            pAssocInfo->dot11PowerMode = dot11_power_mode_active;
            pAssocInfo->ullNumOfTxPacketSuccesses = pwa->Stats.PhyCounters->ullTransmittedFrameCount;
            pAssocInfo->ullNumOfTxPacketFailures = pwa->Stats.PhyCounters->ullFailedCount;
            pAssocInfo->ullNumOfRxPacketSuccesses = pwa->Stats.MacUcastCounters.ullReceivedFrameCount;
            pAssocInfo->ullNumOfRxPacketFailures = pwa->Stats.PhyCounters->ullFailedCount;

            pAssocInfoList->uNumOfEntries = 1;
            pAssocInfoList->uTotalNumOfEntries = 1;
        }
        else {
            /* Not associated - nothing to return */
            pAssocInfoList->uNumOfEntries = 0;
            pAssocInfoList->uTotalNumOfEntries = 0;
            ndisStatus = NDIS_STATUS_INVALID_STATE;
        }

        bytesWritten = pAssocInfoList->uTotalNumOfEntries * sizeof(DOT11_ASSOCIATION_INFO_EX) + 
                        FIELD_OFFSET(DOT11_ASSOCIATION_INFO_LIST, dot11AssocInfo);            
        bytesNeeded = pAssocInfoList->uTotalNumOfEntries * sizeof(DOT11_ASSOCIATION_INFO_EX) +
                        FIELD_OFFSET(DOT11_ASSOCIATION_INFO_LIST, dot11AssocInfo);     
    } while (FALSE);

    NdisRequest->DATA.QUERY_INFORMATION.BytesWritten = bytesWritten;
    NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded = bytesNeeded;
    return ndisStatus;
}

static NDIS_STATUS
WlanQueryDesiredPhyList (
    PNDIS_OID_REQUEST NdisRequest,
    PWLAN_ADAPTER     WlanAdapter
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesWritten = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_PHY_ID_LIST phyIdList;
    
    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;

    do {
        if (informationBufferLength < sizeof(DOT11_PHY_ID_LIST)) {
            bytesNeeded = sizeof(DOT11_PHY_ID_LIST);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        if (FIELD_OFFSET(DOT11_PHY_ID_LIST, dot11PhyId) > 
            FIELD_OFFSET(DOT11_PHY_ID_LIST, dot11PhyId) + WlanAdapter->DesiredPhyCount * sizeof(ULONG)) {
            ndisStatus = NDIS_STATUS_FAILURE;
            break;
        }

        NdisZeroMemory(informationBuffer, informationBufferLength);

        phyIdList = (PDOT11_PHY_ID_LIST)informationBuffer;
        WLAN_ASSIGN_NDIS_OBJECT_HEADER(phyIdList->Header, 
                                       NDIS_OBJECT_TYPE_DEFAULT,
                                       DOT11_PHY_ID_LIST_REVISION_1,
                                       sizeof(DOT11_PHY_ID_LIST));
        phyIdList->uNumOfEntries = 0; 
        phyIdList->uTotalNumOfEntries = WlanAdapter->DesiredPhyCount;

        if (informationBufferLength < 
            FIELD_OFFSET(DOT11_PHY_ID_LIST, dot11PhyId) + WlanAdapter->DesiredPhyCount * sizeof(ULONG)) {
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
        }
        else {
            phyIdList->uNumOfEntries = WlanAdapter->DesiredPhyCount;
            NdisMoveMemory(phyIdList->dot11PhyId,
                           &WlanAdapter->DesiredPhyList[0],
                           WlanAdapter->DesiredPhyCount * sizeof(ULONG));
        }

        bytesWritten = phyIdList->uNumOfEntries * sizeof(ULONG) + 
                        FIELD_OFFSET(DOT11_PHY_ID_LIST, dot11PhyId);
        bytesNeeded = phyIdList->uTotalNumOfEntries * sizeof(ULONG) +
                       FIELD_OFFSET(DOT11_PHY_ID_LIST, dot11PhyId);
    } while (FALSE);

    NdisRequest->DATA.QUERY_INFORMATION.BytesWritten = bytesWritten;
    NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded = bytesNeeded;
    return ndisStatus;
}

static NDIS_STATUS
WlanSetDesiredPhyList (
    PNDIS_OID_REQUEST NdisRequest,
    PWLAN_ADAPTER     WlanAdapter
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesRead = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_PHY_ID_LIST phyIdList;

    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;    
    
    do {
        if (informationBufferLength < FIELD_OFFSET(DOT11_PHY_ID_LIST, dot11PhyId)) {
            bytesNeeded = FIELD_OFFSET(DOT11_PHY_ID_LIST, dot11PhyId);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        phyIdList = (PDOT11_PHY_ID_LIST)informationBuffer;
        if (!WLAN_VERIFY_NDIS_OBJECT_HEADER_DEFAULT(phyIdList->Header, 
                                                    NDIS_OBJECT_TYPE_DEFAULT,
                                                    DOT11_PHY_ID_LIST_REVISION_1,
                                                    sizeof(DOT11_PHY_ID_LIST))) {
            ndisStatus = NDIS_STATUS_INVALID_DATA;
            break;
        }

        if (phyIdList->uNumOfEntries < 1) {
            ndisStatus = NDIS_STATUS_INVALID_DATA;
            break;
        }

        bytesNeeded = phyIdList->uNumOfEntries * sizeof(ULONG) + FIELD_OFFSET(DOT11_PHY_ID_LIST, dot11PhyId);

        if (informationBufferLength < bytesNeeded) {
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }
        
        if (phyIdList->uNumOfEntries > WLAN_PHY_MAX_COUNT) {
            bytesRead = FIELD_OFFSET(DOT11_PHY_ID_LIST, dot11PhyId);
            ndisStatus = NDIS_STATUS_INVALID_LENGTH;
            break;
        }
    
        /* TODO this is probably not good enough? */
        WlanAdapter->DesiredPhyCount = phyIdList->uNumOfEntries;
        NdisMoveMemory(&WlanAdapter->DesiredPhyList[0], phyIdList->dot11PhyId,
                       WlanAdapter->DesiredPhyCount * sizeof(ULONG));
        bytesRead = bytesNeeded;
    } while (FALSE);

    NdisRequest->DATA.SET_INFORMATION.BytesNeeded = bytesNeeded;
    NdisRequest->DATA.SET_INFORMATION.BytesRead = bytesRead;
    return ndisStatus;
}

static NDIS_STATUS
WlanQueryActivePhyList (
    PNDIS_OID_REQUEST NdisRequest,
    PWLAN_ADAPTER     WlanAdapter
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesWritten = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_PHY_ID_LIST phyIdList;

    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;

    do {
        if (informationBufferLength < sizeof(DOT11_PHY_ID_LIST)) {
            bytesNeeded = sizeof(DOT11_PHY_ID_LIST);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }
        NdisZeroMemory(informationBuffer, informationBufferLength);

        phyIdList = (PDOT11_PHY_ID_LIST)informationBuffer;
        WLAN_ASSIGN_NDIS_OBJECT_HEADER(phyIdList->Header, 
                                       NDIS_OBJECT_TYPE_DEFAULT,
                                       DOT11_PHY_ID_LIST_REVISION_1,
                                       sizeof(DOT11_PHY_ID_LIST));

        phyIdList->uTotalNumOfEntries = 1;      
        if (informationBufferLength < 
            FIELD_OFFSET(DOT11_PHY_ID_LIST, dot11PhyId) + phyIdList->uTotalNumOfEntries * sizeof(ULONG)) {
            phyIdList->uNumOfEntries = 0;
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
        }
        else {
            phyIdList->uNumOfEntries = 1;
            phyIdList->dot11PhyId[0] = WlanAdapter->DesiredPhyList[0];
        }

        bytesWritten = phyIdList->uNumOfEntries * sizeof(ULONG) + 
                        FIELD_OFFSET(DOT11_PHY_ID_LIST, dot11PhyId);
            
        bytesNeeded = phyIdList->uTotalNumOfEntries * sizeof(ULONG) +
                       FIELD_OFFSET(DOT11_PHY_ID_LIST, dot11PhyId);
    } while (FALSE);

    NdisRequest->DATA.QUERY_INFORMATION.BytesWritten = bytesWritten;
    NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded = bytesNeeded;
    return ndisStatus;
}

static NDIS_STATUS
WlanQuerySupportedPhyTypes (
    PNDIS_OID_REQUEST NdisRequest,
    PDOT11_SUPPORTED_PHY_TYPES PhyTypes
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesWritten = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_SUPPORTED_PHY_TYPES supportedPhyTypes;
    ULONG maxEntries = 0;
    
    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;

    do {
        if (informationBufferLength < FIELD_OFFSET(DOT11_SUPPORTED_PHY_TYPES, dot11PHYType)) {
            ndisStatus = NDIS_STATUS_INVALID_LENGTH;
            bytesNeeded = FIELD_OFFSET(DOT11_SUPPORTED_PHY_TYPES, dot11PHYType);
            break;
        }

        supportedPhyTypes = (PDOT11_SUPPORTED_PHY_TYPES)informationBuffer;

        informationBufferLength -= FIELD_OFFSET(DOT11_SUPPORTED_PHY_TYPES, dot11PHYType);
        maxEntries = informationBufferLength / sizeof(DOT11_PHY_TYPE);

        /* Only one PHY type */
        if (maxEntries < PhyTypes->uNumOfEntries) {            
            supportedPhyTypes->uTotalNumOfEntries = 1;
            supportedPhyTypes->uNumOfEntries = 0;
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
        }
        else {
            supportedPhyTypes->uTotalNumOfEntries = 1;
            supportedPhyTypes->uNumOfEntries = 1;            
            supportedPhyTypes->dot11PHYType[0] = PhyTypes->dot11PHYType[0];           
        }     

        bytesWritten = FIELD_OFFSET(DOT11_SUPPORTED_PHY_TYPES, dot11PHYType) +
                        supportedPhyTypes->uNumOfEntries * sizeof(DOT11_PHY_TYPE);
        
        bytesNeeded = FIELD_OFFSET(DOT11_SUPPORTED_PHY_TYPES, dot11PHYType) +
                        supportedPhyTypes->uTotalNumOfEntries * sizeof(DOT11_PHY_TYPE);
    } while (FALSE);

    NdisRequest->DATA.QUERY_INFORMATION.BytesWritten = bytesWritten;
    NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded = bytesNeeded;
    return ndisStatus;
}

static NDIS_STATUS
WlanQueryExstaCapability (
    PADAPTER          Adapter,
    PNDIS_OID_REQUEST NdisRequest
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesWritten = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_EXTSTA_CAPABILITY Dot11ExtStaCap;

    pwa;
    Adapter;

    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;

    do {
        if (informationBufferLength < sizeof(DOT11_EXTSTA_CAPABILITY)) {
            bytesNeeded = sizeof(DOT11_EXTSTA_CAPABILITY);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }
        NdisZeroMemory(informationBuffer, informationBufferLength);

        Dot11ExtStaCap = (PDOT11_EXTSTA_CAPABILITY)informationBuffer;

        WLAN_ASSIGN_NDIS_OBJECT_HEADER(Dot11ExtStaCap->Header, 
            NDIS_OBJECT_TYPE_DEFAULT,
            DOT11_EXTSTA_CAPABILITY_REVISION_1,
            sizeof(DOT11_EXTSTA_CAPABILITY));
        Dot11ExtStaCap->uScanSSIDListSize = WLAN_BSSID_MAX_COUNT;
        Dot11ExtStaCap->uDesiredBSSIDListSize = 1;
        Dot11ExtStaCap->uDesiredSSIDListSize = 1;
        Dot11ExtStaCap->uExcludedMacAddressListSize = 4;
        Dot11ExtStaCap->uPrivacyExemptionListSize = 32;
        Dot11ExtStaCap->uKeyMappingTableSize = 32;
        Dot11ExtStaCap->uDefaultKeyTableSize = 4;
        Dot11ExtStaCap->uWEPKeyValueMaxLength = 104 / 8;
        Dot11ExtStaCap->uPMKIDCacheSize = 3;
        Dot11ExtStaCap->uMaxNumPerSTADefaultKeyTables = 32;

        bytesWritten = sizeof(DOT11_EXTSTA_CAPABILITY);
        bytesNeeded = sizeof(DOT11_EXTSTA_CAPABILITY);
    } while (FALSE);

    NdisRequest->DATA.QUERY_INFORMATION.BytesWritten = bytesWritten;
    NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded = bytesNeeded;
    return ndisStatus;
}

static NDIS_STATUS
WlanQueryPrivacyExemptionList (
    PADAPTER          Adapter,
    PNDIS_OID_REQUEST NdisRequest
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesWritten = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_PRIVACY_EXEMPTION_LIST privacyList;
    PDOT11_PRIVACY_EXEMPTION_LIST currentList;
    
    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;

    do {
        if (informationBufferLength < FIELD_OFFSET(DOT11_PRIVACY_EXEMPTION_LIST, PrivacyExemptionEntries)) {
            bytesNeeded = FIELD_OFFSET(DOT11_PRIVACY_EXEMPTION_LIST, PrivacyExemptionEntries);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }
        NdisZeroMemory(informationBuffer, informationBufferLength);

        privacyList = (PDOT11_PRIVACY_EXEMPTION_LIST)informationBuffer;

        WLAN_ASSIGN_NDIS_OBJECT_HEADER(privacyList->Header, 
                                       NDIS_OBJECT_TYPE_DEFAULT,
                                       DOT11_PRIVACY_EXEMPTION_LIST_REVISION_1,
                                       sizeof(DOT11_PRIVACY_EXEMPTION_LIST));
        privacyList->uNumOfEntries = 0;
        privacyList->uTotalNumOfEntries = 0;
        currentList = pwa->PrivacyExemptionList;

        do {
            if ((currentList == NULL)||(currentList->uNumOfEntries == 0)) {
                /* Empty list, just return success with not entries */
                ndisStatus = NDIS_STATUS_SUCCESS;
                break;
            }
    
            if (FIELD_OFFSET(DOT11_PRIVACY_EXEMPTION_LIST, PrivacyExemptionEntries) > 
                     (FIELD_OFFSET(DOT11_PRIVACY_EXEMPTION_LIST, PrivacyExemptionEntries) + 
                      currentList->uNumOfEntries * sizeof(DOT11_PRIVACY_EXEMPTION))) {
                ndisStatus = NDIS_STATUS_FAILURE;
                break;
            }

            privacyList->uTotalNumOfEntries = currentList->uNumOfEntries;
            if (informationBufferLength < (FIELD_OFFSET(DOT11_PRIVACY_EXEMPTION_LIST, PrivacyExemptionEntries) +
                                           currentList->uNumOfEntries * sizeof(DOT11_PRIVACY_EXEMPTION)))  {
                
                ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
                break;
            }
            /* Have enough room, copy in list data */
            privacyList->uNumOfEntries = currentList->uNumOfEntries;
            NdisMoveMemory(privacyList->PrivacyExemptionEntries,
                           currentList->PrivacyExemptionEntries,
                           currentList->uNumOfEntries * sizeof(DOT11_PRIVACY_EXEMPTION));
        } while (FALSE);
            
        bytesWritten = FIELD_OFFSET(DOT11_PRIVACY_EXEMPTION_LIST, PrivacyExemptionEntries) +
                        privacyList->uNumOfEntries * sizeof(DOT11_PRIVACY_EXEMPTION);
        bytesNeeded = FIELD_OFFSET(DOT11_PRIVACY_EXEMPTION_LIST, PrivacyExemptionEntries) +
                       privacyList->uTotalNumOfEntries * sizeof(DOT11_PRIVACY_EXEMPTION);
    } while (FALSE);

    NdisRequest->DATA.QUERY_INFORMATION.BytesWritten = bytesWritten;
    NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded = bytesNeeded;
    return ndisStatus;
}

static NDIS_STATUS
WlanSetPrivacyExemptionList (
    PADAPTER          Adapter,
    PNDIS_OID_REQUEST NdisRequest
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesRead = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_PRIVACY_EXEMPTION_LIST privacyList;
    PDOT11_PRIVACY_EXEMPTION_LIST currentList;

    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;    
    
    do {        
        if (informationBufferLength < FIELD_OFFSET(DOT11_PRIVACY_EXEMPTION_LIST, PrivacyExemptionEntries)) {
            bytesNeeded = FIELD_OFFSET(DOT11_PRIVACY_EXEMPTION_LIST, PrivacyExemptionEntries);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        privacyList = (PDOT11_PRIVACY_EXEMPTION_LIST)informationBuffer;

        if (!WLAN_VERIFY_NDIS_OBJECT_HEADER_DEFAULT(privacyList->Header, 
                                                    NDIS_OBJECT_TYPE_DEFAULT,
                                                    DOT11_PRIVACY_EXEMPTION_LIST_REVISION_1,
                                                    sizeof(DOT11_PRIVACY_EXEMPTION_LIST))) {
            ndisStatus = NDIS_STATUS_INVALID_DATA;
            break;
        }

        bytesNeeded = FIELD_OFFSET(DOT11_PRIVACY_EXEMPTION_LIST, PrivacyExemptionEntries) +
                      privacyList->uNumOfEntries * sizeof(DOT11_PRIVACY_EXEMPTION);
            
        if (informationBufferLength < bytesNeeded) {
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        /* Blow away any current buffer and just allocated a new one */
        if (pwa->PrivacyExemptionList != NULL) {
            NdisFreeMemory(pwa->PrivacyExemptionList, 0, 0);
            pwa->PrivacyExemptionList = NULL;
        }

        currentList = 
            (PDOT11_PRIVACY_EXEMPTION_LIST)NdisAllocateMemoryWithTagPriority(Adapter->NdisAdapterHandle,
                                                                             bytesNeeded, '_nwx', NormalPoolPriority);
        if (currentList == NULL) {
            ndisStatus = NDIS_STATUS_RESOURCES;
            break;
        }

        currentList->uNumOfEntries = privacyList->uNumOfEntries;
        if (currentList->uNumOfEntries > 0) {
            NdisMoveMemory(currentList->PrivacyExemptionEntries,
                           privacyList->PrivacyExemptionEntries,
                           privacyList->uNumOfEntries * sizeof(DOT11_PRIVACY_EXEMPTION));
        }

        pwa->PrivacyExemptionList = currentList;
        bytesRead = bytesNeeded;
    } while (FALSE);

    NdisRequest->DATA.SET_INFORMATION.BytesNeeded = bytesNeeded;
    NdisRequest->DATA.SET_INFORMATION.BytesRead = bytesRead;

    return ndisStatus;
}

static NDIS_STATUS
WlanQueryAssociationParameters(
    PADAPTER          Adapter,
    PNDIS_OID_REQUEST NdisRequest
    )
{
    ULONG BytesNeeded = 0;
    ULONG BytesRead = 0;
    ULONG InformationBufferLength;
    PVOID InformationBuffer;
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_ASSOCIATION_PARAMS dot11AssocParams;

    InformationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    InformationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;    

    do
    {
        if (InformationBufferLength < sizeof(DOT11_ASSOCIATION_PARAMS))
        {
            BytesNeeded = sizeof(DOT11_ASSOCIATION_PARAMS);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        NdisZeroMemory(InformationBuffer, InformationBufferLength);

        dot11AssocParams = (PDOT11_ASSOCIATION_PARAMS)InformationBuffer;
        
        WLAN_ASSIGN_NDIS_OBJECT_HEADER(((PDOT11_ASSOCIATION_PARAMS)InformationBuffer)->Header,
            NDIS_OBJECT_TYPE_DEFAULT,
            DOT11_ASSOCIATION_PARAMS_REVISION_1,
            sizeof(DOT11_ASSOCIATION_PARAMS));

        BytesNeeded = sizeof(DOT11_ASSOCIATION_PARAMS) + pwa->AdditionalIESize;
        if (InformationBufferLength < BytesNeeded)
        {
            BytesRead = 0;
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        NdisMoveMemory(dot11AssocParams->BSSID, pwa->AssociatedBss.Entry.dot11BSSID, ETH_LENGTH_OF_ADDRESS);
        dot11AssocParams->uAssocRequestIEsLength = pwa->AdditionalIESize;
        dot11AssocParams->uAssocRequestIEsOffset = sizeof(DOT11_ASSOCIATION_PARAMS);

        if (pwa->AdditionalIESize > 0)
        {
            PVOID ptr = (PVOID)((PUCHAR)dot11AssocParams + sizeof(DOT11_ASSOCIATION_PARAMS));
            NdisMoveMemory(
                ptr,
                pwa->AdditionalIEData,
                pwa->AdditionalIESize);
        }                  

        BytesRead = BytesNeeded;
    } while(FALSE);

    NdisRequest->DATA.SET_INFORMATION.BytesNeeded = BytesNeeded;
    NdisRequest->DATA.SET_INFORMATION.BytesRead = BytesRead;

    return ndisStatus;
}

static NDIS_STATUS
WlanSetAssociationParameters(
    PADAPTER          Adapter,
    PNDIS_OID_REQUEST NdisRequest
    )
{
    ULONG BytesNeeded = 0;
    ULONG BytesRead = 0;
    ULONG InformationBufferLength;
    PVOID InformationBuffer;
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_ASSOCIATION_PARAMS dot11AssocParams = NULL;
    PVOID tmpBuf = NULL;

    InformationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    InformationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;    

    do
    {
        BytesRead = 0;
        BytesNeeded = 0;

        if (InformationBufferLength < sizeof(DOT11_ASSOCIATION_PARAMS))
        {
            BytesNeeded = sizeof(DOT11_ASSOCIATION_PARAMS);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        dot11AssocParams = (PDOT11_ASSOCIATION_PARAMS)InformationBuffer;

        if (!WLAN_VERIFY_NDIS_OBJECT_HEADER_DEFAULT(dot11AssocParams->Header, 
                NDIS_OBJECT_TYPE_DEFAULT,
                DOT11_ASSOCIATION_PARAMS_REVISION_1,
                sizeof(DOT11_ASSOCIATION_PARAMS)))
        {
            ndisStatus = NDIS_STATUS_INVALID_DATA;
            break;            
        }

        //
        // Verify IE blob length
        //
        BytesNeeded = dot11AssocParams->uAssocRequestIEsOffset + dot11AssocParams->uAssocRequestIEsLength;
        if (InformationBufferLength < BytesNeeded)
        {
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }
        
        if (dot11AssocParams->uAssocRequestIEsLength > 0)
        {
            PVOID ptr;

            tmpBuf = NdisAllocateMemoryWithTagPriority(
                Adapter->NdisAdapterHandle,
                dot11AssocParams->uAssocRequestIEsLength,
                '_nwx', NormalPoolPriority);

            if (tmpBuf == NULL) 
            {
                BytesRead = sizeof(DOT11_ASSOCIATION_PARAMS);
                ndisStatus = NDIS_STATUS_RESOURCES;
                break;
            }

            ptr = (PVOID)((PUCHAR)dot11AssocParams + dot11AssocParams->uAssocRequestIEsOffset);

            NdisMoveMemory(tmpBuf, 
                ptr,
                dot11AssocParams->uAssocRequestIEsLength);
        }

        if (pwa->AdditionalIEData)
        {
            NdisFreeMemory(pwa->AdditionalIEData, 0, 0);
        }

        // Save the parameters
        NdisMoveMemory(pwa->DesiredBss.Entry.dot11BSSID, dot11AssocParams->BSSID, ETH_LENGTH_OF_ADDRESS);
        pwa->AdditionalIESize = dot11AssocParams->uAssocRequestIEsLength;
        pwa->AdditionalIEData = tmpBuf;

        BytesRead = BytesNeeded;

    } while(FALSE);

    NdisRequest->DATA.SET_INFORMATION.BytesNeeded = BytesNeeded;
    NdisRequest->DATA.SET_INFORMATION.BytesRead = BytesRead;

    return ndisStatus;
}

static NDIS_STATUS
WlanQueryExcludedMacList (
    PNDIS_OID_REQUEST NdisRequest
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesWritten = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_MAC_ADDRESS_LIST macAddrList;

    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;

    do {
        if (informationBufferLength < FIELD_OFFSET(DOT11_MAC_ADDRESS_LIST, MacAddrs)) {
            bytesNeeded = FIELD_OFFSET(DOT11_MAC_ADDRESS_LIST, MacAddrs);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        NdisZeroMemory(informationBuffer, informationBufferLength);
        macAddrList = (PDOT11_MAC_ADDRESS_LIST)informationBuffer;

        WLAN_ASSIGN_NDIS_OBJECT_HEADER(macAddrList->Header, 
                                       NDIS_OBJECT_TYPE_DEFAULT,
                                       DOT11_MAC_ADDRESS_LIST_REVISION_1,
                                       sizeof(DOT11_MAC_ADDRESS_LIST));
        macAddrList->uNumOfEntries = 0;
        macAddrList->uTotalNumOfEntries = 0;
        
        /* TODO for now, just return an empty list - this may be good enough */           
        bytesWritten = macAddrList->uNumOfEntries * sizeof(DOT11_MAC_ADDRESS_LIST) + 
            FIELD_OFFSET(DOT11_MAC_ADDRESS_LIST, MacAddrs);
        bytesNeeded = macAddrList->uTotalNumOfEntries * sizeof(DOT11_MAC_ADDRESS_LIST) +
            FIELD_OFFSET(DOT11_MAC_ADDRESS_LIST, MacAddrs);
    } while (FALSE);

    NdisRequest->DATA.QUERY_INFORMATION.BytesWritten = bytesWritten;
    NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded = bytesNeeded;
    return ndisStatus;
}

static NDIS_STATUS
WlanSetExcludedMacList (
    PNDIS_OID_REQUEST NdisRequest
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesRead = 0;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    PDOT11_MAC_ADDRESS_LIST macAddrList;

    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;    
    
    do {
        if (informationBufferLength < FIELD_OFFSET(DOT11_MAC_ADDRESS_LIST, MacAddrs)) {
            bytesNeeded = FIELD_OFFSET(DOT11_MAC_ADDRESS_LIST, MacAddrs);
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            break;
        }

        macAddrList = (PDOT11_MAC_ADDRESS_LIST)informationBuffer;

        if (!WLAN_VERIFY_NDIS_OBJECT_HEADER_DEFAULT(macAddrList->Header, 
                                                    NDIS_OBJECT_TYPE_DEFAULT,
                                                    DOT11_MAC_ADDRESS_LIST_REVISION_1,
                                                    sizeof(DOT11_MAC_ADDRESS_LIST))) {
            ndisStatus = NDIS_STATUS_INVALID_DATA;
            break;
        }

        /* TODO for now, just indicate we read the whole thing */
        bytesRead = bytesNeeded = informationBufferLength;
    } while (FALSE);

    NdisRequest->DATA.SET_INFORMATION.BytesNeeded = bytesNeeded;
    NdisRequest->DATA.SET_INFORMATION.BytesRead = bytesRead;
    return ndisStatus;
}

NDIS_STATUS 
WlanAdapterQueryInformation (
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
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    NDIS_OID oid;    
    DOT11_CURRENT_OPERATION_MODE currentOperationMode = {0};
    BOOLEAN bVal;

    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;
    oid = NdisRequest->DATA.QUERY_INFORMATION.Oid;

    switch (oid) {
        case OID_DOT11_MPDU_MAX_LENGTH:
            infoData = WLAN_MAX_MPDU_LENGTH;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;
        case OID_DOT11_OPERATION_MODE_CAPABILITY:
            info = &pwa->OperationModeCapability;
            bytesAvailable = infoLength = sizeof(DOT11_OPERATION_MODE_CAPABILITY);
            break;
        case OID_DOT11_CURRENT_OPERATION_MODE:
            currentOperationMode.uCurrentOpMode = DOT11_OPERATION_MODE_EXTENSIBLE_STATION | DOT11_OPERATION_MODE_NETWORK_MONITOR;
            info = &currentOperationMode;
            bytesAvailable = infoLength = sizeof(DOT11_CURRENT_OPERATION_MODE);
            break;
        case OID_DOT11_NIC_POWER_STATE:            
            infoData = pwa->RadioOn;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(BOOLEAN);
            break;
        case OID_DOT11_DATA_RATE_MAPPING_TABLE:
            if (informationBufferLength < sizeof(DOT11_DATA_RATE_MAPPING_TABLE)) {
                doCopy = FALSE;
            }
            info = &pwa->OperationalRateMap;
            bytesAvailable = infoLength = sizeof(DOT11_DATA_RATE_MAPPING_TABLE);
            break;
        case OID_DOT11_OPERATIONAL_RATE_SET:            
            if (informationBufferLength < sizeof(DOT11_RATE_SET)) {
                doCopy = FALSE;
            }
            info = &pwa->OperationalRateSet;
            bytesAvailable = infoLength = sizeof(DOT11_RATE_SET);
            break;
        case OID_DOT11_BEACON_PERIOD:
            if (pwa->BSSType != dot11_BSS_type_independent)
            {
                doCopy = FALSE;
                bytesNeeded = infoLength;
                bytesWritten = 0;
                ndisStatus = NDIS_STATUS_INVALID_STATE;
                break;
            }
            infoData = pwa->DesiredBss.Entry.usBeaconPeriod;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
           break;
        case OID_DOT11_PERMANENT_ADDRESS:
        case OID_DOT11_STATION_ID:
            info = Adapter->PermanentAddress;
            bytesAvailable = infoLength = ETH_LENGTH_OF_ADDRESS;
            break;
        case OID_DOT11_CURRENT_ADDRESS:
        case OID_DOT11_MAC_ADDRESS:
            info = Adapter->CurrentAddress;
            bytesAvailable = infoLength = ETH_LENGTH_OF_ADDRESS;
            break;
        case OID_DOT11_RTS_THRESHOLD:
            info = &pwa->RTSThreshold;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;
        case OID_DOT11_FRAGMENTATION_THRESHOLD:
            info = &pwa->FragThreshold;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;
        case OID_DOT11_CURRENT_REG_DOMAIN:
            infoData = DOT11_REG_DOMAIN_OTHER;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;
        case OID_DOT11_REG_DOMAINS_SUPPORT_VALUE:
            if (informationBufferLength < sizeof(DOT11_REG_DOMAINS_SUPPORT_VALUE)) {
                doCopy = FALSE;
            }
            info = &pwa->RegDomains;
            bytesAvailable = infoLength = sizeof(DOT11_REG_DOMAINS_SUPPORT_VALUE);
            break;
        case OID_DOT11_POWER_MGMT_REQUEST:
            info = &pwa->PowerLevel;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;
        case OID_DOT11_DESIRED_SSID_LIST:
            return WlanQueryDesiredSSIDList(NdisRequest, &pwa->DesiredBss.SSID);
        case OID_DOT11_DESIRED_BSSID_LIST:
            return WlanQueryDesiredBSSIDList(NdisRequest, pwa);
        case OID_DOT11_DESIRED_BSS_TYPE:
            info = &pwa->BSSType;
            bytesAvailable = infoLength = sizeof(DOT11_BSS_TYPE);
            break;
        case OID_DOT11_EXCLUDED_MAC_ADDRESS_LIST:
            return WlanQueryExcludedMacList(NdisRequest);
        case OID_DOT11_ENUM_BSS_LIST:
            return WlanEnumerateBSSList(Adapter, NdisRequest);            
        case OID_DOT11_IBSS_PARAMS:
            bytesAvailable = infoLength = sizeof(DOT11_IBSS_PARAMS);
            if (informationBufferLength < infoLength)
            {
                bytesNeeded = infoLength;
                bytesWritten = 0;
                ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
            }
            else
            {
                NdisZeroMemory(informationBuffer, informationBufferLength);
                WLAN_ASSIGN_NDIS_OBJECT_HEADER(
                    ((PDOT11_IBSS_PARAMS)(informationBuffer))->Header, 
                    NDIS_OBJECT_TYPE_DEFAULT,
                    DOT11_IBSS_PARAMS_REVISION_1,
                    sizeof(DOT11_IBSS_PARAMS));
                bytesNeeded = sizeof(DOT11_IBSS_PARAMS);
                bytesWritten = sizeof(DOT11_IBSS_PARAMS);
            }
            NdisRequest->DATA.QUERY_INFORMATION.BytesWritten = bytesWritten;
            NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded = bytesNeeded;
            return ndisStatus;
        case OID_DOT11_STATISTICS:
            if (informationBufferLength < sizeof(DOT11_STATISTICS)) {
                doCopy = FALSE;
            }
            WlanAdapterUpdateStatistics(Adapter);
            if (WpaOrRsnaAuth(pwa->AuthAlgorithm))
                pwa->Stats.ullFourWayHandshakeFailures = 0;
            if (pwa->AssociatedBss.GroupCipher.Tkip)
                pwa->Stats.ullTKIPCounterMeasuresInvoked  = 0;
            info = &pwa->Stats;
            bytesAvailable = infoLength = sizeof(DOT11_STATISTICS);
            break;
        case OID_DOT11_ENABLED_AUTHENTICATION_ALGORITHM:
            return WlanQueryEnabledAuthenticationAlgorithm(NdisRequest, pwa);
        case OID_DOT11_ENABLED_UNICAST_CIPHER_ALGORITHM:
            return WlanQueryEnabledCipherAlgorithm(NdisRequest, pwa, TRUE);
        case OID_DOT11_ENABLED_MULTICAST_CIPHER_ALGORITHM:
            return WlanQueryEnabledCipherAlgorithm(NdisRequest, pwa, FALSE);
        case OID_DOT11_SUPPORTED_UNICAST_ALGORITHM_PAIR:
            return WlanQuerySupportedAlgorithmPair(NdisRequest, pwa, TRUE);
        case OID_DOT11_SUPPORTED_MULTICAST_ALGORITHM_PAIR:
            return WlanQuerySupportedAlgorithmPair(NdisRequest, pwa, FALSE);
        case OID_DOT11_ENUM_ASSOCIATION_INFO:
            return WlanQueryAssociationInfo(Adapter, NdisRequest);
        case OID_DOT11_DESIRED_PHY_LIST:
            return WlanQueryDesiredPhyList(NdisRequest, pwa);
        case OID_DOT11_CURRENT_PHY_ID:
            info = &pwa->CurrentPhyId;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;
        case OID_DOT11_HARDWARE_PHY_STATE:
            infoData = pwa->PhyEnabled;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(BOOLEAN);
            break;
        case OID_DOT11_UNREACHABLE_DETECTION_THRESHOLD:
            info = &pwa->UDThreshold;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;
        case OID_DOT11_ACTIVE_PHY_LIST:
            if ((pwa->State & WLAN_STATE_CONNECTED) == 0) {
                ndisStatus = NDIS_STATUS_INVALID_STATE;
                break;
            }       
            return WlanQueryActivePhyList(NdisRequest, pwa);
        case OID_DOT11_AUTO_CONFIG_ENABLED:
            info = &pwa->AutoConfig;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;
        case OID_DOT11_MEDIA_STREAMING_ENABLED:
            infoData = pwa->MediaStreaming;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(BOOLEAN);
            break;
        case OID_DOT11_MULTI_DOMAIN_CAPABILITY_IMPLEMENTED:
        case OID_DOT11_SAFE_MODE_ENABLED:
            bVal = FALSE; /* turned off in DOT11_EXTSTA_ATTRIBUTES */
            infoData = bVal;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(BOOLEAN);
            break;
        case OID_DOT11_HIDDEN_NETWORK_ENABLED:            
            infoData = pwa->HiddenNetworks;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(BOOLEAN);
            break;
        case OID_DOT11_SUPPORTED_PHY_TYPES:
            return WlanQuerySupportedPhyTypes(NdisRequest, &pwa->SupportedPhyTypes);
        case OID_DOT11_EXCLUDE_UNENCRYPTED:
            bVal = FALSE; /* no crypto - always accept unencrypted */
            infoData = bVal;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(BOOLEAN);
            break;
        case OID_DOT11_PRIVACY_EXEMPTION_LIST:
            return WlanQueryPrivacyExemptionList(Adapter, NdisRequest);
        case OID_DOT11_EXTSTA_CAPABILITY:
            return WlanQueryExstaCapability(Adapter, NdisRequest);
            break;
        case OID_DOT11_UNICAST_USE_GROUP_ENABLED:
            bVal = FALSE; //@@@ No group key cipher in use
            infoData = bVal;
            info = &infoData;
            bytesAvailable = infoLength = sizeof(BOOLEAN);
            break;
        case OID_DOT11_MULTICAST_LIST:
            info = &Adapter->MulticastAddresses[0];
            bytesAvailable = infoLength = 
                Adapter->MulticastAddressesCount * sizeof(ETHERNET_ADDRESS);
            break;
        case OID_DOT11_ASSOCIATION_PARAMS:
            return WlanQueryAssociationParameters(Adapter, NdisRequest);
            break;
        case OID_DOT11_CURRENT_CHANNEL:
            info = &pwa->CurrentChannel;
            bytesAvailable = infoLength = sizeof(ULONG);
            break;
        case OID_DOT11_PMKID_LIST:
            return WlanQueryPmkidList(pwa, NdisRequest);
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

        }
        else {
            bytesNeeded = infoLength;
            bytesWritten = informationBufferLength;
            ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
        }

        if (!doCopy) {
            bytesWritten = 0;
        }

        if (bytesWritten && doCopy) {
            NdisMoveMemory(informationBuffer, info, bytesWritten);
        }
    }
    
    NdisRequest->DATA.QUERY_INFORMATION.BytesWritten = bytesWritten;
    NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded = bytesNeeded;
    return ndisStatus;
}

NDIS_STATUS 
WlanAdapterSetInformation (
    IN  PADAPTER            Adapter,
    IN  PNDIS_OID_REQUEST   NdisRequest
    )
{
    ULONG bytesNeeded = 0;
    ULONG bytesRead = 0;
    ULONG requiredSize = 0;
    ULONG value;
    ULONG informationBufferLength;
    PVOID informationBuffer;
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    NDIS_OID oid;
    PDOT11_BSS_TYPE bssType;
    DOT11_CURRENT_OPERATION_MODE currentOperationMode;
    PDOT11_RATE_SET rateSet = NULL;    
    PDOT11_BYTE_ARRAY keyData;
    ULONG addressCount;

    informationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    informationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;
    oid = NdisRequest->DATA.QUERY_INFORMATION.Oid;

    switch (oid) {
        case OID_DOT11_CURRENT_OPERATION_MODE:            
            if (informationBufferLength < sizeof(DOT11_CURRENT_OPERATION_MODE)) {
                bytesNeeded = sizeof(DOT11_CURRENT_OPERATION_MODE);
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
                break;
            }
            NdisMoveMemory(&currentOperationMode, informationBuffer, sizeof(DOT11_CURRENT_OPERATION_MODE));
            if ((currentOperationMode.uCurrentOpMode != DOT11_OPERATION_MODE_EXTENSIBLE_STATION) &&
               (currentOperationMode.uCurrentOpMode != DOT11_OPERATION_MODE_NETWORK_MONITOR)) {
                ndisStatus = NDIS_STATUS_INVALID_DATA;
                break;
            }
            bytesRead = sizeof(DOT11_CURRENT_OPERATION_MODE);
            break;
        case OID_DOT11_NIC_POWER_STATE:
            if (informationBufferLength < sizeof(ULONG)) {
                bytesNeeded = sizeof(ULONG);
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
                break;
            }
            /* To prevent problems with guest power level changes, let it toggle the way the OS wants */            
            value = *((PULONG)informationBuffer);
            pwa->RadioOn = (BOOLEAN)value;
            bytesRead = sizeof(ULONG);

            /* Stop any running scan - see notes in WlanResetRequest */
            if (!pwa->RadioOn) {
                NdisAcquireSpinLock(&(pwa->Lock));
                if (pwa->State & WLAN_STATE_SCANNING) {
                    pwa->State |= WLAN_STATE_STOPSCAN;
                }
                NdisReleaseSpinLock(&(pwa->Lock));
            }
            break;
        case OID_DOT11_OPERATIONAL_RATE_SET:
            requiredSize = FIELD_OFFSET(DOT11_RATE_SET, ucRateSet);
            if (informationBufferLength < requiredSize) {
                bytesNeeded = requiredSize;
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
                break;
            }

            rateSet = (PDOT11_RATE_SET)informationBuffer;
            
            if ((rateSet->uRateSetLength > DOT11_RATE_SET_MAX_LENGTH)||(rateSet->uRateSetLength == 0)) {
                bytesNeeded = requiredSize;
                ndisStatus = NDIS_STATUS_INVALID_DATA;
                break;
            }

            requiredSize += rateSet->uRateSetLength;
            if (informationBufferLength < requiredSize) {
                bytesNeeded = requiredSize;
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
                break;
            }

            /* Just copy whatever was passed to us - TODO is this enough? */
            bytesRead = requiredSize;
            NdisZeroMemory(&pwa->OperationalRateSet, sizeof(DOT11_RATE_SET));
            NdisMoveMemory(&pwa->OperationalRateSet, rateSet, requiredSize);
            break;
        case OID_DOT11_BEACON_PERIOD:
            if (informationBufferLength < sizeof(ULONG)) {
                bytesNeeded = sizeof(ULONG);
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
                break;
            }
            if (pwa->BSSType != dot11_BSS_type_infrastructure) {
                ndisStatus = NDIS_STATUS_INVALID_DATA;
                break;
            }
            value = *((PULONG)informationBuffer);
            TraceNotice (("SETTING BEACON PERIOD TO: %d\n", value));
            if (value < 1 || value > 65535) {
                ndisStatus = NDIS_STATUS_INVALID_DATA;
                break;
            }
            bytesRead = sizeof(ULONG);
            pwa->DesiredBss.Entry.usBeaconPeriod = (USHORT)value;
            break;
        case OID_DOT11_RTS_THRESHOLD:
            if (informationBufferLength < sizeof(ULONG)) {
                bytesNeeded = sizeof(ULONG);
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
                break;
            }
            bytesRead = sizeof(ULONG);
            value = *((PULONG)informationBuffer);
            if (value > WLAN_MAX_MPDU_LENGTH + 1) {
                ndisStatus = NDIS_STATUS_INVALID_DATA;
                break;
            }

            pwa->RTSThreshold = value;
            break;
        case OID_DOT11_FRAGMENTATION_THRESHOLD:
            if (informationBufferLength < sizeof(ULONG)) {
                bytesNeeded = sizeof(ULONG);
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
                break;
            }
            bytesRead = sizeof(ULONG);
            value = *((PULONG)informationBuffer);


            if (value > WLAN_MAX_MPDU_LENGTH) {
                pwa->FragThreshold = WLAN_MAX_MPDU_LENGTH;
            }
            else if (value < 256) {
                pwa->FragThreshold = 256;
            }
            else {
                pwa->FragThreshold = value;
            }
            break;
        case OID_DOT11_CURRENT_REG_DOMAIN:
            /* Don't have to allow setting */
            ndisStatus = NDIS_STATUS_NOT_SUPPORTED;
            break;
        case OID_DOT11_SCAN_REQUEST:
            return WlanScanRequest(Adapter, NdisRequest);
        case OID_DOT11_FLUSH_BSS_LIST:
            /* Just remove all entries */
            pwa->ScannedBssCount = 0;
            break;
        case OID_DOT11_POWER_MGMT_REQUEST:
            if (informationBufferLength < sizeof(ULONG)) {
                bytesNeeded = sizeof(ULONG);
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
                break;
            }
            bytesRead = sizeof(ULONG);
            /* Again, try to honor changes to power levels to allow host power state changes */
            pwa->PowerLevel = *((PULONG)informationBuffer);
            break;
        case OID_DOT11_DESIRED_SSID_LIST:
            return WlanSetDesiredSSIDList(pwa, NdisRequest);
        case OID_DOT11_DESIRED_BSSID_LIST:
            return WlanSetDesiredBSSIDList(NdisRequest, pwa);
        case OID_DOT11_ENABLED_AUTHENTICATION_ALGORITHM:
            return WlanSetEnabledAuthenticationAlgorithm(NdisRequest, pwa);
        case OID_DOT11_ENABLED_UNICAST_CIPHER_ALGORITHM:
            return WlanSetEnabledCipherAlgorithm(NdisRequest, pwa, TRUE);
        case OID_DOT11_ENABLED_MULTICAST_CIPHER_ALGORITHM:
            return WlanSetEnabledCipherAlgorithm(NdisRequest, pwa, FALSE);
        case OID_DOT11_DESIRED_BSS_TYPE:
            if (informationBufferLength < sizeof(DOT11_BSS_TYPE)) {
                bytesNeeded = sizeof(DOT11_BSS_TYPE);
                ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
                break;
            }
            bssType = (PDOT11_BSS_TYPE)informationBuffer;
            if (*bssType == dot11_BSS_type_any) {
                ndisStatus = NDIS_STATUS_INVALID_DATA ;
                break;
            }
            pwa->BSSType = *bssType;
            bytesRead = sizeof(DOT11_BSS_TYPE);

            /* These need to be reset when this set OID occurs */
            pwa->AuthAlgorithm = DOT11_AUTH_ALGO_80211_OPEN;
            pwa->UnicastCipherAlgorithm = DOT11_CIPHER_ALGO_NONE;
            pwa->MulticastCipherAlgorithm = DOT11_CIPHER_ALGO_NONE;
            break;
        case OID_DOT11_EXCLUDED_MAC_ADDRESS_LIST:
        case OID_DOT11_IBSS_PARAMS:
            /* TODO try failing these ones */
            ndisStatus = NDIS_STATUS_INVALID_DATA;
            break;
        case OID_DOT11_AUTO_CONFIG_ENABLED:
            if (informationBufferLength < sizeof(ULONG)) {
                bytesNeeded = sizeof(ULONG);
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
                break;
            }
            bytesRead = sizeof(ULONG);
            value = *((PULONG)informationBuffer);            
            pwa->AutoConfig = value;
            break;
        case OID_DOT11_CONNECT_REQUEST:
            if (!pwa->RadioOn) {
                ndisStatus = NDIS_STATUS_DOT11_POWER_STATE_INVALID;
                break;
            }
            if (!pwa->PhyEnabled) {
                ndisStatus = NDIS_STATUS_DOT11_POWER_STATE_INVALID;
                break;
            }
            WlanConnectRequest(Adapter);
            break;
        case OID_DOT11_CIPHER_KEY_MAPPING_KEY:
            bytesNeeded = FIELD_OFFSET(DOT11_BYTE_ARRAY, ucBuffer);
            if (informationBufferLength < sizeof(DOT11_BYTE_ARRAY)) {
                ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
                break;
            }

            keyData = (PDOT11_BYTE_ARRAY)informationBuffer;
            bytesNeeded = FIELD_OFFSET(DOT11_BYTE_ARRAY, ucBuffer) + keyData->uNumOfBytes;

            if (!WLAN_VERIFY_NDIS_OBJECT_HEADER_DEFAULT(keyData->Header, 
                                                        NDIS_OBJECT_TYPE_DEFAULT,
                                                        DOT11_CIPHER_KEY_MAPPING_KEY_VALUE_BYTE_ARRAY_REVISION_1,
                                                        sizeof(DOT11_BYTE_ARRAY))) {
                ndisStatus = NDIS_STATUS_INVALID_DATA;
                break;
            }

            if (informationBufferLength < bytesNeeded) {
                ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
                break;
            }
            
            /* Lie and say we accepted the keys */
            bytesRead = bytesNeeded;
            break;
        case OID_DOT11_DISCONNECT_REQUEST:
            NdisAcquireSpinLock(&(pwa->Lock));
            if ((pwa->State & WLAN_STATE_CONNECTED) == 0) {
                NdisReleaseSpinLock(&(pwa->Lock));
                ndisStatus = NDIS_STATUS_INVALID_STATE;
                break;
            }
//            WlanClearBss (&pwa->AssociatedBss);
//            pwa->State &= ~WLAN_STATE_CONNECTED;
            WlanDisconnectRequest (Adapter, DOT11_DISASSOC_REASON_OS);
            NdisReleaseSpinLock(&(pwa->Lock));
            break;
        case OID_DOT11_MEDIA_STREAMING_ENABLED:
            if (informationBufferLength < sizeof(ULONG)) {
                bytesNeeded = sizeof(ULONG);
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
                break;
            }
            value = *((PULONG)informationBuffer);
            pwa->MediaStreaming = (BOOLEAN)value;
            bytesRead = sizeof(ULONG);
            break;
        case OID_DOT11_SAFE_MODE_ENABLED:           
            ndisStatus = NDIS_STATUS_INVALID_DATA; /* this should never be set */
            break;
        case OID_DOT11_HIDDEN_NETWORK_ENABLED:
            if (informationBufferLength < sizeof(ULONG)) {
                bytesNeeded = sizeof(ULONG);
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
                break;
            }
            value = *((PULONG)informationBuffer);
            pwa->HiddenNetworks = (BOOLEAN)value;
            bytesRead = sizeof(ULONG);
            break;
        case OID_DOT11_DESIRED_PHY_LIST:
            return WlanSetDesiredPhyList(NdisRequest, Adapter->WlanAdapter);
        case OID_DOT11_CURRENT_PHY_ID:
            if (informationBufferLength < sizeof(ULONG)) {
                bytesNeeded = sizeof(ULONG);
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
                break;
            }
            bytesRead = sizeof(ULONG);
            value = *((PULONG)informationBuffer);
            if (value >= WLAN_PHY_MAX_COUNT) {
                ndisStatus = NDIS_STATUS_INVALID_DATA;
                break;
            }
            pwa->CurrentPhyId = value;
            break;
        case OID_DOT11_UNREACHABLE_DETECTION_THRESHOLD:
            if (informationBufferLength < sizeof(ULONG)) {
                bytesNeeded = sizeof(ULONG);
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
                break;
            }
            bytesRead = sizeof(ULONG);
            value = *((PULONG)informationBuffer);           
            pwa->UDThreshold = value;
            break;
        case OID_DOT11_EXCLUDE_UNENCRYPTED:
            if (informationBufferLength < sizeof(ULONG)) {
                bytesNeeded = sizeof(ULONG);
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
                break;
            }
            bytesRead = sizeof(ULONG);
            break;
        case OID_DOT11_PRIVACY_EXEMPTION_LIST:
            return WlanSetPrivacyExemptionList(Adapter, NdisRequest);
        case OID_DOT11_CIPHER_DEFAULT_KEY:
            /* Check the buffer includes the key length field */
            bytesNeeded = FIELD_OFFSET(DOT11_CIPHER_DEFAULT_KEY_VALUE, ucKey);
            if (informationBufferLength < bytesNeeded) {
                ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
                break;
            }
            bytesNeeded +=
                ((PDOT11_CIPHER_DEFAULT_KEY_VALUE)informationBuffer)->usKeyLength;

            if (!WLAN_VERIFY_NDIS_OBJECT_HEADER_DEFAULT(
                ((PDOT11_CIPHER_DEFAULT_KEY_VALUE)informationBuffer)->Header,
                NDIS_OBJECT_TYPE_DEFAULT,
                DOT11_CIPHER_DEFAULT_KEY_VALUE_REVISION_1,
                sizeof(DOT11_CIPHER_DEFAULT_KEY_VALUE))) {
                ndisStatus = NDIS_STATUS_INVALID_DATA;
                break;
            }
            if (informationBufferLength < bytesNeeded) {
                ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
                break;
            }
            /* if we were a real adapter, we'd do something with this key. */
            WlanPrintKey("SetCipherDefaultKey", informationBuffer);
            bytesRead = bytesNeeded;
            break;
        case OID_DOT11_CIPHER_DEFAULT_KEY_ID:
            bytesNeeded = sizeof(ULONG);
            if (informationBufferLength < bytesNeeded) {
                ndisStatus = NDIS_STATUS_BUFFER_OVERFLOW;
                break;
            }
            /* Pretend success. */
            bytesRead = bytesNeeded;
            break;
        case OID_PNP_SET_POWER:
            TraceNotice((" Entering device state %d\n",
                *((PNDIS_DEVICE_POWER_STATE)informationBuffer)));
            if (*((PNDIS_DEVICE_POWER_STATE)informationBuffer) != NdisDeviceStateD0)
                DisableXenWatchpoints (Adapter);
            if (*((PNDIS_DEVICE_POWER_STATE)informationBuffer) == NdisDeviceStateD0)
                EnableXenWatchpoints (Adapter);
            break;
        case OID_DOT11_MULTICAST_LIST:
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
        case OID_DOT11_ASSOCIATION_PARAMS:
            break;
        case OID_DOT11_CURRENT_CHANNEL:
            if (informationBufferLength < sizeof(ULONG)) {
                bytesNeeded = sizeof(ULONG);
                ndisStatus = NDIS_STATUS_INVALID_LENGTH;
                break;
            }
            bytesRead = sizeof(ULONG);
            value = *((PULONG)informationBuffer);           
            pwa->CurrentChannel = value;
            break;
        default:
            TraceError(("'%s': unsupported set information OID 0x%08X!\n", __FUNCTION__, oid));
            ndisStatus = NDIS_STATUS_NOT_SUPPORTED;
            break;
    };

    NdisRequest->DATA.SET_INFORMATION.BytesNeeded = bytesNeeded;
    NdisRequest->DATA.SET_INFORMATION.BytesRead = bytesRead;

    return ndisStatus;
}

NDIS_STATUS
WlanAdapterQuerySetInformation(
    IN  PADAPTER            Adapter,
    IN  PNDIS_OID_REQUEST   NdisRequest
    )
{
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    NDIS_OID oid;
    
    oid = NdisRequest->DATA.METHOD_INFORMATION.Oid;

    switch (oid) {
        case OID_DOT11_RESET_REQUEST:           
            return WlanResetRequest(Adapter, NdisRequest);
        case OID_DOT11_ENUM_BSS_LIST:
            return WlanEnumerateBSSList(Adapter, NdisRequest);            
        default:
            TraceError(("'%s': unsupported method information OID 0x%08X!\n", __FUNCTION__, oid));
            ndisStatus = NDIS_STATUS_NOT_SUPPORTED;
            break;
    };
    
    NdisRequest->DATA.METHOD_INFORMATION.BytesNeeded = 0;
    NdisRequest->DATA.METHOD_INFORMATION.BytesRead = 0;
    NdisRequest->DATA.METHOD_INFORMATION.BytesWritten = 0;

    return ndisStatus;
}

VOID
WlanSendPrepareNetBufferLists (
    IN  PNET_BUFFER_LIST    NetBufferList
    )
{
    PNET_BUFFER_LIST currentNetBufferList;
    PNET_BUFFER currentNetBuffer;
    PMDL mdl;
    ULONG delta;
    PUCHAR headerPtr;
    PDOT11_MAC_BASIC_HEADER macHeader;
    PDOT11_DATA_SHORT_HEADER dataFrameHeader;
    PXENNET_NET_BUFFER_RESERVED xennetBuffer;
    struct ethhdr *ethernetHeader;
    DOT11_MAC_ADDRESS src;
    DOT11_MAC_ADDRESS dest;
    ULONG listCount = 0;
    ULONG bufferCount = 0;

    //TraceNotice(("Tx packet\n"));
    //DumpNbl (NetBufferList);

    currentNetBufferList = NetBufferList;

    while (currentNetBufferList != NULL) {
        listCount++;
        currentNetBuffer = NET_BUFFER_LIST_FIRST_NB(currentNetBufferList);
        while (currentNetBuffer != NULL) {
            bufferCount++;

            /* Initialize the miniport context area here in WLAN drivers. Set our
             * specific values.
             */
            xennetBuffer = XENNET_GET_NET_BUFFER_RESERVED(currentNetBuffer);
            memset(xennetBuffer, 0, sizeof (XENNET_NET_BUFFER_RESERVED));
            xennetBuffer->WlanMagic = XENNET_BUFFER_MAGIC;

            /* Get the current MDL - it should contain the 802.11 MAC header */
            mdl = NET_BUFFER_CURRENT_MDL(currentNetBuffer);
            if (MmGetMdlByteCount(mdl) < sizeof(DOT11_MAC_DATA_HEADER)) {
                /* TODO Not a data frame - for now just skip it */
                TraceNotice(("Tx MDL not big enough for data frame MAC header - size: 0x%x\n", MmGetMdlByteCount(mdl)));
                currentNetBuffer = NET_BUFFER_NEXT_NB(currentNetBuffer);
                continue;
            }
            
            /* Get a pointer to the 802.11 frame MAC header */
            headerPtr = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
            if (headerPtr == NULL) {
                /* Low on system resources, not much that can be done */
                TraceWarning(("'%s': failed to map network buffer MAC header\n", __FUNCTION__));
                return;
            }

            //
            // Test for an EAP packet. If found, mark it, short-circuit the
            // process and send the packet as-is.
            //
            ethernetHeader = (struct ethhdr*)(headerPtr + sizeof(DOT11_MAC_DATA_HEADER) - sizeof(struct ethhdr));
            if (ethernetHeader->proto == ETH_P_EAPOL)
            {
                TraceInfo (("Processing EAPoL packet\n"));
                xennetBuffer->EapPacket = 1;
                currentNetBuffer = NET_BUFFER_NEXT_NB(currentNetBuffer);
                continue;
            }

            headerPtr += NET_BUFFER_CURRENT_MDL_OFFSET(currentNetBuffer);
            macHeader = (PDOT11_MAC_BASIC_HEADER)headerPtr;

            /* Check that this is a data frame being sent to the DS */
            if ((macHeader->FrameControl.Type != DOT11_FRAME_TYPE_DATA)||
                (macHeader->FrameControl.ToDS == 0)) {
                /* TODO Not a data frame - for now just skip it */
                TraceNotice(("not a data frame MAC header - type: %d ToDS: %d\n", 
                              macHeader->FrameControl.Type, macHeader->FrameControl.ToDS));
                currentNetBuffer = NET_BUFFER_NEXT_NB(currentNetBuffer);
                continue;
            }

            /* Now it looks like a data frame MAC header - the last 2 bytes of the 802.11 frame header are a
             * standard ethertype (preceeded by an LLC type SNAP header etc).
             */
            dataFrameHeader = (PDOT11_DATA_SHORT_HEADER)headerPtr;

            /* Save a copy */
            NdisMoveMemory(&src[0], &dataFrameHeader->Address2[0], ETH_LENGTH_OF_ADDRESS);
            NdisMoveMemory(&dest[0], &dataFrameHeader->Address3[0], ETH_LENGTH_OF_ADDRESS);

            /* Now move forward and make an 802.3 header overlaying the back part of the 802.11 header. */
            delta = (sizeof(DOT11_MAC_DATA_HEADER) - sizeof(struct ethhdr));
            ethernetHeader = (struct ethhdr*)(headerPtr + delta);
            NdisMoveMemory(&ethernetHeader->src[0], &src[0], ETH_LENGTH_OF_ADDRESS);
            NdisMoveMemory(&ethernetHeader->dest[0], &dest[0], ETH_LENGTH_OF_ADDRESS);
            NdisAdvanceNetBufferDataStart(currentNetBuffer, delta, FALSE, NULL);

            /* Indicate this NB has a modified frame and needs retreating. */
            xennetBuffer->WlanTxMods = 1;

            /* Move on to next one */
            currentNetBuffer = NET_BUFFER_NEXT_NB(currentNetBuffer);
        }

        /* Move on to next one */
        currentNetBufferList = NET_BUFFER_LIST_NEXT_NBL(currentNetBufferList);
    }
}

VOID
WlanSendNetBufferListsComplete (
    IN  PNET_BUFFER_LIST    NetBufferList
    )
{
    PNET_BUFFER_LIST currentNetBufferList;
    PNET_BUFFER currentNetBuffer;
    PXENNET_NET_BUFFER_RESERVED xennetBuffer;
    ULONG delta;
    ULONG listCount = 0;
    ULONG bufferCount = 0;

    currentNetBufferList = NetBufferList;
    while (currentNetBufferList != NULL) {
        listCount++;
        currentNetBuffer = NET_BUFFER_LIST_FIRST_NB(currentNetBufferList);
        while (currentNetBuffer != NULL) {
            bufferCount++;

            xennetBuffer = XENNET_GET_NET_BUFFER_RESERVED(currentNetBuffer);
            XM_ASSERT3U(xennetBuffer->WlanMagic, ==, XENNET_BUFFER_MAGIC);

            /* Undo the advance during the prepare NB step so NDIS gets back what is expects. */
            if (xennetBuffer->WlanTxMods) {
                delta = (sizeof(DOT11_MAC_DATA_HEADER) - sizeof(struct ethhdr));
                NdisRetreatNetBufferDataStart(currentNetBuffer, delta, 0, NULL);
            }

            /* WLAN drivers have to do the miniport context cleanup. */
            memset(xennetBuffer, 0, sizeof (XENNET_NET_BUFFER_RESERVED));

            /* Move on to next one */
            currentNetBuffer = NET_BUFFER_NEXT_NB(currentNetBuffer);
        }

        /* Move on to next one */
        currentNetBufferList = NET_BUFFER_LIST_NEXT_NBL(currentNetBufferList);
    }
}

VOID
WlanReceivePrepareNetBufferLists (
    IN  PADAPTER            Adapter,
    IN  PNET_BUFFER_LIST    NetBufferList
    )
{
    PNET_BUFFER_LIST currentNetBufferList;
    PNET_BUFFER currentNetBuffer;
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    PMDL mdl;
    ULONG delta, offset;
    PUCHAR headerPtr;
    PUCHAR *ptrPtr;
    PDOT11_MAC_DATA_HEADER macDataHeader;
    struct ethhdr ethernetHeader;
    NDIS_STATUS ndisStatus;
    PDOT11_EXTSTA_RECV_CONTEXT rxContext;
    USHORT count;
    PXEN_WLAN_SIG xenContext;
    ULONG listCount = 0;
    ULONG bufferCount = 0;

    //TraceNotice(("Rx packet:\n"));
    //DumpNbl (NetBufferList);

    currentNetBufferList = NetBufferList;
    while (currentNetBufferList != NULL) {
        listCount++;

        /* Need to create a receive context for OOB information */
        rxContext = (PDOT11_EXTSTA_RECV_CONTEXT)NdisAllocateMemoryWithTagPriority(Adapter->NdisAdapterHandle,
                                                sizeof(DOT11_EXTSTA_RECV_CONTEXT), '_nwx', NormalPoolPriority);
        if (rxContext == NULL) {
            /* Low on system resources, not much that can be done */
            TraceWarning(("'%s': failed to allocate Rx context\n", __FUNCTION__));
            return;
        }

        count = 0;
        currentNetBuffer = NET_BUFFER_LIST_FIRST_NB(currentNetBufferList);
        while (currentNetBuffer != NULL) {
            bufferCount++;
            /* Get the current MDL - it should contain the 802.3 MAC header */
            mdl = NET_BUFFER_CURRENT_MDL(currentNetBuffer);
            if (MmGetMdlByteCount(mdl) < sizeof(struct ethhdr)) {
                /* Not an ethernet data frame - that is not good */
                TraceWarning(("'%s': MDL not big enough for data frame MAC header - size: 0x%x\n", __FUNCTION__, MmGetMdlByteCount(mdl)));
                currentNetBuffer = NET_BUFFER_NEXT_NB(currentNetBuffer);
                continue;
            }
            
            /* Get a pointer to the 802.3 frame MAC header */
            headerPtr = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
            if (headerPtr == NULL) {
                /* Low on system resources, not much that can be done */
                TraceWarning(("'%s': failed to map network buffer 802.3 MAC header\n", __FUNCTION__));
                NdisFreeMemory(rxContext, 0, 0);
                return;
            }

            headerPtr += NET_BUFFER_CURRENT_MDL_OFFSET(currentNetBuffer);
            /* Should be safe to assume the backend is giving us 802.3 frames, save a copy */
            NdisMoveMemory(&ethernetHeader, (struct ethhdr*)headerPtr, sizeof(struct ethhdr));

            /* Pull the front buffer back enough for the 802.11 MAC header. The NDIS routine will do the
             * work of allocating us any new buffers and MDLs if it is needed. If there is not enough
             * room in the first MDL for the retreat, it will chain in a new MDL, else it will back up
             * the byte offset.
             */
            offset = MmGetMdlByteOffset(mdl);

            delta = (sizeof(DOT11_MAC_DATA_HEADER) - sizeof(struct ethhdr));
            //
            // Always use the first case below. The alternative was generating bad pointers in the mdl.
            //
            
            //TODO: Fix this block of code up to avoid manipulating pointer directly

            //if (offset < delta) {
                /* In this case, the whole MAC header will now be in a new MDL at the front. */
                ndisStatus = NdisRetreatNetBufferDataStart(currentNetBuffer, sizeof(DOT11_MAC_DATA_HEADER), 0, NULL);
                if (ndisStatus != NDIS_STATUS_SUCCESS) {
                    /* Low on system resources, not much that can be done */
                    TraceWarning(("'%s': failed to retreat network buffer MAC header\n", __FUNCTION__));
                    NdisFreeMemory(rxContext, 0, 0);
                    return;
                }
                /* In the current MDL, move the byte offset forward over the 802.3 header. */
                ptrPtr = (PUCHAR*)&mdl->MappedSystemVa;
                *ptrPtr += sizeof(struct ethhdr);
                mdl->ByteOffset += sizeof(struct ethhdr);
                mdl->ByteCount -= sizeof(struct ethhdr);                

                /* Get the new current MDL and map it - fix up the current values in the NB */
                mdl = NET_BUFFER_CURRENT_MDL(currentNetBuffer);
                headerPtr = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
                if (headerPtr == NULL) {
                    /* Low on system resources, not much that can be done */
                    TraceWarning(("'%s': failed to map network buffer 802.3 MAC header\n", __FUNCTION__));
                    NdisFreeMemory(rxContext, 0, 0);
                    return;
                }
                NET_BUFFER_DATA_LENGTH(currentNetBuffer) -= sizeof(struct ethhdr);
                headerPtr += NET_BUFFER_CURRENT_MDL_OFFSET(currentNetBuffer);
            //}
            //else {
            //    /* In this case, we have just updated the offset in the current MDL with enough space to
            //       build an 802.11 frame header. */
            //    ndisStatus = NdisRetreatNetBufferDataStart(currentNetBuffer, delta, 0, NULL);
            //    if (ndisStatus != NDIS_STATUS_SUCCESS) {
            //        /* Low on system resources, not much that can be done */
            //        TraceWarning(("'%s': failed to retreat network buffer MAC header\n", __FUNCTION__));
            //        NdisFreeMemory(rxContext, 0, 0);
            //        return;
            //    }
            //    headerPtr -= delta;
            //}

            /* Build something that looks like a data frame from an AP */            
            NdisZeroMemory(headerPtr, sizeof(DOT11_MAC_DATA_HEADER));
            macDataHeader = (PDOT11_MAC_DATA_HEADER)headerPtr;
            macDataHeader->FrameHeader.FrameControl.Type = DOT11_FRAME_TYPE_DATA;
            macDataHeader->FrameHeader.FrameControl.FromDS = 1;
            macDataHeader->FrameHeader.DurationID = 0x002c;
            NdisMoveMemory(&macDataHeader->FrameHeader.Address1[0], &ethernetHeader.dest[0], ETH_LENGTH_OF_ADDRESS);
            if (pwa->State & WLAN_STATE_CONNECTED)
                NdisMoveMemory(&macDataHeader->FrameHeader.Address2[0], &pwa->AssociatedBss.Entry.dot11BSSID[0], ETH_LENGTH_OF_ADDRESS);
            else
                NdisMoveMemory(&macDataHeader->FrameHeader.Address2[0], &ethernetHeader.src[0], ETH_LENGTH_OF_ADDRESS);
            NdisMoveMemory(&macDataHeader->FrameHeader.Address3[0], &ethernetHeader.src[0], ETH_LENGTH_OF_ADDRESS);
            macDataHeader->FrameHeader.SequenceControl.SequenceNumber = (USHORT)pwa->FrameCounter;
            macDataHeader->LLC[0] = 0xaa;
            macDataHeader->LLC[1] = 0xaa;
            macDataHeader->LLC[2] = 0x03;
            macDataHeader->Protocol = ethernetHeader.proto;
            pwa->FrameCounter = ++pwa->FrameCounter % 4096;

            /* Move on to next one */
            currentNetBuffer = NET_BUFFER_NEXT_NB(currentNetBuffer);
            count++;
        }

        /* Build something that looks like a receive context */
        NdisZeroMemory(rxContext, sizeof(DOT11_EXTSTA_RECV_CONTEXT));
        WLAN_ASSIGN_NDIS_OBJECT_HEADER(rxContext->Header, 
                                       NDIS_OBJECT_TYPE_DEFAULT,
                                       DOT11_EXTSTA_RECV_CONTEXT_REVISION_1,
                                       sizeof(DOT11_EXTSTA_RECV_CONTEXT));
        rxContext->uPhyId = pwa->CurrentPhyId;
        rxContext->lRSSI = pwa->AssociatedBss.Entry.lRSSI;
        rxContext->ucDataRate = 0x6c; /* TODO get from backed or from tx/rx stats */
        rxContext->uChCenterFrequency = pwa->AssociatedBss.Entry.PhySpecificInfo.uChCenterFrequency;
        rxContext->uReceiveFlags = 0;
        rxContext->usNumberOfMPDUsReceived = count;
        NET_BUFFER_LIST_INFO(currentNetBufferList, MediaSpecificInformation) = rxContext;

        /* Stuff our signature in the context space */
        xenContext = (PXEN_WLAN_SIG)NET_BUFFER_LIST_CONTEXT_DATA_START(currentNetBufferList);
        xenContext->signature = XEN_WLAN_MAGIC_SIGNATURE;

        /* Move on to next one */
        currentNetBufferList = NET_BUFFER_LIST_NEXT_NBL(currentNetBufferList);
        
    }
}

VOID
WlanReceiveReturnNetBufferLists (
    IN  PADAPTER            Adapter,
    IN  PNET_BUFFER_LIST    NetBufferList
    )
{
    PNET_BUFFER_LIST currentNetBufferList;
    PNET_BUFFER currentNetBuffer;
    PMDL mdl;
    ULONG delta;
    PUCHAR *ptrPtr;
    PUCHAR headerPtr;
    PDOT11_DATA_SHORT_HEADER dataFrameHeader;
    PDOT11_EXTSTA_RECV_CONTEXT rxContext;
    PXEN_WLAN_SIG xenContext;

    UNREFERENCED_PARAMETER(Adapter);

    currentNetBufferList = NetBufferList;
    while (currentNetBufferList != NULL) {
        /* First, check for our signature on this NBL */
        xenContext = (PXEN_WLAN_SIG)NET_BUFFER_LIST_CONTEXT_DATA_START(currentNetBufferList);
        if ((NET_BUFFER_LIST_CONTEXT_DATA_SIZE(currentNetBufferList) != sizeof(XEN_WLAN_SIG))||
            (xenContext->signature != XEN_WLAN_MAGIC_SIGNATURE)) {
            currentNetBufferList = NET_BUFFER_LIST_NEXT_NBL(currentNetBufferList);
            continue;
        }

        /* Clean up any media specific OOB data */
        rxContext = NET_BUFFER_LIST_INFO(currentNetBufferList, MediaSpecificInformation);
        if (rxContext != NULL) {
            NdisFreeMemory(rxContext, 0, 0);
            NET_BUFFER_LIST_INFO(currentNetBufferList, MediaSpecificInformation) = NULL;
        }

        currentNetBuffer = NET_BUFFER_LIST_FIRST_NB(currentNetBufferList);
        while (currentNetBuffer != NULL) {
            /* Get the current MDL - it should contain the 802.11 MAC header */
            mdl = NET_BUFFER_CURRENT_MDL(currentNetBuffer);
            if (MmGetMdlByteCount(mdl) < sizeof(DOT11_MAC_DATA_HEADER)) {
                /* Doesn't look like we modified it, just pass it on. */
                currentNetBuffer = NET_BUFFER_NEXT_NB(currentNetBuffer);
                continue;
            }            
            
            /* Get a pointer to the 802.11 frame MAC header */
            headerPtr = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
            if (headerPtr == NULL) {
                /* Low on system resources, not much that can be done, try the next one. */
                TraceWarning(("'%s': failed to map network buffer MAC header\n", __FUNCTION__));
                currentNetBuffer = NET_BUFFER_NEXT_NB(currentNetBuffer);
                continue;
            }
            headerPtr += NET_BUFFER_CURRENT_MDL_OFFSET(currentNetBuffer);
            dataFrameHeader = (PDOT11_DATA_SHORT_HEADER)headerPtr;            
                
            /* If the first MDL contains only the MAC header then we adjusted the second MDL to
               remove the 802.3 header so put that back together. */
            if (MmGetMdlByteCount(mdl) == sizeof(DOT11_MAC_DATA_HEADER)) {
                mdl = mdl->Next;
                if (mdl != NULL) {
                    if (mdl->MappedSystemVa != NULL) {
                        ptrPtr = (PUCHAR*)&mdl->MappedSystemVa;
                        *ptrPtr -= sizeof(struct ethhdr);
                    }
                    mdl->ByteOffset -= sizeof(struct ethhdr);
                    mdl->ByteCount += sizeof(struct ethhdr);
                    NET_BUFFER_DATA_LENGTH(currentNetBuffer) += sizeof(struct ethhdr);
                }
                delta = sizeof(DOT11_MAC_DATA_HEADER);
            }
            else {
                delta = (sizeof(DOT11_MAC_DATA_HEADER) - sizeof(struct ethhdr));
            }

            /* Looks about right, advance the buffer back */           
            NdisAdvanceNetBufferDataStart(currentNetBuffer, delta, TRUE, NULL);

            /* Move on to next one */
            currentNetBuffer = NET_BUFFER_NEXT_NB(currentNetBuffer);
        }

        /* Move on to next one */
        currentNetBufferList = NET_BUFFER_LIST_NEXT_NBL(currentNetBufferList);
    }
}

static NDIS_STATUS
WlanSet80211Attributes(
    IN  PADAPTER Adapter
    )
{
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    NDIS_STATUS ndisStatus = NDIS_STATUS_SUCCESS;
    NDIS_MINIPORT_ADAPTER_NATIVE_802_11_ATTRIBUTES attr;
    PDOT11_PHY_ATTRIBUTES phyAttr;
    PDOT11_EXTSTA_ATTRIBUTES exstaAttr;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    NdisZeroMemory(&attr, sizeof(NDIS_MINIPORT_ADAPTER_NATIVE_802_11_ATTRIBUTES));
    attr.SupportedPhyAttributes = 
        (PDOT11_PHY_ATTRIBUTES)NdisAllocateMemoryWithTagPriority(Adapter->NdisAdapterHandle,
                                   sizeof(DOT11_PHY_ATTRIBUTES), '_nwx', NormalPoolPriority);
    if (attr.SupportedPhyAttributes == NULL) {
        return NDIS_STATUS_RESOURCES;
    }
    phyAttr = attr.SupportedPhyAttributes;

    attr.ExtSTAAttributes = 
        (PDOT11_EXTSTA_ATTRIBUTES)NdisAllocateMemoryWithTagPriority(Adapter->NdisAdapterHandle,
                                      sizeof(DOT11_EXTSTA_ATTRIBUTES), '_nwx', NormalPoolPriority);
    if (attr.ExtSTAAttributes == NULL) {
        NdisFreeMemory(attr.SupportedPhyAttributes, 0, 0);
        return NDIS_STATUS_RESOURCES;
    }
    exstaAttr = attr.ExtSTAAttributes;
    
    /* Basics */
    attr.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_NATIVE_802_11_ATTRIBUTES;
    attr.Header.Revision = NDIS_MINIPORT_ADAPTER_802_11_ATTRIBUTES_REVISION_1;
    attr.Header.Size = sizeof(NDIS_MINIPORT_ADAPTER_NATIVE_802_11_ATTRIBUTES);
    attr.OpModeCapability = DOT11_OPERATION_MODE_EXTENSIBLE_STATION;

    /* Setup HW related information */
    attr.NumOfTXBuffers = pwa->OperationModeCapability.uNumOfTXBuffers;
    attr.NumOfRXBuffers = pwa->OperationModeCapability.uNumOfRXBuffers;
    attr.MultiDomainCapabilityImplemented = FALSE; /* Don't want to support this, TODO remove OIDs */

    /* Setup single PHY */
    attr.NumSupportedPhys = 1;        
    WLAN_ASSIGN_NDIS_OBJECT_HEADER(phyAttr->Header, 
                                   NDIS_OBJECT_TYPE_DEFAULT,
                                   DOT11_PHY_ATTRIBUTES_REVISION_1,
                                   sizeof(DOT11_PHY_ATTRIBUTES));

    phyAttr->PhyType = pwa->SupportedPhyTypes.dot11PHYType[0];
    phyAttr->bHardwarePhyState = TRUE;
    phyAttr->bSoftwarePhyState = TRUE;
    phyAttr->bCFPollable = FALSE; /* Turn off, TODO remove CF support OID */
    phyAttr->uMPDUMaxLength = WLAN_MAX_MPDU_LENGTH;
    phyAttr->TempType = dot11_temp_type_1;
    phyAttr->DiversitySupport = dot11_diversity_support_notsupported;
    phyAttr->uNumberSupportedPowerLevels = 1;
    phyAttr->TxPowerLevels[0] = 10;

    /* Try one data rate for now */
    NdisMoveMemory(&phyAttr->SupportedDataRatesValue,
                   &pwa->SupportedDataRatesValue,
                   sizeof(DOT11_SUPPORTED_DATA_RATES_VALUE_V2));
    phyAttr->DataRateMappingEntries[0].ucDataRateIndex = pwa->SupportedDataRatesValue.ucSupportedTxDataRatesValue[0];
    phyAttr->DataRateMappingEntries[0].ucDataRateFlag = 0;
    phyAttr->DataRateMappingEntries[0].usDataRateValue = (USHORT)pwa->SupportedDataRatesValue.ucSupportedTxDataRatesValue[0];
    phyAttr->uNumDataRateMappingEntries = 1;

    /* Setup ExtSta related information */
    WLAN_ASSIGN_NDIS_OBJECT_HEADER(exstaAttr->Header, 
                                   NDIS_OBJECT_TYPE_DEFAULT,
                                   DOT11_EXTSTA_ATTRIBUTES_REVISION_1,
                                   sizeof(DOT11_EXTSTA_ATTRIBUTES));

    /* Set most to minimum allowed */
    exstaAttr->uScanSSIDListSize = WLAN_BSSID_MAX_COUNT;
    exstaAttr->uDesiredBSSIDListSize = 1;
    exstaAttr->uDesiredSSIDListSize = 1;
    exstaAttr->uExcludedMacAddressListSize = 4;
    exstaAttr->uPrivacyExemptionListSize = 32;
    exstaAttr->uKeyMappingTableSize = 32;
    exstaAttr->uDefaultKeyTableSize = 4;
    exstaAttr->uWEPKeyValueMaxLength = 104 / 8;
    exstaAttr->uPMKIDCacheSize = 3;
    exstaAttr->uMaxNumPerSTADefaultKeyTables = 32;
    exstaAttr->bStrictlyOrderedServiceClassImplemented = FALSE;
    exstaAttr->ucSupportedQoSProtocolFlags = 0;
    exstaAttr->bSafeModeImplemented = FALSE;
    exstaAttr->uNumSupportedCountryOrRegionStrings = 0;
    exstaAttr->pSupportedCountryOrRegionStrings = NULL;

    /* TODO minimal set of auth algorithms */
    exstaAttr->pInfraSupportedUcastAlgoPairs = &InfraAnycastAlgorithmPairs[0];
    exstaAttr->uInfraNumSupportedUcastAlgoPairs = 
        sizeof(InfraAnycastAlgorithmPairs)/sizeof(DOT11_AUTH_CIPHER_PAIR);
    exstaAttr->pInfraSupportedMcastAlgoPairs = &InfraAnycastAlgorithmPairs[0];
    exstaAttr->uInfraNumSupportedMcastAlgoPairs = 
        sizeof(InfraAnycastAlgorithmPairs)/sizeof(DOT11_AUTH_CIPHER_PAIR);
    exstaAttr->pAdhocSupportedUcastAlgoPairs = &AdhocAnycastAlgorithmPairs[0];
    exstaAttr->uAdhocNumSupportedUcastAlgoPairs = 
        sizeof(AdhocAnycastAlgorithmPairs)/sizeof(DOT11_AUTH_CIPHER_PAIR);
    exstaAttr->pAdhocSupportedMcastAlgoPairs = &AdhocAnycastAlgorithmPairs[0];
    exstaAttr->uAdhocNumSupportedMcastAlgoPairs = 
        sizeof(AdhocAnycastAlgorithmPairs)/sizeof(DOT11_AUTH_CIPHER_PAIR);

    /* Register the 802.11 miniport attributes with NDIS */
    ndisStatus = NdisMSetMiniportAttributes(Adapter->NdisAdapterHandle,
                                            (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&attr);

    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        TraceError(("Failed (0x%08X) to set 802.11 adapter registration attributes!\n", 
                      ndisStatus));
    }

    NdisFreeMemory(attr.SupportedPhyAttributes, 0, 0);
    NdisFreeMemory(attr.ExtSTAAttributes, 0, 0);
    
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return ndisStatus;
}

static VOID
WlanAdapterUpdateStatistics (
    IN  PADAPTER  Adapter
    )
{
    BOOLEAN connected = FALSE;
    NDIS_STATISTICS_INFO statisticsInfo;
    PWLAN_ADAPTER pwa = Adapter->WlanAdapter;
    NDIS_STATUS ndisStatus;
    LARGE_INTEGER tc;

    NdisAcquireSpinLock(&(pwa->Lock));
    if (pwa->State & WLAN_STATE_CONNECTED) {
        connected = TRUE;
    }
    NdisReleaseSpinLock(&(pwa->Lock));

    while (connected) {
        ndisStatus = AdapterQueryGeneralStatistics(Adapter, &statisticsInfo);
        if (ndisStatus != NDIS_STATUS_SUCCESS) {
            break;
        }
        pwa->Stats.MacUcastCounters.ullTransmittedFrameCount = 
            statisticsInfo.ifHCOutUcastPkts;
        pwa->Stats.MacUcastCounters.ullReceivedFrameCount = 
            statisticsInfo.ifHCInUcastPkts;

        pwa->Stats.MacMcastCounters.ullTransmittedFrameCount = 
            statisticsInfo.ifHCOutBroadcastPkts + statisticsInfo.ifHCOutMulticastPkts;
        pwa->Stats.MacMcastCounters.ullReceivedFrameCount = 
            statisticsInfo.ifHCInMulticastPkts + statisticsInfo.ifHCInBroadcastPkts;

        pwa->Stats.PhyCounters[0].ullTransmittedFrameCount = statisticsInfo.ifHCOutUcastPkts;
        pwa->Stats.PhyCounters[0].ullMulticastTransmittedFrameCount = 
            statisticsInfo.ifHCOutBroadcastPkts + statisticsInfo.ifHCOutMulticastPkts;

        pwa->Stats.PhyCounters[0].ullReceivedFrameCount = statisticsInfo.ifHCInUcastPkts;
        pwa->Stats.PhyCounters[0].ullMulticastReceivedFrameCount = 
            statisticsInfo.ifHCInMulticastPkts + statisticsInfo.ifHCInBroadcastPkts;
        return;
    }
    
    /* Not connected, so make some stuff up */
    KeQueryTickCount(&tc);
    pwa->Stats.MacUcastCounters.ullTransmittedFrameCount += ((ULONG)tc.QuadPart % 100);
    pwa->Stats.MacMcastCounters.ullTransmittedFrameCount += ((ULONG)tc.QuadPart % 10);
    KeQueryTickCount(&tc);
    pwa->Stats.MacUcastCounters.ullReceivedFrameCount += ((ULONG)tc.QuadPart % 100);
    pwa->Stats.MacMcastCounters.ullReceivedFrameCount += ((ULONG)tc.QuadPart % 55);
    pwa->Stats.PhyCounters[0].ullTransmittedFrameCount = pwa->Stats.MacUcastCounters.ullTransmittedFrameCount;
    pwa->Stats.PhyCounters[0].ullMulticastTransmittedFrameCount = pwa->Stats.MacMcastCounters.ullTransmittedFrameCount;       
    pwa->Stats.PhyCounters[0].ullReceivedFrameCount = pwa->Stats.MacUcastCounters.ullReceivedFrameCount;
    pwa->Stats.PhyCounters[0].ullMulticastReceivedFrameCount = pwa->Stats.MacMcastCounters.ullReceivedFrameCount;       
}
