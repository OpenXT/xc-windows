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

#pragma warning( push, 3 )

#include "precomp.h"
#include "netif.h"
#include "scsiboot.h"
#include "stdlib.h"
#include "xscompat.h"
#include "ntstrsafe.h"
#include "xennet_common.h"
#include "wlan.h"

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



static NDIS_STATUS
WlanGetBackendValues (
    IN  PWLAN_ADAPTER WlanAdapter
    );

static VOID
WlanAdapterDefaults (
    IN  PWLAN_ADAPTER WlanAdapter
    )
{
    /* Set the default MIB values at start time and when a reset occurs */
    WlanAdapter->RTSThreshold = WLAN_MAX_MPDU_LENGTH + 1;
    WlanAdapter->FragThreshold = WLAN_MAX_MPDU_LENGTH;
    WlanAdapter->UDThreshold = 2000;
    WlanAdapter->NetworkInfrastructure = Ndis802_11Infrastructure;
    WlanAdapter->NetworkTypeInUse = Ndis802_11Automode;
    WlanAdapter->MediaStreaming = FALSE;
    WlanAdapter->AuthenticationMode = Ndis802_11AuthModeOpen;
    WlanAdapter->EncryptionMode = Ndis802_11Encryption2Enabled; //Ndis802_11EncryptionDisabled;
    WlanAdapter->FrameCounter = 0;
}

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

    /* Set the default values */
    WlanAdapterDefaults(pwa);

    /* Basic WLAN values */
    pwa->RadioOn = TRUE; /* say it is on when we start */
    pwa->HiddenNetworks = FALSE;
    pwa->CurrentPhyId = 0;

    pwa->Associated = FALSE;

    /* Next, load all backend (xenstore) initial values */
    //ndisStatus = WlanGetBackendValues(pwa);
    //if (ndisStatus != NDIS_STATUS_SUCCESS) {
    //    return ndisStatus;
    //}

    //return ndisStatus;
    return NDIS_STATUS_SUCCESS;
}


static NDIS_STATUS
WlanGetBackendValues (
    IN  PWLAN_ADAPTER WlanAdapter
    )
{
    /* TODO, this is where we will read xenstore up front to get our
       initial values like the MAC for our BSSID and SSID string etc. */

    /* TODO this is just test data */
    NdisMoveMemory(WlanAdapter->XenBSSID, "\x00\x1D\xE0\x97\xAA\x33", sizeof(NDIS_802_11_MAC_ADDRESS));
    NdisMoveMemory(WlanAdapter->XenSSID.Ssid, "OpenXT Wireless", 11);
    WlanAdapter->XenSSID.SsidLength = 11;
    WlanAdapter->XenConnected = TRUE;

    return NDIS_STATUS_SUCCESS;
}

char *
WlanReadBackend(PADAPTER Adapter, char *path)
{
    char *tmp;

    UNREFERENCED_PARAMETER(Adapter);

    if (!NT_SUCCESS(xenbus_read(XBT_NIL, path, &tmp)))
    {
//        TraceNotice (("Xenstore read %s FAILED!!!\n", path));
        return NULL;
    }
//    TraceInfo (("Xenstore read %s : Value %s\n", path, tmp));

    return tmp;
}


VOID 
WlanAdapterDelete (
    IN PADAPTER Adapter
    )
{
    XmFreeMemory(Adapter->WlanAdapter);
    Adapter->WlanAdapter = NULL;
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

ConvertMacAddr (
    char *tmp,
    NDIS_802_11_MAC_ADDRESS *mac,
    PADAPTER Adapter
    )
{
    int x;

    TraceDebug (("mac: %s -> %s.\n", Adapter->XenbusPrefix, tmp));
    for (x = 0; x < ETH_LENGTH_OF_ADDRESS; x++) {
        (*mac)[x] = (unsigned char)HexCharToInt(tmp[x*3]) * 16 +
            (unsigned char)HexCharToInt(tmp[x*3+1]);
    }
}

#ifdef NDIS60_MINIPORT

SetSupportedDataRates (
    IN PWLAN_ADAPTER WlanAdapter,
    ULONG DataRate
    )
{
    int count=0;
    /* Rate setup */
    NdisZeroMemory(&WlanAdapter->OperationalRateSet, sizeof(DOT11_RATE_SET));
    if (DataRate >= 2000)
    {
        WlanAdapter->OperationalRateSet.ucRateSet[count] = 2;
        count++;
    }
    if (DataRate >= 4000)
    {
        WlanAdapter->OperationalRateSet.ucRateSet[count] = 4;
        count++;
    }
    if (DataRate >= 11000)
    {
        WlanAdapter->OperationalRateSet.ucRateSet[count] = 11;
        count++;
    }
    if (DataRate >= 22000)
    {
        WlanAdapter->OperationalRateSet.ucRateSet[count] = 22;
        count++;
    }
    if (DataRate >= 54000)
    {
        WlanAdapter->OperationalRateSet.ucRateSet[count] = 54;
        count++;
    }
    if (DataRate >= 108000)
    {
        WlanAdapter->OperationalRateSet.ucRateSet[count] = 108;
        count++;
    }
    WlanAdapter->OperationalRateSet.uRateSetLength = count;
}

#else

void
GetSupportedRates (
    NDIS_802_11_RATES_EX *user_rates
    )
{
    NDIS_802_11_RATES_EX rates;

    NdisZeroMemory (rates, sizeof(NDIS_802_11_RATES_EX));
    rates[0] = 0x80 | (1 * 2);  // 1 Mbps
    rates[1] = 0x80 | (2 * 2);  // 2 Mbps
    rates[2] = 0x80 | (11 * 2);  // 11 Mbps
    rates[3] = 0x80 | (24 * 2);  // 24 Mbps
    rates[4] = 0x80 | (54 * 2);  // 54 Mbps
    NdisMoveMemory (user_rates, rates, sizeof(NDIS_802_11_RATES_EX));
}

#endif

NDIS_STATUS
WlanStartScan (
    IN PADAPTER Adapter
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    char *str;
    int i, j;
    char path[256];
#ifdef NDIS60_MINIPORT
    LARGE_INTEGER ts, hts;
    PDOT11_BSS_ENTRY pEntry;
    PDOT11_SSID pSSID;
    USHORT PrivacyFlag;
#else
    NDIS_802_11_RATES_EX rates;
    PXEN_BSS_CONFIG pEntry;
    PNDIS_802_11_SSID pSSID;
#endif

    NdisZeroMemory(&WlanAdapter->BSSList[0], sizeof(XEN_BSS_ENTRY));

#ifdef NDIS60_MINIPORT
    NdisGetCurrentSystemTime(&ts);
#endif

    //
    // Read from Xenstore the list of BSSIDs and cache them in the
    // adapter extension.
    //

#ifndef NDIS60_MINIPORT
    GetSupportedRates (&rates);
    NdisMoveMemory (&WlanAdapter->SupportedRates, &rates, sizeof(NDIS_802_11_RATES_EX));
#endif

    i = 0;
    j = 0;
    do
    {
#ifdef NDIS60_MINIPORT
        PrivacyFlag = 0;
#endif
        NdisZeroMemory(&WlanAdapter->BSSList[j], sizeof(XEN_BSS_ENTRY));
        pEntry = &WlanAdapter->BSSList[j].Entry;
        pSSID = &WlanAdapter->BSSList[j].SSID;

        Xmsnprintf (path, sizeof(path), "wlan/%d", i);
        str = WlanReadBackend(Adapter, path);
        if (!str)
            continue;
        XmFreeMemory(str);

        Xmsnprintf (path, sizeof(path), "wlan/%d/mac", i);
        str = WlanReadBackend(Adapter, path);
        if (str)
        {
#ifdef NDIS60_MINIPORT
            ConvertMacAddr (str, &pEntry->dot11BSSID, Adapter);
#else
            ConvertMacAddr (str, &pEntry->BSSID, Adapter);
#endif
            XmFreeMemory(str);
        }
        Xmsnprintf (path, sizeof(path), "wlan/%d/essid", i);
        str = WlanReadBackend(Adapter, path);
        if (str)
        {
#ifdef NDIS60_MINIPORT
            pSSID->uSSIDLength = (ULONG)min (NDIS_802_11_LENGTH_SSID, strlen(str));
            NdisMoveMemory(&pSSID->ucSSID, str, pSSID->uSSIDLength);
#else
            pSSID->SsidLength = (ULONG)min (NDIS_802_11_LENGTH_SSID, strlen(str));
            NdisMoveMemory(&pSSID->Ssid, str, pSSID->SsidLength);
#endif
            XmFreeMemory(str);
        }
        Xmsnprintf (path, sizeof(path), "wlan/%d/quality", i);
        str = WlanReadBackend(Adapter, path);
        if (str)
        {
            int quality;

            quality = atoi(str);

#ifdef NDIS60_MINIPORT
            pEntry->lRSSI = (ULONG)((double)quality * 0.81) - 101;
            pEntry->uLinkQuality = quality;
#else
            pEntry->Rssi = (ULONG)((double)quality * 0.81) - 101;
#endif
            XmFreeMemory(str);
        }
        Xmsnprintf (path, sizeof(path), "wlan/%d/frequency", i);
        str = WlanReadBackend(Adapter, path);
        if (str)
        {
#ifdef NDIS60_MINIPORT
            pEntry->PhySpecificInfo.uChCenterFrequency = atol(str) / 1000;
#else
            pEntry->PhySpecificInfo.DSConfig = atol(str);
#endif
            XmFreeMemory(str);
        }
        Xmsnprintf (path, sizeof(path), "wlan/%d/auth", i);
        str = WlanReadBackend(Adapter, path);
        if (str)
        {
#ifdef NDIS60_MINIPORT
            if (memcmp (str, "wep", 3) == 0)
            {
                WlanAdapter->AuthAlgorithm = DOT11_AUTH_ALGO_80211_OPEN;
                WlanAdapter->UnicastCipherAlgorithm = DOT11_CIPHER_ALGO_WEP;
                WlanAdapter->MulticastCipherAlgorithm = DOT11_CIPHER_ALGO_WEP;
                PrivacyFlag = DOT11_CAPABILITY_INFO_PRIVACY;
            }
            else
            {
                WlanAdapter->AuthAlgorithm = DOT11_AUTH_ALGO_80211_OPEN;
                WlanAdapter->UnicastCipherAlgorithm = DOT11_CIPHER_ALGO_NONE;
                WlanAdapter->MulticastCipherAlgorithm = DOT11_CIPHER_ALGO_NONE;
            }
#else
            if (memcmp (str, "wep", 3) == 0)
                pEntry->Privacy = 1;
            else
                pEntry->Privacy = 0;
#endif
            XmFreeMemory(str);
        }
        Xmsnprintf (path, sizeof(path), "wlan/%d/maxbitrate", i);
        str = WlanReadBackend(Adapter, path);
        if (str)
        {
#ifdef NDIS60_MINIPORT
//@@@            SetSupportedDataRates(WlanAdapter, atol(str));
#else
//@@@            pEntry->PhySpecificInfo.DSConfig = atol(str);
//@@@            SetSupportedDataRates(WlanAdapter, pEntry->PhySpecificInfo.DSConfig);
#endif
            XmFreeMemory(str);
        }

#ifdef NDIS60_MINIPORT
        pEntry->dot11BSSType = dot11_BSS_type_infrastructure;
        pEntry->uPhyId = 0;
        pEntry->bInRegDomain = TRUE;
        pEntry->usBeaconPeriod = 0x64;
        NdisGetCurrentSystemTime(&hts);
        pEntry->ullTimestamp = ts.QuadPart;
        pEntry->ullHostTimestamp = hts.QuadPart;
        pEntry->usCapabilityInformation = DOT11_CAPABILITY_SHORT_SLOT_TIME |
                                          PrivacyFlag |
                                          DOT11_CAPABILITY_INFO_ESS;
        pEntry->uBufferLength = pSSID->uSSIDLength + 2 + sizeof(WLAN_IE_VALUES2); /* 2 byte IE header + SSID length + IE array size */
#else
        pEntry->usBeaconPeriod = 0;
        pEntry->BSSType = WlanAdapter->NetworkInfrastructure;
        pEntry->usBeaconPeriod = 0x64;
        pEntry->usCapabilityInformation = 0x0401;
#endif

        j++;
    }
    while (++i < WLAN_BSSID_MAX_COUNT);

    WlanAdapter->BSSCount = j;

    return NDIS_STATUS_SUCCESS;
}

ULONG
WlanGetScanListSize (
    NDIS_OID oid,
    IN PADAPTER Adapter
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    ULONG size;

    size = max(1, (WlanAdapter->BSSCount)) * (sizeof(NDIS_WLAN_BSSID_EX) - 1 + sizeof(NDIS_802_11_FIXED_IEs));

    return size;
}


NDIS_STATUS
WlanGetScanList (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    PNDIS_802_11_BSSID_LIST_EX BssidList = (PNDIS_802_11_BSSID_LIST_EX)buf;
    PNDIS_WLAN_BSSID_EX Bssid;
    PNDIS_802_11_FIXED_IEs BssidIE;
    LARGE_INTEGER ts;
    int i;
    ULONG BufSize;

    BufSize = WlanGetScanListSize(oid, Adapter);
    NdisZeroMemory(&BssidList->Bssid[0], BufSize);

    BssidList->NumberOfItems = WlanAdapter->BSSCount;

    for (i = 0; i < (int)(WlanAdapter->BSSCount); i++)
    {
        Bssid = &BssidList->Bssid[i];
        Bssid->Length = sizeof(NDIS_WLAN_BSSID_EX);
        NdisMoveMemory(&Bssid->MacAddress, &WlanAdapter->BSSList[i].Entry.BSSID, sizeof(NDIS_802_11_MAC_ADDRESS));
        Bssid->Ssid.SsidLength = WlanAdapter->BSSList[i].SSID.SsidLength;
        NdisMoveMemory(&Bssid->Ssid.Ssid, &WlanAdapter->BSSList[i].SSID.Ssid, Bssid->Ssid.SsidLength);
        Bssid->Privacy = WlanAdapter->BSSList[i].Entry.Privacy;  // 0=none, 1= WEP, WPA or WPA2
        Bssid->Rssi = WlanAdapter->BSSList[i].Entry.Rssi;
        Bssid->NetworkTypeInUse = Ndis802_11DS; //@@@WlanAdapter->NetworkTypeInUse //@@@Ndis802_11OFDM24
        Bssid->InfrastructureMode = WlanAdapter->BSSList[i].Entry.BSSType;
        NdisMoveMemory (&Bssid->SupportedRates, &WlanAdapter->SupportedRates, sizeof(NDIS_802_11_RATES_EX));

        Bssid->Configuration.Length = sizeof(NDIS_802_11_CONFIGURATION);
        Bssid->Configuration.BeaconPeriod = WlanAdapter->BSSList[i].Entry.usBeaconPeriod;
        Bssid->Configuration.DSConfig = WlanAdapter->BSSList[i].Entry.PhySpecificInfo.DSConfig;

        NdisGetCurrentSystemTime(&ts);
        Bssid->IELength = sizeof(NDIS_802_11_FIXED_IEs);
        BssidIE = (PNDIS_802_11_FIXED_IEs)&Bssid->IEs[0];
        NdisMoveMemory (BssidIE->Timestamp, &ts.QuadPart, sizeof(LARGE_INTEGER));
        BssidIE->BeaconInterval = WlanAdapter->BSSList[i].Entry.usBeaconInterval;
        BssidIE->Capabilities = WlanAdapter->BSSList[i].Entry.usCapabilityInformation;

        Bssid++;
    }

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
WlanGetRadioConfiguration (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    PNDIS_802_11_CONFIGURATION radio = (PNDIS_802_11_CONFIGURATION)buf;

    NdisZeroMemory (radio, sizeof(NDIS_802_11_CONFIGURATION));

    radio->Length = sizeof(NDIS_802_11_CONFIGURATION);

    //
    // From MSDN, regarding retrieving the beacon period:
    //
    // If the device is in infrastructure mode and is associated, the driver returns
    //  the current beacon period of the associated access point. 
    // If the device is in ad hoc mode, the driver returns the IBSS beacon period. 
    // If the device is not associated, the driver returns 0. 
    //

    if (WlanAdapter->NetworkInfrastructure == Ndis802_11Infrastructure)
    {
        if (WlanAdapter->Associated)
            radio->BeaconPeriod = WlanAdapter->BeaconPeriod;
        radio->ATIMWindow = 0; //Only valid for ad hoc networks
    }
    else
    {
        // Ad hoc mode
        radio->ATIMWindow = 0; //@@@
        radio->BeaconPeriod = 0; //@@@ Beacon period of IBSS
    }

    //
    // If we're not associated, beacon period must be 0
    //
    if (!WlanAdapter->Associated)
        radio->BeaconPeriod = 0;

    //
    // Current operating frequency for the radio
    //
    radio->DSConfig = WlanAdapter->ChCenterFrequency;

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
WlanSetRadioConfiguration (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    PNDIS_802_11_CONFIGURATION radio = (PNDIS_802_11_CONFIGURATION)buf;

    //
    // This request is only valid when we're associated
    //
    if (WlanAdapter->Associated)
        return NDIS_STATUS_NOT_ACCEPTED;

    if (WlanAdapter->NetworkInfrastructure == Ndis802_11Infrastructure)
    {
        //
        // Not much to do in infrastructure mode
        //
    }
    else
    {
        //
        // Ad hoc mode
        //
        WlanAdapter->BeaconPeriod = radio->BeaconPeriod;
        WlanAdapter->ChCenterFrequency = radio->DSConfig;
    }

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
WlanGetInfrastructureMode (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    PNDIS_802_11_NETWORK_INFRASTRUCTURE net = (PNDIS_802_11_NETWORK_INFRASTRUCTURE)buf;

    *net = WlanAdapter->NetworkInfrastructure;

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
WlanSetInfrastructureMode (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    PNDIS_802_11_NETWORK_INFRASTRUCTURE net = (PNDIS_802_11_NETWORK_INFRASTRUCTURE)buf;

    WlanAdapter->NetworkInfrastructure = *net;

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
WlanGetAuthenticationMode (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    PNDIS_802_11_AUTHENTICATION_MODE net = (PNDIS_802_11_AUTHENTICATION_MODE)buf;

    *net = WlanAdapter->AuthenticationMode;

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
WlanSetAuthenticationMode (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    PNDIS_802_11_AUTHENTICATION_MODE net = (PNDIS_802_11_AUTHENTICATION_MODE)buf;

    WlanAdapter->AuthenticationMode = *net;

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
WlanGetEncryptionMode (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    PNDIS_802_11_ENCRYPTION_STATUS net = (PNDIS_802_11_ENCRYPTION_STATUS)buf;

    *net = WlanAdapter->EncryptionMode;

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
WlanSetEncryptionMode (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    PNDIS_802_11_ENCRYPTION_STATUS net = (PNDIS_802_11_ENCRYPTION_STATUS)buf;

    WlanAdapter->EncryptionMode = *net;

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
WlanGetRSSI (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    char path[256];
    char *str;
//    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    NDIS_802_11_RSSI *rssi = (NDIS_802_11_RSSI *)buf;
    NDIS_802_11_RSSI my_rssi;
    int i = 0;
    int quality;

    Xmsnprintf (path, sizeof(path), "wlan/%d/quality", i);
    str = WlanReadBackend(Adapter, path);
    if (str)
    {
        quality = atoi(str);
        XmFreeMemory(str);
        my_rssi = (ULONG)((double)quality * 0.81) - 101;
        *rssi = my_rssi;
    }
    else
    {
        // The normal range for the RSSI values is from -10 through -200 dBm.
        *rssi = -10;    // We failed to read from Xenstore...assume a perfect signal
    }

    return NDIS_STATUS_SUCCESS;
}


NDIS_STATUS
WlanSetBssid(
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    NDIS_802_11_MAC_ADDRESS *bssid = (NDIS_802_11_MAC_ADDRESS *)buf;

    NdisMoveMemory (WlanAdapter->XenBSSID, bssid, sizeof(NDIS_802_11_MAC_ADDRESS));

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
WlanGetBssid(
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    NDIS_802_11_MAC_ADDRESS *bssid = (NDIS_802_11_MAC_ADDRESS *)buf;

    NdisMoveMemory (bssid, WlanAdapter->XenBSSID, sizeof(NDIS_802_11_MAC_ADDRESS));

    return NDIS_STATUS_SUCCESS;
}


NDIS_STATUS
WlanGetSupportedRates(
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;

    NdisZeroMemory (buf, sizeof(NDIS_802_11_RATES));
    NdisMoveMemory (buf, &WlanAdapter->SupportedRates, sizeof(NDIS_802_11_RATES));

    return NDIS_STATUS_SUCCESS;
}

ULONG
WlanGetNetworkTypeListSize (
    NDIS_OID oid,
    IN PADAPTER Adapter
    )
{
//    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    ULONG size;

    size = sizeof(NDIS_802_11_NETWORK_TYPE_LIST);

    return size;
}

NDIS_STATUS
WlanGetNetworkTypes (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
//    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    PNDIS_802_11_NETWORK_TYPE_LIST net_types = (PNDIS_802_11_NETWORK_TYPE_LIST)buf;

    net_types->NumberOfItems = 1;
    net_types->NetworkType[0] = Ndis802_11OFDM24;

    return NDIS_STATUS_SUCCESS;
}



NDIS_STATUS
WlanGetNetworkTypeInUse (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    PNDIS_802_11_NETWORK_TYPE net_type = (PNDIS_802_11_NETWORK_TYPE)buf;

    *net_type = WlanAdapter->NetworkTypeInUse;

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
WlanSetNetworkTypeInUse (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    PNDIS_802_11_NETWORK_TYPE net_type = (PNDIS_802_11_NETWORK_TYPE)buf;

    WlanAdapter->NetworkTypeInUse = *net_type;

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
WlanSetSSID (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    PNDIS_802_11_SSID Ssid = (PNDIS_802_11_SSID)buf;

    //
    // First tell Windows we have lost our AP association
    //
    if (WlanAdapter->Associated)
    {
        NdisMIndicateStatus (Adapter->AdapterHandle, NDIS_STATUS_MEDIA_DISCONNECT, NULL, 0);
        NdisMIndicateStatusComplete (Adapter->AdapterHandle);
    }

    //
    // At this point we are no longer associated
    //
    WlanAdapter->Associated = FALSE;

    //
    // The SSID can be an empty string, indicating connect to any AP. Pick the AP
    // with the strongest RSSI and no authentication.
    //

    //
    // Be sure we have some BSS's to connect to...
    //
    if ((WlanAdapter->BSSCount == 0) || ((Ssid->SsidLength == 0) && (WlanAdapter->BSSCount == 0)))
    {
        WlanAdapter->XenSSID.SsidLength = 0;
        NdisZeroMemory (&WlanAdapter->XenSSID.Ssid, sizeof(WlanAdapter->XenSSID.Ssid));
        return NDIS_STATUS_SUCCESS;
    }

    //
    // Save the SSID name in the general data structure
    //
    if (Ssid->SsidLength)  //@@@ For the time being...
    {
        WlanAdapter->XenSSID.SsidLength = min(NDIS_802_11_LENGTH_SSID, Ssid->SsidLength);
        NdisMoveMemory (&WlanAdapter->XenSSID.Ssid, &Ssid->Ssid, WlanAdapter->XenSSID.SsidLength);
    }

    //
    // Connect to SSID indicated in NDIS_802_11_SSID struct
    //

    //
    // Write the SSID name (and WEP key?) to the backend to indicate a connect request
    //
    //@@@

    //
    // Tell Windows we are now associated (The below should be deferred until
    // a watch point triggers indicating the backend wrote a status update
    // into Xenstore.)
    //
    NdisMIndicateStatus (Adapter->AdapterHandle, NDIS_STATUS_MEDIA_CONNECT, NULL, 0);
    NdisMIndicateStatusComplete (Adapter->AdapterHandle);
    WlanAdapter->Associated = TRUE;

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
WlanGetSSID (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    PNDIS_802_11_SSID Ssid = (PNDIS_802_11_SSID)buf;

    //
    // If there is no associated AP, the spec (MSDN) says to set length to 0
    //
    if (!WlanAdapter->Associated)
    {
        Ssid->SsidLength = 0;
    }
    else
    {
        Ssid->SsidLength = min(NDIS_802_11_LENGTH_SSID, WlanAdapter->XenSSID.SsidLength);
        NdisMoveMemory (&Ssid->Ssid, &WlanAdapter->XenSSID.Ssid, Ssid->SsidLength);
    }

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
WlanDisassociate (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;

    if (WlanAdapter->Associated)
    {
        //
        // Force the backend to disassociate with the AP via a
        // Xenstore write.
        //
        //@@@

        //
        // Once the Xenstore write completes, indicate the disconnect
        // up to Windows.
        //
        NdisMIndicateStatus (Adapter->AdapterHandle, NDIS_STATUS_MEDIA_DISCONNECT, NULL, 0);
        NdisMIndicateStatusComplete (Adapter->AdapterHandle);
        WlanAdapter->Associated = FALSE;
    }

    //
    // At this point, we must turn off the radio...
    //
    //@@@

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
WlanReloadDefaults (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    PNDIS_802_11_RELOAD_DEFAULTS def_type = (PNDIS_802_11_RELOAD_DEFAULTS )buf;

    if (*def_type == Ndis802_11ReloadWEPKeys)
    {
        //@@@ WlanAdapterDefaults(WlanAdapter);
        //
        // Reset network type to automode...as spec'd in MSDN
        //
        WlanAdapter->NetworkTypeInUse = Ndis802_11Automode;
        return NDIS_STATUS_SUCCESS;
    }
    else
    {
        return NDIS_STATUS_INVALID_DATA;
    }
}

NDIS_STATUS
WlanAddWep (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    PNDIS_802_11_WEP Wep = (PNDIS_802_11_WEP)buf;
    USHORT idx = (USHORT)(Wep->KeyIndex & 0xff);

    if (Wep->KeyIndex & 0x80000000)
    {
        //
        // This is a transmit only key
        //
    }
    else if (Wep->KeyIndex & 0x40000000)
    {
        //
        // This is a per-client key
        //
    }

    //
    // If we alreay have a key, be sure to first free the memory
    //
    if (WlanAdapter->WepKey[idx])
        NdisFreeMemory(WlanAdapter->WepKey[idx], WlanAdapter->WepKeySize[idx], 0);

    //
    // Allocate a buffer to hold the new key
    //
    NdisAllocateMemoryWithTag (&WlanAdapter->WepKey[idx], Wep->KeyLength, 'tenx'); 

    if (WlanAdapter->WepKey[idx] == NULL)
        //
        // If the key cannot be set for any reason, the following
        // must be returned (as per MSDN):
        //
        return NDIS_STATUS_INVALID_DATA;

    NdisMoveMemory(WlanAdapter->WepKey[idx], &Wep->KeyMaterial[0], Wep->KeyLength);
    WlanAdapter->WepKeySize[idx] = Wep->KeyLength;

    return NDIS_STATUS_SUCCESS;
}


NDIS_STATUS
WlanRemoveWep (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    NDIS_802_11_KEY_INDEX *Wep = (NDIS_802_11_KEY_INDEX *)buf;
    USHORT idx = (USHORT)(*Wep & 0xff);

    //
    // Bit 31 of the indicated key index must be 0
    //
    if (*Wep & 0x80000000)
        return NDIS_STATUS_INVALID_DATA;

    //
    // If we alreay have a key, be sure to first free the memory
    //
    if (WlanAdapter->WepKey[idx])
        NdisFreeMemory(WlanAdapter->WepKey[idx], WlanAdapter->WepKeySize[idx], 0);

    WlanAdapter->WepKeySize[idx] = 0;
    WlanAdapter->WepKey[idx] = NULL;

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
WlanAddKey (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    // Reference: http://msdn.microsoft.com/en-us/library/ff559235(VS.85).aspx

    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    NDIS_802_11_KEY *Key = (NDIS_802_11_KEY *)buf;
    USHORT idx = (USHORT)(Key->KeyIndex & 0xff);

    if (Key->KeyIndex & 0x80000000)
    {
        //
        // Transmit key
        //
    }
    if (Key->KeyIndex & 0x40000000)
    {
        //
        // Pairwise key
        //

        if (Key->KeyIndex & 0x80000000)
        {
            //
            // Invalid config
            //
            return NDIS_STATUS_INVALID_DATA;
        }

    }
    else
    {
        //
        // Group Key
        //
    }


    //
    // If we alreay have a key, be sure to first free the memory
    //
    if (WlanAdapter->WpaKey[idx])
        NdisFreeMemory(WlanAdapter->WpaKey[idx], WlanAdapter->WpaKeySize[idx], 0);

    //
    // Allocate a buffer to hold the new key
    //
    NdisAllocateMemoryWithTag (&WlanAdapter->WpaKey[idx], Key->KeyLength, 'tenx'); 

    if (WlanAdapter->WpaKey[idx] == NULL)
        //
        // If the key cannot be set for any reason, the following
        // must be returned (as per MSDN):
        //
        return NDIS_STATUS_INVALID_DATA;

    NdisMoveMemory(WlanAdapter->WpaKey[idx], &Key->KeyMaterial[0], Key->KeyLength);
    WlanAdapter->WpaKeySize[idx] = Key->KeyLength;

    return NDIS_STATUS_SUCCESS;
}


NDIS_STATUS
WlanRemoveKey (
    NDIS_OID oid,
    IN PADAPTER Adapter,
    PVOID buf
    )
{
    PWLAN_ADAPTER WlanAdapter = Adapter->WlanAdapter;
    NDIS_802_11_REMOVE_KEY *Key = (NDIS_802_11_REMOVE_KEY *)buf;
    USHORT idx = (USHORT)(Key->KeyIndex & 0xff);

    //
    // Bit 31 of the indicated key index must be 0
    //
    if (Key->KeyIndex & 0x80000000)
        return NDIS_STATUS_INVALID_DATA;

    //
    // If we alreay have a key, be sure to first free the memory
    //
    if (WlanAdapter->WpaKey[idx])
        NdisFreeMemory(WlanAdapter->WpaKey[idx], WlanAdapter->WpaKeySize[idx], 0);

    WlanAdapter->WpaKeySize[idx] = 0;
    WlanAdapter->WpaKey[idx] = NULL;

    return NDIS_STATUS_SUCCESS;
}
