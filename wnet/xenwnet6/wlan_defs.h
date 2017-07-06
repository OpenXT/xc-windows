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

#ifndef __WLAN_DEFS_H__
#define __WLAN_DEFS_H__

#define DOM0 0

#define WLAN_STATE_CLEAR     0x00000000
#define WLAN_STATE_PAUSED    0x00000001
#define WLAN_STATE_DELETING  0x00000002
#define WLAN_STATE_SCANNING  0x00000010
#define WLAN_STATE_STOPSCAN  0x00000020
#define WLAN_STATE_CONNECTED 0x00000100

#define XEN_WLAN_MAGIC_SIGNATURE 0xaa55aa55b67a9d6d

#define ETH_P_EAPOL 0x8e88         // 0x888e byte swapped
#define ETH_P_RSN_PREAUTH 0xc788   // 0x88c7 byte swapped

//
// V4V support stuff
//
#define V4V_RX_BUF_SIZE 2048
#define V4V_TX_BUF_SIZE 1024

typedef struct _V4V_CONFIG {

#ifdef USE_V4V
    PXEN_V4V V4v;
#endif

    ULONG txSize;
    ULONG rxSize;
    UCHAR *txBuf;
    UCHAR *rxBuf;

    ULONG ringSize;

    HANDLE controlEventHandle;
    PKEVENT controlEvent;
    NTSTATUS transmitStatus;

    union {
        struct {            
            USHORT counter;
        } dgram;
        struct {
            ULONG dataSize;
            FILE *fh;
////            struct _stat finfo;
            ULONG offset;
            ULONG seqnum;
            ULONG seqrx;
            ULONG status;
            BOOLEAN ack;
            BOOLEAN done;
        } dfile;
    } r; 
} V4V_CONFIG, *PV4V_CONFIG;

//
// End of V4V related stuff
//

//@@@
#pragma pack(push, 1)

typedef struct _EAPOL_PKT {
    USHORT proto;
    UCHAR version;
    UCHAR packet_type;
    USHORT packet_body_len;
    unsigned char body;
}
EAPOL_PKT;

typedef struct _RSN_IE_HDR {
	UCHAR elem_id; /* WLAN_EID_RSN */
	UCHAR len;
	UCHAR version[2]; /* little endian */
} RSN_IE_HDR;

typedef struct _WPA_IE_HDR {
	UCHAR elem_id;
	UCHAR len;
	UCHAR oui[4]; /* 24-bit OUI followed by 8-bit OUI type */
	UCHAR version[2]; /* little endian */
} WPA_IE_HDR;

#pragma pack(pop)

char *eap_type[] = {"Start", "Logoff", "Key", "ASF-Alert"};
//@@@

static const DOT11_MAC_ADDRESS WLAN_BSSID_WILDCARD = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static const UCHAR WLAN_IE_VALUES[] = {
    0x01, 0x07, 0x96, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c, /* Supported Rates */
    0x03, 0x01, 0x0b,  /* DS Set - Channel 0x0B */
    0x05, 0x04, 0x00, 0x02, 0x00, 0x00, /* Traffic Indication Map */
    0x07, 0x06, 0x55, 0x53, 0x49, 0x01, 0x0b, 0x1a, /* Country - US Indoor */
    0x2a, 0x01, 0x00 /* ERP Information */
};

static const UCHAR WLAN_IE_VALUES2[] = {
    0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, /* Supported Rates */
    0x03, 0x01, 0x06, /* DS Set - Channel 0x06 */    
    0x2a, 0x01, 0x00, /* ERP Information */
    0x2f, 0x01, 0x00, /* Unknown */
    0x32, 0x04, 0x0c, 0x12, 0x18, 0x60 /* Extended Rates */
};

static const UCHAR WLAN_IE_VALUES3[] = {
    0x01, 0x04, 0x82, 0x84, 0x8b, 0x96, /* Supported Rates */
    0x32, 0x08, 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c, /* Extended Rates */
    0x03, 0x01, 0x06, /* DS Set - Channel 0x06 */    
    0x05, 0x04, 0x00, 0x02, 0x00, 0x00, /* Traffic Indication Map */
    0x2a, 0x01, 0x00 /* ERP Information */
};

static const UCHAR WLAN_IE_VALUES4[] = {
    0x03, 0x01, 0x06, /* DS Set - Channel 0x06 */    
    0x2a, 0x01, 0x00 /* ERP Information */
};

static const UCHAR WLAN_IE_VALUES5[] = {
    0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, /* Supported Rates */
    0x2f, 0x01, 0x00, /* Unknown */
    0x32, 0x04, 0x0c, 0x12, 0x18, 0x60 /* Extended Rates */
};

static const UCHAR WLAN_IE_VALUES6[] = {
    0x2a, 0x01, 0x00 /* ERP Information */
};

static const UCHAR WLAN_HT_CAPA[] = {
    0x2d, 0x1a, 0x1c, 0x18, 0x1a, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, /* High Throughput (.11n) capability */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const UCHAR WLAN_HT_INFO[] = {
    0x3d, 0x16, 0x09, 0x08, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* High Throughput (.11n) information */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00 
};

#pragma pack(push, 1)

typedef struct {
    UCHAR ID;
    UCHAR Length;
    UCHAR Version;
    UCHAR GroupCipher[4];
    USHORT PairwiseCipherCount;
    UCHAR PairwiseCipherSuite[4];
    USHORT AuthSuiteCount;
    UCHAR AuthSuite[4];
    USHORT RsnCapabilities;
    USHORT PmkCount;
    UCHAR PmkList[16];
} RSN;

typedef struct {
    UCHAR Rates[10];
    UCHAR Channel[3];
    UCHAR Erp[3];
    UCHAR Unknown[3];
    UCHAR ExtRates[6];
    RSN Rsn;
} INFORMATION_ELEMENT;

#pragma pack(pop)

//@@@INFORMATION_ELEMENT InformationElement;


static DOT11_AUTH_CIPHER_PAIR InfraAnycastAlgorithmPairs[] = {
    {DOT11_AUTH_ALGO_80211_OPEN, DOT11_CIPHER_ALGO_NONE},
    {DOT11_AUTH_ALGO_80211_OPEN, DOT11_CIPHER_ALGO_WEP},
    {DOT11_AUTH_ALGO_80211_OPEN, DOT11_CIPHER_ALGO_WEP40},
    {DOT11_AUTH_ALGO_80211_OPEN, DOT11_CIPHER_ALGO_WEP104},
    {DOT11_AUTH_ALGO_80211_SHARED_KEY, DOT11_CIPHER_ALGO_WEP},
    {DOT11_AUTH_ALGO_80211_SHARED_KEY, DOT11_CIPHER_ALGO_WEP40},
    {DOT11_AUTH_ALGO_80211_SHARED_KEY, DOT11_CIPHER_ALGO_WEP104},
    {DOT11_AUTH_ALGO_RSNA_PSK, DOT11_CIPHER_ALGO_WPA_USE_GROUP},
    {DOT11_AUTH_ALGO_RSNA_PSK, DOT11_CIPHER_ALGO_TKIP},
    {DOT11_AUTH_ALGO_RSNA_PSK, DOT11_CIPHER_ALGO_CCMP},
    {DOT11_AUTH_ALGO_WPA_PSK, DOT11_CIPHER_ALGO_WPA_USE_GROUP},
    {DOT11_AUTH_ALGO_WPA_PSK, DOT11_CIPHER_ALGO_TKIP},
    {DOT11_AUTH_ALGO_WPA_PSK, DOT11_CIPHER_ALGO_CCMP},
    {DOT11_AUTH_ALGO_RSNA, DOT11_CIPHER_ALGO_TKIP},
    {DOT11_AUTH_ALGO_RSNA, DOT11_CIPHER_ALGO_CCMP},
    {DOT11_AUTH_ALGO_WPA, DOT11_CIPHER_ALGO_TKIP},
    {DOT11_AUTH_ALGO_WPA, DOT11_CIPHER_ALGO_CCMP}
};

static DOT11_AUTH_CIPHER_PAIR AdhocAnycastAlgorithmPairs[] = {
    {DOT11_AUTH_ALGO_80211_OPEN, DOT11_CIPHER_ALGO_NONE},
    {DOT11_AUTH_ALGO_80211_OPEN, DOT11_CIPHER_ALGO_WEP40},    
    {DOT11_AUTH_ALGO_80211_OPEN, DOT11_CIPHER_ALGO_WEP104},
    {DOT11_AUTH_ALGO_80211_OPEN, DOT11_CIPHER_ALGO_WEP}
};






#define DOT11_INFO_ELEMENT_ID_SSID                  0
#define DOT11_INFO_ELEMENT_ID_SUPPORTED_RATES       1
#define DOT11_INFO_ELEMENT_ID_FH_PARAM_SET          2
#define DOT11_INFO_ELEMENT_ID_DS_PARAM_SET          3
#define DOT11_INFO_ELEMENT_ID_CF_PARAM_SET          4
#define DOT11_INFO_ELEMENT_ID_TIM                   5
#define DOT11_INFO_ELEMENT_ID_IBSS_PARAM_SET        6
#define DOT11_INFO_ELEMENT_ID_COUNTRY_INFO          7
#define DOT11_INFO_ELEMENT_ID_FH_PARAM              8
#define DOT11_INFO_ELEMENT_ID_FH_PATTERN_TABLE      9
#define DOT11_INFO_ELEMENT_ID_REQUESTED             10
#define DOT11_INFO_ELEMENT_ID_CHALLENGE             16
#define DOT11_INFO_ELEMENT_ID_ERP                   42
#define DOT11_INFO_ELEMENT_ID_RSN                   48
#define DOT11_INFO_ELEMENT_ID_EXTD_SUPPORTED_RATES  50
#define DOT11_INFO_ELEMENT_ID_VENDOR_SPECIFIC       221


#pragma pack(push, 1)

typedef struct {
    UCHAR   ElementID;      // Element Id
    UCHAR   Length;         // Length of SSID
} DOT11_INFO_ELEMENT, * PDOT11_INFO_ELEMENT;
#define DOT11_IE_SSID_MAX_LENGTH    (DOT11_SSID_MAX_LENGTH + sizeof(DOT11_INFO_ELEMENT))
#define DOT11_IE_RATES_MAX_LENGTH   (8 + sizeof(DOT11_INFO_ELEMENT))

typedef union _DOT11_ERP_IE {
    struct {
        UCHAR           NonERPPresent: 1;
        UCHAR           UseProtection: 1;
        UCHAR           BarkerPreambleMode: 1;
        UCHAR           Reserved: 5;
    };
} DOT11_ERP_IE, * PDOT11_ERP_IE;

typedef union DOT11_OUI_HEADER {
    struct {
        UCHAR OUI[3];
        UCHAR Type;
    };
    UNALIGNED ULONG uValue;
} DOT11_OUI_HEADER, * PDOT11_OUI_HEADER;

typedef union {
    struct {
        USHORT          ESS: 1;
        USHORT          IBSS: 1;
        USHORT          CFPollable: 1;
        USHORT          CFPollRequest: 1;
        USHORT          Privacy: 1;
        USHORT          ShortPreamble: 1;
        USHORT          PBCC: 1;
        USHORT          ChannelAgility: 1;
        USHORT          Reserved: 2;
        USHORT          ShortSlotTime:1;
        USHORT          Reserved2: 2;
        USHORT          DSSSOFDM: 1;
        USHORT          Reserved3: 2;
    };

    USHORT usValue;

} DOT11_CAPABILITY, * PDOT11_CAPABILITY;

typedef struct DOT11_BEACON_FRAME {
    ULONGLONG           Timestamp;      // the value of sender's TSFTIMER
    USHORT              BeaconInterval; // the number of time units between target beacon transmission times
    DOT11_CAPABILITY    Capability;
    //DOT11_INFO_ELEMENT  InfoElements;
} DOT11_BEACON_FRAME, * PDOT11_BEACON_FRAME;

typedef struct DOT11_ASSOC_REQUEST_FRAME {
    DOT11_CAPABILITY Capability;
    USHORT usListenInterval;

    // SSID
    // Supported Rates

} DOT11_ASSOC_REQUEST_FRAME, * PDOT11_ASSOC_REQUEST_FRAME;

typedef struct DOT11_ASSOC_RESPONSE_FRAME {
    DOT11_CAPABILITY Capability;
    USHORT usStatusCode;
    USHORT usAID;

    // Supported Rates

} DOT11_ASSOC_RESPONSE_FRAME, * PDOT11_ASSOC_RESPONSE_FRAME;

typedef struct _XEN_ASSOCIATION_COMPLETION_PARAMETERS {
    DOT11_ASSOCIATION_COMPLETION_PARAMETERS Params;
    ULONG                                   PhyId;
    DOT11_BEACON_FRAME                      BeaconFrame;
} XEN_ASSOCIATION_COMPLETION_PARAMETERS, *PXEN_ASSOCIATION_COMPLETION_PARAMETERS;

typedef enum _DOT11_FRAME_TYPE {
    DOT11_FRAME_TYPE_MANAGEMENT = 0,
    DOT11_FRAME_TYPE_CONTROL = 1,
    DOT11_FRAME_TYPE_DATA = 2,
    DOT11_FRAME_TYPE_RESERVED = 3,
} DOT11_FRAME_TYPE, *PDOT11_FRAME_TYPE;

typedef struct _DOT11_FRAME_CTRL {
    USHORT  Version: 2;
    USHORT  Type: 2;
    USHORT  Subtype: 4;
    USHORT  ToDS: 1;
    USHORT  FromDS: 1;
    USHORT  MoreFrag: 1;
    USHORT  Retry: 1;
    USHORT  PwrMgt: 1;
    USHORT  MoreData: 1;
    USHORT  WEP: 1;
    USHORT  Order: 1;
} DOT11_FRAME_CTRL, *PDOT11_FRAME_CTRL;

CASSERT(sizeof(DOT11_FRAME_CTRL) == 2);

typedef union _DOT11_SEQUENCE_CONTROL {
    struct {
        USHORT  FragmentNumber: 4;
        USHORT  SequenceNumber: 12;
    };
    USHORT Value;
} DOT11_SEQUENCE_CONTROL, *PDOT11_SEQUENCE_CONTROL;

CASSERT(sizeof(DOT11_SEQUENCE_CONTROL) == 2);

typedef struct _DOT11_DATA_SHORT_HEADER {
    DOT11_FRAME_CTRL        FrameControl;
    USHORT                  DurationID;
    DOT11_MAC_ADDRESS       Address1;
    DOT11_MAC_ADDRESS       Address2;
    DOT11_MAC_ADDRESS       Address3;
    DOT11_SEQUENCE_CONTROL  SequenceControl;
} DOT11_DATA_SHORT_HEADER, *PDOT11_DATA_SHORT_HEADER;

CASSERT(sizeof(DOT11_DATA_SHORT_HEADER) == 24);

typedef struct _DOT11_MAC_BASIC_HEADER {
    DOT11_FRAME_CTRL    FrameControl;
    USHORT              DurationID;
    DOT11_MAC_ADDRESS   Address1;
} DOT11_MAC_BASIC_HEADER, *PDOT11_MAC_BASIC_HEADER;

typedef struct _DOT11_MAC_DATA_HEADER {
    DOT11_DATA_SHORT_HEADER FrameHeader;
    UCHAR                   LLC[6];
    USHORT                  Protocol;
} DOT11_MAC_DATA_HEADER, *PDOT11_MAC_DATA_HEADER;

CASSERT(sizeof(DOT11_MAC_DATA_HEADER) == 32);

#define DOT11_ASSOCIATION_PARAMS_REVISION_1 1

/*
typedef struct DOT11_ASSOCIATION_PARAMS {
  NDIS_OBJECT_HEADER Header;
  DOT11_MAC_ADDRESS  BSSID;
  ULONG              uAssocRequestIEsOffset;
  ULONG              uAssocRequestIEsLength;
} DOT11_ASSOCIATION_PARAMS, *PDOT11_ASSOCIATION_PARAMS;
*/

#pragma pack(pop)



typedef struct _SEC_ATTRIBUTES {
    USHORT wpa_key_mgmt;
    struct {
        USHORT rsn_preauth: 1;
        USHORT peerkey: 1;
        USHORT wmm_enabled: 1;
    };
} SEC_ATTRIBUTES, *PSEC_ATTRIBUTES;

typedef union _AUTH_ALGORITHMS {
    struct
    {
        USHORT Open: 1;
        USHORT SharedKey: 1;
        USHORT Wpa: 1;
        USHORT WpaPsk: 1;
        USHORT Rsna: 1;
        USHORT RsnaPsk: 1;
    };
    USHORT Value: 8;
} AUTH_ALGORITHMS, *PAUTH_ALGORITHMS;

typedef union _CIPHER_ALGORITHMS {
    struct
    {
        USHORT None: 1;
        USHORT Wep: 1;
        USHORT Wep40: 1;
        USHORT Wep104: 1;
        USHORT Tkip: 1;
        USHORT Ccmp: 1;
    };
    USHORT Value: 8;
} CIPHER_ALGORITHMS, *PCIPHER_ALGORITHMS;

typedef struct _XEN_BSS_ENTRY {
    DOT11_BSS_ENTRY Entry;
    ULONG XenStoreEntry;
    DOT11_SSID SSID;
    SEC_ATTRIBUTES SecAttribs;
    AUTH_ALGORITHMS Auth;
    CIPHER_ALGORITHMS GroupCipher;
    CIPHER_ALGORITHMS Cipher;
    PVOID WpaInformationElement;
    ULONG WpaInfoElementLen;
} XEN_BSS_ENTRY, *PXEN_BSS_ENTRY;

typedef struct _WLAN_ADAPTER {
    NDIS_SPIN_LOCK                      Lock;
    NDIS_HANDLE                         WorkItem;

    PV4V_CONFIG                         V4vConfig;
    HANDLE                              V4vThread;
    KEVENT                              V4vShutdownComplete;
    NDIS_STATUS                         V4vStartupStatus;

    BOOLEAN                             RadioOn;
    BOOLEAN                             PhyEnabled;
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
    DOT11_BSS_TYPE                      BSSType;
    DOT11_RATE_SET                      OperationalRateSet;
    DOT11_DATA_RATE_MAPPING_TABLE       OperationalRateMap;
    DOT11_REG_DOMAINS_SUPPORT_VALUE     RegDomains;
    DOT11_STATISTICS                    Stats;
    ULONG                               DesiredPhyList[WLAN_PHY_MAX_COUNT];
    ULONG                               DesiredPhyCount;
    ULONG                               CurrentPhyId;
    ULONG                               CurrentChannel;
    USHORT                              CurrentAssocID;
    DOT11_OPERATION_MODE_CAPABILITY     OperationModeCapability;
    PDOT11_PRIVACY_EXEMPTION_LIST       PrivacyExemptionList;
    BOOLEAN                             XenConnected;
    DOT11_SUPPORTED_PHY_TYPES           SupportedPhyTypes;
    DOT11_SUPPORTED_DATA_RATES_VALUE_V2 SupportedDataRatesValue;

    DOT11_AUTH_ALGORITHM                AuthAlgorithm;
    DOT11_CIPHER_ALGORITHM              UnicastCipherAlgorithm;
    DOT11_CIPHER_ALGORITHM              MulticastCipherAlgorithm;

    ULONG                               PMKIDCount;
    DOT11_PMKID_ENTRY                   PMKIDList;

    ULONG                               AdditionalIESize;
    PVOID                               AdditionalIEData;

    XEN_BSS_ENTRY                       AssociatedBss;
    XEN_BSS_ENTRY                       DesiredBss;
    ULONG                               ScannedBssCount;
    XEN_BSS_ENTRY                       ScannedBss[WLAN_BSSID_MAX_COUNT];

} WLAN_ADAPTER, *PWLAN_ADAPTER;


//
// Supplicant stuff
//

#define WPA_PUT_LE16(a, val)			\
	do {					\
		(a)[1] = (UCHAR)(((USHORT) (val)) >> 8);	\
		(a)[0] = (UCHAR)(((USHORT) (val)) & 0xff);	\
	} while (0)

#define WPA_PUT_BE32(a, val)					\
	do {							\
		(a)[0] = (UCHAR) ((((ULONG) (val)) >> 24) & 0xff);	\
		(a)[1] = (UCHAR) ((((ULONG) (val)) >> 16) & 0xff);	\
		(a)[2] = (UCHAR) ((((ULONG) (val)) >> 8) & 0xff);	\
		(a)[3] = (UCHAR) (((ULONG) (val)) & 0xff);		\
	} while (0)

#define RSN_SELECTOR_PUT(a, val) WPA_PUT_BE32((UCHAR *) (a), (val))

#define BIT(x) (1 << (x))

#define WPA_SELECTOR_LEN 4

#define PMKID_LEN 16
#define RSN_NUM_REPLAY_COUNTERS_16 3

/* IEEE 802.11, 7.3.2.25.3 RSN Capabilities */
#define WPA_CAPABILITY_PREAUTH BIT(0)
#define WPA_CAPABILITY_NO_PAIRWISE BIT(1)
/* B2-B3: PTKSA Replay Counter */
/* B4-B5: GTKSA Replay Counter */
#define WPA_CAPABILITY_MFPR BIT(6)
#define WPA_CAPABILITY_MFPC BIT(7)
#define WPA_CAPABILITY_PEERKEY_ENABLED BIT(9)

#define WPA_CIPHER_NONE BIT(0)
#define WPA_CIPHER_WEP40 BIT(1)
#define WPA_CIPHER_WEP104 BIT(2)
#define WPA_CIPHER_TKIP BIT(3)
#define WPA_CIPHER_CCMP BIT(4)

#define RSN_SELECTOR_LEN 4

#define RSN_SELECTOR(a, b, c, d) \
    ((((ULONG) (a)) << 24) | (((ULONG) (b)) << 16) | (((ULONG) (c)) << 8) | \
     (ULONG) (d))

#define RSN_AUTH_KEY_MGMT_UNSPEC_802_1X RSN_SELECTOR(0x00, 0x0f, 0xac, 1)
#define RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X RSN_SELECTOR(0x00, 0x0f, 0xac, 2)
#define RSN_AUTH_KEY_MGMT_802_1X_SHA256 RSN_SELECTOR(0x00, 0x0f, 0xac, 5)
#define RSN_AUTH_KEY_MGMT_PSK_SHA256 RSN_SELECTOR(0x00, 0x0f, 0xac, 6)

#define RSN_CIPHER_SUITE_NONE RSN_SELECTOR(0x00, 0x0f, 0xac, 0)
#define RSN_CIPHER_SUITE_WEP40 RSN_SELECTOR(0x00, 0x0f, 0xac, 1)
#define RSN_CIPHER_SUITE_TKIP RSN_SELECTOR(0x00, 0x0f, 0xac, 2)
#define RSN_CIPHER_SUITE_CCMP RSN_SELECTOR(0x00, 0x0f, 0xac, 4)
#define RSN_CIPHER_SUITE_WEP104 RSN_SELECTOR(0x00, 0x0f, 0xac, 5)

#define WLAN_EID_RSN 48
#define WLAN_EID_VENDOR_SPECIFIC 221
#define WPA_OUI_TYPE RSN_SELECTOR(0x00, 0x50, 0xf2, 1)

#define WPA_VERSION 1
#define RSN_VERSION 1

#define WPA_AUTH_KEY_MGMT_NONE RSN_SELECTOR(0x00, 0x50, 0xf2, 0)
#define WPA_AUTH_KEY_MGMT_UNSPEC_802_1X RSN_SELECTOR(0x00, 0x50, 0xf2, 1)
#define WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X RSN_SELECTOR(0x00, 0x50, 0xf2, 2)
#define WPA_CIPHER_SUITE_NONE RSN_SELECTOR(0x00, 0x50, 0xf2, 0)
#define WPA_CIPHER_SUITE_WEP40 RSN_SELECTOR(0x00, 0x50, 0xf2, 1)
#define WPA_CIPHER_SUITE_TKIP RSN_SELECTOR(0x00, 0x50, 0xf2, 2)
#define WPA_CIPHER_SUITE_CCMP RSN_SELECTOR(0x00, 0x50, 0xf2, 4)
#define WPA_CIPHER_SUITE_WEP104 RSN_SELECTOR(0x00, 0x50, 0xf2, 5)

#define WPA_KEY_MGMT_IEEE8021X BIT(0)
#define WPA_KEY_MGMT_PSK BIT(1)
#define WPA_KEY_MGMT_NONE BIT(2)
#define WPA_KEY_MGMT_IEEE8021X_NO_WPA BIT(3)
#define WPA_KEY_MGMT_WPA_NONE BIT(4)
#define WPA_KEY_MGMT_FT_IEEE8021X BIT(5)
#define WPA_KEY_MGMT_FT_PSK BIT(6)
#define WPA_KEY_MGMT_IEEE8021X_SHA256 BIT(7)
#define WPA_KEY_MGMT_PSK_SHA256 BIT(8)
#define WPA_KEY_MGMT_WPS BIT(9)

#define RtlStringCbPrintf RtlStringCbPrintfA

//
// End of supplicant stuff
//

NDIS_OID XennetWlanSupportedOids[] =
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
    OID_802_3_PERMANENT_ADDRESS,    // Only in Wireless
    OID_802_3_CURRENT_ADDRESS,      // Only in Wireless
    OID_802_3_MULTICAST_LIST,       // Only in Wireless
    OID_802_3_MAXIMUM_LIST_SIZE,    // Only in Wireless
    /* RJP OID_OFFLOAD_ENCAPSULATION,
    OID_TCP_OFFLOAD_PARAMETERS,*/
    OID_PNP_SET_POWER,              // Only in Wireless

    /* 802.11 specific OIDs */
    OID_DOT11_MPDU_MAX_LENGTH,
    OID_DOT11_OPERATION_MODE_CAPABILITY,
    OID_DOT11_CURRENT_OPERATION_MODE,
    OID_DOT11_RESET_REQUEST,
    OID_DOT11_NIC_POWER_STATE,
    OID_DOT11_STATION_ID,
    OID_DOT11_OPERATIONAL_RATE_SET,
    OID_DOT11_BEACON_PERIOD,
    OID_DOT11_MAC_ADDRESS,
    OID_DOT11_CURRENT_ADDRESS,
    OID_DOT11_PERMANENT_ADDRESS,
    OID_DOT11_RTS_THRESHOLD,
    OID_DOT11_FRAGMENTATION_THRESHOLD,
    OID_DOT11_CURRENT_REG_DOMAIN,
    OID_DOT11_SCAN_REQUEST,
    OID_DOT11_ENUM_BSS_LIST,
    OID_DOT11_FLUSH_BSS_LIST,
    OID_DOT11_POWER_MGMT_REQUEST,
    OID_DOT11_DESIRED_SSID_LIST,
    OID_DOT11_DESIRED_BSSID_LIST,
    OID_DOT11_DESIRED_BSS_TYPE,
    OID_DOT11_EXCLUDED_MAC_ADDRESS_LIST,
    OID_DOT11_CONNECT_REQUEST,
    OID_DOT11_STATISTICS,
    OID_DOT11_ENABLED_AUTHENTICATION_ALGORITHM,
    OID_DOT11_ENABLED_UNICAST_CIPHER_ALGORITHM,
    OID_DOT11_ENABLED_MULTICAST_CIPHER_ALGORITHM,
    OID_DOT11_SUPPORTED_UNICAST_ALGORITHM_PAIR,
    OID_DOT11_SUPPORTED_MULTICAST_ALGORITHM_PAIR,
    OID_DOT11_CIPHER_KEY_MAPPING_KEY,
    OID_DOT11_ENUM_ASSOCIATION_INFO,
    OID_DOT11_DISCONNECT_REQUEST,
    OID_DOT11_DESIRED_PHY_LIST,
    OID_DOT11_CURRENT_PHY_ID,
    OID_DOT11_MEDIA_STREAMING_ENABLED,
    OID_DOT11_UNREACHABLE_DETECTION_THRESHOLD,
    OID_DOT11_ACTIVE_PHY_LIST,
    OID_DOT11_HARDWARE_PHY_STATE,
    OID_DOT11_IBSS_PARAMS,
    OID_DOT11_AUTO_CONFIG_ENABLED,
    OID_DOT11_SAFE_MODE_ENABLED,
    OID_DOT11_HIDDEN_NETWORK_ENABLED,
    OID_DOT11_SUPPORTED_PHY_TYPES,
    OID_DOT11_EXCLUDE_UNENCRYPTED,
    OID_DOT11_PRIVACY_EXEMPTION_LIST,
    OID_DOT11_REG_DOMAINS_SUPPORT_VALUE,
    OID_DOT11_MULTI_DOMAIN_CAPABILITY_IMPLEMENTED,
    OID_DOT11_EXTSTA_CAPABILITY,
    OID_DOT11_DATA_RATE_MAPPING_TABLE,    
    OID_DOT11_CIPHER_DEFAULT_KEY_ID,
    OID_DOT11_CIPHER_DEFAULT_KEY,
    OID_DOT11_MULTICAST_LIST,
    OID_DOT11_ASSOCIATION_PARAMS,
    OID_DOT11_UNICAST_USE_GROUP_ENABLED,
    OID_DOT11_CURRENT_CHANNEL,
    OID_DOT11_PMKID_LIST
};

//
// Macros for assigning and verifying NDIS_OBJECT_HEADER
//
#define MP_ASSIGN_NDIS_OBJECT_HEADER(_header, _type, _revision, _size) \
    (_header).Type = _type; \
    (_header).Revision = _revision; \
    (_header).Size = _size; 

ULONG XennetWlanSupportedOidsSize = sizeof(XennetWlanSupportedOids);

static NDIS_STATUS
WlanGetBackendValues (
    IN  PWLAN_ADAPTER WlanAdapter
    );

static NDIS_STATUS
WlanSet80211Attributes (
    IN  PADAPTER Adapter
    );

static VOID
WlanAdapterUpdateStatistics (
    IN  PADAPTER  Adapter
    );

NDIS_STATUS
WlanPerformScan (
    IN PADAPTER Adapter
    );

static VOID
SetSupportedDataRates (
    IN PWLAN_ADAPTER WlanAdapter,
    ULONG DataRate
    );

static VOID
WlanDisconnectRequest (
    PADAPTER          Adapter,
    DOT11_ASSOC_STATUS DiscReason
    );

#endif
