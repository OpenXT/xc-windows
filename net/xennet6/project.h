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

#include "xsapi.h"
#include "netif.h"
#include "xennet_common.h"
#include "scsiboot.h"

//
// Build Tag Control Information (TCI).
//

#define BUILD_TCI(pcp, cfi, vid)    \
    (USHORT)((((pcp) & 7) << 13) | (((cfi) & 1) << 12) | ((vid) & 0xFFF))

#define UNPACK_TCI(n, tci) {                                \
    (n)->TagHeader.UserPriority = (tci) >> 13;              \
    (n)->TagHeader.CanonicalFormatId = ((tci) >> 12) & 1;   \
    (n)->TagHeader.VlanId = (tci) & 0xFFF;                  \
}

//
// Forward type declarations.
//

typedef struct _ADAPTER ADAPTER, *PADAPTER;
typedef netif_tx_sring_t* PNETIF_TX_SHARED_RING;
typedef netif_rx_sring_t* PNETIF_RX_SHARED_RING;

#define XENNET_PACKET_HDR_SIZE  14

#define mb()                XsMemoryBarrier()
#define wmb()               XsMemoryBarrier()
#define rmb()               XsMemoryBarrier()

#define XENNET_TAG          'TENX'

#define XennetAcquireSpinLock(l, d) {   \
    if (d) {                            \
        NdisDprAcquireSpinLock(l);      \
    } else {                            \
        NdisAcquireSpinLock(l);         \
    }                                   \
}

#define XennetReleaseSpinLock(l, d) {   \
    if (d) {                            \
        NdisDprReleaseSpinLock(l);      \
    } else {                            \
        NdisReleaseSpinLock(l);         \
    }                                   \
}

NTSTATUS 
DriverEntry (
    IN  PDRIVER_OBJECT   DriverObject,
    IN  PUNICODE_STRING  RegistryPath
    );

VOID 
DriverUnload (
    IN  PDRIVER_OBJECT  DriverObject
    );

#define GetNetBufferData(n, o, b, s)    CopyNetBufferData(n, o, (PUCHAR)(b), s, TRUE)

#define SetNetBufferData(n, o, b, s)    CopyNetBufferData(n, o, (PUCHAR)(b), s, FALSE)

__forceinline
int
HexCharToInt(
    CHAR c
    )
{
    if (c >= '0' && c <= '9') {
        return c - '0';

    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;

    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;

    } else {
        ASSERT(FALSE);
    }

    return -1;
}

NDIS_STATUS
MpSetAdapterSettings(
    IN PADAPTER Adapter
    );

NDIS_STATUS
MpGetAdvancedSettings(
    IN PADAPTER Adapter
    );

#include "transmitter.h"
#include "receiver.h"
#include "adapter.h"
#include "miniport.h"
