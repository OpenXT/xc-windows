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

ULONG
CopyNetBufferData (
    IN  PNET_BUFFER     NetBuffer,
    IN  ULONG           Offset,
    IN  PUCHAR          Buffer,
    IN  ULONG           Size,
    IN  BOOLEAN         FromNetBuffer
    )
{
    ULONG currLength;
    PMDL currentMdl;
    ULONG dataLength;
    PUCHAR dest;
    PUCHAR end;
    PUCHAR src;

    XM_ASSERT(NetBuffer != NULL);
    XM_ASSERT(Buffer != NULL);

    currentMdl = NET_BUFFER_CURRENT_MDL(NetBuffer);
    dest = Buffer;
    end = dest + Size;
    Offset += NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer);
    dataLength = NET_BUFFER_DATA_LENGTH(NetBuffer);
    while ((currentMdl != NULL) && (dataLength > 0)) {
        NdisQueryMdl(currentMdl, &src, &currLength, NormalPagePriority);
        if (src == NULL) {
            break;
        }

        if (currLength > Offset) { 
            src += Offset;
            currLength -= Offset;
            if (currLength > dataLength) {
                currLength = dataLength;
            }

            if (currLength >= Size) {
                if (FromNetBuffer) {
                    NdisMoveMemory(dest, src, Size);

                } else {
                    NdisMoveMemory(src, dest, Size);
                }

                dest += Size;
                break;
            }

            if (FromNetBuffer) {
                NdisMoveMemory(dest, src, currLength);

            } else {
                NdisMoveMemory(src, dest, currLength);
            }

            Size -= currLength;
            dataLength -= currLength;
            dest += currLength;
            Offset = 0;

        } else {
            Offset -= currLength;
        }

        NdisGetNextMdl(currentMdl, &currentMdl);
    }

    return (ULONG)(dest - Buffer);
}

NDIS_STATUS 
MiniportInitialize (
    IN  NDIS_HANDLE                        MiniportAdapterHandle,
    IN  NDIS_HANDLE                        MiniportDriverContext,
    IN  PNDIS_MINIPORT_INIT_PARAMETERS     MiniportInitParameters
    )
{
    PADAPTER adapter = NULL;
    NDIS_STATUS ndisStatus;
    PCHAR path;
    PDEVICE_OBJECT pdo;
    PCHAR xenbusPath = NULL;
    int i;

    UNREFERENCED_PARAMETER(MiniportDriverContext);
    UNREFERENCED_PARAMETER(MiniportInitParameters);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    //
    // Wait for xenbus to come up.  SMP guests sometimes try and
    // initialise xennet and xenvbd in parallel when they come back
    // from hibernation, and that causes problems.
    //

    if (!xenbus_await_initialisation()) {
        ndisStatus = NDIS_STATUS_DEVICE_FAILED;
        goto exit;
    }

    //
    // 8021P support is disabled by default.
    // It can be turned on by specifying the appropriate PV boot option.
    //

    if (XenPVFeatureEnabled(DEBUG_NIC_8021_P)) {
        XennetMacOptions |= NDIS_MAC_OPTION_8021P_PRIORITY;
    }

    xenbus_write(XBT_NIL, "drivers/xenwnet", XENNET_VERSION);
    NdisMGetDeviceProperty(MiniportAdapterHandle,
                           &pdo,
                           NULL,
                           NULL,
                           NULL,
                           NULL);

    xenbusPath = xenbus_find_frontend(pdo);
    if (!xenbusPath) {
        ndisStatus = NDIS_STATUS_ADAPTER_NOT_FOUND;
        goto exit;
    }

    TraceNotice(("Found '%s' frontend.\n", xenbusPath));
    adapter = XmAllocateZeroedMemory(sizeof(ADAPTER));
    if (adapter == NULL) {
        ndisStatus = NDIS_STATUS_RESOURCES;
        goto exit;
    }

    path = xenbusPath;
    xenbusPath = NULL;

    i = 0;
    do {
        ndisStatus = AdapterInitialize(adapter, MiniportAdapterHandle, path);
        if (ndisStatus != NDIS_STATUS_SUCCESS) {
            TraceWarning (("Waiting for backend...\n"));
            NdisMSleep (1000000);   // 1 sec
        }
    } while ((ndisStatus != NDIS_STATUS_SUCCESS) && (++i < 30));
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        goto exit;
    }

exit:
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        if (adapter) {
			XmFreeMemory(adapter->BackendPath);
			adapter->BackendPath = NULL;
            AdapterDelete(&adapter);
        }

        if (xenbusPath) {
            XmFreeMemory(xenbusPath);
        }
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return ndisStatus;
}
