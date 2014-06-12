//
// xennet.c - Xen network miniport driver
//
// Copyright (c) 2006, XenSource, Inc. - All rights reserved.
//

/*
 * Copyright (c) 2011 Citrix Systems, Inc.
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
#include "scsiboot.h"

#pragma warning( pop )

#pragma NDIS_INIT_FUNCTION(DriverEntry)

extern PULONG InitSafeBootMode;

USHORT NdisVersion;

static PDRIVER_UNLOAD NdisDriverUnload;

static VOID
DriverUnload (
    IN  PDRIVER_OBJECT  DriverObject
    )
{
    TraceInfo(("%s\n", __FUNCTION__));

    NdisDriverUnload(DriverObject);
}

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    First entry point to be called, when this driver is loaded.
    Register with NDIS as an intermediate driver.

Arguments:

    DriverObject - pointer to the system's driver object structure
        for this driver

    RegistryPath - system's registry path for this driver

Return Value:

    STATUS_SUCCESS if all initialization is successful, STATUS_XXX
    error code if not.

--*/
{
    NDIS_STATUS                     Status;
    NDIS_MINIPORT_CHARACTERISTICS   MChars;
    NDIS_HANDLE                     NdisWrapperHandle;

    if (*InitSafeBootMode > 0)
        return NDIS_STATUS_SUCCESS;

    if (!XmCheckXenutilVersionString(FALSE, XENUTIL_CURRENT_VERSION))
        return STATUS_REVISION_MISMATCH;

    TraceInfo(("%s\n", __FUNCTION__));

    Status = NDIS_STATUS_SUCCESS;

    NdisMInitializeWrapper(&NdisWrapperHandle, DriverObject, 
            RegistryPath, NULL);

    NdisZeroMemory(&MChars, sizeof(NDIS_MINIPORT_CHARACTERISTICS));

    MChars.InitializeHandler = MPInitialize;
    MChars.HaltHandler = MPHalt;
    MChars.QueryInformationHandler = MPQueryInformation;
    MChars.SetInformationHandler = MPSetInformation;
    MChars.ResetHandler = MPReset;
    MChars.ReturnPacketHandler = MPReturnPacket;
    MChars.SendPacketsHandler = MPSendPackets;
    MChars.AdapterShutdownHandler = MPAdapterShutdown;
    /* NDIS 5.1 only */
    MChars.PnPEventNotifyHandler = MPPnPEventNotify;

    /* Try NDIS 5.1 first */
    MChars.MajorNdisVersion = 5;
    MChars.MinorNdisVersion = 1;
    TraceDebug (("Registering miniport.\n"));
    Status = NdisMRegisterMiniport(NdisWrapperHandle,
                                   &MChars,
                                   sizeof(NDIS51_MINIPORT_CHARACTERISTICS));
    if (Status == NDIS_STATUS_BAD_VERSION) {
        /* Try 5.0 */
        MChars.MinorNdisVersion = 0;
        Status = NdisMRegisterMiniport(NdisWrapperHandle,
                                       &MChars,
                                       sizeof(NDIS50_MINIPORT_CHARACTERISTICS));
        if (!NT_SUCCESS(Status)) {
            TraceWarning (("Failed to register as an NDIS miniport.\n"));
            return Status;
        }
        TraceNotice (("Registered NDIS5.0 miniport.\n"));
        NdisVersion = XENNET_NDIS_50;
    } else {
        TraceNotice (("Registered NDIS5.1 miniport.\n"));
        NdisVersion = XENNET_NDIS_51;
    }
    TraceDebug (("Registered miniport.\n"));

    NdisDriverUnload = DriverObject->DriverUnload;
    DriverObject->DriverUnload = DriverUnload;

    return(Status);
}
