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

#include "common.h"

#pragma NDIS_INIT_FUNCTION(DriverEntry)

//
// Global miniport data.
//

static NDIS_HANDLE MiniportDriverHandle;

NTSTATUS 
DriverEntry (
    IN  PDRIVER_OBJECT   DriverObject,
    IN  PUNICODE_STRING  RegistryPath
    )
{
    NDIS_STATUS ndisStatus;
    NDIS_MINIPORT_DRIVER_CHARACTERISTICS mpChars;

    if (*InitSafeBootMode > 0)
        return NDIS_STATUS_SUCCESS;

    if (!XmCheckXenutilVersionString(FALSE, XENUTIL_CURRENT_VERSION))
        return STATUS_REVISION_MISMATCH;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    //
    // Register miniport with NDIS.
    //

    NdisZeroMemory(&mpChars, sizeof(mpChars));
    mpChars.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS,
    mpChars.Header.Size = sizeof(NDIS_MINIPORT_DRIVER_CHARACTERISTICS);
    mpChars.Header.Revision = NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1;

    mpChars.MajorNdisVersion = XENNET_NDIS_MAJOR_VERSION;
    mpChars.MinorNdisVersion = XENNET_NDIS_MINOR_VERSION;
    mpChars.MajorDriverVersion = XENNET_MAJOR_DRIVER_VERSION;
    mpChars.MinorDriverVersion = XENNET_MINOR_DRIVER_VERSION;

    mpChars.CancelOidRequestHandler = AdapterCancelOidRequest;
    mpChars.CancelSendHandler = AdapterCancelSendNetBufferLists;
    mpChars.CheckForHangHandlerEx = AdapterCheckForHang;
    mpChars.InitializeHandlerEx = MiniportInitialize;
    mpChars.HaltHandlerEx = AdapterHalt;
    mpChars.OidRequestHandler = AdapterOidRequest;    
    mpChars.PauseHandler = AdapterPause;      
    mpChars.DevicePnPEventNotifyHandler  = MPPnPEventHandler; //AdapterPnPEventHandler;
    mpChars.ResetHandlerEx = AdapterReset;
    mpChars.RestartHandler = AdapterRestart;    
    mpChars.ReturnNetBufferListsHandler  = AdapterReturnNetBufferLists;
    mpChars.SendNetBufferListsHandler = AdapterSendNetBufferLists;
    mpChars.ShutdownHandlerEx = AdapterShutdown;
    mpChars.UnloadHandler = DriverUnload;

    TraceInfo(("Registering miniport...\n"));
    MiniportDriverHandle = NULL;
    ndisStatus = NdisMRegisterMiniportDriver(DriverObject,
                                             RegistryPath,
                                             NULL,
                                             &mpChars,
                                             &MiniportDriverHandle);
    if (ndisStatus != NDIS_STATUS_SUCCESS ) {
        TraceError(("Failed (0x%08X) to register miniport.\n", ndisStatus));

    } else {
        TraceNotice(("Registered miniport.\n"));
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return ndisStatus;
}

VOID 
DriverUnload (
    IN  PDRIVER_OBJECT  DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (MiniportDriverHandle) {
        TraceNotice(("Deregistering miniport...\n"));
        NdisMDeregisterMiniportDriver(MiniportDriverHandle);
        TraceNotice(("Deregistered miniport.\n"));
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return;
}
