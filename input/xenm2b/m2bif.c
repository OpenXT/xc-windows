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

// Xen Windows PV M2B Bus interface

#include <ntddk.h>
#include <ntstrsafe.h>
#include <hidport.h>
#include "input.h"
#include "xmou.h"
#include "xenm2b.h"

static NTSTATUS
XenM2BInterfaceGetHidAttributes(PVOID pContext,
                                PVOID pBuffer,
                                ULONG_PTR *pLength)
{
    PXENM2B_INTERFACE     pInterface = pContext;
    PXENM2B_PDO_EXTENSION pPdoExt;
    NTSTATUS              Status;

    pPdoExt = CONTAINING_RECORD(pInterface, XENM2B_PDO_EXTENSION, Interface);

    TraceDebug(("%s: ====>\n", __FUNCTION__));

    Status = STATUS_INVALID_BUFFER_SIZE;
    if (*pLength >= sizeof(HID_DEVICE_ATTRIBUTES)) {
        RtlCopyMemory(pBuffer,
                      XenM2BGetHidAttributes(pPdoExt->pHidCtx),
                      sizeof(HID_DEVICE_ATTRIBUTES));
        *pLength = sizeof(HID_DEVICE_ATTRIBUTES);
        Status = STATUS_SUCCESS;
    }

    TraceDebug(("%s: <==== %08x\n", __FUNCTION__, Status));
    return Status;
}

static NTSTATUS
XenM2BInterfaceGetHidDescriptor(PVOID pContext,
                                PVOID pBuffer,
                                ULONG_PTR *pLength)
{
    PXENM2B_INTERFACE     pInterface = pContext;
    PXENM2B_PDO_EXTENSION pPdoExt;
    NTSTATUS              Status;

    pPdoExt = CONTAINING_RECORD(pInterface, XENM2B_PDO_EXTENSION, Interface);

    TraceDebug(("%s: ====>\n", __FUNCTION__));

    Status = STATUS_INVALID_BUFFER_SIZE;
    if (*pLength >= sizeof(HID_DESCRIPTOR)) {
        RtlCopyMemory(pBuffer,
                      XenM2BGetHidDescriptor(pPdoExt->pHidCtx),
                      sizeof(HID_DESCRIPTOR));
        *pLength = sizeof(HID_DESCRIPTOR);
        Status = STATUS_SUCCESS;
    }

    TraceDebug(("%s: <==== %08x\n", __FUNCTION__, Status));
    return Status;
}

static NTSTATUS
XenM2BInterfaceGetReportDescriptor(PVOID pContext,
                                   PVOID pBuffer,
                                   ULONG_PTR *pLength)
{
    PXENM2B_INTERFACE     pInterface = pContext;
    PXENM2B_PDO_EXTENSION pPdoExt;
    PUCHAR                pDesc;
    ULONG                 Length;
    NTSTATUS              Status;

    pPdoExt = CONTAINING_RECORD(pInterface, XENM2B_PDO_EXTENSION, Interface);

    TraceDebug(("%s: ====>\n", __FUNCTION__));

    pDesc = XenM2BGetReportDescriptor(pPdoExt->pHidCtx, &Length);

    // Copy report descriptor structure to buffer
    Status = STATUS_INVALID_BUFFER_SIZE;
    if (*pLength >= Length) {
        RtlCopyMemory(pBuffer, pDesc, Length);
        *pLength = Length;
        Status = STATUS_SUCCESS;
    }

    TraceDebug(("%s: <==== %08x\n", __FUNCTION__, Status));
    return Status;
}

static NTSTATUS
XenM2BInterfaceGetFeature(PVOID pContext,
                          PVOID pBuffer,
                          ULONG_PTR *pLength)
{
    PXENM2B_INTERFACE     pInterface = pContext;
    PXENM2B_PDO_EXTENSION pPdoExt;
    NTSTATUS              Status;

    pPdoExt = CONTAINING_RECORD(pInterface, XENM2B_PDO_EXTENSION, Interface);

    TraceDebug(("%s: ====>\n", __FUNCTION__));

    // Copy feature information to the xfer packet.
    Status = XenM2BGetFeature(pPdoExt->pHidCtx, (PHID_XFER_PACKET)pBuffer, pLength);

    TraceDebug(("%s: <==== %08x\n", __FUNCTION__, Status));
    return Status;
}

static NTSTATUS
XenM2BInterfaceSetFeature(PVOID pContext,
                          PVOID pBuffer,
                          ULONG_PTR *pLength)
{
    PXENM2B_INTERFACE     pInterface = pContext;
    PXENM2B_PDO_EXTENSION pPdoExt;
    NTSTATUS              Status;

    pPdoExt = CONTAINING_RECORD(pInterface, XENM2B_PDO_EXTENSION, Interface);

    TraceDebug(("%s: ====>\n", __FUNCTION__));

    // Copy feature information to the xfer packet.
    Status = XenM2BSetFeature(pPdoExt->pHidCtx, (PHID_XFER_PACKET)pBuffer, pLength);

    TraceDebug(("%s: <==== %08x\n", __FUNCTION__, Status));
    return Status;
}

static NTSTATUS
XenM2BInterfaceGetString(PVOID pContext,
                         ULONG StringId,
                         PVOID pBuffer,
                         ULONG_PTR* pLength)
{
    PXENM2B_INTERFACE     pInterface = pContext;
    PXENM2B_PDO_EXTENSION pPdoExt;
    PUCHAR                pString;
    NTSTATUS              Status;

    pPdoExt = CONTAINING_RECORD(pInterface, XENM2B_PDO_EXTENSION, Interface);

    Status = XenM2BGetString(StringId, &pString, pLength);
    if (NT_SUCCESS(Status))
        RtlCopyMemory(pBuffer, pString, *pLength);

    return Status;
}

static NTSTATUS
XenM2BInterfaceProcessReports(PVOID pContext)
{
    PXENM2B_INTERFACE     pInterface = pContext;
    PXENM2B_PDO_EXTENSION pPdoExt;
    PXENM2B_FDO_EXTENSION pFdoExt;

    pPdoExt = CONTAINING_RECORD(pInterface, XENM2B_PDO_EXTENSION, Interface);
    pFdoExt = pPdoExt->pFdo->DeviceExtension;

    // Queue the request as a DPC to sync it with the rest of the event
    // processing in xenm2b devices.
    KeInsertQueueDpc(&pFdoExt->EventDpc, NULL, NULL);

    return STATUS_SUCCESS;
}

static XENM2B_OPERATIONS XenM2BOperations = {
    XenM2BInterfaceGetHidAttributes,
    XenM2BInterfaceGetHidDescriptor,
    XenM2BInterfaceGetReportDescriptor,
    XenM2BInterfaceGetFeature,
    XenM2BInterfaceSetFeature,
    XenM2BInterfaceGetString,
    XenM2BInterfaceProcessReports
};

XENM2B_OPERATIONS*
XenM2BGetInterfaceOperations(VOID)
{
    return &XenM2BOperations;
}

VOID
XenM2BInterfaceReference(PVOID pContext)
{
    PXENM2B_INTERFACE     pInterface = pContext;
    PXENM2B_PDO_EXTENSION pPdoExt;

    pPdoExt = CONTAINING_RECORD(pInterface, XENM2B_PDO_EXTENSION, Interface);

    TraceDebug(("%s: ====>\n", __FUNCTION__));

    if (!pInterface->Referenced)
        pInterface->Referenced = TRUE;
}

VOID
XenM2BInterfaceDereference(PVOID pContext)
{
    PXENM2B_INTERFACE     pInterface = pContext;
    PXENM2B_PDO_EXTENSION pPdoExt;
    KIRQL                 Irql;

    pPdoExt = CONTAINING_RECORD(pInterface, XENM2B_PDO_EXTENSION, Interface);

    TraceDebug(("%s: ====>\n", __FUNCTION__));

    ASSERT(pInterface->Referenced);

    pInterface->Referenced = FALSE;

    pInterface->pXenHidOperations = NULL;
    pInterface->pXenHidContext = NULL;
}

