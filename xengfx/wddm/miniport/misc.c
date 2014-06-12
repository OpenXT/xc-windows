//
// misc.c - Xen Windows PV WDDM Miniport Driver misc helper routines.
//
// Copyright (c) 2010 Citrix, Inc. - All rights reserved.
//

/*
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


#include "xengfxwd.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE,XenGfxReadConfigSpace)
#pragma alloc_text(PAGE,XenGfxReadRegistryValues)
#pragma alloc_text(PAGE,XenGfxGetPrivateData)
#pragma alloc_text(PAGE,XenGfxFreeResources)
#endif

NTSTATUS
XenGfxReadConfigSpace(PDEVICE_OBJECT pDeviceObject,
                      PVOID pBuffer,
                      ULONG Offset,
                      ULONG Length)
{
    KEVENT Event;
    NTSTATUS Status = STATUS_SUCCESS;
    PIRP pIrp;
    IO_STATUS_BLOCK IoStatusBlock;
    PIO_STACK_LOCATION pIsl;
    PDEVICE_OBJECT pTargetObject;
    PAGED_CODE();

    do {
        KeInitializeEvent(&Event, NotificationEvent, FALSE);
        pTargetObject = IoGetAttachedDeviceReference(pDeviceObject);
        if (pTargetObject == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        pIrp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
                                            pTargetObject,
                                            NULL,
                                            0,
                                            NULL,
                                            &Event,
                                            &IoStatusBlock);
        if (pIrp == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        pIsl = IoGetNextIrpStackLocation(pIrp);
        pIsl->MinorFunction = IRP_MN_READ_CONFIG;
        pIsl->Parameters.ReadWriteConfig.WhichSpace = PCI_WHICHSPACE_CONFIG;
        pIsl->Parameters.ReadWriteConfig.Buffer = pBuffer;
        pIsl->Parameters.ReadWriteConfig.Offset = Offset;
        pIsl->Parameters.ReadWriteConfig.Length = Length;

        // Initialize the status to error in case the bus driver does not 
        // set it correctly.
        pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
        Status = IoCallDriver(pTargetObject, pIrp);
        if (Status == STATUS_PENDING) {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL );
            Status = IoStatusBlock.Status;
        }
    } while (FALSE);

    if (pTargetObject != NULL)
        ObDereferenceObject(pTargetObject);

    return Status;
}

VOID
XenGfxReadRegistryValues(XENGFX_DEVICE_EXTENSION *pXenGfxExtension,
                         PUNICODE_STRING pDeviceRegistryPath)
{
#define _XENGFX_REGBUF_SPACE 240
    NTSTATUS Status;
    HANDLE   Key = NULL;
    ULONG    Len = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(WCHAR)*_XENGFX_REGBUF_SPACE; // room for 240 UNICODE chars
    ULONG    LenOut;
    UNICODE_STRING                 ValueName;
    OBJECT_ATTRIBUTES              ObjectAttrs;
    KEY_VALUE_PARTIAL_INFORMATION *pKvpi = NULL;
    PAGED_CODE();
	
    do {
        TraceVerbose(("%s Reading XENGFX device registry location: %.*ws\n",
                      __FUNCTION__, pDeviceRegistryPath->Length >> 1, pDeviceRegistryPath->Buffer));

        // Make a buffer for registry data
        pKvpi = (KEY_VALUE_PARTIAL_INFORMATION*)ExAllocatePoolWithTag(PagedPool, Len, XENGFX_TAG);
        if (pKvpi == NULL) {
            TraceError(("%s Failed to alloc registry read buffer!!\n", __FUNCTION__));
            break;
        }

        // Open the device key, it should be present.
        InitializeObjectAttributes(&ObjectAttrs, pDeviceRegistryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = ZwOpenKey(&Key, KEY_QUERY_VALUE, &ObjectAttrs);
        if (!NT_SUCCESS(Status)) {
            TraceError(("%s Failed to open registry key for driver - error: 0x%x\n", __FUNCTION__, Status));
            break;
        }

        // Get the ChildDeviceCount value - continue if it is not there.
        RtlInitUnicodeString(&ValueName, XENGFX_REG_CHILDDEVICECOUNT);
        RtlZeroMemory(pKvpi, Len);

        Status = ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, pKvpi, Len, &LenOut);
        if ((!NT_SUCCESS(Status))||(pKvpi->Type != REG_DWORD)||(pKvpi->DataLength != sizeof(ULONG))) {
            TraceInfo(("%s Could not query ChildDeviceCount (may not be present) - type: %d length: 0x%x status: 0x%x\n", 
                       __FUNCTION__, pKvpi->Type, pKvpi->DataLength, Status));          
        }
        else
            pXenGfxExtension->VCrtcRegistryCount = *((ULONG*)pKvpi->Data);

        // Get the VidPnTracing value - continue if it is not there.
        RtlInitUnicodeString(&ValueName, XENGFX_REG_VIDPNTRACING);
        RtlZeroMemory(pKvpi, Len);

        Status = ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, pKvpi, Len, &LenOut);
        if ((!NT_SUCCESS(Status))||(pKvpi->Type != REG_DWORD)||(pKvpi->DataLength != sizeof(ULONG))) {
            TraceInfo(("%s Could not query VidPnTracing (may not be present) - type: %d length: 0x%x status: 0x%x\n", 
                       __FUNCTION__, pKvpi->Type, pKvpi->DataLength, Status));
        }
        else
            pXenGfxExtension->VidPnTracing = (*((ULONG*)pKvpi->Data) != 0) ? TRUE : FALSE;

        // Get the VidPnTracing value - continue if it is not there.
        RtlInitUnicodeString(&ValueName, XENGFX_REG_DEBUGLOGNAME);
        RtlZeroMemory(pKvpi, Len);

        Status = ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, pKvpi, Len, &LenOut);
        if ((!NT_SUCCESS(Status))||(pKvpi->Type != REG_SZ)||(pKvpi->DataLength > _XENGFX_REGBUF_SPACE*sizeof(WCHAR))) {
            TraceInfo(("%s Could not query DebugLogName (may not be present) - type: %d length: 0x%x status: 0x%x\n", 
                       __FUNCTION__, pKvpi->Type, pKvpi->DataLength, Status));
        }
        else {
            RtlStringCchCopyW(pXenGfxExtension->DebugLogName,
                              pKvpi->DataLength/sizeof(WCHAR),
                              (CONST WCHAR*)pKvpi->Data);
            TraceInfo(("%s DebugLogName: %S\n", __FUNCTION__, pXenGfxExtension->DebugLogName));
        }

    } while (FALSE);

    if (pKvpi != NULL)
        ExFreePoolWithTag(pKvpi, XENGFX_TAG);
}

VOID
XenGfxGetPrivateData(XENGFX_DEVICE_EXTENSION *pXenGfxExtension)
{
    NTSTATUS Status;
    PAGED_CODE();

    pXenGfxExtension->PrivateData.Magic = XENGFX_D3D_MAGIC;
    pXenGfxExtension->PrivateData.Version = XENGFX_D3D_VERSION;

    // Read PCI values
    Status = XenGfxReadConfigSpace(pXenGfxExtension->pPhysicalDeviceObject,
                                   &(pXenGfxExtension->PrivateData.VendorId),
                                   0,
                                   2);
    if (!NT_SUCCESS(Status)) {
        TraceWarning(("XenGfxReadConfigSpace(VendorId) failed - error: 0x%x\n", Status));
        // Set a default
        pXenGfxExtension->PrivateData.VendorId = XENGFX_DEFAULT_VENDORID;
    }

    Status = XenGfxReadConfigSpace(pXenGfxExtension->pPhysicalDeviceObject,
                                   &(pXenGfxExtension->PrivateData.DeviceId),
                                   2,
                                   2);
    if (!NT_SUCCESS(Status)) {
        TraceWarning(("XenGfxReadConfigSpace(DeviceId) failed - error: 0x%x\n", Status));
        // Set a default
        pXenGfxExtension->PrivateData.DeviceId = XENGFX_DEFAULT_DEVICEID;
    }

    pXenGfxExtension->PrivateData.ApertureSize = PAGE_SIZE*pXenGfxExtension->GartPfns;
    RtlMoveMemory(&(pXenGfxExtension->PrivateData.AdapterGuid),
                  &(pXenGfxExtension->DxgkStartInfo.AdapterGuid),
                  sizeof(GUID));
}

VOID
XenGfxFreeResources(XENGFX_DEVICE_EXTENSION *pXenGfxExtension)
{
    PAGED_CODE();
    // T & S Level 3
    XenGfxDisableVCrtcs(pXenGfxExtension);

    if (pXenGfxExtension->pSources != NULL) {
        ExFreePoolWithTag(pXenGfxExtension->pSources, XENGFX_TAG);
        pXenGfxExtension->pSources = NULL;
    }

    XenGfxFreeVCrtcBanks(pXenGfxExtension);

    if (pXenGfxExtension->pXgfxRegs != NULL) {
        MmUnmapIoSpace(pXenGfxExtension->pXgfxRegs,
                       pXenGfxExtension->XgfxRegistersDescriptor.u.Memory.Length);
        pXenGfxExtension->pXgfxRegs = NULL;
        pXenGfxExtension->pGartRegs = NULL;
        pXenGfxExtension->pVCrtcsRegs = NULL;
        pXenGfxExtension->pGlobalRegs = NULL;        
        pXenGfxExtension->pGartBaseReg = NULL;
    }

    RtlZeroMemory(&pXenGfxExtension->GraphicsApertureDescriptor,
                  sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));
    RtlZeroMemory(&pXenGfxExtension->XgfxRegistersDescriptor,
                  sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR));

    pXenGfxExtension->pPhysicalDeviceObject = NULL;
    pXenGfxExtension->hDxgkHandle = NULL;
}

VOID
XenGfxChangeXgfxMode(PXENGFX_DEVICE_EXTENSION pXenGfxExtension, BOOLEAN Enable)
{
    ULONG ControlReg;

    if ((Enable)&&(!pXenGfxExtension->XgfxMode)) {
        ControlReg = READ_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_CONTROL));

        // Enable XGFX hires mode and endable interrupts.
        ControlReg |= XGFX_CONTROL_INT_EN|XGFX_CONTROL_HIRES_EN;

        WRITE_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_CONTROL), ControlReg);

        pXenGfxExtension->XgfxMode = TRUE;
    }
    else if ((!Enable)&&(pXenGfxExtension->XgfxMode)) {
        ControlReg = READ_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_CONTROL));

        // Disable XGFX mode
        ControlReg &= ~(XGFX_CONTROL_INT_EN|XGFX_CONTROL_HIRES_EN);

        WRITE_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_CONTROL), ControlReg);

        pXenGfxExtension->XgfxMode = FALSE;
    }
}

ULONG
XenGfxBppFromDdiFormat(D3DDDIFORMAT DdiFormat)
{
    ULONG i;

    for (i = 0; i < XENGFX_D3D_FORMAT_COUNT; i++) {
        if (g_XenGfxFormatMap[i].DdiFormat == DdiFormat)
            return g_XenGfxFormatMap[i].BitsPerPixel;
    }

    return XENGFX_UNSET_BPP;
}

ULONG
XenGfxXgfxFormatFromDdiFormat(D3DDDIFORMAT DdiFormat)
{
    ULONG i;

    for (i = 0; i < XENGFX_D3D_FORMAT_COUNT; i++) {
        if (g_XenGfxFormatMap[i].DdiFormat == DdiFormat)
            return g_XenGfxFormatMap[i].XgfxFormat;
    }

    return XGFX_VCRTC_VALID_FORMAT_NONE;
}

D3DDDIFORMAT
XenGfxDdiFormatFromXgfxFormat(ULONG XgfxFormat)
{
    ULONG i;

    for (i = 0; i < XENGFX_D3D_FORMAT_COUNT; i++) {
        if (g_XenGfxFormatMap[i].XgfxFormat == XgfxFormat)
            return g_XenGfxFormatMap[i].DdiFormat;
    }

    return D3DDDIFMT_UNKNOWN;
}

static ULONG64 g_EnterCounter1 = 0;
static ULONG64 g_EnterCounter2 = 0;
static ULONG64 g_EnterCounter3 = 0;
static ULONG64 g_LeaveCounter  = 0;

VOID
_XenGfxEnter(const char *pFunction, ULONG Level)
{
    TraceVerbose(("====> '%s'.\n", pFunction));
    if (Level == 1)
        g_EnterCounter1++;
    else if (Level == 2)
        g_EnterCounter2++;
    else
        g_EnterCounter3++;
}

VOID
_XenGfxLeave(const char *pFunction)
{
    TraceVerbose(("<==== '%s'.\n", pFunction));
    g_LeaveCounter++;
}
