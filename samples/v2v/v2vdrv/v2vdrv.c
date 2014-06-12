/*
 * Copyright (c) 2009 Citrix Systems, Inc.
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

#include <ntddk.h>
#include <ntstrsafe.h>
#include "v2vk.h"
#include "v2vdrv.h"

PDRIVER_OBJECT g_driverObject = NULL;
PDEVICE_OBJECT g_deviceObject = NULL;
UNICODE_STRING g_symbolicLink = {0};
wchar_t g_symbolicLinkText[V2V_MAX_NAME_STRING];

ULONG g_osMajorVersion = 0;
ULONG g_osMinorVersion = 0;


NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath);
static DRIVER_UNLOAD DriverUnload;
static VOID NTAPI DriverUnload(PDRIVER_OBJECT driverObject);

static DRIVER_DISPATCH V2vMjDispatchRequest;
static NTSTATUS NTAPI
V2vMjDispatchRequest(PDEVICE_OBJECT deviceObject, PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObject);

	irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

static DRIVER_DISPATCH V2vMjCreate;
static NTSTATUS NTAPI
V2vMjCreate(PDEVICE_OBJECT deviceObject, PIRP irp)
{
	NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp;

    UNREFERENCED_PARAMETER(deviceObject);

	irpSp = IoGetCurrentIrpStackLocation(irp);
	irpSp->FileObject->FsContext = NULL;
	irpSp->FileObject->FsContext2 = NULL;

    status = V2vkCreateContext(irpSp->FileObject);
	
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}

static DRIVER_DISPATCH V2vMjCleanup;
static NTSTATUS NTAPI
V2vMjCleanup(PDEVICE_OBJECT deviceObject, PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;

	PIO_STACK_LOCATION irpSp;

    UNREFERENCED_PARAMETER(deviceObject);

	irpSp = IoGetCurrentIrpStackLocation(irp);

    status = V2vkDestroyContext(irpSp->FileObject);
	ASSERT(irpSp->FileObject->FsContext == NULL);    

    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}

static DRIVER_DISPATCH V2vMjClose;
static NTSTATUS NTAPI
V2vMjClose(PDEVICE_OBJECT deviceObject, PIRP irp)
{
    NTSTATUS           status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpSp;

    UNREFERENCED_PARAMETER(deviceObject);

	irpSp = IoGetCurrentIrpStackLocation(irp);
    ASSERT(irpSp->FileObject->FsContext == NULL);

    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}

static DRIVER_DISPATCH V2vMjDeviceControl;
static NTSTATUS NTAPI
V2vMjDeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp)
{
	NTSTATUS            status = STATUS_SUCCESS;
	PIO_STACK_LOCATION  irpSp;
	ULONG               ioControlCode;
	PVOID               ioBuffer;
	ULONG               ioInLen;
	ULONG               ioOutLen;

	UNREFERENCED_PARAMETER(deviceObject);

	irpSp = IoGetCurrentIrpStackLocation(irp);

	ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
	ioBuffer      = irp->AssociatedIrp.SystemBuffer;
    ioInLen       = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ioOutLen      = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	DbgPrint("%s =IOCTL= 0x%x\n", V2VDRV_LOGTAG, ioControlCode);

	switch (ioControlCode) {
    case V2VK_IOCTL_INIT_INTERNAL_XFER:
		{
			V2VK_IOCD_INIT_INTERNAL_XFER *iixfer = (V2VK_IOCD_INIT_INTERNAL_XFER*)ioBuffer;
			if (ioInLen == sizeof(V2VK_IOCD_INIT_INTERNAL_XFER)) {
				status = V2vkInitInternalXfer(irpSp->FileObject, iixfer);
			}
			else {
				DbgPrint("%s Invalid input for init internal xfer.\n", V2VDRV_LOGTAG);
				status = STATUS_INVALID_PARAMETER;
			}

			irp->IoStatus.Information = 0;
			irp->IoStatus.Status = status;
			break;
		}
    case V2VK_IOCTL_INIT_FILE_XFER:
		{
			V2VK_IOCD_INIT_FILE_XFER *ifxfer = (V2VK_IOCD_INIT_FILE_XFER*)ioBuffer;
			if (ioInLen == sizeof(V2VK_IOCD_INIT_FILE_XFER)) {
				status = V2vkInitFileXfer(irpSp->FileObject, ifxfer);
			}
			else {
				DbgPrint("%s Invalid input for init file xfer.\n", V2VDRV_LOGTAG);
				status = STATUS_INVALID_PARAMETER;
			}

			irp->IoStatus.Information = 0;
			irp->IoStatus.Status = status;
			break;
		}
    case V2VK_IOCTL_RUN_CONNECTOR:
		{
            status = V2vkRunConnector(irpSp->FileObject);
			
			irp->IoStatus.Information = 0;
			irp->IoStatus.Status = status;
			break;
        }
    case V2VK_IOCTL_RUN_LISTENER:
		{
            status = V2vkRunListener(irpSp->FileObject);
			
			irp->IoStatus.Information = 0;
			irp->IoStatus.Status = status;
			break;
        }
	default:
        status = STATUS_INVALID_PARAMETER;
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = status;		
	}

	if (status != STATUS_PENDING) {
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}

	return status;
}

#pragma alloc_text(INIT, DriverEntry)

NTSTATUS NTAPI
DriverEntry(PDRIVER_OBJECT driverObject,
			PUNICODE_STRING registryPath)
{
	NTSTATUS       status = STATUS_SUCCESS;
	PDEVICE_OBJECT deviceObject = NULL;
	BOOLEAN        validSymbolicLink = FALSE;
	LONG           ldx;
	UNICODE_STRING deviceName;

    UNREFERENCED_PARAMETER(registryPath);	

	DbgPrint("%s Initializing...\n", V2VDRV_LOGTAG);

	g_driverObject = driverObject;
    g_deviceObject = NULL;

	RtlStringCchCopyW(g_symbolicLinkText, V2V_MAX_NAME_STRING, V2V_SYMBOLIC_NAME);		
	RtlInitUnicodeString(&g_symbolicLink, g_symbolicLinkText);

    PsGetVersion(&g_osMajorVersion, &g_osMinorVersion, NULL, NULL);

	do {
		if (g_osMajorVersion < 5) {
			DbgPrint("%s Windows 2000 or later operating systems supported!\n", V2VDRV_LOGTAG);
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		driverObject->DriverUnload = DriverUnload;
    
		// Set pointers to MJ routines
		for (ldx = 0; ldx < IRP_MJ_MAXIMUM_FUNCTION; ldx++) {
			driverObject->MajorFunction[ldx] = V2vMjDispatchRequest;
		}
		
		driverObject->MajorFunction[IRP_MJ_CREATE]         = V2vMjCreate;
		driverObject->MajorFunction[IRP_MJ_CLOSE]          = V2vMjClose;
		driverObject->MajorFunction[IRP_MJ_CLEANUP]        = V2vMjCleanup;
		driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = V2vMjDeviceControl;

		// Create our device
		RtlInitUnicodeString(&deviceName, V2V_DEVICE_NAME);

		status = IoCreateDevice(driverObject, 0, &deviceName, FILE_DEVICE_NETWORK, 0, FALSE, &deviceObject);
		if (!NT_SUCCESS(status)) {
			DbgPrint("%s Failed to create device object - error: 0x%x\n", V2VDRV_LOGTAG, status);
			break;
		}
        g_deviceObject = deviceObject;

		// Create our symbolic link
		status = IoCreateSymbolicLink(&g_symbolicLink, &deviceName);
		if (!NT_SUCCESS(status)) {
			DbgPrint("%s Failed to create symbolic - error: 0x%x\n", V2VDRV_LOGTAG, status);
			break;
		}
		validSymbolicLink = TRUE;
		
	} while (FALSE);

	// Test for succes includes STATUS_PENDING
	if (!NT_SUCCESS(status)) {
		DbgPrint("%s Initialization Failed! - error: 0x%8.8x\n", V2VDRV_LOGTAG, status);

		if (validSymbolicLink) {
			IoDeleteSymbolicLink(&g_symbolicLink);
		}

		if (deviceObject) {
			IoDeleteDevice(deviceObject);
			g_deviceObject = NULL;
		}			
	}
	
	return status;
}

static VOID NTAPI
DriverUnload(PDRIVER_OBJECT driverObject)
{
	UNREFERENCED_PARAMETER(driverObject);
	
	DbgPrint("%s Driver shutting down...\n", V2VDRV_LOGTAG);
	
	if (g_deviceObject) {
		IoDeleteDevice(g_deviceObject);
		g_deviceObject = NULL;
	}
	IoDeleteSymbolicLink(&g_symbolicLink);
}
