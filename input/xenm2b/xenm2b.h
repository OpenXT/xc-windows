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

// Xen Windows PV M2B Bus Driver

#ifndef XENM2B_H
#define XENM2B_H

// Compile and link option to use internal debugging routines
#if defined(NO_XENUTIL)
#undef XSAPI
#define XSAPI
#endif

#include "xsapi.h"

#define XENM2B_POOL_TAG         (ULONG)'dihX'
#define XENM2B_SYM_NAME_LENGTH  64
#define XENM2B_PDO_NAME_LENGTH  128
#define XENM2B_MAX_TEXT_LENGTH  128
#define XENM2B_MAX_DEVID_LENGTH 200
#define XENM2B_EVENT_ARRAY_SIZE 32

typedef struct _XENM2B_INTERFACE {
    PVOID              pXenHidContext;
    PXENHID_OPERATIONS pXenHidOperations;
    BOOLEAN            Referenced;
} XENM2B_INTERFACE, *PXENM2B_INTERFACE;

typedef enum _XENM2B_DEVICE_TYPE {
    XenM2BFdo = 1,
    XenM2BPdo = 2
} XENM2B_DEVICE_TYPE;

typedef enum _XENM2B_PNP_STATE {
    PnPStateInvalid = 0,
    PnPStatePresent,        // PDO only
    PnPStateEnumerated,     // PDO only
    PnPStateAdded,          // FDO only
    PnPStateStarted,
    PnPStateStopPending,
    PnPStateStopped,
    PnPStateRemovePending,
    PnPStateSurpriseRemoval,
    PnPStateDeleted
} XENM2B_PNP_STATE;

typedef struct _XENM2B_DEVICE_PNP_STATE {
    FAST_MUTEX       PnPStateMutex;
    XENM2B_PNP_STATE CurrentPnPState;
    XENM2B_PNP_STATE PreviousPnPState;
} XENM2B_DEVICE_PNP_STATE, *PXENM2B_DEVICE_PNP_STATE;

typedef struct _XENM2B_BASE_EXTENSION {
    XENM2B_DEVICE_TYPE Type;
} XENM2B_BASE_EXTENSION, *PXENM2B_BASE_EXTENSION;

typedef struct _XENM2B_HID_CONTEXT XENM2B_HID_CONTEXT, *PXENM2B_HID_CONTEXT;

#define XenM2BDeviceType(e) (((PXENM2B_BASE_EXTENSION)e)->Type)

#define ListForEach(p, h) \
    for (p = (h)->Flink; p != h; p = p->Flink)

typedef struct _XENM2B_FDO_EXTENSION {
    // Set to XenM2BFdo
    XENM2B_DEVICE_TYPE Type;

    // A backpointer to the device object (FDO) for which this is the extension
    PDEVICE_OBJECT pDevice;

    // The physical device (PDO) on the PCI bus
    PDEVICE_OBJECT pBusPdo;

    // The M2B driver
    PDRIVER_OBJECT pDriver;

    // The top of the stack before this filter was added.  AKA the location
    // to which all IRPS should be directed.
    PDEVICE_OBJECT pTopOfStack;

    // Stuffs for symbolic link
    UNICODE_STRING SymbolicLink;
    wchar_t SymbolicLinkText[XENM2B_SYM_NAME_LENGTH];

    // PnP and Power states of this device object
    XENM2B_DEVICE_PNP_STATE DevicePnPState;
    SYSTEM_POWER_STATE SystemPowerState;
    DEVICE_POWER_STATE DevicePowerState;

    // Translated resource descriptor for the MMIO region
    CM_PARTIAL_RESOURCE_DESCRIPTOR XenM2BRegistersDescriptor;

    // Pointer to mapped virtual address for MMIO registers
    PUCHAR pXenM2BRegs;
    PUCHAR pGlobalRegs;
    PUCHAR pEventRegs;
    PUCHAR pConfigRegs;

    // Translated resource descriptor for the interrupt
    CM_PARTIAL_RESOURCE_DESCRIPTOR InterruptDescriptor;

    // ISR and DPC
    PKINTERRUPT pInterruptObject;
    KSPIN_LOCK InterruptSpinLock;
    KDPC EventDpc;
    KSPIN_LOCK DpcSpinLock;

    // Xenmou2 event data
    ULONG EventSize;
    ULONG RWRegSize;
    ULONG ConfigSize;
    ULONG EventRegsPages;
    ULONG EventCount;

    // The Active HID context events are being sent to.
    PXENM2B_HID_CONTEXT pActiveHidCtx;

    // PDO children of the M2B bus
    LIST_ENTRY PdoList;
    KSPIN_LOCK PdoListLock;

    // References for each PDO and one for this FDO
    ULONG References;

} XENM2B_FDO_EXTENSION, *PXENM2B_FDO_EXTENSION;

typedef struct _XENM2B_PDO_EXTENSION {
    // Set to XenM2BPdo
    XENM2B_DEVICE_TYPE Type;

    // A backpointer to the device object for which this is the extension
    PDEVICE_OBJECT pDevice;

    // A pointer to the M2 Bus device that created me
    PDEVICE_OBJECT pFdo;

    // Link to list of PDO's owned by the M2B bus
    LIST_ENTRY ListEntry;

    // Device missing due to a removal event
    BOOLEAN Missing;

    // PnP and Power states of this device object
    XENM2B_DEVICE_PNP_STATE DevicePnPState;
    SYSTEM_POWER_STATE SystemPowerState;
    DEVICE_POWER_STATE DevicePowerState;

    // Interface XenM2B <-> XenHid structure
    XENM2B_INTERFACE Interface;

    // Device name values    
    WCHAR          pDeviceNameW[XENM2B_PDO_NAME_LENGTH];
    WCHAR          pInstanceIDW[XENM2B_PDO_NAME_LENGTH];
    UNICODE_STRING DeviceName;
    UNICODE_STRING InstanceID;

    // HID data and state for this device
    PXENM2B_HID_CONTEXT pHidCtx;

    // Chain for device relations query.
    struct _XENM2B_PDO_EXTENSION *pNextExt;

} XENM2B_PDO_EXTENSION, *PXENM2B_PDO_EXTENSION;

// Bus Device
VOID
XenM2BEventDpc(KDPC *pDpc, VOID *pDeferredContext, VOID *pSysArg1, VOID *pSysArg2);

VOID
XenM2BDeleteDevice(PXENM2B_FDO_EXTENSION pFdoExt);

// HID Context
VOID
XenM2BReleaseHidContext(PXENM2B_HID_CONTEXT pHidCtx);

PHID_DEVICE_ATTRIBUTES
XenM2BGetHidAttributes(PXENM2B_HID_CONTEXT pHidCtx);

PHID_DESCRIPTOR
XenM2BGetHidDescriptor(PXENM2B_HID_CONTEXT pHidCtx);

PUCHAR
XenM2BGetReportDescriptor(PXENM2B_HID_CONTEXT pHidCtx, PULONG pLengthOut);

NTSTATUS
XenM2BGetFeature(PXENM2B_HID_CONTEXT pHidCtx, PHID_XFER_PACKET pHidPacket, ULONG_PTR *pLength);

NTSTATUS
XenM2BSetFeature(PXENM2B_HID_CONTEXT pHidCtx, PHID_XFER_PACKET pHidPacket, ULONG_PTR *pLength);

NTSTATUS
XenM2BGetString(ULONG StringId, PUCHAR* pString, ULONG_PTR* pLength);

// PDO Child Devices
PDEVICE_OBJECT
XenM2BPdoCreate(PXENM2B_FDO_EXTENSION pFdoExt, PCHAR pDeviceName, UCHAR SlotID);

VOID
XenM2BPdoDeleteDevice(PDEVICE_OBJECT pDeviceObject);

VOID
XenM2BPdoLink(PXENM2B_FDO_EXTENSION pFdoExt,
              PXENM2B_PDO_EXTENSION pPdoExt,
              BOOLEAN Locked);

VOID
XenM2BPdoUnlink(PXENM2B_PDO_EXTENSION pPdoExt,
                BOOLEAN Locked);

NTSTATUS
XenM2BPdoPnP(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);

NTSTATUS
XenM2BPdoPower(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);

// Interface

XENM2B_OPERATIONS*
XenM2BGetInterfaceOperations(VOID);

VOID
XenM2BInterfaceReference(PVOID pContext);

VOID
XenM2BInterfaceDereference(PVOID pContext);

// Misc Support
VOID
XenM2BSetPnPState(PXENM2B_DEVICE_PNP_STATE pDevicePnPState,
                  XENM2B_PNP_STATE PnPState);

BOOLEAN
XenM2BRestorePnPState(PXENM2B_DEVICE_PNP_STATE pDevicePnPState,
                      XENM2B_PNP_STATE PnPState);

XENM2B_PNP_STATE
XenM2BGetPnPState(PXENM2B_DEVICE_PNP_STATE pDevicePnPState);

//#define M2B_DEBUG_EVENT_TRACE 1
#if defined(M2B_DEBUG_EVENT_TRACE)
VOID
XenM2BDebugEventTrace(PXENMOU2_EVENT pEvent);
#endif

#endif  // XENM2B_H
