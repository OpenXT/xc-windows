//
// xeninp.h - Xen Windows PV Input Driver
//
// Copyright (c) 2010 Citrix, Inc.
//

#ifndef XENINP_H
#define XENINP_H

#define XENINP_POOL_TAG         (ULONG)'pniX'
#define XENINP_SYM_NAME_LEN     64
#define XENINP_EVENT_ARRAY_SIZE 32

// i8042 Defaults
#define MOUSE_NUMBER_OF_BUTTONS 2
#define MOUSE_SAMPLE_RATE       60

#define WHEEL_DELTA		120

typedef struct _XENINP_DEVICE_EXTENSION
{
    // A backpointer to the device object for which this is the extension
    PDEVICE_OBJECT pSelf;

    // "THE PDO"  (ejected by the bus)
    PDEVICE_OBJECT pPDO;

    // The top of the stack before this filter was added.  AKA the location
    // to which all IRPS should be directed.
    PDEVICE_OBJECT pTopOfStack;

    // Stuffs for symbolic link
    UNICODE_STRING SymbolicLink;
    wchar_t SymbolicLinkText[XENINP_SYM_NAME_LEN];

    // Number of creates sent down
    LONG EnableCount;

    // Current power state of the device
    DEVICE_POWER_STATE DeviceState;

    // State of the stack and this device object
    BOOLEAN Started;
    BOOLEAN SurpriseRemoved;
    BOOLEAN RemovePending;
    BOOLEAN Removed;

    // Translated resource descriptor for the MMIO region
    CM_PARTIAL_RESOURCE_DESCRIPTOR XenInpRegistersDescriptor;
    
    // Pointer to mapped virtual address for MMIO registers
    PUCHAR pXenInpRegs;
    PUCHAR pGlobalRegs;
    PUCHAR pEventRegs;

    // Translated resource descriptor for the interrupt
    CM_PARTIAL_RESOURCE_DESCRIPTOR InterruptDescriptor;

    // ISR and DPC
    PKINTERRUPT pInterruptObject;
    KSPIN_LOCK InterruptSpinLock;
    KSPIN_LOCK EventLock;

    // Mouse event data
    ULONG EventStructSize;
    ULONG RWStructSize;
    ULONG EventRegsPages;
    ULONG EventCount;
    CONNECT_DATA UpperConnectData;
    MOUSE_INPUT_DATA InputArray[XENMOU_DIC];

} XENINP_DEVICE_EXTENSION, *PXENINP_DEVICE_EXTENSION;

#endif  // XENINP_H
