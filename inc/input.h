//
// input.h - Xen Windows PV Mouse Driver user mode interface
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


#ifndef INPUT_H
#define INPUT_H

#define XENINP_DRIVER_NAME    L"xeninp"
#define XENINP_DEVICE_NAME    L"\\Device\\xeninp"
#define XENINP_SYMBOLIC_NAME  L"\\DosDevices\\Global\\xeninp"
#define XENINP_USER_FILE_NAME L"\\\\.\\Global\\xeninp"
#define XENINP_BASE_FILE_NAME L"xeninp"

#define XENM2B_DRIVER_NAME    L"xenm2b"
#define XENM2B_DEVICE_NAME    L"\\Device\\xenm2b"
#define XENM2B_SYMBOLIC_NAME  L"\\DosDevices\\Global\\xenm2b"
#define XENM2B_USER_FILE_NAME L"\\\\.\\Global\\xenm2b"
#define XENM2B_BASE_FILE_NAME L"xenm2b"

typedef struct _XENINP_ACCELERATION {
    ULONG Acceleration;
} XENINP_ACCELERATION, *PXENINP_ACCELERATION;

/* XENINP I/O Control Function Codes */
#define XENINP_FUNC_ACCELERATION 0x10

#define	XENINP_IOCTL_ACCELERATION CTL_CODE(FILE_DEVICE_UNKNOWN, XENINP_FUNC_ACCELERATION, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Kernel Mode Only Bits
#if defined(XENINP_DRIVER)

//TODO Read DIC out of the registry in the future
#define XENMOU_DIC 128

#pragma pack(push, 1)
typedef struct _XENMOU_EVENT {
	ULONG RevFlags;
	ULONG Data;
} XENMOU_EVENT, *PXENMOU_EVENT;
#pragma pack(pop)

#define XENMOU_GET_REVISION(v) ((USHORT)(v >> 16) & 0xFFFF)
#define XENMOU_TEST_FLAG(v, f) (((((USHORT)(v) & 0xFFFF) & f) == f) ? TRUE : FALSE)
#define XENMOU_GET_ABS_XDATA(v) ((USHORT)(v) & 0xFFFF)
#define XENMOU_GET_ABS_YDATA(v) ((USHORT)(v >> 16) & 0xFFFF)
#define XENMOU_GET_REL_XDATA(v) ((SHORT)(v & 0xFFFF))
#define XENMOU_GET_REL_YDATA(v) ((SHORT)((v >> 16) & 0xFFFF))
#define XENMOU_GET_WDATA(v) ((USHORT)(v) & 0xFFFF)

#pragma pack(push, 1)
typedef struct _XENMOU2_EVENT {
	ULONG TypeCode;
	ULONG Value;
} XENMOU2_EVENT, *PXENMOU2_EVENT;
#pragma pack(pop)

#define XENMOU2_GET_TYPE(v) ((USHORT)(v) & 0xFFFF)
#define XENMOU2_GET_CODE(v) ((USHORT)(v >> 16) & 0xFFFF)

#define XENMOU2_NAME_LENGTH 40

#pragma pack(push, 1)
typedef struct _XENMOU2_DEV_CONFIG {
    char  Name[XENMOU2_NAME_LENGTH]; // This is the name of the device, in text.
    ULONG EvBits;     // A bit mask indicating which types are used. Eg, 0xB
                      // would indicate SYN events, KEY and ABS events, but not
                      // REL events (Or any other type). DEV events are always
                      // present, and not included in this bit mask.
    ULONG AbsBits[2]; // A bit mask (64 bits) indicating which absolute codes
                      // are used. Each bit corresponds to the code number, so
                      // 0x3 would indicate ABS_X codes and ABS_Y codes.
    ULONG RelBits;    // A bit mask indicating which relative codes are used.
    ULONG BtnBits[3]; // A bit mask (96 bits) indicating which button codes are
                      // in use.  This bit mask starts at code 0x100, and not
                      // 0x0 as for the other bit mask. A bit mask of 0xC00
                      // would indicate the device is capable of emitting
                      // BTN_LEFT and BTN_RIGHT events.

} XENMOU2_DEV_CONFIG, *PXENMOU2_DEV_CONFIG;
#pragma pack(pop)

// The XenM2B HID Minidriver <-> Bus Driver interface

#define XENM2B_CLIENT_INTERFACE_VERSION (('C' << 8) | 0x01)
#define XENM2B_SERVER_INTERFACE_VERSION (('V' << 8) | 0x01)

// {1E0DCC5F-328D-4d8f-B365-5398C15590CA}
DEFINE_GUID(XENM2B_CLIENT_INTERFACE_GUID,
0x1e0dcc5f, 0x328d, 0x4d8f, 0xb3, 0x65, 0x53, 0x98, 0xc1, 0x55, 0x90, 0xca);

typedef struct _XENHID_OPERATIONS {
    NTSTATUS (*pSendReport)(PVOID pContext, PVOID pBuffer, ULONG Length);
} XENHID_OPERATIONS, *PXENHID_OPERATIONS;

typedef struct _XENM2B_OPERATIONS {
    NTSTATUS (*pGetHidAttributes)(PVOID pContext, PVOID pBuffer, ULONG_PTR *pLength);
    NTSTATUS (*pGetHidDescriptor)(PVOID pContext, PVOID pBuffer, ULONG_PTR *pLength);
    NTSTATUS (*pGetReportDescriptor)(PVOID pContext, PVOID pBuffer, ULONG_PTR *pLength);
    NTSTATUS (*pGetFeature)(PVOID pContext, PVOID pBuffer, ULONG_PTR *pLength);
    NTSTATUS (*pSetFeature)(PVOID pContext, PVOID pBuffer, ULONG_PTR *pLength);
    NTSTATUS (*pGetString)(PVOID pContext, ULONG StringId, PVOID pBuffer, ULONG_PTR *pLength);
    NTSTATUS (*pProcessReports)(PVOID pContext);
} XENM2B_OPERATIONS, *PXENM2B_OPERATIONS;

typedef struct _XENM2B_CLIENT_INTERFACE {
    INTERFACE Header;
    union {
        PXENHID_OPERATIONS pXenHid;
        PXENM2B_OPERATIONS pXenM2B;
    } Operations;
} XENM2B_CLIENT_INTERFACE, *PXENM2B_CLIENT_INTERFACE;

#endif

#endif  // INPUT_H
