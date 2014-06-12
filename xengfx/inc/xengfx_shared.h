//
// xengfx_shared.h
//
// Funtionality shared between xengfx driver versions
// implemented in the xengfxsh.lib
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


#ifndef XENGFX_SHARED_H
#define XENGFX_SHARED_H

/// DDK ////

// Some basic types
typedef unsigned short      WORD;
typedef unsigned char       BYTE;
typedef unsigned long       DWORD;

// A pool tag
#define XENGFX_TAG          'XFGX'

#ifndef _NTDDK_

// These definitions are pulled in from the WDK. Pulling in the DDK headers
// directly results in many conflicts and redefinitions with the mini-port
// headers. This is the bare minimum needed to keep xsapi.h happy.
typedef LONG NTSTATUS;
typedef ULONG PFN_NUMBER;
typedef struct _DEVICE_OBJECT *PDEVICE_OBJECT;

#define PAGE_SIZE 4096

#define NTAPI __stdcall

#pragma intrinsic(_InterlockedExchangeAdd)
#pragma intrinsic(_InterlockedExchange)
#define InterlockedExchangeAdd          _InterlockedExchangeAdd
#define InterlockedExchange             _InterlockedExchange

#endif //_NTDDK_

// Compile and link option to use internal debugging routines
#if defined(NO_XENUTIL)
#undef XSAPI
#define XSAPI
#endif

#include "xsapi.h"

typedef VOID (NTAPI *CallbackFuncion_t)(PVOID pCallbackContext,
                                        PVOID pArgument1,
                                        PVOID pArgument2);

PVOID NTAPI XenGfxCreateCallback(const wchar_t *pCallback);
PVOID NTAPI XenGfxRegisterCallback(PVOID pCallbackObject, CallbackFuncion_t pCallbackFuncion, PVOID pContext);
VOID NTAPI XenGfxNotifyCallback(PVOID pCallbackObject, PVOID pContext);
VOID NTAPI XenGfxUnregisterCallback(PVOID pCallbackHandle);
VOID NTAPI XenGfxDestroyCallback(PVOID pCallbackObject);
KIRQL NTAPI XenGfxRaiseIrqlToDpcLevel();
VOID NTAPI XenGfxLowerIrql(KIRQL Irql);
PVOID XenGfxAllocateContiguousPages(ULONG Count);
VOID XenGfxFreeContiguousPages(PVOID pPages, ULONG Count);
PVOID XenGfxAllocateSystemPages(ULONG Count, PVOID *ppContex);
VOID XenGfxFreeSystemPages(PVOID pContext);
VOID XenGfxMemoryBarrier();
BOOLEAN XenGfxGetPhysicalAddressess(PVOID pVirtualAddress,
                                    PHYSICAL_ADDRESS *pPhysArray,
                                    ULONG PageCount);

/// VGA/VBE ///

#define XENGFX_VGA_FRAME_BUFFER_BASE      0xA0000
#define XENGFX_VGA_FRAME_BUFFER_LENGTH    0x20000
#define XENGFX_EDID_SIZE                  0x80

#define XENGFX_VBE_PORT_BASE              0x01CE
#define XENGFX_SHADOW_PORT_BASE           0x3800

VOID NTAPI XenGfxInt10SpinLock(UCHAR *pShadowPortBase);
VOID NTAPI XenGfxInt10SpinUnlock(UCHAR *pShadowPortBase);

BOOLEAN NTAPI XenGfxVgaResetMode3(UCHAR *pShadowPortBase, UCHAR *pVbePortBase);
BOOLEAN NTAPI XenGfxVgaInitBiosCalls(VOID);
BOOLEAN NTAPI XenGfxVgaSetMode(USHORT ModeNumber);

#pragma pack(push, 1)
typedef struct
{
   char     Signature[4];
   USHORT   Version;
   USHORT   OemStringOffset;
   USHORT   OemStringSeg;
   BYTE     Capabilities[4];
   USHORT   VideoModeOffset;
   USHORT   VideoModeSeg;
   USHORT   TotalMemory;
   USHORT   OemRev;
   USHORT   OemVendorOffset;
   USHORT   OemVendorSeg;
   USHORT   OemProductOffset;
   USHORT   OemProductSeg;
   USHORT   OemProductRevOffset;
   USHORT   OemProductRevSeg;
   USHORT   Reserved[111];
   char     OemData[256];
} VBE_EXT_INFO, *PVBE_EXT_INFO;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct 
{
   WORD ModeAttributes;
   BYTE  WinAAttributes;
   BYTE  WinBAttributes;
   WORD WinGranularity;
   WORD WinSize;
   WORD WinASegment;
   WORD WinBSegment;
   DWORD WinFuncPtr;
   WORD BytesPerScanLine;

   WORD XResolution;
   WORD YResolution;
   BYTE  XCharSize;
   BYTE  YCharSize;
   BYTE  NumberOfPlanes;
   BYTE  BitsPerPixel;
   BYTE  NumberOfBanks;
   BYTE  MemoryModel;
   BYTE  BankSize;
   BYTE  NumberOfImagePages;
   BYTE  Reserved_page;

   BYTE  RedMaskSize;
   BYTE  RedFieldPosition;
   BYTE  GreenMaskSize;
   BYTE  GreenFieldPosition;
   BYTE  BlueMaskSize;
   BYTE  BlueFieldPosition;
   BYTE  RsvdMaskSize;
   BYTE  RsvdFieldPosition;
   BYTE  DirectColorModeInfo;

   DWORD PhysBasePtr;
   DWORD OffScreenMemOffset;
   WORD OffScreenMemSize;

   WORD LinBytesPerScanLine;
   BYTE  BnkNumberOfPages;
   BYTE  LinNumberOfPages;
   BYTE  LinRedMaskSize;
   BYTE  LinRedFieldPosition;
   BYTE  LinGreenMaskSize;
   BYTE  LinGreenFieldPosition;
   BYTE  LinBlueMaskSize;
   BYTE  LinBlueFieldPosition;
   BYTE  LinRsvdMaskSize;
   BYTE  LinRsvdFieldPosition;
   DWORD MaxPixelClock;
} VBE_MODE_INFO, *PVBE_MODE_INFO;
#pragma pack(pop)

BOOLEAN NTAPI XenGfxVbeInitialize(UCHAR *pShadowPortBase);
BOOLEAN NTAPI XenGfxVbeGetExtInfo(VBE_EXT_INFO *pVbeExtInfo, ULONG *pModeCount);
BOOLEAN NTAPI XenGfxVbeGetModeInfo(USHORT ModeNumber, VBE_MODE_INFO* pVbeModeInfo);
BOOLEAN NTAPI XenGfxVbeSetMode(USHORT ModeNumber);
BOOLEAN NTAPI XenGfxVbeGetEdid(UCHAR *pChildDescriptor, ULONG Length);
BOOLEAN NTAPI XenGfxVbeGetCurrentMode(USHORT * XRes, USHORT *YRes, USHORT *bpp);
USHORT XenGfxVbeGetAlignedStride(const WORD CurrentModeStride);

/// XENGFX Core ///

#define XENGFX_INVALID_MODE_INDEX    0xFFFFFFFF
#define XENGFX_XGFXREG_SIZE          0x300000
#define XENGFX_XGFXREG_MAX_SIZE      0x600000 // actually only 3M right now but leave room
#define XENGFX_UNSET_BPP             0
#define XENGFX_STD_BPP               32
#define XENGFX_PAGE_ALIGN_MASK       0xFFF
#define XENGFX_DEFAULT_VENDORID      0x1234;
#define XENGFX_DEFAULT_DEVICEID      0x1111;
#define XENGFX_UNDEFINED_SCANLINE    ((UINT)-1)

#define XENGFX_MASK_ALIGN(x, m) (((ULONG)x + m) & ~m)
#define XENGFX_BYTE_ALIGN(x, m) (((ULONG)x + (m - 1)) & ~(m - 1))

#define XENGFX_MIN(a, b) ((a)<(b)?(a):(b))
#define XENGFX_MAX(a, b) ((a)>(b)?(a):(b))

#define XENGFX_MODE_FLAG_BASE_SET    0x00000001
#define XENGFX_MODE_FLAG_EDID_MODE   0x00000002

typedef struct _XENGFX_MODE {
    ULONG XResolution;
    ULONG YResolution;
    ULONG BitsPerPixel;
    ULONG ScreenStride;
    ULONG XgfxFormat;
    ULONG Flags;
} XENGFX_MODE, *PXENGFX_MODE;

// EDID structures for 1.1 - 1.3 and E-EDID
#pragma pack(push, 1)
typedef struct _XENGFX_EDID {
    UCHAR Header[8];
    UCHAR VendorID[2];
    UCHAR ProductID[2];
    UCHAR SerialNumber[4];
    UCHAR WeekYearMFG[2];
    UCHAR Version[1];
    UCHAR Revision[1];
    UCHAR Middle[34];
    UCHAR Descriptor1[18]; // starts at 0x0036
    UCHAR Descriptor2[18]; // starts at 0x0048
    UCHAR Descriptor3[18]; // starts at 0x005A
    UCHAR Descriptor4[18]; // starts at 0x006C
    UCHAR ExtensionFlag[1];
    UCHAR Checksum[1];
} XENGFX_EDID, *PXENGFX_EDID;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _XENGFX_TIMING_DESCRIPTOR {
    UCHAR PixelClock[2];
    UCHAR HorizontalActive;
    UCHAR HorizontalBlanking;
    UCHAR HorizontalActiveHigh;
    UCHAR VerticalActive;
    UCHAR VerticalBlanking;
    UCHAR VerticalActiveHigh;
    UCHAR HorizontalSyncOffset;
    UCHAR HorizontalSyncPulseWidth;
    UCHAR VerticalSyncOffsetPulseWidth;
    UCHAR HorizontalVerticalHighSyncBits;
    UCHAR HorizontalImageSize;
    UCHAR VerticalImageSize;
    UCHAR HorizontalImageSizeHigh;
    UCHAR HorizontalBorder;
    UCHAR VerticalBorder;
    UCHAR Interlaced;
} XENGFX_TIMING_DESCRIPTOR, *PXENGFX_TIMING_DESCRIPTOR;
#pragma pack(pop)

#define XENGFX_MONITOR_BT_NAME          0xFC
#define XENGFX_MONITOR_BT_DESCRIPTION   0xFE
#define XENGFX_MONITOR_BT_SERIAL_NUMBER 0xFF

#pragma pack(push, 1)
typedef struct _XENGFX_MONITOR_DESCRIPTOR {
    UCHAR PixelClock[2]; // == 00 00
    UCHAR Unused;
    UCHAR BlockType; // for BT == FC/FE/FF/
    UCHAR Text[14];
} XENGFX_MONITOR_DESCRIPTOR, *PXENGFX_MONITOR_DESCRIPTOR;
#pragma pack(pop)

typedef struct _XENGFX_MODE_VALUES {
    // Input
    XENGFX_EDID *pEdid;
    ULONG MaxHorizontal;
    ULONG MaxVertical;
    ULONG StrideAlignment;
    ULONG XgfxFormat;

    // Output
    ULONG MaxStride;
    ULONG MaxHeight;
    XENGFX_MODE *pModes;
} XENGFX_MODE_VALUES, *PXENGFX_MODE_VALUES;

ULONG NTAPI XenGfxCreateModes(XENGFX_MODE_VALUES *pModeValues);
ULONG NTAPI XenGfxCreateBaseSetModes(XENGFX_MODE_VALUES *pModeValues);
VOID NTAPI XenGfxReleaseModes(XENGFX_MODE *pModes);
ULONG NTAPI XenGfxGetBitsPerPixel(ULONG XgfxFormat);

#endif //XENGFX_SHARED_H
