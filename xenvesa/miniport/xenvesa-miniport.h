//
// xenvesa-miniport.h - Xen Windows Vesa Miniport Driver
//
// Copyright (c) 2008 Citrix, Inc.
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


#ifndef XEN_VESA_H
#define XEN_VESA_H

#define VBE_GET_CONTROLLER_INFORMATION       0x4F00
#define VBE_GET_MODE_INFORMATION             0x4F01
#define VBE_SET_VBE_MODE                     0x4F02
#define VBE_SET_GET_PALETTE_DATA             0x4F09
#define VBE_POWER_MANAGEMENT_EXTENSIONS      0x4F10
#define VBE_DISPLAY_IDENTIFICATION           0x4F15

#define VBE_READ_EDID                        0x1
#define VBE_EDID_SIZE                        0x80
#define VBE_SUCCESS                          0x4F

#define VBE_MEMORYMODEL_PACKEDPIXEL          0x04
#define VBE_MEMORYMODEL_DIRECTCOLOR          0x06
#define VBE_MODEATTR_LINEAR                  0x80

#if 0
#define VBE_IO_INDEX_PORT                    0x01CE
#define VBE_IO_DATA_PORT                     0x01CF
#define VBE_DISPI_INDEX_ID                   0x0
#define VBE_DISPI_ID0                        0xB0C0
#endif

#define DPMS_MODE_POWERON                    0x0
#define DPMS_MODE_STANDBY                    0x100
#define DPMS_MODE_SUSPEND                    0x200
#define DPMS_MODE_POWEROFF                   0x400

#define XEN_VESA_FRAME_BUFFER                0xA0000
#define XEN_VESA_FRAME_BUFFER_LENGTH         0x20000

#define XENVESA_TAG 'XVBE'

typedef unsigned short      WORD;
typedef unsigned char       BYTE;
typedef unsigned long       DWORD;

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

typedef struct 
{
	PVOID Private;

    VBE_EXT_INFO VbeExtInfo;
    USHORT * VbeModeNumbers;
    PVBE_MODE_INFO VbeModeInfo;
    ULONG VbeModeCount;
    USHORT VbeCurrentMode;

    UNICODE_STRING RegistryPath;

} XEN_VESA_DEVICE_EXTENSION, *PXEN_VESA_DEVICE_EXTENSION;

NTSTATUS XenVideoPortSetRegistryParameters(PXEN_VESA_DEVICE_EXTENSION PublicExt, PWSTR DefaultSetting, 
                                           PVOID Value, ULONG Size);

NTSTATUS  __stdcall XenVesaSetRegistryDeviceResolution(PXEN_VESA_DEVICE_EXTENSION);
void __stdcall XenVesaGetRegistryPath(PXEN_VESA_DEVICE_EXTENSION, PWSTR);

#endif //XEN_VESA_H
