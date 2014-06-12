//
// xengfx_vbe.c - VBE support routines
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


#include <ntddk.h>
#include "xengfx_shared.h"
#include "xengfx_regs.h"

// N. B. This is the working code for using VBE directly from Windows bypassing
// int10 BIOS calls. It is not currently used in XenGfx. Note the shadow ports
// for the EDID and Modes table have to be setup in qemu for this to work.

#define VBE_PORT_INDEX                   0x01CE
#define VBE_PORT_DATA                    0x01CF

#define VBE_DISPI_DISABLED               0x00
#define VBE_DISPI_ENABLED                0x01
#define VBE_DISPI_ENABLED                0x01
#define VBE_DISPI_GETCAPS                0x02
#define VBE_DISPI_8BIT_DAC               0x20
#define VBE_DISPI_LFB_ENABLED            0x40
#define VBE_DISPI_NOCLEARMEM             0x80

#define VBE_DISPI_INDEX_ID               0x0
#define VBE_DISPI_INDEX_XRES             0x1
#define VBE_DISPI_INDEX_YRES             0x2
#define VBE_DISPI_INDEX_BPP              0x3
#define VBE_DISPI_INDEX_ENABLE           0x4
#define VBE_DISPI_INDEX_BANK             0x5
#define VBE_DISPI_INDEX_VIRT_WIDTH       0x6
#define VBE_DISPI_INDEX_VIRT_HEIGHT      0x7
#define VBE_DISPI_INDEX_X_OFFSET         0x8
#define VBE_DISPI_INDEX_Y_OFFSET         0x9
#define VBE_DISPI_INDEX_VIDEO_MEMORY_64K 0xa
#define VBE_DISPI_INDEX_LFB_ADDRESS_H    0xb
#define VBE_DISPI_INDEX_LFB_ADDRESS_L    0xc
#define VBE_DISPI_INDEX_STRIDE           0xd
#define VBE_DISPI_INDEX_EDID_XRES        0xe
#define VBE_DISPI_INDEX_EDID_YRES        0xf
#define VBE_DISPI_INDEX_STRIDE_ALIGN     0x10

#define VBE_EDID_SIZE                    0x80

// VGA port facility and BDA shadow
#define VGA_PORT_RANGE_BASE    0x3800
#define VGA_PORT_RANGE_SIZE    0x40

#define VGA_PORT_SPIN_LOCK     0x3800 /* word */
#define VGA_PORT_CONTROL_FLAGS 0x3802 /* word */
#define VGA_PORT_RESERVED      0x3804 /* word */
#define VGA_PORT_ALIGN         0x3806 /* byte */
#define VGA_PORT_CURRENT_MODE  0x3807 /* byte */
#define VGA_PORT_NB_COLS       0x3808 /* word */
#define VGA_PORT_PAGE_BYTES    0x380A /* word */
#define VGA_PORT_CURRENT_START 0x380C /* word */
#define VGA_PORT_CURSOR_POS    0x380E /* 8 word ports - 16 bytes */
#define VGA_PORT_CURSOR_TYPE   0x381E /* word */
#define VGA_PORT_CHAR_HEIGHT   0x3820 /* word */
#define VGA_PORT_CRTC_ADDRESS  0x3822 /* word */
#define VGA_PORT_CURRENT_PAGE  0x3824 /* byte */
#define VGA_PORT_CURRENT_MSR   0x3825 /* byte */
#define VGA_PORT_CURRENT_PAL   0x3826 /* byte */
#define VGA_PORT_NB_ROWS       0x3827 /* byte */
#define VGA_PORT_VIDEO_CTL     0x3828 /* byte */
#define VGA_PORT_SWITCHES      0x3829 /* byte */
#define VGA_PORT_MODESET_CTL   0x382A /* byte */
#define VGA_PORT_DCC_INDEX     0x382B /* byte */
#define VGA_PORT_VS_POINTER    0x382C /* 2 word ports - 4 bytes */
#define VGA_PORT_VBE_FLAG      0x3830 /* word */
#define VGA_PORT_VBE_MODE      0x3832 /* word */
#define VGA_PORT_VBE_POWER     0x3834 /* word */
#define VGA_PORT_VGA_M3RADDR   0x3836 /* word */
#define VGA_PORT_VGA_M3RSEG    0x3838 /* word */
#define VGA_PORT_VBE_XVTADDR   0x383A /* word */
#define VGA_PORT_VBE_XVTSEG    0x383C /* word */


#define VGABIOS_ACTL_ADDRESS           0x3c0
#define VGABIOS_ACTL_READ_DATA         0x3c1
#define VGABIOS_SEQU_ADDRESS           0x3c4
#define VGABIOS_SEQU_DATA              0x3c5
#define VGABIOS_GRDC_ADDRESS           0x3ce
#define VGABIOS_GRDC_DATA              0x3cf
#define VGABIOS_PORT_CRTC_ADDRESS      0x3d4
#define VGABIOS_PORT_CRTC_DATA         0x3d5
#define VGABIOS_PORT_ACTL_RESET        0x3da

// VBE Capabilities
#define VBE_CAPABILITY_8BIT_DAC                          0x0001
#define VBE_CAPABILITY_NOT_VGA_COMPATIBLE                0x0002
#define VBE_CAPABILITY_RAMDAC_USE_BLANK_BIT              0x0004
#define VBE_CAPABILITY_STEREOSCOPIC_SUPPORT              0x0008
#define VBE_CAPABILITY_STEREO_VIA_VESA_EVC               0x0010

// Mode Attributes
#define VBE_MODE_ATTRIBUTE_SUPPORTED                     0x0001
#define VBE_MODE_ATTRIBUTE_EXT_INFORMATION_AVAILABLE     0x0002
#define VBE_MODE_ATTRIBUTE_TTY_BIOS_SUPPORT              0x0004
#define VBE_MODE_ATTRIBUTE_COLOR_MODE                    0x0008
#define VBE_MODE_ATTRIBUTE_GRAPHICS_MODE                 0x0010
#define VBE_MODE_ATTRIBUTE_NOT_VGA_COMPATIBLE            0x0020
#define VBE_MODE_ATTRIBUTE_NO_VGA_COMPATIBLE_WINDOW      0x0040
#define VBE_MODE_ATTRIBUTE_LINEAR_FRAME_BUFFER_MODE      0x0080
#define VBE_MODE_ATTRIBUTE_DOUBLE_SCAN_MODE              0x0100
#define VBE_MODE_ATTRIBUTE_INTERLACE_MODE                0x0200
#define VBE_MODE_ATTRIBUTE_HARDWARE_TRIPLE_BUFFER        0x0400
#define VBE_MODE_ATTRIBUTE_HARDWARE_STEREOSCOPIC_DISPLAY 0x0800
#define VBE_MODE_ATTRIBUTE_DUAL_DISPLAY_START_ADDRESS    0x1000

// VBE Mode Numbers
#define VBE_MODE_VESA_DEFINED                            0x0100
#define VBE_MODE_REFRESH_RATE_USE_CRTC                   0x0800
#define VBE_MODE_LINEAR_FRAME_BUFFER                     0x4000
#define VBE_MODE_PRESERVE_DISPLAY_MEMORY                 0x8000

// VBE modes list offset into VBE_EXT_INFO
#define VBE_VESA_MODE_POINTER_OFFSET                     34

#define VBE_MEMORYMODEL_PACKEDPIXEL                      0x04
#define VBE_MEMORYMODEL_DIRECTCOLOR                      0x06

// VBE structures
// XenVesa VBE table to pass information on bits in Vesa
// BIOS needed to operate.
#pragma pack(push, 1)
typedef struct {
    // Standard 256b EDID for the preferred mode info
    USHORT EdidAddr;
    USHORT EdidSeg;
    // Vesa modes table.
    USHORT ModesAddr;
    USHORT ModesSeg;       
    // Tag 'XENVTBL'
    char Tag[8];
} VBE_XENVESA_TABLE, *PVBE_XENVESA_TABLE;
#pragma pack(pop)

#define VBE_XENVESA_TAG "XENVTBL\0"
static VBE_XENVESA_TABLE g_VbeTable = {0};

#pragma pack(push, 1)
typedef struct
{
    USHORT        ModeNumber;
    VBE_MODE_INFO ModeInfo;
} MODE_INFO_ITEM, *PMODE_INFO_ITEM;
#pragma pack(pop)

#define XENVBE_MODE_END_OF_LIST                         0xFFFF
#define XENVBE_BITS_PER_PIXEL                           32
#define XENVBE_FRAME_BUFFER                             0xA0000
#define XENVBE_FRAME_BUFFER_LENGTH                      0x20000
#define XENVBE_TAG                                      'XVBE'

// The mode info table in our vVBE BIOS is static and around
// half a page big so this should be plenty of room to pull it up.
#define NUM_MODE_PAGES  2
#define MODE_SIZE (NUM_MODE_PAGES * PAGE_SIZE)
static UCHAR g_ModeInfoList[MODE_SIZE];
static BOOLEAN g_VbeInfoInitialized = FALSE;

static VOID NTAPI XenGfxVbeVgaCompatibility(VOID)
{
    USHORT XRes, YRes, Bpp;
    UCHAR Value;

    // Get VBE values
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_XRES);
    XRes = READ_PORT_USHORT((USHORT*)VBE_PORT_DATA);
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_YRES);
    YRes = READ_PORT_USHORT((USHORT*)VBE_PORT_DATA) - 1;
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_BPP);
    Bpp = READ_PORT_USHORT((USHORT*)VBE_PORT_DATA);

    // -- CRTC --

    // Disable write protection for CRTC (Address=0x11, Data=0x00)
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_ADDRESS, 0x11);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA, 0x00);

    // Set End Horizontal Display (Address=0x01, Data=<character clocks - 1>)    
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_ADDRESS, 0x01);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA, (UCHAR)((XRes >> 3) - 1));

    // Set Offset Register (Address=0x13, Data=<vertical width for BPP > 4>)
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_ADDRESS, 0x13);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA, (UCHAR)(XRes >> 3));

    // Set Vertical Display End Register (Address=0x12, Data=<end scanline counter bits 0-7>)    
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_ADDRESS, 0x12);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA, (UCHAR)(YRes & 0x00FF));

    // Set Overflow (Address=0x07, Data=<end scanline counter bits 8-9>)    
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_ADDRESS, 0x07);
    Value = READ_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA);
    // Clear VDE8 VDE9 and set if present in YRes
    Value &= 0xBD; // 10111101 mask off VDE bits
    Value |= (YRes & 0x100) ? 0x02 : 0x00;
    Value |= (YRes & 0x200) ? 0x40 : 0x00;
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA, Value);

    // Clear Maximum Scan Line Register (Address=0x09, Data=0x00)
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_ADDRESS, 0x09);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA, 0x00);

    // Get CRTC Mode Control Register (Address=0x17, Data=<mode control bits>)    
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_ADDRESS, 0x17);
    Value = READ_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA, (Value | 0x03)); // + MAP14|MAP13

    // Bpp >= 8...
    // Get Underline Location Register (Address=0x14, Data=<underline loc and ctrl>)    
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_ADDRESS, 0x14);
    Value = READ_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA, (Value | 0x40)); // + DW

    // -- ACTL --

    // Reset Attribute Control Flip-Flop rubbish
    (VOID)READ_PORT_UCHAR((UCHAR*)VGABIOS_PORT_ACTL_RESET);
    // N.B. normally a READ_PORT_UCHAR((UCHAR*)VGABIOS_ACTL_ADDRESS) would be saved to restore
    // at the end of reading/writing but our virtual BIOS does not need this.

    // Get Attribute Mode Control Register 
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_ACTL_ADDRESS, 0x10);
    Value = READ_PORT_UCHAR((UCHAR*)VGABIOS_ACTL_READ_DATA);
    // In write mode
    Value |= 0x01|0x40; // + ATGE | + 8BIT
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_ACTL_ADDRESS, Value);

    // -- GRDC --

    // Set Miscellaneous Graphics Register
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_ADDRESS, 0x06);
    Value = 0x05; // <A0000h-AFFFFh (64K region) and Alpha Dis.>
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_DATA, Value);
    // Bpp >= 8...
    // Set Graphics Mode Register 
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_ADDRESS, 0x05);
    Value = READ_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_DATA);
    Value &= 0x9f; // Clear Shift256 and Shift Reg.
    Value |= 0x40; // + Shift256
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_DATA, Value);

    // -- SEQU --

    // Set Map Mask Register
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_ADDRESS, 0x02);
    Value = 0x0F; // <Write VGA display planes 3-0>
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_DATA, Value);
    // Bpp >= 8...
    // Set Sequencer Memory Mode 
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_ADDRESS, 0x04);
    Value = READ_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_DATA);
    Value |= 0x08; // + Chain 4
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_DATA, Value);
}

static BOOLEAN NTAPI XenGfxPullUpModeInfo(VOID)
{
    ULONG Addr;
    PHYSICAL_ADDRESS PhysAddr = {0};
    UCHAR *pVirtAddr;
    ULONG Size = 0;
    MODE_INFO_ITEM *pCurrentMode;

    // Map the table and copy it up (plus any extra junk). The spinlock is not
    // needed since the mode table is a static/ro chunk.
    Addr = ((ULONG)g_VbeTable.ModesSeg & (0x0000FFFF));
    Addr = Addr << 4;
    Addr = Addr | ((ULONG)g_VbeTable.ModesAddr & (0x0000FFFF));
    PhysAddr.LowPart = Addr;
    pVirtAddr = (UCHAR*)MmMapIoSpace(PhysAddr, MODE_SIZE, MmNonCached);
    if (pVirtAddr == NULL) {
        TraceError(("Could not MAP in Mode Info List virtual address!\n"));
        return FALSE;
    }

    RtlCopyMemory(g_ModeInfoList, pVirtAddr, MODE_SIZE);
    MmUnmapIoSpace(pVirtAddr, MODE_SIZE);

    // Check and cleanup the table
    pCurrentMode = (MODE_INFO_ITEM*)g_ModeInfoList;
    while (pCurrentMode->ModeNumber != XENVBE_MODE_END_OF_LIST) {        
        if (Size + 2 >= MODE_SIZE) {
            // This should never happen. The table is static but if it did ever happens,
            // this routine could be changed to use dynamic allocation (note this would
            // leak though since there is not unload call to use in video drivers).
            TraceError(("Unexpected Mode Info List overflow! Incorrect size: %d\n", Size));
            return FALSE;
        }

        Size += sizeof(MODE_INFO_ITEM);
        pCurrentMode++;
    }

    // Clear out the tail end so it is easy to see where the end of the table is
    // for debugging purposes. Skip the terminator.
    Size += 2;
    RtlZeroMemory(g_ModeInfoList + Size, MODE_SIZE - Size);

    return TRUE;
}

static const MODE_INFO_ITEM* NTAPI XenGfxFindMode(USHORT ModeNumber, BOOLEAN UsingLFB)
{
    MODE_INFO_ITEM *pCurrentMode = (MODE_INFO_ITEM*)g_ModeInfoList;

    while (pCurrentMode->ModeNumber != XENVBE_MODE_END_OF_LIST) {
        if (pCurrentMode->ModeNumber == ModeNumber) {
            if (!UsingLFB) {
                return pCurrentMode;
            }
            if (pCurrentMode->ModeInfo.ModeAttributes & VBE_MODE_ATTRIBUTE_LINEAR_FRAME_BUFFER_MODE) {
                return pCurrentMode;
            }
        }
        pCurrentMode++;
    }
    
    return NULL;
}

BOOLEAN NTAPI XenGfxVbeInitialize(UCHAR *pShadowPortBase)
{
    ULONG Addr;
    PHYSICAL_ADDRESS PhysAddr = {0};
    UCHAR *pVirtAddr;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (g_VbeInfoInitialized) {
        TraceVerbose(("VBE support already initialized?\n"));
        return FALSE;
    }

    // Pull up the VBE table information from the VBE BIOS area.
    Addr = (READ_PORT_USHORT((USHORT*)(pShadowPortBase + VGA_PORT_VBE_XVTSEG)) & (0x0000FFFF)) << 4;
    Addr = Addr | (READ_PORT_USHORT((USHORT*)(pShadowPortBase + VGA_PORT_VBE_XVTADDR)) & (0x0000FFFF));
    PhysAddr.LowPart = Addr;
    pVirtAddr = (UCHAR*)MmMapIoSpace(PhysAddr, sizeof(VBE_XENVESA_TABLE), MmNonCached);
    if (pVirtAddr == NULL) {
        TraceError(("Could not MAP in VBE info table!\n"));
        return FALSE;
    }
    RtlCopyMemory(&g_VbeTable, pVirtAddr, sizeof(VBE_XENVESA_TABLE));
    MmUnmapIoSpace(pVirtAddr, sizeof(VBE_XENVESA_TABLE));

    // Sanity check the tag for the table
    if (RtlCompareMemory(g_VbeTable.Tag, VBE_XENVESA_TAG, sizeof(g_VbeTable.Tag)) != sizeof(g_VbeTable.Tag)) {
        TraceError(("Invalid VBE info tag?? Tag value: %.*s\n", sizeof(g_VbeTable.Tag) - 1, g_VbeTable.Tag));
        return FALSE;
    }

    // Pull up the Vesa mode information once up front.
    if (!XenGfxPullUpModeInfo()) {
        // Errors traced in call
        return FALSE;
    }

    g_VbeInfoInitialized = TRUE;

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return TRUE;
}

BOOLEAN NTAPI XenGfxVbeGetExtInfo(VBE_EXT_INFO *pVbeExtInfo, ULONG *pModeCount)
{
    USHORT XRes, YRes;
    ULONG Count = 0;
    USHORT *pModeNumbers;
    MODE_INFO_ITEM *pCurrentMode;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (!g_VbeInfoInitialized) {
        return FALSE;
    }

    if ((pVbeExtInfo == NULL)||(pModeCount == NULL)) {
        return FALSE;
    }

    RtlZeroMemory(pVbeExtInfo, sizeof(VBE_EXT_INFO));
    *pModeCount = 0;    

    // The spinlock is not needed since this routine just reads values from the
    // local mode table or from vbe ports.

    // VBE Signature
    pVbeExtInfo->Signature[0] = 'V';
    pVbeExtInfo->Signature[1] = 'E';
    pVbeExtInfo->Signature[2] = 'S';
    pVbeExtInfo->Signature[3] = 'A';

    // VBE Version supported
    pVbeExtInfo->Version = 0x0200;

    // Capabilities (only 1)
    pVbeExtInfo->Capabilities[0] = VBE_CAPABILITY_8BIT_DAC;

    // VBE Video Mode Pointer - this isn't really used since we are not making
    // int10 calls but for convenience, stick the offset in there. At this offset
    // each of the mode numbers from the table will be stored.
    pVbeExtInfo->VideoModeSeg = g_VbeTable.ModesSeg;
    pVbeExtInfo->VideoModeOffset = VBE_VESA_MODE_POINTER_OFFSET;

    // VBE Total Memory (in 64b blocks)
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_VIDEO_MEMORY_64K);
    pVbeExtInfo->TotalMemory = READ_PORT_USHORT((USHORT*)VBE_PORT_DATA);

    // Setup to load mode values
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_EDID_XRES);
    XRes = READ_PORT_USHORT((USHORT*)VBE_PORT_DATA);

    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_EDID_YRES);
    YRes = READ_PORT_USHORT((USHORT*)VBE_PORT_DATA);

    pModeNumbers = (USHORT*)(((UCHAR*)pVbeExtInfo) + VBE_VESA_MODE_POINTER_OFFSET);
    pCurrentMode = (MODE_INFO_ITEM*)g_ModeInfoList;

    // Now load the mode numbers
    while (pCurrentMode->ModeNumber != XENVBE_MODE_END_OF_LIST)
    {
        if ((pCurrentMode->ModeInfo.XResolution <= XRes)&&
            (pCurrentMode->ModeInfo.YResolution <= YRes)&&
            (pCurrentMode->ModeInfo.BitsPerPixel == XENVBE_BITS_PER_PIXEL)) {
            *pModeNumbers = pCurrentMode->ModeNumber;
            TraceVerbose(("VBE mode 0x%04x (xres=0x%04x / yres=0x%04x / bpp=0x%02x) stored @index=%d\n",
                         pCurrentMode->ModeNumber, pCurrentMode->ModeInfo.XResolution,
                         pCurrentMode->ModeInfo.YResolution, pCurrentMode->ModeInfo.BitsPerPixel, Count));
            pModeNumbers++;
            Count++;
        }
        else {
            TraceVerbose(("VBE mode 0x%04x (xres=0x%04x / yres=0x%04x / bpp=0x%02x) not supported.\n",
                         pCurrentMode->ModeNumber, pCurrentMode->ModeInfo.XResolution,
                         pCurrentMode->ModeInfo.YResolution, pCurrentMode->ModeInfo.BitsPerPixel));
        }
        
        pCurrentMode++;
    }
    
    // Terminate the mode number list
    *(pModeNumbers + 1) = XENVBE_MODE_END_OF_LIST;
    *pModeCount = Count;

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return TRUE;
}

BOOLEAN NTAPI XenGfxVbeGetModeInfo(USHORT ModeNumber, VBE_MODE_INFO* pVbeModeInfo)
{
    const MODE_INFO_ITEM *pCurrentMode;
    BOOLEAN UsingLFB;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (!g_VbeInfoInitialized) {
        return FALSE;
    }

    if (pVbeModeInfo == NULL) {
        return FALSE;
    }

    RtlZeroMemory(pVbeModeInfo, sizeof(VBE_MODE_INFO));

    UsingLFB = ((ModeNumber & VBE_MODE_LINEAR_FRAME_BUFFER) == VBE_MODE_LINEAR_FRAME_BUFFER) ? TRUE : FALSE;
    ModeNumber &= 0x1ff;

    // The spinlock is not needed since this routine just reads values from the
    // local mode table or from vbe ports.

    pCurrentMode = XenGfxFindMode(ModeNumber, UsingLFB);
    if (pCurrentMode == NULL) {
        TraceWarning(("VBE mode %04x NOT FOUND??\n", ModeNumber));
        return FALSE;
    }

    TraceVerbose(("Found VBE mode 0x%04x\n", ModeNumber));
    RtlCopyMemory(pVbeModeInfo, &pCurrentMode->ModeInfo, sizeof(VBE_MODE_INFO));

    // Fix it up a bit. Setting WinFuncPtr for VBE_WINDOW_ATTRIBUTE_RELOCATABLE is probably not so useful...
    if (UsingLFB) {
        pVbeModeInfo->NumberOfBanks = 1;
    }

    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_LFB_ADDRESS_H);
    pVbeModeInfo->PhysBasePtr = READ_PORT_USHORT((USHORT*)VBE_PORT_DATA);
    pVbeModeInfo->PhysBasePtr = pVbeModeInfo->PhysBasePtr << 16;
        
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return TRUE;
}

BOOLEAN NTAPI XenGfxVbeSetMode(USHORT ModeNumber)
{
    const MODE_INFO_ITEM *pCurrentMode;
    BOOLEAN UsingLFB;
    USHORT FlagLFB, FlagNoClear;
    USHORT StrideAlign;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (!g_VbeInfoInitialized) {
        return FALSE;
    }

    ModeNumber &= 0x1FF;

    if (ModeNumber < VBE_MODE_VESA_DEFINED) {
        TraceError(("Could not set non-VBE mode!\n"));
        return FALSE;
    }

    // Get mode attributes
    UsingLFB = ((ModeNumber & VBE_MODE_LINEAR_FRAME_BUFFER) == VBE_MODE_LINEAR_FRAME_BUFFER) ? TRUE : FALSE;
    FlagLFB = (UsingLFB) ? VBE_DISPI_LFB_ENABLED : 0;
    FlagNoClear = ((ModeNumber & VBE_MODE_PRESERVE_DISPLAY_MEMORY) == VBE_MODE_PRESERVE_DISPLAY_MEMORY) ? VBE_DISPI_NOCLEARMEM : 0;

    pCurrentMode = XenGfxFindMode(ModeNumber, UsingLFB);
    if (pCurrentMode == NULL) {
        TraceWarning(("VBE mode %04x NOT FOUND (and not set)??\n", ModeNumber));
        return FALSE;
    }
    
    TraceVerbose(("Set VBE mode 0x%04x (xres=0x%04x / yres=0x%04x / bpp=0x%02x) found.\n",
                 pCurrentMode->ModeNumber, pCurrentMode->ModeInfo.XResolution,
                 pCurrentMode->ModeInfo.YResolution, pCurrentMode->ModeInfo.BitsPerPixel));

    // Need to lock here - this is going to change the mode and the state of the
    // emulated video card.
    XenGfxInt10SpinLock((UCHAR*)VGA_PORT_RANGE_BASE);

    // Disable while setting VESA modes.
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_ENABLE);
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_DATA, VBE_DISPI_DISABLED);

    // N.B. don't need to worry about setting up 4 BPP modes for XenVesa

    // Set BPP, X and Y res, stride, bank
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_BPP);
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_DATA, pCurrentMode->ModeInfo.BitsPerPixel);
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_XRES);
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_DATA, pCurrentMode->ModeInfo.XResolution);
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_YRES);
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_DATA, pCurrentMode->ModeInfo.YResolution);

    //New feature...
    StrideAlign = XenGfxVbeGetAlignedStride(pCurrentMode->ModeInfo.BytesPerScanLine);
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_STRIDE);
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_DATA, StrideAlign);

    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_BANK);
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_DATA, 0);

    // Store some of the VGA port values as in the vBIOS. Note we only need to write our shadow
    // ports at this point since we switched to exclusive shadow use.
    WRITE_PORT_USHORT((USHORT*)VGA_PORT_VBE_MODE, ModeNumber);
    WRITE_PORT_USHORT((USHORT*)VGA_PORT_VIDEO_CTL, (0x60|FlagNoClear));

    // Enable new VESA mode
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_ENABLE);
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_DATA, VBE_DISPI_ENABLED|FlagLFB|FlagNoClear);

    XenGfxInt10SpinUnlock((UCHAR*)VGA_PORT_RANGE_BASE);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return TRUE;
}

BOOLEAN NTAPI XenGfxVbeGetCurrentMode(USHORT *XRes, USHORT *YRes, USHORT * bpp)
{

	if (!g_VbeInfoInitialized) {
		return FALSE;
	}

	if (XRes == NULL || YRes == NULL || bpp == NULL) {
		return FALSE;
	}
	    // Get VBE values
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_XRES);
    *XRes = READ_PORT_USHORT((USHORT*)VBE_PORT_DATA);
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_YRES);
    *YRes = READ_PORT_USHORT((USHORT*)VBE_PORT_DATA) - 1;
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_BPP);
    *bpp = READ_PORT_USHORT((USHORT*)VBE_PORT_DATA);
	return TRUE;
}
BOOLEAN NTAPI XenGfxVbeGetEdid(UCHAR *pChildDescriptor, ULONG Length)
{
    ULONG Addr;
    PHYSICAL_ADDRESS PhysAddr = {0};
    UCHAR *pVirtAddr;
    USHORT XRes, YRes;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (!g_VbeInfoInitialized) {
        return FALSE;
    }

    if ((pChildDescriptor == NULL)||(Length < VBE_EDID_SIZE)) {
        return FALSE;
    }

    // Find the EDID and map it in. The spinlock is not needed since the 
    // EDID is a static/ro chunk (after initialization).
    Addr = ((ULONG)g_VbeTable.EdidSeg & (0x0000FFFF));
    Addr = Addr << 4;
    Addr = Addr | ((ULONG)g_VbeTable.EdidAddr & (0x0000FFFF));
    PhysAddr.LowPart = Addr;
    pVirtAddr = (UCHAR*)MmMapIoSpace(PhysAddr, VBE_EDID_SIZE, MmNonCached);
    if (pVirtAddr == NULL) {
        TraceError(("Could not MAP in EDID virtual address!\n"));
        return FALSE;
    }

    RtlCopyMemory(pChildDescriptor, pVirtAddr, VBE_EDID_SIZE);
    MmUnmapIoSpace(pVirtAddr, VBE_EDID_SIZE);

    // Fix up EDID with resolution on this system.
    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_EDID_XRES);
    XRes = READ_PORT_USHORT((USHORT*)VBE_PORT_DATA);

    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_EDID_YRES);
    YRes = READ_PORT_USHORT((USHORT*)VBE_PORT_DATA);

    *(pChildDescriptor + 0x38) = (UCHAR)(XRes & 0x00FF);
    *(pChildDescriptor + 0x3A) = (UCHAR)(((XRes >> 8) & 0x000F) << 4);
    *(pChildDescriptor + 0x3B) = (UCHAR)(YRes & 0x00FF);
    *(pChildDescriptor + 0x3D) = (UCHAR)(((YRes >> 8) & 0x000F) << 4);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return TRUE;
}
USHORT XenGfxVbeGetAlignedStride( const WORD CurrentModeStride)
{
    USHORT strideAlign, alignedStride;

    WRITE_PORT_USHORT((USHORT*)VBE_PORT_INDEX, VBE_DISPI_INDEX_STRIDE_ALIGN);
    strideAlign = READ_PORT_USHORT((USHORT*)VBE_PORT_DATA)  -1;
    alignedStride = (CurrentModeStride + (strideAlign)) & ~strideAlign;
    return alignedStride;
}
