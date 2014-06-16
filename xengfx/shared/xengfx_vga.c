//
// xengfx_vga.c - VGA support routines
//
// Copyright (c) 2010 Citrix, Inc.
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

// TODO:
//  - Remove the current xenvesa VBE patch, create a new one...
//  - Add VGA_PORT_VGA_M3RADDR and VGA_PORT_VGA_M3RSEG to shadow ports.
//  - Call a routine out of vgabios_init_func to setup the M3 block below.
//  - Need to limit available VBE modes that fit in the 4Mb pre-alloced buffer.

// FUTURE:
//  - Create an ACPI device to claim the VBE and Shadow port ranges.
//  - Support DualView in XDDM.
//  - Modify the VBE virtual BIOS to use XGFX.

// VGA port facility and BDA shadow offsets 
#define VGA_PORT_SPIN_LOCK     0x00 // word
#define VGA_PORT_CONTROL_FLAGS 0x02 // word
#define VGA_PORT_RESERVED      0x04 // word
#define VGA_PORT_ALIGN         0x06 // byte
#define VGA_PORT_CURRENT_MODE  0x07 // byte
#define VGA_PORT_NB_COLS       0x08 // word
#define VGA_PORT_PAGE_BYTES    0x0A // word
#define VGA_PORT_CURRENT_START 0x0C // word
#define VGA_PORT_CURSOR_POS    0x0E // 8 word ports - 16 bytes
#define VGA_PORT_CURSOR_TYPE   0x1E // word
#define VGA_PORT_CHAR_HEIGHT   0x20 // word
#define VGA_PORT_CRTC_ADDRESS  0x22 // word
#define VGA_PORT_CURRENT_PAGE  0x24 // byte
#define VGA_PORT_CURRENT_MSR   0x25 // byte
#define VGA_PORT_CURRENT_PAL   0x26 // byte
#define VGA_PORT_NB_ROWS       0x27 // byte
#define VGA_PORT_VIDEO_CTL     0x28 // byte
#define VGA_PORT_SWITCHES      0x29 // byte
#define VGA_PORT_MODESET_CTL   0x2A // byte
#define VGA_PORT_DCC_INDEX     0x2B // byte
#define VGA_PORT_VS_POINTER    0x2C // 2 word ports - 4 bytes
#define VGA_PORT_VBE_FLAG      0x30 // word
#define VGA_PORT_VBE_MODE      0x32 // word
#define VGA_PORT_VBE_POWER     0x34 // byte
#define VGA_PORT_VGA_M3RADDR   0x36 // word
#define VGA_PORT_VGA_M3RSEG    0x38 // word

// VBE port offsets
#define VBE_PORT_INDEX         0x00
#define VBE_PORT_DATA          0x01

#define VBE_DISPI_INDEX_ENABLE 0x4
#define VBE_DISPI_DISABLED     0x00
#define VBE_DISPI_ENABLED      0x01

// VGA legacy IO ports. These are well known ports that are accessed
// directly. Windows automatically reserves them for graphics devices.
#define VGABIOS_ACTL_ADDRESS           0x3c0
#define VGABIOS_ACTL_WRITE_DATA        0x3c0
#define VGABIOS_ACTL_READ_DATA         0x3c1
#define VGABIOS_WRITE_MISC_OUTPUT      0x3c2
#define VGABIOS_SEQU_ADDRESS           0x3c4
#define VGABIOS_SEQU_DATA              0x3c5
#define VGABIOS_PEL_MASK               0x3c6
#define VGABIOS_DAC_WRITE_ADDRESS      0x3c8
#define VGABIOS_DAC_DATA               0x3c9
#define VGABIOS_READ_MISC_OUTPUT       0x3cc
#define VGABIOS_GRDC_ADDRESS           0x3ce
#define VGABIOS_GRDC_DATA              0x3cf
#define VGABIOS_PORT_CRTC_ADDRESS      0x3d4
#define VGABIOS_PORT_CRTC_DATA         0x3d5
#define VGABIOS_PORT_ACTL_RESET        0x3da

// VGA modeset control bits
#define MODESET_CTL_ENABLE_CURSOR_SCALING    0x01
#define MODESET_CTL_ENABLE_GRAYSCALE_SUMMING 0x02
#define MODESET_CTL_DISABLE_PALLETTE_LOADING 0x08

// Color Text Mode 0x03 (4 BBP):
#define VGA_M3_VIDEO_SEGSTART 0xB800
#define VGA_M3_VIDEO_SEGSIZE  0x800
#define VGA_M3_FONT_SEGSTART  0xA000
#define VGA_M3_PELMASK        0xFF
#define VGA_M3_VPARAMS_INDEX  0x18
#define VGA_M3_PALETTE_SIZE   0xC0

// XenVesa VGA table to pass information on bits in VGA
// BIOS needed to do a reset.
#pragma pack(push, 1)
typedef struct {
    // Size: 30x64b entries
    USHORT VideoParamTableAddr;
    USHORT VideoParamTableSeg;
    // Size: 194b
    USHORT PaletteAddr;
    USHORT PaletteSeg;
    // Size: one page
    USHORT VgaFont16Addr;
    USHORT VgaFont16Seg;
    // Tag 'M3RTBLE'
    char Tag[8];
} VGA_M3RESET_TABLE, *PVGA_M3RESET_TABLE;
#pragma pack(pop)

#define VGA_M3RESET_TAG "M3RTBLE\0"
static VGA_M3RESET_TABLE g_M3Table = {0};

// VGA Video Parameter Table (default reset values)
#pragma pack(push, 1)
typedef struct {
    BYTE TWidth;
    BYTE THeight;
    BYTE CHeight;
    BYTE SLengthLow;
    BYTE SLengthHigh;
    BYTE SequRegs[4];
    BYTE MiscReg;
    BYTE CrtcRegs[25];
    BYTE ActlRegs[20];
    BYTE GrdcRegs[9];
} VIDEO_PARAM_ENTRY, *PVIDEO_PARAM_ENTRY;
#pragma pack(pop)

// Video Params at 0x18 for Mode 3
static VIDEO_PARAM_ENTRY g_M3VideoParams = {0};

// Palette for Mode 2 DAC
static UCHAR g_DAC2Palette[VGA_M3_PALETTE_SIZE];

// VGA Font for 8 and 16 char height
static UCHAR g_VgaFont16[PAGE_SIZE];

VOID NTAPI XenGfxInt10SpinLock(UCHAR *pShadowPortBase)
{
    USHORT Lock;

    do {
        Lock = READ_PORT_USHORT((USHORT*)(pShadowPortBase + VGA_PORT_SPIN_LOCK));
        if (Lock != 0)
            break;
    } while (TRUE);
}

VOID NTAPI XenGfxInt10SpinUnlock(UCHAR *pShadowPortBase)
{
    WRITE_PORT_USHORT((USHORT*)(pShadowPortBase + VGA_PORT_SPIN_LOCK), 0x0001);
}

static BOOLEAN NTAPI XenGfxPullUpM3RInfo(UCHAR *pShadowPortBase)
{
    ULONG Addr;
    PHYSICAL_ADDRESS PhysAddr = {0};
    UCHAR *pVirtAddr;
    VIDEO_PARAM_ENTRY *pVPTable;

    Addr = (READ_PORT_USHORT((USHORT*)(pShadowPortBase + VGA_PORT_VGA_M3RSEG)) & (0x0000FFFF)) << 4;
    Addr = Addr | (READ_PORT_USHORT((USHORT*)(pShadowPortBase + VGA_PORT_VGA_M3RADDR)) & (0x0000FFFF));
    PhysAddr.LowPart = Addr;
    pVirtAddr = (UCHAR*)MmMapIoSpace(PhysAddr, sizeof(VGA_M3RESET_TABLE), MmNonCached);
    if (pVirtAddr == NULL) {
        TraceError(("Could not MAP in Mode 3 Reset table!\n"));
        return FALSE;
    }
    RtlCopyMemory(&g_M3Table, pVirtAddr, sizeof(VGA_M3RESET_TABLE));
    MmUnmapIoSpace(pVirtAddr, sizeof(VGA_M3RESET_TABLE));

    // Sanity check the tag for the table
    if (RtlCompareMemory(g_M3Table.Tag, VGA_M3RESET_TAG, sizeof(g_M3Table.Tag)) != sizeof(g_M3Table.Tag)) {
        TraceError(("Invalid Mode 3 Reset tag?? Tag value: %.*s\n", sizeof(g_M3Table.Tag) - 1, g_M3Table.Tag));
        return FALSE;
    }

    // Get the Vidoe Params Table and copy the one entry we care about.
    Addr = (g_M3Table.VideoParamTableSeg & (0x0000FFFF)) << 4;
    Addr = Addr | (g_M3Table.VideoParamTableAddr & (0x0000FFFF));
    PhysAddr.LowPart = Addr;
    pVirtAddr = (UCHAR*)MmMapIoSpace(PhysAddr, PAGE_SIZE, MmNonCached);
    if (pVirtAddr == NULL) {
        TraceError(("Could not MAP in VideoParamTable!\n"));
        return FALSE;
    }

    pVPTable = (VIDEO_PARAM_ENTRY*)pVirtAddr + VGA_M3_VPARAMS_INDEX;
    RtlCopyMemory(&g_M3VideoParams, pVPTable, sizeof(VIDEO_PARAM_ENTRY));
    MmUnmapIoSpace(pVirtAddr, PAGE_SIZE);

    // Get the Palette.
    Addr = (g_M3Table.PaletteSeg & (0x0000FFFF)) << 4;
    Addr = Addr | (g_M3Table.PaletteAddr & (0x0000FFFF));
    PhysAddr.LowPart = Addr;
    pVirtAddr = (UCHAR*)MmMapIoSpace(PhysAddr, PAGE_SIZE, MmNonCached);
    if (pVirtAddr == NULL) {
        TraceError(("Could not MAP in Palette!\n"));
        return FALSE;
    }

    RtlCopyMemory(&g_DAC2Palette[0], pVirtAddr, VGA_M3_PALETTE_SIZE);
    MmUnmapIoSpace(pVirtAddr, PAGE_SIZE);

    // Get the Fonts.
    Addr = (g_M3Table.VgaFont16Seg & (0x0000FFFF)) << 4;
    Addr = Addr | (g_M3Table.VgaFont16Addr & (0x0000FFFF));
    PhysAddr.LowPart = Addr;
    pVirtAddr = (UCHAR*)MmMapIoSpace(PhysAddr, PAGE_SIZE, MmNonCached);
    if (pVirtAddr == NULL) {
        TraceError(("Could not MAP in Fonts!\n"));
        return FALSE;
    }

    RtlCopyMemory(&g_VgaFont16[0], pVirtAddr, PAGE_SIZE);
    MmUnmapIoSpace(pVirtAddr, PAGE_SIZE);

    return TRUE;
}

static VOID NTAPI XenGfxLoadFonts(UCHAR *pVirtFontDst, UCHAR *pVirtFontSrc)
{
    UCHAR MiscGR;
    ULONG i;

    // Map plane 2 for write access - the font area in text mode is the
    // beginning of plane 2.
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_ADDRESS, 0x00);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_DATA, 0x01);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_ADDRESS, 0x02);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_DATA, 0x04); // enable writes to plane 2
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_ADDRESS, 0x04);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_DATA, 0x07);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_ADDRESS, 0x00);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_DATA, 0x03);

    // Set the vidoe memory write mode to 0 for 
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_ADDRESS, 0x04);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_DATA, 0x02);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_ADDRESS, 0x05);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_DATA, 0x00); // write mode 0, read mode 0
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_ADDRESS, 0x06);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_DATA, 0x04); // memory map select A0000h-AFFFFh (64K region) 

    // Load the fonts into plane 2
    for (i = 0; i < PAGE_SIZE/0x10; i++) {
        RtlCopyMemory((pVirtFontDst + (i*32)), (pVirtFontSrc + (i*16)), 16);
    }

    // Re-enable writing to planes 0 and 1.
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_ADDRESS, 0x00);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_DATA, 0x01);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_ADDRESS, 0x02);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_DATA, 0x03); // enable writes to planes 0 and 1
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_ADDRESS, 0x04);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_DATA, 0x03);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_ADDRESS, 0x00);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_DATA, 0x03);

    // Reset read/write modes. Not sure about the reading of the misc register
    // value Input/Output Address Select and using it for writing the Memory Map Select.
    MiscGR = (g_M3VideoParams.MiscReg & 0x01);
    MiscGR <<= 2;
    MiscGR |= 0x0A;
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_ADDRESS, 0x06);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_DATA, MiscGR);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_ADDRESS, 0x04);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_DATA, 0x00);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_ADDRESS, 0x05);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_DATA, 0x10);    
}

BOOLEAN NTAPI XenGfxVgaResetMode3(UCHAR *pShadowPortBase, UCHAR *pVbePortBase)
{
    USHORT i, SLength;
    UCHAR Value;
    PHYSICAL_ADDRESS PhysAddr = {0};
    UCHAR *pVirtAddrVideo, *pVirtAddrFonts;
    UCHAR *pPtr;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    // First, load the reset values block that the VGA BIOS setup
    // for XenVesa use. Don't need the lock to load the folloing 
    // static ro data.
    if ((g_M3Table.VideoParamTableAddr == 0)&&(g_M3Table.PaletteAddr == 0)) {
        if (!XenGfxPullUpM3RInfo(pShadowPortBase)) {
            // Errors traced in call
            return FALSE;
        }
    }

    // Have to map the video memory frame buffer for text mode 3.
    PhysAddr.LowPart = (VGA_M3_VIDEO_SEGSTART & (0x0000FFFF)) << 4; // offset addr is 0
    pVirtAddrVideo = (UCHAR*)MmMapIoSpace(PhysAddr, VGA_M3_VIDEO_SEGSIZE, MmNonCached);
    if (pVirtAddrVideo == NULL) {
        TraceError(("Could not MAP in Mode 3 vidoe buffer start address!\n"));
        return FALSE;
    }

    // Have to map the video memory start segment to load fonts (about 2 pages)
    PhysAddr.LowPart = 0x0000A000 << 4; // offset addr is 0
    pVirtAddrFonts = (UCHAR*)MmMapIoSpace(PhysAddr, 2*PAGE_SIZE, MmNonCached);
    if (pVirtAddrFonts == NULL) {
        MmUnmapIoSpace(pVirtAddrVideo, 0x800);
        TraceError(("Could not MAP in Mode 3 vidoe memory start address for font loading!\n"));
        return FALSE;
    }    
    
    // Need to lock here - this is going to change the mode and the state of the
    // emulated video card.
    XenGfxInt10SpinLock(pShadowPortBase);

    // Disable VESA modes - going to VGA mode 3
    WRITE_PORT_USHORT((USHORT*)(pVbePortBase + VBE_PORT_INDEX), VBE_DISPI_INDEX_ENABLE);
    WRITE_PORT_USHORT((USHORT*)(pVbePortBase + VBE_PORT_DATA), VBE_DISPI_DISABLED);

    // NOTE assuming AH=12 BL=31 AL=0 (disable palette loading off) -> mode control 0x08 not set (palette loading enabled).
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PEL_MASK, VGA_M3_PELMASK);
    // Index of the first DAC entry == 0
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_DAC_WRITE_ADDRESS, 0);
    // Load the palette into the DAC - the 4bpp colors are mixed throughout
    // NOTE: could configure DAC to pass through just 4b colors (setting ACLT 10h bit 7)
    for (i = 0; i < 64; i++) {
        WRITE_PORT_UCHAR((UCHAR*)VGABIOS_DAC_DATA, g_DAC2Palette[(i*3) + 0]);
        WRITE_PORT_UCHAR((UCHAR*)VGABIOS_DAC_DATA, g_DAC2Palette[(i*3) + 1]);
        WRITE_PORT_UCHAR((UCHAR*)VGABIOS_DAC_DATA, g_DAC2Palette[(i*3) + 2]);
    }
    // Set the rest to 0
    for (i = 64; i < 256; i++) {
        WRITE_PORT_UCHAR((UCHAR*)VGABIOS_DAC_DATA, 0);
        WRITE_PORT_UCHAR((UCHAR*)VGABIOS_DAC_DATA, 0);
        WRITE_PORT_UCHAR((UCHAR*)VGABIOS_DAC_DATA, 0);
    }

    // CRTC
    // Disable write protection for CRTC (Address=0x11, Data=0x00)
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_ADDRESS, 0x11);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA, 0x00);

    // Load default ACTL values
    for (i = 0; i < 25; i++) {
        WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_ADDRESS, (UCHAR)i);
        WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA, g_M3VideoParams.CrtcRegs[i]);
    }

    // ACTL
    // Reset Attribute Control Flip-Flop
    (VOID)READ_PORT_UCHAR((UCHAR*)VGABIOS_PORT_ACTL_RESET);

    // Load default ACTL values
    for (i = 0; i < 20; i++) {
        WRITE_PORT_UCHAR((UCHAR*)VGABIOS_ACTL_ADDRESS, (UCHAR)i);
        WRITE_PORT_UCHAR((UCHAR*)VGABIOS_ACTL_ADDRESS, g_M3VideoParams.ActlRegs[i]);
    }
    // P54S not set in Attribute Mode Control Register, clear Color Select Register
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_ACTL_ADDRESS, 0x14);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_ACTL_ADDRESS, 0x00);

    // GRDC 
    // Load default GRDC values
    for (i = 0; i < 9; i++) {
        WRITE_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_ADDRESS, (UCHAR)i);
        WRITE_PORT_UCHAR((UCHAR*)VGABIOS_GRDC_DATA, g_M3VideoParams.GrdcRegs[i]);
    }

    // SEQU
    // Set reset bits to allow sequencer to operate
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_ADDRESS, 0x00);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_DATA, 0x03);

    // Load default SEQU values. Note that Character Map Select Register is
    // already 0x000 select font residing at 0x0000 that are loaded below.
    for (i = 0; i < 4; i++) {
        WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_ADDRESS, (UCHAR)(i + 1));
        WRITE_PORT_UCHAR((UCHAR*)VGABIOS_SEQU_DATA, g_M3VideoParams.SequRegs[i]);
    }

    // Misc default
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_WRITE_MISC_OUTPUT, g_M3VideoParams.MiscReg);

    // Reset Attribute Control Flip-Flop
    (VOID)READ_PORT_UCHAR((UCHAR*)VGABIOS_PORT_ACTL_RESET);
    // Palette Address Source set for normal operation
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_ACTL_ADDRESS, 0x20);
    
    // Clear alphanumeric framebuffer by setting space characters and
    // forground color attributes on planes 0 and 1 (Map Mask Register
    // SEQU register set above).
    pPtr = pVirtAddrVideo;
    for (i = 0; i < VGA_M3_VIDEO_SEGSIZE; i += 2, pPtr += 2) {
        *pPtr = 0x20;
        *(pPtr + 1) = 0x07;
    }

    // PAGE
    // Set the active page and the start address to 0
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_ADDRESS, 0x0C); // Start Address High Register 
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA, 0);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_ADDRESS, 0x0D); // Start Address Low Register 
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA, 0);    

    // CURSOR
    // Adjust the cursor shape - make a two scan line cursor at the 
    // bottom (where Maximum Scan Line == CHeight - 1).
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_ADDRESS, 0x0A); // Cursor Start Register 
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA, 14);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_ADDRESS, 0x0B); // Cursor End Register 
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA, 15);

    // Set the cursor position to the beginning of page 0
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_ADDRESS, 0x0E); // Cursor Location High
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA, 0);
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_ADDRESS, 0x0F); // Cursor Location Low
    WRITE_PORT_UCHAR((UCHAR*)VGABIOS_PORT_CRTC_DATA, 0);

    // FONTS
    XenGfxLoadFonts(pVirtAddrFonts, &g_VgaFont16[0]);

    // VGA SHADOW
    SLength = g_M3VideoParams.SLengthHigh & (0x00FF);
    SLength = SLength << 8;
    SLength = SLength | (g_M3VideoParams.SLengthLow & (0x00FF));

    // Store VGA values in our shadow ports. Going to VGA mode 3.
    WRITE_PORT_UCHAR((UCHAR*)(pShadowPortBase + VGA_PORT_CURRENT_MODE), 0x03);

    // Defaults    
    WRITE_PORT_UCHAR((UCHAR*)(pShadowPortBase + VGA_PORT_VIDEO_CTL), 0x60);
    WRITE_PORT_UCHAR((UCHAR*)(pShadowPortBase + VGA_PORT_SWITCHES), 0xF9);
    WRITE_PORT_UCHAR((UCHAR*)(pShadowPortBase + VGA_PORT_DCC_INDEX), 0x08); // combination code VGA emulation level and analog color monitor
    WRITE_PORT_USHORT((USHORT*)(pShadowPortBase + VGA_PORT_CRTC_ADDRESS), VGABIOS_PORT_CRTC_ADDRESS);

    // Values from the video params table.
    WRITE_PORT_USHORT((USHORT*)(pShadowPortBase + VGA_PORT_NB_COLS), g_M3VideoParams.TWidth); // 80
    WRITE_PORT_UCHAR((UCHAR*)(pShadowPortBase + VGA_PORT_NB_ROWS), g_M3VideoParams.THeight); // 24
    WRITE_PORT_USHORT((USHORT*)(pShadowPortBase + VGA_PORT_CHAR_HEIGHT), g_M3VideoParams.CHeight); // 16
    WRITE_PORT_USHORT((USHORT*)(pShadowPortBase + VGA_PORT_PAGE_BYTES), SLength);

    // Set page, address and cursor positions to zero
    WRITE_PORT_USHORT((USHORT*)(pShadowPortBase + VGA_PORT_CURRENT_START), 0);
    WRITE_PORT_USHORT((USHORT*)(pShadowPortBase + VGA_PORT_CURRENT_PAGE), 0);
    for (i = 0; i < 8; i++) {
        WRITE_PORT_USHORT((USHORT*)(pShadowPortBase + VGA_PORT_CURSOR_POS + (2*i)), 0);
    }

    // Save a cursor type that is a 2 line cursor at the bottom of the cell.
    WRITE_PORT_USHORT((USHORT*)(pShadowPortBase + VGA_PORT_CURSOR_TYPE), 0x0607);

    // Ensure the modeset control value is consistent with our usage.
    Value = READ_PORT_UCHAR((UCHAR*)(pShadowPortBase + VGA_PORT_MODESET_CTL));
    Value &= ~(MODESET_CTL_ENABLE_GRAYSCALE_SUMMING|MODESET_CTL_DISABLE_PALLETTE_LOADING);
    Value |= MODESET_CTL_ENABLE_CURSOR_SCALING;
    WRITE_PORT_UCHAR((UCHAR*)(pShadowPortBase + VGA_PORT_MODESET_CTL), Value);

    XenGfxInt10SpinUnlock(pShadowPortBase);

    MmUnmapIoSpace(pVirtAddrFonts, 2*PAGE_SIZE);
    MmUnmapIoSpace(pVirtAddrVideo, VGA_M3_VIDEO_SEGSIZE);

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return TRUE;
}

typedef struct {
    ULONG Eax;
    ULONG Ecx;
    ULONG Edx;
    ULONG Ebx;
    ULONG Ebp;
    ULONG Esi;
    ULONG Edi;
    USHORT SegDs;
    USHORT SegEs;
} X86BIOS_CALL_REGISTERS;

typedef NTKERNELAPI BOOLEAN (NTAPI *x86BiosCall_t)(ULONG InterruptNumber, X86BIOS_CALL_REGISTERS *Registers);

static x86BiosCall_t g_x86BiosCallFn = NULL;

BOOLEAN NTAPI XenGfxVgaInitBiosCalls(VOID)
{
    UNICODE_STRING BiosCallName;

    RtlInitUnicodeString(&BiosCallName, L"x86BiosCall");

    // Locate the x86BiosCall x86 emulator function exported from the HAL
    g_x86BiosCallFn = MmGetSystemRoutineAddress(&BiosCallName);
    if (g_x86BiosCallFn == NULL) {
        TraceError(("Could not initialize x86 function!\n"));
        return FALSE;
    }

    return TRUE;
}

BOOLEAN NTAPI XenGfxVgaSetMode(USHORT ModeNumber)
{
    X86BIOS_CALL_REGISTERS Regs = {0};

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    if (g_x86BiosCallFn == NULL) {
        TraceError(("VGA set mode failed - no x86 function!\n"));
        return FALSE;
    }

    // VGA set mode int10: ah=00 al=mode (bit 7 for clear)
    Regs.Eax = (ModeNumber & 0x00FF);
    if (!g_x86BiosCallFn(0x10, &Regs)) {
        TraceError(("VGA set mode failed - x86 function call failed.\n"));
        return FALSE;
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return TRUE;
}
