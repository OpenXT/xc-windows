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

/* Internal definitions for the xenvesa-shared.lib */

#ifndef XENVESA_DEFS_H
#define XENVESA_DEFS_H

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
#define VGA_PORT_VBE_POWER     0x3834 /* byte */
#define VGA_PORT_VGA_M3RADDR   0x3836 /* word */
#define VGA_PORT_VGA_M3RSEG    0x3838 /* word */
#define VGA_PORT_VBE_XVTADDR   0x383A /* word */
#define VGA_PORT_VBE_XVTSEG    0x383C /* word */

VOID __stdcall XenVesaVgaCompatibility(VOID);
VOID __stdcall XenVesaInt10SpinLock(VOID);
VOID __stdcall XenVesaInt10SpinUnlock(VOID);

#endif //XENVESA_DEFS_H
