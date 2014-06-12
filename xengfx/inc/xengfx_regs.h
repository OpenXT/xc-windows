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

/*
 * XENGFX HW register map and associated values.
 */

#ifndef _XENGFX_REG_H_
#define _XENGFX_REG_H_

#define XGFX_MAGIC_VALUE               0x58464758
#define XGFX_CURRENT_REV               0x1

/* Global Regisers */
#define XGFX_GLOBAL_OFFSET             0x000000

#define XGFX_MAGIC                     0x0000  /* reads 0x58464758 'XGFX' */
#define XGFX_REV                       0x0004  /* currently reads 0x1 */
#define XGFX_CONTROL                   0x0100
#define XGFX_ISR                       0x0104
#define XGFX_GART_SIZE                 0x0200
#define XGFX_INVALIDATE_GART           0x0204
#define XGFX_STOLEN_BASE               0x0208
#define XGFX_STOLEN_SIZE               0x020C
#define XGFX_NVCRTC                    0x0300
#define XGFX_RESET                     0x0400
#define XGFX_MADVISE                   0x1000

/* XGFX_CONTROL bits */
#define XGFX_CONTROL_HIRES_EN          0x00000001
#define XGFX_CONTROL_INT_EN            0x00000002

/* XGFX_ISR bits */
#define XGFX_ISR_INT                   0x00000001

/* VCRTC Register banks */
#define XGFX_VCRTC_OFFSET              0x100000

#define XGFX_VCRTC_STATUS              0x0000
#define XGFX_VCRTC_STATUS_CHANGE       0x0004
#define XGFX_VCRTC_STATUS_INT          0x0008
#define XGFX_VCRTC_SCANLINE            0x000C
#define XGFX_VCRTC_CURSOR_STATUS       0x0010
#define XGFX_VCRTC_CURSOR_CONTROL      0x0014 
#define XGFX_VCRTC_CURSOR_MAXSIZE      0x0018
#define XGFX_VCRTC_CURSOR_SIZE         0x001C
#define XGFX_VCRTC_CURSOR_BASE         0x0020
#define XGFX_VCRTC_CURSOR_POS          0x0024
#define XGFX_VCRTC_EDID_REQUEST        0x1000
#define XGFX_VCRTC_CONTROL             0x2000
#define XGFX_VCRTC_VALID_FORMAT        0x2004
#define XGFX_VCRTC_FORMAT              0x2008
#define XGFX_VCRTC_MAX_HORIZONTAL      0x2010
#define XGFX_VCRTC_HORIZONTAL_ACTIVE   0x2014
#define XGFX_VCRTC_MAX_VERTICAL        0x2018
#define XGFX_VCRTC_VERTICAL_ACTIVE     0x201c
#define XGFX_VCRTC_STRIDE_ALIGNMENT    0x2020
#define XGFX_VCRTC_STRIDE              0x2024
#define XGFX_VCRTC_BASE                0x3000
#define XGFX_VCRTC_LINEOFFSET          0x4000
#define XGFX_VCRTC_EDID                0x5000

/* XGFX_VCRTC_STATUS bits */
#define XGFX_VCRTC_STATUS_HOTPLUG           0x00000001
#define XGFX_VCRTC_STATUS_ONSCREEN          0x00000002
#define XGFX_VCRTC_STATUS_RETRACE           0x00000004

/* XGFX_VCRTC_STATUS_CHANGE bits */
#define XGFX_VCRTC_STATUS_CHANGE_D_HOTPLUG  0x00000001
#define XGFX_VCRTC_STATUS_CHANGE_D_ONSCREEN 0x00000002
#define XGFX_VCRTC_STATUS_CHANGE_D_RETRACE  0x00000004

/* XGFX_VCRTC_STATUS_INT bits */
#define XGFX_VCRTC_STATUS_INT_HOTPLUG_EN    0x00000001
#define XGFX_VCRTC_STATUS_INT_ONSCREEN_EN   0x00000002
#define XGFX_VCRTC_STATUS_INT_RETRACE_EN    0x00000004

/* XGFX_VCRTC_CURSOR_STATUS bits */
#define XGFX_VCRTC_CURSOR_STATUS_SUPPORTED  0x00000001

/* XGFX_VCRTC_CURSOR_CONTROL bits */
#define XGFX_VCRTC_CURSOR_CONTROL_SHOW      0x00000001

/* XGFX_VCRTC_CONTROL bits */
#define XGFX_VCRTC_CONTROL_ENABLE           0x00000001

/* XGFX_VCRTC_VALID_FORMAT bits */
#define XGFX_VCRTC_VALID_FORMAT_NONE        0x00000000
#define XGFX_VCRTC_VALID_FORMAT_RGB555      0x00000001
#define XGFX_VCRTC_VALID_FORMAT_BGR555      0x00000002
#define XGFX_VCRTC_VALID_FORMAT_RGB565      0x00000004
#define XGFX_VCRTC_VALID_FORMAT_BGR565      0x00000008
#define XGFX_VCRTC_VALID_FORMAT_RGB888      0x00000010
#define XGFX_VCRTC_VALID_FORMAT_BGR888      0x00000020
#define XGFX_VCRTC_VALID_FORMAT_RGBX8888    0x00000040
#define XGFX_VCRTC_VALID_FORMAT_BGRX8888    0x00000080

/* Bank/register offset macro. Use values 0x0 through 0xF for
   the bank. */
#define XGFX_VCRTCN_BANK_OFFSET(bank) \
    (XGFX_VCRTC_OFFSET + ((bank << 0x10) & 0xF0000))

#define XGFX_VCRTCN_REG_OFFSET(bank, reg) \
    ((XGFX_VCRTC_OFFSET + ((bank << 0x10) & 0xF0000)) + reg)

/* GART Registers */
#define XGFX_GART_OFFSET                0x200000

#define XGFX_GART_VALID_PFN             0x80000000
#define XGFX_GART_CLEAR_PFN             0x00000000
#define XGFX_GART_REG_MASK              0xBFFFFFFF
#define XGFX_GART_UNMAP_MASK            0X3FFFFFFF

/* GART offset macro. Returns offset to requested PFN register */
#define XGFX_GART_REG_OFFSET(reg) ((XGFX_GART_OFFSET + (reg<<2))

#endif
