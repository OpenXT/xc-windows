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


/* One for 1280 (0x500) x 1024 (0x400)
 *
 * For this case this works as:
 *
 * 60 = x / ((0x500 + 0x18 + 0x8 + 0x8) * (0x400 + 0x03 + 0x11))
 * 60 = x / (0x528) * (0x414)
 * 60 = x / 0x150720
 * x = 82684800
 * 60 = 82684800 / ((0x500 + 0x18 + 0x8 + 0x8) * (0x400 + 0x03 + 0x11))
 * Round for 10 kHz = ~82680000 = 0x204C
 */
static uint8_t xengfx_edid_1280_1024[128] = {
    0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ,0xFF, 0x00,   /* 0x0000 8-byte header */
    0x04, 0x21,                                       /* 0x0008 Vendor ID ("AAA") */
    0xAB, 0xCD,                                       /* 0x000A Product ID */
    0x00, 0x00, 0x00, 0x00,                           /* 0x000C Serial number (none) */
    0x01, 0x15,                                       /* 0x0010 Week 1 of manufactur in year 2011 of manufacture */
    0x01, 0x01,                                       /* 0x0012 EDID version number (1.1) */
    0x0F,                                             /* 0x0014 Video signal interface (analogue, 0.700 : 0.300 : 1.000 V p-p,
                                                         Video Setup: Blank Level = Black Level, Separate Sync H & V Signals
                                                         are supported, Composite Sync Signal on Horizontal is supported, Composite
                                                         Sync Signal on Green Video is supported, Serration on the Vertical Sync
                                                         is supported) */
    0x21, 0x19,                                       /* 0x0015 Scren size (330 mm * 250 mm) */
    0x78,                                             /* 0x0017 Display gamma (2.2) */
    0x0D,                                             /* 0x0018 Feature flags (no DPMS states, RGB, sRGB color space, continuous frequency) */
                                                      /*        Note, DPMS may be useful later in XENGFX */
    0x78, 0xF5,                                       /* 0x0019 Least significant bits for chromaticity and default white point */
    0xA6, 0x55, 0x48, 0x9B, 0x26, 0x12, 0x50, 0x54,   /* 0x001B Most significant bits for chromaticity and default white point */
    0x00,                                             /* 0x0023 Established timings 1 (unset) */
    0x00,                                             /* 0x0024 Established timings 2 (unset) */
    0x00,                                             /* 0x0025 Established timings 2 (unset and no manufacturer timings) */
    0x31, 0x40,                                       /* 0x0026 Standard timing #1 (640 x 480 @ 60 Hz) */
    0x45, 0x40,                                       /* 0x0028 Standard timing #2 (800 x 600 @ 60 Hz) */
    0x61, 0x40,                                       /* 0x002A Standard timing #3 (1024 x 768 @ 60 Hz) */
    0x01, 0x01,                                       /* 0x002C Standard timing #4 (unused) */
    0x01, 0x01,                                       /* 0x002E Standard timing #5 (unused) */
    0x01, 0x01,                                       /* 0x0030 Standard timing #6 (unused) */
    0x01, 0x01,                                       /* 0x0032 Standard timing #7 (unused) */
    0x01, 0x01,                                       /* 0x0034 Standard timing #8 (unused) */
                                                      /* 0x0036 First 18-byte descriptor (Preferred Timing Mode) */
                                                      /*        Currently set to 1024 x 768 @ 60 Hz */
    0x4c, 0x20,                                       /* Pixel clock = 81,160,000 Hz  (~81 Mhz) */
    0x00,                                             /* Horizontal addressable pixels low byte (0x0500 & 0xFF) */
    0x18,                                             /* Horizontal blanking low byte (0x0018 & 0xFF) */
    0x50,                                             /* Horizontal addressable pixels high 4 bits (0x0500 >> 8), and */
                                                      /* Horizontal blanking high 4 bits (0x0018 >> 8) */
    0x00,                                             /* Vertical addressable pixels low byte (0x0400 & 0xFF) */
    0x03,                                             /* Vertical blanking low byte (0x0003 & 0xFF) */
    0x40,                                             /* Vertical addressable pixels high 4 bits (0x0400 >> 8), and */
                                                      /* Vertical blanking high 4 bits (0x0003 >> 8) */
    0x08,                                             /* Horizontal front porch in pixels low byte (0x0030 & 0xFF) */
    0x08,                                             /* Horizontal sync pulse width in pixels low byte (0x0070 & 0xFF) */
    0x11,                                             /* Vertical front porch in lines low 4 bits (0x0001 & 0x0F), and */
                                                      /* Vertical sync pulse width in lines low 4 bits (0x0003 & 0x0F) */
    0x00,                                             /* Horizontal front porch pixels high 2 bits (0x0030 >> 8), and */
                                                      /* Horizontal sync pulse width in pixels high 2 bits (0x0070 >> 8), and */
                                                      /* Vertical front porch in lines high 2 bits (0x0001 >> 4), and */
                                                      /* Vertical sync pulse width in lines high 2 bits (0x0003 >> 4) */
    0x00,                                             /* Horizontal addressable video image size in mm low 8 bits (0x012C & 0xFF) */
    0x00,                                             /* Vertical addressable video image size in mm low 8 bits (0x00E1 & 0xFF) */
    0x00,                                             /* Horizontal addressable video image size in mm low 8 bits (0x012C >> 8), and */
                                                      /* Vertical addressable video image size in mm low 8 bits (0x00E1 >> 8) */
    0x00,                                             /*          Left and right border size in pixels (0x00) */
    0x00,                                             /*          Top and bottom border size in lines (0x00) */
    0x00,                                             /* Flags (non-interlaced, no stereo, analog composite sync, sync on */
                                                      /* all three (RGB) video signals) */

    0x00, 0x00, 0x00, 0x10, 0x00,                     /* 0x0048 Second 18-byte descriptor - Dummy */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00 ,0x00, 0x00, 0x00, 0x00,

    0x00, 0x00, 0x00, 0xFF, 0x00,                     /* 0x005A Third 18-byte descriptor - Display product serial number */
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    0x0A, 0x20, 0x20,

    0x00, 0x00, 0x00, 0xFC, 0x00,                     /* 0x006C Fourth 18-byte descriptor - Display product name  */
    'X', 'G', 'F', 'X', ' ', 'D', 'i', 's', 'p', 'l', 'a', 'y',
    0x0A,

    0x00,                                             /* 0x007E Extension block count (none)  */
    0x00,                                             /* 0x007F Checksum (recalculated when needed)  */
};
