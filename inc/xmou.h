//
// xmou.h - Xen Virutal Mouse/Input Hardware
//
// Copyright (c) 2012 Citrix, Inc.
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


#ifndef XMOU_H
#define XMOU_H

#define XMOU_MAGIC_VALUE               0x584D4F55 // 'XMOU'

// Global Registers
#define XMOU_GLOBAL_BASE               0x000000

#define XMOU_MAGIC                     0x00000  // reads 0x584D4F55 'XMOU'
#define XMOU_REV                       0x00004
#define XMOU_CONTROL                   0x00100
#define XMOU_EVENT_SIZE                0x00104
#define XMOU_EVENT_NPAGES              0x00108
#define XMOU_ACCELERATION              0x0010C
#define XMOU_ISR                       0x00110
#define XMOU_CONFIG_SIZE               0x00114
#define XMOU_CLIENT_REV                0x00118

// XMOU_CONTROL bits
#define XMOU_CONTROL_XMOU_EN           0x00000001
#define XMOU_CONTROL_INT_EN            0x00000002

// XMOU_ISR bits
#define XMOU_ISR_INT                   0x00000001

// Event Registers
#define XMOU_EVENT_BASE                0x10000

// The first two DWORDs contain the read and write pointer.
#define XMOU_READ_PTR                  0x00000
#define XMOU_WRITE_PTR                 0x00004

// XENMOU 1: Mouse Event Flags, Revision and Data
#define XMOU1_CLIENT_REV               0x1

#define XMOU_FLAG_ABSOLUTE             0x0001
#define XMOU_FLAG_RELATIVE             0x0002
#define XMOU_FLAG_FENCE                0x0004
#define XMOU_FLAG_LEFT_BUTTON_DOWN     0x0008
#define XMOU_FLAG_LEFT_BUTTON_UP       0x0010
#define XMOU_FLAG_RIGHT_BUTTON_DOWN    0x0020
#define XMOU_FLAG_RIGHT_BUTTON_UP      0x0040
#define XMOU_FLAG_MIDDLE_BUTTON_DOWN   0x0080
#define XMOU_FLAG_MIDDLE_BUTTON_UP     0x0100
#define XMOU_FLAG_HWHEEL               0x0200
#define XMOU_FLAG_VWHEEL               0x0400

// XENMOU 2: HID Event Types, Codes and Values

#define XMOU2_CLIENT_REV               0x2

// Most of the keys/buttons are modeled after USB HUT 1.12
// (see http://www.usb.org/developers/hidpage)
// (and http://lxr.free-electrons.com/source/include/linux/input.h)

#define XMOU_TYPE_EV_SYN                 0x00
#define XMOU_TYPE_EV_KEY                 0x01
#define XMOU_TYPE_EV_REL                 0x02
#define XMOU_TYPE_EV_ABS                 0x03
#define XMOU_TYPE_EV_DEV                 0x06

// Event code values
#define XMOU_CODE_SYN_REPORT              0x0
#define XMOU_CODE_SYN_MT_REPORT           0x2

#define XMOU_CODE_KEY_RESERVED           0xff

#define XMOU_BTN_REBASE                 0x100 // Adjust BTN values down

#define XMOU_CODE_BTN_LEFT              0x110
#define XMOU_CODE_BTN_RIGHT             0x111
#define XMOU_CODE_BTN_MIDDLE            0x112
#define XMOU_CODE_BTN_SIDE              0x113
#define XMOU_CODE_BTN_EXTRA             0x114
#define XMOU_CODE_BTN_FORWARD           0x115
#define XMOU_CODE_BTN_BACK              0x116
#define XMOU_CODE_BTN_TASK              0x117
#define XMOU_CODE_BTN_TOOL_PEN          0x140
#define XMOU_CODE_BTN_TOOL_RUBBER       0x141
#define XMOU_CODE_BTN_TOOL_BRUSH        0x142
#define XMOU_CODE_BTN_TOOL_PENCIL       0x143
#define XMOU_CODE_BTN_TOOL_AIRBRUSH     0x144
#define XMOU_CODE_BTN_TOOL_FINGER       0x145
#define XMOU_CODE_BTN_TOOL_MOUSE        0x146
#define XMOU_CODE_BTN_TOOL_LENS         0x147
#define XMOU_CODE_BTN_TOUCH             0x14a
#define XMOU_CODE_BTN_STYLUS            0x14b
#define XMOU_CODE_BTN_STYLUS2           0x14c

#define XMOU_CODE_REL_X                  0x00
#define XMOU_CODE_REL_Y                  0x01
#define XMOU_CODE_REL_WHEEL              0x08

#define XMOU_CODE_ABS_X                  0x00
#define XMOU_CODE_ABS_Y                  0x01
#define XMOU_CODE_ABS_PRESSURE           0x18
#define XMOU_CODE_ABS_MT_SLOT            0x2f
#define XMOU_CODE_ABS_MT_POSITION_X      0x35
#define XMOU_CODE_ABS_MT_POSITION_Y      0x36
#define XMOU_CODE_ABS_MT_TRACKING_ID     0x39
#define XMOU_CODE_ABS_MT_PRESSURE        0x3a

#define XMOU_CODE_DEV_SET                 0x1
#define XMOU_CODE_DEV_CONF                0x2
#define XMOU_CODE_DEV_RESET               0x3

// Device Configuration

// TODO:
//  - As slots are freed, hopefully existing configs do not move?

#define XMOU_DEV_CONFIG_INVALID_SLOT     0xff

#endif  // XMOU_H
