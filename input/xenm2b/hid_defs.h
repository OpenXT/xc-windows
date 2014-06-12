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

// Xen Windows PV M2B Bus Driver - HID specific defs.

#ifndef HID_DEFS_H
#define HID_DEFS_H

// Report IDs for the various devices
#define REPORT_ID_KEYBOARD      0x01
#define REPORT_ID_MOUSE         0x02
#define REPORT_ID_TABLET        0x03
#define REPORT_ID_MULTITOUCH    0x04
#define REPORT_ID_STYLUS        0x05
#define REPORT_ID_PUCK          0x06
#define REPORT_ID_FINGER        0x07
#define REPORT_ID_MT_MAX_COUNT  0x10
#define REPORT_ID_CONFIG        0x11
#define REPORT_ID_INVALID       0xff

// Bit mask specifying what types are present in composite devices
#define DEVICE_TYPE_UNKNOWN     0x00000000
#define DEVICE_TYPE_KEYBOARD    0x00000001
#define DEVICE_TYPE_MOUSE       0x00000002
#define DEVICE_TYPE_TABLET      0x00000004
#define DEVICE_TYPE_MULTITOUCH  0x00000010
#define DEVICE_TYPE_DIGITIZER   0x00000020

// NULL values
#define BYTE_NULL_VALUE         0xff
#define WORD_NULL_VALUE         0xffff
#define DWORD_NULL_VALUE        0xffffffff
#define QWORD_NULL_VALUE        0xffffffffffffffff

// Button related values
#define MOUSE_BUTTON_START      0x110
#define TOOL_BUTTON_START       0x140

// Digitizer usage fields
#define DIGITIZER_TIP_SWITCH    0
#define DIGITIZER_TOUCH_VALID   1
#define DIGITIZER_IN_RANGE      2
#define DIGITIZER_BARREL_SWITCH 2
#define DIGITIZER_ERASER_SWITCH 3
#define DIGITIZER_INVERT        4

// Key usage ranges for modifier keys
#define USAGE_LEFT_SHIFT        0xE0
#define USAGE_RIGHT_WINDOWS     0xE7

//#define TEN_FINGER_MT_REPORT    1

#ifdef TEN_FINGER_MT_REPORT
#define MT_FINGER_MAX_COUNT     0x0a
#else
#define MT_FINGER_MAX_COUNT     0x02
#endif

extern const HID_DEVICE_ATTRIBUTES HidAttributes;
extern const HID_DESCRIPTOR HidDescriptor;

extern const UCHAR KeyboardReportDescriptor[];
extern const UCHAR MouseReportDescriptor[];
extern const UCHAR TabletReportDescriptor[];
extern const UCHAR MultitouchReportDescriptor[];
extern const UCHAR DigitizerReportDescriptor[];

extern const ULONG KeyboardDescriptorLength;
extern const ULONG MouseDescriptorLength;
extern const ULONG TabletDescriptorLength;
extern const ULONG MultitouchDescriptorLength;
extern const ULONG DigitizerDescriptorLength;

extern const UCHAR KeyMap[];

typedef struct _HID_STRING {
    UCHAR       Id;
    UCHAR       Length;
    PUCHAR      String;
} HID_STRING;

extern const HID_STRING MouseHidStrings[];
extern const HID_STRING TabletHidStrings[];
extern const HID_STRING TouchHidStrings[];
extern const HID_STRING DigitizerHidStrings[];
extern const HID_STRING CitrixHidStrings[];

#pragma pack(push, 1)

// Default data structures - defined by report descriptors above
typedef struct _KeyboardReportData {
    UCHAR       ReportID;
    UCHAR       Modifiers;
    UCHAR       Reserved;
    UCHAR       Keys[6];
} KeyboardReportData;

typedef struct _MouseReportData {
    UCHAR       ReportID;
    UCHAR       Buttons;
    UCHAR       X; // relative
    UCHAR       Y; // relative
    UCHAR       Z; // relative
} MouseReportData;

typedef struct _TabletReportData {
    UCHAR       ReportID;
    UCHAR       Buttons;
    USHORT      X; // absolute
    USHORT      Y; // absolute
    UCHAR       Z; // relative
} TabletReportData;

typedef struct _MultiFingerData {
    UCHAR       Buttons;
    UCHAR       ContactID;
    USHORT      X; // absolute
    USHORT      Y; // absolute
} MultiFingerData;

typedef struct _MultitouchReportData {
    UCHAR           ReportID;
    MultiFingerData Fingers[MT_FINGER_MAX_COUNT];
    USHORT          ScanTime; // 100 microsecs
    UCHAR           ContactCount;
} MultitouchReportData;

typedef struct _SylusReportData {
    UCHAR       ReportID;
    UCHAR       Buttons;
    USHORT      X; // absolute
    USHORT      Y; // absolute
    USHORT      Pressure;
} StylusReportData;

typedef struct _PuckReportData {
    UCHAR       ReportID;
    UCHAR       Buttons;
    USHORT      X; // absolute
    USHORT      Y; // absolute
} PuckReportData;

typedef struct _FingerReportData {
    UCHAR       ReportID;
    UCHAR       Buttons;
    USHORT      X; // absolute
    USHORT      Y; // absolute
} FingerReportData;

#pragma pack(pop)

#endif  // HID_DEFS_H
