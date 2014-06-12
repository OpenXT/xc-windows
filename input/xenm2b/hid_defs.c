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

#include <ntddk.h>
#include <ntstrsafe.h>
#include <hidport.h>
#include "input.h"
#include "xmou.h"
#include "xenm2b.h"
#include "hid_defs.h"

/* HID structures */
const HID_DEVICE_ATTRIBUTES HidAttributes = {
    sizeof(HID_DEVICE_ATTRIBUTES),
    0x5853,     // VendorID
    0x8000,     // ProductID
    0x0101,     // VersionNumber
    { 0 }       // reserved
};

const HID_DESCRIPTOR HidDescriptor = {
    0x09,       // bLength
    0x21,       // bDescriptorType - hid
    0x0101,     // bcdHid (v1.01 of spec)
    0x00,       // bContryCode - not specified
    0x01,       // bNumDescriptors
    {
        0x22,   // bDescriptorType - report descriptor
        0x0000, // wDescriptorLength (overriden)
    }
};

const UCHAR KeyboardReportDescriptor[] = {
    0x05, 0x01,                    // USAGE_PAGE (Generic Desktop)
    0x09, 0x06,                    // USAGE (Keyboard)
    0xa1, 0x01,                    // COLLECTION (Application)
    0x85, REPORT_ID_KEYBOARD,      //   REPORT_ID (REPORT_ID_KEYBOARD)
    0x05, 0x07,                    //   USAGE_PAGE (Keyboard)
    0x19, 0xe0,                    //   USAGE_MINIMUM (Keyboard LeftControl)
    0x29, 0xe7,                    //   USAGE_MAXIMUM (Keyboard Right GUI)
    0x15, 0x00,                    //   LOGICAL_MINIMUM (0)
    0x25, 0x01,                    //   LOGICAL_MAXIMUM (1)
    0x75, 0x01,                    //   REPORT_SIZE (1)
    0x95, 0x08,                    //   REPORT_COUNT (8)
    0x81, 0x02,                    //   INPUT (Data,Var,Abs)
    0x95, 0x01,                    //   REPORT_COUNT (1)
    0x75, 0x08,                    //   REPORT_SIZE (8)
    0x81, 0x03,                    //   INPUT (Cnst,Var,Abs)
    0x95, 0x06,                    //   REPORT_COUNT (6)
    0x75, 0x08,                    //   REPORT_SIZE (8)
    0x15, 0x00,                    //   LOGICAL_MINIMUM (0)
    0x25, 0x65,                    //   LOGICAL_MAXIMUM (101)
    0x05, 0x07,                    //   USAGE_PAGE (Keyboard)
    0x19, 0x00,                    //   USAGE_MINIMUM (Reserved (no event indicated))
    0x29, 0x65,                    //   USAGE_MAXIMUM (Keyboard Application)
    0x81, 0x00,                    //   INPUT (Data,Ary,Abs)
    0xc0,                          // END_COLLECTION
};

// This is a relative mouse with 5 buttons and a vertical wheel.
const UCHAR MouseReportDescriptor[] = {
    0x05, 0x01,                    // USAGE_PAGE (Generic Desktop)
    0x09, 0x02,                    // USAGE (Mouse)
    0xa1, 0x01,                    // COLLECTION (Application)
    0x85, REPORT_ID_MOUSE,         //   REPORT_ID (2)
    0x09, 0x01,                    //   USAGE (Pointer)
    0xa1, 0x00,                    //   COLLECTION (Physical)
    0x05, 0x09,                    //     USAGE_PAGE (Button)
    0x19, 0x01,                    //     USAGE_MINIMUM (Button 1)
    0x29, 0x05,                    //     USAGE_MAXIMUM (Button 5)
    0x15, 0x00,                    //     LOGICAL_MINIMUM (0)
    0x25, 0x01,                    //     LOGICAL_MAXIMUM (1)
    0x95, 0x05,                    //     REPORT_COUNT (5)
    0x75, 0x01,                    //     REPORT_SIZE (1)
    0x81, 0x02,                    //     INPUT (Data,Var,Abs)
    0x95, 0x01,                    //     REPORT_COUNT (1)
    0x75, 0x03,                    //     REPORT_SIZE (3)
    0x81, 0x03,                    //     INPUT (Cnst,Var,Abs)
    0x05, 0x01,                    //     USAGE_PAGE (Generic Desktop)
    0x09, 0x30,                    //     USAGE (X)
    0x09, 0x31,                    //     USAGE (Y)
    0x09, 0x38,                    //     USAGE (Z)
    0x15, 0x81,                    //     LOGICAL_MINIMUM (-127)
    0x25, 0x7f,                    //     LOGICAL_MAXIMUM (127)
    0x75, 0x08,                    //     REPORT_SIZE (8)
    0x95, 0x03,                    //     REPORT_COUNT (3)
    0x81, 0x06,                    //     INPUT (Data,Var,Rel)
    0xc0,                          //   END_COLLECTION
    0xc0                           // END_COLLECTION
};

// This is an absolute tablet/mouse with 5 buttons and a vertical wheel.
const UCHAR TabletReportDescriptor[] = {
    0x05, 0x01,                    // Usage Page (Generic Desktop)
    0x09, 0x01,                    // Usage (Pointer)
    0xa1, 0x01,                    // Collection (Application)
    0x85, REPORT_ID_TABLET,        //   REPORT_ID (3 REPORT_ID_TABLET)
    0x09, 0x01,                    //   Usage (Pointer)
    0xa1, 0x00,                    //   Collection (Physical)
    0x05, 0x09,                    //     Usage Page (Button)
    0x19, 0x01,                    //     Usage Minimum (1)
    0x29, 0x05,                    //     Usage Maximum (5)
    0x15, 0x00,                    //     Logical Minimum (0)
    0x25, 0x01,                    //     Logical Maximum (1)
    0x95, 0x05,                    //     Report Count (5)
    0x75, 0x01,                    //     Report Size (1)
    0x81, 0x02,                    //     Input (Data, Variable, Absolute)
    0x95, 0x01,                    //     Report Count (1)
    0x75, 0x03,                    //     Report Size (3)
    0x81, 0x01,                    //     Input (Constant)
    0x05, 0x01,                    //     Usage Page (Generic Desktop)
    0x09, 0x30,                    //     Usage (X)
    0x09, 0x31,                    //     Usage (Y)
    0x15, 0x00,                    //     Logical Minimum (0)
    0x26, 0xff, 0x7f,              //     Logical Maximum (0x7fff)
    0x35, 0x00,                    //     Physical Minimum (0)
    0x46, 0xff, 0x7f,              //     Physical Maximum (0x7fff)
    0x75, 0x10,                    //     Report Size (16)
    0x95, 0x02,                    //     Report Count (2)
    0x81, 0x02,                    //     Input (Data, Variable, Absolute)
    0x09, 0x38,                    //     Usage (Wheel)
    0x15, 0x81,                    //     Logical Minimum (-0x7f)
    0x25, 0x7f,                    //     Logical Maximum (0x7f)
    0x35, 0x00,                    //     Physical Minimum (same as logical)
    0x45, 0x00,                    //     Physical Maximum (same as logical)
    0x75, 0x08,                    //     Report Size (8)
    0x95, 0x01,                    //     Report Count (1)
    0x81, 0x06,                    //     Input (Data, Variable, Relative)
    0xc0,                          //   End Collection
    0xc0,                          // End Collection
};

#define LOGICAL_FINGER\
    0x05, 0x0d,                    /*     USAGE_PAGE (Digitizers) */\
    0x09, 0x22,                    /*     USAGE (Finger) */\
    0xa1, 0x02,                    /*     COLLECTION (Logical) */\
    0x09, 0x42,                    /*       USAGE (Tip Switch) */\
    0x15, 0x00,                    /*       LOGICAL_MINIMUM (0) */\
    0x25, 0x01,                    /*       LOGICAL_MAXIMUM (1) */\
    0x75, 0x01,                    /*       REPORT_SIZE (1) */\
    0x95, 0x01,                    /*       REPORT_COUNT (1) */\
    0x81, 0x02,                    /*       INPUT (Data,Var,Abs) */\
    0x09, 0x47,                    /*       USAGE (Confidence) */\
    0x81, 0x02,                    /*       INPUT (Data,Var,Abs) */\
    0x95, 0x06,                    /*       REPORT_COUNT (6) */\
    0x81, 0x01,                    /*       INPUT (Cnst,Ary,Abs) */\
    0x75, 0x08,                    /*       REPORT_SIZE (8) */\
    0x09, 0x51,                    /*       USAGE (Contact Identifier) */\
    0x95, 0x01,                    /*       REPORT_COUNT (1) */\
    0x81, 0x02,                    /*       INPUT (Data,Var,Abs) */\
    0x05, 0x01,                    /*       USAGE_PAGE (Generic Desktop) */\
    0x15, 0x00,                    /*       LOGICAL_MINIMUM (0) */\
    0x26, 0xff, 0x7f,              /*       LOGICAL_MAXIMUM (32767) */\
    0x75, 0x10,                    /*       REPORT_SIZE (16) */\
    0x09, 0x30,                    /*       USAGE (X) */\
    0x81, 0x02,                    /*       INPUT (Data,Var,Abs) */\
    0x09, 0x31,                    /*       USAGE (Y) */\
    0x81, 0x02,                    /*       INPUT (Data,Var,Abs) */\
    0xc0                           /*     END_COLLECTION */

const UCHAR MultitouchReportDescriptor[] = {
    0x05, 0x0d,                    // USAGE_PAGE (Digitizers)
    0x09, 0x04,                    // USAGE (Touch Screen)
    0xa1, 0x01,                    // COLLECTION (Application)
    0x85, REPORT_ID_MULTITOUCH,    //   REPORT_ID (REPORT_ID_MULTITOUCH)
    LOGICAL_FINGER,                
    LOGICAL_FINGER,                
#ifdef TEN_FINGER_MT_REPORT
    // Windows 8 specifies a minumum of 5 touch points for multitouch 
    LOGICAL_FINGER,                
    LOGICAL_FINGER,                
    LOGICAL_FINGER,                
    LOGICAL_FINGER,                
    LOGICAL_FINGER,                
    LOGICAL_FINGER,                
    LOGICAL_FINGER,                
    LOGICAL_FINGER,                
#endif
    0x05, 0x0d,                    //   USAGE_PAGE (Digitizers)
    0x55, 0x0C,                    //   UNIT_EXPONENT (-4)
    0x66, 0x01, 0x10,              //   UNIT (Seconds)
    0x47, 0xff, 0xff, 0x00, 0x00,  //   PHYSICAL_MAXIMUM (65535)
    0x27, 0xff, 0xff, 0x00, 0x00,  //   LOGICAL_MAXIMUM (65535)
    0x75, 0x10,                    //   REPORT_SIZE (16)
    0x95, 0x01,                    //   REPORT_COUNT (1)
    0x09, 0x56,                    //   USAGE (Scan Time)
    0x81, 0x02,                    //   INPUT (Data,Var,Abs)
    0x55, 0x00,                    //   UNIT_EXPONENT (0)
    0x65, 0x00,                    //   UNIT (None)
    0x35, 0x00, 	               // 	PYSICAL_MINIMUM (0)
    0x45, 0x00,                    //   PHYSICAL_MAXIMUM (0)
    0x09, 0x54,                    //   USAGE (Contact count)
    0x95, 0x01,                    //   REPORT_COUNT (1)
    0x75, 0x08,                    //   REPORT_SIZE (8)
    0x15, 0x00,                    //   LOGICAL_MINIMUM (0)
    0x25, MT_FINGER_MAX_COUNT,     //   LOGICAL_MAXIMUM (Max Fingers)
    0x81, 0x02,                    //   INPUT (Data,Var,Abs)
    0x85, REPORT_ID_MT_MAX_COUNT,  //   REPORT_ID (Contact Count Max)
    0x09, 0x55,                    //   USAGE(Contact Count Maximum)
    0x95, 0x01,                    //   REPORT_COUNT (1)
    0xb1, 0x02,                    //   FEATURE (Data,Var,Abs)
    0xc0,                          // END_COLLECTION
    0x09, 0x0e,                    // USAGE (Device Configuration)
    0xa1, 0x01,                    // COLLECTION (Application)
    0x85, REPORT_ID_CONFIG,        //   REPORT_ID (REPORT_ID_CONFIG) 
    0x09, 0x22,                    //   USAGE (Finger)
    0xa1, 0x00,                    //   COLLECTION (Physical)
    0x09, 0x52,                    //     USAGE (Device Mode)	
    0x25, 0x0a,                    //     LOGICAL_MAXIMUM (10) 
    0x75, 0x08,                    //     REPORT_SIZE (8)
    0x95, 0x01,                    //     REPORT_COUNT (1)
    0xb1, 0x02,                    //     FEATURE (Data, Var, Abs)
    0xc0,                          //   END_COLLECTION
    0xc0, 		                   // END_COLLECTION
    // Single touch fallback device
    0x05, 0x01,		               // USAGE_PAGE (Generic Desktop)
    0x09, 0x02, 		           // USAGE (Mouse)
    0xa1, 0x01, 		           // COLLECTION (Application)
    0x85, REPORT_ID_FINGER,        //   REPORT_ID (REPORT_ID_FINGER)
    0x09, 0x01, 		           //   USAGE (Pointer)
    0xa1, 0x00, 		           //   COLLECTION (Physical)
    0x05, 0x09, 		           //     USAGE_PAGE (Button)
    0x19, 0x01, 		           //     USAGE_MINIMUM (1)
    0x29, 0x02, 		           //     USAGE_MAXIMUM (2)
    0x15, 0x00,                    //     LOGICAL_MINIMUM (0)
    0x25, 0x01,                    //     LOGICAL_MAXIMUM (1)
    0x75, 0x01, 		           //     REPORT_SIZE (1)
    0x95, 0x02, 		           //     REPORT_COUNT (2)
    0x81, 0x02, 		           //     INPUT (Data, Var, Abs)
    0x95, 0x06, 		           //     REPORT_COUNT (6)
    0x81, 0x03, 		           //     INPUT (Cnst, Var, Abs)
    0x26, 0xff, 0x7f,              //     LOGICAL_MAXIMUM (32767)
    0x05, 0x01,                    //     USAGE_PAGE (Generic Desktop)
    0x75, 0x10, 		           //     REPORT_SIZE (16)
    0x95, 0x01, 		           //     REPORT_COUNT (1)
    0x09, 0x30, 		           //     USAGE (X)
    0x81, 0x02, 		           //     INPUT (Data, Var, Abs)
    0x09, 0x31, 			       //     USAGE (Y)
    0x81, 0x02, 		           //     INPUT (Data, Var, Abs)
    0xc0, 		                   //   END_COLLECTION
    0xc0 		                   // END_COLLECTION
};

const UCHAR DigitizerReportDescriptor[] = {
    0x05, 0x0d,                    // USAGE_PAGE (Digitizers)
    0x09, 0x02,                    // USAGE (Digitizer)
    0xa1, 0x01,                    // COLLECTION (Application)
    0x85, REPORT_ID_STYLUS,        //   REPORT_ID (Stylus)
    0x09, 0x20,                    //   USAGE (Stylus)
    0xa1, 0x00,                    //   COLLECTION (Physical)
    0x09, 0x42,                    //     USAGE (Tip Switch)
    0x09, 0x32,                    //     USAGE (In Range)
    0x09, 0x44,                    //     USAGE (Barrel Switch)
    0x09, 0x45,                    //     USAGE (Eraser Switch)
    0x09, 0x3c,                    //     USAGE (Invert)
    0x15, 0x00,                    //     LOGICAL_MINIMUM (0)
    0x25, 0x01,                    //     LOGICAL_MAXIMUM (1)
    0x75, 0x01,                    //     REPORT_SIZE (1)
    0x95, 0x05,                    //     REPORT_COUNT (5)
    0x81, 0x02,                    //     INPUT (Data,Var,Abs)
    0x95, 0x03,                    //     REPORT_COUNT (3)
    0x81, 0x03,                    //     INPUT (Cnst,Var,Abs) (3b pad)
    0x05, 0x01,                    //     USAGE_PAGE (Generic Desktop)
    0x26, 0xff, 0x7f,              //     LOGICAL_MAXIMUM (32767)
    0x75, 0x10,                    //     REPORT_SIZE (16)
    0x95, 0x01,                    //     REPORT_COUNT (1)
    0xa4,                          //     PUSH
    0x55, 0x0d,                    //     UNIT_EXPONENT (-3)
    0x65, 0x33,                    //     UNIT (Inch,EngLinear)
    0x09, 0x30,                    //     USAGE (X)
    0x35, 0x00,                    //     PHYSICAL_MINIMUM (0)
    0x46, 0x00, 0x00,              //     PHYSICAL_MAXIMUM (0)
    0x81, 0x02,                    //     INPUT (Data,Var,Abs)
    0x09, 0x31,                    //     USAGE (Y)
    0x46, 0x00, 0x00,              //     PHYSICAL_MAXIMUM (0)
    0x81, 0x02,                    //     INPUT (Data,Var,Abs)
    0xb4,                          //     POP
    0x05, 0x0d,                    //     USAGE_PAGE (Digitizers)
    0x09, 0x30,                    //     USAGE (Tip Pressure)
    0x81, 0x02,                    //     INPUT (Data,Var,Abs)
    0xc0,                          //   END_COLLECTION
    0x85, REPORT_ID_PUCK,          //   REPORT_ID (Puck)
    0x09, 0x21,                    //   USAGE (Puck)
    0xa1, 0x00,                    //   COLLECTION (Physical)
    0x05, 0x0d,                    //     USAGE_PAGE (Digitizers)
    0x09, 0x42,                    //     USAGE (Tip Switch)
    0x09, 0x32,                    //     USAGE (In Range)
    0x09, 0x44,                    //     USAGE (Barrel Switch)
    0x15, 0x00,                    //     LOGICAL_MINIMUM (0)
    0x25, 0x01,                    //     LOGICAL_MAXIMUM (1)
    0x75, 0x01,                    //     REPORT_SIZE (1)
    0x95, 0x03,                    //     REPORT_COUNT (3)
    0x81, 0x02,                    //     INPUT (Data,Var,Abs)
    0x95, 0x05,                    //     REPORT_COUNT (5)
    0x81, 0x03,                    //     INPUT (Cnst,Var,Abs) (5b pad)
    0x05, 0x01,                    //     USAGE_PAGE (Generic Desktop)
    0x26, 0xff, 0x7f,              //     LOGICAL_MAXIMUM (32767)
    0x75, 0x10,                    //     REPORT_SIZE (16)
    0x95, 0x01,                    //     REPORT_COUNT (1)
    0xa4,                          //     PUSH
    0x55, 0x0d,                    //     UNIT_EXPONENT (0)
    0x65, 0x33,                    //     UNIT (Inch,EngLinear)
    0x09, 0x30,                    //     USAGE (X)
    0x35, 0x00,                    //     PHYSICAL_MINIMUM (0)
    0x46, 0x00, 0x00,              //     PHYSICAL_MAXIMUM (0)
    0x81, 0x02,                    //     INPUT (Data,Var,Abs)
    0x09, 0x31,                    //     USAGE (Y)
    0x46, 0x00, 0x00,              //     PHYSICAL_MAXIMUM (0)
    0x81, 0x02,                    //     INPUT (Data,Var,Abs)
    0xb4,                          //     POP
    0xc0,                          //   END_COLLECTION
    0x85, REPORT_ID_FINGER,        //   REPORT_ID (Finger)
    0x09, 0x22,                    //   USAGE (Finger)
    0xa1, 0x02,                    //   COLLECTION (Physical)
    0x05, 0x0d,                    //     USAGE_PAGE (Digitizers)
    0x09, 0x42,                    //     USAGE (Tip Switch)
    0x09, 0x32,                    //     USAGE (In Range)
    0x09, 0x47,                    //     USAGE (Touch Valid)
    0x15, 0x00,                    //     LOGICAL_MINIMUM (0)
    0x25, 0x01,                    //     LOGICAL_MAXIMUM (1)
    0x75, 0x01,                    //     REPORT_SIZE (1)
    0x95, 0x01,                    //     REPORT_COUNT (3)
    0x81, 0x02,                    //     INPUT (Data,Var,Abs)
    0x95, 0x05,                    //     REPORT_COUNT (5)
    0x81, 0x03,                    //     INPUT (Cnst,Ary,Abs) (5b pad)
    0x05, 0x01,                    //     USAGE_PAGE (Generic Desktop)
    0x26, 0xff, 0x7f,              //     LOGICAL_MAXIMUM (32767)
    0x75, 0x10,                    //     REPORT_SIZE (16)
    0x95, 0x01,                    //     REPORT_COUNT (1)
    0xa4,                          //     PUSH
    0x55, 0x00,                    //     UNIT_EXPONENT (0)
    0x65, 0x00,                    //     UNIT (None)
    0x09, 0x30,                    //     USAGE (X)
    0x35, 0x00,                    //     PHYSICAL_MINIMUM (0)
    0x46, 0x00, 0x00,              //     PHYSICAL_MAXIMUM (0)
    0x81, 0x02,                    //     INPUT (Data,Var,Abs)
    0x09, 0x31,                    //     USAGE (Y)
    0x46, 0x00, 0x00,              //     PHYSICAL_MAXIMUM (0)
    0x81, 0x02,                    //     INPUT (Data,Var,Abs)
    0xb4,                          //     POP
    0xc0,                          //   END_COLLECTION
    0xc0,                          // END_COLLECTION
};

const ULONG KeyboardDescriptorLength = sizeof(KeyboardReportDescriptor);
const ULONG MouseDescriptorLength = sizeof(MouseReportDescriptor);
const ULONG TabletDescriptorLength = sizeof(TabletReportDescriptor);
const ULONG MultitouchDescriptorLength = sizeof(MultitouchReportDescriptor);
const ULONG DigitizerDescriptorLength = sizeof(DigitizerReportDescriptor);

const UCHAR KeyMap[] = {
 // HID     KEY_*   HID     KEY_*   HID     KEY_*   HID     KEY_*
    0x04,   30,     0x05,   48,     0x06,   46,     0x07,   32,
    0x08,   18,     0x09,   33,     0x0A,   34,     0x0B,   35,
    0x0C,   23,     0x0D,   36,     0x0E,   37,     0x0F,   38,
    0x10,   50,     0x11,   49,     0x12,   24,     0x13,   25,
    0x14,   16,     0x15,   19,     0x16,   31,     0x17,   20,
    0x18,   22,     0x19,   47,     0x1A,   17,     0x1B,   45,
    0x1C,   21,     0x1D,   44,     0x1E,   2,      0x1F,   3,
    0x20,   4,      0x21,   5,      0x22,   6,      0x23,   7,
    0x24,   8,      0x25,   9,      0x26,   10,     0x27,   11,
    0x28,   28,     0x29,   1,      0x2A,   14,     0x2B,   15,
    0x2C,   57,     0x2D,   12,     0x2E,   13,     0x2F,   26,
    0x30,   27,     0x31,   43,     0x32,   86,     0x33,   39,
    0x34,   40,     0x35,   41,     0x36,   51,     0x37,   52,
    0x38,   53,     0x39,   58,     0x3A,   59,     0x3B,   60,
    0x3C,   61,     0x3D,   62,     0x3E,   63,     0x3F,   64,
    0x40,   65,     0x41,   66,     0x42,   67,     0x43,   68,
    0x44,   87,     0x45,   88,     0x46,   99,     0x47,   70,
    0x48,   119,    0x49,   110,    0x4A,   102,    0x4B,   104,
    0x4C,   111,    0x4D,   107,    0x4E,   109,    0x4F,   106,
    0x50,   105,    0x51,   108,    0x52,   103,    0x53,   69,
    0x54,   98,     0x55,   55,     0x56,   74,     0x57,   78,
    0x58,   96,     0x59,   79,     0x5A,   80,     0x5B,   81,
    0x5C,   75,     0x5D,   76,     0x5E,   77,     0x5F,   71,
    0x60,   72,     0x61,   73,     0x62,   82,     0x63,   83,
    0x64,   86,     0x65,   127,
    0x66,   116,    /* 67 */
    0x68,   183,    0x69,   184,    0x6A,   185,    0x6B,   186,
    0x6C,   187,    0x6D,   188,    0x6E,   189,    0x6F,   190,
    0x70,   191,    0x71,   192,    0x72,   193,    0x73,   194,
    /* 74 */
    0x75,   138,    0x76,   139,    /* 77 - 78 */
    0x79,   182,    0x7A,   131,    0x7B,   137,    0x7C,   133,
    0x7D,   135,    /* 7E */
    0x7F,   113,    0x80,   115,    0x81,   114,
    /* 82 - 84 */
    0x85,   121,    0x86,   117,    0x87,   85,    0x88,   89,
    0x89,   90,     0x8A,   91,     0x8B,   92,    0x8C,   93,
    0x8D,   94,     0x8E,   122,    0x8F,   123,   0x90,   124,
    /* 91 - B5 */
    0xB6,   179,    0xB7,   180,
    /* B8 - D6 */
    0xD7,   118,    0xE0,   29,     0xE1,   42,    0xE2,   56,
    0xE3,   125,    0xE4,   97,     0xE5,   54,    0xE6,   100,
    0xE7,   126,
     /*terminator*/
    0,     0
};

const WCHAR ManufacturerID[] = L"5853";
const WCHAR ProductID[] = L"8000";
const WCHAR SerialNo[] = L"000001";

const HID_STRING CitrixHidStrings[] = {
    { HID_STRING_ID_IMANUFACTURER, (UCHAR) sizeof(ManufacturerID), (PUCHAR) ManufacturerID },
    { HID_STRING_ID_IPRODUCT, (UCHAR) sizeof(ProductID), (PUCHAR) ProductID },
    { HID_STRING_ID_ISERIALNUMBER, (UCHAR) sizeof(SerialNo), (PUCHAR) SerialNo },
    { 0, 0, NULL }
};
