/*
 * Copyright (c) 2010 Citrix Systems, Inc.
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

#if !defined(_V4V_IOCTL_H_)
#define _V4V_IOCTL_H_

#define V4VD_DRIVER_NAME    L"v4vdrv"
#define V4VD_DEVICE_NAME    L"\\Device\\v4vdrv"
#define V4VD_SYMBOLIC_NAME  L"\\DosDevices\\Global\\v4vdrv"
#define V4VD_DOS_NAME       L"\\\\.\\v4vdrv"
#define V4VD_FILE_NAME      L"v4vdrv"

#define V4VD_SYS_FILENAME   L"%SystemRoot%\\system32\\drivers\\v4vdrv.sys"

#define V4VD_MAX_NAME_STRING     64
#define V4VD_MAX_IOCTL_STRING   512

typedef struct _V4VD_IOCD_START_DRIVER_TEST {
    USHORT partnerDomain;
} V4VD_IOCD_START_DRIVER_TEST, *PV4VD_IOCD_START_DRIVER_TEST;

/* V4V I/O Control Function Codes */
#define V4VD_START_DRIVER_TEST    0x10
#define V4VD_STOP_DRIVER_TEST     0x11

/* V4V I/O Control Codes */
#define V4VD_IOCTL_START_DRIVER_TEST CTL_CODE(FILE_DEVICE_UNKNOWN, V4VD_START_DRIVER_TEST, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define V4VD_IOCTL_STOP_DRIVER_TEST  CTL_CODE(FILE_DEVICE_UNKNOWN, V4VD_STOP_DRIVER_TEST, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif /*_V4V_IOCTL_H_*/
