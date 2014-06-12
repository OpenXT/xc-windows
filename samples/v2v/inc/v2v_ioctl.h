/*
 * Copyright (c) 2009 Citrix Systems, Inc.
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

#if !defined(_V2V_IOCTL_H_)
#define _V2V_IOCTL_H_

#define V2V_DRIVER_NAME    L"v2vdrv"
#define V2V_DEVICE_NAME    L"\\Device\\v2vdrv"
#define V2V_SYMBOLIC_NAME  L"\\DosDevices\\Global\\v2vdrv"
#define V2V_DOS_NAME       L"\\\\.\\v2vdrv"

#define V2V_CONNECTOR_INTERNAL_NAME L"v2vdrv\\connector\\internal"
#define V2V_CONNECTOR_FILE_NAME     L"v2vdrv\\connector\\file"
#define V2V_LISTENER_INTERNAL_NAME  L"v2vdrv\\listener\\internal"
#define V2V_LISTENER_FILE_NAME      L"v2vdrv\\listener\\file"

#define V2V_SYS_FILENAME      L"%SystemRoot%\\system32\\drivers\\v2vdrv.sys"

#define V2V_MAX_NAME_STRING     64
#define V2V_MAX_IOCTL_STRING   512

#define V2V_KERNEL_ASYNC       0x1
#define V2V_KERNEL_FASTRX      0x2

typedef struct _V2VK_IOCD_INIT_INTERNAL_XFER {
    char localPrefix[V2V_MAX_IOCTL_STRING];
    ULONG flags;
    ULONG xferTimeout;
    ULONG xferSize;    
    ULONG xferCount;
    ULONG xferMaxFastRx;
} V2VK_IOCD_INIT_INTERNAL_XFER, *PV2VK_IOCD_INIT_INTERNAL_XFER;

typedef struct _V2VK_IOCD_INIT_FILE_XFER {
    char localPrefix[V2V_MAX_IOCTL_STRING];
    char filePath[V2V_MAX_IOCTL_STRING];
    ULONG flags;
    ULONG xferTimeout;
    ULONG xferSize;
    ULONG xferMaxFastRx;
} V2VK_IOCD_INIT_FILE_XFER, *PV2VK_IOCD_INIT_FILE_XFER;

#if defined(_WIN64)
#define CLIENT_64BIT 0x800
#else
#define CLIENT_64BIT 0x000
#endif

// V2V I/O Control Function Codes
#define V2VK_FUNC_INIT_INTERNAL_XFER    0x10
#define V2VK_FUNC_INIT_FILE_XFER        0x11
#define V2VK_FUNC_RUN_CONNECTOR         0x12
#define V2VK_FUNC_RUN_LISTENER          0x13

// V2V I/O Control Codes
#define V2VK_IOCTL_INIT_INTERNAL_XFER CTL_CODE(FILE_DEVICE_UNKNOWN, V2VK_FUNC_INIT_INTERNAL_XFER, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define V2VK_IOCTL_INIT_FILE_XFER     CTL_CODE(FILE_DEVICE_UNKNOWN, V2VK_FUNC_INIT_FILE_XFER, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define V2VK_IOCTL_RUN_CONNECTOR      CTL_CODE(FILE_DEVICE_UNKNOWN, V2VK_FUNC_RUN_CONNECTOR, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define V2VK_IOCTL_RUN_LISTENER       CTL_CODE(FILE_DEVICE_UNKNOWN, V2VK_FUNC_RUN_LISTENER, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif /*_V2V_IOCTL_H_*/
