//
// pnp.h - General support declarations for plug and play functions.
//
// Copyright (c) 2006 XenSource, Inc. - All rights reserved.
//

/*
 * Copyright (c) 2007 Citrix Systems, Inc.
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

#ifndef _PNP_H_
#define _PNP_H_

//
// PnP handler function prototypes.
//
NTSTATUS
DefaultPnpHandler(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
);

NTSTATUS
IgnoreRequest(
    PDEVICE_OBJECT pdo,
    PIRP Irp
);

typedef
NTSTATUS
(*PEVTCHN_PNP_HANDLER)(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
);

//
// PnP function vector table
//
#define XENEVT_MAX_PNP_FN   24
typedef struct  {
    PEVTCHN_PNP_HANDLER fdoHandler;
    PEVTCHN_PNP_HANDLER pdoHandler;
    PCHAR name;
} PNP_INFO, *PPNP_INFO;

extern PNP_INFO pnpInfo[];

DEFINE_GUID(GUID_XENBUS_BUS_TYPE, 0x8a1b2f56, 0x5023, 0x473e, 0x8e,
        0x06, 0x56, 0x74, 0x2f, 0xb0, 0x20, 0x28);

#endif // _PNP_H_
