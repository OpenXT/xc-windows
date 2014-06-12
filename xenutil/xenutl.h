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

#include <ntddk.h>
#include <stdarg.h>
#include <ntstrsafe.h>
#include "xsapi.h"
#include "scsiboot.h"
#include "verinfo.h"

#ifndef _XENUTL_H
#define _XENUTL_H

#define XUTIL_TAG 'LUTX'

extern VOID *dom0_debug_port;

typedef ULONG (*DBG_PRINT)(
    IN CHAR *,
    ...
    );

typedef ULONG (*VDBG_PRINT_EX)(
    IN ULONG,
    IN ULONG,
    IN const CHAR *,
    IN va_list
    );

extern VDBG_PRINT_EX __XenvDbgPrintEx;

extern ULONG
__XenDbgPrint(
    IN CHAR *Format,
    ...
    );

extern DBG_PRINT XenDbgPrint;

typedef VOID (*WPP_TRACE)(
    IN XEN_TRACE_LEVEL Level,
    IN CHAR *Message
    );

extern VOID SetWppTrace(
    IN WPP_TRACE Function
    );

extern PVOID
XenWorkItemInit(
    VOID
    );

extern ULONG SuspendGetCount(void);

extern BOOLEAN XenPVEnabled(VOID);

extern void InitOldUnplugProtocol(PHYSICAL_ADDRESS ioportbase, ULONG nports);

#endif  // _XENUTL_H

