//
// xenbus.h - Exports and prototypes for access to the xen bus.
//
// Copyright (c) 2006 XenSource Inc. - All rights reserved.
//

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

#ifndef _XENBUS_H_
#define _XENBUS_H_

#define MAX_XENBUS_PATH 256

#include "xsapi.h"

NTSTATUS
XenevtchnInitXenbus(
    VOID
);

VOID
CleanupXenbus(
    VOID
);

NTSTATUS xenbus_remove(xenbus_transaction_t xbt, const char *path);
void xenbus_recover_from_s3(void);

extern EVTCHN_PORT
xenbus_evtchn;

void xenbus_fail_transaction(xenbus_transaction_t xbt, NTSTATUS status);

#endif

