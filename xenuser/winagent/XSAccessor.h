/*
 * Copyright (c) 2006 XenSource, Inc. All use and distribution of this 
 * copyrighted material is governed by and subject to terms and 
 * conditions as licensed by XenSource, Inc. All other rights reserved. 
 */

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


#ifndef _XSACCESSOR_H
#define _XSACCESSOR_H

#include <string>

#include "vm_stats.h"

using namespace std;

#define MAX_XENBUS_PATH 256

#ifdef AMD64
typedef long long ssize_t;
#else
typedef long ssize_t;
#endif

void InitXSAccessor();
void ShutdownXSAccessor();
int XenstoreList(const char *path, char ***entries, unsigned *numEntries);
ssize_t XenstoreRead(const char *path, char **value);
int XenstoreRemove(const char *path);
int XenstorePrintf(const char *path, const char *fmt, ...);
int XenstoreWrite(const char *path, const void *data, size_t len);
void XenstoreKickXapi(void);
void XenstoreDoDump(VMData *data);
int XenstoreDoNicDump(uint32_t num_vif, VIFData *vif);
struct xs2_watch *XenstoreWatch(const char *path, HANDLE event);
void XenstoreUnwatch(struct xs2_watch *watch);
int ListenSuspend(HANDLE event);
void GetXenTime(FILETIME *res);
void XsLog(const char *fmt, ...);

#endif
