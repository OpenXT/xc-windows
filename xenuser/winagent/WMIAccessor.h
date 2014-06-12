/*
 * Copyright (c) 2006 XenSource, Inc. All use and distribution of this 
 * copyrighted material is governed by and subject to terms and 
 * conditions as licensed by XenSource, Inc. All other rights reserved. 
 */

/*
 * Copyright (c) 2008 Citrix Systems, Inc.
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

#ifndef _WMIACCESSOR_H
#define _WMIACCESSOR_H

#include <Wbemidl.h>
#include <list>
#include <vector>
#include <map>
#include <string>

#include "vm_stats.h"
#include "XSAccessor.h"

using namespace std;

typedef unsigned __int64 uint64_t;

struct WMIAccessor;

struct WMIAccessor *ConnectToWMI(void);
void ReleaseWMIAccessor(struct WMIAccessor *);

void GetWMIData(WMIAccessor *wmi, VMData& data);
void DumpOSData(WMIAccessor *wmi);

VOID AddHotFixInfoToStore(WMIAccessor* wmi);
void UpdateProcessListInStore(WMIAccessor *wmi);

#endif
