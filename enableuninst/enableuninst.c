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

#include <windows.h>
#include <cfgmgr32.h>
#include <winioctl.h>
#include <stdio.h>

#include "xs_ioctl.h"

int __cdecl main(int argc, char *argv[])
{
    HANDLE h;
    DEVINST root;
    int ret;
    HANDLE token;
    TOKEN_PRIVILEGES tkp;
    DWORD err;
    DWORD tmp;

    h = CreateFile("\\\\.\\XenBus", GENERIC_READ | GENERIC_WRITE, 0,
                   NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        /* Conclude we were booted in ioemu mode, for which this is
           trivial.x*/
        printf("Failed to open device.\n");
        return 0;
    }

    if (!DeviceIoControl(h, IOCTL_XS_ENABLE_UNINST, NULL, 0, NULL, 0, &tmp,
                         NULL))
        printf("DeviceIoControl failed.\n");

    return 0;
}
