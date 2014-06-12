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
#pragma warning(push,3)
#include <winioctl.h>
#pragma warning(pop)
#include <stdio.h>
#include <stdlib.h>
#include "xs_ioctl.h"

int __cdecl main()
{
    HANDLE h;
    int buf_size;
    char *buf;
    DWORD t;
    unsigned s;

    h = CreateFile("\\\\.\\XenBus", GENERIC_READ | GENERIC_WRITE,
                   0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "error openning xenbus device\n");
        return 1;
    }

    while (1) {
        if (!DeviceIoControl(h, IOCTL_XS_GET_LOG_SIZE, NULL,
                             0, &buf_size, sizeof(buf_size), &t, NULL)) {
            printf("Error %d getting buffer size.\n", GetLastError());
            return 1;
        }
        buf = malloc(buf_size);
        if (!buf) {
            printf("Cannot allocate %d byte buffer!\n", buf_size);
            return 1;
        }
        if (DeviceIoControl(h, IOCTL_XS_GET_LOG, NULL, 0,
                            buf, buf_size, &t, NULL)) {
            while (buf_size > 0) {
                s = (unsigned)strnlen(buf, buf_size);
                fwrite(buf, s, 1, stdout);
                buf_size -= s + 1;
                buf += s + 1;
            }
            return 0;
        }
        free(buf);
    }
}
