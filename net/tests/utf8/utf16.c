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

#include <assert.h>
#include <err.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

typedef unsigned NTSTATUS;
typedef unsigned long ULONG;

#define STATUS_SUCCESS 0
#define STATUS_DATA_ERROR 1

typedef unsigned short WCHAR;
typedef WCHAR *PWCHAR;

#define XM_ASSERT assert
#define NT_SUCCESS(x) ((x) == STATUS_SUCCESS)

#define XmAllocateMemory malloc

static void
XmBugCheck(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    verrx(1, fmt, args);
}

#include "../../utf8.c"

static unsigned
wchar_strlen(PWCHAR s)
{
    unsigned x;
    for (x = 0; s[x]; x++)
        ;
    return x;
}

int
main()
{
    unsigned l;
    WCHAR *res;
    unsigned char buf[4096];
    unsigned size;

    size = read(0, buf, sizeof(buf));
    buf[size] = 0;
    res = utf8_to_utf16(buf);
    l = wchar_strlen(res);
    fwrite(res, l, sizeof(WCHAR), stdout);
    return 0;
}
