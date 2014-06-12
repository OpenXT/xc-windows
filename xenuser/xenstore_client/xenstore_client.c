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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "xs.h"

static HANDLE
xs_handle;

static void
usage(void)
{
    printf(
"xenstore_client -- access xenstore from the command line\n"
"\n"
"Usage:\n"
"    xenstore_client read {path}         Read {path} and print contents\n"
"    xenstore_client write {path} {data} Set {path} to {data}\n"
"    xenstore_client dir {path}          List subkeys of {path}\n"
"    xenstore_client remove {path}       Remove key {path}\n");
    exit(1);
}

static void
win_err(int code, const char *fmt, ...)
{
    va_list args;
    DWORD err;
    LPVOID lpMsgBuf;

    err = GetLastError();
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0,
        NULL);

    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf(": %s\n", lpMsgBuf);

    exit(code);
}

static void
do_read(int argc, char *argv[])
{
    size_t len;
    void *contents;

    if (argc != 3)
        usage();
    contents = xs_read(xs_handle, argv[2], &len);
    if (!contents)
        win_err(1, "reading %s", argv[2]);
    fwrite(contents, len, 1, stdout);
    exit(0);
}

static void
do_write(int argc, char *argv[])
{
    if (argc != 4)
        usage();
    if (!xs_write(xs_handle, argv[2], argv[3]))
        win_err(1, "writing to %s", argv[2]);
    exit(0);
}

static void
do_dir(int argc, char *argv[])
{
    char **contents;
    unsigned count;
    unsigned x;

    if (argc != 3)
        usage();
    contents = xs_directory(xs_handle, argv[2], &count);
    if (!contents)
        win_err(1, "listing %s", argv[2]);
    for (x = 0; x < count; x++)
        printf("%s\n", contents[x]);
    exit(0);
}

static void
do_remove(int argc, char *argv[])
{
    if (argc != 3)
        usage();
    if (!xs_remove(xs_handle, argv[2]))
        win_err(1, "removing %s", argv[2]);
    exit(0);
}

int
main(int argc, char *argv[])
{
    if (argc < 2)
        usage();
    xs_handle = xs_domain_open();
    if (xs_handle == NULL)
        win_err(1, "cannot open xenstore interface");
    if (!strcmp(argv[1], "read"))
        do_read(argc, argv);
    if (!strcmp(argv[1], "write"))
        do_write(argc, argv);
    if (!strcmp(argv[1], "dir"))
        do_dir(argc, argv);
    if (!strcmp(argv[1], "remove"))
        do_remove(argc, argv);
    usage();
}
