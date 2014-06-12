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

#include <windows.h>
#include <stdio.h>
#include <malloc.h>

int
main(int argc, char *argv[])
{
    void *buffer;
    HANDLE h;
    DWORD start, end;
    unsigned x;
    DWORD count;

    UNREFERENCED_PARAMETER(argc);

    buffer = _aligned_offset_malloc(4096, 4096, 4096-20);
//    buffer = _aligned_malloc(65536, 65536-20);

    printf("buffer at %p.\n", buffer);

    h = CreateFile(argv[1],
                   GENERIC_WRITE,
                   0,
                   NULL,
                   CREATE_NEW,
                   FILE_ATTRIBUTE_NORMAL|FILE_FLAG_NO_BUFFERING|FILE_FLAG_WRITE_THROUGH,
                   NULL);
    if (!h) {
        printf("Failed to open\n");
        return 1;
    }

    start = GetTickCount();
    for (x = 0; x < 100000; x++) {
        if (!WriteFile(h, buffer, 512, &count, NULL)) {
            printf("Error writing.\n");
            return 1;
        }
        FlushFileBuffers(h);
    }
    end = GetTickCount();

    printf("%d ticks -> %e seconds per operation.\n", end - start,
           (double)(end - start) / (1000.0 * 10000) );

    CloseHandle(h);

    DeleteFile(argv[1]);

    return 0;
}
