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

#include <windows.h>
#pragma warning (push, 3)
#include <winioctl.h>
#pragma warning (pop)
#include <stdio.h>

#include "xs_ioctl.h"

static const char *
bool_to_string(BOOLEAN b)
{
    if (b)
        return "TRUE";
    else
        return "FALSE";
}

int __cdecl
main(int argc, char *argv[])
{
    HANDLE h;
    DWORD tmp;
    XS_QUERY_BALLOON res;
    BOOLEAN verbose;

    verbose = FALSE;
    if (argc > 1) {
        if (argc == 2 && !strcmp(argv[1], "-v")) {
            verbose = TRUE;
        } else {
            printf("Only valid argument is -v\n");
            return 1;
        }
    }
    h = CreateFile("\\\\.\\XenBus", GENERIC_READ | GENERIC_WRITE, 0,
                   NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("Failed to open Xen event channel device (%x).\n",
               GetLastError());
        return 1;
    }

    if (!DeviceIoControl(h, IOCTL_XS_QUERY_BALLOON, NULL, 0, &res,
                         sizeof(res), &tmp, NULL)) {
        printf("Failed to query balloon statistics (%x).\n", GetLastError());
        return 1;
    }

    printf("Max memory:     %dKB\n", res.max_pages * 4);
    printf("Current memory: %dKB\n", res.current_pages * 4);
    printf("Target memory:  %dKB\n", res.target_pages * 4);
    printf("Failed allocs:  %d\n", res.allocations_failed);
    printf("Partial allocs: %d\n", res.partial_allocations);
    printf("2MB allocs:     %d\n", res.two_mb_allocations);
    if (verbose) {
        printf("Running:        %s\n", bool_to_string(res.running));
        printf("Shutdown:       %s\n", bool_to_string(res.shutdown_requested));
        printf("Timer fired:    %s\n", bool_to_string(res.timer_fired));
        printf("Timer running:  %s\n", bool_to_string(res.timer_inserted));
        printf("Watch fired:    %s\n", bool_to_string(res.watch_fired));
    }

    return 0;
}
