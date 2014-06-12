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
#include <stdio.h>
#include <stdlib.h>
#include <xenops.h>
#include <xs_private.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static struct xenops_handle *
xenops;

static void *
allocate_page(void)
{
    void *buf;

    buf = malloc(PAGE_SIZE * 2);
    return (void *)( ((ULONG_PTR)buf + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
}

static void
dump_page(const void *_page)
{
    const unsigned *const page = _page;
    unsigned x;

    for (x = 0; x < PAGE_SIZE / 4; x += 8) {
        printf("%3x %08x %08x %08x %08x %08x %08x %08x %08x\n",
               x,
               page[x],
               page[x+1],
               page[x+2],
               page[x+3],
               page[x+4],
               page[x+5],
               page[x+6],
               page[x+7]);
    }
}

static int
test_xenops_close(int argc, char *argv[])
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    xenops_close(xenops);
    return 0;
}

static int
test_offer_const(int argc, char *argv[])
{
    DOMAIN_ID domid;
    unsigned delay;
    GRANT_REF gref;
    void *buffer;
    unsigned x;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));
    delay = atoi(argv[1]);

    buffer = allocate_page();
    memset(buffer, 0x73, PAGE_SIZE);
    printf("buffer at %p\n", buffer);
    if (!xenops_grant_readonly(xenops, domid, buffer, &gref))
        xs_win_err(1, &xs_render_error_stderr,
                   "performing grant operation");
    printf("grant with reference %d\n", xen_GRANT_REF(gref));
    if (delay == 0) {
        while (1)
            Sleep(INFINITE);
    } else {
        Sleep(delay * 1000);
        if (!xenops_ungrant(xenops, gref))
            xs_win_err(1, &xs_render_error_stderr,
                       "revoking grant after %d seconds", delay);
        xenops_close(xenops);

        for (x = 0; x < PAGE_SIZE; x++) {
            if ( ((unsigned char *)buffer)[x] != 0x73 )
                xs_errx(1, &xs_render_error_stderr,
                        "granted page was corrupted: %x changed to %x at %x\n",
                        0x73, ((unsigned char *)buffer)[x], x);
        }
        return 0;
    }
}

static int
test_offer_write(int argc, char *argv[])
{
    DOMAIN_ID domid;
    unsigned delay;
    GRANT_REF gref;
    void *buffer;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));
    delay = atoi(argv[1]);

    buffer = allocate_page();
    memset(buffer, 0, PAGE_SIZE);
    printf("buffer at %p\n", buffer);
    if (!xenops_grant_readwrite(xenops, domid, buffer, &gref))
        xs_win_err(1, &xs_render_error_stderr,
                   "performing grant operation");
    printf("grant with reference %d\n", xen_GRANT_REF(gref));
    if (delay == 0) {
        while (1)
            Sleep(INFINITE);
    } else {
        Sleep(delay * 1000);
        if (!xenops_ungrant(xenops, gref))
            xs_win_err(1, &xs_render_error_stderr,
                       "revoking grant after %d seconds", delay);
    }
    dump_page(buffer);

    return 0;
}

static void *
atop(const char *a)
{
#ifdef AMD64
    return (void *)_atoi64(a);
#else
    return (void *)atoi(a);
#endif
}

static int
test_offer_address(int argc, char *argv[])
{
    DOMAIN_ID domid;
    GRANT_REF gref;
    void * address;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));
    address = atop(argv[1]);
    if (!xenops_grant_readonly(xenops, domid, address, &gref))
        xs_win_err(1, &xs_render_error_stderr,
                   "performing grant operation");
    return 0;
}

static int
test_offer_unbacked(int argc, char *argv[])
{
    void *address;
    GRANT_REF gref;
    DOMAIN_ID domid;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));

    address = VirtualAlloc(NULL, PAGE_SIZE, MEM_RESERVE,
                           PAGE_EXECUTE_READWRITE);
    printf("Unbacked VA at %p\n", address);
    if (!xenops_grant_readonly(xenops, domid, address, &gref))
        xs_win_err(1, &xs_render_error_stderr,
                   "performing grant operation");
    return 0;
}

static int
test_offer_writable_ro(int argc, char *argv[])
{
    void *address;
    GRANT_REF gref;
    DOMAIN_ID domid;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));

    address = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT,
                           PAGE_READONLY);
    printf("readonly VA at %p\n", address);
    if (!xenops_grant_readwrite(xenops, domid, address, &gref))
        xs_win_err(1, &xs_render_error_stderr,
                   "performing grant operation");
    printf("Granted with gref %d\n", xen_GRANT_REF(gref));
    return 0;
}

static int
test_offer_mmap(int argc, char *argv[])
{
    char *fname;
    unsigned delay;
    DOMAIN_ID domid;
    BOOL readonly;
    HANDLE file;
    HANDLE mapping;
    void *view;
    GRANT_REF gref;

    domid = wrap_DOMAIN_ID(atoi(argv[0]));
    fname = argv[1];
    delay = atoi(argv[2]);
    readonly = FALSE;
    if (argc > 3) {
        if (argc == 4 && !strcmp(argv[3], "/r"))
            readonly = TRUE;
        else
            xs_errx(1, &xs_render_error_stderr, "too many arguments");
    }

    file = CreateFile(fname, GENERIC_READ | (readonly ? 0 : GENERIC_WRITE),
                      0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                      NULL);
    if (file == INVALID_HANDLE_VALUE)
        xs_win_err(1, &xs_render_error_stderr,
                   "opening %s", fname);
    mapping = CreateFileMapping(file, NULL,
                                readonly ? PAGE_READONLY : PAGE_READWRITE,
                                0, PAGE_SIZE, NULL);
    if (!mapping)
        xs_win_err(1, &xs_render_error_stderr,
                   "creating mapping of %s", fname);
    view = MapViewOfFile(mapping,
                         readonly ? FILE_MAP_READ : FILE_MAP_WRITE,
                         0, 0, PAGE_SIZE);
    if (!view)
        xs_win_err(1, &xs_render_error_stderr,
                   "mapping %s", fname);
    printf("%s mapped at %p\n", fname, view);

    if (!(readonly ? xenops_grant_readonly
                   : xenops_grant_readwrite)(xenops, domid, view, &gref))
        xs_win_err(1, &xs_render_error_stderr,
                   "performing grant operation");

    printf("Grant reference %d\n", xen_GRANT_REF(gref));

    if (delay == 0) {
        while (1)
            Sleep(INFINITE);
    }

    Sleep(delay * 1000);
    if (!xenops_ungrant(xenops, gref))
        xs_win_err(1, &xs_render_error_stderr,
                   "revoking grant after %d seconds", delay);

    if (!UnmapViewOfFile(view))
        xs_win_err(1, &xs_render_error_stderr, "unmapping view of file");
    CloseHandle(mapping);
    CloseHandle(file);

    xenops_close(xenops);
    return 0;
}

static int
test_offer_dup_exit(int argc, char *argv[])
{
    DOMAIN_ID domid;
    GRANT_REF gref;
    void *buffer;
    STARTUPINFO startInfo;
    PROCESS_INFORMATION processInfo;
    HANDLE xenopsHandle;
    HANDLE xenopsTargetHandle;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));
    buffer = allocate_page();

    printf("buffer at %p\n", buffer);
    if (!xenops_grant_readonly(xenops, domid, buffer, &gref))
        xs_win_err(1, &xs_render_error_stderr,
                   "performing grant operation");
    printf("grant with reference %d\n", xen_GRANT_REF(gref));
    memset(&startInfo, 0, sizeof(startInfo));
    startInfo.cb = sizeof(startInfo);
    
    if (!CreateProcessA("xenops_test.exe",
                        "xenops_test.exe /offer_dup_child",
                        NULL,
                        NULL,
                        FALSE,
                        0,
                        NULL,
                        NULL,
                        &startInfo,
                        &processInfo))
        xs_win_err(1, &xs_render_error_stderr, "starting child process");
    CloseHandle(processInfo.hThread);

    xenopsHandle = *((HANDLE *)xenops);
    printf("xenops handle %p\n", xenopsHandle);
    if (!DuplicateHandle(GetCurrentProcess(),
                         xenopsHandle,
                         processInfo.hProcess,
                         &xenopsTargetHandle,
                         0,
                         FALSE,
                         DUPLICATE_SAME_ACCESS))
        xs_win_err(1, &xs_render_error_stderr, "transfering handle");

    printf("Duplicated to %p\n", xenopsTargetHandle);

    Sleep(1000);

    printf("Parent exiting.\n");

    return 0;
}

static int
test_map_dup_exit(int argc, char *argv[])
{
    DOMAIN_ID domid;
    ALIEN_GRANT_REF gref;
    STARTUPINFO startInfo;
    PROCESS_INFORMATION processInfo;
    HANDLE xenopsTargetHandle;
    HANDLE xenopsHandle;
    GRANT_MAP_HANDLE handle;
    void *map;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));
    gref = wrap_ALIEN_GRANT_REF(atoi(argv[1]));

    if (!xenops_grant_map_readonly(xenops,
                                   domid,
                                   1,
                                   &gref,
                                   &handle,
                                   &map))
        xs_win_err(1, &xs_render_error_stderr,
                   "mapping %d::%d readonly", unwrap_DOMAIN_ID(domid), gref);
    printf("Mapped to %p\n", map);

    memset(&startInfo, 0, sizeof(startInfo));
    startInfo.cb = sizeof(startInfo);
    if (!CreateProcessA("xenops_test.exe",
                        "xenops_test.exe /offer_dup_child",
                        NULL,
                        NULL,
                        FALSE,
                        0,
                        NULL,
                        NULL,
                        &startInfo,
                        &processInfo))
        xs_win_err(1, &xs_render_error_stderr, "starting child process");
    CloseHandle(processInfo.hThread);

    xenopsHandle = *((HANDLE *)xenops);
    printf("xenops handle %p\n", xenopsHandle);
    if (!DuplicateHandle(GetCurrentProcess(),
                         xenopsHandle,
                         processInfo.hProcess,
                         &xenopsTargetHandle,
                         0,
                         FALSE,
                         DUPLICATE_SAME_ACCESS))
        xs_win_err(1, &xs_render_error_stderr, "transfering handle");

    printf("Duplicated to %p\n", xenopsTargetHandle);

    Sleep(1000);

    printf("Parent exiting.\n");

    return 0;
}

static void
offer_dup_child(void)
{
    printf("I am the child.\n");

    Sleep(5000);
    printf("Exiting now.\n");
}

static int
test_offer_free(int argc, char *argv[])
{
    DOMAIN_ID domid;
    GRANT_REF gref;
    void *buffer;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));

    buffer = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
    if (!buffer)
        xs_win_err(1, &xs_render_error_stderr, "allocating test buffer");
    memset(buffer, 0xaa, PAGE_SIZE);

    printf("buffer at %p\n", buffer);
    if (!xenops_grant_readonly(xenops, domid, buffer, &gref))
        xs_win_err(1, &xs_render_error_stderr,
                   "performing grant operation");
    printf("grant with reference %d\n", xen_GRANT_REF(gref));

    if (!VirtualFree(buffer, 0, MEM_RELEASE))
        xs_win_err(1, &xs_render_error_stderr,
                   "releasing buffer");

    /* Hang around forever */
    while (1)
        Sleep(INFINITE);
}

static int
test_map_dump(int argc, char *argv[])
{
    DOMAIN_ID domid;
    void *map;
    GRANT_MAP_HANDLE handle;
    ALIEN_GRANT_REF gref;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));
    gref = wrap_ALIEN_GRANT_REF(atoi(argv[1]));

    if (!xenops_grant_map_readonly(xenops,
                                   domid,
                                   1,
                                   &gref,
                                   &handle,
                                   &map))
        xs_win_err(1, &xs_render_error_stderr,
                   "mapping %d::%d readonly", unwrap_DOMAIN_ID(domid), gref);
    printf("Mapped to %p\n", map);

    dump_page(map);

    xenops_unmap_grant(xenops, handle);

    return 0;

}

static int
test_map_write(int argc, char *argv[])
{
    DOMAIN_ID domid;
    ALIEN_GRANT_REF gref;
    void *map;
    GRANT_MAP_HANDLE handle;
    unsigned x;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));
    gref = wrap_ALIEN_GRANT_REF(atoi(argv[1]));

    if (!xenops_grant_map_readwrite(xenops,
                                    domid,
                                    1,
                                    &gref,
                                    &handle,
                                    &map))
        xs_win_err(1, &xs_render_error_stderr,
                   "mapping %d::%d readwrite",
                   unwrap_DOMAIN_ID(domid),
                   unwrap_ALIEN_GRANT_REF(gref));
    printf("Mapped to %p\n", map);

    for (x = 0; x < PAGE_SIZE / 4; x ++)
        ((unsigned *)map)[x] += x + 5;

    xenops_unmap_grant(xenops, handle);

    return 0;

}
static int
test_map_write_readonly(int argc, char *argv[])
{
    DOMAIN_ID domid;
    ALIEN_GRANT_REF gref;
    void *map;
    GRANT_MAP_HANDLE handle;
    unsigned x;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));
    gref = wrap_ALIEN_GRANT_REF(atoi(argv[1]));

    if (!xenops_grant_map_readonly(xenops,
                                   domid,
                                   1,
                                   &gref,
                                   &handle,
                                   &map))
        xs_win_err(1, &xs_render_error_stderr,
                   "mapping %d::%d readonly",
                   unwrap_DOMAIN_ID(domid),
                   unwrap_ALIEN_GRANT_REF(gref));
    printf("Mapped to %p\n", map);

    for (x = 0; x < PAGE_SIZE; x ++)
        ((unsigned char *)map)[x] = (unsigned char)(x + 5);

    printf("Completed write phase.\n");

    dump_page(map);

    xenops_unmap_grant(xenops, handle);

    printf("Performed unmap.\n");

    return 0;
}

static int
test_map_read_after_unmap(int argc, char *argv[])
{
    DWORD code;
    DOMAIN_ID domid;
    ALIEN_GRANT_REF gref;
    void *map;
    GRANT_MAP_HANDLE handle;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));
    gref = wrap_ALIEN_GRANT_REF(atoi(argv[1]));

    if (!xenops_grant_map_readonly(xenops,
                                   domid,
                                   1,
                                   &gref,
                                   &handle,
                                   &map))
        xs_win_err(1, &xs_render_error_stderr,
                   "mapping %d::%d readonly",
                   unwrap_DOMAIN_ID(domid),
                   unwrap_ALIEN_GRANT_REF(gref));
    xenops_unmap_grant(xenops, handle);

    code = 0xf001dead;
    __try {
        dump_page(map);
    } __except (code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        printf("Exception %x reading from unmapped memory\n",
               code);
    }

    return 0;
}

static int
test_map_hold(int argc, char *argv[])
{
    BOOLEAN readonly;
    DOMAIN_ID domid;
    ALIEN_GRANT_REF gref;
    unsigned delay;
    GRANT_MAP_HANDLE handle;
    void *map;

    domid = wrap_DOMAIN_ID(atoi(argv[0]));
    gref = wrap_ALIEN_GRANT_REF(atoi(argv[1]));
    delay = atoi(argv[2]);

    readonly = FALSE;
    if (argc > 3) {
        if (argc == 4 && !strcmp(argv[3], "/r"))
            readonly = TRUE;
        else
            xs_errx(1, &xs_render_error_stderr, "too many arguments");
    }

    if (readonly) {
        if (!xenops_grant_map_readonly(xenops,
                                       domid,
                                       1,
                                       &gref,
                                       &handle,
                                       &map))
            xs_win_err(1, &xs_render_error_stderr,
                       "mapping %d::%d readonly",
                       unwrap_DOMAIN_ID(domid),
                       unwrap_ALIEN_GRANT_REF(gref));
    } else {
        if (!xenops_grant_map_readwrite(xenops,
                                        domid,
                                        1,
                                        &gref,
                                        &handle,
                                        &map))
            xs_win_err(1, &xs_render_error_stderr,
                       "mapping %d::%d readwrite",
                       unwrap_DOMAIN_ID(domid),
                       unwrap_ALIEN_GRANT_REF(gref));
    }
    if (delay) {
        Sleep(delay * 1000);
    } else {
        while (1)
            Sleep(INFINITE);
    }
    xenops_unmap_grant(xenops, handle);

    return 0;
}

static void
test_evtchn_listen_connect(DOMAIN_ID domid, unsigned delay,
                           ALIEN_EVTCHN_PORT remote_port)
{
    EVTCHN_PORT port;
    HANDLE event;
    DWORD start;
    DWORD now;
    DWORD res;

    event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!event)
        xs_win_err(1, &xs_render_error_stderr, "creating Windows event");

    if (is_null_ALIEN_EVTCHN_PORT(remote_port)) {
        if (!xenops_evtchn_listen(xenops, domid, event, &port))
            xs_win_err(1, &xs_render_error_stderr, "xenops_evtchn_listen()");
    } else {
        if (!xenops_evtchn_connect(xenops, domid, remote_port, event,
                                   &port))
            xs_win_err(1, &xs_render_error_stderr, "xenops_evtchn_connect()");
    }

    printf("evtchn port %d\n", unwrap_EVTCHN_PORT(port));

    start = GetTickCount();
    while (1) {
        if (delay != 0) {
            now = GetTickCount();
            if (now - start >= delay * 1000)
                break;
            res = WaitForSingleObject(event,
                                      delay * 1000 - now + start);
            if (res == WAIT_TIMEOUT)
                break;
        } else {
            res = WaitForSingleObject(event, INFINITE);
        }
        if (res == WAIT_OBJECT_0) {
            printf("notified\n");
        } else {
            SetLastError(res);
            xs_win_err(1, &xs_render_error_stderr, "waiting for event");
        }
    }
    xenops_evtchn_close(xenops, port);
}

static int
test_evtchn_listen(int argc, char *argv[])
{
    DOMAIN_ID domid;
    unsigned delay;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));
    delay = atoi(argv[1]);

    test_evtchn_listen_connect(domid, delay, null_ALIEN_EVTCHN_PORT());
    return 0;
}

static int
test_evtchn_connect(int argc, char *argv[])
{
    DOMAIN_ID domid;
    unsigned delay;
    ALIEN_EVTCHN_PORT port;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));
    port = wrap_ALIEN_EVTCHN_PORT(atoi(argv[1]));
    delay = atoi(argv[2]);

    if (is_null_ALIEN_EVTCHN_PORT(port))
        xs_errx(1, &xs_render_error_stderr, "attempt to connect to port 0?");

    test_evtchn_listen_connect(domid, delay, port);
    return 0;
}

static int
test_evtchn_listen_bad_event(int argc, char *argv[])
{
    DOMAIN_ID domid;
    EVTCHN_PORT port;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));

    if (!xenops_evtchn_listen(xenops, domid, (HANDLE)0xbad, &port))
        xs_win_err(1, &xs_render_error_stderr, "xenops_evtchn_listen()");

    xenops_evtchn_close(xenops, port);

    return 0;
}

static void
test_evtchn_listen_connect_kick(DOMAIN_ID domid, unsigned delay,
                                ALIEN_EVTCHN_PORT remote_port)
{
    HANDLE event;
    unsigned x;
    EVTCHN_PORT port;

    event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!event)
        xs_win_err(1, &xs_render_error_stderr, "creating Windows event");

    if (is_null_ALIEN_EVTCHN_PORT(remote_port)) {
        if (!xenops_evtchn_connect(xenops, domid, remote_port, event,
                                   &port))
            xs_win_err(1, &xs_render_error_stderr, "xenops_evtchn_connect()");
    } else {
        if (!xenops_evtchn_listen(xenops, domid, event, &port))
            xs_win_err(1, &xs_render_error_stderr, "xenops_evtchn_listen()");
    }

    x = 0;
    while (1) {
        printf("Kicking local port %d.\n", unwrap_EVTCHN_PORT(port));
        xenops_evtchn_notify(xenops, port);
        if (delay == 0 || x < delay) {
            Sleep(1000);
            x++;
        } else {
            break;
        }
    }
    xenops_evtchn_close(xenops, port);
}

static int
test_evtchn_listen_kick(int argc, char *argv[])
{
    DOMAIN_ID domid;
    unsigned delay;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));
    delay = atoi(argv[1]);

    test_evtchn_listen_connect_kick(domid, delay, null_ALIEN_EVTCHN_PORT());

    return 0;
}

static int
test_evtchn_connect_kick(int argc, char *argv[])
{
    ALIEN_EVTCHN_PORT remote_port;
    DOMAIN_ID domid;
    unsigned delay;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));
    remote_port = wrap_ALIEN_EVTCHN_PORT(atoi(argv[1]));
    delay = atoi(argv[2]);

    if (is_null_ALIEN_EVTCHN_PORT(remote_port))
        xs_errx(1, &xs_render_error_stderr, "attempt to connect to port 0?");

    test_evtchn_listen_connect_kick(domid, delay, remote_port);

    return 0;
}

static int
test_evtchn_offer_echo(int argc, char *argv[])
{
    HANDLE event;
    EVTCHN_PORT port;
    DOMAIN_ID domid;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));

    event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!event)
        xs_win_err(1, &xs_render_error_stderr, "creating Windows event");

    if (!xenops_evtchn_listen(xenops, domid, event, &port))
        xs_win_err(1, &xs_render_error_stderr, "xenops_evtchn_listen()");

    printf("listening on port %d\n", unwrap_EVTCHN_PORT(port));
    while (1) {
        WaitForSingleObject(event, INFINITE);
        xenops_evtchn_notify(xenops, port);
    }
}

static int
test_evtchn_connect_rtt(int argc, char *argv[])
{
    ALIEN_EVTCHN_PORT remote_port;
    DOMAIN_ID domid;
    HANDLE event;
    unsigned x;
    EVTCHN_PORT port;
    DWORD start;
    DWORD end;

    UNREFERENCED_PARAMETER(argc);

    domid = wrap_DOMAIN_ID(atoi(argv[0]));
    remote_port = wrap_ALIEN_EVTCHN_PORT(atoi(argv[1]));

    if (is_null_ALIEN_EVTCHN_PORT(remote_port))
        xs_errx(1, &xs_render_error_stderr, "attempt to connect to port 0?");

    event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!event)
        xs_win_err(1, &xs_render_error_stderr, "creating Windows event");

    if (!xenops_evtchn_connect(xenops, domid, remote_port, event,
                               &port))
        xs_win_err(1, &xs_render_error_stderr, "xenops_evtchn_connect()");

    /* Wait a bit to make sure the other end really is connected */
    Sleep(1000);
    printf("starting test\n");
#define NR_ITERATIONS 1000000
    start = GetTickCount();
    for (x = 0; x < NR_ITERATIONS; x++) {
        xenops_evtchn_notify(xenops, port);
        WaitForSingleObject(event, INFINITE);
    }
    end = GetTickCount();

    printf("Done test.  RTT %e\n",
           (double)(end - start) / (NR_ITERATIONS * 1000));

    xenops_evtchn_close(xenops, port);

    return 0;
}

struct test {
    const char *name;
    const char *help;
    int (*worker)(int argc, char *argv[]);
} tests[] = {
    { "xenops_close",
      "Simple open/close test.  No arguments\n",
      test_xenops_close },
    { "offer_const",
      "Offer a page containing a constant pattern, then revoke it after a delay.\n"
      "Arguments are {domid} {delay}\n"
      "Delay is in seconds.  A delay of zero waits forever.\n",
      test_offer_const },
    { "offer_write",
      "Offer a page containing zeroes, then revoke it after a delay.\n"
      "The grant is writable, and we dump the contents when the delay expires.\n"
      "Arguments are {domid} {delay}\n",
      test_offer_write },
    { "offer_address",
      "Try to grant read-only access to a particular address.\n"
      "Arguments {domid} {address}\n",
      test_offer_address },
    { "offer_unbacked",
      "Try to grant read-only access to unbacked memory.\n"
      "Arguments {domid}\n",
      test_offer_unbacked },
    { "offer_writable_ro",
      "Try to grant read-write access to read-only memory.\n"
      "Arguments {domid}\n",
      test_offer_writable_ro },
    { "offer_mmap",
      "Try to grant access to a memory-mapped file.\n"
      "Arguments {domid} {filename} {delay} </r>\n"
      "Writable unless /r specified",
      test_offer_mmap },
    { "offer_dup_exit",
      "Grant access to some memory, then duplicate the handle into another (newly\n"
      "created) process, and then make the original process exit.\n"
      "Arguments {domid}\n",
      test_offer_dup_exit },
    { "offer_free",
      "Grant access to some memory, and then try to release it back to Windows."
      "Arguments {domid}\n",
      test_offer_free },
    { "map_dump",
      "Map a remote grant reference read-only and dump the contents.\n"
      "Arguments {domid} {gref}\n",
      test_map_dump },
    { "map_write",
      "Map a remote grant reference and scribble all over it.\n"
      "Arguments {domid} {gref}\n",
      test_map_write },
    { "map_write_readonly",
      "Map a remote grant reference for reading and try to write through it.\n"
      "Arguments {domid} {gref}\n",
      test_map_write_readonly },
    { "map_read_after_unmap",
      "Map a remote grant reference for reading, then unmap, and then try to access the map again.\n"
      "Arguments {domid} {gref}\n",
      test_map_read_after_unmap },
    { "map_hold",
      "Map a remote grant reference and hold it for a delay.\n"
      "Arguments {domid} {gref} {delay} </r>\n"
      "Writable unless /r specified",
      test_map_hold },
    { "map_dup_exit",
      "Map a grant reference read-only, then duplicate the handle into another (newly\n"
      "created) process, and then make the original process exit.\n"
      "Arguments {domid} {gref}\n",
      test_map_dup_exit },
    { "evtchn_listen",
      "Allocate a listening event channel port, and then print a message whenever it \n"
      "gets notified.  Exit after a delay (or forever, if 0 specified)\n"
      "Arguments {domid} {delay}\n",
      test_evtchn_listen },
    { "evtchn_listen_bad_event",
      "Try to listen, but pass in a bad event channel port.\n"
      "Arguments {domid}\n",
      test_evtchn_listen_bad_event },
    { "evtchn_listen_kick",
      "Allocate a listening event channel port, and then loop notifying it once a\n"
      "Exit after a delay (or never, if 0 specified)\n"
      "Arguments {domid} {delay}\n",
      test_evtchn_listen_kick },
    { "evtchn_connect",
      "Connect to a remote event channel port, and then print a message whenever it\n"
      "gets notified.  Exit after a delay (or forever, if 0 specified)\n"
      "Arguments {domid} {port} {delay}\n",
      test_evtchn_connect },
    { "evtchn_connect_kick",
      "Connect to a remote event channel port, and then loop notifying it once a\n"
      "Exit after a delay (or never, if 0 specified)\n"
      "Arguments {domid} {port} {delay}\n",
      test_evtchn_connect_kick },
    { "evtchn_offer_echo",
      "Allocate a listening event channel, and then kick it whenever it receives an\n"
      "event.\n"
      "Arguments {domid}\n",
      test_evtchn_offer_echo },
    { "evtchn_connect_rtt",
      "Connect to an echo server and use it to measure the event channel RTT.\n"
      "Arguments {domid} {port}\n",
      test_evtchn_connect_rtt }
};

#define NR_TESTS (sizeof(tests)/sizeof(tests[0]))

static struct test *
find_test(const char *name)
{
    unsigned x;
    for (x = 0; x < NR_TESTS; x++)
        if (!strcmp(tests[x].name, name))
            return &tests[x];
    return NULL;
}

static void
usage(void)
{
    unsigned x;

    printf("gntoffer {test_name} {test_arguments}\n");
    printf("where {test_name} is one of:\n");
    for (x = 0; x < NR_TESTS; x++)
        printf("\t%s\n", tests[x].name);
    printf("gntoffer /? {test_name} gives help for individual tests\n");
    exit(1);
}

int __cdecl
main(int argc, char *argv[])
{
    struct test *t;

    if (argc == 1)
        usage();
    if (!strcmp(argv[1], "/offer_dup_child")) {
        offer_dup_child();
        return 0;
    }
    if (!strcmp(argv[1], "/?")) {
        if (argc != 3)
            usage();
        t = find_test(argv[2]);
        if (!t)
            xs_errx(1, &xs_render_error_stderr,
                    "can't find test %s", argv[2]);
        printf("%s", t->help);
        return 0;
    } else {
        xenops = xenops_open();
        if (!xenops)
            xs_win_err(1, &xs_render_error_stderr,
                       "cannot open xenops interface");

        t = find_test(argv[1]);
        if (!t)
            xs_errx(1, &xs_render_error_stderr,
                    "can't find test %s", argv[1]);
        return t->worker(argc-2, argv+2);
    }

}
