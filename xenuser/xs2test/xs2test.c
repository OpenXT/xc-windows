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

#include "xs2.h"
#include "xs_private.h"

static struct xs2_handle *
xs_handle;
static int
failed;

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
fail_test(unsigned code, const char *fmt, ...)
{
    va_list args;

    printf("fail test %d: ", code);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
    failed++;
}

static char *
gather_read(size_t *lp, const char *comp, ...)
{
    va_list args;
    char *acc;
    size_t acc_size, acc_used, l;
    char *res;

    acc_size = 4096;
    acc = malloc(acc_size);
    if (!acc) {
        printf("out of memory\n");
        exit(1);
    }
    acc_used = 0;
    va_start(args, comp);
    do {
        l = strlen(comp);
        while (acc_used + l + 1 > acc_size) {
            acc_size *= 2;
            acc = realloc(acc, acc_size);
            if (!acc) {
                printf("out of memory\n");
                exit(1);
            }
        }
        memcpy(acc + acc_used, comp, l);
        acc[acc_used + l] = '/';
        acc_used += l + 1;
        comp = va_arg(args, const char *);
    } while (comp);
    va_end(args);
    acc[acc_used-1] = 0;

    res = xs2_read(xs_handle, acc, lp);
    free(acc);
    return res;
}

static void
xs_read_expected_error(unsigned code, const char *path, DWORD e)
{
    char *t;
    DWORD err;

    t = xs2_read(xs_handle, path, NULL);
    if (t) {
        fail_test(code, "managed to read %s (%s)\n", path, t);
        free(t);
    } else {
        err = GetLastError();
        if (e != err) {
            fail_test(code,
                      "reading %s failed with %d, should have failed with %d",
                      path,
                      err,
                      e);
        }
    }
}

static void
xs_ls_expected_error(unsigned code, const char *path, DWORD e)
{
    char **contents;
    unsigned count;
    DWORD err;

    contents = xs2_directory(xs_handle, path, &count);
    if (contents) {
        fail_test(code, "managed to ls %s (%d)\n", path, count);
        free(contents);
    } else {
        err = GetLastError();
        if (e != err) {
            fail_test(code,
                      "ls %s failed with %d, should have failed with %d",
                      path,
                      err,
                      e);
        }
    }
}

static void
xs_write_expected_error(unsigned code, const char *path, const char *data,
                        DWORD e)
{
    DWORD err;

    if (xs2_write(xs_handle, path, data)) {
        fail_test(code, "managed to write %s to %s\n", data, path);
    } else {
        err = GetLastError();
        if (e != err) {
            fail_test(code,
                      "write %s to %s failed with %d, should have failed with %d",
                      data,
                      path,
                      err,
                      e);
        }
    }
}

static void
test_write_sizes(size_t max_size)
{
    size_t s;
    char *buf, *b2;
    size_t l;

    buf = malloc(max_size);
    if (!buf) {
        printf("no memory");
        exit(1);
    }
    for (s = 0; s < max_size; s++) {
        buf[s] = 0;
        if (!xs2_write(xs_handle, "data/test/key1", buf))
            break;
        b2 = xs2_read(xs_handle, "data/test/key1", &l);
        if (!b2) {
            fail_test(__LINE__, "failed to read in size %d", s);
        } else if (l != s) {
            fail_test(__LINE__, "read wrong size %d != %d", s, l);
        } else if (strcmp(b2, buf)) {
            fail_test(__LINE__, "read wrong data size %d %s ! = %s",
                      s, b2, buf);
        }
        if (b2)
            free(b2);
        buf[s] = 'X';
    }
    /* Experimentally, 2027 is the maximum key size we can write
       before we hit xenstore quota limits. */
    if (s < 2027)
        fail_test(__LINE__, "Could only write %d bytes to xenstore", s);
    free(buf);
}

static DWORD WINAPI
thread_func(PVOID _ident)
{
    int ident;
    HANDLE h;
    int x;
    char path[4096], buf[2000];
    char *t;
    size_t l;

    ident = (int)(ULONG_PTR)_ident;
    h = xs2_open();
    if (!h) win_err(1, "thread %d can't start", ident);

    sprintf(path, "data/test/thread%d", ident);
    for (x = 0; x < 5000; x++) {
        if ( (ident + x) % 256 == 0)
            memset(buf, 1, sizeof(buf));
        else
            memset(buf, ident + x, sizeof(buf));
        buf[sizeof(buf)-1] = 0;
        if (!xs2_write(h, path, buf))
            fail_test(__LINE__, "thread %d pass %d", ident, x);
        t = xs2_read(h, path, &l);
        if (!t) {
            if (GetLastError() == ERROR_FILE_NOT_FOUND) {
                printf("ERROR_NOT_FOUND, did the VM get suspended?\n");
            } else {
                fail_test(__LINE__, "thread %d pass %d (%d)", ident, x,
                          GetLastError());
            }
        } else {
            if (l != sizeof(buf)-1)
                fail_test(__LINE__, "thread %d pass %d (%d, %d)", ident, x,
                          l, sizeof(buf)-1);
            if (strcmp(buf, t))
                fail_test(__LINE__, "thread %d pass %d", ident, x);
            free(t);
        }
    }

    xs2_close(h);

    return 0;
}

static void
run_stress(void)
{
    HANDLE h[16];
    int i;

    for (i = 0; i < 16; i++) {
        h[i] = CreateThread(NULL, 0, thread_func, (void *)(ULONG_PTR)i, 0,
                            NULL);
        if (!h[i])
            win_err(1, "creating thread %d", i);
    }
    WaitForMultipleObjects(16, h, TRUE, INFINITE);
}

static void
test_many_watches(void)
{
    HANDLE events[64];
    struct xs2_watch *watches[64];
    int i;
    char buf[64];

    for (i = 0; i < 64; i++) {
        events[i] = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (events[i] == INVALID_HANDLE_VALUE)
            win_err(0, "CreateEvent() %d in test_many_watches", i);
    }
    for (i = 0; i < 64; i++) {
        sprintf(buf, "data/test/key%d", i);
        watches[i] = xs2_watch(xs_handle, buf, events[i]);
        if (watches[i] == NULL) {
            fail_test(__LINE__, "couldn't watch %s: %d", buf,
                      GetLastError());
        } else {
            /* Wait for the watch to go idle. */
            while (WaitForSingleObject(events[i], 100) != WAIT_TIMEOUT)
                ;
        }
    }
    /* Make sure that the watches all fire. */
    for (i = 0; i < 64; i++) {
        sprintf(buf, "data/test/key%d", i);
        xs2_write(xs_handle, buf, "foo");
        if (WaitForSingleObject(events[i], 100) != WAIT_OBJECT_0)
            fail_test(__LINE__, "Watch %d on %s failed to fire", i, buf);
    }

    /* Cancel the watches and close the events. */
    for (i = 0; i < 64; i++) {
        if (watches[i] >= 0)
            xs2_unwatch(watches[i]);
        CloseHandle(events[i]);
    }
}

int __cdecl
main()
{
    char *vm_path, *uuid, *t;
    size_t l;
    char **contents;
    unsigned count;
    HANDLE xs_handle2;
    HANDLE event;
    HANDLE event2;
    struct xs2_watch *watch;
    struct xs2_watch *watch2;
    int i;
    DWORD status;
    WRITE_ON_CLOSE_HANDLE woc;

    xs_handle = xs2_open();
    if (!xs_handle)
        win_err(1, "openning xenstore interface");

    /* Try to give ourselves a clean place to start */
    xs2_remove(xs_handle, "data/test");

    /* Check basic xenstore reads with relative path... */
    vm_path = xs2_read(xs_handle, "vm", NULL);
    if (!vm_path)
        win_err(1, "reading vm path");
    if (vm_path[0] != '/') {
        fail_test(__LINE__, "expected vm path to be absolute, got %s",
                  vm_path);
    }

    /* and with an absolute path. */
    uuid = gather_read(&l, vm_path, "uuid", NULL);
    if (!uuid)
        win_err(1, "reading uuid");
    if (l != 36) {
        fail_test(__LINE__, "uuid length was %d bytes, expected 36");
    }
    if (strlen(uuid) != 36) {
        fail_test(__LINE__,
                  "uuid was %s, not right length (%d, should be 36), returned length %d",
                  uuid,
                  strlen(uuid),
                  l);
    }

    /* Make sure read error sets a suitable code. */
    xs_read_expected_error(__LINE__, "non_existent", ERROR_FILE_NOT_FOUND);
    xs_read_expected_error(__LINE__, "invalid\\path",
                           ERROR_INVALID_PARAMETER);
    xs_read_expected_error(__LINE__, "/local/domain/0/name",
                           ERROR_ACCESS_DENIED);

    /* Test basic xs2_write functionality. */
    if (!xs2_write(xs_handle, "data/test/key1", "data1")) {
        fail_test(__LINE__, "write data/test/key1 failed with %lx",
                  GetLastError());
    } else {
        t = xs2_read(xs_handle, "data/test/key1", &l);
        if (!t) {
            fail_test(__LINE__, "error reading from data/test/key1: %lx",
                      GetLastError());
        } else {
            if (l != 5) {
                fail_test(__LINE__,
                          "manifest length wrong reading data/test/key1: %d should be 5.",
                          l);
            }
            if (strcmp(t, "data1")) {
                fail_test(__LINE__,
                          "got wrong data reading data/test/key1: %s should be data1.",
                          t);
            }
            free(t);
        }
    }

    xs_write_expected_error(__LINE__, "foo", "bar", ERROR_ACCESS_DENIED);
    xs_write_expected_error(__LINE__, "/foo", "bar", ERROR_ACCESS_DENIED);

    /* Try a very large write and make sure that it fails in the
       expected way. */
    t = malloc(65536);
    memset(t, 'a', 65536);
    t[65535] = 0;
    xs_write_expected_error(__LINE__,"data/test/key1", t,
                            ERROR_DISK_FULL);
    free(t);

    /* Test that read and write work for keys containing nul bytes. */
    if (!xs2_write_bin(xs_handle, "data/test/key1", "xxx\0yyy", 7)) {
        fail_test(__LINE__, "failed to write nul bytes (%d)",
                  GetLastError());
    }
    t = xs2_read(xs_handle, "data/test/key1", &l);
    if (!t) {
        fail_test(__LINE__, "failed to read nul bytes (%d)",
                  GetLastError());
    } else {
        if (l != 7) {
            fail_test(__LINE__, "read with nuls: expected 7, got %d.\n", l);
        } else if (memcmp(t, "xxx\0yyy", 7)) {
            fail_test(__LINE__, "bad data from read with nuls: %s",
                      t);
        }
        free(t);
    }

    if (!xs2_remove(xs_handle, "data/test/key1")) {
        fail_test(__LINE__, "failed to remove data/test/key1 (%d)",
                  GetLastError());
    }

    xs_read_expected_error(__LINE__, "data/test/key1", ERROR_FILE_NOT_FOUND);

    xs_ls_expected_error(__LINE__, "data/test/key1", ERROR_FILE_NOT_FOUND);

    if (!xs2_write(xs_handle, "data/test/key1", "data1")) {
        fail_test(__LINE__, "failed to rewrite data/test/key1");
    }

    contents = xs2_directory(xs_handle, "data/test/key1", &count);
    if (!contents) {
        fail_test(__LINE__, "failed to ls data/test/key1: %x",
                  GetLastError());
    } else if (count != 0) {
        fail_test(__LINE__, "ls data/test/key1 had %d items", count);
        free(contents);
    } else {
        free(contents);
    }

    if (!xs2_write(xs_handle, "data/test/key1/key2", "data2")) {
        fail_test(__LINE__, "failed to rewrite data/test/key1/key2");
    }

    contents = xs2_directory(xs_handle, "data/test/key1", &count);
    if (!contents) {
        fail_test(__LINE__, "failed to ls data/test/key1: %x",
                  GetLastError());
    } else if (count != 1) {
        fail_test(__LINE__, "ls data/test/key1 had %d items", count);
        free(contents);
    } else if (strcmp(contents[0], "key2")) {
        fail_test(__LINE__, "ls data/test/key1 gave unexpected result %s",
                  contents[0]);
    }

    xs2_remove(xs_handle, "data/test");

    /* Looks like most of the basic functionality works.  Try
     * transactions. */
    xs_handle2 = xs2_open();
    if (!xs_handle2) win_err(1, "couldn't re-open domain interface");

    if (!xs2_write(xs_handle, "data/test/key1", "before"))
        fail_test(__LINE__, "failed to write to data/test/key1: %x",
                  GetLastError());
    if (!xs2_transaction_start(xs_handle2))
        win_err(1, "couldn't open a transaction on second handle");
    if (!xs2_write(xs_handle2, "data/test/key1", "after"))
        fail_test(__LINE__, "failed to write to data/test/key1 under transaction: %x",
                  GetLastError());
    if (!xs2_transaction_commit(xs_handle2))
        fail_test(__LINE__, "failed to write to end transaction: %x",
                  GetLastError());
    if (strcmp(xs2_read(xs_handle, "data/test/key1", NULL), "after"))
        fail_test(__LINE__, "transaction didn't stick");

    /* Now try aborting the transaction. */
    if (!xs2_write(xs_handle, "data/test/key1", "before"))
        fail_test(__LINE__, "failed to write to data/test/key1: %x",
                  GetLastError());
    if (!xs2_transaction_start(xs_handle2))
        win_err(1, "couldn't open a transaction on second handle");
    if (!xs2_write(xs_handle2, "data/test/key1", "after"))
        fail_test(__LINE__, "failed to write to data/test/key1 under transaction: %x",
                  GetLastError());
    xs2_transaction_abort(xs_handle2);
    if (strcmp(xs2_read(xs_handle, "data/test/key1", NULL), "before"))
        fail_test(__LINE__, "transaction didn't abort");

    /* Try to arrange that the transaction fails. */
    if (!xs2_write(xs_handle, "data/test/key1", "before"))
        fail_test(__LINE__, "failed to write to data/test/key1: %x",
                  GetLastError());
    if (!xs2_transaction_start(xs_handle2))
        win_err(1, "couldn't open a transaction on second handle");
    if (!xs2_write(xs_handle2, "data/test/key1", "after"))
        fail_test(__LINE__, "failed to write to data/test/key1 under transaction: %x",
                  GetLastError());
    if (!xs2_write(xs_handle, "data/test/key1", "other"))
        fail_test(__LINE__, "failed to write to data/test/key1: %x",
                  GetLastError());
    if (xs2_transaction_commit(xs_handle2))
        fail_test(__LINE__, "transaction succeeded when it shouldn't",
                  GetLastError());
    if (strcmp(xs2_read(xs_handle, "data/test/key1", NULL), "other"))
        fail_test(__LINE__, "transaction did something strange");


    if (!xs2_write(xs_handle, "data/test/key1", "before1"))
        fail_test(__LINE__, "failed to write to data/test/key1: %x",
                  GetLastError());
    if (!xs2_write(xs_handle, "data/test/key2", "before2"))
        fail_test(__LINE__, "failed to write to data/test/key2: %x",
                  GetLastError());
    if (!xs2_transaction_start(xs_handle2))
        win_err(1, "couldn't open a transaction on second handle");
    if (!xs2_write(xs_handle2, "data/test/key1", "after"))
        fail_test(__LINE__, "failed to write to data/test/key1 under transaction: %x",
                  GetLastError());
    t = xs2_read(xs_handle2, "data/test/key2", NULL);
    if (!t) {
        fail_test(__LINE__,
                  "failed to read data/test/key2 under transaction: %x",
                  GetLastError());
    } else {
        if (strcmp(t, "before2"))
            fail_test(__LINE__,
                      "got wrong thing reading dtaa/test/key2 (%s)",
                      t);
        free(t);
    }
    if (!xs2_write(xs_handle, "data/test/key2", "other"))
        fail_test(__LINE__, "failed to write to data/test/key1: %x",
                  GetLastError());
    if (xs2_transaction_commit(xs_handle2))
        fail_test(__LINE__, "transaction succeeded when it shouldn't",
                  GetLastError());
    if (strcmp(xs2_read(xs_handle, "data/test/key1", NULL), "before1"))
        fail_test(__LINE__, "transaction did something strange");

    xs2_close(xs_handle2);

    /* Try a couple of transaction error cases. */
    xs_handle2 = xs2_open();
    if (!xs_handle2) win_err(1, "couldn't re-open domain interface a second time");
    if (!xs2_transaction_start(xs_handle2))
        win_err(1, "couldn't open a transaction for re-test");
    if (xs2_transaction_start(xs_handle2)) {
        fail_test(__LINE__, "openned two transactions on same handle");
    }
    xs2_close(xs_handle2);

    xs_handle2 = xs2_open();
    if (!xs_handle2) win_err(1, "couldn't re-open domain interface a third time");
    if (xs2_transaction_commit(xs_handle2)) {
        fail_test(__LINE__, "ended transaction without starting it");
    }
    if (!xs2_transaction_start(xs_handle2))
        win_err(1, "couldn't open a transaction for re-test");
    if (!xs2_transaction_commit(xs_handle2))
        fail_test(__LINE__, "failed to end transaction");
    if (xs2_transaction_commit(xs_handle2)) {
        fail_test(__LINE__, "double-ended transaction");
    }
    xs2_close(xs_handle2);


    /* Transactions appear to be working, at least in their most basic
       form.  Have a go at watches. */
    event = CreateEvent(NULL, FALSE, FALSE, NULL);
    watch = xs2_watch(xs_handle, "data/test/key1", event);
    if (!watch) {
        fail_test(__LINE__, "couldn't watch data/test/key1");
    } else {
        while (WaitForSingleObject(event, 100) != WAIT_TIMEOUT)
            ;
        xs2_write(xs_handle, "data/test/key1", "foo");
        if (WaitForSingleObject(event, INFINITE) != WAIT_OBJECT_0)
            fail_test(__LINE__, "failed wait for data/test/key1: %x",
                      GetLastError());
        xs2_write(xs_handle, "data/test/key1", "foo");
        if (WaitForSingleObject(event, INFINITE) != WAIT_OBJECT_0)
            fail_test(__LINE__, "failed wait for data/test/key1: %x",
                      GetLastError());
        xs2_write(xs_handle, "data/test/key1", "foo");
        if (WaitForSingleObject(event, INFINITE) != WAIT_OBJECT_0)
            fail_test(__LINE__, "failed wait for data/test/key1: %x",
                      GetLastError());
        status = WaitForSingleObject(event, 2000);
        if (status != WAIT_TIMEOUT)
            fail_test(__LINE__,
                      "should have timed out waiting for data/test/key1 (%d, %d)",
                      status,
                      GetLastError());

        xs2_unwatch(watch);
    }

    /* Create two watches on the same key, kill one of them, and then
       make sure that the other one still works. */
    watch = xs2_watch(xs_handle, "data/test/key1/subkey", event);
    if (!watch) {
        fail_test(__LINE__, "couldn't watch data/test/key1/subkey");
    } else {
        event2 = CreateEvent(NULL, FALSE, FALSE, NULL);
        watch2 = xs2_watch(xs_handle, "data/test/key1/subkey", event);
        if (!watch2) {
            fail_test(__LINE__, "couldn't double watch data/test/key1/subkey");
        } else {
            xs2_unwatch(watch2);
            ResetEvent(event);
            xs2_remove(xs_handle, "data/test/key1");
            if (WaitForSingleObject(event, 5000) != WAIT_OBJECT_0)
                fail_test(__LINE__, "failed wait for data/test/key1: %x",
                          GetLastError());
            xs2_unwatch(watch);
        }
    }

    /* Watch a node, then modify it in a transaction, and check that
       the watch fires. */
    watch = xs2_watch(xs_handle, "data/test/key1", event);
    if (!watch) {
        fail_test(__LINE__, "couldn't watch data/test/key1");
    } else {
        for (i = 0; i < 100; i++) {
            ResetEvent(event);
            do {
                if (!xs2_transaction_start(xs_handle))
                    win_err(1, "couldn't open a transaction for watch test");
                xs2_write(xs_handle, "data/test/key1", "foo");
            } while (!xs2_transaction_commit(xs_handle));
            if (WaitForSingleObject(event, 5000) != WAIT_OBJECT_0)
                fail_test(__LINE__, "failed wait for data/test/key1(%d): %x",
                          i, GetLastError());
        }
        xs2_unwatch(watch);
    }

    /* Check that write-on-close works */
    xs2_write(xs_handle, "data/test/woc", "fail");
    xs_handle2 = xs2_open();
    if (!xs_handle2)
        win_err(1, "couldn't re-open domain interface a fourth time");
    woc = xs2_write_on_close(xs_handle2, "data/test/woc", "pass", 4);
    if (is_null_WRITE_ON_CLOSE_HANDLE(woc))
        win_err(1, "setting up woc handle");
    t = xs2_read(xs_handle2, "data/test/woc", NULL);
    if (!t)
        win_err(1, "Huh?  data/test/woc disappeared while we were working");
    if (strcmp(t, "fail"))
        fail_test(__LINE__, "expected data/test/woc to be fail, was %s",
                  t);
    xs2_free(t);
    xs2_close(xs_handle2);
    t = xs2_read(xs_handle, "data/test/woc", NULL);
    if (!t || strcmp(t, "pass"))
        fail_test(__LINE__, "expected data/test/woc to be pass, was %s", t);
    xs2_free(t);

    /* And make sure that it's cancellable. */
    xs_handle2 = xs2_open();
    if (!xs_handle2)
        win_err(1, "couldn't re-open domain interface a fourth time");
    woc = xs2_write_on_close(xs_handle2, "data/test/woc", "fail", 4);
    if (is_null_WRITE_ON_CLOSE_HANDLE(woc))
        win_err(1, "setting up woc handle");
    xs2_cancel_write_on_close(xs_handle2, woc);
    xs2_close(xs_handle2);
    t = xs2_read(xs_handle, "data/test/woc", NULL);
    if (!t || strcmp(t, "pass"))
        fail_test(__LINE__, "expected data/test/woc to be pass, was %s", t);
    xs2_free(t);

    /* Make a lot of watches, make sure they all work. */
    test_many_watches();

    /* Try some different sized requests */
    test_write_sizes(4096);

    xs2_close(xs_handle);

    run_stress();

    if (failed) {
        printf("failed\n");
        return 1;
    } else {
        printf("passed\n");
        return 0;
    }
}
