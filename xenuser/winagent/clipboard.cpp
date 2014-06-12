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

/* Support for synchronising the clipboard with a vnc viewer using
   xenbus messages */

/* The clipboard protocol is quite simple.  If qemu wants to set a
   guest's clipboard, it does this:

   -- Set data/set_clipboard to the first chunk
   -- Wait for data/set_clipboard to be removed
   -- Sets data/set_clipboard to the second chunk
   -- Wait
   -- Repeat until no more chunks
   -- Set data/set_clipboard to the empty string.

   The protocol for the guest to set qemu's clipboard is analogous,
   but uses data/report_clipboard instead.

   This is all very simple, except that:

   -- qemu can't wait for the guest.
   -- There are some versions of qemu which don't support this,
      so we have to be able to shut down when we're waiting for
      qemu.
   -- It's slightly-asynchronous, in that either qemu or the guest
      could receive another clipboard change while this is going
      on.  In that case, we abort the current run and start again.

*/
#include <windows.h>
#include <stdlib.h>
#include "xs2.h"
#include "xs_private.h"
#include "XService.h"

#define MAX_CHUNKSIZE 1024

#define MIN(x,y) ((x)<(y)?(x):(y))
#define MAX(x,y) ((x)>(y)?(x):(y))

/* We don't want to use the same handle as the main accessor, because
   we can end up colliding over transactions. */
static struct xs2_handle *
XsHandle;

static struct {
    char *data;
    char *prev;
    BOOLEAN need_reset;
    size_t offset;
}
ReportClipboardState;

static HANDLE
ReportClipboardEvt = INVALID_HANDLE_VALUE;

static HANDLE
ClipboardThread = INVALID_HANDLE_VALUE;
static HANDLE
ShutdownEvent = INVALID_HANDLE_VALUE;

static void
FinishClipboardPush(void)
{
    XsLogMsg("finishing clipboard push");
    free(ReportClipboardState.prev);
    ReportClipboardState.prev = ReportClipboardState.data;
    ReportClipboardState.data = NULL;
    ReportClipboardState.need_reset = TRUE;
    SetEvent(ReportClipboardEvt);
    XsLogMsg("finished clipboard push");
}

/* Cause @cb to be pushed to qemu.  Aborts any existing push-out.
   No-op if @cb is the same as it was last time this was called. */
static void
PushClipboardUpdate(const char *cb)
{
    size_t len;
    char *b;

    XsLogMsg("pushing clipboard update");
    if (ReportClipboardState.prev && !strcmp(ReportClipboardState.prev, cb)) {
        XsLogMsg("nothing changed?");
        return;
    }

    if (ReportClipboardState.data)
        FinishClipboardPush();
    len = strlen(cb);
    b = (char *)malloc(len + 1);
    if (!b) {
        XsLogMsg("Out of memory trying to copy clipboard for push-out?");
        return;
    }
    memcpy(b, cb, len + 1);
    b[len] = 0;

    ReportClipboardState.data = b;
    ReportClipboardState.offset = 0;

    /* Start the reporting state machine if it's not already
     * running. */
    SetEvent(ReportClipboardEvt);
    XsLogMsg("clipboard ready for a push");
}

/* Called on the clipboard thread whenever the watch on
 * data/report_clipboard fires.  Responsible for pushing the next
 * chunk of data out. */
static void
ReportClipboardEvent(void)
{
    size_t size, bytes_this_time;
    char *cur_value;

    XsLogMsg("reporting a clipboard event");
    cur_value = (char *)xs2_read(XsHandle, "data/report_clipboard", &size);
    if (cur_value != NULL) {
        /* qemu hasn't acked the previous message yet */
        xs2_free(cur_value);
        return;
    }
    if (GetLastError() != ERROR_FILE_NOT_FOUND) {
        XsLogMsg("Unexpected error redaing data/report_clipboard: %d\n",
                 GetLastError());
        return;
    }

    if (ReportClipboardState.need_reset) {
        XsLogMsg("reseting clipboard");
        xs2_write(XsHandle, "data/report_clipboard", "");
        ReportClipboardState.need_reset = FALSE;
        return;
    }

    if (ReportClipboardState.data == NULL) {
        XsLogMsg("nothing to report");
        return;
    }

    bytes_this_time =
        MIN(strlen(ReportClipboardState.data) - ReportClipboardState.offset,
            MAX_CHUNKSIZE);
    if (bytes_this_time != 0) {
        xs2_write_bin(XsHandle, "data/report_clipboard",
                     ReportClipboardState.data + ReportClipboardState.offset,
                     bytes_this_time);
        ReportClipboardState.offset += bytes_this_time;
    } else {
        FinishClipboardPush();
    }
    XsLogMsg("finished reporting clipboard event");
}

/* @hwnd is the clipboard window.  Called on the clipboard thread. */
static void
SetClipboardEvent(HWND hwnd)
{
    char *this_chunk;
    size_t size;
    static HANDLE accumulated_clipboard;
    static size_t acc_clipboard_size;
    static size_t acc_clipboard_buf_size;
    char *acc_clipboard;

    XsLogMsg("clipboard event");

    /* Qemu just pushed in another chunk of update to the local
       clipboard.  Do something sensible with it. */

    this_chunk = (char *)xs2_read(XsHandle, "data/set_clipboard", &size);
    if (this_chunk == NULL) {
        /* Probably a bogus watch firing before qemu set the value.
           Wait and try again later. */
        XsLogMsg("bogus watch event?");
        return;
    }

    /* Embedded nuls cause problems.  Don't copy them.  (xs2_read
       always returns a nul-terminated result) */
    size = strlen(this_chunk);

    XsLogMsg("chunk size %d", size);

    /* +1 for the nul */
    if (acc_clipboard_size + size + 1 > acc_clipboard_buf_size) {
        size_t new_acc_buf_size;
        HANDLE new_acc;

        new_acc_buf_size = MAX((acc_clipboard_size + size + 1) * 2, 64);
        if (accumulated_clipboard) {
            new_acc =
                GlobalReAlloc(accumulated_clipboard,
                              new_acc_buf_size,
                              0);
        } else {
            new_acc =
                GlobalAlloc(GMEM_MOVEABLE, new_acc_buf_size);
        }
        if (new_acc == NULL) {
            XsLogMsg("No memory for clipboard accumulator buffer (%d)",
                     new_acc_buf_size);
            xs2_free(this_chunk);
            return;
        }
        accumulated_clipboard = new_acc;
        acc_clipboard_buf_size = new_acc_buf_size;
    }

    acc_clipboard = (char *)GlobalLock(accumulated_clipboard);
    if (!acc_clipboard) {
        DBGPRINT(("Failed to lock clipboard accumulation buffer"));
        xs2_free(this_chunk);
        return;
    }
    memcpy(acc_clipboard + acc_clipboard_size,
           this_chunk,
           size + 1); /* Make sure we pick up the nul */
    acc_clipboard_size += size; /* Next block should go over the top
                                   of the nul */
    GlobalUnlock(accumulated_clipboard);

    if (size == 0) {
        /* Empty string -> finished the current batch.  Set the
         * Windows clipboard */

        XsLogMsg("finished clipboard operation");
        if (OpenClipboard(hwnd)) {
            HANDLE old_handle;
            BOOLEAN do_set;
            char *old_data;

            /* Don't set the clipboard to the same value as it
               currently has. */
            do_set = FALSE;
            old_handle = GetClipboardData(CF_TEXT);
            if (!old_handle) {
                /* Assume that the error means ``clipboard doesn't
                   contain text''.  XXX not necessarily true */
                do_set = TRUE;
            } else {
                old_data = (char *)GlobalLock(old_handle);
                if (old_data) {
                    if (strcmp(old_data, acc_clipboard))
                        do_set = TRUE;
                    GlobalUnlock(old_handle);
                }
            }

            if (do_set) {
                if (EmptyClipboard()) {
                    /* Some Windows programs have bugs where putting
                       the empty string on the clipboard causes
                       problems (e.g. wordpad).  Avoid triggering
                       these by just emptying the clipboard when
                       someone tries to put an empty string on it,
                       even though that isn't strictly speaking
                       correct. */
                    if (acc_clipboard_size != 0) {
                        if (SetClipboardData(CF_TEXT,
                                             accumulated_clipboard)) {
                            accumulated_clipboard = NULL;
                        }
                    }
                }
            }

            CloseClipboard();
        }

        XsLogMsg("pushed clipboard to windows");

        /* Reset and prepare for the next update */
        if (accumulated_clipboard)
            GlobalFree(accumulated_clipboard);
        accumulated_clipboard = NULL;
        acc_clipboard_size = 0;
        acc_clipboard_buf_size = 0;
    }

    xs2_remove(XsHandle, "data/set_clipboard");
    XsLogMsg("processed clipboard event");
}

static void
ProcessPendingMessages(void)
{
    MSG msg;

    while (PeekMessage(&msg,
                       NULL,
                       0,
                       0,
                       PM_REMOVE)) {
        DispatchMessage(&msg);
    }
}

static LRESULT CALLBACK
WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static HWND next_clipboard_hwnd;
    static DWORD clipboard_batch_start;
    static int clipboard_batch_count;
    static CHAR *last_clipboard;
    static BOOLEAN on_clipboard_chain;
    DWORD now;
    size_t n;

    XsLogMsg("clipboard msg %d", msg);

    switch (msg) {
    case WM_CREATE:
        next_clipboard_hwnd = SetClipboardViewer(hwnd);
        on_clipboard_chain = TRUE;
        break;

    case WM_CHANGECBCHAIN:
        if (!on_clipboard_chain)
            break;
        if ( (HWND)wParam == next_clipboard_hwnd ) {
            next_clipboard_hwnd = (HWND)lParam;
        } else if (next_clipboard_hwnd != NULL) {
            SendMessage(next_clipboard_hwnd, msg, wParam, lParam);
        }
        break;

    case WM_DRAWCLIPBOARD:

        if (!on_clipboard_chain)
            break;

        /* Ick: work around what appears to be a bug in the RDP
           server, where clipboard notifier chains get message storms
           if you disconnect and reconnect a few times.  If it looks
           like we're getting a storm, de-register ourselves, wait a
           bit, and then re-register. */
        now = GetTickCount();
        if (now - clipboard_batch_start > 500) {
            clipboard_batch_start = now;
            clipboard_batch_count = 0;
        }
        clipboard_batch_count++;
        if (clipboard_batch_count > 10) {
            XsLogMsg("Clipboard storm, deregistering notifier (%d messages in %d milliseconds)",
                     clipboard_batch_count, now - clipboard_batch_start);
            ChangeClipboardChain(hwnd, next_clipboard_hwnd);
            on_clipboard_chain = FALSE;
            /* Stay off the clipboard chain for a second, to encourage
               rdpclip to sort itself out. */
            SetTimer(hwnd, 1, 1000, NULL);
        }

        if (OpenClipboard(hwnd)) {
            HANDLE h = GetClipboardData(CF_TEXT);
            if (h) {
                CHAR *l = (CHAR *)GlobalLock(h);
                if (l) {
                    PushClipboardUpdate(l);
                    GlobalUnlock(h);
                }
            }
            CloseClipboard();
        }
        SendMessage(next_clipboard_hwnd, msg, wParam, lParam);
        break;
    case WM_TIMER:
        if (on_clipboard_chain)
            break;
        XsLogMsg("Re-registering clipboard notifier.\n");
        next_clipboard_hwnd = SetClipboardViewer(hwnd);
        on_clipboard_chain = TRUE;
        break;
    case WM_DESTROY:
        if (on_clipboard_chain)
            ChangeClipboardChain(hwnd, next_clipboard_hwnd);
        on_clipboard_chain = FALSE;
        break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

static HWND
MakeTheWindow(void)
{
    WNDCLASS klass;
    ATOM atom;
    HWND h = NULL;

    memset(&klass, 0, sizeof(klass));
    klass.style = CS_CLASSDC;
    klass.lpfnWndProc = WindowProc;
    klass.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    klass.hCursor = LoadCursor(NULL, IDC_ARROW);
    klass.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    klass.lpszClassName = "Citrix XenService Window Class";
    atom = RegisterClass(&klass);
    if (!atom) {
        PrintError("RegisterClass()");
    } else {
        h = CreateWindow((LPCTSTR)atom,
                         "Citrix XenService",
                         0,
                         0,
                         0,
                         1,
                         1,
                         NULL,
                         NULL,
                         NULL,
                         NULL);
        if (!h)
            PrintError("CreateWindow()");
    }
    return h;
}

struct watch_event {
    HANDLE event;
    struct xs2_watch *watch;
};

static void
ReleaseWatch(struct watch_event *we)
{
    if (we == NULL)
        return;
    if (we->event != INVALID_HANDLE_VALUE)
        CloseHandle(we->event);
    if (we->watch)
        xs2_unwatch(we->watch);
    free(we);
}

static struct watch_event *
EstablishWatch(const char *path)
{
    struct watch_event *we;
    DWORD err;

    we = (struct watch_event *)malloc(sizeof(*we));
    if (!we) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    memset(we, 0, sizeof(*we));
    we->watch = NULL;
    we->event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (we->event != INVALID_HANDLE_VALUE)
        we->watch = xs2_watch(XsHandle, path, we->event);
    if (we->watch == NULL) {
        err = GetLastError();
        ReleaseWatch(we);
        SetLastError(err);
        return NULL;
    }
    return we;
}

static void
ClipboardThreadFunc(void)
{
    struct watch_event *set_clipboard, *report_clipboard;
    HANDLE handles[3];
    HWND window;
    DWORD status;

    XsLogMsg("Starting clipboard sync");

    XsHandle = xs2_open();
    if (!XsHandle) {
        XsLogMsg("Cannot open xs.dll from clipboard thread");
        return;
    }
    set_clipboard = EstablishWatch("data/set_clipboard");
    report_clipboard = EstablishWatch("data/report_clipboard");
    if (!set_clipboard || !report_clipboard) {
        XsLogMsg("Cannot establish clipboard watches");
        ReleaseWatch(set_clipboard);
        ReleaseWatch(report_clipboard);
        xs2_close(XsHandle);
        XsHandle = NULL;
        return;
    }

    window = MakeTheWindow();
    if (!window) {
        XsLogMsg("Cannot make clipboard window");
        ReleaseWatch(set_clipboard);
        ReleaseWatch(report_clipboard);
        xs2_close(XsHandle);
        XsHandle = NULL;
        return;
    }

    handles[0] = ShutdownEvent;
    handles[1] = set_clipboard->event;
    ReportClipboardEvt = handles[2] = report_clipboard->event;

    while (1) {
        XsLogMsg("clipboard thread going to sleep");
        status = MsgWaitForMultipleObjects(3, handles, FALSE,
                                           INFINITE, QS_ALLINPUT);
        XsLogMsg("clipboard thread woke up for %d", status);
        if (status == WAIT_OBJECT_0 ||
            status == WAIT_OBJECT_0 + 1 ||
            status == WAIT_OBJECT_0 + 2) {
            if (handles[status - WAIT_OBJECT_0] == ShutdownEvent) {
/**/            break;
            } else if (handles[status - WAIT_OBJECT_0] ==
                       set_clipboard->event) {
                SetClipboardEvent(window);
            } else if (handles[status - WAIT_OBJECT_0] ==
                       report_clipboard->event) {
                ReportClipboardEvent();
            } else {
                ASSERT(0);
            }
        } else if (status == WAIT_OBJECT_0 + 3) {
            ProcessPendingMessages();
        } else {
            DBGPRINT(("Wait for multiple objects failed when it shouldn't have done (%d)\n", status));
        }
    }

    XsLogMsg("clipboard thread shutting down");

    ReleaseWatch(set_clipboard);
    ReleaseWatch(report_clipboard);

    ReportClipboardEvt = INVALID_HANDLE_VALUE;

    DestroyWindow(window);

    /* Clear the thread message queue before we exit */
    ProcessPendingMessages();

    xs2_close(XsHandle);
    XsHandle = NULL;
    XsLogMsg("clipboard thread finished");
}

static DWORD WINAPI
ClipboardThreadCb(PVOID ignore)
{
    UNREFERENCED_PARAMETER(ignore);

    XsInitPerThreadLogging();
    __try
    {
        ClipboardThreadFunc();
    }
    __except(XsDumpLogThisThread(), EXCEPTION_CONTINUE_SEARCH)
    {
    }

    return 0;
}

void
StartClipboardSync(void)
{
    ShutdownEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (ShutdownEvent == INVALID_HANDLE_VALUE) {
        PrintError("CreateEvent(clipboard shutdown event)");
        return;
    }
    ClipboardThread = CreateThread(NULL,
                                   0,
                                   ClipboardThreadCb,
                                   NULL,
                                   0,
                                   NULL);
    if (ClipboardThread == INVALID_HANDLE_VALUE) {
        PrintError("CreateThread(clipboard thread)");
        CloseHandle(ShutdownEvent);
        ShutdownEvent = INVALID_HANDLE_VALUE;
    }
}

void
FinishClipboardSync(void)
{
    XsLogMsg("Stopping clipboard synchronisation");
    if (ShutdownEvent == INVALID_HANDLE_VALUE) {
        XsLogMsg("already stopped?");
        ASSERT(ClipboardThread == INVALID_HANDLE_VALUE);
        return;
    }
    ASSERT(ClipboardThread != INVALID_HANDLE_VALUE);
    SetEvent(ShutdownEvent);
    WaitForSingleObject(ClipboardThread, INFINITE);

    CloseHandle(ShutdownEvent);
    CloseHandle(ClipboardThread);
    ShutdownEvent = INVALID_HANDLE_VALUE;
    ClipboardThread = INVALID_HANDLE_VALUE;
    XsLogMsg("clipboard sync stopped");
}
