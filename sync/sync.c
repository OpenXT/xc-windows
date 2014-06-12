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

/* Sync the registry and every disk volume.  Used during
   uninstallation to make sure that e.g. filters are removed from the
   registry before they're removed from disk. */
/* This is a very big hammer compared to what's actually needed.  Oh
 * well. */
#include <windows.h>
#include <stdlib.h>
#include "xs_private.h"

static void
sync_this_volume(const char *name)
{
    HANDLE hand;
    char *path;

    /* Obviously, the names which Find{First,Next}Volume() return have
       slightly different syntax from those used by CreateFileA()
       (\\?\%s\ vs \\.\%s), because someone in Microsoft took the
       saying ``foolish consistency is the hobgoblin of little minds''
       a bit too seriously. */
    if (name[0] != '\\' || name[1] != '\\' || name[2] != '?' ||
        name[3] != '\\' || name[strlen(name)-1] != '\\') {
        /* This isn't in the format which we expect, so ignore it. */
        return;
    }
    path = xs_asprintf("%s", name);
    if (!path)
        xs_errx(1, &xs_render_error_msgbox, "failed to format path for %s",
                name);
    /* The ? needs to be a . */
    path[2] = '.';
    /* Need to strip the trailing backslash */
    path[strlen(path)-1] = 0;

    hand = CreateFileA(path,
                       GENERIC_WRITE,
                       FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);
    if (hand == INVALID_HANDLE_VALUE) {
        /* Don't report an error: it might just be that this is a
           read-only volume */
        free(path);
        return;
    }

    /* Ignore the return value of this: for some reason, Windows lets
       us open CD-ROMs writable, but then fails the flush call.  It
       might also be a network volume. */
    FlushFileBuffers(hand);

    CloseHandle(hand);
    free(path);
}

static int
is_prefix_of(const char *needle, const char *haystack)
{
    if (strlen(needle) <= strlen(haystack) &&
        !_strnicmp(needle, haystack, strlen(needle)))
        return 1;
    else
        return 0;
}

static void
flush_this_key(HKEY parent, const char *name)
{
    HKEY key;
    DWORD err;

    err = RegOpenKeyEx(parent, name, 0, KEY_QUERY_VALUE, &key);
    if (err != ERROR_SUCCESS) {
        /* For some reason which remains obscure to me, a default XP
           installation doesn't give Administrator sufficient access
           rights to flush all keys to disk.  It does give them
           sufficient access rights to grant themselves access to
           flush all keys, or to create a service which has permission
           to flush keys on their behalf, but that doesn't really
           sound like something I'd want to do.  Deal with it by just
           ignoring security errors on the affected key.  It's not one
           which we ever need to modify, anyway, and if Windows is
           modifying it behind our back and forgetting to flush then
           we're already screwed. */
        if (err == ERROR_ACCESS_DENIED && parent == HKEY_LOCAL_MACHINE &&
            !strcmp(name, "SECURITY"))
            return;
        SetLastError(err);
        xs_win_err(1, &xs_render_error_msgbox,
                   "cannot open registry key %s to synchronise it to disk",
                   name);
    }
    err = RegFlushKey(key);
    if (err != ERROR_SUCCESS) {
        SetLastError(err);
        xs_win_err(1, &xs_render_error_msgbox,
                   "cannot synchronise registry key %s to disk",
                   name);
    }
    RegCloseKey(key);
}

#define HIVELIST_KEY "SYSTEM\\CurrentControlSet\\Control\\hivelist"

/* Flush the entire registry to disk.  We rely on the fact that
   RegFlushKey() flushes an entire hive, which is arguably a bit of an
   implementation detail, but it is documented behaviour, so we should
   be okay. */
static void
flush_registry(void)
{
    HKEY hivelist_key;
    LONG err;
    DWORD idx;
    char value_name[16384];
    DWORD s;

    err = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                       HIVELIST_KEY,
                       0,
                       KEY_QUERY_VALUE,
                       &hivelist_key);
    if (err != ERROR_SUCCESS) {
        SetLastError(err);
        xs_win_err(1, &xs_render_error_msgbox,
                   "opening hive list in HKLM\\%s",
                   HIVELIST_KEY);
    }

    for (idx = 0; ; idx++) {
        s = ARRAYSIZE(value_name);
        err = RegEnumValue(hivelist_key,
                           idx,
                           value_name,
                           &s,
                           NULL,
                           NULL,
                           NULL,
                           NULL);
        if (err == ERROR_NO_MORE_ITEMS)
            break;
        if (err != ERROR_SUCCESS) {
            SetLastError(err);
            xs_win_err(1, &xs_render_error_msgbox,
                       "enumerating HKLM\\%s", HIVELIST_KEY);
        }

        if (is_prefix_of("\\REGISTRY\\MACHINE\\", value_name)) {
            flush_this_key(HKEY_LOCAL_MACHINE,
                           value_name + strlen("\\REGISTRY\\MACHINE\\"));
        } else if (is_prefix_of("\\REGISTRY\\USER\\", value_name)) {
            flush_this_key(HKEY_USERS,
                           value_name + strlen("\\REGISTRY\\USER\\"));
        } else {
            /* Don't know how to parse this registry hive.  Oh well,
             * just ignore it and hope for the best. */
            xs_win_err(1, &xs_render_error_msgbox,
                       "strange value %s", value_name);
        }
    }

    RegCloseKey(hivelist_key);
}

int __cdecl
main()
{
    HANDLE find_handle;
    char vol_name[MAX_PATH+1];

    flush_registry();

    /* Now loop over every volume and sync them as well. */
    find_handle = FindFirstVolume(vol_name, ARRAYSIZE(vol_name));
    if (find_handle == INVALID_HANDLE_VALUE)
        xs_win_err(1, &xs_render_error_msgbox,
                   "failed to start enumerating disk volumes");
    while (1) {
        sync_this_volume(vol_name);

        if (!FindNextVolume(find_handle, vol_name, ARRAYSIZE(vol_name))) {
            if (GetLastError() == ERROR_NO_MORE_FILES)
                break;
            xs_win_err(1, &xs_render_error_msgbox,
                       "failed to enumerate disk volumes");
        }
    }
    FindVolumeClose(find_handle);

    return 0;
}
