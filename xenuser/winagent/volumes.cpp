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

/* Various gubbins needed to reflect bits of volume data into
   xenstore.  This can also be compiled as a stand-alone program (see
   tests/volumes), for testing purposes. */
#include <windows.h>
#include <stdlib.h>

#pragma warning(disable:4201)
#include <winioctl.h>

#include <xs_private.h>
#include <scsifilt_ioctl.h>

#ifndef NO_XS_ACCESSOR
#include "XSAccessor.h"
#endif
#include "XService.h"

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

struct disk_extent {
    char *disk;
    LARGE_INTEGER sizeBytes;
};

struct volume {
    struct volume *next;
    char *xenstore_name;
    TCHAR *name;
    TCHAR **mount_points;
    ULARGE_INTEGER sizeBytes;
    ULARGE_INTEGER freeBytes;
    struct disk_extent *extents;
    unsigned nr_extents;
    TCHAR *volName;
    TCHAR *fs;
};

struct volume_data {
    struct volume *head_volume;
};

typedef void set_volume_field_t(const struct volume *volume,
                                const char *field,
                                const char *value);
typedef void destroy_volume_t(const struct volume *v);
typedef void create_volume_t(const struct volume *v);

static unsigned
tstrlen(const TCHAR *what)
{
    unsigned r;

    for (r = 0; what[r]; r++)
        ;

    return r;
}

static TCHAR *
tstrdup(const TCHAR *what)
{
    unsigned len;
    TCHAR *res;

    len = tstrlen(what) + 1;
    res = (TCHAR *)malloc(len * sizeof(TCHAR));
    memcpy(res, what, len * sizeof(TCHAR));
    return res;
}

static VOLUME_DISK_EXTENTS *
query_volume_extents(const TCHAR *name)
{
    HANDLE h;
    int nr_extents;
    VOLUME_DISK_EXTENTS *extents;
    DWORD outSize;
    DWORD newOutSize;
    TCHAR *other_name;
    unsigned cntr;

    other_name = tstrdup(name);
    other_name[tstrlen(other_name) - 1] = 0;
    h = CreateFile(other_name, FILE_ANY_ACCESS,
                   FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                   FILE_ATTRIBUTE_NORMAL, NULL);
    free(other_name);
    if (h == INVALID_HANDLE_VALUE)
        return NULL;

    cntr = 0;
    nr_extents = 1;
    while (1) {
        outSize = sizeof(VOLUME_DISK_EXTENTS) +
            sizeof(DISK_EXTENT) * (nr_extents - 1);
        extents = (VOLUME_DISK_EXTENTS *)malloc(outSize);
        if (DeviceIoControl(h,
                            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                            NULL,
                            0,
                            extents,
                            outSize,
                            &newOutSize,
                            NULL))
            break;

        if (++cntr % 16 == 0)
            XenstorePrintf("control/warning",
                           "having trouble getting extent list (%d tries so far, %d -> %d)",
                           cntr,
                           nr_extents,
                           extents->NumberOfDiskExtents);
        nr_extents = extents->NumberOfDiskExtents;
        free(extents);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER &&
            GetLastError() != ERROR_MORE_DATA) {
            /* This is probably a CD drive */
            extents = NULL;
            break;
        }
    }
    CloseHandle(h);

    return extents;
}

static char *
find_xenbus_name_for_physical_disk(unsigned index)
{
    char *filename;
    HANDLE h;
    char *buf;
    unsigned buf_size;
    DWORD ignore;
    unsigned cntr;

    filename = xs_asprintf("\\\\.\\PhysicalDrive%d", index);
    h = CreateFile(filename,
                   GENERIC_READ,
                   FILE_SHARE_READ|FILE_SHARE_WRITE,
                   NULL,
                   OPEN_EXISTING,
                   FILE_ATTRIBUTE_NORMAL,
                   NULL);
    if (h == INVALID_HANDLE_VALUE)
        return xs_asprintf("<cannot open physical drive %d>", index);
    buf_size = 0;
    buf = NULL;
    cntr = 0;
    while (1) {
        buf = (char *)malloc(buf_size);
        if (DeviceIoControl(h,
                            IOCTL_SCSIFILT_GET_XENBUS_NAME,
                            NULL,
                            0,
                            buf,
                            buf_size,
                            &ignore,
                            NULL)) {
            CloseHandle(h);
            return buf;
        }
        free(buf);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            /* Probably doesn't support the ioctl */
            CloseHandle(h);
            return xs_asprintf("<cannot get xenbus name for physical drive %d>",
                               index);
        }
        buf_size += 128;
        if (buf_size > 4096)
            XenstorePrintf("control/warning",
                           "device %d has a xenbus name longer than %d characters",
                           buf_size);
    }
}

static TCHAR **
explode_multisz(TCHAR *what)
{
    unsigned nr_strings;
    unsigned src_idx;
    unsigned dest_idx;
    unsigned src_end_idx;
    TCHAR **res;

    src_idx = 0;
    nr_strings = 0;
    while (1) {
        if (!what[src_idx])
            nr_strings++;
        if (!what[src_idx] && !what[src_idx+1])
            break;
        src_idx++;
    }
    res = (TCHAR **)calloc(sizeof(res[0]), nr_strings + 1);
    dest_idx = 0;
    src_idx = 0;
    src_end_idx = 0;
    while (1) {
        if (!what[src_end_idx]) {
            res[dest_idx] =
                (TCHAR*)malloc((src_end_idx - src_idx + 1) * sizeof(TCHAR));
            memcpy(res[dest_idx],
                   what + src_idx,
                   (src_end_idx - src_idx + 1) * sizeof(TCHAR));
            src_idx = src_end_idx + 1;
            dest_idx++;
        }
        if (!what[src_end_idx] && !what[src_end_idx+1])
            break;
        src_end_idx++;
    }
    return res;
}

/* Unfortunately, GetVolumePathNamesForVolumeName isn't available on
   Windows 2000, so provide a wrapper. */
typedef WINBASEAPI BOOL WINAPI typeGetVolumePathNamesForVolumeNameA(
    LPCSTR lpszVolumeName, LPCH lpszVolumePathNames, DWORD cchBufferLength,
    PDWORD lpcchReturnLength);

static BOOL
getVolumePathNamesForVolumeName(LPCSTR lpszVolumeName,
                                LPCH lpszVolumePathNames,
                                DWORD cchBufferLength,
                                PDWORD lpcchReturnLength)
{
    static typeGetVolumePathNamesForVolumeNameA *f;
    static BOOL failed;
    HMODULE kernel32;

    if (!f && !failed) {
        kernel32 = LoadLibrary("kernel32");
        /* if we can't load that we're truly screwed */

        f = (typeGetVolumePathNamesForVolumeNameA *)GetProcAddress(kernel32, "GetVolumePathNamesForVolumeNameA");
        if (!f) {
            /* Probably running on Windows 2000.  Give up. */
            failed = TRUE;
        }
        FreeLibrary(kernel32);
    }

    if (failed) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return FALSE;
    } else {
        return f(lpszVolumeName, lpszVolumePathNames,
                 cchBufferLength, lpcchReturnLength);
    }
}

static int
tstrcmp(const TCHAR *a, const TCHAR *b)
{
    unsigned x;

    if (a && !b)
        return -1;
    else if (!a && b)
        return 1;
    else if (!a && !b)
        return 0;

    for (x = 0; a[x] || b[x]; x++) {
        if (a[x] < b[x])
            return -1;
        else if (a[x] > b[x])
            return 1;
    }
    return 0;
}

static int __cdecl
compare_tstr(const void *_a, const void *_b)
{
    const TCHAR *const a = *(const TCHAR *const*)_a;
    const TCHAR *const b = *(const TCHAR *const*)_b;
    return tstrcmp(a, b);
}

static void
populate_mountpoints(struct volume *v)
{
    TCHAR *buf;
    DWORD bufSize;
    DWORD newBufSize;
    TCHAR **paths;
    unsigned nr_mountpoints;
    unsigned cntr;

    buf = NULL;
    bufSize = 0;
    newBufSize = 0;
    cntr = 0;
    while (1) {
        if (getVolumePathNamesForVolumeName(v->name,
                                            buf,
                                            bufSize,
                                            &newBufSize))
            break;
        if (GetLastError() != ERROR_MORE_DATA) {
            /* Make up something vaguely sensible */
#define msg TEXT("cannot get mount points")
            buf = (TCHAR*)realloc(buf, sizeof(msg) + sizeof(TCHAR));
            memcpy(buf, msg, sizeof(msg));
            buf[sizeof(msg)] = 0;
#undef msg
            break;
        }
        if (++cntr % 8 == 0)
            XenstorePrintf("control/warning",
                           "having trouble getting mountpoints for %s (%d tries so far, %d -> %d)",
                           v->name,
                           cntr,
                           bufSize,
                           newBufSize);
        if (bufSize == newBufSize) {
            /* XXX For reasons which aren't particularly clear,
             * GetVolumePathNamesForVolumeName() sometimes sets
             * newBufSize equal to bufSize even when it's failed with
             * ERROR_MORE_DATA.  It's not clear under what
             * circumstances this will happen, but it's easy for us to
             * work around, so do so. */
            newBufSize += 128;
        }
        buf = (TCHAR *)realloc(buf, newBufSize);
        bufSize = newBufSize;
    }
    if (!memcmp(buf, "\0\0", 2)) {
        /* Special case: a volume with no mount points get reported as
           having a single one of length zero.  Edit it back out. */
        paths = (TCHAR **)malloc(sizeof(paths[0]));
        paths[0] = NULL;
    } else {
        paths = explode_multisz(buf);
    }
    free(buf);

    v->mount_points = paths;

    for (nr_mountpoints = 0;
         v->mount_points[nr_mountpoints];
         nr_mountpoints++)
        ;
    qsort(v->mount_points, nr_mountpoints, sizeof(v->mount_points[0]),
          compare_tstr);
}

static int __cdecl
compare_disk_extents(const void *_a, const void *_b)
{
    const struct disk_extent *const a = (const struct disk_extent *const)_a;
    const struct disk_extent *const b = (const struct disk_extent *const)_b;
    int r;

    r = strcmp(a->disk, b->disk);
    if (r != 0)
        return r;
    if (a->sizeBytes.QuadPart < b->sizeBytes.QuadPart)
        return -1;
    else if (a->sizeBytes.QuadPart > b->sizeBytes.QuadPart)
        return 1;
    else
        return 0;
}

static int
compare_volume(const struct volume *a, const struct volume *b)
{
    /* NULLs sort to the end */
    if (a && !b)
        return -1;
    if (!a && b)
        return 1;
    if (!a && !b)
        return 0;

    /* name is supposed to be unique, so we don't need to compare any
       other fields. */
    return compare_tstr(&a->name, &b->name);
}

static void
insert_volume(struct volume *v, struct volume_data *vd)
{
    struct volume *cursor;
    struct volume **pprev;
    unsigned cntr;

    pprev = &vd->head_volume;
    cursor = *pprev;
    cntr = 0;
    while (cursor && compare_volume(v, cursor) > 0) {
        pprev = &cursor->next;
        cursor = *pprev;
        if (++cntr % 1000 == 0)
            XenstorePrintf("control/warning",
                           "volume list is very long (found %d so far)",
                           cntr);
    }

    v->next = cursor;
    *pprev = v;
}

static void
populate_volume_label(struct volume *v)
{
    TCHAR nameBuffer[MAX_PATH+1];
    TCHAR fsNameBuffer[MAX_PATH+1];

    if (GetVolumeInformation(v->name,
                             nameBuffer,
                             ARRAY_SIZE(nameBuffer),
                             NULL,
                             NULL,
                             NULL,
                             fsNameBuffer,
                             ARRAY_SIZE(fsNameBuffer))) {
        v->volName = tstrdup(nameBuffer);
        v->fs = tstrdup(fsNameBuffer);
    }
}

static void
process_volume(struct volume_data *vd, const TCHAR *name)
{
    struct volume *v;
    VOLUME_DISK_EXTENTS *extents;
    unsigned x;

    UNREFERENCED_PARAMETER(vd);

    v = (struct volume *)malloc(sizeof(*v));
    memset(v, 0, sizeof(*v));
    v->name = tstrdup(name);
    GetDiskFreeSpaceEx(name, NULL, &v->sizeBytes, &v->freeBytes);

    extents = query_volume_extents(name);
    if (extents) {
        v->nr_extents = extents->NumberOfDiskExtents;
        v->extents = (struct disk_extent *)calloc(sizeof(v->extents[0]),
                                                  v->nr_extents);
        for (x = 0; x < extents->NumberOfDiskExtents; x++) {
            v->extents[x].disk =
                find_xenbus_name_for_physical_disk(extents->Extents[x].DiskNumber);
            v->extents[x].sizeBytes = extents->Extents[x].ExtentLength;
        }
        free(extents);

        qsort(v->extents, v->nr_extents, sizeof(v->extents[0]),
              compare_disk_extents);
    }

    populate_mountpoints(v);

    populate_volume_label(v);

    insert_volume(v, vd);
}

static struct volume_data *
empty_volume_data(void)
{
    struct volume_data *work;
    work = (struct volume_data *)malloc(sizeof(*work));
    memset(work, 0, sizeof(*work));
    return work;
}

static struct volume_data *
fetch_windows_volume_data(void)
{
    HANDLE volume_enum;
    TCHAR volume_name[MAX_PATH];
    struct volume_data *work;
    unsigned cntr;

    volume_enum = FindFirstVolume(volume_name, ARRAY_SIZE(volume_name));
    if (volume_enum == INVALID_HANDLE_VALUE)
        return NULL;
    work = empty_volume_data();
    process_volume(work, volume_name);
    cntr = 0;
    while (1) {
        if (!FindNextVolume(volume_enum, volume_name,
                            ARRAY_SIZE(volume_name)))
            break;
        process_volume(work, volume_name);
        if (++cntr % 1000 == 0)
            XenstorePrintf("control/warning",
                           "found lots of volumes (%d so far)",
                           cntr);
    }
    FindVolumeClose(volume_enum);

    return work;
}

static void
lost_volume(destroy_volume_t *f, const struct volume *v)
{
    f(v);
}

static void
field_write_string(set_volume_field_t *set_volume_field,
                   const struct volume *v,
                   const char *data,
                   const char *fmt,
                   ...)
{
    char *path;
    va_list args;

    va_start(args, fmt);
    path = xs_vasprintf(fmt, args);
    va_end(args);

    set_volume_field(v, path, data);
    free(path);
}

static void
field_write_ulong64(set_volume_field_t *set_volume_field,
                    const struct volume *v,
                    ULONG64 val,
                    const char *fmt,
                    ...)
{
    char *path;
    char *data;
    va_list args;

    va_start(args, fmt);
    path = xs_vasprintf(fmt, args);
    va_end(args);

    data = xs_asprintf("%I64d", val);
    set_volume_field(v, path, data);
    free(path);
    free(data);
}

static void
clear_fieldv(set_volume_field_t *set_volume_field,
             const struct volume *v,
             const char *fmt,
             ...)
{
    va_list args;
    char *path;

    va_start(args, fmt);
    path = xs_vasprintf(fmt, args);
    va_end(args);

    set_volume_field(v, path, NULL);
    free(path);
}

static void
set_mount_point(set_volume_field_t *set_volume_field,
                const struct volume *v,
                unsigned idx)
{
    field_write_string(set_volume_field, v, v->mount_points[idx],
                       "mount_points/%d", idx);
}

static void
clear_mount_point(set_volume_field_t *set_volume_field,
                  const struct volume *v,
                  unsigned idx)
{
    clear_fieldv(set_volume_field, v, "mount_points/%d", idx);
}

static void
set_volume_size(set_volume_field_t *set_volume_field,
                const struct volume *v,
                ULONG64 size)
{
    field_write_ulong64(set_volume_field, v, size, "size");
}

static void
set_volume_free(set_volume_field_t *set_volume_field,
                const struct volume *v,
                ULONG64 fre)
{
    field_write_ulong64(set_volume_field, v, fre, "free");
}

static void
set_extent(set_volume_field_t *set_volume_field,
           const struct volume *v,
           unsigned idx)
{
    field_write_string(set_volume_field, v, v->extents[idx].disk,
                       "extents/%d", idx);
}

static void
clear_extent(set_volume_field_t *set_volume_field,
             const struct volume *v,
             unsigned idx)
{
    clear_fieldv(set_volume_field, v, "extents/%d", idx);
}

static void
set_volume_name(set_volume_field_t *set_volume_field,
                const struct volume *v,
                const TCHAR *volName)
{
    field_write_string(set_volume_field, v, volName,
                       "volume_name");
}

static void
set_volume_fs(set_volume_field_t *set_volume_field,
              const struct volume *v,
              const TCHAR *fs)
{
    field_write_string(set_volume_field, v, fs, "filesystem");
}

static void
new_volume(create_volume_t *f, set_volume_field_t *svf,
           struct volume *v)
{
    static ULONG64 next_id;
    unsigned x;

    v->xenstore_name = xs_asprintf("%I64d", next_id++);

    f(v);
    field_write_string(svf, v, v->name, "name");
    for (x = 0; v->mount_points[x]; x++)
        set_mount_point(svf, v, x);
    set_volume_size(svf, v, v->sizeBytes.QuadPart);
    set_volume_free(svf, v, v->freeBytes.QuadPart);
    for (x = 0; x < v->nr_extents; x++)
        set_extent(svf, v, x);
    set_volume_name(svf, v, v->volName);
    set_volume_fs(svf, v, v->fs);
}

static void
changed_volume(set_volume_field_t *set_volume_field,
               const struct volume *from, struct volume *to)
{
    unsigned x;

    to->xenstore_name = tstrdup(from->xenstore_name);

    for (x = 0; from->mount_points[x] && to->mount_points[x]; x++)
        if (tstrcmp(from->mount_points[x], to->mount_points[x]))
            set_mount_point(set_volume_field, to, x);
    if (from->mount_points[x]) {
        while (from->mount_points[x]) {
            clear_mount_point(set_volume_field, from, x);
            x++;
        }
    } else if (to->mount_points[x]) {
        while (to->mount_points[x]) {
            set_mount_point(set_volume_field, to, x);
            x++;
        }
    }

    if (from->sizeBytes.QuadPart != to->sizeBytes.QuadPart)
        set_volume_size(set_volume_field, to, to->sizeBytes.QuadPart);
    if (from->freeBytes.QuadPart != to->freeBytes.QuadPart) {
        /* Don't update the fields in xenstore unless free space has
           changed by more than 1% of the total size of the disk. */
        LONG64 change;
        change = from->freeBytes.QuadPart - to->freeBytes.QuadPart;
        if (change < 0)
            change = -change;
        if (change > (LONG64)(from->sizeBytes.QuadPart / 100)) {
            set_volume_free(set_volume_field, to, to->freeBytes.QuadPart);
        } else {
            /* Hack: we know that new is going to become xenstore_vd
               shortly, so we fix the freeBytes in there to reflect
               the fact that we haven't updated the values in the
               store. */
            to->freeBytes = from->freeBytes;
        }
    }

    for (x = 0; x < from->nr_extents && x < to->nr_extents; x++)
        if (compare_disk_extents(&from->extents[x], &to->extents[x]))
            set_extent(set_volume_field, to, x);
    while (x < from->nr_extents) {
        clear_extent(set_volume_field, from, x);
        x++;
    }
    while (x < to->nr_extents) {
        set_extent(set_volume_field, to, x);
        x++;
    }

    if (tstrcmp(from->volName, to->volName))
        set_volume_name(set_volume_field, to, to->volName);
    if (tstrcmp(from->fs, to->fs))
        set_volume_fs(set_volume_field, to, to->fs);
}

static void
free_volume(struct volume *v)
{
    unsigned x;

    free(v->xenstore_name);
    free(v->name);
    for (x = 0; v->mount_points[x]; x++)
        free(v->mount_points[x]);
    free(v->mount_points);
    for (x = 0; x < v->nr_extents; x++)
        free(v->extents[x].disk);
    free(v->volName);
    free(v->fs);
    free(v->extents);
    free(v);
}

static void
free_volume_data(struct volume_data *vd)
{
    struct volume *v;
    unsigned cntr;
    cntr = 0;
    while (vd->head_volume) {
        v = vd->head_volume->next;
        free_volume(vd->head_volume);
        vd->head_volume = v;
        if (++cntr % 1000 == 0)
            XenstorePrintf("control/warning",
                           "lots of volumes to free (%d so far)",
                           cntr);
    }
    free(vd);
}

static void
update_xenstore_volume_data(create_volume_t *create_volume,
                            destroy_volume_t *destroy_volume,
                            set_volume_field_t *set_volume_field)
{
    static struct volume_data *current_xenstore_vd;
    struct volume_data *windows_volume_data;
    struct volume *xenstore_cursor;
    struct volume *windows_cursor;
    int r;
    unsigned cntr;

    if (!current_xenstore_vd)
        current_xenstore_vd = empty_volume_data();
    windows_volume_data = fetch_windows_volume_data();

    cntr = 0;
    xenstore_cursor = current_xenstore_vd->head_volume;
    windows_cursor = windows_volume_data->head_volume;
    while (xenstore_cursor || windows_cursor) {
        r = compare_volume(xenstore_cursor, windows_cursor);
        if (r < 0) {
            lost_volume(destroy_volume, xenstore_cursor);
            xenstore_cursor = xenstore_cursor->next;
        } else if (r > 0) {
            new_volume(create_volume, set_volume_field, windows_cursor);
            windows_cursor = windows_cursor->next;
        } else {
            changed_volume(set_volume_field, xenstore_cursor, windows_cursor);
            xenstore_cursor = xenstore_cursor->next;
            windows_cursor = windows_cursor->next;
        }
        if (++cntr % 1000 == 0)
            XenstorePrintf("control/warning",
                           "found lots of volume changes (%d so far)\n",
                           cntr);
    }

    free_volume_data(current_xenstore_vd);
    current_xenstore_vd = windows_volume_data;
}

#ifndef NO_XS_ACCESSOR
static void
create_volume_xenstore(const struct volume *v)
{
    UNREFERENCED_PARAMETER(v);
}

static void
destroy_volume_xenstore(const struct volume *v)
{
    char *path;

    path = xs_asprintf("data/volumes/%s", v->xenstore_name);
    XenstoreRemove(path);
    free(path);
}

static void
set_volume_field_xenstore(const struct volume *v,
                          const char *field,
                          const char *value)
{
    char *path;
    path = xs_asprintf("data/volumes/%s/%s", v->xenstore_name, field);
    XenstorePrintf(path, "%s", value);
    free(path);
}

void
DoVolumeDump(void)
{
    update_xenstore_volume_data(create_volume_xenstore,
                                destroy_volume_xenstore,
                                set_volume_field_xenstore);
}
#endif
