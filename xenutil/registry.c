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

#include "xenutl.h"

NTSTATUS
XenCreateRegistryKey(
    IN  HANDLE          Parent,
    IN  const WCHAR     *Path,
    IN  ACCESS_MASK     Access,
    OUT PHANDLE         pKey
    )
{
    UNICODE_STRING      String;
    OBJECT_ATTRIBUTES   Attributes;
    ULONG               Disposition;
    HANDLE              Key;
    NTSTATUS            status;

    RtlInitUnicodeString(&String, Path);

    InitializeObjectAttributes(&Attributes,
                               &String,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               Parent,
                               NULL);
    status = ZwCreateKey(&Key,
                         Access,
                         &Attributes,
                         0,
                         NULL,
                         REG_OPTION_NON_VOLATILE,
                         &Disposition);
    if (!NT_SUCCESS(status))
        goto fail1;

    if (Disposition == REG_CREATED_NEW_KEY)
        TraceNotice(("%s: created %ws\n", __FUNCTION__, Path));

    *pKey = Key;
    return STATUS_SUCCESS;

fail1:
    TraceError(("%s(%ws): fail1 (%08x)\n", __FUNCTION__, Path, status));

    return status;
}

NTSTATUS
XenOpenRegistryKey(
    IN  const WCHAR     *Path,
    IN  ACCESS_MASK     Access,
    OUT PHANDLE         pKey
    )
{
    UNICODE_STRING      String;
    OBJECT_ATTRIBUTES   Attributes;
    HANDLE              Key;
    NTSTATUS            status;

    RtlInitUnicodeString(&String, Path);

    InitializeObjectAttributes(&Attributes,
                               &String,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);
    status = ZwOpenKey(&Key,
                       Access,
                       &Attributes);
    if (!NT_SUCCESS(status))
        goto fail1;

    *pKey = Key;
    return STATUS_SUCCESS;

fail1:
    TraceError(("%s(%ws): fail1 (%08x)\n", __FUNCTION__, Path, status));

    return status;
}

NTSTATUS
XenReadRegistryValue(
    IN  const WCHAR                     *Path,
    IN  const WCHAR                     *Name,
    OUT PKEY_VALUE_PARTIAL_INFORMATION  *pInfo
    )
{
    UNICODE_STRING                      String;
    HANDLE                              Key;
    PVOID                               Buffer;
    ULONG                               Size;
    NTSTATUS                            status;
            
    status = XenOpenRegistryKey(Path, KEY_READ, &Key);    
    if (!NT_SUCCESS(status))
        goto fail1;

    RtlInitUnicodeString(&String, Name);

    Buffer = NULL;
    Size = 0;

    for (;;) {
        status = ZwQueryValueKey(Key,
                                 &String,
                                 KeyValuePartialInformation,
                                 Buffer,
                                 Size,
                                 &Size);
        if (NT_SUCCESS(status))
            break;

        if (status == STATUS_OBJECT_NAME_NOT_FOUND)
            goto not_found;

        if (status != STATUS_BUFFER_OVERFLOW &&
            status != STATUS_BUFFER_TOO_SMALL)
            goto fail2;

        if (Buffer != NULL)
            ExFreePoolWithTag(Buffer, XUTIL_TAG);

        Buffer = ExAllocatePoolWithTag(NonPagedPool, Size, XUTIL_TAG);

        status = STATUS_INSUFFICIENT_RESOURCES;
        if (Buffer == NULL)
            goto fail3;

        RtlZeroMemory(Buffer, Size);
    }
        
    ZwClose(Key);

    *pInfo = Buffer;
    return STATUS_SUCCESS;

not_found:
    return STATUS_OBJECT_NAME_NOT_FOUND;

fail3:
    TraceError(("%s: fail2\n", __FUNCTION__));

fail2:
    TraceError(("%s: fail2\n", __FUNCTION__));

fail1:

    TraceError(("%s(%ws\\%ws): fail1 (%08x)\n", __FUNCTION__, Path, Name, status));

    return status;
}

VOID
XenMoveRegistryValues(
    IN  HANDLE src_handle,
    IN  HANDLE dest_handle
    )
{
    NTSTATUS status;
    UNICODE_STRING valueNameString;
    PKEY_VALUE_FULL_INFORMATION valueBuffer = NULL;
    DWORD valueBufferLength;
    PKEY_NAME_INFORMATION srcNameBuffer = NULL;
    UNICODE_STRING srcNameString;
    PKEY_NAME_INFORMATION destNameBuffer = NULL;
    UNICODE_STRING destNameString;
    DWORD nameBufferLength;
    ULONG count;

    status = ZwQueryKey(src_handle, KeyNameInformation, NULL, 0, &nameBufferLength);
    XM_ASSERT(status == STATUS_BUFFER_TOO_SMALL);

    srcNameBuffer = XmAllocateMemory(nameBufferLength);

    status = STATUS_NO_MEMORY;
    if (srcNameBuffer == NULL)
        goto fail1;

    status = ZwQueryKey(src_handle, KeyNameInformation, srcNameBuffer, nameBufferLength, &nameBufferLength);
    if (status != STATUS_SUCCESS)
        goto fail2;

    srcNameString.Length = (USHORT)srcNameBuffer->NameLength;
    srcNameString.MaximumLength = (USHORT)srcNameBuffer->NameLength;
    srcNameString.Buffer = srcNameBuffer->Name;

    status = ZwQueryKey(dest_handle, KeyNameInformation, NULL, 0, &nameBufferLength);
    XM_ASSERT(status == STATUS_BUFFER_TOO_SMALL);

    destNameBuffer = XmAllocateMemory(nameBufferLength);

    status = STATUS_NO_MEMORY;
    if (destNameBuffer == NULL)
        goto fail3;

    status = ZwQueryKey(dest_handle, KeyNameInformation, destNameBuffer, nameBufferLength, &nameBufferLength);
    if (status != STATUS_SUCCESS)
        goto fail4;

    destNameString.Length = (USHORT)destNameBuffer->NameLength;
    destNameString.MaximumLength = (USHORT)destNameBuffer->NameLength;
    destNameString.Buffer = destNameBuffer->Name;

    valueBuffer = NULL;
    valueBufferLength = 0;

    // Transfer values.  We always try to move the first remaining
    // value on every loop, and, because we delete things as we go,
    // and we want to ignore the default value.  We therefore need to
    // use a constant index of zero.
    count = 0;
    for (;;) {
        status = ZwEnumerateValueKey(src_handle,
                                     0,
                                     KeyValueFullInformation,
                                     NULL,
                                     0,
                                     &valueBufferLength);
        if (status == STATUS_NO_MORE_ENTRIES)   // No more values to copy
            break;

        XM_ASSERT(status == STATUS_BUFFER_TOO_SMALL);

        valueBuffer = XmAllocateZeroedMemory(valueBufferLength);

        status = STATUS_NO_MEMORY;
        if (valueBuffer == NULL)
            goto fail5;

        status = ZwEnumerateValueKey(src_handle,
                                     0,
                                     KeyValueFullInformation,
                                     valueBuffer,
                                     valueBufferLength,
                                     &valueBufferLength);
        // It's possible that someone else modified the value while we
        // were working, in which case we'll have to retry.
        if (status == STATUS_NO_MORE_ENTRIES ||
            status == STATUS_BUFFER_TOO_SMALL ||
            status == STATUS_BUFFER_OVERFLOW)
            continue;

        if (!NT_SUCCESS(status))
            goto fail6;

        XM_ASSERT3U(valueBuffer->NameLength, <, 65536);
        valueNameString.Length = (USHORT)valueBuffer->NameLength;
        valueNameString.MaximumLength = (USHORT)valueBuffer->NameLength;
        valueNameString.Buffer = valueBuffer->Name;

        if (count == 0)
            TraceNotice(("COPY: %wZ -> %wZ\n", &srcNameString, &destNameString));

        TraceNotice(("COPY[%u]: %wZ\n", count, &valueNameString));

        // Write the new value
        status = ZwSetValueKey(dest_handle,
                               &valueNameString,
                               valueBuffer->TitleIndex,
                               valueBuffer->Type,
                               (void *)((ULONG_PTR)valueBuffer + valueBuffer->DataOffset),
                               valueBuffer->DataLength);
        if (!NT_SUCCESS(status))
            goto fail7;

        // Delete the original
        status = ZwDeleteValueKey(src_handle, &valueNameString);
        if (!NT_SUCCESS(status))
            goto fail8;

        count++;

        XmFreeMemory(valueBuffer);
        valueBuffer = NULL;
        valueBufferLength = 0;
    }
    XM_ASSERT3P(valueBuffer, ==, NULL);
    XM_ASSERT3U(valueBufferLength, ==, 0);

    XmFreeMemory(destNameBuffer);
    XmFreeMemory(srcNameBuffer);

    return;

fail8:
    TraceError(("%s: fail8\n", __FUNCTION__));
fail7:
    TraceError(("%s: fail7\n", __FUNCTION__));
fail6:
    TraceError(("%s: fail6\n", __FUNCTION__));

    XmFreeMemory(valueBuffer);

fail5:
    TraceError(("%s: fail5\n", __FUNCTION__));

fail4:
    TraceError(("%s: fail4\n", __FUNCTION__));

    XmFreeMemory(destNameBuffer);

fail3:
    TraceError(("%s: fail3\n", __FUNCTION__));
fail2:
    TraceError(("%s: fail2\n", __FUNCTION__));

    XmFreeMemory(srcNameBuffer);

fail1:
    TraceError(("%s: fail1 (%08x)\n", __FUNCTION__, status));
}

static PWCHAR
string_to_wstring(PCSTR src)
{
    size_t len;
    PWCHAR res;
    unsigned x;

    len = strlen(src) + 1;
    res = XmAllocateZeroedMemory(len * sizeof(WCHAR));
    if (!res)
        return NULL;
    for (x = 0; x < len; x++)
        res[x] = src[x];
    return res;
}

static NTSTATUS
get_unicode_char_from_utf8(const unsigned char *start,
                           const unsigned char **next,
                           unsigned *resp)
{
    unsigned len;
    ULONG res;
    unsigned x;

    if (start[0] < 0x80) {
        len = 1;
        res = start[0];
    } else if ((start[0] & 0xe0) == 0xc0) {
        len = 2;
        res = start[0] & ~0xe0;
    } else if ((start[0] & 0xf0) == 0xe0) {
        len = 3;
        res = start[0] & ~0xf0;
    } else if ((start[0] & 0xf8) == 0xf0) {
        len = 4;
        res = start[0] & ~0xf8;
    } else {
        return STATUS_DATA_ERROR;
    }
    for (x = 1; x < len; x++) {
        if ((start[x] & 0xc0) != 0x80)
            return STATUS_DATA_ERROR;
        res <<= 6;
        res |= start[x] & ~0xc0;
    }
    if ((res >= 0xd800 && res <= 0xdfff) ||
        res == 0xfffe || res == 0xffff)
        return STATUS_DATA_ERROR;
    /* Check that we have a minimal encoding. */
    switch (len) {
    case 1:
        /* Trivially minimal */
        break;
    case 2:
        if (res < 0x80)
            return STATUS_DATA_ERROR;
        break;
    case 3:
        if (res < 0x800)
            return STATUS_DATA_ERROR;
        break;
    case 4:
        if (res < 0x1000)
            return STATUS_DATA_ERROR;
        break;
    default:
        TraceBugCheck(("huh?  decoded %d UTF-8 bytes\n", len));
    }
    *next = start + len;
    *resp = res;
    return STATUS_SUCCESS;
}

static void
encode_utf16(WCHAR **outp, unsigned unicode_char)
{
    WCHAR *out = *outp;
    XM_ASSERT(!(unicode_char >= 0xd800 && unicode_char < 0xe000));
    XM_ASSERT(unicode_char < 0x110000);
    if (unicode_char < 0x10000) {
        *out = (WCHAR)unicode_char;
        *outp = out + 1;
    } else {
        unicode_char -= 0x10000;
        out[0] = (WCHAR)(((unicode_char >> 10) & 0x3ff) | 0xd800);
        out[1] = (WCHAR)((unicode_char & 0x3ff) | 0xdc00);
        *outp = out + 2;
    }
}

static PWCHAR
utf8_to_utf16(const unsigned char *src)
{
    unsigned nr_wchars;
    unsigned unicode_char;
    NTSTATUS status;
    const unsigned char *next;
    PWCHAR res;
    PWCHAR out;

    nr_wchars = 0;
    next = src;
    while (*next != 0) {
        status = get_unicode_char_from_utf8(next, &next, &unicode_char);
        if (!NT_SUCCESS(status))
            return NULL;
        if (unicode_char >= 0x110000) {
            /* This is in some sense a valid unicode character, but we
               it can't be represented in UTF-16, so we have to
               fail. */
            return NULL;
        }
        if (unicode_char >= 0x10000) {
            nr_wchars += 2;
        } else {
            nr_wchars++;
        }
    }

    res = XmAllocateMemory((nr_wchars + 1) * sizeof(WCHAR));
    if (!res)
        return NULL;
    next = src;
    out = res;
    while (*next != 0) {
        status = get_unicode_char_from_utf8(next, &next, &unicode_char);
        XM_ASSERT(NT_SUCCESS(status));
        encode_utf16(&out, unicode_char);
    }
    *out = 0;

    return res;
}

static NTSTATUS
read_multi_sz(const char *prefix, const char *node, void **data,
              size_t *data_size)
{
    char *path;
    unsigned x;
    size_t this_len;
    char *this_entry;
    WCHAR *this_entry_wide;
    WCHAR *accumulator;
    WCHAR *new_accumulator;
    size_t accumulator_len;
    NTSTATUS status;

    accumulator = NULL;
    accumulator_len = 0;
    x = 0;
    while (1) {
        status = STATUS_INSUFFICIENT_RESOURCES;

        path = Xmasprintf("%s/%s/%d", prefix, node, x);
        if (!path)
            goto err;
        status = xenbus_read(XBT_NIL, path, &this_entry);
        XmFreeMemory(path);
        if (status == STATUS_OBJECT_NAME_NOT_FOUND)
            break;
        if (!NT_SUCCESS(status))
            goto err;
        status = STATUS_INSUFFICIENT_RESOURCES;
        this_entry_wide = utf8_to_utf16((unsigned char *)this_entry);
        XmFreeMemory(this_entry);
        if (!this_entry_wide)
            goto err;
        this_len = wcslen(this_entry_wide);
        new_accumulator = XmAllocateZeroedMemory(
            (accumulator_len + this_len + 1) * sizeof(WCHAR));
        if (!new_accumulator) {
            XmFreeMemory(this_entry_wide);
            goto err;
        }
        memcpy(new_accumulator, accumulator, accumulator_len * sizeof(WCHAR));
        memcpy(new_accumulator + accumulator_len + 1,
               this_entry_wide,
               this_len * sizeof(WCHAR));
        XmFreeMemory(this_entry_wide);
        accumulator_len += this_len;
        XmFreeMemory(accumulator);
        accumulator = new_accumulator;
        new_accumulator = NULL;

        x++;
    }

    new_accumulator =
        XmAllocateZeroedMemory((accumulator_len + 2) * sizeof(WCHAR));
    if (!new_accumulator)
        goto err;
    memcpy(new_accumulator, accumulator, accumulator_len * sizeof(WCHAR));
    XmFreeMemory(accumulator);
    *data = new_accumulator;
    *data_size = (accumulator_len + 2) * sizeof(WCHAR);
    return STATUS_SUCCESS;
err:
    XmFreeMemory(accumulator);
    return status;
}

VOID
XenSetRegistryValueFromXenstore(
    IN  const char *prefix,
    IN  const char *item,
    IN  HANDLE reg_area
    )
{
    char *path;
    NTSTATUS status;
    char *type;
    void *data_utf8;
    void *data;
    size_t data_size;
    char *typepath;
    char *datapath;
    DWORD reg_type;
    UNICODE_STRING valueNameString;
    PWCHAR wide_name;
    char *name;
    char *namepath;

    path = NULL;
    type = NULL;
    data = NULL;
    data_utf8 = NULL;
    typepath = NULL;
    datapath = NULL;
    wide_name = NULL;
    namepath = NULL;
    name = NULL;

    path = Xmasprintf("%s/%s", prefix, item);
    if (!path)
        goto err;
    namepath = Xmasprintf("%s/name", path);
    if (!namepath)
        goto err;
    status = xenbus_read(XBT_NIL, namepath, &name);
    if (!NT_SUCCESS(status))
        goto err;
    wide_name = string_to_wstring(name);
    if (!wide_name)
        goto err;
    RtlInitUnicodeString(&valueNameString, wide_name);
    typepath = Xmasprintf("%s/type", path);
    if (!typepath)
        goto err;
    status = xenbus_read(XBT_NIL, typepath, &type);
    if (!NT_SUCCESS(status))
        goto err;
    status = STATUS_SUCCESS;
    if (!strcmp(type, "none")) {
        data = NULL;
        data_size = 0;
        reg_type = REG_NONE;
    } else if (!strcmp(type, "string") || !strcmp(type, "env_string")) {
        datapath = Xmasprintf("%s/data", path);
        if (!datapath)
            goto err;
        status = xenbus_read(XBT_NIL, datapath, (PSTR *)&data);
        status = xenbus_read(XBT_NIL, datapath, (PSTR *)&data_utf8);
        if (!NT_SUCCESS(status))
            goto err;
        data = utf8_to_utf16(data_utf8);
        if (!data) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto err;
        }
        data_size = (wcslen(data) + 1) * sizeof(WCHAR);
        if (!strcmp(type, "string"))
            reg_type = REG_SZ;
        else
            reg_type = REG_EXPAND_SZ;
    } else if (!strcmp(type, "binary")) {
        status = xenbus_read_bin(XBT_NIL, path, "data", &data, &data_size);
        reg_type = REG_BINARY;
    } else if (!strcmp(type, "dword")) {
        ULONG64 tmp;
        status = xenbus_read_int(XBT_NIL, path, "data", &tmp);
        if (!NT_SUCCESS(status))
            goto err;
        if (tmp > 0xffffffff) {
            status = STATUS_DATA_ERROR;
            goto err;
        }
        data = XmAllocateMemory(sizeof(DWORD));
        if (!data)
            goto err;
        *(DWORD *)data = (DWORD)tmp;
        reg_type = REG_DWORD;
        data_size = sizeof(DWORD);
    } else if (!strcmp(type, "multi_sz")) {
        status = read_multi_sz(path, "data", &data, &data_size);
        reg_type = REG_MULTI_SZ;
    } else if (!strcmp(type, "qword")) {
        data = XmAllocateMemory(sizeof(ULONG64));
        if (!data)
            goto err;
        status = xenbus_read_int(XBT_NIL, path, "data", data);
        reg_type = REG_QWORD;
        data_size = sizeof(ULONG64);
    } else if (!strcmp(type, "remove")) {
        status = ZwDeleteValueKey(reg_area, &valueNameString);
        if (!NT_SUCCESS(status))
            TraceWarning(("Failed to remove %wZ (%x)!\n", &valueNameString,
                          status));
        goto err;
    } else {
        TraceError(("Unknown xenstore registry type %s\n", type));
        goto err;
    }
    if (!NT_SUCCESS(status)) {
        TraceWarning(("%x reading %s/data\n", status, path));
        goto err;
    }

    status = ZwSetValueKey(reg_area,
                           &valueNameString,
                           0,
                           reg_type,
                           data,
                           (DWORD)data_size);
    if (!NT_SUCCESS(status))
        TraceWarning(("Failed to set %wZ from xenstore (%x)!\n",
                      &valueNameString, status));

err:
    XmFreeMemory(wide_name);
    XmFreeMemory(name);
    XmFreeMemory(namepath);
    XmFreeMemory(type);
    XmFreeMemory(data);
    XmFreeMemory(data_utf8);
    XmFreeMemory(path);
    XmFreeMemory(typepath);
    XmFreeMemory(datapath);
    return;
}
