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

/* Utility functions to encode and decode UTF-8 */
#ifndef NDIS60_MINIPORT
#pragma warning(push, 3)
#include "precomp.h"
#pragma warning(pop)
#else
#include "common.h"
#endif

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

PWCHAR
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
