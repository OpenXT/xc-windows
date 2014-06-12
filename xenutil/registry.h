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

#ifndef _REGISTRY_H
#define _REGISTRY_H

extern NTSTATUS XenCreateRegistryKey(
    IN  HANDLE          Parent,
    IN  const WCHAR     *Path,
    IN  ACCESS_MASK     Access,
    OUT PHANDLE         pKey
    );

extern NTSTATUS XenOpenRegistryKey(
    IN  const WCHAR     *Path,
    IN  ACCESS_MASK     Access,
    OUT PHANDLE         pKey
    );

extern NTSTATUS XenReadRegistryValue(
    IN  const WCHAR                     *Path,
    IN  const WCHAR                     *Name,
    OUT PKEY_VALUE_PARTIAL_INFORMATION  *pInfo
    );

extern VOID XenMoveRegistryValues(
    IN  HANDLE SourceKey,
    IN  HANDLE DestinationKey
    );

extern VOID XenSetRegistryValueFromXenstore(
    IN  const CHAR  *Prefix,
    IN  const CHAR  *Item,
    IN  HANDLE      DestinationKey
    );

#endif  // _REGISTRY_H
