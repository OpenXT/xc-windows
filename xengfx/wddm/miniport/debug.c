//
// debug.c - Xen Windows PV WDDM Miniport Driver debugging support.
//
// Copyright (c) 2011 Citrix, Inc. - All rights reserved.
//

/*
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


#include "xengfxwd.h"

VOID
XenGfxOpenDebugLog(XENGFX_DEVICE_EXTENSION *pXenGfxExtension)
{
    NTSTATUS Status;
    UNICODE_STRING DebugLogName;
    OBJECT_ATTRIBUTES ObjectAttrs;
    IO_STATUS_BLOCK Iosb;

    // Get file name and open if there is a name there.
    if (pXenGfxExtension->DebugLogName[0] == L'\0') {
        TraceError(("%s Trying to open a debug log file with no file name??\n", __FUNCTION__));
        return;
    }
    RtlInitUnicodeString(&DebugLogName, pXenGfxExtension->DebugLogName);

    // Specify OBJ_KERNEL_HANDLE and make this HANDLE valid in all process contexts
    // since logging can come from any process passing through our hooks.
    InitializeObjectAttributes(&ObjectAttrs, 
                               &DebugLogName,
                               OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    // Create our log file with write access, overwrite existing and also 
    // make all operations on the file synchronous. 
    Status = ZwCreateFile(&pXenGfxExtension->hDebugLog,
                          GENERIC_WRITE | SYNCHRONIZE,
                          &ObjectAttrs,
                          &Iosb,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ,
                          FILE_OVERWRITE_IF,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                          NULL,
                          0);
    if (!NT_SUCCESS(Status)) {
        TraceError(("%s Failed to open log file: 0x%x\n", __FUNCTION__, Status));
        pXenGfxExtension->hDebugLog = NULL;
    }
    else
        TraceInfo(("%s Opened debug log file: %S\n", __FUNCTION__, pXenGfxExtension->DebugLogName));
}

VOID
XenGfxCloseDebugLog(XENGFX_DEVICE_EXTENSION *pXenGfxExtension)
{
    NTSTATUS Status;

    if (pXenGfxExtension->hDebugLog == NULL)
        return;

    Status = ZwClose(pXenGfxExtension->hDebugLog);
    pXenGfxExtension->hDebugLog = NULL;
    if (NT_SUCCESS(Status))
        TraceInfo(("%s Closed debug log file: %S\n", __FUNCTION__, pXenGfxExtension->DebugLogName));
    else
        TraceError(("%s Failed to close log file handle: 0x%x\n", __FUNCTION__, Status));        
}
