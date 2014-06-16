//
// xenvesa-registry.c - Xen Windows Miniport Driver Registry helper routines.
//
// Copyright (c) 2012 Citrix, Inc.
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


#include <ntddk.h>
#include "xenvesa-miniport.h"

#define REG_CONFIG_PATH  L"\\Registry\\Machine\\System\\CurrentControlSet\\Hardware Profiles\\Current\\System\\CurrentControlSet\\Control\\VIDEO\\"

static NTSTATUS
XenVesaOpenRegistryKey(PUNICODE_STRING PathStr, ACCESS_MASK Access, PHANDLE pKey, PHANDLE pRootKey)
{
    OBJECT_ATTRIBUTES   Attributes;
    NTSTATUS            Status;
    HANDLE              Key;
    ULONG               Disposition;


    InitializeObjectAttributes(&Attributes, PathStr, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        pRootKey? *pRootKey : NULL, NULL);

    Status = ZwOpenKey(&Key, Access, &Attributes);

    if (Status == STATUS_OBJECT_NAME_NOT_FOUND && pRootKey) {
        Status = ZwCreateKey(&Key, GENERIC_READ | GENERIC_WRITE | KEY_CREATE_SUB_KEY, &Attributes, 0, NULL, 
            REG_OPTION_NON_VOLATILE,    &Disposition);

    }
    if (Status != STATUS_SUCCESS){
        DbgPrint("XenVesaOpenRegistryKey Failed to read/create %ws with %d\n", PathStr->Buffer, Status);
        Key = NULL;
    }

    *pKey = Key;
    return Status;        
}

static NTSTATUS
XenVesaReadRegistryValue(PXEN_VESA_DEVICE_EXTENSION XenVesaExt, HANDLE Key, PWCHAR KeyName,
                              PUNICODE_STRING strValue)
{
    PKEY_VALUE_FULL_INFORMATION     Buffer = NULL;
    ULONG                           Size = 0;
    NTSTATUS                        Status;
    UNICODE_STRING                  NameStr;

    RtlInitUnicodeString(&NameStr, KeyName);
    Status = ZwQueryValueKey(Key, &NameStr, KeyValueFullInformation, Buffer, Size, &Size);
 
    if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL)
        return Status;

    Buffer = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, Size, XENVESA_TAG);

    Status = ZwQueryValueKey(Key, &NameStr, KeyValueFullInformation, Buffer, Size, &Size);
    
    RtlInitUnicodeString(strValue, Buffer->Name);
    ExFreePoolWithTag(Buffer, XENVESA_TAG);

    return Status;
}

static int
XenVesaParseVideoString(PWCHAR string, ULONG length)
{
    int   i;
    wchar_t startChar[] = L"{";

    for (i = 0; i < (int)length; i++){

        if (!wcsncmp(&string[i], &startChar[0], 1)) return i;
    }
    return (int)length + 1;
}

static NTSTATUS
XenVesaGetVideoGuidString(PXEN_VESA_DEVICE_EXTENSION XenVesaExt, PUNICODE_STRING VideoString)
{
    NTSTATUS                        Status;
    HANDLE                          Key;
    ULONG                           index; 
    UNICODE_STRING                  PathStr;
    UNICODE_STRING                  RegVideoString;

    RtlInitUnicodeString(&PathStr, L"\\Registry\\Machine\\Hardware\\devicemap\\video");
    Status = XenVesaOpenRegistryKey(&PathStr, GENERIC_READ, &Key, FALSE);
    if (Status != 0) return Status;

    Status = XenVesaReadRegistryValue(XenVesaExt, Key, L"\\Device\\Video0", &RegVideoString);
    if (Status != STATUS_SUCCESS) {
        ZwClose(Key);
        return Status;
    }

    index = XenVesaParseVideoString(RegVideoString.Buffer, RegVideoString.Length);
    if (index > RegVideoString.Length) {
        ZwClose(Key);
        return STATUS_NOT_FOUND;
    }

    RtlInitUnicodeString(VideoString, &RegVideoString.Buffer[index]);
    ZwClose(Key);
    return 0;
}

static NTSTATUS
XenVesaOpenRootKey(PCWCHAR KeyName, PHANDLE pKey)
{
    UNICODE_STRING  uKeyName;
    ACCESS_MASK     RootKeyMask = KEY_CREATE_SUB_KEY | GENERIC_READ |GENERIC_WRITE;

    RtlInitUnicodeString(&uKeyName, KeyName);
    return XenVesaOpenRegistryKey(&uKeyName, RootKeyMask, pKey, NULL);
}

static NTSTATUS
XenVesaOpenVideoKey(PXEN_VESA_DEVICE_EXTENSION XenVesaExt, PCUNICODE_STRING pVideoString, PHANDLE pKey, PHANDLE pRootKey)
{
    NTSTATUS        Status;
    HANDLE          VideoKey;
    HANDLE          VideoKey1;
    UNICODE_STRING  VideoName;

    //Open the two subkeys in pVideoString

    RtlInitUnicodeString(&VideoName, pVideoString->Buffer);
    VideoName.Length -= (sizeof(L"\\0000") -2);
    Status = XenVesaOpenRegistryKey(&VideoName, GENERIC_WRITE |GENERIC_READ |KEY_CREATE_SUB_KEY,
        &VideoKey, pRootKey);
        
    if (Status != STATUS_SUCCESS) return Status;
    ZwClose(VideoKey);

    //Create/open the "0000" key
    RtlInitUnicodeString(&VideoName, pVideoString->Buffer);
    Status = XenVesaOpenRegistryKey(&VideoName, GENERIC_WRITE |GENERIC_READ |KEY_CREATE_SUB_KEY,
        &VideoKey1, pRootKey);
    if (Status == STATUS_SUCCESS) {
        *pKey = VideoKey1;
    }
    return Status;
}

static NTSTATUS
XenVesaSetDefaultSetting(HANDLE Key, PCWCHAR DefaultStr, DWORD DefaultValue)
{
    NTSTATUS        Status;
    UNICODE_STRING  DefaultSetting;
    
    RtlInitUnicodeString(&DefaultSetting, DefaultStr);
    Status = ZwSetValueKey(Key, &DefaultSetting, 0, REG_DWORD, &DefaultValue, sizeof(DWORD));
    return Status;
}

static NTSTATUS
XenVesaSetVideoResolution(PXEN_VESA_DEVICE_EXTENSION XenVesaExt, HANDLE Key)
{
    NTSTATUS        Status;
    PVBE_MODE_INFO  VbeModeInfo = &(XenVesaExt->VbeModeInfo[XenVesaExt->VbeCurrentMode]);

    Status = XenVesaSetDefaultSetting(Key, L"DefaultSettings.BitsPerPel",
                                      VbeModeInfo->BitsPerPixel);
    if (Status != 0)
        DbgPrint("XenVesaSetVideoResolution Write default BitsPerPel failed\n");
    
    Status = XenVesaSetDefaultSetting(Key, L"DefaultSettings.XResolution", 
                                      VbeModeInfo->XResolution);
    if (Status != 0)
        DbgPrint("XenVesaSetVideoResolution Write Default XResolution failed\n");

    Status = XenVesaSetDefaultSetting(Key, L"DefaultSettings.YResolution",
                                      VbeModeInfo->YResolution);
    if (Status != 0)
        DbgPrint("XenVesaSetVideoResolution Write Default YResolution failed\n");

    Status = XenVesaSetDefaultSetting(Key, L"XenVesaDriverInstalled", 1);
    if (Status != 0)
        DbgPrint("XenVesaSetVideoResolution Write Installed flag failed\n");
    return Status;
}

void __stdcall XenVesaGetRegistryPath( PXEN_VESA_DEVICE_EXTENSION XenVesaExt, PWSTR RegistryPath )
{
    int index = XenVesaParseVideoString(RegistryPath, wcslen(RegistryPath));
    RtlInitUnicodeString(&XenVesaExt->RegistryPath, &RegistryPath[index]);
}

static NTSTATUS
SetVideoPortReg(PXEN_VESA_DEVICE_EXTENSION XenVesaExt, 
                                  PWSTR DefaultSetting, ULONG Value)
{
    NTSTATUS Status;

    Status = XenVideoPortSetRegistryParameters(XenVesaExt, DefaultSetting, 
                                            (PVOID)&Value, sizeof(REG_DWORD));
    if (Status != STATUS_SUCCESS) 
        DbgPrint("SetVideoPortReg Failed to set %ws\n", DefaultSetting);
    return Status;
}

static NTSTATUS
XenVesaSetVideoPortRegistry(PXEN_VESA_DEVICE_EXTENSION XenVesaExt)
{
    NTSTATUS        Status;
    PVBE_MODE_INFO  defaultMode = &XenVesaExt->VbeModeInfo[XenVesaExt->VbeCurrentMode];
    
    if (Status = SetVideoPortReg(XenVesaExt, L"DefaultSettings.BitsPerPel", 
                            defaultMode->BitsPerPixel) != STATUS_SUCCESS)
        return Status;

    if (Status = SetVideoPortReg(XenVesaExt, L"DefaultSettings.XResolution", 
                                 defaultMode->XResolution) != STATUS_SUCCESS)
        return Status;                                               

     return SetVideoPortReg(XenVesaExt, L"DefaultSettings.YResolution",
                                 defaultMode->YResolution);
}

NTSTATUS
XenVesaSetRegistryDeviceResolution(PXEN_VESA_DEVICE_EXTENSION XenVesaExt)
{
    NTSTATUS                    Status;
    HANDLE                      Key;
    HANDLE                      RootKey;
    UNICODE_STRING              strXRes;
    UNICODE_STRING				PathPrefix; 

    Status = XenVesaOpenRootKey(REG_CONFIG_PATH, &RootKey);
    if (Status != 0) {
        DbgPrint("XenVesaSetRegistryDeviceResolution Failed to open device registry path %ws\n", REG_CONFIG_PATH);
        return Status;
    }

    Status = XenVesaOpenVideoKey(XenVesaExt, &XenVesaExt->RegistryPath, &Key, &RootKey);
    if (Status != STATUS_SUCCESS) {
        return Status;
    }

    Status = XenVesaReadRegistryValue(XenVesaExt, Key, L"XenVesaDriverInstalled", &strXRes);

    //If this hasn't been set, set it now.
    if (Status == STATUS_OBJECT_NAME_NOT_FOUND) {
        XenVesaSetVideoPortRegistry(XenVesaExt);
        XenVesaSetVideoResolution(XenVesaExt, Key);
    }

    ZwClose(Key);
    return 0;
}
