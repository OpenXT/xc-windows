/*
 * Copyright (c) 2014 Citrix Systems, Inc.
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

#pragma warning(disable: 4201)
#include <stdio.h> 
#include <tchar.h>
#include <windows.h>  
#include <newdev.h>
#include <setupapi.h>

#define MAX_CLASS_NAME_LEN 32

BOOL FindExistingDevice(LPTSTR HardwareId)
{
    HDEVINFO DeviceInfoSet;
    SP_DEVINFO_DATA DeviceInfoData;
    DWORD i,err;
    BOOL Found;
    ULONG Error;

    DeviceInfoSet = SetupDiGetClassDevs(NULL, 0, 0, DIGCF_ALLCLASSES | DIGCF_PRESENT ); 
    if (DeviceInfoSet == INVALID_HANDLE_VALUE)
        MessageBox(NULL, "GetClassDevs failed", "Error", MB_OK);
    
    Found = FALSE;
    DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    for (i=0; SetupDiEnumDeviceInfo(DeviceInfoSet, i, &DeviceInfoData); i++)
    {
        DWORD DataT;
        LPTSTR p,buffer = NULL;
        DWORD buffersize = 0;

        while (!SetupDiGetDeviceRegistryProperty(DeviceInfoSet,
                                                 &DeviceInfoData,
                                                 SPDRP_HARDWAREID,
                                                 &DataT,
                                                 (PBYTE)buffer,
                                                 buffersize,
                                                 &buffersize))
        {
            if (GetLastError() == ERROR_INVALID_DATA)
            {
                break;
            }
            else if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
            {
                if (buffer) 
                    LocalFree(buffer);
                buffer = LocalAlloc(LPTR,buffersize);
            }
            else
            {
                MessageBox(NULL, "GetDeviceRegistryProperty failed", "Error", MB_OK);
                goto cleanup;
            }            
        }
        
        if (GetLastError() == ERROR_INVALID_DATA) 
            continue;
        
        for (p = buffer; (*p&&(p<&buffer[buffersize])); p += lstrlen(p) + sizeof(TCHAR))
        {   
            if (!_tcsicmp(HardwareId,p))
            {
                Found = TRUE;
                break;
            }
        }
        
        if (buffer)
            LocalFree(buffer);
        if (Found)
            break;
    }
    
    Error = GetLastError();
    if (!(Error == NO_ERROR || Error == ERROR_NO_MORE_ITEMS))
        MessageBox(NULL, "EnumDeviceInfo failed", "Error", MB_OK);
    
cleanup:
    err = GetLastError();
    SetupDiDestroyDeviceInfoList(DeviceInfoSet);
    SetLastError(err);
    
    return Found;
}

int IsAmd64(void)
{
    BOOL res;
    BOOL (*f)(HANDLE handle, PBOOL res);
    HANDLE k32;

    k32 = GetModuleHandle("kernel32");
    if (k32 == NULL) {
        MessageBox(NULL, "weird, can't find kernel32", "Error", MB_OK);
        return 0;
    }
    f = (BOOL (*)(HANDLE, PBOOL))GetProcAddress(k32, "IsWow64Process");
    if (!f)
        return 0;
    if (!f(GetCurrentProcess(), &res)) {
        MessageBox(NULL, "IsWow64Process returned error.", "Error", MB_OK);
        return 0;
    } else {
        return res;
    }
}

int GetServicePack(void)
{
    OSVERSIONINFOEX verInfo;

    verInfo.dwOSVersionInfoSize = sizeof(verInfo);
    if (GetVersionEx((POSVERSIONINFO)&verInfo)) {
        return verInfo.wServicePackMajor;
    } else {
        return -1;
    }
}


int GetProductType(void)
{
    OSVERSIONINFOEX verInfo;

    verInfo.dwOSVersionInfoSize = sizeof(verInfo);
    if (GetVersionEx((POSVERSIONINFO)&verInfo)) {
        return verInfo.wProductType;
    } else {
        return -1;
    }
}

void SetXSdllRegKey(const char *path)
{
    HKEY handle;

    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE,
                       "Software\\Citrix\\XenTools",
                       0,
                       NULL,
                       0,
                       KEY_SET_VALUE | KEY_WOW64_64KEY,
                       NULL,
                       &handle,
                       NULL) != ERROR_SUCCESS)
        return;
    RegSetValueEx(handle, "xs2.dll", 0, REG_SZ,
                  (BYTE *)path, (DWORD)(strlen(path) + 1));
    RegCloseKey(handle);
}

