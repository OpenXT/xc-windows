/*
 * Copyright (c) 2010 Citrix Systems, Inc.
 * Copyright (c) 2016 Assured Information Security, Inc
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
#include <powrprof.h>
#include <stdlib.h>
#include <stdio.h>
#include <strsafe.h>

#define SIZECHARS(x) (sizeof(x)/sizeof(TCHAR))

//
// Enumerate Functions.
//
typedef 
DWORD
(WINAPI *POWER_ENUMERATE) (
    __in_opt HKEY RootPowerKey,
    __in_opt CONST GUID *SchemeGuid,
    __in_opt CONST GUID *SubGroupOfPowerSettingsGuid,
    __in POWER_DATA_ACCESSOR AccessFlags,
    __in ULONG Index,
    __out_bcount_opt(*BufferSize) UCHAR *Buffer,
    __inout DWORD *BufferSize
    );

typedef 
DWORD
(WINAPI *POWER_READ_FRIENDLY_NAME) (
    __in_opt HKEY RootPowerKey,
    __in_opt CONST GUID *SchemeGuid,
    __in_opt CONST GUID *SubGroupOfPowerSettingsGuid,
    __in_opt CONST GUID *PowerSettingGuid,
    __out_bcount_opt(*BufferSize) PUCHAR Buffer,
    __inout LPDWORD BufferSize
    );

//
// Write functions.
//
typedef 
DWORD
(WINAPI *POWER_WRITE_AC_VALUE_INDEX) (
    __in_opt HKEY RootPowerKey,
    __in CONST GUID *SchemeGuid,
    __in_opt CONST GUID *SubGroupOfPowerSettingsGuid,
    __in_opt CONST GUID *PowerSettingGuid,
    __in DWORD AcValueIndex
    );

typedef 
DWORD
(WINAPI *POWER_WRITE_DC_VALUE_INDEX) (
    __in_opt HKEY RootPowerKey,
    __in CONST GUID *SchemeGuid,
    __in_opt CONST GUID *SubGroupOfPowerSettingsGuid,
    __in_opt CONST GUID *PowerSettingGuid,
    __in DWORD DcValueIndex
    );

POWER_ENUMERATE pPowerEnumerate = NULL;
POWER_READ_FRIENDLY_NAME pPowerReadFriendlyName = NULL;
POWER_WRITE_AC_VALUE_INDEX pPowerWriteACValueIndex = NULL;
POWER_WRITE_DC_VALUE_INDEX pPowerWriteDCValueIndex = NULL;


void PowerDisplayError(DWORD error)
{
    wchar_t *messageBuffer = NULL;
    DWORD ret;

    ret = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                         NULL, 
                         error,
                         MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                         (wchar_t*)&messageBuffer,
                         0,  
                         NULL);
    if (ret == 0) {
        return;
    }
    
    // [XC-4655] This should never be used in a Windows service
    // since it's not allowed to interact with the desktop
//    MessageBoxW(NULL, messageBuffer, L"PowerOpts Error", MB_OK);

    if (messageBuffer != NULL) {
        LocalFree(messageBuffer);
    }
}

#define POWER_BUFFER_SIZE 2048

static int PowerDisableHybridSleep(void)
{
    DWORD i1 = 0, i2;
    DWORD ret, gsize = sizeof(GUID), bsize;
    GUID scheme, setting;
    wchar_t buf[(POWER_BUFFER_SIZE - 1)/sizeof(wchar_t)];
	int stat = 0;

    // Level one, enum the power schemes present
    do {
        // Each scheme is a GUID
        ret = pPowerEnumerate(NULL, NULL, NULL, ACCESS_SCHEME, i1, (UCHAR*)&scheme, &gsize);
        if (ret != ERROR_SUCCESS) {
            break;
        }

        // Level two, enum the individual settings for the sleep subgroup for this scheme
        i2 = 0;
        do {
            // Each individual setting w/in a scheme and subgroup is also a GUID
            ret = pPowerEnumerate(NULL, &scheme, &GUID_SLEEP_SUBGROUP, ACCESS_INDIVIDUAL_SETTING, i2, (UCHAR*)&setting, &gsize);
            if (ret != ERROR_SUCCESS) {
                // This is expected when there are no more power schemes
                break;
            }

            // Read each friendly name and find "Allow hybrid sleep"
            bsize = POWER_BUFFER_SIZE;
            ret = pPowerReadFriendlyName(NULL, &scheme, &GUID_SLEEP_SUBGROUP, &setting, (UCHAR*)buf, &bsize);
            if (ret != ERROR_SUCCESS) {
                // [XC-4655] Special case the return code of ERROR_FILE_NOT_FOUND
                // This is returned when there are no more power schemes to enumerate
                if (ret != ERROR_FILE_NOT_FOUND) {
                    PowerDisplayError(ret);
                    stat = -6;
                }
                break;
            }

            if (_wcsnicmp(buf, L"allow hybrid sleep", bsize/sizeof(wchar_t)) == 0) {

                // Set the AC and DC value indices for this setting to 0 which sets a value of OFF
                (void)pPowerWriteACValueIndex(NULL, &scheme, &GUID_SLEEP_SUBGROUP, &setting, 0);                

                (void)pPowerWriteDCValueIndex(NULL, &scheme, &GUID_SLEEP_SUBGROUP, &setting, 0);               
            }

            i2++;
        } while (TRUE);

        i1++;
    } while (TRUE);

    return stat;
}

int LoadPowerProfDll()
{
    HMODULE hModule = NULL;
    TCHAR NewDevPath[MAX_PATH];
    //
    // Load the entry points into the POWRPROF DLL...
    //
    GetSystemDirectory(NewDevPath, SIZECHARS(NewDevPath));
    StringCchCat (NewDevPath, SIZECHARS(NewDevPath), TEXT("\\POWRPROF.DLL"));
    hModule = LoadLibrary(NewDevPath);
    if (!hModule)
    {
		return -1;
	}

	pPowerEnumerate = (POWER_ENUMERATE)GetProcAddress(hModule, "PowerEnumerate");
    pPowerReadFriendlyName = (POWER_READ_FRIENDLY_NAME)GetProcAddress(hModule, "PowerReadFriendlyName");
    pPowerWriteACValueIndex = (POWER_WRITE_AC_VALUE_INDEX)GetProcAddress(hModule, "PowerWriteACValueIndex");
    pPowerWriteDCValueIndex = (POWER_WRITE_DC_VALUE_INDEX)GetProcAddress(hModule, "PowerWriteDCValueIndex");

    if (!pPowerEnumerate || !pPowerReadFriendlyName || !pPowerWriteACValueIndex || !pPowerWriteDCValueIndex)
    {
//@@@		MessageBox(hWnd, "Error loading Wifi API procedure(s)", "Error", MB_OK);
		return -2;
	}

	return 0;
}

int poweropts()
{
    OSVERSIONINFO osvi = {0};

    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    if (!GetVersionEx((OSVERSIONINFO*)&osvi)) {
        PowerDisplayError(GetLastError());
        return -1;
	}
    
    if (osvi.dwMajorVersion < 6) {
//        MessageBoxW(NULL, L"This utility only runs on Windows Vista and later operating systems", L"PowerOpts Error", MB_OK);
        return -2;
    }

	if (LoadPowerProfDll() != 0) {
		return -3;
	}

    //
    // May use this for other power settings later. For now, use it to turn off
    // hybrid-sleep settings
    //
    // [XC-4655] Propagate the final status back to the caller
    return PowerDisableHybridSleep();
}
