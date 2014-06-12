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

#include <windows.h>
#pragma warning(push)
#pragma warning(disable: 4201)
#include <winioctl.h>
#pragma warning(pop)
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include <sys/stat.h>
#include "v4vapi.h"
#include "v4vapp.h"

ULONG
V4vDcInstallDriver(const wchar_t *driverName, const wchar_t *serviceExe, BOOL systemStart)
{
    ULONG error = ERROR_SUCCESS;
    SC_HANDLE schSCM, schService;
    DWORD startType = (systemStart ? SERVICE_SYSTEM_START : SERVICE_DEMAND_START);

    schSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCM == NULL)
        return GetLastError();

    schService = CreateServiceW(schSCM,
                                driverName,
                                driverName,
                                SERVICE_ALL_ACCESS,
                                SERVICE_KERNEL_DRIVER,
                                startType,
                                SERVICE_ERROR_NORMAL,
                                serviceExe,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL);
                                
    if (schService == NULL)
        error = GetLastError();
    else
        CloseServiceHandle(schService);

    CloseServiceHandle(schSCM);
    return error;
}

ULONG
V4vDcStartDriver(const wchar_t *driverName)
{
#define _START_SLEEP_INTERVAL 250
    ULONG error = ERROR_SUCCESS;
    ULONG i;
    BOOL  rc;
    SC_HANDLE schSCM, schService;

    schSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCM == NULL)
        return GetLastError();

    schService = OpenServiceW(schSCM,
                              driverName,
                              SERVICE_ALL_ACCESS);
    if (schService == NULL)
        return GetLastError();

    for (i = 0; i < 10; i++) {
        SetLastError(ERROR_SUCCESS);
        rc = StartService(schService, 0, NULL);
	    error = GetLastError();

        if (rc) {
		    error = ERROR_SUCCESS;
            break;
        }
        else if (error == ERROR_SERVICE_ALREADY_RUNNING)
            break;
        else if (error == ERROR_SERVICE_DATABASE_LOCKED)		    
            Sleep(_START_SLEEP_INTERVAL);    
        else
            break;
    }
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCM);
    return error;
}

ULONG
V4vDcOpenDeviceFile(const wchar_t *fileName, HANDLE *deviceOut)
{
#define _MAX_DEVICE_NAME 128
    wchar_t completeDeviceName[_MAX_DEVICE_NAME];
    HANDLE  device;

    _snwprintf_s(completeDeviceName,
		         _countof(completeDeviceName),
		         _TRUNCATE,
		         L"\\\\.\\Global\\%s",
		         fileName);

    device = CreateFileW(completeDeviceName,
                         GENERIC_READ, FILE_SHARE_READ,
				         NULL, OPEN_EXISTING,
				         FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OVERLAPPED, NULL);
    if (device == INVALID_HANDLE_VALUE)
        return GetLastError();
    
    if (deviceOut != NULL)
        *deviceOut = device;   
    else
        CloseHandle(device);
   
    return ERROR_SUCCESS;
}

ULONG
V4vDcStopDriver(const wchar_t *driverName)
{
#define _STOP_SLEEP_INTERVAL 500
    SC_HANDLE       schSCM, schService;
    BOOL            rc;
    SERVICE_STATUS  serviceStatus;
    int             i;
    ULONG           error;

    schSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCM == NULL)
        return GetLastError();

    schService = OpenServiceW(schSCM, driverName, SERVICE_ALL_ACCESS);
    if (schService == NULL) {
	    error = GetLastError();
	    CloseServiceHandle(schSCM);
	    return error;
    }

    rc = ControlService(schService, SERVICE_CONTROL_STOP, &serviceStatus);
    if (!rc) {
	    error = GetLastError();
	    CloseServiceHandle(schService);
	    CloseServiceHandle(schSCM);
	    return error;
    }
   
    error = ERROR_GEN_FAILURE;
    for (i = 0; i < 6; i++) {
        QueryServiceStatus(schService, &serviceStatus);
	    if (serviceStatus.dwCurrentState == SERVICE_STOPPED) {
		    error = ERROR_SUCCESS;
            break;
	    }
        Sleep(_STOP_SLEEP_INTERVAL);
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCM);
    return error;
}

ULONG
V4vDcRemoveDriver(const wchar_t *driverName)
{
    SC_HANDLE schSCM, schService;
    BOOL      rc;
    ULONG     error = ERROR_SUCCESS;

    schSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCM == NULL)
        return GetLastError();

    schService = OpenServiceW(schSCM,
                              driverName,
                              SERVICE_ALL_ACCESS);
    if (schService == NULL) {
	    error = GetLastError();
	    CloseServiceHandle(schSCM);
	    return error;
    }

    rc = DeleteService(schService);
    if (!rc)
        error = GetLastError();

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCM);
    return error;
}
