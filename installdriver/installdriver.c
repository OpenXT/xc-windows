/*
 * Copyright (c) 2011 Citrix Systems, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <windows.h>
#include <newdev.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <regstr.h>
#include <strsafe.h>

BOOL
InstallSelectedDriver(
    IN HWND  hwndParent,
    IN HDEVINFO  DeviceInfoSet,
    IN LPCTSTR  Reserved,
    IN BOOL  Backup,
    OUT PBOOL  bRebootRequired
    );

#define SIZECHARS(x) (sizeof(x)/sizeof(TCHAR))

DWORD
InstallInfOnDevice(
    IN HWND hWnd,
    HDEVINFO DeviceInfoSet,
    PSP_DEVINFO_DATA DeviceInfoData,
    PTSTR Inf,
    BOOL DelayInstall
    )
{
    DWORD Err = NO_ERROR;
    SP_DEVINSTALL_PARAMS DeviceInstallParams;
    BOOL Reboot = FALSE;

    if (!SetupDiSetSelectedDevice(DeviceInfoSet, DeviceInfoData)) {
        Err = GetLastError();
        goto exit;
    }

    DeviceInstallParams.cbSize = sizeof(DeviceInstallParams);
    if (!SetupDiGetDeviceInstallParams(DeviceInfoSet,
                                       DeviceInfoData,
                                       &DeviceInstallParams)) {
        Err = GetLastError();
        goto exit;
    }

    //
    // Set DriverPath to the path of the INF that we want to install from.
    // Set the DI_ENUMSINGLEINFO so setupapi builds up a driver list just from
    //   this specific INF.
    // Set DI_DONOTCALLCONFIGMG so that we won't call kernel PnP when installing
    //   the driver.  This will do all the install actions except stop/start the 
    //   device so it won't start using the new driver until a reboot.
    //
    StringCchCopy(DeviceInstallParams.DriverPath, 
                  SIZECHARS(DeviceInstallParams.DriverPath),
                  Inf);
    DeviceInstallParams.hwndParent = hWnd;
    DeviceInstallParams.Flags |= (DI_ENUMSINGLEINF | DI_QUIETINSTALL);
    if (DelayInstall) {
        DeviceInstallParams.Flags |= DI_DONOTCALLCONFIGMG;
    }
    DeviceInstallParams.FlagsEx |= DI_FLAGSEX_ALLOWEXCLUDEDDRVS;
    if (!SetupDiSetDeviceInstallParams(DeviceInfoSet,
                                       DeviceInfoData,
                                       &DeviceInstallParams)) {
        Err = GetLastError();
        goto exit;
    }

    //
    // Build up a list of drivers from the specified INFs
    //
    if (!SetupDiBuildDriverInfoList(DeviceInfoSet, DeviceInfoData, SPDIT_COMPATDRIVER)) {
        Err = GetLastError();
        goto exit;
    }

    //
    // Tell setupapi and the class installers to select the best driver from the 
    // list built from the specified INF.
    //
    if (!SetupDiCallClassInstaller(DIF_SELECTBESTCOMPATDRV,
                                   DeviceInfoSet,
                                   DeviceInfoData)) {
        Err = GetLastError();
        goto exit;
    }

    //
    // Install the selected driver on the selected device without calling kernel mode
    //
    if (!InstallSelectedDriver(hWnd,
                               DeviceInfoSet,
                               NULL,
                               FALSE,
                               &Reboot)) {
        Err = GetLastError();
        goto exit;
    }

exit:
    return Err;
}


int
InstallPnPDriver(
    IN HWND hWnd,
    PTSTR HardwareId, 
    PTSTR Inf,
    BOOL DelayInstall,
    BOOL ForceUpdateDriver
    )
{
    DWORD Err = NO_ERROR;
    SP_DEVINFO_DATA DeviceInfoData;
    HDEVINFO DeviceInfoSet = INVALID_HANDLE_VALUE;
    TCHAR DeviceIds[REGSTR_VAL_MAX_HCID_LEN];
    DWORD memberIndex;
    PTSTR singleDeviceId;

    DeviceInfoSet = SetupDiGetClassDevs(NULL, NULL, NULL, DIGCF_ALLCLASSES);
    if (DeviceInfoSet == INVALID_HANDLE_VALUE) {
        Err = GetLastError();
        goto clean;
    }

    memberIndex = 0;
    DeviceInfoData.cbSize = sizeof(DeviceInfoData);
    while (SetupDiEnumDeviceInfo(DeviceInfoSet,
                                 memberIndex++,
                                 &DeviceInfoData)) {
        if (SetupDiGetDeviceRegistryProperty(DeviceInfoSet,
                                             &DeviceInfoData,
                                             SPDRP_HARDWAREID,
                                             NULL,
                                             (PBYTE)DeviceIds,
                                             sizeof(DeviceIds),
                                             NULL)) {
            for (singleDeviceId = DeviceIds;
                 *singleDeviceId;
                 singleDeviceId += lstrlen(singleDeviceId) + 1) {

                if (!lstrcmpi(HardwareId, singleDeviceId)) {
                    //
                    // Found a match.  Check if it is a phantom if PhantomOnly is
                    // TRUE
                    //
                    if (InstallInfOnDevice(hWnd, 
                                           DeviceInfoSet,
                                           &DeviceInfoData,
                                           Inf,
                                           DelayInstall) != NO_ERROR) {
                        MessageBox(hWnd, "Failed to install drivers on one of the devices", "Install Error", MB_OK);
                    }
                    if (ForceUpdateDriver)
                    {
                        BOOL reboot;
                        if (!UpdateDriverForPlugAndPlayDevices(
                                               hWnd,
                                               HardwareId,
                                               Inf,
                                               INSTALLFLAG_FORCE,
                                               &reboot))
                            MessageBox(hWnd, "Failed to force update driver for one of the devices", "Install Error", MB_OK);
                    }
                }
            }
        }
    }

clean:
    if (DeviceInfoSet != INVALID_HANDLE_VALUE) {
        SetupDiDestroyDeviceInfoList(DeviceInfoSet);
    }

    if (Err == NO_ERROR) {
        return 0;
    }
    return 1;
}

int 
DisplayError(
    HWND hWnd,
    TCHAR *ErrorName)
{
    DWORD Err = GetLastError();
    LPVOID lpMessageBuffer = NULL;
    TCHAR buf[256];

    if (FormatMessage( 
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, 
        Err,  
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMessageBuffer,  
        0,  
        NULL ))
    {
        //MessageBox(hWnd, "Wrong number of arguments", "Error", MB_OK);
        StringCchPrintf(buf, SIZECHARS(buf), TEXT("%s FAILURE: %s\n"),ErrorName,(TCHAR *)lpMessageBuffer);
        _tprintf(TEXT("%s FAILURE: %s\n"),ErrorName, (TCHAR *)lpMessageBuffer);
    }
    else 
    {
        StringCchPrintf(buf, SIZECHARS(buf),  TEXT("%s FAILURE: (0x%08x)\n"), ErrorName, Err);
        _tprintf(TEXT("%s FAILURE: (0x%08x)\n"), ErrorName, Err);
    }
    MessageBox(hWnd, buf, "Error", MB_OK);

    if (lpMessageBuffer) LocalFree( lpMessageBuffer ); // Free system buffer 

    SetLastError(Err);    
    return FALSE;
}

int
InstallRootEnumeratedDriver(
    IN HWND hWnd,
    IN LPTSTR HardwareId,
    IN LPTSTR INFFile
    )
{
    HDEVINFO DeviceInfoSet = INVALID_HANDLE_VALUE;
    SP_DEVINFO_DATA DeviceInfoData;
    GUID ClassGUID;
    TCHAR ClassName[MAX_CLASS_NAME_LEN];
    DWORD Err = NO_ERROR;
    BOOL reboot;
    LPTSTR MultiSzHardwareId = NULL;
    DWORD cbMultiSzHardwareId;

    //
    // SPDRP_HARDWAREID needs to be a multi_sz string so allocate a buffer that is
    // two characters more than the HardwareId passed in and use that buffer.
    //
    cbMultiSzHardwareId = (lstrlen(HardwareId) + 2) * sizeof(TCHAR);
    MultiSzHardwareId = malloc(cbMultiSzHardwareId);
    if (!MultiSzHardwareId) {
        MessageBox(hWnd, "Cannot allocate memory", "Error", MB_OK);
        Err = ERROR_NOT_ENOUGH_MEMORY;
        goto clean;
    }
    ZeroMemory(MultiSzHardwareId, cbMultiSzHardwareId);
    StringCbCopy(MultiSzHardwareId, cbMultiSzHardwareId, HardwareId);


    //
    // Use the INF File to extract the Class GUID. 
    //
    if (!SetupDiGetINFClass(INFFile, &ClassGUID, ClassName, sizeof(ClassName), 0)) {
        Err = GetLastError();
        DisplayError(hWnd, TEXT("GetINFClass"));
        goto clean;
    }
    
    //
    // Create the container for the to-be-created Device Information Element.
    //
    DeviceInfoSet = SetupDiCreateDeviceInfoList(&ClassGUID, 0);
    if(DeviceInfoSet == INVALID_HANDLE_VALUE) {
        Err = GetLastError();
        DisplayError(hWnd, TEXT("CreateDeviceInfoList"));
        goto clean;
    }
    
    // 
    // Now create the element. 
    // Use the Class GUID and Name from the INF file.
    //
    DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    if (!SetupDiCreateDeviceInfo(DeviceInfoSet,
                                 ClassName,
                                 &ClassGUID,
                                 NULL,
                                 0,
                                 DICD_GENERATE_ID,
                                 &DeviceInfoData)) {
        Err = GetLastError();
        DisplayError(hWnd, TEXT("CreateDeviceInfo"));
        goto clean;
    }
    
    //
    // Add the HardwareID to the Device's HardwareID property.
    //
    if(!SetupDiSetDeviceRegistryProperty(DeviceInfoSet,
                                         &DeviceInfoData,
                                         SPDRP_HARDWAREID,
                                         (LPBYTE)MultiSzHardwareId,
                                         cbMultiSzHardwareId)) {
        Err = GetLastError();
        DisplayError(hWnd, TEXT("SetDeviceRegistryProperty"));
        goto clean;
    }
    
    //
    // Transform the registry element into an actual devnode 
    // in the PnP HW tree.
    //
    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE,
                                   DeviceInfoSet,
                                   &DeviceInfoData)) {
        Err = GetLastError();
        DisplayError(hWnd, TEXT("CallClassInstaller(REGISTERDEVICE)"));
        goto clean;
    }
    
    //
    // The element is now registered. We must explicitly remove the 
    // device using DIF_REMOVE, if we encounter any failure from now on.
    //
    
    //
    // Install the Driver.  We don't actually care about @reboot, but
    // supplying it avoids an annoying popup on Windows 2000.
    //
    if (!UpdateDriverForPlugAndPlayDevices(hWnd,
                                           HardwareId,
                                           INFFile,
                                           INSTALLFLAG_FORCE,
                                           &reboot))
    {
        Err = GetLastError();
        DisplayError(hWnd, TEXT("UpdateDriverForPlugAndPlayDevices"));
        
        if (!SetupDiCallClassInstaller(DIF_REMOVE,
                                       DeviceInfoSet,
                                       &DeviceInfoData)) {
            DisplayError(hWnd, TEXT("CallClassInstaller(REMOVE)"));
        }
    }
    
    //
    //  Cleanup.
    //    
clean:
    if (DeviceInfoSet != INVALID_HANDLE_VALUE) {
        SetupDiDestroyDeviceInfoList(DeviceInfoSet);
    }

    if (MultiSzHardwareId) {
        free(MultiSzHardwareId);
    }
    
    if (Err == NO_ERROR) {
        return 0;
    } else {
        return 1;
    }
}

int
InstallINF(
    IN HWND hWnd,
    IN LPTSTR INFFile
    )
{
    TCHAR media_location[MAX_PATH];
    PTSTR ptr;

    StringCchCopy(media_location, SIZECHARS(media_location), INFFile);
    ptr = strrchr(media_location, '\\');
    if (ptr) {
        *ptr = 0;
    }
    if (!SetupCopyOEMInf(INFFile,
                         media_location,
                         SPOST_PATH,
                         0,
                         NULL,
                         0,
                         NULL,
                         NULL)) {
        MessageBox(hWnd, "Failed to install one of the INF files.", "Install Error", MB_OK);
        return 1;
    }

    return 0;
}

#define SVC_NAME "xensvc"
#define SVC_DISPLAYNAME "Citrix Tools for Virtual Machines Service"
#define SVC_DESC "Monitors and provides various metrics to XenStore"

static void
AddEventSource(
    IN LPTSTR Service
    )
{
    const TCHAR keyName[] = TEXT("SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\" SVC_NAME);
    HKEY key;
    DWORD types;

    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, keyName, 0, NULL, 0,
                       KEY_SET_VALUE, NULL, &key, NULL))
        return;

    RegSetValueEx(key, TEXT("EventMessageFile"), 0, REG_SZ,
                  (PBYTE)Service, lstrlen(Service) + 1);

    types = EVENTLOG_INFORMATION_TYPE | EVENTLOG_WARNING_TYPE |
        EVENTLOG_ERROR_TYPE;
    RegSetValueEx(key, TEXT("TypesSupported"), 0, REG_DWORD, (PBYTE)&types,
                  sizeof(types));
    RegCloseKey(key);
}

int 
ServiceInstall(
    IN HWND hWnd,
    IN LPTSTR Service
    )
{
    DWORD Err = NO_ERROR;
    SC_HANDLE hSvc = NULL;
    SC_HANDLE hMgr = NULL;
    SERVICE_DESCRIPTION desc;
    SC_ACTION restartAction[3];
    SERVICE_FAILURE_ACTIONS actions;
    SERVICE_FAILURE_ACTIONS_FLAG flag;
    OSVERSIONINFOEX info;
    ULONG WindowsVersion;
	
    info.dwOSVersionInfoSize = sizeof(info);
    WindowsVersion = 0;
    if (GetVersionEx((OSVERSIONINFO*)&info)) {
        if (((info.dwMajorVersion & ~0xff) == 0)
            && ((info.dwMinorVersion & ~0xff) == 0)) {
            WindowsVersion = (info.dwMajorVersion << 8) |
                              info.dwMinorVersion;
        }
    }

    AddEventSource(Service);

    hMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hMgr == NULL) {
        Err = GetLastError();
        goto exit;
    }

    //
    // First check if xenservice is already installed
    //
    hSvc = OpenService(hMgr, SVC_NAME, SERVICE_ALL_ACCESS);
    if (hSvc == NULL) {
        //
        // Service does not exist, so create it.
        //
        hSvc = CreateService(hMgr,                      // SCManager database
                             SVC_NAME,			        // name of service
                             SVC_DISPLAYNAME,           // name to display
                             SERVICE_ALL_ACCESS,        // desired access
                             SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS,  // service type
                             SERVICE_AUTO_START,		// start type
                             SERVICE_ERROR_NORMAL,      // error control type
                             Service,                   // service's binary
                             NULL,                      // no load ordering group
                             NULL,                      // no tag identifier
                             (((WindowsVersion >= 0x0600) || (info.wSuiteMask == 0x0300)) ?//dependencies //despite what MSDN doc says, XP Home does _not_ evaluate to VER_SUITE_PERSONAL (0x0200)
                                  "WinMgmt\0" :
                                  "Wmi\0WinMgmt\0"),          
                             NULL,                      // LocalSystem account
                             NULL);                     // no password

        if (hSvc == NULL) {
            Err = GetLastError();
            MessageBox(hWnd, "Failed to install the service.", "Install Error", MB_OK);
            goto exit;
        }

        StartService(hSvc, 0, NULL);

    } else {
        //
        // Service already exists, so just update its values.
        //
        if (!ChangeServiceConfig(hSvc,
                                 SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
                                 SERVICE_AUTO_START,           
                                 SERVICE_ERROR_NORMAL,         
                                 Service,                      
                                 NULL,                         
                                 NULL,                         
                                 (((WindowsVersion >= 0x0600) || (info.wSuiteMask == 0x0300)) ? 
                                    "WinMgmt\0" :
                                    "Wmi\0WinMgmt\0"),          
                                 NULL,                        
                                 NULL,            
                                 SVC_DISPLAYNAME)) {
            Err = GetLastError();
            MessageBox(hWnd, "Failed to update the service.", "Install Error", MB_OK);
            goto exit;
        }
    }

    //
    // In all cases change the service description.
    //
    desc.lpDescription = SVC_DESC;
    if (!ChangeServiceConfig2(hSvc, SERVICE_CONFIG_DESCRIPTION, &desc))
        DisplayError(hWnd, TEXT("ChangeServiceConfig2(...SERVICE_CONFIG_DESCRIPTION...)"));

    restartAction[0].Type = SC_ACTION_RESTART;
    restartAction[0].Delay = 4      // minutes
                           * 60     // s
                           * 1000;  // ms

    restartAction[1].Type = SC_ACTION_RESTART;
    restartAction[1].Delay = 8      // minutes
                           * 60     // s
                           * 1000;  // ms

    restartAction[2].Type = SC_ACTION_RESTART;
    restartAction[2].Delay = 12     // minutes
                           * 60     // s
                           * 1000;  // ms

    actions.dwResetPeriod = 3600;
    actions.lpRebootMsg = NULL;
    actions.lpCommand = NULL;
    actions.cActions = sizeof (restartAction) / sizeof (restartAction[0]);
    actions.lpsaActions = restartAction;

    if (!ChangeServiceConfig2(hSvc, SERVICE_CONFIG_FAILURE_ACTIONS, &actions))
        DisplayError(hWnd, TEXT("ChangeServiceConfig2(...SERVICE_CONFIG_FAILURE_ACTIONS...)"));

    flag.fFailureActionsOnNonCrashFailures = TRUE;
    /* This is expected to fail on anything other than Windows 7; just
       ignore the error. */
    ChangeServiceConfig2(hSvc, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                         &flag);

exit:
    if (hSvc != NULL) {
        CloseServiceHandle(hSvc);
    }
    if (hMgr != NULL) {
        CloseServiceHandle(hMgr);
    }
    if (Err == NO_ERROR) {
        return 0;
    } else {
        return 1;
    }
}

int 
PreInstallFromInf(
    IN HWND hWnd,
    IN LPTSTR Inf,
    IN LPTSTR InstallSection,
    IN LPTSTR ServiceSection
    )
{
    DWORD Err = NO_ERROR;
    HINF hInf = INVALID_HANDLE_VALUE;
    UINT ErrorLine;
    PVOID Context = NULL;

    hInf = SetupOpenInfFile(Inf,
                            NULL,
                            INF_STYLE_WIN4,
                            &ErrorLine);
    if (hInf == INVALID_HANDLE_VALUE) {
        Err = GetLastError();
        goto clean;
    }

    //
    // Install the service section
    //
    if (!SetupInstallServicesFromInfSection(hInf,
                                            ServiceSection,
                                            0)) {
        Err = GetLastError();
        goto clean;
    }

    Context = SetupInitDefaultQueueCallback(hWnd);

    if (!SetupInstallFromInfSection(hWnd,
                                    hInf,
                                    InstallSection,
                                    SPINST_REGISTRY | SPINST_FILES,
                                    NULL,
                                    NULL,
                                    0,
                                    SetupDefaultQueueCallback,
                                    Context,
                                    NULL,
                                    NULL)) {
        Err = GetLastError();
        goto clean;
    }

clean:
    if (Context != NULL) {
        SetupTermDefaultQueueCallback(Context);
    }
    if (hInf != INVALID_HANDLE_VALUE) {
        SetupCloseInfFile(hInf);
    }
    if (Err == NO_ERROR) {
        return 0;
    } else {
        return 1;
    }
}


//////////////////////////////////////////////////////////////////////////////////
//
// argv[1] must be one of the following flags:
//  '/p' -> argv[3] is the HardwareId and argv[4] is the full path to the INF
//          Call UpdateDriverForPlugAndPlayDevices to install drivers on a PnP
//          device.  Also check if any of the devices are currently phantoms and
//          if so mark them for reinstall so they will get their drivers installed
//          when they are reconnected to the machine.
//
//  '/i' -> argv[3] is the full path to the INF.
//          This preforms an INF install only by calling SetupCopyOEMInf.
//
//  '/r' -> argv[3] is the HardwareId and argv[4] is the full path to the INF
//          This option is used for root enumerated devices.  This api will first check
//          if there is a root enumerated device that matches the given HardwareId.  If
//          there is then it will simply update the drivers on that device by calling
//          UpdateDriverForPlugAndPlayDevices.  If it is not present yet it will create
//          the root enumerated device first and then call UpdateDriverForPlugAndPlayDevices
//          to install the drivers on it.
//  '/s' -> argv[3] is the full path to the service binary to install or update.
//          This option is used to install the xensvc service or to update its
//          configuration.
//  '/d' -> arg[3] is the full path to the INF file and argv[4] is the service section
//          to install from the INF file.
//          This option is used to install a driver service from a specified INF file.
// 
//////////////////////////////////////////////////////////////////////////////////
int _cdecl main(int argc, char *argv[])
{
    int res = 0;
    BOOL DelayInstall = FALSE;
    HWND hWnd = NULL;

    if (argc < 2) {
        MessageBox(hWnd, "Invalid number of parameters passed in", "Error", MB_OK);
        return 1;
    }

    hWnd = (HWND)(ULONG_PTR)atoi(argv[2]);

    if (!lstrcmpi(argv[1], "/p")) {
        DelayInstall = (BOOL)atoi(argv[5]);
        res = InstallPnPDriver(hWnd, argv[3], argv[4], DelayInstall, FALSE);
    } else if (!lstrcmpi(argv[1], "/u")) {
        DelayInstall = (BOOL)atoi(argv[5]);
        res = InstallPnPDriver(hWnd, argv[3], argv[4], DelayInstall, TRUE);
    } else if (!lstrcmpi(argv[1], "/r")) {
        res = InstallRootEnumeratedDriver(hWnd, argv[3], argv[4]);
    } else if (!lstrcmpi(argv[1], "/i")) {
        res = InstallINF(hWnd, argv[3]);
    } else if (!lstrcmpi(argv[1], "/s")) {
        res = ServiceInstall(hWnd, argv[3]);
    } else if (!lstrcmpi(argv[1], "/d")) {
        res = PreInstallFromInf(hWnd, argv[3], argv[4], argv[5]);
    }else {
        MessageBox(hWnd, "Invalid device install type passed in", "Error", MB_OK);
        return 1;
    }
    
    return res;
}
