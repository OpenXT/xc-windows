/*
 * Copyright (c) 2006 XenSource, Inc. All use and distribution of this 
 * copyrighted material is governed by and subject to terms and 
 * conditions as licensed by XenSource, Inc. All other rights reserved. 
 */

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

#include <windows.h>
#include <shlobj.h>
#include <process.h>
#include <powrprof.h>
#include "stdafx.h"
#include "XSAccessor.h"
#include "WMIAccessor.h"
#include "XService.h"
#include "vm_stats.h"
#include "NicInfo.h"

#include "xs2.h"
#include "xs_private.h"
#include "verinfo.h"
#include "messages.h"
#include "TSInfo.h"

#include <setupapi.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <devguid.h>
#include <wintrust.h>
#include <shellapi.h>

//////////////////////////////////////////////////////////////////////////////
//
// WINTRUST_ACTION_GENERIC_VERIFY_V2 Guid  (Authenticode)
//----------------------------------------------------------------------------
//  Assigned to the pgActionID parameter of WinVerifyTrust to verify the
//  authenticity of a file/object using the Microsoft Authenticode
//  Policy Provider,
//
//          {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
//
#define WINTRUST_ACTION_GENERIC_VERIFY_V2                       \
            { 0xaac56b,                                         \
              0xcd44,                                           \
              0x11d0,                                           \
              { 0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee } \
            }

#define SIGNER_CITRIX       "Citrix Systems, Inc"
#define SIGNER_XENSOURCE    "XenSource, Inc"

#ifdef AMD64
#define XENTOOLS_INSTALL_REG_KEY "SOFTWARE\\Wow6432Node\\Citrix\\XenTools"
#else
#define XENTOOLS_INSTALL_REG_KEY "SOFTWARE\\Citrix\\XenTools"
#endif


SERVICE_STATUS ServiceStatus; 
SERVICE_STATUS_HANDLE hStatus;  

static HANDLE hServiceExitEvent;
static ULONG WindowsVersion;
static BOOL LegacyHal = FALSE;
static HINSTANCE local_hinstance;

#define SIZECHARS(x) (sizeof((x))/sizeof(TCHAR))

// Internal routines
static void ServiceControlHandler(DWORD request);
static void ServiceControlManagerUpdate(DWORD dwExitCode, DWORD dwState);
static void ServiceMain(int argc, char** argv);
static void GetWindowsVersion();

void PrintError(const char *func, DWORD err)
{
	LPVOID lpMsgBuf;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &lpMsgBuf,
		0,
		NULL);
	DBGPRINT(("%s failed: %s (%lx)\n", func, lpMsgBuf, err));
    XenstorePrintf("control/error", "%s failed: %s (%x)", func, lpMsgBuf, err);
	LocalFree(lpMsgBuf);
}

void PrintError(const char *func)
{
	PrintError(func, GetLastError());
}

void PrintUsage()
{
	printf("Usage: xenservice [-i|-u|-c|-t]\n");
	printf("\t -i: install service\n");
	printf("\t -u: uninstall service\n");
}

HMODULE SLC_API;
HMODULE SLWGA_API;

typedef HRESULT (WINAPI *SL_GET_WINDOWS_INFORMATION_DWORD)(
    __in    PCWSTR  pwszValueName,
    __out   DWORD   *pdwValue
    );

typedef GUID SLID;

typedef enum _SL_GENUINE_STATE {
  SL_GEN_STATE_IS_GENUINE        = 0,
  SL_GEN_STATE_INVALID_LICENSE   = 1,
  SL_GEN_STATE_TAMPERED          = 2,
  SL_GEN_STATE_LAST              = 3 
} SL_GENUINE_STATE;

typedef HRESULT (WINAPI *SL_IS_GENUINE_LOCAL)(
    __in        const SLID                  *pAppId,
    __out       SL_GENUINE_STATE            *pGenuineState,
    __inout_opt VOID                        *pUnused
    );

#define WINDOWS_SLID                                                \
            { 0x55c92734,                                           \
              0xd682,                                               \
              0x4d71,                                               \
              { 0x98, 0x3e, 0xd6, 0xec, 0x3f, 0x16, 0x05, 0x9f }    \
            }

static VOID
AddLicenseInfoToStore(
    VOID
    )
{
    SLID                                appId = WINDOWS_SLID;
    SL_IS_GENUINE_LOCAL                 __SLIsGenuineLocal = NULL;
    SL_GET_WINDOWS_INFORMATION_DWORD    __SLGetWindowsInformationDWORD = NULL;
    HRESULT                             hResult;
    SL_GENUINE_STATE                    genuineState;
    DWORD                               isAllowed = 0;

    if (SLWGA_API != NULL) {
        __SLIsGenuineLocal = 
            (SL_IS_GENUINE_LOCAL)GetProcAddress(SLWGA_API, "SLIsGenuineLocal");

        if (__SLIsGenuineLocal != NULL) {
            if ((hResult = __SLIsGenuineLocal(&appId, &genuineState, NULL)) == S_OK) {
                switch (genuineState) {
                case SL_GEN_STATE_IS_GENUINE:
                    XenstorePrintf("attr/os/license", "genuine");
                    break;    
                case SL_GEN_STATE_INVALID_LICENSE:
                    XenstorePrintf("attr/os/license", "invalid");
                    break;    
                case SL_GEN_STATE_TAMPERED:
                    XenstorePrintf("attr/os/license", "tampered");
                    break;    
                case SL_GEN_STATE_LAST:
                default:
                    break;
                }
            } else {
                XsLog("SLIsGenuineLocal() failed (%08x)", hResult);
            }
        } else {
            XsLog("SLIsGenuineLocal() not available");
        }
    }

    if (SLC_API != NULL) {
        __SLGetWindowsInformationDWORD =
            (SL_GET_WINDOWS_INFORMATION_DWORD)GetProcAddress(SLC_API, "SLGetWindowsInformationDWORD");

        if (__SLGetWindowsInformationDWORD != NULL) {
            if ((hResult =__SLGetWindowsInformationDWORD(L"VirtualXP-licensing-Enabled", &isAllowed)) == S_OK) {
                if (isAllowed != 0)
                    XenstorePrintf("attr/os/virtualxp_enabled", "1");
                else
                    XenstorePrintf("attr/os/virtualxp_enabled", "0");
            } else {
                XsLog("SLGetWindowsInformationDWORD(VirtualXP-licensing-Enabled) failed (%08x)", hResult);
            }
        } else {
            XsLog("SLGetWindowsInformationDWORD() not available");
        }
    }
}

/* Add operating system version, service pack, etc. to store. */
static VOID
AddSystemInfoToStore(
    WMIAccessor* wmi
    )
{
    OSVERSIONINFOEX info;
    char buf[MAX_PATH];
    
    XenstorePrintf("attr/os/class", "windows NT");
    /* Windows version, service pack, build number */
    info.dwOSVersionInfoSize = sizeof(info);
    if (GetVersionEx((LPOSVERSIONINFO)&info)) {
#define do_field(name, field) \
        XenstorePrintf("attr/os/" #name , "%d", info. field)
        do_field(major, dwMajorVersion);
        do_field(minor, dwMinorVersion);
        do_field(build, dwBuildNumber);
        do_field(platform, dwPlatformId);
        do_field(spmajor, wServicePackMajor);
        do_field(spminor, wServicePackMinor);
        do_field(suite, wSuiteMask);
        do_field(type, wProductType);
#undef do_field

        XenstorePrintf("data/os_distro", "windows");
        XenstorePrintf("data/os_majorver", "%d", info.dwMajorVersion);
        XenstorePrintf("data/os_minorver", "%d", info.dwMinorVersion);
    } else {
        /* Flag that we couldn't collect this information. */
        XenstorePrintf("attr/os/major", "-1");
    }

    DumpOSData(wmi);

    XenstorePrintf("attr/os/boottype", "%d", GetSystemMetrics(SM_CLEANBOOT));
    /* HAL version in use */
    if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_SYSTEM, NULL, SHGFP_TYPE_CURRENT, buf))) {
        DWORD tmp;
        DWORD versize;
        LPVOID buffer = NULL;
        TCHAR buffer2[128];
        LPTSTR halname;
        UINT halnamelen;
        struct {
            WORD language, code_page;
        } *trans;
        UINT trans_size;

        XenstorePrintf("attr/os/system32_dir", "%s", buf);
        strcat(buf, "\\hal.dll");
        versize = GetFileVersionInfoSize(buf, &tmp);
        if (versize == 0) {
            XenstorePrintf("attr/os/hal", "<unknown versize=0>");
            goto done_hal;
        }
        buffer = malloc(versize);
        if (!buffer) {
            XenstorePrintf("attr/os/hal", "<unknown versize=%d>", versize);
            goto done_hal;
        }
        if (GetFileVersionInfo(buf, tmp, versize, buffer) == 0) {
            PrintError("GetFileVersioInfo(hal.dll)");
            goto done_hal;
        }
        if (!VerQueryValue(buffer, TEXT("\\VarFileInfo\\Translation"),
                           (LPVOID *)&trans, &trans_size)) {
            PrintError("VerQueryValue(hal.Translation");
            goto done_hal;
        }
        if (trans_size < sizeof(*trans)) {
            XenstorePrintf("attr/os/hal", "<no translations>");
            goto done_hal;
        }
        sprintf(buffer2, "\\StringFileInfo\\%04x%04x\\InternalName",
                trans->language, trans->code_page);
        if (VerQueryValue(buffer, buffer2, (LPVOID *)&halname,
                          &halnamelen)) {
            XenstorePrintf("attr/os/hal", "%s", halname);

            if (!lstrcmpi(halname, "hal.dll")) {
                LegacyHal = TRUE;
            }
        } else {
            PrintError("VerQueryValue(hal.InternalName)");
        }
    done_hal:
        free(buffer);
    }

    /* Kernel command line */
    HKEY regKey;
    DWORD res;
    res = RegOpenKey(HKEY_LOCAL_MACHINE,
                     "SYSTEM\\CurrentControlSet\\Control",
                     &regKey);
    if (res != ERROR_SUCCESS) {
        PrintError("RegOpenKey(\"HKLM\\SYSTEM\\CurrentControlSet\\Control\")");
    } else {
        DWORD keyType;
        DWORD tmp;
        tmp = sizeof(buf);
        res = RegQueryValueEx(regKey, "SystemStartOptions",
                              NULL, &keyType, (LPBYTE)buf, &tmp);
        if (res != ERROR_SUCCESS) {
            PrintError("RegQueryValue(SystemStartOptions)");
        } else if (keyType != REG_SZ) {
            XenstorePrintf("attr/os/boot_options", "<not string>");
        } else {
            XenstorePrintf("attr/os/boot_options", buf);
        }
        RegCloseKey(regKey);
        regKey = NULL;
    }

    AddHotFixInfoToStore(wmi);

    AddLicenseInfoToStore();
}

struct watch_event {
    HANDLE event;
    struct xs2_watch *watch;
};

static void
ReleaseWatch(struct watch_event *we)
{
    if (we == NULL)
        return;
    if (we->event != INVALID_HANDLE_VALUE)
        CloseHandle(we->event);
    if (we->watch)
        XenstoreUnwatch(we->watch);
    free(we);
}

static struct watch_event *
EstablishWatch(const char *path)
{
    struct watch_event *we;
    DWORD err;

    we = (struct watch_event *)malloc(sizeof(*we));
    if (!we) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    memset(we, 0, sizeof(*we));
    we->watch = NULL;
    we->event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (we->event != INVALID_HANDLE_VALUE)
        we->watch = XenstoreWatch(path, we->event);
    if (we->watch == NULL) {
        err = GetLastError();
        ReleaseWatch(we);
        SetLastError(err);
        return NULL;
    }
    return we;
}

struct watch_feature {
    struct watch_event *watch;
    const char *feature_flag;
    const char *name;
    void (*handler)(void *);
    void *ctx;
};

#define MAX_FEATURES 10
struct watch_feature_set {
    struct watch_feature features[MAX_FEATURES];
    unsigned nr_features;
};

static void
AddFeature(struct watch_feature_set *wfs, const char *path,
           const char *flag, const char *name,
           void (*handler)(void *), void *ctx)
{
    unsigned n;
    if (wfs->nr_features == MAX_FEATURES) {
        PrintError("Too many features!", ERROR_INVALID_FUNCTION);
        return;
    }
    n = wfs->nr_features;
    wfs->features[n].watch = EstablishWatch(path);
    if (wfs->features[n].watch == NULL) {
        PrintError("EstablishWatch() for AddFeature()");
        return;
    }
    wfs->features[n].feature_flag = flag;
    wfs->features[n].handler = handler;
    wfs->features[n].ctx = ctx;
    wfs->features[n].name = name;
    wfs->nr_features++;
}

static void
AdvertiseFeatures(struct watch_feature_set *wfs)
{
    unsigned x;
    for (x = 0; x < wfs->nr_features; x++) {
        if (wfs->features[x].feature_flag != NULL)
            XenstorePrintf(wfs->features[x].feature_flag, "1");
    }
}

VOID
RegisterPVAddOns(
    WMIAccessor* wmi
    )
{
    HKEY hRegKey;
    HANDLE h = INVALID_HANDLE_VALUE;
    DWORD dwVersion;
    DWORD cbData;

    // If we get here, the drivers are installed.
    XenstorePrintf ("attr/PVAddons/Installed", "1");

    // Put the major, minor, and build version numbers in the store.
    LONG lRet = 0;

    lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                        XENTOOLS_INSTALL_REG_KEY, 
                        0, 
                        KEY_READ,
                        &hRegKey);

    if (lRet == ERROR_SUCCESS)
    {
        cbData = sizeof(dwVersion);
#define DO_VERSION(type)                                                    \
        lRet = RegQueryValueEx (                                            \
            hRegKey,                                                        \
            #type "Version",                                                \
            NULL,                                                           \
            NULL,                                                           \
            (PBYTE)&dwVersion,                                              \
            &cbData);                                                       \
        if (lRet == ERROR_SUCCESS)                                          \
            XenstorePrintf ("attr/PVAddons/" #type "Version", "%d",         \
                            dwVersion);                                     \
        else                                                                \
            DBGPRINT (("Failed to get version " #type));
        DO_VERSION(Major);
        DO_VERSION(Minor);
        DO_VERSION(Micro);
        DO_VERSION(Build);
#undef DO_VERSION
        RegCloseKey(hRegKey);
    }

    AddSystemInfoToStore(wmi);
}

void ServiceUninstall()
{
	SC_HANDLE   hSvc;
	SC_HANDLE   hMgr;
	
	hMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if ( hMgr )
	{
		hSvc = OpenService(hMgr, SVC_NAME, SERVICE_ALL_ACCESS);

		if (hSvc)
		{
			 // try to stop the service
			 if ( ControlService( hSvc, SERVICE_CONTROL_STOP, &ServiceStatus ) )
			 {
				printf("Stopping %s.", SVC_DISPLAYNAME);
				Sleep( 1000 );

				while ( QueryServiceStatus( hSvc, &ServiceStatus ) )
				{
					if ( ServiceStatus.dwCurrentState == SERVICE_STOP_PENDING )
					{
						printf(".");
						Sleep( 1000 );
					}
					else
						break;
				}

				if ( ServiceStatus.dwCurrentState == SERVICE_STOPPED )
					printf("\n%s stopped.\n", SVC_DISPLAYNAME );
				else
					printf("\n%s failed to stop.\n", SVC_DISPLAYNAME );
         }

         // now remove the service
         if ( DeleteService(hSvc) )
            printf("%s uninstalled.\n", SVC_DISPLAYNAME );
         else
            printf("Unable to uninstall - %d\n", GetLastError());

         CloseServiceHandle(hSvc);

         /* Tell dom0 that we're no longer installed.  This is a bit
            of a hack. */
         InitXSAccessor();

         XenstorePrintf("attr/PVAddons/Installed", "0");
         XenstorePrintf("attr/PVAddons/MajorVersion", "0");
         XenstorePrintf("attr/PVAddons/MinorVersion", "0");
         XenstorePrintf("attr/PVAddons/BuildVersion", "0");

         /* Crank the update number so xapi notices it. */
         char *v;
         XenstoreRead("data/update_cnt", &v);
         if (v) {
             int cnt = atoi(v);
             XenstorePrintf("data/update_cnt", "%d", cnt + 1);
             xs2_free(v);
         }
      }
      else
         printf("Unable to open service - %d\n", GetLastError());

      CloseServiceHandle(hMgr);
   }
   else
      printf("Unable to open scm - %d\n", GetLastError());

}


int __stdcall
WinMain(HINSTANCE hInstance, HINSTANCE ignore,
        LPSTR lpCmdLine, int nCmdShow)
{
    local_hinstance = hInstance;

    if (strlen(lpCmdLine) == 0) {
		SERVICE_TABLE_ENTRY ServiceTable[2];
		ServiceTable[0].lpServiceName = SVC_NAME;
		ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

		ServiceTable[1].lpServiceName = NULL;
		ServiceTable[1].lpServiceProc = NULL;

		DBGPRINT(("XenSvc: starting ctrl dispatcher "));

		// Start the control dispatcher thread for our service
		if (!StartServiceCtrlDispatcher(ServiceTable))
		{
			if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
			{
				DBGPRINT(("XenSvc: unable to start ctrl dispatcher - %d", GetLastError()));
			}
		}
		else
		{
			// We get here when the service is shut down.
		}
    } else if (!strcmp(lpCmdLine, "-u") || !strcmp(lpCmdLine, "\"-u\"")) {
        ServiceUninstall();
    } else {
        PrintUsage();
    }

    return 0;
}

static void AcquireSystemPrivilege(LPCTSTR name)
{
    HANDLE token;
    TOKEN_PRIVILEGES tkp;
    DWORD err;

    LookupPrivilegeValue(NULL, name, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,
                          &token)) {
        DBGPRINT(("Failed to open local token.\n"));
    } else {
        AdjustTokenPrivileges(token, FALSE, &tkp,
                              NULL, 0, NULL);
        err = GetLastError();
        if (err != ERROR_SUCCESS) {
            PrintError("AdjustTokenPrivileges", err);
        }
    }
}

static void AcquireSystemShutdownPrivilege(void)
{
    AcquireSystemPrivilege(SE_SHUTDOWN_NAME);
}

enum XShutdownType {
	XShutdownPoweroff,
	XShutdownReboot,
	XShutdownSuspend,
    XShutdownS3
};

static void respondAwake(void *ctx)
{
	char *v;
	if(XenstoreRead("control/awake", &v) >= 0)
		XenstoreRemove("control/awake");
}

static void maybeReboot(void *ctx)
{
	char *shutdown_type;
	unsigned int len;
	BOOL res;
	enum XShutdownType type;
    int cntr = 0;
    HANDLE eventLog;

	if (XenstoreRead("control/shutdown", &shutdown_type) < 0)
		return;
	DBGPRINT(("Shutdown type %s\n", shutdown_type));
	if (strcmp(shutdown_type, "poweroff") == 0 ||
	    strcmp(shutdown_type, "halt") == 0) {
		type = XShutdownPoweroff;
	} else if (strcmp(shutdown_type, "reboot") == 0) {
		type = XShutdownReboot;
	} else if (strcmp(shutdown_type, "hibernate") == 0) {
		type = XShutdownSuspend;
	} else if (strcmp(shutdown_type, "s3") == 0) {
		type = XShutdownS3;
	} else {
		DBGPRINT(("Bad shutdown type %s\n", shutdown_type));
		goto out;
	}

	/* We try to shutdown even if this fails, since it might work
	   and it can't do any harm. */
	AcquireSystemShutdownPrivilege();

    eventLog = RegisterEventSource(NULL, "xensvc");
    if (eventLog) {
        DWORD eventId;

        switch (type) {
        case XShutdownPoweroff:
            eventId = EVENT_XENUSER_POWEROFF;
            break;
        case XShutdownReboot:
            eventId = EVENT_XENUSER_REBOOT;
            break;
        case XShutdownSuspend:
            eventId = EVENT_XENUSER_HIBERNATE;
            break;
        case XShutdownS3:
            eventId = EVENT_XENUSER_S3;
            break;
        }
        ReportEvent(eventLog, EVENTLOG_SUCCESS, 0, eventId, NULL, 0, 0,
                    NULL, NULL);
        DeregisterEventSource(eventLog);
    }
	/* do the shutdown */
	switch (type) {
	case XShutdownPoweroff:
	case XShutdownReboot:
        if (WindowsVersion == 0x500)
        {
            /* Windows 2000 InitiateSystemShutdownEx is funny in
               various ways (e.g. sometimes fails to power off after
               shutdown, especially if the local terminal is locked,
               not doing anything if there's nobody logged on, etc.).
               ExitWindowsEx seems to be more reliable, so use it
               instead. */
            /* XXX I don't really understand why
               InitiateSystemShutdownEx behaves so badly. */
            /* If this is a legacy hal then use EWX_SHUTDOWN when shutting
               down instead of EWX_POWEROFF. */
#pragma warning (disable : 28159)
            res = ExitWindowsEx((type == XShutdownReboot ? 
                                    EWX_REBOOT : 
                                    (LegacyHal ? 
                                        EWX_SHUTDOWN :
                                        EWX_POWEROFF))|
                                EWX_FORCE,
                                SHTDN_REASON_MAJOR_OTHER|
                                SHTDN_REASON_MINOR_ENVIRONMENT |
                                SHTDN_REASON_FLAG_PLANNED);
#pragma warning (default: 28159)
            if (!res)
                PrintError("ExitWindowsEx");
            else
                XenstoreRemove("control/shutdown");
        } else {
#pragma warning (disable : 28159)
            res = InitiateSystemShutdownEx(
                NULL,
                NULL,
                0,
                TRUE,
                type == XShutdownReboot,
                SHTDN_REASON_MAJOR_OTHER |
                SHTDN_REASON_MINOR_ENVIRONMENT |
                SHTDN_REASON_FLAG_PLANNED);
#pragma warning (default: 28159)
            if (!res) {
                PrintError("InitiateSystemShutdownEx");
            } else {
                XenstoreRemove("control/shutdown");
            }
        }
		break;
	case XShutdownSuspend:
        XenstorePrintf ("control/hibernation-state", "started");
        /* Even if we think hibernation is disabled, try it anyway.
           It's not like it can do any harm. */
		res = SetSystemPowerState(FALSE, FALSE);
        XenstoreRemove ("control/shutdown");
        if (!res) {
            /* Tell the tools that we've failed. */
            PrintError("SetSystemPowerState");
            XenstorePrintf ("control/hibernation-state", "failed");
        }
		break;
    case XShutdownS3:
        XenstorePrintf ("control/s3-state", "started");
        res = SetSuspendState(FALSE, TRUE, FALSE);
        XenstoreRemove ("control/shutdown");
        if (!res) {
            PrintError("SetSuspendState");
            XenstorePrintf ("control/s3-state", "failed");
        }
        break;
	}

out:
	xs2_free(shutdown_type);
}

static
void
GetWindowsVersion()
{
    OSVERSIONINFO info;
    info.dwOSVersionInfoSize = sizeof(info);

    WindowsVersion = 0;

    if (GetVersionEx(&info)) {
        if (((info.dwMajorVersion & ~0xff) == 0)
         && ((info.dwMinorVersion & ~0xff) == 0))
        {
            WindowsVersion = (info.dwMajorVersion << 8) |
                              info.dwMinorVersion;
        }
    }
}

static TCHAR *
FetchRexecBinary(void)
{
    TCHAR *res;
    TCHAR tempbuf[MAX_PATH];
    HANDLE h;
    ssize_t chunk_len;
    char *chunk;
    ssize_t off_in_chunk;
    DWORD bytes_this_time;

    if (!GetTempPath(sizeof(tempbuf) / sizeof(tempbuf[0]), tempbuf)) {
        PrintError(("GetTempPath()"));
        return NULL;
    }
    res = (TCHAR *)malloc(sizeof(TCHAR) * MAX_PATH);
    if (!res) {
        DBGPRINT(("No memory for temporary path"));
        return NULL;
    }

    if (!GetTempFileName(tempbuf, "xenservice", 0, res)) {
        PrintError("GetTempFileName()");
        free(res);
        return NULL;
    }

    h = CreateFile(res,
                   GENERIC_WRITE,
                   0,
                   NULL,
                   CREATE_ALWAYS,
                   FILE_ATTRIBUTE_NORMAL|FILE_ATTRIBUTE_TEMPORARY,
                   NULL);

    if (h == INVALID_HANDLE_VALUE) {
        PrintError("openning temporary file");
        DeleteFile(res);
        free(res);
        return NULL;
    }

    /* Read the file in */
    while (1) {
        chunk_len = XenstoreRead("control/rexec_chunk", &chunk);
        if (chunk_len < 0) {
            if (GetLastError() == ERROR_FILE_NOT_FOUND) {
                /* Wait for dom0 to give us the next chunk.  Rather
                   icky; the right answer would be to use a watch, but
                   it's hardly worth it for this little thing. */
                Sleep(1);
                continue;
            } else {
                PrintError("read rexec chunk");
                goto err;
            }
        }
        XenstoreRemove("control/rexec_chunk");
        if (chunk_len == 0) {
            xs2_free(chunk);
            break;
        }
        off_in_chunk = 0;
        while (off_in_chunk < chunk_len) {
            if (!WriteFile(h,
                           chunk + off_in_chunk,
                           (ULONG)(chunk_len - off_in_chunk),
                           &bytes_this_time,
                           NULL)) {
                PrintError(("WriteFile()"));
                goto err;
            }
            off_in_chunk += bytes_this_time;
        }
        xs2_free(chunk);
    }
    CloseHandle(h);
    return res;

err:
    CloseHandle(h);
    DeleteFile(res);
    free(res);
    return NULL;
}

static BOOL
VerifyRexec(
    PCTSTR path
    )
{
    DWORD Err;
    WINTRUST_FILE_INFO FileData;
    WCHAR FileName[MAX_PATH];
    WINTRUST_DATA WinTrustData;
    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    BOOL valid = FALSE;
    PCRYPT_PROVIDER_DATA CryptProviderData;
    PCRYPT_PROVIDER_SGNR CryptProviderSgnr;
    PCRYPT_PROVIDER_CERT CryptProviderCert;
    TCHAR Buffer[32];

    if (mbstowcs(FileName, path, MAX_PATH) == -1) {
        goto clean;
    }

    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = FileName;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    memset(&WinTrustData, 0, sizeof(WinTrustData));

    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE; 
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwProvFlags = WTD_SAFER_FLAG;
    WinTrustData.dwUIContext = 0;
    WinTrustData.pFile = &FileData;

    Err = WinVerifyTrust(NULL,
                         &WVTPolicyGUID,
                         &WinTrustData);

    if (Err != ERROR_SUCCESS) {
        PrintError("WinVerifyTrust()", Err);
        goto clean;
    }

    CryptProviderData = WTHelperProvDataFromStateData(WinTrustData.hWVTStateData);
    if (!CryptProviderData) {
        goto clean;
    }

    CryptProviderSgnr = WTHelperGetProvSignerFromChain(CryptProviderData,
                                                       0, //index
                                                       FALSE,
                                                       0);
    if (!CryptProviderSgnr) {
        goto clean;
    }

    CryptProviderCert = WTHelperGetProvCertFromChain(CryptProviderSgnr,
                                                     0); //index
    if (!CryptProviderCert) {
        goto clean;
    }

    if (CertGetNameString(CryptProviderCert->pCert,
                          CERT_NAME_SIMPLE_DISPLAY_TYPE,
                          0,
                          NULL,
                          Buffer,
                          sizeof(Buffer)/sizeof(TCHAR))) {
        if (!lstrcmp(Buffer, SIGNER_CITRIX) ||
            !lstrcmp(Buffer, SIGNER_XENSOURCE)) {
            valid = TRUE;
        } else {
            //
            // The package is properly signed, just not by Citrix or XenSource and therefore
            // we don't trust it enough to run it.
            //
	        DBGPRINT(("VerifyRexec() failed: not signed by trusted signer\n"));
            XenstorePrintf("control/error", "VerifyRexec() failed: not signed by trusted signer");
        }
    }

clean:
    if (WinTrustData.hWVTStateData != NULL) {
        WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL,
                       &WVTPolicyGUID,
                       &WinTrustData);
    }

    return valid;
}

static void
processRexec(void *ctx)
{
    char *cmd = NULL;
    PROCESS_INFORMATION processInfo = {0};
    STARTUPINFO startInfo = {0};
    BOOL success;
    DWORD code;
    TCHAR *path = NULL;

    if (XenstoreRead("control/rexec_cmdline", &cmd) < 0)
        goto clean;
    DBGPRINT(("rexec %s\n", cmd));
    XenstoreRemove("control/rexec_cmdline");

    //
    // Download the binary over xenstore
    //
    path = FetchRexecBinary();
    if (!path) {
        XenstorePrintf("control/rexec_res", "-3");
        goto clean;
    }

    //
    // Verify that the binary is digitally signed
    //
    if (!VerifyRexec(path)) {
        XenstorePrintf("control/rexec_res", "-4");
        goto clean;
    }

    //
    // Execute the binary
    //
    success = CreateProcessA(path, /* name */
                             cmd, /* command line */
                             NULL, /* process security attributes */
                             NULL, /* thread security attributes */
                             FALSE, /* Inherit handles ? */
                             0, /* Creation flags */
                             NULL, /* environment */
                             NULL, /* initial working directory */
                             &startInfo, /* startup info */
                             &processInfo); /* Process information */
    if (!success) {
        PrintError("CreateProcess()");
        XenstorePrintf("control/rexec_res", "-1");
        goto clean;
    }

    CloseHandle(processInfo.hThread);

    WaitForSingleObject(processInfo.hProcess, INFINITE);

    success = GetExitCodeProcess(processInfo.hProcess, &code);
    if (!success) {
        PrintError("GetExitCodeProcess()");
        CloseHandle(processInfo.hProcess);
        XenstorePrintf("control/rexec_res", "-2");
        goto clean;
    }
    CloseHandle(processInfo.hProcess);

    XenstorePrintf("control/rexec_res", "%d", code);

clean:
    if (cmd != NULL) {
        xs2_free(cmd);
    }
    if (path != NULL) {
        DeleteFile(path);
        free(path);
    }

    return;
}

static void
processRsend(void *ctx)
{
    PTSTR path = NULL; 
    PTSTR data = NULL;
    TCHAR expandedPath[MAX_PATH];
    DWORD err;
    int write_off;
    DWORD bytes_written;
    HANDLE h = INVALID_HANDLE_VALUE;
    ssize_t data_len;

    if (XenstoreRead("control/rsend_path", &path) < 0)
        goto clean;

    //
    // Expand out any environment variables that are in the path
    //
    err = ExpandEnvironmentStrings(path, expandedPath, SIZECHARS(expandedPath));
    if ((err == 0) || 
        (err >= SIZECHARS(expandedPath))) {
        if (err >= SIZECHARS(expandedPath))
            SetLastError(ERROR_BUFFER_OVERFLOW);
        PrintError("ExpandEnvironmentStrings() for processRsend");
        XenstorePrintf("control/rsend_res", "-3");
        goto clean;
    }

    data_len = XenstoreRead("control/rsend_data", &data);
    if (data_len < 0) {
        PrintError("XenstoreRead(control/rsend_data)");
        goto clean;
    }

    XenstoreRemove("control/rsend_data");
    XenstoreRemove("control/rsend_path");

    h = CreateFile(expandedPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                   FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,
                   NULL);
    if (h == INVALID_HANDLE_VALUE) {
        PrintError("CreateFile() for processRsend");
        XenstorePrintf("control/rsend_res", "-1");
        goto clean;
    }

    write_off = 0;
    while (write_off < data_len) {
        if (!WriteFile(h, data + write_off, (DWORD)(data_len - write_off),
                       &bytes_written, NULL)) {
            PrintError("WriteFile() for processRsend");
            XenstorePrintf("control/rsend_res", "-2");
            goto clean;
        }
        write_off += bytes_written;
    }
    XenstorePrintf("control/rsend_res", "0");

clean:
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
    }
    if (path != NULL) {
        xs2_free(path);
    }
    if (data != NULL) {
        xs2_free(data);
    }
}

/* We need to resync the clock when we recover from suspend/resume. */
static void
finishSuspend(void)
{
    FILETIME now = {0};
    SYSTEMTIME sys_time;
    SYSTEMTIME current_time;

    DBGPRINT(("Coming back from suspend.\n"));
    GetXenTime(&now);
    XsLog("Xen time is %I64x", now);
    if (!FileTimeToSystemTime(&now, &sys_time)) {
        PrintError("FileTimeToSystemTime()");
        DBGPRINT(("FileTimeToSystemTime(%x.%x)\n",
                  now.dwLowDateTime, now.dwHighDateTime));
    } else {
        XsLog("Set time to %d.%d.%d %d:%d:%d.%d",
              sys_time.wYear, sys_time.wMonth, sys_time.wDay,
              sys_time.wHour, sys_time.wMinute, sys_time.wSecond,
              sys_time.wMilliseconds);
        GetLocalTime(&current_time);
        XsLog("Time is now  %d.%d.%d %d:%d:%d.%d",
              current_time.wYear, current_time.wMonth, current_time.wDay,
              current_time.wHour, current_time.wMinute, current_time.wSecond,
              current_time.wMilliseconds);
        if (!SetLocalTime(&sys_time))
            PrintError("SetSystemTime()");
    }
}

static void
refreshStoreData(WMIAccessor *wmi, NicInfo *nicInfo,
                 TSInfo *tsInfo, struct watch_feature_set *wfs)
{
    PCHAR buffer = NULL;
    static int64_t last_meminfo_free;
    static int cntr;
    unsigned need_kick;

    need_kick = 0;
    if (XenstoreRead("attr/PVAddons/Installed",
                     &buffer) < 0) {
        if (GetLastError() == ERROR_NO_SYSTEM_RESOURCES)
            return;

        XsLogMsg("register ourself in the store");
        RegisterPVAddOns(wmi);
        nicInfo->Refresh();
        UpdateProcessListInStore(wmi);
        AdvertiseFeatures(wfs);
        need_kick = 1;
    } else {
        xs2_free(buffer);
    }

    if (XenstoreRead("data/meminfo_free", &buffer) < 0) {
        cntr = 0;
        last_meminfo_free = 0;
    } else {
        xs2_free(buffer);
    }

    if (XenstoreRead("data/ts", &buffer) < 0) {
        cntr = 0;
    } else {
        xs2_free(buffer);
    }

    /* XXX HACK: Restrict ourselves to only doing this once every two
     * minutes or so (we get called about every 4.5 seconds). */
    if (cntr++ % 26 == 0) {
        VMData data;
        BOOLEAN enabled;

        XsLogMsg("Get memory data");
        memset(&data, 0, sizeof(VMData));
        GetWMIData(wmi, data);

        if (data.meminfo_free - last_meminfo_free > 1024 ||
            data.meminfo_free - last_meminfo_free < -1024) {
            XsLogMsg("update memory data in store");
            XenstoreDoDump(&data);
            need_kick = 1;
            last_meminfo_free = data.meminfo_free;
        }

        XsLogMsg("Refresh terminal services status");
        tsInfo->Refresh();

        XsLogMsg("Get volume mapping data");
        DoVolumeDump();
    }

    if (need_kick)
        XenstoreKickXapi();
}

static void
ProcessTsControl(void *ctx)
{
    TSInfo *tsInfo = (TSInfo *)ctx;

    tsInfo->ProcessControl();
}

static void
processPing(void *ctx)
{
    XenstoreRemove("control/ping");
}

static void
processDumpLog(void *ctx)
{
    char *val;
    int do_it;

    do_it = 0;
    if (XenstoreRead("control/dumplog", &val) >= 0) {
        xs2_free(val);
        do_it = 1;
    } else if (GetLastError() != ERROR_FILE_NOT_FOUND)
        do_it = 1;

    if (do_it) {
        XsDumpLogThisThread();
        XenstoreRemove("control/dumplog");
    }
}

//
// Main loop
//
void Run()
{
    VMData data;
    bool exit=false;
    PCHAR pPVAddonsInstalled = NULL;
	PCHAR buffer = NULL;
    STARTUPINFO startInfo;
    PROCESS_INFORMATION processInfo;
    HANDLE suspendEvent;
    struct WMIAccessor *wmi;
    MSG msg;
    int cntr = 0;
    NicInfo *nicInfo;
    TSInfo *tsInfo;
    struct watch_feature_set features;
    BOOL snap = FALSE;
	HKEY hKey = NULL;

    XsLogMsg("Guest agent main loop starting");

    memset(&features, 0, sizeof(features));

    GetWindowsVersion();

    // Load Software Licensing API
    SLC_API = LoadLibrary("Slc");
    SLWGA_API = LoadLibrary("Slwga");

    //
    // Refresh WMI ADAP classes
    //
    ZeroMemory (&startInfo, sizeof (startInfo));
    ZeroMemory (&processInfo, sizeof (processInfo));
    startInfo.cb = sizeof (startInfo);
    if (!CreateProcessA(
               NULL,
               "\"wmiadap\" /f",
               NULL,
               NULL,
               FALSE,
               0,
               NULL,
               NULL,
               &startInfo,
               &processInfo
               ))
    {
        DBGPRINT (("XenSvc: Unable to refresh WMI ADAP: %d\n", GetLastError()));
    }
    else
    {
        WaitForSingleObject (processInfo.hProcess, 5000);

        CloseHandle (processInfo.hProcess);
        CloseHandle (processInfo.hThread);
    }

    // 
    // Enable disk counters forcibly so that we can retrieve disk performance
    // using IOCTL_DISK_PERFORMANCE
    //
    if (!CreateProcessA(
               NULL,
               "\"diskperf\" -y",
               NULL,
               NULL,
               FALSE,
               0,
               NULL,
               NULL,
               &startInfo,
               &processInfo
               ))
    {
        DBGPRINT (("XenSvc: Cannot enable disk perf counters: %d\n", GetLastError()));
    }
    else
    {
        WaitForSingleObject (processInfo.hProcess, 5000);

        CloseHandle (processInfo.hProcess);
        CloseHandle (processInfo.hThread);
    }


    AddFeature(&features, "control/shutdown", "control/feature-shutdown", 
               "shutdown", maybeReboot, NULL);
    AddFeature(&features, "control/rexec_cmdline", "control/feature-rexec",
               "rexec", processRexec, NULL);
    AddFeature(&features, "control/ping", NULL, "ping", processPing, NULL);
    AddFeature(&features, "control/dumplog", NULL, "dumplog", processDumpLog, NULL);
    AddFeature(&features, "control/awake", NULL, "awake", respondAwake, NULL);

    /* Disabled for now, until we figure out exactly what we're going
       to use this for. */
#if 0
    AddFeature(&features, "control/resend_path", "control/feature-rsend",
               "rsend", processRsend, NULL);
#endif

    suspendEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (!suspendEvent) {
        PrintError("CreateEvent() suspendEvent");
    } else {
        if (ListenSuspend(suspendEvent) < 0) {
            PrintError("ListenSuspend()");
            CloseHandle(suspendEvent);
            suspendEvent = NULL;
        }
    }

    StartClipboardSync();

    wmi = ConnectToWMI();

    UpdateProcessListInStore(wmi);

    nicInfo = new NicInfo();
    nicInfo->Prime();

    tsInfo = new TSInfo();
    AddFeature(&features,
               "control/ts",
               "control/feature-ts",
               "ts",
               ProcessTsControl,
               tsInfo);

    XenstoreRemove("attr/PVAddons/Installed");
    refreshStoreData(wmi, nicInfo, tsInfo, &features);

    while (1)
    {
        DWORD status;
        int nr_handles = 2;
        HANDLE handles[3 + MAX_FEATURES];
        unsigned x;

        handles[0] = hServiceExitEvent;
        handles[1] = nicInfo->NicChangeEvent;
        if (suspendEvent)
            handles[nr_handles++] = suspendEvent;
        for (x = 0; x < features.nr_features; x++)
            handles[nr_handles++] = features.features[x].watch->event;

        XsLogMsg("win agent going to sleep");
        status = WaitForMultipleObjects(nr_handles, handles, FALSE, 4500);
        XsLogMsg("win agent woke up for %d", status);

        if (status == WAIT_TIMEOUT)
        {
            refreshStoreData(wmi, nicInfo, tsInfo, &features);

            if (++cntr % 12 == 0) {
                /* Only do this once a minute or so, because it
                   doesn't really need to be up to date. */
                UpdateProcessListInStore(wmi);
            }
        }
        /* WAIT_OBJECT_0 happens to be 0, so the compiler gets shirty
           about status >= WAIT_OBJECT_0 (since status is unsigned).
           This is more obviously correct than the compiler-friendly
           version, though, so just disable the warning. */
#pragma warning (disable: 4296)
        else if (status >= WAIT_OBJECT_0 &&
                 status < WAIT_OBJECT_0 + nr_handles)
#pragma warning (default: 4296)
        {
            HANDLE event = handles[status - WAIT_OBJECT_0];
            if (event == hServiceExitEvent)
            {
                XsLogMsg("service exit event");
                break;
            }
            else if (event == nicInfo->NicChangeEvent)
            {
                XsLogMsg("NICs changed");
                nicInfo->Refresh();
                XenstoreKickXapi();
                XsLogMsg("Handled NIC change");
                nicInfo->Prime();
            }
            else if (event == suspendEvent)
            {
                XsLogMsg("Suspend event");
                finishSuspend();
                refreshStoreData(wmi, nicInfo, tsInfo, &features);
                XsLogMsg("Handled suspend event");
            }
            else
            {
                for (x = 0; x < features.nr_features; x++) {
                    if (features.features[x].watch->event == event) {
                        XsLogMsg("fire feature %s", features.features[x].name);
                        features.features[x].handler(features.features[x].ctx);
                        XsLogMsg("fired feature %s",
                                 features.features[x].name);
                    }
                }
            }
        }
        else
        {
            PrintError("WaitForMultipleObjects()");
            break;
        }
    }

    XsLogMsg("Guest agent finishing");
    ReleaseWMIAccessor(wmi);

    FinishClipboardSync();

    delete tsInfo;
    delete nicInfo;

    ServiceControlManagerUpdate(0, SERVICE_STOPPED);

    if (SLC_API != NULL)
        FreeLibrary(SLC_API);
    if (SLWGA_API != NULL)
        FreeLibrary(SLWGA_API);

    XsLogMsg("Guest agent finished");
}


// Service initialization
bool ServiceInit()
{
	ServiceStatus.dwServiceType        = SERVICE_WIN32; 
    ServiceStatus.dwCurrentState       = SERVICE_START_PENDING; 
    ServiceStatus.dwControlsAccepted   = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode      = 0; 
    ServiceStatus.dwServiceSpecificExitCode = 0; 
    ServiceStatus.dwCheckPoint         = 0; 
    ServiceStatus.dwWaitHint           = 0; 
 
    hStatus = RegisterServiceCtrlHandler(
		"XenService", 
		(LPHANDLER_FUNCTION)ServiceControlHandler); 
    if (hStatus == (SERVICE_STATUS_HANDLE)0) 
    { 
        // Registering Control Handler failed
		DBGPRINT(("XenSvc: Registering service control handler failed - %d\n", GetLastError()));
        return false; 
    }  

	ServiceStatus.dwCurrentState = SERVICE_RUNNING; 
	SetServiceStatus (hStatus, &ServiceStatus);

	return true;
}

void ServiceMain(int argc, char** argv)
{
    // Perform common initialization
    hServiceExitEvent = CreateEvent(NULL, false, false, NULL);
    if (hServiceExitEvent == NULL)
    {
        DBGPRINT(("XenSvc: Unable to create the event obj - %d\n", GetLastError()));
        return;
    }

    if (!ServiceInit())
    {
        DBGPRINT(("XenSvc: Unable to init xenservice\n"));
        return;
    }

    XsInitPerThreadLogging();

    InitXSAccessor();
    XsLog("Guest agent service starting");

    __try
    {
        Run();
    }
    __except(XsDumpLogThisThread(), EXCEPTION_CONTINUE_SEARCH)
    {
    }

    XsLog("Guest agent service stopped");
    ShutdownXSAccessor();

    return;
}

void ServiceControlManagerUpdate(DWORD dwExitCode, DWORD dwState)
{
    ServiceStatus.dwWin32ExitCode = dwExitCode; 
    ServiceStatus.dwCurrentState  = dwState; 
    SetServiceStatus (hStatus, &ServiceStatus);
}

// Service control handler function
void ServiceControlHandler(DWORD request) 
{ 
    switch(request) 
    { 
        case SERVICE_CONTROL_STOP: 
            DBGPRINT(("XenSvc: xenservice stopped.\n"));
            ServiceControlManagerUpdate(0, SERVICE_STOP_PENDING);
            SetEvent(hServiceExitEvent);
            return; 
 
        case SERVICE_CONTROL_SHUTDOWN: 
            DBGPRINT(("XenSvc: xenservice shutdown.\n"));
            ServiceControlManagerUpdate(0, SERVICE_STOP_PENDING);
            SetEvent(hServiceExitEvent);
            return; 
        
        default:
	    DBGPRINT(("XenSvc: unknown request."));
            break;
    } 

    return; 
}
