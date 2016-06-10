/*
 * Copyright (c) 2014 Citrix Systems, Inc.
 * Copyright (c) 2016 Assured Information Security, Inc.
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

// OxtService.cpp : Implementation of WinMain

#include "stdafx.h"
#include "resource.h"
#include "oxtmsg.h"
#include "OxtService.h"
#include "OxtService_i.h"
#include "XenStoreWrapper.h"
#include "OxtSecurityHelper.h"

#include <stdio.h>
#include <assert.h>
#include <string>
#include <sstream>
#include <iomanip>

#define XGA_INSTALL_REGKEY  _T("Software\\Citrix\\XenGuestPlugin")
#define XC_INSTALL_REGKEY  _T("Software\\Citrix\\XenTools")
#define XGA_INSTALL_INSTVAL _T("Install_Dir")
#define XGA_SERVICE_INFO_SIZE 256
#define XGA_RUN_REGKEY		_T("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
#define XGA_RUN_INSTVAL		_T("XciPlugin")
#define XGA_RUN_BLANK		_T("")

extern "C" {
	int poweropts();
}

#ifdef _DEBUG
//#define _CAN_CONSOLE
#endif // _DEBUG

class COxtServiceModule : public CAtlServiceModuleT< COxtServiceModule, IDS_SERVICENAME >
{
public :
	HINSTANCE m_hInstance;
	TCHAR m_tszDisplayName[XGA_SERVICE_INFO_SIZE];
	TCHAR m_tszServiceDesc[XGA_SERVICE_INFO_SIZE];
	TCHAR m_tszParamsKey[XGA_SERVICE_INFO_SIZE];

	DECLARE_LIBID(LIBID_OxtServiceLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_OXTSERVICE, APPID_OxtService)

	HRESULT InitializeSecurity() throw()
	{
		COxtSecurityHelper clXsh(&_OxtService);

		// If not a consolable build, check not running remotely
#		ifndef _CAN_CONSOLE
		// If the remote access check fails, fail to start the service.
		if (!clXsh.CheckDenyRemoteAccess())
			return E_ACCESSDENIED;
#		else //!_CAN_CONSOLE
		//CoInitializeSecurity(NULL // pSecDesc
		//	,0 // cAuthSvc
		//	,NULL // asAuthSvc
		//	,NULL // pReserved1
		//	,0 // dwAuthnLevel
		//	,0 // dwImplLevel
		//	,NULL // pAuthList
		//	,0 // dwCapabilities
		//	,NULL // pReserved3
		//	);
#		endif //_CAN_CONSOLE

		// Calling CoInitializeSecurity at this point will override the values
		// setup for the AppID in the registry. These values explicitly set the
		// security access control to deny all remote access and to allow only
		// the interactive user access and launch permissions (aside from the
		// administrator). The default authentication values are fine for this.

		// NOTE: One oddity was that a NULL DACL was being passed to CoInitializeSecurity
		// earlier but the values in the AppID were still being used. Perhaps
		// there is more to the overriding of AppID registry values than simply
		// ignoring them in some cases.

		return S_OK;
	}

	void LoadStrings(HINSTANCE hInstance)
	{
		m_hInstance = hInstance;

		::LoadString(m_hInstance, IDS_DISPLAYNAME, m_tszDisplayName, sizeof(m_tszDisplayName)/sizeof(TCHAR));
		::LoadString(m_hInstance, IDS_SERVICEDESC, m_tszServiceDesc, sizeof(m_tszServiceDesc)/sizeof(TCHAR));

		_sntprintf_s(m_tszParamsKey,
					 XGA_SERVICE_INFO_SIZE,
					 _TRUNCATE,
					 _T("SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters"),
					 m_szServiceName);
	}

	void SetupParameterKey()
	{
		LONG lRet;
		CRegKey keyParams;

		lRet = keyParams.Open(HKEY_LOCAL_MACHINE, m_tszParamsKey);
		if (lRet != ERROR_SUCCESS)
		{
			// Attempt to create the key
			lRet = keyParams.Create(HKEY_LOCAL_MACHINE, m_tszParamsKey);
			if (_OxtService.LogEventTypeIdLastRegistryError(ctxLS(IDS_SETUPPARAMETERKEY_COULD_NOT_CREA_OXTSERVICE_106)
				,EVENTLOG_ERROR_TYPE
				,EVMSG_START_FAILURE
				,lRet))
			{
				return;
			}
		}
		lRet = keyParams.SetDWORDValue(_T("LogCommunicationErrors"), 0);
		if (_OxtService.LogEventTypeIdLastRegistryError(ctxLS(IDS_SETUPPARAMETERKEY_COULD_NOT_SET__OXTSERVICE_115)
				,EVENTLOG_ERROR_TYPE
				,EVMSG_START_FAILURE
				,lRet))
		{
			return;
		}
		lRet = keyParams.SetDWORDValue(_T("LogOperationErrors"), 0);
		if (_OxtService.LogEventTypeIdLastRegistryError(ctxLS(IDS_SETUPPARAMETERKEY_COULD_NOT_SET__OXTSERVICE_123)
				,EVENTLOG_ERROR_TYPE
				,EVMSG_START_FAILURE
				,lRet))
		{
			return;
		}
	}

	void RegisterEventSource()
	{
		LONG lRet;
		CRegKey keyAppLog;
		CRegKey keyNewApp;
		TCHAR tszImageName[_MAX_PATH + 1];

		::ZeroMemory(tszImageName, sizeof(TCHAR)*(_MAX_PATH + 1));
		::GetModuleFileName(NULL, tszImageName, _MAX_PATH);

		// Open the app log key
		lRet = keyAppLog.Open(HKEY_LOCAL_MACHINE,
							  _T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application"));
		if (_OxtService.LogEventTypeIdLastRegistryError(ctxLS(IDS_REGISTEREVENTSOURCE_COULD_NOT_OP_OXTSERVICE_145)
			,EVENTLOG_ERROR_TYPE
			,EVMSG_START_FAILURE
			,lRet))
		{
			return;
		}

		// Create a new key for event logging for this service
		lRet = keyNewApp.Create(keyAppLog, m_szServiceName);
		if (_OxtService.LogEventTypeIdLastRegistryError(ctxLS(IDS_REGISTEREVENTSOURCE_COULD_NOT_CR_OXTSERVICE_155)
				,EVENTLOG_ERROR_TYPE
				,EVMSG_START_FAILURE
				,lRet))
		{
			return;
		}

		// Set the value of the message code base
		lRet = keyNewApp.SetStringValue(_T("EventMessageFile"), tszImageName);
		if (_OxtService.LogEventTypeIdLastRegistryError(ctxLS(IDS_REGISTEREVENTSOURCE_COULD_NOT_SE_OXTSERVICE_165)
				,EVENTLOG_ERROR_TYPE
				,EVMSG_START_FAILURE
				,lRet))
		{
			return;
		}

		// Set the event types allowed
		DWORD dwData = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
		lRet = keyNewApp.SetDWORDValue(_T("TypesSupported"), dwData);
		if (_OxtService.LogEventTypeIdLastRegistryError(ctxLS(IDS_REGISTEREVENTSOURCE_COULD_NOT_SE_OXTSERVICE_176)
				,EVENTLOG_ERROR_TYPE
				,EVMSG_START_FAILURE
				,lRet))
		{
			return;
		}
	}

	void UnregisterEventSource()
	{
		LONG lRet;
		CRegKey keyAppLog;

		// Open the app log key
		lRet = keyAppLog.Open(HKEY_LOCAL_MACHINE,
							  _T("SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application"));
		if (_OxtService.LogEventTypeIdLastRegistryError(ctxLS(IDS_UNREGISTEREVENTSOURCE_COULD_NOT__OXTSERVICE_193)
			,EVENTLOG_ERROR_TYPE
			,EVMSG_START_FAILURE
			,lRet))
		{
			return;
		}

		// Delete this service's logging key
		keyAppLog.DeleteSubKey(m_szServiceName);
	}

	void DenyRemoteAccess()
	{
		COxtSecurityHelper clXsh(&_OxtService);
		clXsh.DenyRemoteAccess();
		clXsh.DenyRemoteLaunchAndActivate();
	}

	void CheckRemoteAccess()
	{
		COxtSecurityHelper clXsh(&_OxtService);

		if (clXsh.CheckDenyRemoteAccess())
			::MessageBox(NULL, _T("CheckRemoteAccess: Remote access is denied."), m_szServiceName, MB_OK|MB_ICONINFORMATION);
		else
			::MessageBox(NULL, _T("CheckRemoteAccess: WARNING remote access is not denied!"), m_szServiceName, MB_OK|MB_ICONEXCLAMATION);
	}

	void UpdateServiceRegistry()
	{
		SC_HANDLE hSCM = NULL;
		SC_HANDLE hService = NULL;
		BOOL rc;
		SERVICE_DESCRIPTION stDesc;

		do {
			hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
			if (hSCM == NULL)
			{
				_OxtService.LogEventTypeId(ctxLS(IDS_UPDATESERVICEREGISTRY_COULD_NOT__OXTSERVICE_233),
											  EVENTLOG_ERROR_TYPE,
											  EVMSG_START_FAILURE,
											  ::GetLastError());
				break;
			}

			hService = ::OpenService(hSCM, m_szServiceName, SERVICE_CHANGE_CONFIG);
			if (hSCM == NULL)
			{
				::CloseServiceHandle(hSCM);
				_OxtService.LogEventTypeId(ctxLS(IDS_UPDATESERVICEREGISTRY_COULD_NOT__OXTSERVICE_244),
											  EVENTLOG_ERROR_TYPE,
											  EVMSG_START_FAILURE,
											  ::GetLastError());
				break;
			}

			rc = ::ChangeServiceConfig(hService,
									   SERVICE_NO_CHANGE,
									   SERVICE_AUTO_START,
									   SERVICE_NO_CHANGE,
									   NULL,
									   NULL,
									   NULL,
									   NULL,
									   NULL,
									   NULL,
									   m_tszDisplayName);
			if (!rc)
			{
				_OxtService.LogEventTypeId(ctxLS(IDS_UPDATESERVICEREGISTRY_CHANGE_SER_OXTSERVICE_264),
											  EVENTLOG_ERROR_TYPE,
											  EVMSG_START_FAILURE,
											  ::GetLastError());
				break;
			}

			stDesc.lpDescription = m_tszServiceDesc;
			rc = ::ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, (LPVOID)&stDesc);
			if (!rc)
			{
				_OxtService.LogEventTypeId(ctxLS(IDS_UPDATESERVICEREGISTRY_CHANGE_SER_OXTSERVICE_275),
											  EVENTLOG_ERROR_TYPE,
											  EVMSG_START_FAILURE,
											  ::GetLastError());
			}
		} while (false);

		if (hService != NULL)
			::CloseServiceHandle(hService);

		if (hSCM != NULL)
			::CloseServiceHandle(hSCM);
	}

	bool PreStartTasks()
	{
		LPTSTR lpCmdLine = GetCommandLine();
		TCHAR tszTokens[] = _T("-/");
		bool rc = false;

		LPCTSTR lpszToken = FindOneOf(lpCmdLine, tszTokens);
		while (lpszToken != NULL)
		{
			if (WordCmpI(lpszToken, _T("RegServer")) == 0)
			{
				RegisterEventSource();
				break;
			}

			if (WordCmpI(lpszToken, _T("Service")) == 0)
			{
				RegisterEventSource();
				SetupParameterKey();
				break;
			}

			if (WordCmpI(lpszToken, _T("UnregServer")) == 0)
			{
				UnregisterEventSource();
				break;
			}

			if (WordCmpI(lpszToken, _T("DenyRemoteAccess")) == 0)
			{
				DenyRemoteAccess();
				rc = true;
				break;
			}

			if (WordCmpI(lpszToken, _T("CheckRemoteAccess")) == 0)
			{
				CheckRemoteAccess();
				rc = true;
				break;
			}

			lpszToken = FindOneOf(lpszToken, tszTokens);
		}

		return rc;
	}

	void PostStartTasks()
	{
		LPTSTR lpCmdLine = GetCommandLine();
		TCHAR tszTokens[] = _T("-/");

		LPCTSTR lpszToken = FindOneOf(lpCmdLine, tszTokens);
		while (lpszToken != NULL)
		{
			if (WordCmpI(lpszToken, _T("Service"))==0)
			{
				UpdateServiceRegistry();
				break;
			}

			lpszToken = FindOneOf(lpszToken, tszTokens);
		}
	}

	//! @brief Try to run the program as a console executable.
	//! Useful for debugging.
	//! @param dwArgc	Number of command line params.
	//! @param lpszArgv	Command line params.
	void ConsoleMain(DWORD dwArgc, LPTSTR* lpszArgv) throw()
	{
		lpszArgv;
		dwArgc;
		m_status.dwWin32ExitCode = S_OK;
		m_status.dwCheckPoint = 0;
		m_status.dwWaitHint = 0;

#ifndef _ATL_NO_COM_SUPPORT

		HRESULT hr = E_FAIL;
		hr = COxtServiceModule::InitializeCom();
		if (FAILED(hr))
		{
			// Ignore RPC_E_CHANGED_MODE if CLR is loaded. Error is due to CLR initializing
			// COM and InitializeCOM trying to initialize COM with different flags.
			if (hr != RPC_E_CHANGED_MODE || GetModuleHandle(_T("Mscoree.dll")) == NULL)
			{
				return;
			}
		}
		else
		{
			m_bComInitialized = true;
		}

		m_bDelayShutdown = false;
#endif //_ATL_NO_COM_SUPPORT
		// When the Run function returns, the service has stopped.
		m_status.dwWin32ExitCode = this->Run(SW_HIDE);

		// Ok, I give up. How do we remote debug with the correct credentials ?
#		ifdef _CAN_CONSOLE
		if (m_status.dwWin32ExitCode == CO_E_WRONG_SERVER_IDENTITY)
		{
			this->RunMessageLoop();
			this->PostMessageLoop();
		}
#		endif // _CAN_CONSOLE

#ifndef _ATL_NO_COM_SUPPORT
		if (m_bService && m_bComInitialized)
			COxtServiceModule::UninitializeCom();
#endif

		SetServiceStatus(SERVICE_STOPPED);
		LogEvent(_T("Service running as Console stopped"));
	}

	HRESULT Start(int nShowCmd) throw()
	{
		// Explicitly load the xs2.dll here for use in the service.
		if (!CXenStoreWrapper::XS2Initialize())
		{
			_OxtService.LogEventTypeId(ctxLS(IDS_FAILED_TO_LOAD_XS2_LIBRARY___ERR_OXTSERVICE_413),
										  EVENTLOG_ERROR_TYPE, EVMSG_START_FAILURE, ::GetLastError());
			return E_FAIL;
		}

		// We are overriding start with our own. Since we are always a service then
		// can ditch the registry checks. First, start the non-COM related tasks.
		if (!_OxtService.Start())
			return E_UNEXPECTED;

		// Now start the COM service
		m_bService = TRUE;

		SERVICE_TABLE_ENTRY st[] =
		{
			{ m_szServiceName, _ServiceMain },
			{ NULL, NULL }
		};
		if (::StartServiceCtrlDispatcher(st) == 0)
		{
			DWORD const dwLastError = GetLastError();
			if (dwLastError == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) // If failed to connect
			{
#				ifndef _CAN_CONSOLE
				m_status.dwWin32ExitCode = dwLastError;
#				endif // _CAN_CONSOLE
				_OxtService.LogEventTypeIdLastError(ctxLS(IDS_FAILED_TO_START__SERVICE_SHOULD__OXTSERVICE_439)
					,EVENTLOG_ERROR_TYPE
					,EVMSG_START_FAILURE
				);
				// Allow debug build to attempt to run as console program.
				// Currently doesn't always work that well since there's a problem with
				// "CoRegisterClassObject()" failing with CO_E_WRONG_SERVER_IDENTITY causing an assert.
#				ifdef _CAN_CONSOLE
#					ifdef UNICODE
					LPTSTR *lpCmdLine = __wargv;
#					else //!UNICODE
					LPTSTR *lpCmdLine = __argv;
#					endif //!UNICODE
				ConsoleMain(__argc, lpCmdLine);
#				endif _CAN_CONSOLE

			} // Ends if failed to connect
			else // Else unknown error
			{
				m_status.dwWin32ExitCode = dwLastError;
				_OxtService.LogEventTypeIdLastError(ctxLS(IDS_FAILED_TO_START_SERVICE_OXTSERVICE_459)
					,EVENTLOG_ERROR_TYPE
					,EVMSG_START_FAILURE
				);
			} // Ends else unknown error
		}

		return m_status.dwWin32ExitCode;
	}

	void OnStop() throw()
	{
		// Override the OnStop to get control of our shutdown event first
		_OxtService.SetShutdownEvent();
		// Call up to parent class to shut the service down
		CAtlServiceModuleT<COxtServiceModule, IDS_SERVICENAME>::OnStop();
	}
};

COxtServiceModule _AtlModule;

bool COxtService::Initialize()
{
#define XGA_MAX_MESSAGE 512
	LONG lRet;
	DWORD dwVal;
	CRegKey clInstKey;
	CRegKey keyParams;

	m_osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if (!::GetVersionEx((OSVERSIONINFO*)&m_osvi))
	{
		LogEventTypeId(ctxLS(IDS_GETVERSIONEX_FAILED_____ERROR__z_OXTSERVICE_537), // SNO!
					   EVENTLOG_ERROR_TYPE, EVMSG_START_FAILURE, ::GetLastError());
		return false;
	}

	m_hShutdownEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	if (m_hShutdownEvent == NULL)
	{
		LogEventTypeId(ctxLS(IDS_FAILED_TO_CREATE_SHUTDOWN_EVENT__OXTSERVICE_545),
					   EVENTLOG_ERROR_TYPE, EVMSG_START_FAILURE, ::GetLastError());
		return false;
	}

	// Try reading the logging flags if they are there.
	lRet = keyParams.Open(HKEY_LOCAL_MACHINE, _AtlModule.m_tszParamsKey);
	if (lRet == ERROR_SUCCESS)
	{
		lRet = keyParams.QueryDWORDValue(_T("LogCommunicationErrors"), dwVal);
		if (lRet == ERROR_SUCCESS)
			m_bLogCommunicationErrors = (dwVal == 0) ? false : true;

		lRet = keyParams.QueryDWORDValue(_T("LogOperationErrors"), dwVal);
		if (lRet == ERROR_SUCCESS)
			m_bLogOperationErrors = (dwVal == 0) ? false : true;
	}

	return true;
}

void COxtService::Uninitialize()
{
	if (m_hShutdownEvent != NULL)
	{
		::CloseHandle(m_hShutdownEvent);
		m_hShutdownEvent = NULL;
	}
}

bool COxtService::Start()
{
	// Configure power options
	poweropts();
	return true;
}

void COxtService::LogEventTypeId(LPCTSTR tszFormat, WORD wType, DWORD dwEventId, va_list args)
{
	TCHAR   tszMsg[XGA_MAX_MESSAGE + 1];

	// Check log flags
	if ((dwEventId == EVMSG_COMMUNICATION_FAILURE)&&(!m_bLogCommunicationErrors))
		return;
	if ((dwEventId == EVMSG_OPERATION_FAILURE)&&(!m_bLogOperationErrors))
		return;

	if (tszFormat != NULL)
	{
		_vsntprintf_s(tszMsg, XGA_MAX_MESSAGE, _TRUNCATE, tszFormat, args);

		_AtlModule.LogEventEx(dwEventId, tszMsg, wType);
	}
	else
		_AtlModule.LogEventEx(dwEventId, NULL, wType);
}

void COxtService::LogEventTypeId(ULONG ulFormat, WORD wType, DWORD dwEventId, va_list args)
{
	if (ulFormat != 0)
	{
		TCHAR tszFormat[_MAX_PATH];

		_stprintf_s(tszFormat, _MAX_PATH, _T("%d"), ulFormat);
		LoadString(NULL, ulFormat, tszFormat, _MAX_PATH);
		LogEventTypeId(tszFormat, wType, dwEventId, args);
	}
	else
		LogEventTypeId((LPCTSTR)NULL, wType, dwEventId, args);
}

void COxtService::LogEventTypeId(ULONG ulFormat, WORD wType, DWORD dwEventId, ...)
{
	va_list pArg;
	va_start(pArg, dwEventId);
	LogEventTypeId(ulFormat, wType, dwEventId, pArg);
	va_end(pArg);
}

//! @brief Log event on error, using "GetLastError()".
//! If there is a text description of the error available from Windows, include it in the event log output.
//! @param tszFormat	Format string.
//! @param wType	Event type.
//! @param dwEventId	Event Id.
//! @param lRet	Return value from registry call.
//! @param args	ellipsis arguments.
//! @return	true if error occurred, otherwise false.
bool COxtService::LogEventTypeIdLastError(ULONG ulFormat, WORD wType, DWORD dwEventId, va_list args)
{
#	ifdef UNICODE
	typedef std::wstring tstring;
	typedef std::wostringstream tostringstream;
#	else // !UNICODE
	typedef std::string tstring;
	typedef std::ostringstream tostringstream;
#	endif // !UNICODE
	static size_t const HexWidth = 2;
	DWORD const dwLastError = ::GetLastError();
	bool const bError = dwLastError != 0;
	TCHAR tszFormat[_MAX_PATH];

	_stprintf_s(tszFormat, _MAX_PATH, _T("%d"), ulFormat);
	LoadString(NULL, ulFormat, tszFormat, _MAX_PATH);

	if (bError) // If error occurred
	{
		LPVOID lpMsgBuf = NULL;
		tostringstream strstrFormat;
		DWORD dwFormatMessageResult;

		strstrFormat << tszFormat <<  _T(" - ERROR");

		dwFormatMessageResult = FormatMessage(
			 FORMAT_MESSAGE_ALLOCATE_BUFFER |
			 FORMAT_MESSAGE_FROM_SYSTEM |
			 FORMAT_MESSAGE_IGNORE_INSERTS
			,NULL // source
			,dwLastError // Message ID
			,MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT) // Language ID
			,(LPTSTR) &lpMsgBuf // Buffer
			,0 // Size
			,NULL // Arguments
		);

		bool const bGotDescription = dwFormatMessageResult != 0 && lpMsgBuf != NULL;
		if (bGotDescription) // If got error description
		{
			strstrFormat << _T("(");

		} // Ends if got error description
		else // Else no error description
		{
			strstrFormat << _T(": ");

		} // Ends else no error description

		// Output the error code.
		strstrFormat << dwLastError;

		if (bGotDescription) // If got error description
		{
			strstrFormat << _T("): ") << reinterpret_cast<LPCTSTR>(lpMsgBuf);

		} // Ends else got error description

		if (lpMsgBuf != NULL) // If got message
		{
			LocalFree(lpMsgBuf);

		} // Ends if got message

		LogEventTypeId(strstrFormat.str().c_str()
			,EVENTLOG_ERROR_TYPE
			,EVMSG_START_FAILURE
			,args
		);
	} // Ends if error occurred

	return bError;
}

bool COxtService::LogEventTypeIdLastError(ULONG ulFormat, WORD wType, DWORD dwEventId, ...)
{
	va_list pArg;
	va_start(pArg, dwEventId);
	bool const bResult = LogEventTypeIdLastError(ulFormat, wType, dwEventId, pArg);
	va_end(pArg);
	return bResult;
}

//! @brief Log event on registry error, using "GetLastError()" if possible, otherwise last registry error argument.
//! If there is a text description of the error available from Windows, include it in the event log output.
//! @param tszFormat	Format string.
//! @param wType	Event type.
//! @param dwEventId	Event Id.
//! @param lRet	Return value from registry call.
//! @param args	ellipsis arguments.
//! @return	true if registry error occurred, otherwise false.
bool COxtService::LogEventTypeIdLastRegistryError(ULONG ulFormat, WORD wType, DWORD dwEventId, LONG lRet, va_list args)
{
#	ifdef UNICODE
	typedef std::wstring tstring;
	typedef std::wostringstream tostringstream;
#	else // !UNICODE
	typedef std::string tstring;
	typedef std::ostringstream tostringstream;
#	endif // !UNICODE
	static size_t const HexWidth = 2;
	bool const bError = lRet != ERROR_SUCCESS;
	TCHAR tszFormat[_MAX_PATH];

	_stprintf_s(tszFormat, _MAX_PATH, _T("%d"), ulFormat);
	LoadString(NULL, ulFormat, tszFormat, _MAX_PATH);
	if (bError) // If error occurred
	{
		LPVOID lpMsgBuf = NULL;
		DWORD const dwLastError = ::GetLastError();
		tostringstream strstrFormat;
		DWORD dwFormatMessageResult;

		strstrFormat << tszFormat <<  _T(" - error ");

		if (dwLastError != 0) // If there is a last error
		{
			dwFormatMessageResult = FormatMessage(
				 FORMAT_MESSAGE_ALLOCATE_BUFFER |
				 FORMAT_MESSAGE_FROM_SYSTEM |
				 FORMAT_MESSAGE_IGNORE_INSERTS
				,NULL // source
				,dwLastError // Message ID
				,MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL) // Language ID
				,(LPTSTR) &lpMsgBuf // Buffer
				,0 // Size
				,NULL // Arguments
			);
		} // Ends if there is a last error
		else // Else no last error
		{
			// Work out what went wrong with the registry key.
			// Retrieve the system error message for the last-error code.
			dwFormatMessageResult = FormatMessage(
				 FORMAT_MESSAGE_ALLOCATE_BUFFER |
				 FORMAT_MESSAGE_FROM_SYSTEM |
				 FORMAT_MESSAGE_IGNORE_INSERTS
				,NULL // source
				,lRet // Message ID
				,MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL) // Language ID
				,(LPTSTR) &lpMsgBuf // Buffer
				,0 // Size
				,NULL // Arguments
			);
		} // Ends else no last error

		bool const bGotDescription = dwFormatMessageResult != 0 && lpMsgBuf != NULL;
		if (bGotDescription) // If got error description
		{
			strstrFormat << _T("(");
		}

		// Output the error code in hex.
		strstrFormat << _T("0x") << std::hex << std::setfill(_T('0')) << std::setw(HexWidth);

		if (dwLastError != 0) // If last error
		{
			strstrFormat << dwLastError;

		} // Ends if last error
		else // Else no last error
		{
			strstrFormat << lRet;

		} // Ends else no last error

		strstrFormat << std::resetiosflags(strstrFormat.flags());

		if (bGotDescription) // If got error description
		{
			strstrFormat << _T("): ") << reinterpret_cast<LPCTSTR>(lpMsgBuf);

		} // Ends else got error description

		if (lpMsgBuf != NULL) // If got message
		{
			LocalFree(lpMsgBuf);

		} // Ends if got message

		LogEventTypeId(strstrFormat.str().c_str()
			,EVENTLOG_ERROR_TYPE
			,EVMSG_START_FAILURE
			,args
		);
	} // Ends if error occurred

	return bError;
}

bool COxtService::LogEventTypeIdLastRegistryError(ULONG ulFormat, WORD wType, DWORD dwEventId, LONG lRet, ...)
{
	va_list args;
	va_start(args, lRet);
	bool const bResult = LogEventTypeIdLastRegistryError(ulFormat, wType, dwEventId, lRet, args);
	va_end(args);
	return bResult;
}

//! @brief Log event on error, using "GetLastError()". If no error, log output anyway.
//! If there is a text description of the error available from Windows, include it in the event log output.
//! @param tszFormat	Format string.
//! @param wType	Event type.
//! @param dwEventId	Event Id.
//! @param lRet	Return value from registry call.
//! @param args	ellipsis arguments.
//! @return	true if error occurred, otherwise false.
bool COxtService::LogEventTypeIdLastErrorAlways(ULONG ulFormat, WORD wType, DWORD dwEventId, va_list args)
{
	bool const bError = LogEventTypeIdLastError(ulFormat, wType, dwEventId, args);
	if (!bError)
	{
		LogEventTypeId(ulFormat, wType, dwEventId);
	}
	return bError;
}

bool COxtService::LogEventTypeIdLastErrorAlways(ULONG ulFormat, WORD wType, DWORD dwEventId, ...)
{
	va_list args;
	va_start(args, dwEventId);
	bool const bResult = LogEventTypeIdLastErrorAlways(ulFormat, wType, dwEventId, args);
	va_end(args);
	return bResult;
}

bool COxtService::RegisterXgs()
{
	LONG lRet;

	lRet = ::InterlockedIncrement(&m_ulXgsCount);

	if (lRet > XGS_MAX_INSTANCES)
	{
		::InterlockedDecrement(&m_ulXgsCount);
		return false;
	}
	return true;
}

void COxtService::UnregisterXgs()
{
	::InterlockedDecrement(&m_ulXgsCount);
	assert(m_ulXgsCount >= 0);
}

COxtService _OxtService;

extern "C" int WINAPI _tWinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/,
								LPTSTR /*lpCmdLine*/, int nShowCmd)
{
	int iRet;

	_AtlModule.LoadStrings(hInstance);

	if (!_OxtService.Initialize())
	{
		_OxtService.SetShutdownEvent();
		_OxtService.Uninitialize();
		return -2;
	}

	// Up front tasks like registering the event log message binary. For
	// tasks like updating local only access, the app will quite following these.
	if (_AtlModule.PreStartTasks())
		return 0;

	iRet = _AtlModule.WinMain(nShowCmd);

	// Tasks after server/service registration
	_AtlModule.PostStartTasks();

	_OxtService.SetShutdownEvent();
	_OxtService.Uninitialize();

	// Free the xs2.dll library as late as possible after all threads are done. If
	// it was not loaded, the routine will handle that.
	CXenStoreWrapper::XS2Uninitialize();

	return iRet;
}

