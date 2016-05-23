/*
 * Copyright (c) 2012 Citrix Systems, Inc.
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

// XenGuestServices.h : Declaration of the CXenGuestServices

#pragma once
#include "resource.h"       // main symbols
#include "input.h"
#include "OxtService_i.h"

#define APPID_OxtService "{50DCAB6F-A549-4E77-BF95-A3B688BDF625}"

#define XGS_MAX_INSTANCES 64

// A single instance of this class connects the various bits and pieces of the
// OxtService service together.

class COxtService
{
private:
	OSVERSIONINFOEX  m_osvi;
	volatile LONG    m_ulXgsCount;
	HANDLE           m_hShutdownEvent;
	bool             m_bLogCommunicationErrors;
	bool             m_bLogOperationErrors;;

public:
	COxtService() : m_ulXgsCount(0),
	                m_hShutdownEvent(NULL),	                  
	                m_bLogCommunicationErrors(false),
	                m_bLogOperationErrors(false)
	{
		::ZeroMemory(&m_osvi, sizeof(OSVERSIONINFO));
	}

	~COxtService()
	{
	}

	HANDLE GetShutdownEvent()
	{
		return m_hShutdownEvent;
	}

	VOID SetShutdownEvent()
	{
		if (m_hShutdownEvent != NULL)
			::SetEvent(m_hShutdownEvent);
	}

	const OSVERSIONINFOEX* GetOsInfo()
	{
		return &m_osvi;
	}

	bool Initialize();
	VOID Uninitialize();
	bool Start();

	VOID LogEventTypeId(LPCTSTR tszFormat, WORD wType, DWORD dwEventId, va_list args);
	VOID LogEventTypeId(ULONG ulFormat, WORD wType, DWORD dwEventId, va_list args);
	VOID LogEventTypeId(ULONG ulFormat, WORD wType, DWORD dwEventId, ...);
	bool LogEventTypeIdLastError(ULONG ulFormat, WORD wType, DWORD dwEventId, va_list args);
	bool LogEventTypeIdLastError(ULONG ulFormat, WORD wType, DWORD dwEventId, ...);
	bool LogEventTypeIdLastRegistryError(ULONG ulFormat, WORD wType, DWORD dwEventId, LONG lRet, va_list args);
	bool LogEventTypeIdLastRegistryError(ULONG ulFormat, WORD wType, DWORD dwEventId, LONG lRet, ...);
	bool LogEventTypeIdLastErrorAlways(ULONG ulFormat, WORD wType, DWORD dwEventId, va_list args);
	bool LogEventTypeIdLastErrorAlways(ULONG ulFormat, WORD wType, DWORD dwEventId, ...);

	bool RegisterXgs();
	void UnregisterXgs();

private:

};

extern COxtService _OxtService;
