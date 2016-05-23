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

// OxtGuestServices.cpp : Implementation of COxtGuestServices

#include "stdafx.h"
#include <sys/stat.h>
#include "oxtmsg.h"
#include "OxtGuestServices.h"
#include "OxtSecurityHelper.h"

HRESULT COxtGuestServices::FinalConstruct()
{
	HRESULT hr = S_OK;

	do {
		// Open an XS instance for use by this object
		if (!m_clXs.XS2Open())
		{
			hr = LogCreateFailure((IDS_FAILED_TO_OPEN_XENSTORE___HRESUL_OXTGUESTSERVICES_32),
								  E_FAIL);
			break;
		}

		// Register this object - if it fails the global count is exceeded
		if (!m_pclOxtSvc->RegisterXgs())
		{
            m_clXs.XS2Close();
			hr = E_ACCESSDENIED;
			LogCreateFailure((IDS_MAXIMUM_INSTANCE_COUNT_REACHED___OXTGUESTSERVICES_61), hr);
		}
	} while (false);

	return hr;
}

void COxtGuestServices::FinalRelease()
{
	// Drop out of the main list
	m_pclOxtSvc->UnregisterXgs();

	m_clXs.XS2Close();
}

HRESULT COxtGuestServices::LogCreateFailure(ULONG ulMsg, HRESULT hr)
{
	m_pclOxtSvc->LogEventTypeId(ulMsg, EVENTLOG_ERROR_TYPE, EVMSG_CREATION_FAILURE, hr);
	return hr;
}

STDMETHODIMP COxtGuestServices::InterfaceSupportsErrorInfo(REFIID riid)
{
	static const IID* arr[] = 
	{
		&IID_IOxtGuestServices
	};

	for (int i=0; i < sizeof(arr) / sizeof(arr[0]); i++)
	{
		if (InlineIsEqualGUID(*arr[i],riid))
			return S_OK;
	}
	return S_FALSE;
}

STDMETHODIMP COxtGuestServices::XenStoreRead(BSTR bstrPath, BSTR *pbstrValue)
{
    LPCSTR szValue;
    CComBSTR bstrValue;
    HRESULT hr;

    szValue = (LPCSTR)m_clXs.XS2Read(CW2A(bstrPath), NULL);
    if (szValue == NULL)
    {
        hr = LogCreateFailure((IDS_FAILED_TO_OPEN_XENSTORE___HRESUL_OXTGUESTSERVICES_32),
								  E_UNEXPECTED);
        return hr;
    }

    bstrValue = szValue;

    m_clXs.XS2Free((LPVOID)szValue);
    *pbstrValue = bstrValue.Copy();
	return S_OK;
}

STDMETHODIMP COxtGuestServices::XenStoreWrite(BSTR bstrPath, BSTR bstrValue)
{
    HRESULT hr;

    if (!m_clXs.XS2Write(CW2A(bstrPath), CW2A(bstrValue)))
    {
        hr = LogCreateFailure((IDS_FAILED_TO_OPEN_XENSTORE___HRESUL_OXTGUESTSERVICES_32),
								  E_UNEXPECTED);
        return hr;
    }

	return S_OK;
}