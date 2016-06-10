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

// OxtGuestServices.h : Declaration of the COxtGuestServices

#pragma once
#include "resource.h"	   // main symbols

#include "OxtService_i.h"
#include "OxtService.h"
#include "XenStoreWrapper.h"

// COxtGuestServices

class ATL_NO_VTABLE COxtGuestServices :
	public CComObjectRootEx<CComMultiThreadModel>,
	public CComCoClass<COxtGuestServices, &CLSID_OxtGuestServices>,
	public ISupportErrorInfo,
	public IDispatchImpl<IOxtGuestServices, &IID_IOxtGuestServices, &LIBID_OxtServiceLib, /*wMajor =*/ 1, /*wMinor =*/ 0>
{
private:
	COxtService	     *m_pclOxtSvc;
	CXenStoreWrapper  m_clXs;

public:
	COxtGuestServices() : m_pclOxtSvc(&_OxtService)
	{
	}

DECLARE_REGISTRY_RESOURCEID(IDR_OXTGUESTSERVICES)

BEGIN_COM_MAP(COxtGuestServices)
	COM_INTERFACE_ENTRY(IOxtGuestServices)
	COM_INTERFACE_ENTRY(IDispatch)
	COM_INTERFACE_ENTRY(ISupportErrorInfo)
END_COM_MAP()

// ISupportsErrorInfo
	STDMETHOD(InterfaceSupportsErrorInfo)(REFIID riid);

	DECLARE_PROTECT_FINAL_CONSTRUCT()

	HRESULT FinalConstruct();
	void FinalRelease();

	HRESULT LogCreateFailure(ULONG ulMsg, HRESULT hr);

public:

	STDMETHOD(XenStoreRead)(BSTR bstrPath, BSTR *pbstrValue);
	STDMETHOD(XenStoreWrite)(BSTR bstrPath, BSTR bstrValue);
};

OBJECT_ENTRY_AUTO(__uuidof(OxtGuestServices), COxtGuestServices)
