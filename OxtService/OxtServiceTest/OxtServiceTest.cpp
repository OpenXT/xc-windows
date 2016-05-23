/*
 * Copyright (c) 2012 Citrix Systems, Inc.
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

// XenGuestTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "XenGuestAgent_i.h"
#include <sddl.h>

static const WCHAR g_XgsEventDACL[] = 
{
	SDDL_DACL SDDL_DELIMINATOR SDDL_PROTECTED

	// Local system - full access
	SDDL_ACE_BEGIN
	SDDL_ACCESS_ALLOWED
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_GENERIC_ALL
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_LOCAL_SYSTEM
	SDDL_ACE_END

	// Creator/Owner - full access
	SDDL_ACE_BEGIN
	SDDL_ACCESS_ALLOWED
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_GENERIC_ALL
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_CREATOR_OWNER
	SDDL_ACE_END

	// LocalService - Read access.
	SDDL_ACE_BEGIN
	SDDL_ACCESS_ALLOWED
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_GENERIC_ALL
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_LOCAL_SERVICE
	SDDL_ACE_END

	// Interactive - Read access.
	SDDL_ACE_BEGIN
	SDDL_ACCESS_ALLOWED
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_GENERIC_READ
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_INTERACTIVE
	SDDL_ACE_END
};

void make_event()
{	
	BOOL b;
	PSECURITY_DESCRIPTOR pdesc = NULL;
	SECURITY_ATTRIBUTES sa;
	HANDLE h;
	
	b = ::ConvertStringSecurityDescriptorToSecurityDescriptor(g_XgsEventDACL, SDDL_REVISION_1, &pdesc, NULL);
	if (!b)
		return;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = pdesc;
	sa.bInheritHandle = FALSE;

	h = ::CreateEvent(&sa, FALSE, FALSE, L"testevent");

	::CloseHandle(h);
	::LocalFree(pdesc);
}

void test_remote()
{
	HRESULT hr;
	COSERVERINFO csi = {0, L"10.204.2.52", 0, 0};
	MULTI_QI mqi[] = {&IID_IXenGuestServices, NULL, S_OK};

	::CoInitializeEx(NULL, COINIT_MULTITHREADED);

	hr = CoCreateInstanceEx(CLSID_XenGuestServices, NULL, CLSCTX_SERVER, &csi, 1, mqi);
}

int _tmain(int argc, _TCHAR* argv[])
{
	HRESULT hr;
	IXenGuestServices *piXgs = NULL;
	IXenVmInfo *piXvi = NULL;
	USHORT usd;
	BSTR uuid;
	ULONG c;
	SAFEARRAY *psa;

	::CoInitializeEx(NULL, COINIT_MULTITHREADED);
	hr = ::CoCreateInstance(CLSID_XenGuestServices,
							NULL,
							CLSCTX_LOCAL_SERVER,
							IID_IXenGuestServices,
							(LPVOID*)&piXgs);

	
	if (FAILED(hr))
	{
		_tprintf(_T("Borked...\n"));
		return -1;
	}

	piXgs->GetDomId(&usd);
	_tprintf(_T("My DOMID: %d\n"), usd);

	piXgs->GetUuid(&uuid);
	wprintf(L"My UUID: %s\n", uuid);
	::SysFreeString(uuid);

	piXgs->QueryVms(&c);
	wprintf(L"Domains: %d\n", c);

	if (c == 0)
		goto done;

	piXgs->GetVmObject(0, &piXvi);

	if (piXvi == NULL)
	{
		wprintf(L"Hosed...\n");
		goto done;
	}

	piXvi->GetUuid(&uuid);
	wprintf(L"VM UUID: %s\n", uuid);
	::SysFreeString(uuid);

	piXvi->GetImage(&psa);
	if (psa != NULL)
	{
		wprintf(L"Elements: %d\n", psa->cbElements);
		::SafeArrayDestroy(psa);
	}

	piXvi->Release();
	
done:
	piXgs->Release();
	::CoUninitialize();
	return 0;
}

