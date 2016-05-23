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

// xgasec_test.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "XenGuestAgent_i.h"

int wmain(int argc, WCHAR* argv[])
{
	HRESULT hr;
	COSERVERINFO csi = {0, L"", 0, 0};
	MULTI_QI mqi[1] = {&IID_IXenGuestServices, NULL, S_OK};

	if (argc < 2)
	{
		wprintf(L"USAGE: xgasec_test <ip-address>\n");
		return 0;
	}

	::CoInitializeEx(NULL, COINIT_MULTITHREADED);

	// Try to create the remote object
	csi.pwszName = argv[1];
	hr = ::CoCreateInstanceEx(CLSID_XenGuestServices, NULL, CLSCTX_SERVER, &csi, 1, mqi);	
	if (hr == S_OK)
	{
		wprintf(L"XGA security check FAILED! Remote object was able to be created!\n");
		wprintf(L" -- Remote object was able to be created!\n");
		mqi[0].pItf->Release();
	}
	else
	{
		wprintf(L"XGA security check PASSED. Could not create object.\n");
		wprintf(L" -- Failure code returned: 0x%x\n", hr);
		if (hr != E_ACCESSDENIED)
		{
			wprintf(L" -- Access was blocked by a firewall or some other means\n");
			wprintf(L" -- including the service not running.\n");
		}
		else
		{
			wprintf(L" -- E_ACCESSDENIED indicates the tool contacted the DCOM server\n");
			wprintf(L" -- but the security settings prevent object creation.\n");
		}
	}

	::CoUninitialize();
	return 0;
}

