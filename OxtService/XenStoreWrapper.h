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

#pragma once
#include "resource.h"       // main symbols
#include "xs2.h"

#define XSW_MAX_WATCHES 16

class CXenStoreWrapper
{
private:
	static void       *m_fps;
	static HMODULE     m_hxs2;

	struct xs2_handle *m_xsh;
	LPVOID             m_watches[16];
	
	
public:
	CXenStoreWrapper() : m_xsh(NULL)
	{
		::ZeroMemory(m_watches, 16*sizeof(LPVOID));
	}

	~CXenStoreWrapper()
	{
		XS2Close();
	}

	static bool XS2Initialize();
	static void XS2Uninitialize();
	
	bool XS2Open();
	bool XS2Close();
	void XS2Free(LPVOID pvMem);
	bool XS2Write(LPCSTR szPath, LPCSTR szData);
	bool XS2WriteBin(LPCSTR szPath, LPVOID pvData, DWORD dwLen);
	LPVOID XS2Read(LPCSTR szPath, LPDWORD pdwCount);
	LPSTR* XS2Directory(LPCSTR szPath, LPDWORD pdwCount);
	void XS2FreeDirectory(LPSTR* pszDir, DWORD dwCount);
	bool XS2Remove(LPCSTR szPath);
	LPVOID XS2Watch(LPCSTR szPath, HANDLE hEvent);
	void XS2Unwatch(LPVOID pvWatch);
};
