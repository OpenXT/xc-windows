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

#include "stdafx.h"
#include "resource.h"
#include "XenStoreWrapper.h"

#define XSW_XENTOOLS_REGKEY  _T("Software\\Citrix\\XenTools")
#define XSW_DEFAULT_XS2PATH  _T("C:\\Program Files\\Citrix\\XenTools\\xs2.dll")
#define XSW_XENTOOLS_XS2DLL _T("xs2.dll")

#if !defined(_WIN64)
#define XS2_OPEN "_xs2_open@0"
#else
#define XS2_OPEN "xs2_open"
#endif

#if !defined(_WIN64)
#define XS2_CLOSE "_xs2_close@4"
#else
#define XS2_CLOSE "xs2_close"
#endif

#if !defined(_WIN64)
#define XS2_FREE "_xs2_free@4"
#else
#define XS2_FREE "xs2_free"
#endif

#if !defined(_WIN64)
#define XS2_WRITE "_xs2_write@12"
#else
#define XS2_WRITE "xs2_write"
#endif

#if !defined(_WIN64)
#define XS2_WRITE_BIN "_xs2_write_bin@16"
#else
#define XS2_WRITE_BIN "xs2_write_bin"
#endif

#if !defined(_WIN64)
#define XS2_READ "_xs2_read@12"
#else
#define XS2_READ "xs2_read"
#endif

#if !defined(_WIN64)
#define XS2_DIRECTORY "_xs2_directory@12"
#else
#define XS2_DIRECTORY "xs2_directory"
#endif

#if !defined(_WIN64)
#define XS2_REMOVE "_xs2_remove@8"
#else
#define XS2_REMOVE "xs2_remove"
#endif

#if !defined(_WIN64)
#define XS2_WATCH "_xs2_watch@12"
#else
#define XS2_WATCH "xs2_watch"
#endif

#if !defined(_WIN64)
#define XS2_UNWATCH "_xs2_unwatch@4"
#else
#define XS2_UNWATCH "xs2_unwatch"
#endif

typedef struct xs2_handle *(WINAPI *xs2_open_t)(void);
typedef void (WINAPI *xs2_close_t)(struct xs2_handle *handle);
typedef void (WINAPI *xs2_free_t)(const void *mem);
typedef BOOL (WINAPI *xs2_write_t)(struct xs2_handle *handle, 
								   const char *path,
								   const char *data);
typedef BOOL (WINAPI *xs2_write_bin_t)(struct xs2_handle *handle,
									   const char *path,
									   const void *data,
									   size_t size);
typedef char** (WINAPI *xs2_directory_t)(struct xs2_handle *handle,
										 const char *path,
										 unsigned int *num);
typedef void* (WINAPI *xs2_read_t)(struct xs2_handle *handle,
								   const char *path,
								   size_t *len);
typedef BOOL (WINAPI *xs2_remove_t)(struct xs2_handle *handle,
									const char *path);
typedef struct xs2_watch* (WINAPI *xs2_watch_t)(struct xs2_handle *handle,
												const char *path,
												HANDLE event);
typedef void (WINAPI *xs2_unwatch_t)(struct xs2_watch *watch);

typedef struct _XSW_FUNCTIONS {
	xs2_open_t      fp_xs2_open;
	xs2_close_t     fp_xs2_close;
	xs2_free_t      fp_xs2_free;
	xs2_write_t     fp_xs2_write;
	xs2_write_bin_t fp_xs2_write_bin;
	xs2_read_t      fp_xs2_read;
	xs2_directory_t fp_xs2_directory;
	xs2_remove_t    fp_xs2_remove;
	xs2_watch_t     fp_xs2_watch;
	xs2_unwatch_t   fp_xs2_unwatch;
} XSW_FUNCTIONS;

void *CXenStoreWrapper::m_fps = NULL;
HMODULE CXenStoreWrapper::m_hxs2 = NULL;

bool CXenStoreWrapper::XS2Initialize()
{
	bool rc = false;
	LONG lRes;
	DWORD dwLen;
	CRegKey clXenTools;
	TCHAR tszXs2Path[_MAX_PATH + 1];
	XSW_FUNCTIONS *fps;

	do {
		if (m_hxs2 != NULL)
		{
			::SetLastError(ERROR_GEN_FAILURE);
			break;
		}

		m_fps = malloc(sizeof(XSW_FUNCTIONS));
		if (m_fps == NULL)
		{
			::SetLastError(ERROR_OUTOFMEMORY);
			break;
		}
		::ZeroMemory(m_fps, sizeof(XSW_FUNCTIONS));
		fps = (XSW_FUNCTIONS*)m_fps;

		// Load a default location
		_tcsncpy_s(tszXs2Path, _MAX_PATH, XSW_DEFAULT_XS2PATH, _TRUNCATE);

		// Find library in registry, load and get proc addresses.
		lRes = clXenTools.Open(HKEY_LOCAL_MACHINE, XSW_XENTOOLS_REGKEY, KEY_READ);
		if (lRes == ERROR_SUCCESS)
		{
			dwLen = _MAX_PATH;
			lRes = clXenTools.QueryStringValue(XSW_XENTOOLS_XS2DLL, tszXs2Path, &dwLen);
			if ((lRes != ERROR_SUCCESS)||(dwLen == 0))
			{
				_tcsncpy_s(tszXs2Path, _MAX_PATH, XSW_DEFAULT_XS2PATH, _TRUNCATE);
			}
		}

		m_hxs2 = ::LoadLibrary(tszXs2Path);
		if (m_hxs2 == NULL)
			break;

#define XSW_CHECK_FP(f) \
	if (f == NULL) {::SetLastError(ERROR_INVALID_FUNCTION); break;}

		fps->fp_xs2_open = (xs2_open_t)::GetProcAddress(m_hxs2, XS2_OPEN);
		XSW_CHECK_FP(fps->fp_xs2_open);

		fps->fp_xs2_close = (xs2_close_t)::GetProcAddress(m_hxs2, XS2_CLOSE);
		XSW_CHECK_FP(fps->fp_xs2_close);

		fps->fp_xs2_free = (xs2_free_t)::GetProcAddress(m_hxs2, XS2_FREE);
		XSW_CHECK_FP(fps->fp_xs2_free);

		fps->fp_xs2_write = (xs2_write_t)::GetProcAddress(m_hxs2, XS2_WRITE);
		XSW_CHECK_FP(fps->fp_xs2_write);

		fps->fp_xs2_write_bin = (xs2_write_bin_t)::GetProcAddress(m_hxs2, XS2_WRITE_BIN);
		XSW_CHECK_FP(fps->fp_xs2_write_bin);

		fps->fp_xs2_read = (xs2_read_t)::GetProcAddress(m_hxs2, XS2_READ);
		XSW_CHECK_FP(fps->fp_xs2_read);

		fps->fp_xs2_directory = (xs2_directory_t)::GetProcAddress(m_hxs2, XS2_DIRECTORY);
		XSW_CHECK_FP(fps->fp_xs2_directory);

		fps->fp_xs2_remove = (xs2_remove_t)::GetProcAddress(m_hxs2, XS2_REMOVE);
		XSW_CHECK_FP(fps->fp_xs2_remove);

		fps->fp_xs2_watch = (xs2_watch_t)::GetProcAddress(m_hxs2, XS2_WATCH);
		XSW_CHECK_FP(fps->fp_xs2_watch);

		fps->fp_xs2_unwatch = (xs2_unwatch_t)::GetProcAddress(m_hxs2, XS2_UNWATCH);
		XSW_CHECK_FP(fps->fp_xs2_unwatch);

		rc = true;
	} while (false);

	if (!rc)
		CXenStoreWrapper::XS2Uninitialize();

	return rc;
}

void CXenStoreWrapper::XS2Uninitialize()
{
	if (m_hxs2 != NULL)
	{
		::FreeLibrary(m_hxs2);
		m_hxs2 = NULL;
	}

	if (m_fps != NULL)
	{
		free(m_fps);
		m_fps = NULL;
	}
}

bool CXenStoreWrapper::XS2Open()
{
	XSW_FUNCTIONS *fps = (XSW_FUNCTIONS*)m_fps;

	if (m_hxs2 == NULL)
	{
		::SetLastError(ERROR_INVALID_FUNCTION);
		return false;
	}

	// Note if the xs2 call fails it will set the last error
	m_xsh = fps->fp_xs2_open();
	
	return (m_xsh != NULL) ? true : false;
}

bool CXenStoreWrapper::XS2Close()
{
	XSW_FUNCTIONS *fps = (XSW_FUNCTIONS*)m_fps;
	ULONG i;

	if ((m_hxs2 == NULL)||(m_xsh == NULL))
	{
		::SetLastError(ERROR_INVALID_PARAMETER);
		return false;
	}

	// Clean up any watches that were opened
	for (i = 0; i < XSW_MAX_WATCHES; i++)
	{
		if (m_watches[i] != NULL)
		{
			XS2Unwatch(m_watches[i]);
			m_watches[i] = NULL;
		}
	}

	fps->fp_xs2_close(m_xsh);
	m_xsh = NULL;

	return true;
}

void CXenStoreWrapper::XS2Free(LPVOID pvMem)
{
	XSW_FUNCTIONS *fps = (XSW_FUNCTIONS*)m_fps;

	if (fps == NULL)
		return;

	fps->fp_xs2_free(pvMem);
}

bool CXenStoreWrapper::XS2Write(LPCSTR szPath, LPCSTR szData)
{
	XSW_FUNCTIONS *fps = (XSW_FUNCTIONS*)m_fps;

	if ((m_hxs2 == NULL)||(m_xsh == NULL)||(szPath == NULL)||(szData == NULL))
	{
		::SetLastError(ERROR_INVALID_PARAMETER);
		return false;
	}

	if (!fps->fp_xs2_write(m_xsh, szPath, szData))
		return false;

	return true;
}

bool CXenStoreWrapper::XS2WriteBin(LPCSTR szPath, LPVOID pvData, DWORD dwLen)
{
	XSW_FUNCTIONS *fps = (XSW_FUNCTIONS*)m_fps;

	if ((m_hxs2 == NULL)||(m_xsh == NULL)||(szPath == NULL)||(pvData == NULL))
	{
		::SetLastError(ERROR_INVALID_PARAMETER);
		return false;
	}

	if (!fps->fp_xs2_write_bin(m_xsh, szPath, pvData, dwLen))
		return false;

	return true;
}

LPVOID CXenStoreWrapper::XS2Read(LPCSTR szPath, LPDWORD pdwCount)
{
	XSW_FUNCTIONS *fps = (XSW_FUNCTIONS*)m_fps;
	void *pv;
	UINT ui;


	if ((m_hxs2 == NULL)||(m_xsh == NULL)||(szPath == NULL))
	{
		::SetLastError(ERROR_INVALID_PARAMETER);
		return NULL;
	}

	pv = fps->fp_xs2_read(m_xsh, szPath, &ui);

	if (pdwCount != NULL)
		*pdwCount = ui;

	return pv;
}

LPSTR* CXenStoreWrapper::XS2Directory(LPCSTR szPath, LPDWORD pdwCount)
{
	XSW_FUNCTIONS *fps = (XSW_FUNCTIONS*)m_fps;
	char **ppc;
	UINT ui;


	if ((m_hxs2 == NULL)||(m_xsh == NULL)||(szPath == NULL)||(pdwCount == NULL))
	{
		::SetLastError(ERROR_INVALID_PARAMETER);
		return NULL;
	}

	ppc = fps->fp_xs2_directory(m_xsh, szPath, &ui);

	*pdwCount = ui;

	return ppc;
}

void CXenStoreWrapper::XS2FreeDirectory(LPSTR* pszDir, DWORD dwCount)
{
	XSW_FUNCTIONS *fps = (XSW_FUNCTIONS*)m_fps;
	DWORD i;

	if ((m_hxs2 == NULL)||(m_xsh == NULL)||(pszDir == NULL)||(dwCount == 0))
		return;

	for (i = 0; i < dwCount; i++)
		fps->fp_xs2_free(pszDir[i]);

	fps->fp_xs2_free(pszDir);
}

bool CXenStoreWrapper::XS2Remove(LPCSTR szPath)
{
	XSW_FUNCTIONS *fps = (XSW_FUNCTIONS*)m_fps;

	if ((m_hxs2 == NULL)||(m_xsh == NULL)||(szPath == NULL))
	{
		::SetLastError(ERROR_INVALID_PARAMETER);
		return false;
	}

	if (!fps->fp_xs2_remove(m_xsh, szPath))
		return false;

	return true;
}

LPVOID CXenStoreWrapper::XS2Watch(LPCSTR szPath, HANDLE hEvent)
{
	XSW_FUNCTIONS *fps = (XSW_FUNCTIONS*)m_fps;
	void *pv;
	ULONG i;

	if ((m_hxs2 == NULL)||(m_xsh == NULL)||(szPath == NULL)||(hEvent == NULL))
	{
		::SetLastError(ERROR_INVALID_PARAMETER);
		return NULL;
	}

	for (i = 0; i < XSW_MAX_WATCHES; i++)
	{
		if (m_watches[i] == NULL)
			break;
	}

	if (i >= XSW_MAX_WATCHES)
	{
		::SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return NULL;
	}

	pv = (LPVOID)fps->fp_xs2_watch(m_xsh, szPath, hEvent);
	m_watches[i] = pv;

	return pv;
}

void CXenStoreWrapper::XS2Unwatch(LPVOID pvWatch)
{
	XSW_FUNCTIONS *fps = (XSW_FUNCTIONS*)m_fps;
	ULONG i;

	if ((m_hxs2 == NULL)||(m_xsh == NULL)||(pvWatch == NULL))
		return;

	for (i = 0; i < XSW_MAX_WATCHES; i++)
	{
		if (m_watches[i] == pvWatch)
		{
			m_watches[i] = NULL;
			break;
		}
	}

	fps->fp_xs2_unwatch((struct xs2_watch*)pvWatch);
}
