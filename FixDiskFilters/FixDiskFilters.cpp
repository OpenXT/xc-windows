/*
 * Copyright (c) 2010 Citrix Systems, Inc.
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


#define _CRT_SECURE_NO_WARNINGS	// To allow u sto use sprintf() instead of sprintf_s()
#define _CRT_NON_CONFORMING_SWPRINTFS 

#include <stdlib.h>   // For _MAX_PATH definition
#include <stdio.h>
#include <malloc.h>
#include <windows.h>
#include <tchar.h>


int main()
{
	LONG status;

	_tprintf(_T("FixDiskFilt v1.0\n"));
	_tprintf(_T("Fix order of lower disk class filter drivers in registry\n\n"));

	LPTSTR Filters = NULL;
	LPTSTR NewFilters = NULL;
	DWORD BufSize = 0;
	LPTSTR FiltArr[16];
	int idx = 0;
	int i, j, n;
	LPTSTR p = Filters;
	bool ReorgHappened = FALSE;
	DWORD RegType;
	HKEY hKey;

	RegOpenKeyEx (
		HKEY_LOCAL_MACHINE,
		_T("System\\CurrentControlSet\\Control\\Class\\{4D36E967-E325-11CE-BFC1-08002BE10318}"),
		0,
		KEY_ALL_ACCESS,
		&hKey);

	//
	// Fetch registry value for list of disk filter drivers
	//
	RegType = REG_MULTI_SZ;
	status = RegQueryValueEx (
		hKey, 
		_T("LowerFilters"),
		NULL,
		&RegType,
		(BYTE *)NULL,
		&BufSize);

	//
	// ERROR_MORE_DATA means our buffer wasn't big enough.
	// ERROR_SUCCESS means we sent a NULL for the buffer ptr and
	// BufSize now holds the number of bytes we need to allocate.
	//
	if ((status == ERROR_MORE_DATA) || (status == ERROR_SUCCESS))
	{
		// Allocate a new buffer to hold reg value
		Filters = (LPTSTR)malloc(BufSize);
		// ...and fetch it
		RegType = REG_MULTI_SZ;
		status = RegQueryValueEx (
			hKey, 
			_T("LowerFilters"),
			NULL,
			&RegType,
			(BYTE *)Filters,
			&BufSize);
	}
	else
	{
		//
		// Some other error occured...
		//
		_tprintf(_T("Failed to read registry: status = 0x%08x\n"), status);
		return status;
	}

	//
	// The data is now in Filters...let's start working on it.
	//

	//
	// Build an array of char ptrs to point to each
	// value in the REG_MULTI_STRING read from the registry
	//
	p = Filters;
	_tprintf(_T("Current order:\n"));
	while (*p != NULL)
	{
		_tprintf(_T("Filter[%d]: %s\n"), idx, p);
		FiltArr[idx] = p;
		idx++;
		p += _tcslen(p) + 1;
	}

	_tprintf(_T("\n"));

	//
	// Scan thru the list of entries looking for
	// "scsifilt". If it ends up not being the first,
	// then flag it.
	//
	for (i = 0; i < idx; i++)
	{
		if (_tcsicmp(FiltArr[i], _T("scsifilt")) == 0)
		{
			// Found scsifilt...which entry is it?
			if (i != 0)
			{
				_tprintf(_T("Found scsifilt: entry = %d\n"), i);
				//
				// scsifilt is not the first filter. Reorganize
				// the array of pointers.
				//
				LPTSTR tmp = FiltArr[i];
				_tprintf(_T("Reorganizing...\n"));
				ReorgHappened = TRUE;
				//
				// Basically, just shift all entries prior to where
				// scsifilt was found down 1. Then move scsifilt into
				// location [0].
				//
				for (j = i; j > 0; j--)
					FiltArr[j] = FiltArr[j-1];
				FiltArr[0] = tmp;
			}
			else
			{
				_tprintf(_T("scsifilt found in correct order\n"));
			}
		}
	}

	//
	// If we reorged the array, then we need to write out a
	// new value to the registry.
	//
	if (ReorgHappened)
	{
		_tprintf(_T("New order:\n"));
		// Alocate new buffer to write to registry
		NewFilters = (LPTSTR)malloc(BufSize);
		p = NewFilters;
		//
		// Now populate new array. The for loop
		// will use the array of pointers to regenerate
		// the array fo filter drivers.
		//
		for (i = 0; i < idx; i++)
		{
			_tprintf(_T("Filter[%d]: %s\n"), i, FiltArr[i]);
			n = _stprintf (p, _T("%s\0"), FiltArr[i]);
			p += n + 1;
		}
		// Need to double terminate the new buffer
		_stprintf (p, _T("\0"));

		_tprintf(_T("Writing new registry value..."));

		//
		// ...and write it to the registry!
		//
		status = RegSetValueEx (
			hKey, 
			_T("LowerFilters"),
			NULL,
			REG_MULTI_SZ,
			(BYTE *)NewFilters,
			BufSize);

		if (status == ERROR_SUCCESS)
			_tprintf(_T("Done!\n"));
		else
			_tprintf(_T("\nFAILED: status = 0x%08x\n"), status);
	}

	if (Filters)
		free (Filters);
	if (NewFilters)
		free (NewFilters);

	RegCloseKey(hKey); 

	return status;
}
