/*
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

#include "stdafx.h"
#include <atlbase.h>
#include <atlstr.h>
#include "OxtUserAgent.h"
#include "OxtService_i.h"

#pragma warning(disable:4996)

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;								// current instance
TCHAR szTitle[MAX_LOADSTRING];					// The title bar text
TCHAR szWindowClass[MAX_LOADSTRING];			// the main window class name

static void OxtUpdateScreen()
{
    DWORD dwDevNum;
    DISPLAY_DEVICE DisplayDevice;
    BOOL bRet;
    IOxtGuestServices *piOxtSvcs = NULL;
    HRESULT hr;
    int iWidth, iHeight;
    WCHAR wszData[MAX_LOADSTRING];
    CComBSTR bstrPath, bstrValue;

    ::memset(&DisplayDevice, 0, sizeof(DISPLAY_DEVICE));
    DisplayDevice.cb = sizeof(DISPLAY_DEVICE);

    for (dwDevNum = 0; ; dwDevNum++)
    {
        bRet = ::EnumDisplayDevices(NULL, dwDevNum, &DisplayDevice, 0);
        if (!bRet)
        {
            // We are done, error returned when there are no more
            break;
        }
    }

    hr = ::CoCreateInstance(CLSID_OxtGuestServices,
                            NULL,
                            CLSCTX_LOCAL_SERVER,
                            IID_IOxtGuestServices,
							(LPVOID*)&piOxtSvcs);
    if (FAILED(hr))
    {
		// Not much we can do...
        return;
    }

    // First the active adapter count (not sure if it is used though).
    bstrPath = L"display/activeAdapter";
    _snwprintf(wszData, MAX_LOADSTRING, L"%d", (int)dwDevNum);
    bstrValue = wszData;
    piOxtSvcs->XenStoreWrite(bstrPath, bstrValue);

    iWidth = ::GetSystemMetrics(SM_CXVIRTUALSCREEN);
    iHeight = ::GetSystemMetrics(SM_CYVIRTUALSCREEN);

    bstrPath = L"attr/desktopDimensions";
    _snwprintf(wszData, MAX_LOADSTRING, L"%d %d", iWidth, iHeight);
    bstrValue = wszData;
    piOxtSvcs->XenStoreWrite(bstrPath, bstrValue);

    piOxtSvcs->Release();
}

LRESULT CALLBACK OxtWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_POWERBROADCAST:
        if (wParam == PBT_APMRESUMEAUTOMATIC)
        {
            OxtUpdateScreen();
        }
        break;
    case WM_DISPLAYCHANGE:
        OxtUpdateScreen();
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return ::DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

static BOOL OxtInitInstance(HINSTANCE hInstance, int nCmdShow)
{
    HWND hWnd;

    hInst = hInstance; // Store instance handle in our global variable

    hWnd = ::CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
              CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);
    if (!hWnd)
    {
       return FALSE;
    }

    // We do not want to see the winder
    //ShowWindow(hWnd, nCmdShow);
    //UpdateWindow(hWnd);

    return TRUE;
}

static void OxtRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEX wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style			= CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc	= OxtWndProc;
    wcex.cbClsExtra		= 0;
    wcex.cbWndExtra		= 0;
    wcex.hInstance		= hInstance;
    wcex.hIcon			= LoadIcon(hInstance, MAKEINTRESOURCE(IDI_OXTUSERAGENT));
    wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName	= MAKEINTRESOURCE(IDC_OXTUSERAGENT);
    wcex.lpszClassName	= szWindowClass;
    wcex.hIconSm		= LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_OXTUSERAGENT));

    (void)::RegisterClassEx(&wcex);
}

int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    MSG msg;

    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    ::CoInitializeEx(NULL, COINIT_MULTITHREADED);

    LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_OXTUSERAGENT, szWindowClass, MAX_LOADSTRING);

    OxtRegisterClass(hInstance);

	// Perform application initialization:
	if (!OxtInitInstance(hInstance, nCmdShow))
	{
		return FALSE;
	}

    // Call once to initialize things a bit
    OxtUpdateScreen();

    // Main message loop:
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    ::CoUninitialize();

    return (int) msg.wParam;
}
