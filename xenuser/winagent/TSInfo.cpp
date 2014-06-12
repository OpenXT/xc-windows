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

#define _WIN32_DCOM
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <iostream>
#include <wbemidl.h>

#include "XSAccessor.h"
#include "TSInfo.h"

using namespace std;

#pragma comment(lib, "wbemuuid.lib")

TSInfo::TSInfo()
{
    HRESULT                 Result;
    OSVERSIONINFOEX         VersionInfo;
    BSTR                    NameSpace;

	pNamespace = NULL;
	pLocator = NULL;
    
    Result = CoInitializeEx(0,
                            COINIT_MULTITHREADED);
    if (FAILED(Result))
        goto fail1;

    Result = CoInitializeSecurity(NULL,
                                  -1,
                                  NULL,
                                  NULL,
                                  RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                                  RPC_C_IMP_LEVEL_IMPERSONATE,
                                  NULL,
                                  EOAC_NONE,
                                  NULL);
    if (FAILED(Result) && Result != RPC_E_TOO_LATE)
        goto fail2;

    Result = CoCreateInstance(CLSID_WbemLocator,
                              0,
                              CLSCTX_INPROC_SERVER,
                              IID_IWbemLocator,
                              (LPVOID*)&pLocator);
    if (FAILED(Result))
        goto fail3;

	ZeroMemory(&VersionInfo, sizeof(OSVERSIONINFOEX));
    VersionInfo.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEX);
    Result = WBEM_E_FAILED;
    if (!GetVersionEx((OSVERSIONINFO*)&VersionInfo))
        goto fail4;

	if (VersionInfo.wSuiteMask == VER_SUITE_PERSONAL)
		goto fail4;

    if (VersionInfo.dwMajorVersion >= 6)
        NameSpace = L"ROOT\\CIMV2\\TERMINALSERVICES";
    else
        NameSpace = L"ROOT\\CIMV2";

    Result = pLocator->ConnectServer(NameSpace,
                                     NULL,
                                     NULL,
                                     0,
                                     NULL,
                                     0,
                                     0,
                                     &pNamespace);
    if (FAILED(Result))
        goto fail5;

    Result = CoSetProxyBlanket(pNamespace,
                               RPC_C_AUTHN_WINNT,
                               RPC_C_AUTHZ_NONE,
                               NULL,
                               RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                               RPC_C_IMP_LEVEL_IMPERSONATE,
                               NULL,
                               EOAC_NONE);
    if (FAILED(Result))
        goto fail6;

    return;

fail6:
    XsLog("%s: fail6\n", __FUNCTION__);

    pNamespace->Release();

fail5:
    XsLog("%s: fail5\n", __FUNCTION__);

fail4:
    XsLog("%s: fail4\n", __FUNCTION__);

    pLocator->Release();

fail3:
    XsLog("%s: fail3\n", __FUNCTION__);

fail2:
    XsLog("%s: fail2\n", __FUNCTION__);

    CoUninitialize();

fail1:
    XsLog("%s: fail1 (%08x)\n", __FUNCTION__, Result);
}

TSInfo::~TSInfo()
{
    pNamespace->Release();

    pLocator->Release();

    CoUninitialize();
}

HRESULT
TSInfo::Query(
    __out   BOOLEAN         *pEnabled
    )
{
    HRESULT                 Result = E_FAIL;
    IEnumWbemClassObject    *pEnumerator = NULL;
    IWbemClassObject        *pObject = NULL;
    ULONG                   Count;
    VARIANT                 Flag;

	if (pNamespace == NULL)
		goto fail0;

    Result = pNamespace->ExecQuery(L"WQL",
                                   L"SELECT * FROM Win32_TerminalServiceSetting",
                                   WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                   NULL,
                                   &pEnumerator);
    if (FAILED(Result))
        goto fail1;

    Count = 0;
    (VOID) pEnumerator->Next(WBEM_INFINITE,
                             1,
                             &pObject,
                             &Count);

    Result = WBEM_S_FALSE;
    if (Count == 0)
        goto fail2;

    Result = pObject->Get(L"AllowTSConnections",
                          0,
                          &Flag,
                          NULL,
                          NULL);

    if (FAILED(Result))
        goto fail3;

    Result = WBEM_E_FAILED;    
    if (V_VT(&Flag) != VT_I4)
        goto fail4;

    *pEnabled = (V_I4(&Flag) != 0) ? TRUE : FALSE;

    VariantClear(&Flag);

    pObject->Release();

    pEnumerator->Release();

    return WBEM_S_NO_ERROR;

fail4:
    XsLog("%s: fail4\n", __FUNCTION__);

    VariantClear(&Flag);

fail3:
    XsLog("%s: fail3\n", __FUNCTION__);

    pObject->Release();

fail2:
    XsLog("%s: fail2\n", __FUNCTION__);

    pEnumerator->Release();

fail1:
    XsLog("%s: fail1 (%08x)\n", __FUNCTION__, Result);

fail0:
    XsLog("%s: fail0\n", __FUNCTION__);

    return Result;
}

HRESULT
TSInfo::Set(
    __in    BOOLEAN         Enable
    )
{
    HRESULT                 Result = E_FAIL;
    IEnumWbemClassObject    *pEnumerator = NULL;
    IWbemClassObject        *pObject = NULL;
    ULONG                   Count;
    BSTR                    ClassName = L"Win32_TerminalServiceSetting";
    IWbemClassObject        *pClass = NULL;
    BSTR                    MethodName = L"SetAllowTSConnections";
    IWbemClassObject        *pInParamsDefinition = NULL;
    IWbemClassObject        *pClassInstance = NULL;
    IWbemClassObject        *pOutParams = NULL;
    VARIANT                 Flag;
    VARIANT                 Path;

	if (pNamespace == NULL)
		goto fail0;

    Result = pNamespace->ExecQuery(L"WQL",
                                   L"SELECT * FROM Win32_TerminalServiceSetting",
                                   WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                   NULL,
                                   &pEnumerator);
    if (FAILED(Result))
        goto fail1;

    Count = 0;
    (VOID) pEnumerator->Next(WBEM_INFINITE,
                             1,
                             &pObject,
                             &Count);

    Result = WBEM_S_FALSE;
    if (Count == 0)
        goto fail2;

    Result = pNamespace->GetObject(ClassName,
                                   0,
                                   NULL,
                                   &pClass,
                                   NULL);
    if (FAILED(Result))
        goto fail3;

    Result = pClass->GetMethod(MethodName, 
                               0,
                               &pInParamsDefinition,
                               NULL);
    if (FAILED(Result))
        goto fail4;

    Result = pInParamsDefinition->SpawnInstance(0,
                                                &pClassInstance);
    if (FAILED(Result))
        goto fail5;

    V_VT(&Flag) = VT_I4;
    V_I4(&Flag) = (Enable) ? 1 : 0;

    Result = pClassInstance->Put(L"AllowTSConnections",
                                 0,
                                 &Flag,
                                 0);
    if (FAILED(Result))
        goto fail6;

    Result = pObject->Get(L"__PATH",
                          0,
                          &Path,
                          NULL,
                          NULL);
    if (FAILED(Result))
        goto fail7;

    Result = pNamespace->ExecMethod(Path.bstrVal,
                                    MethodName, 
                                    0,
                                    NULL,
                                    pClassInstance,
                                    &pOutParams,
                                    NULL);
    if (FAILED(Result))
        goto fail8;

    pOutParams->Release();

    VariantClear(&Path);

    VariantClear(&Flag);

    pClassInstance->Release();

    pInParamsDefinition->Release();

    pClass->Release();

    pObject->Release();

    pEnumerator->Release();

    return WBEM_S_NO_ERROR;

fail8:
    XsLog("%s: fail8\n", __FUNCTION__);

    VariantClear(&Path);

fail7:
    XsLog("%s: fail7\n", __FUNCTION__);

    VariantClear(&Flag);

fail6:
    XsLog("%s: fail6\n", __FUNCTION__);

    pClassInstance->Release();

fail5:
    XsLog("%s: fail5\n", __FUNCTION__);

    pInParamsDefinition->Release();

fail4:
    XsLog("%s: fail4\n", __FUNCTION__);

    pClass->Release();

fail3:
    XsLog("%s: fail3\n", __FUNCTION__);

    pObject->Release();

fail2:
    XsLog("%s: fail2\n", __FUNCTION__);

    pEnumerator->Release();

fail1:
    XsLog("%s: fail1 (%08x)\n", __FUNCTION__, Result);

fail0:
    XsLog("%s: fail0\n", __FUNCTION__);

    return Result;
}

VOID
TSInfo::Refresh()
{
    HRESULT Result;
    BOOLEAN Enabled;

    Result = Query(&Enabled);
    if (FAILED(Result))
        goto fail1;

    XenstorePrintf("data/ts", "%d", (Enabled) ? 1 : 0);

    return;

fail1:
    XsLog("%s: fail1 (%08x)\n", __FUNCTION__, Result);
}

VOID
TSInfo::ProcessControl()
{
    CHAR    *Buffer; 
    BOOLEAN Enable;
    HRESULT Result;

    if (XenstoreRead("control/ts", &Buffer) < 0)
        return;

    XenstoreRemove("control/ts");

    Enable = (strtol(Buffer, NULL, 0) != 0) ? TRUE : FALSE;

    Result = Set(Enable);
    if (FAILED(Result))
        goto fail1;

    XsLog("%s terminal services", (Enable) ? "Enabled" : "Disabled");

    Refresh();

    return;

fail1:
    XsLog("%s: fail1 (%08x)\n", __FUNCTION__, Result);
}

