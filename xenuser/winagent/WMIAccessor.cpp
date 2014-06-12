/*
 * Copyright (c) 2006 XenSource, Inc. All use and distribution of this 
 * copyrighted material is governed by and subject to terms and 
 * conditions as licensed by XenSource, Inc. All other rights reserved. 
 */

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

#include "stdafx.h"
#define _WIN32_DCOM
#include <windows.h>
#include <iostream>
#include <algorithm>
#include <hash_map>
#include <stdio.h>
#include "WMIAccessor.h"
#include "XService.h"
#include "NicInfo.h"
#include <xs2.h>

#include "xs_private.h"

#pragma comment(lib, "wbemuuid.lib")

struct WMIAccessor
{
    IWbemServices *mpSvc;
    BOOLEAN com_initialized;
    HANDLE owning_thread;
};

static string wstring2string(const wstring& wstr)
{ 
    int len;

    len = WideCharToMultiByte(CP_UTF8,
                              0,
                              wstr.c_str(),
                              -1,
                              NULL,
                              0,
                              NULL,
                              NULL);

    string str(len, 0);

    len = WideCharToMultiByte(CP_UTF8,
                              0,
                              wstr.c_str(),
                              -1,
                              &str[0],
                              str.length(),
                              NULL,
                              NULL);

	return str;
}

static string bstr2string(const BSTR& bstr)
{
	wstring wstr(bstr);

	return wstring2string(wstr);
}

static IEnumWbemClassObject* runQuery(WMIAccessor *wmi, BSTR query)
{
    if (wmi == NULL)
        return NULL;

    ASSERT(wmi->mpSvc != NULL);

    // Use the IWbemServices pointer to make requests of WMI. 
    // Make requests here:
    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hres = wmi->mpSvc->ExecQuery(L"WQL", 
                                         query,
                                         WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
                                         NULL,
                                         &pEnumerator);
    if (FAILED(hres))
    {
		DBGPRINT(("ExecQuery failed\n"));
        XsLog("ExecQuery %S failed with 0x%X", query, hres);
		pEnumerator = NULL;
    }
	return pEnumerator;
}

VOID
AddHotFixInfoToStore(WMIAccessor* wmi)
{
    IEnumWbemClassObject *pEnum;
    char buffer2[4096];
    DWORD index;
    ULONG uReturn;
    IWbemClassObject *pclsObj;
    HRESULT hr;
    VARIANT vtData;

    index = 0;
    pEnum = runQuery(wmi, L"SELECT HotFixID FROM Win32_QuickFixEngineering");
    if (pEnum == NULL)
        return;

    while (1) {
        hr = pEnum->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (FAILED(hr) || 0 == uReturn)
            break;

        hr = pclsObj->Get(L"HotFixID", 0, &vtData, NULL, NULL);

        if ( !FAILED(hr) ) {
            if ( vtData.vt == VT_BSTR ) {
                //
                // Windows replaces a hotfix id with "File 1" when it has been
                // replaced by a newer hotfix, so just ignore these.
                //
                if (_wcsicmp(vtData.bstrVal, L"File 1")) {
                    string str = bstr2string(vtData.bstrVal);
                    sprintf(buffer2, "attr/os/hotfixes/%d", index);
                    XenstoreWrite(buffer2, str.c_str(), str.length());
                    index++;
                }
            }
            VariantClear(&vtData);
        }

        pclsObj->Release();
    }
    pEnum->Release ();
}

struct WMIAccessor *ConnectToWMI(void)
{
    struct WMIAccessor *wmi;
    IWbemLocator *locator;
    HRESULT hres;

    wmi = (struct WMIAccessor *)malloc(sizeof(*wmi));
    if (wmi == NULL) {
        XsLog("No memory for WMI accessor?");
        return NULL;
    }
    memset(wmi, 0, sizeof(*wmi));

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        XsLog("Failed to initialise COM (%x)", hres);
        goto err_out;
    }
    wmi->com_initialized = TRUE;
    wmi->owning_thread = GetCurrentThread();

    // Initialize COM security.  Most of this is irrelevant to us.
    hres = CoInitializeSecurity(
        NULL,     /* Security descriptor. Only relevant to servers */
        -1,       /* Nr. of auth services. Only relevant to servers */
        NULL,     /* List of auth services. Only relevant to servers */
        NULL,     /* Reserved */
        RPC_C_AUTHN_LEVEL_DEFAULT, /* Default authentication.  The
                                      details don't really matter when
                                      you're localhost. */
        RPC_C_IMP_LEVEL_IMPERSONATE, /* WMI needs to be able to
                                        impersonate us. */
        NULL,             /* Authentication info */
        EOAC_NONE,        /* Additional capabilities */
        NULL              /* Reserved */
        );
    if (FAILED(hres)) {
        XsLog("Failed to initialise COM security (%x)", hres);
        goto err_out;
    }

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0, 
        CLSCTX_INPROC_SERVER, 
        IID_IWbemLocator,
        (LPVOID *) &locator);
    if (FAILED(hres)) {
        XsLog("Failed to create WMI locator service (%x)", hres);
        goto err_out;
    }
    hres = locator->ConnectServer(
        L"root\\CIMV2",          // WMI namespace
        NULL,                    // User name
        NULL,                    // User password
        NULL,                    // Locale
        0,                       // Security flags
        NULL,                    // Authority
        NULL,                    // Context object
        &wmi->mpSvc              // IWbemServices proxy
        );
    locator->Release();
    if (FAILED(hres)) {
        XsLog("Failed to connect to WMI (%x)", hres);
        goto err_out;
    }

    /* WMI needs to impersonate us, because it normally runs as an
       unprivileged user and needs our authority in order to access
       device files and so forth.  Turn impersonation on. */
    hres = CoSetProxyBlanket(
        wmi->mpSvc,                  // the proxy to set
        RPC_C_AUTHN_WINNT,           /* LAN manager authentication,
                                        although it doesn't really
                                        matter on localhost. */
        RPC_C_AUTHZ_NONE,            // LANMAN can't do much authorization.
        NULL,                        // Server principal name
        RPC_C_AUTHN_LEVEL_CALL,      // Do authentication on every call
        RPC_C_IMP_LEVEL_IMPERSONATE, // Allow full impersonation.
        NULL,                        // Use current client identity
        EOAC_NONE                    // No extended proxy capabilities
    );
    if (FAILED(hres)) {
        XsLog("Failed to set WMI proxy security blanket (%x)", hres);
        goto err_out;
    }

    /* All done. */
    return wmi;

err_out:
    XsLog("WMI-based features disabled.");
    ReleaseWMIAccessor(wmi);
    return NULL;
}

/* Careful: WMI accessors must be released on the same thread that
   allocated them. */
void ReleaseWMIAccessor(struct WMIAccessor *wmi)
{
    if (wmi == NULL)
        return;
    if (wmi->mpSvc != NULL)
        wmi->mpSvc->Release();
    if (wmi->com_initialized) {
        ASSERT(wmi->owning_thread == GetCurrentThread());
        CoUninitialize();
    }
    /* Poison wmi to make use-after-free()s a bit more obvious. */
    memset(wmi, 0xab, sizeof(*wmi));
    free(wmi);
}

/* The fact that something is documented as being a uint64_t field
   doesn't imply that it will be returned as a VT_UI8 field in a
   variant structure.  Work around this with a handy conversion
   function. */
static uint64_t
GetVariantUint64(VARIANT *vtData)
{
    switch (vtData->vt) {
    case VT_I2:
        return vtData->iVal;
    case VT_I4:
        return vtData->lVal;
    case VT_I8:
        return vtData->llVal;
    case VT_UI2:
        return vtData->uiVal;
    case VT_UI4:
        return vtData->ulVal;
    case VT_UI8:
        return vtData->ullVal;
    case VT_BSTR:
        /* Yes, I really do mean BSTR: XP returns 64 bit values as
           strings, and we then have to do atoill on it. */
        return _wtoi64(vtData->bstrVal);
    default:
        DBGPRINT(("Bad uint64_t variant %d.\n",vtData->vt));
        return -1;
    }
}

static HRESULT
QueryVariant(WMIAccessor *wmi, PWCHAR field, PWCHAR table, VARIANT *vt)
{
    IEnumWbemClassObject *pEnum;
    BSTR query;
    unsigned query_len;
    IWbemClassObject *pclsObj;
    HRESULT hr;
    ULONG uReturn;
    uint64_t result;

    query_len = strlen("SELECT  FROM ") + wcslen(field) + wcslen(table) + 1;
    query = SysAllocStringLen(NULL, query_len);
    if (query == NULL) {
        hr = E_OUTOFMEMORY;
        goto err;
    }
    swprintf_s(query, query_len, L"SELECT %s FROM %s", field, table);
    pEnum = runQuery(wmi, query);
    SysFreeString(query);

    if (pEnum == NULL) {
        hr = E_OUTOFMEMORY;
        goto err;
    }

    hr = pEnum->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
    pEnum->Release();
    if (FAILED(hr))
        goto err;
    if (uReturn == 0) {
        hr = E_FAIL;
        goto err;
    }

    hr = pclsObj->Get(field, 0, vt, NULL, NULL);
    pclsObj->Release();

    return hr;

err:
    XsLog("Failed to query %S::%S (%x)", table, field, hr);
    return hr;
}

static uint64_t
QueryUint64(WMIAccessor *wmi, PWCHAR field, PWCHAR table)
{
    HRESULT hr;
    uint64_t res;
    VARIANT vt;

    memset(&vt, 0, sizeof(vt));

    hr = QueryVariant(wmi, field, table, &vt);
    if (FAILED(hr))
        return 0;

    res = GetVariantUint64(&vt);
    VariantClear(&vt);
    return res;
}

static BSTR
QueryBstr(WMIAccessor *wmi, PWCHAR field, PWCHAR table)
{
    HRESULT hr;
    BSTR res;
    VARIANT vt;

    memset(&vt, 0, sizeof(vt));

    hr = QueryVariant(wmi, field, table, &vt);
    if (FAILED(hr))
        return NULL;
    if (vt.vt != VT_BSTR) {
        VariantClear(&vt);
        return NULL;
    }
    return vt.bstrVal;
}

void GetWMIData(WMIAccessor *wmi, VMData& data)
{
    data.meminfo_free = QueryUint64(wmi, L"FreePhysicalMemory",
                                    L"Win32_OperatingSystem");
    //
    // Get total memory.  We don't support ballooning, and so this can't
    // change for the life of the VM.
    //

    static int64_t meminfo_total;
    if (meminfo_total == 0) {
        meminfo_total = QueryUint64(wmi, L"TotalPhysicalMemory",
                                    L"Win32_ComputerSystem");
        /* For some reason, TotalPhysicalMemory is in bytes but
           FreePhysicalMemoryy is in megabytes.  The agent expects
           megabytes, so do the conversion here. */
        meminfo_total >>= 10;
    }
    data.meminfo_total = meminfo_total;
}

void DumpOSData(WMIAccessor *wmi)
{
    BSTR os_name;
    BSTR host_name;
    BSTR domain;

    os_name = QueryBstr(wmi, L"Name", L"Win32_OperatingSystem");
    if (os_name != NULL) {
        string str = bstr2string(os_name);
        SysFreeString(os_name);

        XenstoreWrite("data/os_name", str.c_str(), str.length());
    }
    host_name = QueryBstr(wmi, L"Name", L"Win32_ComputerSystem");
    if (host_name != NULL) {
        string str = bstr2string(host_name);
        SysFreeString(host_name);

        XenstoreWrite("data/host_name", str.c_str(), str.length());
    }
    domain = QueryBstr(wmi, L"Domain", L"Win32_ComputerSystem");
    if (domain != NULL) {
        string str = bstr2string(domain);
        SysFreeString(domain);

        XenstoreWrite("data/domain", str.c_str(), str.length());
    }
}

/* hash comparator for strings which strips off trailing .exe
 * suffix */
class string_eq_exe {
private:
    static size_t len_without_suffix(const char *x)
    {
        size_t l;
        l = strlen(x);
        if (l > 4 && !strcmp(x + l - 4, ".exe"))
            l -= 4;
        return l;
    }

public:
    enum {bucket_size = 4, min_buckets = 8};
    bool operator()(const string &a, const string &b) const
    {
        const char *a_c, *b_c;
        size_t a_l, b_l;
        a_c = a.c_str();
        b_c = b.c_str();
        a_l = len_without_suffix(a_c);
        b_l = len_without_suffix(b_c);

        if (a_l != b_l)
            return 1;
        if (memcmp(a_c, b_c, a_l))
            return 1;
        else
            return 0;
    }

    size_t operator()(const string &a) const
    {
        size_t acc = 0;
        const char *c_str = a.c_str();
        size_t len = len_without_suffix(c_str);
        unsigned x;
        for (x = 0; x < len; x++)
            acc = (acc * 17 + c_str[x]) % 257;
        return acc;
    }
};

typedef stdext::hash_map <string, int, string_eq_exe>
   process_counters;

static process_counters *
GetCurrentProcessList(WMIAccessor *wmi)
{
    IEnumWbemClassObject *pEnum;
    IWbemClassObject *pclsObj;
    HRESULT hr;
    ULONG uReturn;
    string caption;
    VARIANT vtData;
    process_counters *work;

    work = new process_counters();

    if (!work) {
        DBGPRINT(("No memory for process counters?\n"));
        return NULL;
    }

    pEnum = runQuery(wmi, L"SELECT Caption,ProcessId FROM Win32_Process");
    if (!pEnum) {
        DBGPRINT(("Failed to query for running processes\n"));
        delete work;
        return NULL;
    }

    VariantInit(&vtData);

    while (1) {
        hr = pEnum->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (uReturn == 0)
            break;
        if (hr != WBEM_S_NO_ERROR) {
            DBGPRINT(("Error %x enumerating process list\n", hr));
            goto failed;
        }

        hr = pclsObj->Get(L"Caption", 0, &vtData, NULL, NULL);
        if (hr != WBEM_S_NO_ERROR) {
            DBGPRINT(("Error %x getting process caption\n", hr));
            goto failed;
        }
        if ( vtData.vt == VT_BSTR ) {
            caption = bstr2string(vtData.bstrVal);
        } else {
            caption = string("<not a string>");
        }
        VariantClear(&vtData);

        (*work)[caption]++;

        pclsObj->Release();
        pclsObj = NULL;
    }

    pEnum->Release();

    return work;

failed:
    if (pclsObj)
        pclsObj->Release();
    VariantClear(&vtData);
    pEnum->Release();
    delete work;

    return NULL;
}

static void
UpdateProcessListInStore(process_counters *live)
{
    char **wanted_entries;
    unsigned nr_wanted_entries;
    int res;
    unsigned i;
    char buf[4096];

    res = XenstoreList("data/processes", &wanted_entries,
                       &nr_wanted_entries);
    if (res < 0)
        return;

    for (i = 0; i < nr_wanted_entries; i++) {
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "data/processes/%s",
                    wanted_entries[i]);
        XenstorePrintf(buf, "%d", (*live)[string(wanted_entries[i])]);
        xs2_free(wanted_entries[i]);
    }
    xs2_free(wanted_entries);
}

void
UpdateProcessListInStore(WMIAccessor *wmi)
{
    XsLogMsg("updating process list in store");
    process_counters *curProcList = GetCurrentProcessList(wmi);
    if (curProcList)
        UpdateProcessListInStore(curProcList);
    delete curProcList;
    XsLogMsg("updated process list in store");
}
