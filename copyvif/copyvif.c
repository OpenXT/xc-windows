/*
 * Copyright (c) 2009 Citrix Systems, Inc.
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

/* Simple thing which walks over every active NIC in the system and
   copies its configuration to a place where xennet/xennet6 can get at
   it, hence arrange to transfer emulated NIC settings over to the PV
   one. */
/* Leaks like a sieve, but we don't care because it doesn't run for
   very long. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <iptypes.h>
#include <iphlpapi.h>
#include <aclapi.h>
#include <xs_private.h>

#define SERVICES_KEY "SYSTEM\\CurrentControlSet\\Services"
#define SERVICE_KEY(x) SERVICES_KEY "\\" x
#define RTL8139_SERVICE_KEY SERVICE_KEY("rtl8139")

static void render_error_logfile(struct xs_error_renderer *this,
                                 const char *msg);

static struct xs_error_renderer
err_print = {render_error_logfile};
static FILE *
logfile;

static void
render_error_logfile(struct xs_error_renderer *this,
                     const char *msg)
{
    UNREFERENCED_PARAMETER(this);
    fputs(msg, logfile);
    fputs("\n", logfile);
    fflush(logfile);
}

static void
err(unsigned code, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    xs_vwin_err(1, code, &err_print, fmt, args);
}


static DWORD
read_reg_dword(HKEY parent_key, const TCHAR *subkey, const TCHAR *value)
{
    HKEY key;
    LONG r;
    DWORD type;
    DWORD val;
    DWORD sz;

    r = RegOpenKeyEx(parent_key, subkey, 0, KEY_QUERY_VALUE, &key);
    if (r != ERROR_SUCCESS)
        return 0;
    sz = sizeof(val);
    r = RegQueryValueEx(key, value, 0, &type, (BYTE*)&val, &sz);
    if (r != ERROR_SUCCESS)
        err(1, "querying %S::%S", subkey, value);
    if (type != REG_DWORD)
        xs_errx(1, &err_print, "expected %S::%S to be a DWORD, was type %d",
                subkey, value, type);
    RegCloseKey(key);
    return val;
}

static TCHAR *
read_reg_string(HKEY parent_key, const TCHAR *subkey, const TCHAR *value)
{
    HKEY key;
    LONG r;
    DWORD type;
    TCHAR *buf;
    DWORD buf_size;
    DWORD sz;

    r = RegOpenKeyEx(parent_key, subkey, 0, KEY_QUERY_VALUE, &key);
    if (r != ERROR_SUCCESS)
        err(1, "opening %S", subkey);
    buf_size = 16;
    buf = malloc(buf_size + sizeof(TCHAR));
    while (1) {
        sz = buf_size;
        r = RegQueryValueEx(key, value, 0, &type, (BYTE *)buf, &sz);
        if (r == ERROR_SUCCESS)
            break;
        if (r != ERROR_MORE_DATA)
            err(r, "querying %S::%S", subkey, value);
        free(buf);
        buf = malloc(sz+sizeof(TCHAR));
        buf_size = sz;
    }
    if (type != REG_SZ)
        xs_errx(1, &err_print, "expected %S::%S to be a string, was type %d",
                subkey, value, type);
    RegCloseKey(key);
    buf[sz/sizeof(TCHAR)] = 0;
    return buf;
}

static TCHAR **
read_reg_multi_string(HKEY parent_key, const TCHAR *subkey,
                      const TCHAR *value)
{
    HKEY key;
    LONG r;
    DWORD type;
    TCHAR *buf;
    DWORD buf_size;
    DWORD sz;
    TCHAR **res;
    unsigned nr_strings;
    unsigned x;
    unsigned y;

    r = RegOpenKeyEx(parent_key, subkey, 0, KEY_QUERY_VALUE, &key);
    if (r != ERROR_SUCCESS)
        err(r, "opening %S", subkey);
    buf_size = 16;
    buf = malloc(buf_size + 2 * sizeof(TCHAR));
    while (1) {
        sz = buf_size;
        r = RegQueryValueEx(key, value, 0, &type, (BYTE *)buf, &sz);
        if (r == ERROR_SUCCESS)
            break;
        if (r != ERROR_MORE_DATA)
            err(r, "querying %S::%S", subkey, value);
        free(buf);
        buf = malloc(sz+2*sizeof(TCHAR));
        buf_size = sz;
    }
    RegCloseKey(key);
    buf[sz/sizeof(TCHAR)] = 0;
    buf[sz/sizeof(TCHAR)+1] = 0;
    if (type == REG_SZ) {
        xs_warnx(&err_print, "expected a MULTI_SZ at %S::%S, got an SZ",
                 subkey, value);
        res = malloc(sizeof(res[0]) * 2);
        res[0] = buf;
        res[1] = NULL;
    } else if (type == REG_MULTI_SZ) {
        nr_strings = 0;
        x = 0;
        if (buf[0] != 0 || buf[1] != 0) {
            while (1) {
                while (buf[x] != 0)
                    x++;
                nr_strings++;
                x++;
                if (buf[x] == 0)
                    break;
            }
        }
        res = calloc(sizeof(res[0]), (nr_strings + 1));
        nr_strings = 0;
        x = 0;
        if (buf[0] != 0 || buf[1] != 0) {
            while (1) {
                y = x;
                while (buf[y] != 0)
                    y++;
                res[nr_strings] = malloc((y - x + 1) * sizeof(TCHAR));
                memcpy(res[nr_strings], buf + x, (y - x + 1) * sizeof(TCHAR));
                nr_strings++;
                x = y + 1;
                if (buf[x] == 0)
                    break;
            }
        }
        free(buf);
    } else {
        xs_errx(1, &err_print,
                "expected %S::%S to be a string or multi string, was type %d",
                subkey, value, type);
        res = NULL;
    }

    return res;
}

static PIP_ADAPTER_INFO
get_win32_adapter_info(void)
{
    PIP_ADAPTER_INFO buffer;
    ULONG buffer_size;
    DWORD r;

    buffer_size = sizeof(*buffer);
    buffer = malloc(buffer_size);
    while (1) {
        r = GetAdaptersInfo(buffer, &buffer_size);
        switch (r) {
        case ERROR_SUCCESS:
            return buffer;
        case ERROR_NO_DATA:
            free(buffer);
            return NULL;
        case ERROR_BUFFER_OVERFLOW:
            free(buffer);
            buffer = malloc(buffer_size);
            break;
        default:
            err(r, "getting adapter list");
        }
    }
}

static const IP_ADAPTER_INFO *
find_adapter_by_uuid(const IP_ADAPTER_INFO *adapters, const char *uuid)
{
    while (adapters && strcmp(adapters->AdapterName, uuid))
        adapters = adapters->Next;
    return adapters;
}

static void
copy_registry_key(HKEY source_root,
                  const TCHAR *source_path,
                  HKEY dest_root,
                  const TCHAR *dest_path)
{
    LONG r;
    HKEY source_key;
    HKEY dest_key;
    SECURITY_ATTRIBUTES sec_attrib;
    PSECURITY_DESCRIPTOR sec_descriptor;
    TCHAR valueName[16384];
    DWORD valueNameLen;
    DWORD dataSize;
    DWORD index;
    DWORD type;
    void *valueData;
    DWORD subkeyNameLen;
    TCHAR subkeyName[256];

    xs_warnx(&err_print, "copy registry key %S to %S", source_path,
             dest_path);
    r = RegOpenKeyEx(source_root, source_path, 0,
                     KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &source_key);
    if (r != ERROR_SUCCESS)
        err(r, "opening %s for source of copy", source_path);
    r = GetSecurityInfo(source_key, SE_REGISTRY_KEY, 0, NULL, NULL, NULL,
                        NULL, &sec_descriptor);
    if (r != ERROR_SUCCESS)
        err(r, "querying security attributes of %s", source_path);
    memset(&sec_attrib, 0, sizeof(sec_attrib));
    sec_attrib.nLength = sizeof(sec_attrib);
    sec_attrib.lpSecurityDescriptor = sec_descriptor;
    sec_attrib.bInheritHandle = FALSE;
    r = RegCreateKeyEx(dest_root, dest_path, 0, NULL, 0,
                       KEY_CREATE_SUB_KEY | KEY_SET_VALUE, &sec_attrib,
                       &dest_key, NULL);
    if (r != ERROR_SUCCESS)
        err(r, "create %s as destination of copy", dest_path);
    LocalFree(sec_descriptor);

    /* Transfer values */
    index = 0;
    while (1) {
        valueNameLen = sizeof(valueName) / sizeof(valueName[0]);
        dataSize = 0;
        r = RegEnumValue(source_key, index, valueName, &valueNameLen,
                         NULL, &type, NULL, &dataSize);
        if (r == ERROR_NO_MORE_ITEMS)
            break;

#if 0
        /* RegEnumValue() has a bad habit of returning completely
           nonsense error values if dataSize was originally 0.  Ignore
           the problem by just not checking return values; the second
           call to RegEnumValue is the important one, anyway. */
        if (r != ERROR_MORE_DATA)
            err(r,
                "expected enum values of %S to fail with ERROR_MORE_DATA (index %d, size %d)",
                source_path, index, dataSize);
#endif

        xs_warnx(&err_print, "transfer %.*S", valueNameLen,
                 valueName);
        valueData = malloc(dataSize);
        valueNameLen = sizeof(valueName) / sizeof(valueName[0]);
        r = RegEnumValue(source_key, index, valueName, &valueNameLen,
                         NULL, &type, valueData, &dataSize);
        if (r != ERROR_SUCCESS)
            err(r, "querying %S::%S", source_path, valueName);
        r = RegSetValueEx(dest_key, valueName, 0, type,
                          valueData, dataSize);
        if (r != ERROR_SUCCESS)
            err(r, "setting value %S::%S", dest_path, valueName);
        free(valueData);
        index++;
        xs_warnx(&err_print, "transfered %.*S", valueNameLen,
                 valueName);
    }

    /* And subkeys */
    index = 0;
    while (1) {
        subkeyNameLen = sizeof(subkeyName) / sizeof(subkeyName[0]);
        r = RegEnumKeyEx(source_key, index, subkeyName, &subkeyNameLen,
                         NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS)
            break;
        if (r != ERROR_SUCCESS)
            err(r, "enumerating subkeys of %S (slot %d)", source_path,
                index);
        copy_registry_key(source_key, subkeyName, dest_key, subkeyName);
        index++;
    }

    RegCloseKey(source_key);
    RegCloseKey(dest_key);

    xs_warnx(&err_print, "done copy registry key %S to %S", source_path,
             dest_path);
}

static TCHAR *
string2tstr(const char *s)
{
    size_t l;
    TCHAR *res;
    unsigned x;

    l = strlen(s) + 1;
    res = malloc(l * sizeof(TCHAR));
    memset(res, 0, l * sizeof(TCHAR));
    for (x = 0; s[x]; x++)
        res[x] = s[x];
    return res;
}

static char *
tstr2string(const TCHAR *s)
{
    size_t l;
    char *res;
    unsigned x;

    l = lstrlen(s) + 1;
    res = malloc(l * sizeof(char));
    memset(res, 0, l * sizeof(char));
    for (x = 0; s[x]; x++) {
        res[x] = (char)s[x];
        if (res[x] != s[x])
            xs_errx(1, &err_print, "expected %S to be pure ascii (%s)!", s,
                    res);
    }
    return res;
}

static void
transfer_nic_to_service(const char *uuid, const char *mac,
                        const char *service)
{
    LONG r;
    HKEY key1;
    HKEY key2;

    xs_warnx(&err_print, "transfer nic uuid %s mac %s service %s",
             uuid, mac, service);
    r = RegCreateKeyEx(HKEY_LOCAL_MACHINE,
                       string2tstr(xs_asprintf("%s\\%s",
                                               SERVICES_KEY, service)),
                       0,
                       NULL,
                       0,
                       KEY_CREATE_SUB_KEY,
                       NULL,
                       &key1,
                       NULL);
    if (r != ERROR_SUCCESS)
        err(r, "creating %s\\%s", SERVICES_KEY, service);
    r = RegCreateKeyEx(key1, TEXT("Parameters"), 0, NULL, 0,
                       KEY_CREATE_SUB_KEY, NULL, &key2, NULL);
    if (r != ERROR_SUCCESS)
        err(r, "creating %s\\%s\\Parameters", SERVICES_KEY, service);
    RegCloseKey(key1);
    r = RegCreateKeyEx(key2, TEXT("nics"), 0, NULL, 0, KEY_CREATE_SUB_KEY,
                       NULL, &key1, NULL);
    if (r != ERROR_SUCCESS)
        err(r, "creating %s\\%s\\Parameters\\nics", SERVICES_KEY, service);
    RegCloseKey(key2);
    r = RegCreateKeyEx(key1, string2tstr(mac), 0, NULL, 0, KEY_CREATE_SUB_KEY,
                       NULL, &key2, NULL);
    if (r != ERROR_SUCCESS)
        err(r, "creating %s\\%s\\Parameters\\nics\\%s", SERVICES_KEY, service, mac);
    RegCloseKey(key1);
    RegCloseKey(key2);

    copy_registry_key(HKEY_LOCAL_MACHINE,
                      string2tstr(
                          xs_asprintf("%s\\Parameters\\Interfaces\\Tcpip_%s",
                                      SERVICE_KEY("NETBT"), uuid)),
                      HKEY_LOCAL_MACHINE,
                      string2tstr(xs_asprintf("%s\\%s\\Parameters\\nics\\%s\\nbt",
                                              SERVICES_KEY, service, mac)));
    copy_registry_key(HKEY_LOCAL_MACHINE,
                      string2tstr(
                          xs_asprintf("%s\\Parameters\\Interfaces\\%s",
                                      SERVICE_KEY("Tcpip"), uuid)),
                      HKEY_LOCAL_MACHINE,
                      string2tstr(xs_asprintf("%s\\%s\\Parameters\\nics\\%s\\tcpip",
                                              SERVICES_KEY, service, mac)));
    copy_registry_key(HKEY_LOCAL_MACHINE,
                      string2tstr(
                          xs_asprintf("%s\\Parameters\\Interfaces\\%s",
                                      SERVICE_KEY("Tcpip6"), uuid)),
                      HKEY_LOCAL_MACHINE,
                      string2tstr(xs_asprintf("%s\\%s\\Parameters\\nics\\%s\\tcpip6",
                                              SERVICES_KEY, service, mac)));

}

static void
transfer_nic_by_uuid(const IP_ADAPTER_INFO *adapters, const char *uuid)
{
    const IP_ADAPTER_INFO *adapter;
    char *nic_mac;

    adapter = find_adapter_by_uuid(adapters, uuid);
    if (!adapter) {
        xs_warnx(&err_print, "cannot find MAC address for adapter %s", uuid);
        return;
    }
    if (adapter->AddressLength != 6) {
        xs_warnx(&err_print,
                 "adapter %s has strange MAC address length %d (should be 6)",
                uuid, adapter->AddressLength);
        return;
    }
    nic_mac = xs_asprintf("%02X_%02X_%02X_%02X_%02X_%02X",
                          adapter->Address[0],
                          adapter->Address[1],
                          adapter->Address[2],
                          adapter->Address[3],
                          adapter->Address[4],
                          adapter->Address[5]);
    transfer_nic_to_service(uuid, nic_mac, "xennet");
    transfer_nic_to_service(uuid, nic_mac, "xennet6");
}

static void
handle_emul_nic_service(const IP_ADAPTER_INFO *adapter_info,
                        const char *service)
{
    const char *service_key;
    const char *enum_key;
    unsigned nr_emul_cards;
    unsigned x;
    char *pci_device_id;
    char *driver_id;
    char *dev_uuid;
    TCHAR **linkage;

    service_key = xs_asprintf("%s\\%s", SERVICES_KEY, service);
    enum_key = xs_asprintf("%s\\enum", service_key);
    nr_emul_cards =
        read_reg_dword(HKEY_LOCAL_MACHINE,
                       string2tstr(enum_key),
                       TEXT("count"));
    xs_warnx(&err_print, "%d class %s emulated NICs to copy.",
             nr_emul_cards, service);
    for (x = 0; x < nr_emul_cards; x++) {
        pci_device_id =
            tstr2string(
                read_reg_string(
                    HKEY_LOCAL_MACHINE,
                    string2tstr(enum_key),
                    string2tstr(xs_asprintf("%d", x))));
        xs_warnx(&err_print, "device id %s", pci_device_id);
        driver_id =
            tstr2string(
                read_reg_string(
                    HKEY_LOCAL_MACHINE,
                    string2tstr(xs_asprintf("System\\CurrentControlSet\\Enum\\%s", pci_device_id)),
                    TEXT("driver")));
        xs_warnx(&err_print, "driver id %s", driver_id);
        linkage = read_reg_multi_string(
            HKEY_LOCAL_MACHINE,
            string2tstr(xs_asprintf("system\\currentcontrolset\\control\\class\\%s\\Linkage", driver_id)),
            TEXT("RootDevice"));
        xs_warnx(&err_print, "linkage %p", linkage);
        xs_warnx(&err_print, "linkage[0] %p", linkage[0]);
        xs_warnx(&err_print, "linkage[0] %S", linkage[0]);
        dev_uuid = tstr2string(linkage[0]);
        xs_warnx(&err_print, "dev uuid %s", dev_uuid);
        transfer_nic_by_uuid(adapter_info, dev_uuid);
        xs_warnx(&err_print, "done %s.", dev_uuid);
    }
}

int __cdecl
main(int argc, char *argv[])
{
    PIP_ADAPTER_INFO adapter_info;

    if (argc == 1) {
        logfile = stderr;
    } else if (argc == 2) {
        logfile = fopen(argv[1], "a");
        if (!logfile)
            xs_err(1, &xs_render_error_msgbox, "opening logfile %s",
                   argv[1]);
    } else {
        xs_errx(1, &xs_render_error_msgbox,
                "expected to get at most one argument, the name of the log file");
    }

    adapter_info = get_win32_adapter_info();
    handle_emul_nic_service(adapter_info, "rtl8139");
    handle_emul_nic_service(adapter_info, "rtl8023xp");
    handle_emul_nic_service(adapter_info, "rtl8023x64");
    fclose(logfile);

    return 0;
}
