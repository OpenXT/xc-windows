//
// settings.c - Stuff to copy settings from the ioemu device to the PV device
//
// Copyright (c) 2006, XenSource, Inc. - All rights reserved.
//

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


/* This opens and closes registry keys far more often than is needed,
   and is probably a shade on the fragile side when things fail. */

#ifndef NDIS60_MINIPORT
#pragma warning( push, 3 )

#include "precomp.h"
#include "stdlib.h"
#include "scsiboot.h"

#pragma warning( pop )

#else /* NDIS60_MINIPORT */
#include "common.h"
#endif /* NDIS60_MINIPORT */

#include "ntstrsafe.h"
#include "../xenutil/registry.h"

#define CONTROL_SET(x) L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\" x
#define SERVICE_KEY(x) CONTROL_SET(L"Services\\") x
#define SERVICE_PARAMETERS(x) SERVICE_KEY(x) L"\\Parameters"

#ifdef NDIS60_MINIPORT
#define SERVICE L"xennet6"
#else /* NDIS60_MINIPORT */
#define SERVICE L"xennet"
#endif /* NDIS60_MINIPORT */

static PWCHAR
unicode_string_to_pwchar(const UNICODE_STRING *us)
{
    PWCHAR res;
    res = XmAllocateZeroedMemory(us->Length + sizeof(WCHAR));
    if (!res)
        return NULL;
    memcpy(res, us->Buffer, us->Length);
    return res;
}

static PWCHAR
string_to_wstring(PCSTR src)
{
    size_t len;
    PWCHAR res;
    unsigned x;

    len = strlen(src) + 1;
    res = XmAllocateZeroedMemory(len * sizeof(WCHAR));
    if (!res)
        return NULL;
    for (x = 0; x < len; x++)
        res[x] = src[x];
    return res;
}

static WCHAR *
zstrcat(
    IN  const WCHAR *Prefix,
    IN  const WCHAR *Suffix
    )
{
    SIZE_T          PrefixLength;
    SIZE_T          SuffixLength;
    SIZE_T          BufferLength;
    WCHAR           *Buffer;

    PrefixLength = wcslen(Prefix);
    SuffixLength = wcslen(Suffix);
    BufferLength = PrefixLength + SuffixLength + 1;

    Buffer = XmAllocateMemory(BufferLength * sizeof (WCHAR));
    if (Buffer == NULL)
        return NULL;

    memcpy(Buffer, Prefix, PrefixLength * sizeof (WCHAR));
    memcpy(Buffer + PrefixLength, Suffix, SuffixLength * sizeof (WCHAR));
    Buffer[BufferLength - 1] = L'\0';

    return Buffer;
}

static NTSTATUS
open_dest_key(const WCHAR *parent_path, const WCHAR *prefix, const WCHAR *suffix, PHANDLE out)
{
    WCHAR *path;
    NTSTATUS status;
    HANDLE parent;

    status = XenOpenRegistryKey(parent_path, GENERIC_ALL, &parent);
    if (!NT_SUCCESS(status))
        goto fail1;

    path = zstrcat(prefix, suffix);

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (path == NULL)
        goto fail2;

    status = XenCreateRegistryKey(parent, path, GENERIC_ALL, out);
    if (!NT_SUCCESS(status))
        goto fail3;

    XmFreeMemory(path);
    ZwClose(parent);

    return STATUS_SUCCESS;

fail3:
    TraceError(("%s: fail3\n", __FUNCTION__));

    XmFreeMemory(path);

fail2:
    TraceError(("%s: fail2\n", __FUNCTION__));

    ZwClose(parent);

fail1:
    TraceError(("%s: fail1 (%08x)\n", __FUNCTION__, status));

    return status;
}

static char *
MacToChar(const unsigned char *mac)
{
    return Xmasprintf("%02X_%02X_%02X_%02X_%02X_%02X",
                      mac[0], mac[1], mac[2], mac[3],
                      mac[4], mac[5]);
}

static PWCHAR
MacToWchar(const unsigned char *mac)
{
    char *temp;
    PWCHAR res;

    temp = MacToChar(mac);
    if (!temp)
        return NULL;
    res = string_to_wstring(temp);
    XmFreeMemory(temp);
    return res;
}

/* Open the appropriate SERVICE\\Parameters\\nic\\{mac} registry key,
   creating it if necessary. */
static NTSTATUS
_MpGetSettingsKey(PADAPTER pAdapter, PHANDLE out)
{
    PWCHAR mac;
    NTSTATUS status;
    HANDLE h1;
    HANDLE h2;

    status = XenOpenRegistryKey(SERVICE_KEY(SERVICE), GENERIC_ALL, &h1);
    if (!NT_SUCCESS(status))
        return status;
    status = XenCreateRegistryKey(h1, L"Parameters", GENERIC_ALL, &h2);
    ZwClose(h1);
    if (!NT_SUCCESS(status))
        return status;
    status = XenCreateRegistryKey(h2, L"nics", GENERIC_ALL, &h1);
    ZwClose(h2);
    if (!NT_SUCCESS(status))
        return status;
    mac = MacToWchar(pAdapter->CurrentAddress);
    if (!mac) {
        ZwClose(h1);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = XenCreateRegistryKey(h1, mac, GENERIC_ALL, out);
    XmFreeMemory(mac);
    ZwClose(h1);
    return status;
}

/* Check whether a particular service is set to start at boot.
   Returns TRUE if it is, or FALSE if it isn't.  Also returns FALSE if
   the service doesn't exist. */
static BOOLEAN
ServiceIsEnabled(PWCHAR serviceKey)
{
    PKEY_VALUE_PARTIAL_INFORMATION info = NULL;
    NTSTATUS status;
    BOOLEAN res;
    ULONG start_type;

    status = XenReadRegistryValue(serviceKey, L"Start", &info);
    if (!NT_SUCCESS(status)) {
        TraceInfo(("Can't get at %S\n", serviceKey));
        return FALSE;
    }
    if (info->Type == REG_DWORD) {
        start_type = (ULONG)*info->Data;
        /* Start type 0 -> boot, type 1 -> system, type 2 ->
           automatic, 3 -> manual, 4 -> disabled. */
        if (start_type == 0 || start_type == 1 || start_type == 2) {
            TraceVerbose(("Service %S enabled.\n", serviceKey));
            res = TRUE;
        } else {
            TraceVerbose(("Service %S disabled.\n", serviceKey));
            res = FALSE;
        }
    } else {
        TraceWarning(("%S\\start wasn't a DWORD?\n", serviceKey));
        res = FALSE;
    }
    ExFreePool(info);

    return res;
}

/* Decide whether to allow csum_blank packets to enter the Windows
   network stack if we don't have a per-interface override.  We allow
   it unless the remote access or ICS services are enabled, because
   they often needs to forward packets and that interacts badly with
   blank checksums. */
static BOOLEAN
FindDefaultAllowCsumBlank(void)
{
    BOOLEAN raEnabled;
    BOOLEAN icsEnabled;

    raEnabled = ServiceIsEnabled(SERVICE_KEY(L"RemoteAccess"));
    icsEnabled = ServiceIsEnabled(SERVICE_KEY(L"SharedAccess"));
    if (raEnabled || icsEnabled) {
        TraceVerbose(("Csum blank unsafe because of running services.\n"));
        return FALSE;
    } else {
        TraceVerbose(("Csum blank safe.\n"));
        return TRUE;
    }
}

static char *
find_xenstore_prefix(PADAPTER pAdapter)
{
    char *mac;
    char *res;
    mac = MacToChar(pAdapter->PermanentAddress);
    if (!mac)
        return NULL;
    res = Xmasprintf("vm-data/vif/%s", mac);
    XmFreeMemory(mac);
    return res;
}

static void
do_xenstore_settings(const char *xenstore_prefix,
                     const char *xenstore_suffix,
                     HANDLE reg_area)
{
    char *xb_area;
    NTSTATUS status;
    char **items;
    unsigned x;

    xb_area = Xmasprintf("%s/%s", xenstore_prefix, xenstore_suffix);

    status = STATUS_NO_MEMORY;
    if (xb_area == NULL)
        goto fail1;

    status = xenbus_ls(XBT_NIL, xb_area, &items);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND)
        goto done;

    if (!NT_SUCCESS(status))
        goto fail2;

    for (x = 0; items[x]; x++) {
        XenSetRegistryValueFromXenstore(xb_area, items[x], reg_area);
        XmFreeMemory(items[x]);
    }
    XmFreeMemory(items);

done:
    XmFreeMemory(xb_area);

    return;

fail2:
    TraceError(("%s: fail2\n", __FUNCTION__));

    XmFreeMemory(xb_area);

fail1:
    TraceError(("%s: fail1 (%08x)\n", __FUNCTION__, status));
}

/* Find the area of the registry which corresponds to the NDIS
   configuration for adapter uuid @uuid.  This will be sub-key of
   HKLM\system\currentcontrolset\control\class\<GUID_DEVCLASS_NET> which has
   NetCfgInstanceId a REG_SZ with value @uuid.

   GUID_DEVCLASS_NET = 0x4d36e972L, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08,
   0x00, 0x2b, 0xe1, 0x03, 0x18
*/
static NTSTATUS
open_ndis_parameters(const WCHAR *uuid, HANDLE *out)
{
    HANDLE class;
    NTSTATUS status;
    unsigned index;
    PKEY_BASIC_INFORMATION keyBuffer;
    DWORD keyBufferLength;
    UNICODE_STRING subkeyName;
    DECLARE_CONST_UNICODE_STRING(NetCfgInstanceId,
                                 L"NetCfgInstanceId");
    OBJECT_ATTRIBUTES subkeyAttrs;
    HANDLE candidate_handle;
    DWORD valueBufferLength;
    PKEY_VALUE_PARTIAL_INFORMATION valueBuffer;

    keyBuffer = NULL;
    class = NULL;
    candidate_handle = NULL;
    valueBuffer = NULL;

    status = XenOpenRegistryKey(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}",
                                GENERIC_ALL,
                                &class);
    if (!NT_SUCCESS(status)) {
        TraceError(("Cannot open network class key\n"));
        return status;
    }
    for (index = 0; ; index++) {
        status = ZwEnumerateKey(class,
                                index,
                                KeyBasicInformation,
                                NULL,
                                0,
                                &keyBufferLength);
        if (status == STATUS_NO_MORE_ENTRIES) {
            /* Failed to find it */
            goto err;
        }
        if (status != STATUS_BUFFER_OVERFLOW &&
            status != STATUS_BUFFER_TOO_SMALL) {
            if (NT_SUCCESS(status))
                status = STATUS_UNSUCCESSFUL;
            goto err;
        }
        XmFreeMemory(keyBuffer);
        keyBuffer = XmAllocateZeroedMemory(keyBufferLength);
        if (!keyBuffer) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto err;
        }
        status = ZwEnumerateKey(class,
                                index,
                                KeyBasicInformation,
                                keyBuffer,
                                keyBufferLength,
                                &keyBufferLength);
        if (!NT_SUCCESS(status))
            goto err;

        XM_ASSERT3U(keyBuffer->NameLength, <, 65536);
        subkeyName.Length = (USHORT)keyBuffer->NameLength;
        subkeyName.MaximumLength = (USHORT)keyBuffer->NameLength;
        subkeyName.Buffer = keyBuffer->Name;
        InitializeObjectAttributes(&subkeyAttrs, &subkeyName,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                   class, NULL);
        status = ZwOpenKey(&candidate_handle, GENERIC_ALL, &subkeyAttrs);
        if (!NT_SUCCESS(status))
            goto err;

        status = ZwQueryValueKey(candidate_handle,
                                 (PUNICODE_STRING)&NetCfgInstanceId,
                                 KeyValuePartialInformation,
                                 NULL,
                                 0,
                                 &valueBufferLength);
        if (status != STATUS_BUFFER_OVERFLOW &&
            status != STATUS_BUFFER_TOO_SMALL) {
            ZwClose(candidate_handle);
            continue;
        }
        XmFreeMemory(valueBuffer);
        valueBuffer = XmAllocateZeroedMemory(valueBufferLength);
        if (!valueBuffer) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto err;
        }
        status = ZwQueryValueKey(candidate_handle,
                                 (PUNICODE_STRING)&NetCfgInstanceId,
                                 KeyValuePartialInformation,
                                 valueBuffer,
                                 valueBufferLength,
                                 &valueBufferLength);
        if (!NT_SUCCESS(status))
            goto err;
        if (valueBuffer->Type != REG_SZ ||
            valueBuffer->DataLength < wcslen(uuid) * sizeof(WCHAR) ||
            wcscmp((PWCHAR)valueBuffer->Data, uuid)) {
            XmFreeMemory(valueBuffer);
            valueBuffer = NULL;
            ZwClose(candidate_handle);
            continue;
        }
        goto found_it;
    }

found_it:
    status = STATUS_SUCCESS;
    *out = candidate_handle;

err:
    XmFreeMemory(keyBuffer);
    XmFreeMemory(valueBuffer);
    if (class)
        ZwClose(class);
    if (!NT_SUCCESS(status)) {
        TraceError(("Cannot find NDIS config for uuid %S\n", uuid));
        if (candidate_handle)
            ZwClose(candidate_handle);
    }
    return status;
}

static NDIS_STATUS
_NdisOpenConfiguration(
    IN  PADAPTER                pAdapter,
    OUT NDIS_HANDLE             *pConfigurationHandle
    )
{
    NDIS_STATUS                 ndisStatus;
#ifdef NDIS60_MINIPORT
    NDIS_CONFIGURATION_OBJECT   configObject;

    configObject.Header.Type = NDIS_OBJECT_TYPE_CONFIGURATION_OBJECT;
    configObject.Header.Revision = NDIS_CONFIGURATION_OBJECT_REVISION_1;
    configObject.Header.Size = NDIS_SIZEOF_CONFIGURATION_OBJECT_REVISION_1;
    configObject.NdisHandle = pAdapter->NdisAdapterHandle;
    configObject.Flags = 0;

    ndisStatus = NdisOpenConfigurationEx(&configObject, pConfigurationHandle);
#else /* !NDIS60_MINIPORT */
    UNREFERENCED_PARAMETER(pAdapter);

    NdisOpenConfiguration(&ndisStatus, pConfigurationHandle,
                          pAdapter->WrapperConfigurationContext);
#endif /* !NDIS60_MINIPORT */

    return ndisStatus;
}

NDIS_STATUS
MpSetAdapterSettings(
    IN  PADAPTER        pAdapter
    )
{
    HANDLE              srcHandle;
    HANDLE              tcpipDestHandle;
    HANDLE              tcpip6DestHandle;
    HANDLE              nbtDestHandle;
    HANDLE              parametersDestHandle;
    NDIS_HANDLE         hConfigurationHandle;
    NDIS_HANDLE         hNdisHandle;
    ULONG               ulIndex;
    char                *xenstore_prefix;
    NDIS_STATUS         ndisStatus;
    NTSTATUS            status;

    XM_ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    status = _MpGetSettingsKey(pAdapter, &srcHandle);
    if (!NT_SUCCESS(status))
        goto fail1;

    ndisStatus = _NdisOpenConfiguration(pAdapter, &hConfigurationHandle);

    status = STATUS_UNSUCCESSFUL;
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        goto fail2;

    tcpipDestHandle = NULL;
    tcpip6DestHandle = NULL;
    nbtDestHandle = NULL;
    parametersDestHandle = NULL;

    for (ulIndex = 0; ; ulIndex++) {
        NDIS_STRING     ndisValue;
        UNICODE_STRING  linkage;

        NdisOpenConfigurationKeyByIndex(&ndisStatus, hConfigurationHandle,
                                        ulIndex, &ndisValue, &hNdisHandle);

        status = STATUS_UNSUCCESSFUL;
        if (ndisStatus != NDIS_STATUS_SUCCESS)
            goto fail3;

        RtlInitUnicodeString(&linkage, L"Linkage");
        if (!RtlCompareUnicodeString(&ndisValue, &linkage, TRUE)) {
            PNDIS_CONFIGURATION_PARAMETER   pNdisData;
            PWCHAR                          uuid;

            RtlInitUnicodeString(&ndisValue, L"RootDevice");
            NdisReadConfiguration(&ndisStatus, &pNdisData, hNdisHandle,
                                  &ndisValue, NdisParameterMultiString);

            status = STATUS_UNSUCCESSFUL;
            if (ndisStatus != NDIS_STATUS_SUCCESS)
                goto fail4;

            // Get a NUL terminated wide string copy of the UUID
            uuid = unicode_string_to_pwchar(&pNdisData->ParameterData.StringData);

            status = STATUS_INSUFFICIENT_RESOURCES;
            if (uuid == NULL)
                goto fail5;

            status = open_dest_key(
                SERVICE_PARAMETERS(L"NetBT") L"\\Interfaces\\",
                L"Tcpip_",
                uuid,
                &nbtDestHandle);
            if (!NT_SUCCESS(status))
                nbtDestHandle = NULL;

            status = open_dest_key(
                SERVICE_PARAMETERS(L"Tcpip") L"\\Interfaces\\",
                L"",
                uuid,
                &tcpipDestHandle);
            if (!NT_SUCCESS(status))
                tcpipDestHandle = NULL;

            status = open_dest_key(
                SERVICE_PARAMETERS(L"Tcpip6") L"\\Interfaces\\",
                L"",
                uuid,
                &tcpip6DestHandle);
            if (!NT_SUCCESS(status))
                tcpip6DestHandle = NULL;

            status = open_ndis_parameters(uuid, &parametersDestHandle);
            if (!NT_SUCCESS(status))
                parametersDestHandle = NULL;

            XmFreeMemory(uuid);
            break;
        }

        NdisCloseConfiguration(hNdisHandle);
        hNdisHandle = NULL;
    }

    if (tcpipDestHandle != NULL) {
        PWCHAR  src;

        TraceNotice(("%s: checking for tcpip values\n", __FUNCTION__));

        status = XenCreateRegistryKey(srcHandle, L"tcpip",
                                      KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_SET_VALUE,
                                      &src);
        if (NT_SUCCESS(status)) {
            XenMoveRegistryValues(src, tcpipDestHandle);
            ZwClose(src);
        }
    } else {
        TraceNotice(("%s: not checking for tcpip values\n", __FUNCTION__));
    }

    if (tcpip6DestHandle != NULL) {
        PWCHAR  src;

        TraceNotice(("%s: checking for tcpip6 values\n", __FUNCTION__));

        status = XenCreateRegistryKey(srcHandle, L"tcpip6",
                                      KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_SET_VALUE,
                                      &src);
        if (NT_SUCCESS(status)) {
            XenMoveRegistryValues(src, tcpip6DestHandle);
            ZwClose(src);
        }
    } else {
        TraceNotice(("%s: not checking for tcpip6 values\n", __FUNCTION__));
    }

    if (nbtDestHandle != NULL) {
        PWCHAR  src;

        TraceNotice(("%s: checking for nbt values\n", __FUNCTION__));

        status = XenCreateRegistryKey(srcHandle, L"nbt",
                                      KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_SET_VALUE,
                                      &src);
        if (NT_SUCCESS(status)) {
            XenMoveRegistryValues(src, nbtDestHandle);
            ZwClose(src);
        }
    } else {
        TraceNotice(("%s: not checking for nbt values\n", __FUNCTION__));
    }

    if (parametersDestHandle != NULL) {
        PWCHAR  src;

        TraceNotice(("%s: checking for xenserver values\n", __FUNCTION__));

        status = XenCreateRegistryKey(srcHandle, L"xenserver",
                                      KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_SET_VALUE,
                                      &src);
        if (NT_SUCCESS(status)) {
            XenMoveRegistryValues(src, parametersDestHandle);
            ZwClose(src);
        }
    } else {
        TraceNotice(("%s: not checking for xenserver values\n", __FUNCTION__));
    }

    xenstore_prefix = find_xenstore_prefix(pAdapter);
    if (xenstore_prefix != NULL) {
        if (tcpipDestHandle != NULL)
            do_xenstore_settings(xenstore_prefix, "tcpip", tcpipDestHandle);

        if (tcpip6DestHandle != NULL)
            do_xenstore_settings(xenstore_prefix, "tcpip6", tcpip6DestHandle);

        if (nbtDestHandle != NULL)
            do_xenstore_settings(xenstore_prefix, "nbt", nbtDestHandle);

        if (parametersDestHandle != NULL)
            do_xenstore_settings(xenstore_prefix, "xenserver", parametersDestHandle);

        XmFreeMemory(xenstore_prefix);
    }

    if (parametersDestHandle != NULL)
        ZwClose(parametersDestHandle);

    if (nbtDestHandle != NULL)
        ZwClose(nbtDestHandle);

    if (tcpip6DestHandle != NULL)
        ZwClose(tcpip6DestHandle);

    if (tcpipDestHandle != NULL)
        ZwClose(tcpipDestHandle);

    NdisCloseConfiguration(hNdisHandle);
    NdisCloseConfiguration(hConfigurationHandle);
    ZwClose(srcHandle);

    return NDIS_STATUS_SUCCESS;

fail5:
    TraceError(("%s: fail5\n", __FUNCTION__));
fail4:
    TraceError(("%s: fail4\n", __FUNCTION__));

    NdisCloseConfiguration(hNdisHandle);

fail3:
    TraceError(("%s: fail3\n", __FUNCTION__));

    NdisCloseConfiguration(hConfigurationHandle);

fail2:
    TraceError(("%s: fail2\n", __FUNCTION__));

    ZwClose(srcHandle);

fail1:
    TraceError(("%s: fail1 (%08x)\n", __FUNCTION__, status));

    return NDIS_STATUS_FAILURE;
}

NDIS_STATUS
MpGetAdvancedSettings(
    IN PADAPTER pAdapter
    )
{
    NDIS_HANDLE hConfigurationHandle;
    NDIS_STRING ndisValue;
    PNDIS_CONFIGURATION_PARAMETER pNdisData;
#ifdef NDIS60_MINIPORT
    BOOLEAN allowCsumBlank;
#endif
    NDIS_STATUS ndisStatus;
    NTSTATUS status;

    TraceVerbose (("====> '%s'\n", __FUNCTION__));

    ndisStatus = _NdisOpenConfiguration(pAdapter, &hConfigurationHandle);

    status = STATUS_UNSUCCESSFUL;
    if (ndisStatus != NDIS_STATUS_SUCCESS)
        goto fail1;

#define read_property(field, name, default_val) \
    do { \
        RtlInitUnicodeString(&ndisValue, name); \
        NdisReadConfiguration(&ndisStatus, &pNdisData, hConfigurationHandle, &ndisValue, NdisParameterInteger); \
        if (ndisStatus == NDIS_STATUS_SUCCESS) { \
            pAdapter->Properties.field = pNdisData->ParameterData.IntegerData; \
            TraceVerbose (("%ws = %d\n", name, pAdapter->Properties.field)); \
        } else { \
            TraceVerbose (("%ws not found (default = %d)\n", name, default_val)); \
            pAdapter->Properties.field = default_val; \
        } \
    } while (FALSE);

    read_property(ip_csum, L"*IPChecksumOffloadIPv4", 1);
    read_property(tcp_csum, L"*TCPChecksumOffloadIPv4", 3);
    read_property(udp_csum, L"*UDPChecksumOffloadIPv4", 3);
    read_property(lso, L"*LSOv1IPv4", 1);

#ifdef NDIS60_MINIPORT
    read_property(lro, L"LROIPv4", 0);
    read_property(allow_csum_blank, L"AllowCsumBlank", 1);
    read_property(force_csum, L"ForceCsum", 0);
    pAdapter->Receiver.ForceCsum = (BOOLEAN)pAdapter->Properties.force_csum;

    switch (pAdapter->Properties.allow_csum_blank) {
    case 0:
        allowCsumBlank = FALSE;
        break;
    case 2:
        allowCsumBlank = TRUE;
        break;
    default:
        allowCsumBlank = FindDefaultAllowCsumBlank();
        break;
    }

    pAdapter->Receiver.CsumBlankSafe = allowCsumBlank;
#endif

    NdisCloseConfiguration(hConfigurationHandle);

    TraceVerbose (("<==== '%s'\n", __FUNCTION__));
    return NDIS_STATUS_SUCCESS;

fail1:
    TraceError(("%s: fail1 (%08x)\n", __FUNCTION__, status));

    TraceVerbose (("<==== '%s'\n", __FUNCTION__));
    return NDIS_STATUS_FAILURE;
}
