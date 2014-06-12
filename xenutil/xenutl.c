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

#include "xenutl.h"
#include "aux_klib.h"
#include "gnttab.h"
#include "debug.h"
#include "hvm.h"
#include "xenbus.h"
#include "registry.h"
#include "xsmtcapi.h"

#define DEBUG_DEFAULT_FEATURE_SET (                               \
                                    DEBUG_PATCH_APIC            | \
                                    DEBUG_BALLOON               | \
                                    DEBUG_NIC_FAST_AND_LOOSE    | \
                                    DEBUG_PATCH_TLB_FLUSH       | \
                                    DEBUG_PATCH_SPINLOCKS       | \
                                    DEBUG_PATCH_2K_IDLE_DELAY   | \
                                    DEBUG_PATCH_KD_POLL         | \
                                    DEBUG_NIC_NO_DMA            | \
                                    DEBUG_FORCE_EARLY_UNPLUG    | \
                                    DEBUG_INTERNAL_XENNET       | \
                                    DEBUG_TRAP_DBGPRINT         | \
                                    DEBUG_DISABLE_LICENSE_CHECK | \
                                    0                             \
                                  )

static ULONG    _g_PVFeatureFlags   = DEBUG_DEFAULT_FEATURE_SET;

static BOOLEAN done_unplug; /* True if we've done a device unplug.
                               This is not reset when we hibernate, so
                               is only an approximation to whether the
                               emulated devices are actually
                               present. */

extern PULONG InitSafeBootMode;

static const CHAR *
FeatureFlagName(
    IN  ULONG   Bit
    )
{
#define _FLAG_NAME(_flag)                                       \
    case DEBUG_ ## _flag:                                       \
        return #_flag;

    XM_ASSERT(Bit < 32);
    switch (1ul << Bit) {
    _FLAG_NAME(NO_PARAVIRT);
    _FLAG_NAME(PATCH_BLUESCREEN);
    _FLAG_NAME(PATCH_APIC);
    _FLAG_NAME(NIC_FAST_AND_LOOSE);
    _FLAG_NAME(VERY_LOUD);
    _FLAG_NAME(BALLOON);
    _FLAG_NAME(VERY_QUIET);
    _FLAG_NAME(PATCH_TLB_FLUSH);
    _FLAG_NAME(PATCH_SPINLOCKS);
    _FLAG_NAME(FAKE_NETIF);
    _FLAG_NAME(NIC_8021_P);
    _FLAG_NAME(PATCH_KD_POLL);
    _FLAG_NAME(NIC_NO_TSO);
    _FLAG_NAME(NIC_NO_DMA);
    _FLAG_NAME(FORCE_EARLY_UNPLUG);
    _FLAG_NAME(PATCH_2K_IDLE_DELAY);
    _FLAG_NAME(HA_SAFEMODE);
    _FLAG_NAME(BOOT_EMULATED);
    _FLAG_NAME(HCT_DP_HACKS);
    _FLAG_NAME(TRACE_PROCESS_CREATE);
    _FLAG_NAME(TRACE_IMAGE_LOAD);
    _FLAG_NAME(INTERNAL_XENNET);
    _FLAG_NAME(TRAP_DBGPRINT);
    _FLAG_NAME(HCT_MODE);
    _FLAG_NAME(DISABLE_LICENSE_CHECK);
    _FLAG_NAME(NIC_EMULATED);
    default:
        break;
    }

    return "UNKNOWN";
}

static VOID
DumpFeatureFlags(
    VOID
    )
{
    ULONG   Flags = _g_PVFeatureFlags;
    ULONG   Bit;

    TraceNotice(("PV feature flags:\n"));
    Bit = 0;
    while (Flags != 0) {
        if (Flags & 0x00000001)
            TraceNotice(("- %s\n", FeatureFlagName(Bit)));

        Flags >>= 1;
        Bit++;
    }
}

static ULONG
wcstoix(__in PWCHAR a, __out PBOOLEAN err)
{
    ULONG acc = 0;
    if (err) *err = FALSE;
    if (!a || !a[0]) *err = TRUE;

    while (a[0] && a[0] != L' ') {
        if (a[0] >= L'0' && a[0] <= L'9')
            acc = acc * 16 + a[0] - L'0';
        else if (a[0] >= L'a' && a[0] <= L'f')
            acc = acc * 16 + a[0] - L'a' + 10;
        else if (a[0] >= L'A' && a[0] <= L'F')
            acc = acc * 16 + a[0] - L'A' + 10;
        else
        {
            if (err) *err = TRUE;
            break;
        }
        
        a++;
    }
    return acc;
}

/* Read a DWORD out of xenevtchn's parameters key. */
static NTSTATUS
ReadRegistryParameterDword(const WCHAR *value, ULONG *out)
{
    NTSTATUS stat;
    PKEY_VALUE_PARTIAL_INFORMATION pKeyValueInfo;

    pKeyValueInfo = NULL;

    stat = XenReadRegistryValue(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\xenevtchn\\Parameters",
                                value,
                                &pKeyValueInfo);
    if (NT_SUCCESS(stat))
    {
        if (pKeyValueInfo->Type == REG_DWORD)
        {
            *out = *((ULONG*)pKeyValueInfo->Data);
        }
        else
        {
            TraceError(("Expected %ws to be a DWORD, actually type %x\n",
                        value, pKeyValueInfo->Type));
            stat = STATUS_INVALID_PARAMETER;
        }
        ExFreePool(pKeyValueInfo);
    }
    return stat;
}

/* Read a flags field out of the registry.  Returns 0 if there is any
   error reading the key.  @value says which value to read; it is
   pulled out of the xenevtchn service's parameters key. */
static ULONG
ReadRegistryFlagsOrZero(PWCHAR value)
{
    ULONG res;
    NTSTATUS stat;

    stat = ReadRegistryParameterDword(value, &res);
    if (NT_SUCCESS(stat))
        return res;
    else
        return 0;
}

#define XUTIL_TAG 'LUTX'

static VOID
XenParseBootParams(void)
{
    NTSTATUS        Status;
    PKEY_VALUE_PARTIAL_INFORMATION pKeyValueInfo = NULL;

    PWCHAR          wzReturnValue = NULL;
    PWCHAR          wzPVstring;
    ULONG           features;
    BOOLEAN         bError;
    BOOLEAN         bDefault;

    //
    // XXX: HACK: Should never be called at anything other then
    // passive level but we cant import KeGetCurrentIRql in the xenvbd
    // and we try to call this again in dump_xenvbd at high irql which
    // is bad so the check is here to keep the compiler/linker happy.
    //
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }

    Status = ReadRegistryParameterDword(L"FeatureFlags", &features);
    if (NT_SUCCESS(Status))
        _g_PVFeatureFlags = features;
    _g_PVFeatureFlags |= ReadRegistryFlagsOrZero(L"SetFlags");
    _g_PVFeatureFlags &= ~ReadRegistryFlagsOrZero(L"ClearFlags");

    if (*InitSafeBootMode > 0) {
        _g_PVFeatureFlags |= DEBUG_NO_PARAVIRT;
    }   

    //
    // If the "NOPVBoot" value us in our service's key then do *not*
    // go into pv mode.
    //
    Status = XenReadRegistryValue(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\xenevtchn",
                                  L"NOPVBoot",
                                  &pKeyValueInfo);
    if (NT_SUCCESS(Status)) 
    {
        _g_PVFeatureFlags |= DEBUG_NO_PARAVIRT;
        ExFreePool(pKeyValueInfo);
        pKeyValueInfo = NULL;
    }

    //
    // Normally we want to assert paged code here but whatever. see above.
    //
    Status = XenReadRegistryValue(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control",
                                  L"SystemStartOptions",
                                  &pKeyValueInfo);
    if (! NT_SUCCESS(Status))
    {
        TraceError(("%s: Failed with Status = %d\n", __FUNCTION__, Status));
        goto _Cleanup;
    }

    //
    // A hack to null terminate the string
    //

    wzReturnValue = ExAllocatePoolWithTag ( PagedPool, 
                                            pKeyValueInfo->DataLength 
                                             + sizeof(WCHAR),
                                            XUTIL_TAG);
    if (wzReturnValue == NULL) 
    {
        ASSERT (FALSE);
        goto _Cleanup;
    }
    
    RtlCopyMemory (wzReturnValue, pKeyValueInfo->Data,
                   pKeyValueInfo->DataLength);
    wzReturnValue[pKeyValueInfo->DataLength/sizeof(WCHAR)] = L'\0';

    bError = FALSE;
    bDefault = FALSE;
    features = 0;

    //
    // find the /PV=X string where X is a hex string of features
    //
        
    wzPVstring = wcsstr (wzReturnValue, L" PV");

    if (wzPVstring != NULL)
    {

        switch (wzPVstring[3])
        {
        case L'=':
            features = wcstoix(&wzPVstring[4], &bError);
            break;

        case L'^':
                if (wzPVstring[4] == L'=')
                {
                    features = wcstoix(&wzPVstring[5], &bError);
                    features = _g_PVFeatureFlags ^ features;
                }
                else
                {
                    bError = TRUE;
                }
                break;

            case L'~':
                if (wzPVstring[4] == L'=')
                {
                    features = wcstoix(&wzPVstring[5], &bError);
                    features = _g_PVFeatureFlags & ~features;
                }
                else
                {
                    bError = TRUE;
                }
                break;

            case L'|':
                if (wzPVstring[4] == L'=')
                {
                    features = wcstoix(&wzPVstring[5], &bError);
                    features = _g_PVFeatureFlags | features;
                }
                else
                {
                    bError = TRUE;
                }
                break;

            case L'\0':
            case L'\t':
            case L' ':
                bDefault = TRUE;
                break;

            default:
                bError = TRUE;
                break;
        }

        if (!bError)
        {
            if (!bDefault)
            {
                TraceNotice (("%s: Booting PV features = %I64x\n", __FUNCTION__, features));
                _g_PVFeatureFlags = features;
            }
        }
        else
        {
            TraceWarning(("%s: error parsing /PV argument.\n", __FUNCTION__));
        }
    }

    if (_g_PVFeatureFlags & DEBUG_HA_SAFEMODE)
    {
        if (_g_PVFeatureFlags & DEBUG_NO_PARAVIRT)
        {
            //
            // If both the DEBUG_HA_SAFEMODE and DEBUG_NO_PARAVIRT flags
            // are set the clear the DEBUG_NO_PARAVIRT so we will start
            // up xenevtchn.
            //
            _g_PVFeatureFlags &= ~DEBUG_NO_PARAVIRT;
        } 
        else 
        {
            //
            // This means the DEBUG_HA_SAFEMODE flag was set but the
            // DEBUG_NO_PARAVIRT is not set, so we aren't in safe mode.
            // This is not a valid config so just clear the DEBUG_HA_SAFEMODE
            // flag
            //
            _g_PVFeatureFlags &= ~DEBUG_HA_SAFEMODE;
        }
    }

    if (!AustereMode) {
        if (_g_PVFeatureFlags & DEBUG_NO_PARAVIRT)
            TraceNotice(("Booting into NON-PV mode\n"));
        else if (_g_PVFeatureFlags & DEBUG_HA_SAFEMODE)
            TraceNotice(("Booting into NON-PV mode (HA PV mode)\n"));
        else
            TraceNotice(("Booting into PV mode\n"));
    }

_Cleanup:
    if (wzReturnValue != NULL)
        ExFreePool (wzReturnValue);
        
    if (pKeyValueInfo != NULL)
        ExFreePool (pKeyValueInfo);

    if (!CheckXenHypervisor()) {
        /* Turn off all feature flags except FAKE_NETIF, turn on
         * NO_PARAVIRT */
        _g_PVFeatureFlags &= DEBUG_FAKE_NETIF;
        _g_PVFeatureFlags |= DEBUG_NO_PARAVIRT;
    }

    if (!AustereMode)
        DumpFeatureFlags();

    return;
}

BOOLEAN
XenPVFeatureEnabled(
    IN ULONG    FeatureFlag
    )
{
    return (BOOLEAN)((_g_PVFeatureFlags & FeatureFlag) != 0);
}

BOOLEAN
_XmCheckXenutilVersionString(
    IN  const CHAR  *Module,
    IN  BOOLEAN     Critical,
    IN  const CHAR  *ExpectedVersion
    )
{
    if (strcmp(ExpectedVersion, XENUTIL_CURRENT_VERSION) == 0)
        return TRUE;

    if (Critical) {
        TraceCritical(("%s expected XENUTIL version %s, but got version %s!\n",
                       Module,
                       ExpectedVersion,
                       XENUTIL_CURRENT_VERSION));

        if (done_unplug)
            TraceBugCheck(("Can't start PV drivers, but have already disconnected emulated devices!\n"));

        // Prevent any further PV activity
        _g_PVFeatureFlags |= DEBUG_NO_PARAVIRT;
    } else {
        TraceWarning(("%s expected XENUTIL version %s, but got version %s!\n",
                      Module,
                      ExpectedVersion,
                      XENUTIL_CURRENT_VERSION));
    }

    return FALSE;
}

BOOLEAN
XenPVEnabled()
{
    if (_g_PVFeatureFlags & DEBUG_NO_PARAVIRT)
        return FALSE;
    else
        return TRUE;
}

/* Device unplugging and connecting to the log-to-dom0 port.  This is
   slightly icky, mostly because there are two different protocols.

   In the old protocol, we have two io ports on the PCI scsi
   controller, one for unplugging and one for logging.  Writing
   anything to the unplug port causes both network and IDE disks to
   get unplugged.  Log-to-dom0 is done by writing bytes to the other
   port.

   In the new protocol, we still have two ports, but they're
   hard-coded to 0x10 and 0x12, which are reserved to the motherboard
   in the ACPI tables.  You can tell the new protocol is available if
   reading 0x10 gives you the signature 0x49d2.  If the new protocol
   is available, there will be a version number which can be obtained
   by reading a byte from 0x12.  There are two versions:

   -- 0, the base protocol.  You unplug devices by writing a USHORT
      bitmask to 0x10 (0x01 -> IDE disks, 0x02 -> rtl8139 NICs, all
      other bits -> reserved).  Logging is done by writing bytes to
      0x12.

   -- 1, which is like 0 but adds a mechanism for telling qemu what
      version of the drivers we are, and for qemu to block versions
      which are known to be bad.  The drivers are expected to write a
      product id to port 0x12 as a short and their build number to
      0x10 as a long, and then check the magic on port 0x10 again.  If
      the drivers are blacklisted, it will have changed to something
      other than the magic.  The only defined product ID is 1, which
      is the Citrix Windows PV drivers.

   The old protocol still works on new toolstacks, but the new one is
   better because it means you can unplug the PCI devices before the
   PCI driver comes up.
*/

static USHORT unplug_protocol; /* 0 -> old, 1 -> new */

/* Old protocol */
static PVOID device_unplug_port_old; /* NULL -> unknown or new
                                      * protocol */

/* New protocol */
#define NEW_UNPLUG_PORT ((PVOID)(ULONG_PTR)0x10)
#define NEW_DOM0LOG_PORT ((PVOID)(ULONG_PTR)0x12)
#define UNPLUG_VERSION_PORT ((PVOID)(ULONG_PTR)0x12)
#define UNPLUG_DRIVER_VERSION_PORT ((PVOID)(ULONG_PTR)0x10)
#define UNPLUG_DRIVER_PRODUCT_PORT ((PVOID)(ULONG_PTR)0x12)
#define DEVICE_UNPLUG_PROTO_MAGIC 0x49d2
#define UNPLUG_DRIVER_PRODUCT_NUMBER 1

#define UNPLUG_ALL_IDE 1
#define UNPLUG_ALL_NICS 2
#define UNPLUG_AUX_IDE 4

/* Shared */
PVOID dom0_debug_port;

/* Decide which protocol we're using.  This also sets up the port
   numbers for the new protocol.  The old protocol can't do that until
   the PCI resources are available. */
void
InitUnplug(void)
{
    USHORT magic;
    UCHAR version;

    magic = READ_PORT_USHORT(NEW_UNPLUG_PORT);
    if (magic == DEVICE_UNPLUG_PROTO_MAGIC) {
        unplug_protocol = 1;
        version = READ_PORT_UCHAR(UNPLUG_VERSION_PORT);
        if (version >= 1) {
            WRITE_PORT_USHORT(UNPLUG_DRIVER_PRODUCT_PORT,
                              UNPLUG_DRIVER_PRODUCT_NUMBER);
            WRITE_PORT_ULONG(UNPLUG_DRIVER_VERSION_PORT,
                             VER_BUILD_NR);
            magic = READ_PORT_USHORT(NEW_UNPLUG_PORT);
            if (magic != DEVICE_UNPLUG_PROTO_MAGIC) {
                /* Okay, qemu doesn't like this version of the drivers
                   for some reason.  Turn ourselves off. */
                _g_PVFeatureFlags = DEBUG_NO_PARAVIRT;
                return;
            }
        }
        dom0_debug_port = NEW_DOM0LOG_PORT;
    } else {
        unplug_protocol = 0;
    }
}

void
UnplugIoemu(void)
{
    /* If PV mode is disabled then unplugging the emulated devices is
       a really bad idea. */
    XM_ASSERT(XenPVEnabled());

    if (unplug_protocol == 1) {
        USHORT flags;

        flags = UNPLUG_ALL_NICS | UNPLUG_ALL_IDE;

        if (XenPVFeatureEnabled(DEBUG_BOOT_EMULATED)) {
            flags &= ~UNPLUG_ALL_IDE;
            flags |= UNPLUG_AUX_IDE;
        }

        if (XenPVFeatureEnabled(DEBUG_NIC_EMULATED))
            flags &= ~UNPLUG_ALL_NICS;

        TraceVerbose(("%s: unplug flags = %04x\n", __FUNCTION__, flags));
        WRITE_PORT_USHORT(NEW_UNPLUG_PORT, flags);
        done_unplug = TRUE;
    } else if (unplug_protocol == 0 && device_unplug_port_old) {
        WRITE_PORT_ULONG(device_unplug_port_old, 0);
        done_unplug = TRUE;
    } else if (XenPVFeatureEnabled(DEBUG_FORCE_EARLY_UNPLUG)) {
        /* Icky hack so that you can use scsifilt on Rio, because
           there's some bad interaction between atapi.sys, scsifilt,
           and late unplugging. */
        WRITE_PORT_ULONG((PVOID)0xc104, 0);
        done_unplug = TRUE;
    }
}

void
InitOldUnplugProtocol(PHYSICAL_ADDRESS ioportbase, ULONG nports)
{
    if (unplug_protocol == 0 && nports >= 12) {
        device_unplug_port_old = (PVOID)(ULONG_PTR)(ioportbase.LowPart + 4);
        dom0_debug_port = (PVOID)(ULONG_PTR)(ioportbase.LowPart + 8);
        TraceNotice(("Using old device unplugging protocol.\n"));
    }
}

static VOID
ParseRegistryPath(
    IN  PUNICODE_STRING Path
    )
{
    PWSTR Name;

    // Assume 'Path' is NUL terminated
    Name = wcsrchr(Path->Buffer, L'\\');
    Name++;

    if (wcscmp(Name, L"dump_XENUTIL") == 0) {
        TraceNotice(("Loading PV drivers in DUMP mode.\n"));
        SetOperatingMode(DUMP_MODE);
    } else if (wcscmp(Name, L"hiber_XENUTIL") == 0) {
        TraceNotice(("Loading PV drivers in HIBER mode.\n"));
        SetOperatingMode(HIBER_MODE);
    } else {
        TraceNotice(("Loading PV drivers in NORMAL mode.\n"));
        SetOperatingMode(NORMAL_MODE);
    }
}

typedef NTSTATUS (*PDBG_SET_DEBUG_FILTER_STATE)(
    IN ULONG,
    IN ULONG,
    IN BOOLEAN
    );

static PDBG_SET_DEBUG_FILTER_STATE __XenDbgSetDebugFilterState;

//
// XC-4394
//
// The following static and function are only used by xenvbd
// when entering hibernate (and probably crash dump file generation).
// We must detect Win7 SP1 so we can avoid a problem in SCSIPORT
// that was introduced with SP1.
//
static RTL_OSVERSIONINFOEXW Info;

VOID XenutilGetOsVersionDuringAustere(PXEN_WINDOWS_VERSION WinVer)
{
	WinVer->dwMajorVersion = Info.dwMajorVersion;
	WinVer->dwMinorVersion = Info.dwMinorVersion;
	WinVer->dwBuildNumber = Info.dwBuildNumber;
	WinVer->dwPlatformId = Info.dwPlatformId;
	WinVer->wServicePackMajor = Info.wServicePackMajor;
	WinVer->wServicePackMinor = Info.wServicePackMinor;
}

NTSTATUS
DllInitialize(PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING fn;
    NTSTATUS ntStatus;

    TraceInfo(("%s\n", __FUNCTION__));

    ParseRegistryPath(RegistryPath);

    if (!AustereMode)
        XenWorkItemInit();

	if (AustereMode)
		XenutilGetVersionInfo(&Info);

    ntStatus = AuxKlibInitialize();
    if (!NT_SUCCESS(ntStatus)) {
        TraceError(("Cannot initialize auxiliary library: %x\n",
                    ntStatus));
        return ntStatus;
    }

    /*
     * Attempt to replace the default DbgPrint call with a
     * call to DbgPrintEx, to allow better debug filtering
     */
    RtlInitUnicodeString(&fn, L"vDbgPrintEx");
    __XenvDbgPrintEx = (VDBG_PRINT_EX)(ULONG_PTR)MmGetSystemRoutineAddress(&fn);

    if (__XenvDbgPrintEx != NULL) {
        XenDbgPrint = __XenDbgPrint;

#if DBG
        /*
         * Attempt to enable the appropriate debug filter to avoid having to set it
         * in the registry.
         */
        RtlInitUnicodeString(&fn, L"DbgSetDebugFilterState");
        __XenDbgSetDebugFilterState = (PDBG_SET_DEBUG_FILTER_STATE)(ULONG_PTR)MmGetSystemRoutineAddress(&fn);

        if (__XenDbgSetDebugFilterState != NULL)
            __XenDbgSetDebugFilterState(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, TRUE);
#endif  //DBG
    }

    XenParseBootParams();

    if (XenPVFeatureEnabled(DEBUG_MTC_PROTECTED_VM))
        XenTraceSetMtcLevels();

    if (XenPVFeatureEnabled(DEBUG_NO_PARAVIRT))
        return STATUS_SUCCESS;

    if (XenPVFeatureEnabled(DEBUG_VERY_LOUD))
    {
        int dispositions[XenTraceLevels] = {-1,-1,-1,-1,-1,-1,-1};
        XenTraceSetLevels(dispositions);
    }

    if (XenPVFeatureEnabled(DEBUG_VERY_QUIET))
    {
        int dispositions[XenTraceLevels] = {0};
        TraceNotice(("Disable all logging...\n"));
        XenTraceSetLevels(dispositions);
    }

    InitUnplug();

    if (XenPVFeatureEnabled(DEBUG_HA_SAFEMODE))
        return STATUS_SUCCESS;

    UnplugIoemu();

    return STATUS_SUCCESS;
}

static BOOLEAN
isInS3;
static SUSPEND_TOKEN
s3SuspendToken;

void
XmRecoverFromS3(void)
{
    if (!isInS3)
        return;
    isInS3 = FALSE;
    HvmResume(NULL, s3SuspendToken);
    ConnectDebugVirq();
    xenbus_recover_from_s3();
    EvtchnReleaseSuspendToken(s3SuspendToken);
}

void
XmPrepForS3(void)
{
    if (isInS3)
        return;
    isInS3 = TRUE;
    s3SuspendToken = EvtchnAllocateSuspendToken("S3");
    DisconnectDebugVirq();
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT dev, PUNICODE_STRING reg_path)
{
    UNREFERENCED_PARAMETER(dev);
    UNREFERENCED_PARAMETER(reg_path);

    TraceInfo(("%s: IRQL = %d\n", __FUNCTION__, KeGetCurrentIrql()));

    return STATUS_SUCCESS;
}
