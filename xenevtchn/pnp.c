//
// pnp.c - Handler functions for various Windows Plug and
//         Play functions.
//
// Copyright (c) 2006 XenSource, Inc. - All rights reserved.
//

/*
 * Copyright (c) 2014 Citrix Systems, Inc.
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


#define INITGUID 1
#include "xenevtchn.h"
#include "pnp.h"
#include "scsiboot.h"
#include "wdmguid.h"
#include "xsapi.h"
#include "xevtchn_msgs.h"

#include "ntstrsafe.h"

// These should not be here. Code requiring them will eventually
// move into xenutil
#include "../xenutil/hvm.h"
#include "../xenutil/hypercall.h"
#include "../xenutil/xenbus.h"
#include "../xenutil/evtchn.h"
#include "../xenutil/debug.h"
#include "../xenutil/gnttab.h"
#include "../xenutil/balloon.h"
#include "../xenutil/iohole.h"
#include "../xenutil/xenutl.h"

//
// Dont care about unreferenced formal parameters here
//
#pragma warning( disable : 4100 )

#define XPNP_TAG 'PNPX'

static NTSTATUS PdoHandleQueryCapabilities(PDEVICE_OBJECT DeviceObject,
                                           PIRP Irp);
static NTSTATUS FailRequestNotSupported(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS PdoQueryBusInformation(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS FdoQueryDeviceRelations(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS PdoQueryDeviceRelations(PDEVICE_OBJECT DeviceObject, PIRP Irp);

static NTSTATUS
TrivialIrpHandler(PIRP Irp, NTSTATUS status)
{
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS
FailRequestNotSupported(PDEVICE_OBJECT DeviceObject,
                        PIRP Irp)
{
    return TrivialIrpHandler(Irp, STATUS_NOT_SUPPORTED);
}

static NTSTATUS
FdoQueryDeviceState(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx = 
        (PXENEVTCHN_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    TraceDebug(("Querying device state.\n"));
    XM_ASSERT(pXevtdx->Header.Signature == XENEVTCHN_FDO_SIGNATURE);
    if (Irp->IoStatus.Status != STATUS_SUCCESS)
        Irp->IoStatus.Information = 0;
    if (!pXevtdx->UninstEnabled)
        Irp->IoStatus.Information |= PNP_DEVICE_NOT_DISABLEABLE;
    if (!CheckXenHypervisor()) {
        Irp->IoStatus.Information |= PNP_DEVICE_DONT_DISPLAY_IN_UI;
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    return DefaultPnpHandler(DeviceObject, Irp);
}

static NTSTATUS
PdoQueryDeviceState(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    struct xenbus_device *xd = GetXenbusDeviceForPdo(DeviceObject);

    ExAcquireFastMutex(&xd->devExt->xenbus_lock);

    TraceDebug(("Querying device state (%s).\n", xd->class->class));

    if (Irp->IoStatus.Status != STATUS_SUCCESS)
        Irp->IoStatus.Information = 0;
    if (((xd->enumerate == 0) && (xd->was_connected == 1)))
    {
        TraceNotice(("** Setting PNP_DEVICE_REMOVED **\n"));
        Irp->IoStatus.Information |= PNP_DEVICE_REMOVED;
    }

    ExReleaseFastMutex(&xd->devExt->xenbus_lock);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (!xd->devExt->UninstEnabled)
    {
        IoInvalidateDeviceRelations (xd->devExt->PhysicalDeviceObject, BusRelations);
    }
    else
    {
        TraceNotice(("Querying device state; No rescan, uninstall in progress \n"));
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoQueryBusInformation(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PPNP_BUS_INFORMATION busInfo;
    NTSTATUS status;

    busInfo = ExAllocatePoolWithTag(PagedPool, sizeof(*busInfo), XPNP_TAG);
    if (busInfo) {
        if (XenPVFeatureEnabled(DEBUG_INTERNAL_XENNET)) {
            busInfo->BusTypeGuid = GUID_BUS_TYPE_INTERNAL;

        } else {
            busInfo->BusTypeGuid = GUID_XENBUS_BUS_TYPE;
        }

        busInfo->LegacyBusType = PCIBus;
        busInfo->BusNumber = 0;
        status = STATUS_SUCCESS;
    } else {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    Irp->IoStatus.Information = (ULONG_PTR)busInfo;
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS
PdoHandleQueryCapabilities(PDEVICE_OBJECT DeviceObject,
                           PIRP Irp)
{
    PIO_STACK_LOCATION pios =
        IoGetCurrentIrpStackLocation(Irp);
    PDEVICE_CAPABILITIES pdc =
        pios->Parameters.DeviceCapabilities.Capabilities;
    int i;
    NTSTATUS res;

    if (pdc->Version != 1) {
        res = STATUS_INVALID_PARAMETER;
    } else {
        res = STATUS_SUCCESS;
        pdc->DeviceD1 = 0;
        pdc->DeviceD2 = 0;
        pdc->LockSupported = 0;
        pdc->EjectSupported = 0;
        pdc->Removable = 1;
        pdc->DockDevice = 0;
        pdc->UniqueID = 1;
        pdc->SilentInstall = 0;
        pdc->RawDeviceOK = 0;
        pdc->SurpriseRemovalOK = 1;
        pdc->HardwareDisabled = 0;
        pdc->NoDisplayInUI = 0;

        pdc->Address = 0xffffffff;
        pdc->UINumber = 0xffffffff;
        for (i = 0; i < PowerSystemMaximum; i++) {
            switch (i) {
            case PowerSystemUnspecified:
                break;
            case PowerSystemWorking:
                pdc->DeviceState[i] = PowerDeviceD0;
                break;
            default:
                pdc->DeviceState[i] = PowerDeviceD3;
                break;
            }
        }
        pdc->SystemWake = PowerSystemUnspecified;
        pdc->DeviceWake = PowerDeviceUnspecified;
        pdc->D1Latency = 0;
        pdc->D2Latency = 0;
        pdc->D3Latency = 0;
        if (XenPVFeatureEnabled(DEBUG_FAKE_NETIF)) {
            pdc->NoDisplayInUI = 1;
            pdc->SilentInstall = 1;
        }
    }

    Irp->IoStatus.Status = res;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return res;
}

//
// Default handler function for plug and play operations
// not handled by this driver.
//
NTSTATUS
DefaultPnpHandler(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )
{
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx =
        (PXENEVTCHN_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    if (stack->MinorFunction <= IRP_MN_QUERY_LEGACY_BUS_INFORMATION) {
        TraceDebug (("DefaultPnpHandler: passing on %s\n", 
                    pnpInfo[stack->MinorFunction].name));
    } else {
        TraceVerbose (("DefaultPnpHandler: passing on unknown minor %d\n", 
                       stack->MinorFunction));
    }

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(pXevtdx->LowerDeviceObject, Irp);
}

static IO_COMPLETION_ROUTINE _SynchronousIrpCompletion;

static NTSTATUS
_SynchronousIrpCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context)
{
    PKEVENT             Event = Context;

    TraceInfo(("%s: (%08x)\n", __FUNCTION__, Irp->IoStatus.Status));
    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
ForwardIrpSynchronously(
    IN  PDEVICE_OBJECT          DeviceObject,
    IN  PIRP                    Irp
    )
{
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx;
    KEVENT                      Event;
    NTSTATUS                    status;

    TraceInfo(("%s: ====>\n", __FUNCTION__));

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    /* Send the IRP down */
    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp,
                           _SynchronousIrpCompletion,
                           &Event,
                           TRUE,
                           TRUE,
                           TRUE);

    pXevtdx = (PXENEVTCHN_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    status = IoCallDriver(pXevtdx->LowerDeviceObject, Irp);
    if (status == STATUS_PENDING) {
        TraceInfo(("%s: <==== (PENDING)\n", __FUNCTION__));
        KeWaitForSingleObject(&Event,
                              Executive,
                              KernelMode,
                              FALSE,
                              NULL);
        status = Irp->IoStatus.Status;
    } else {
        XM_ASSERT3U(status, ==, Irp->IoStatus.Status);
        TraceInfo(("%s: <==== (%08x)\n", __FUNCTION__, status));
    }

    return status;
}

static PWCHAR
AnsiToWchar(PCHAR src)
{
    size_t l;
    PWCHAR res;
    size_t x;

    l = strlen(src) + 1;
    res = XmAllocateMemory(l * sizeof(WCHAR));
    if (!res)
        return NULL;
    for (x = 0; x < l; x++)
        res[x] = src[x];
    return res;
}

/* x -> XEN\\x.  Used to construct both device and hardware ID
   strings */
static PWCHAR
MakeDeviceHwId(PCHAR class)
{
    size_t l;
    PWCHAR res;
    int x;

    l = strlen(class) + 6; /* I really do mean 6 here: XEN\\ -> 4,
                              nul terminator -> 5, second
                              terminator -> 6, so that device id
                              and hardware id are the same*/
    res = XmAllocateMemory(l * sizeof(WCHAR));
    if (!res)
        return NULL;
    memcpy(res, L"XEN\\", 8);
    for (x = 0; class[x]; x++)
        res[x + 4] = class[x];
    res[x+4] = 0;
    res[x+5] = 0;
    return res;
}

static char *
xsstrdup(const char *s)
{
    size_t l = strlen(s);
    char *res;
    res = XmAllocateMemory(l + 1);
    if (!res) return res;
    memcpy(res, s, l + 1);
    return res;
}

static struct xenbus_device *
FindDevice(struct xenbus_device_class *class, const char *instance)
{
    LIST_ENTRY *ple;
    struct xenbus_device *xd;

    ple = class->devices.Flink;
    while (ple != &class->devices) {
        xd = CONTAINING_RECORD(ple, struct xenbus_device,
                               devices_this_class);
        if (!strcmp(xd->name, instance)) {
            InterlockedIncrement(&xd->refcount);
            return xd;
        }
        ple = ple->Flink;
    }
    return NULL;
}

static void
xenbus_device_deref(struct xenbus_device *xd)
{
    SUSPEND_TOKEN token;

    XM_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
    if (!InterlockedDecrement(&xd->refcount)) {
        XM_ASSERT(!xd->present_in_xenbus);
        XM_ASSERT(!xd->reported_to_pnpmgr);
        XM_ASSERT(!xd->pdo);
        TraceInfo(("Releasing device %s::%s.\n", xd->class->class,
                   xd->name));
        token = EvtchnAllocateSuspendToken("xenbus pnp deref");
        if (xd->bstate_watch)
            xenbus_unregister_watch(xd->bstate_watch);
        EvtchnReleaseSuspendToken(token);
        XmFreeMemory(xd->frontend_path);
        XmFreeMemory(xd->name);
        XmFreeMemory(xd->InstanceId);
        XmFreeMemory(xd->DeviceId);
        XmFreeMemory(xd->HardwareId);
        XmFreeMemory(xd);
    }
}

static XENBUS_STATE
read_backend_state(struct xenbus_device *xd)
{
    char *state_str;
    size_t state_str_len;
    ULONG64 state;
    NTSTATUS status;
    int err;

    status = xenbus_read_backend_bin(XBT_NIL, xd->pdo, "state",
                                     &state_str, &state_str_len);
    if (!NT_SUCCESS(status))
        return null_XENBUS_STATE();
    state = xm_strtoll(state_str, state_str_len, 10, &err);
    XmFreeMemory(state_str);
    if (err || state > _XENBUS_STATE_CLOSED)
        return null_XENBUS_STATE();
    else
        return wrap_XENBUS_STATE((int)state);
}

NTSTATUS
xenbus_write_state(xenbus_transaction_t xbt, PCSTR prefix,
                   PCSTR node, XENBUS_STATE state);

static void
xenbus_set_surprise_removal(struct xenbus_device *xd)
{
    NTSTATUS status;
    char *path;

    path = Xmasprintf("%s/surprise-removal", xd->frontend_path);
    if (!path)
    {
        TraceError(("%s Failed to allocate path for setting surprise-removal for %s/%s\n",
                   __FUNCTION__, xd->class->class, xd->name));
        return;
    }

    status = xenbus_write(XBT_NIL, path, "gone");
    XmFreeMemory(path);
    if (!NT_SUCCESS(status))
    {
        TraceError(("%s Failed to write surprise-removal for %s/%s - status: 0x%x\n",
                   __FUNCTION__, xd->class->class, xd->name, status));
    }
}

static BOOLEAN
xenbus_check_surprise_removal(struct xenbus_device *xd)
{
    NTSTATUS status;
    BOOLEAN ret = FALSE;
    char *path;
    char *value;

    path = Xmasprintf("%s/surprise-removal", xd->frontend_path);
    if (!path)
    {
        TraceError(("%s Failed to allocate path for checking surprise-removal for %s/%s\n",
                   __FUNCTION__, xd->class->class, xd->name));
        return FALSE;
    }

    status = xenbus_read(XBT_NIL, path, &value);
    XmFreeMemory(path);

    /* OK, the node does not exist so it is not a surprise removed device */
    if (status == STATUS_OBJECT_NAME_NOT_FOUND)
        return FALSE;

    if (!NT_SUCCESS(status))
    {
        TraceError(("%s Failed to read surprise-removal for %s/%s - status: 0x%x\n",
                   __FUNCTION__, xd->class->class, xd->name, status));
        /* Don't know what happened so default to not surprise removed */
        return FALSE;
    }

    if (strcmp(value, "gone") == 0)
    {
        TraceNotice(("%s Device in surprise-removal state for %s/%s\n",
                   __FUNCTION__, xd->class->class, xd->name));
        ret = TRUE;
    }

    /* There is no documentation but in all other places the out value is
     * only freed on the status success path.
     */
    XmFreeMemory(value);
    return ret;
}

static void
xenbus_remove_frontend_node (struct xenbus_device *xd, char *node)
{
    char *path;

    if (xd)
    {
        char *curr_data, *new_data;
        int pass;
        NTSTATUS status;

        path = Xmasprintf("%s/%s", xd->frontend_path, node);
        if (!path)
        {
            TraceError (("Failed to allocate storage for path to remove backend node '%s'\n", node));
            return;
        }

        xenbus_read(XBT_NIL, path, &curr_data);
        pass = 0;

        do {
            xenbus_remove (XBT_NIL, path);
            TraceNotice (("Removed backend path node %s\n", path));
            XmFreeMemory(path);

            //
            // Now try to read it back
            //
            status = xenbus_read(XBT_NIL, path, &new_data);
            TraceNotice (("Read Backend path: %x\n", status));
            TraceNotice (("Backend path old: %s\n", curr_data));
            TraceNotice (("Backend path new: %s\n", new_data));
            if (NT_SUCCESS(status) && strcmp(curr_data, new_data) != 0)
            {
                LARGE_INTEGER i;
                TraceError (("Failed to remove backend node '%s'...retrying\n", node));
                i.QuadPart = -10000000;
                KeDelayExecutionThread(KernelMode, FALSE, &i);
                pass++;
            }
            XmFreeMemory(new_data);

        } while ((NT_SUCCESS(status)) && pass < 10);

        XmFreeMemory(curr_data);
    }
}

static BOOLEAN
xenbus_frontend_node_changed (struct xenbus_device *xd, char *node, char *old_data)
{
    char *path;
    NTSTATUS status;
    char *curr_data;
    BOOLEAN ret;

    //
    // Default to TRUE since if someone is asking if a node contents have
    // changed, the caller most likely thinks the node exists. So if the
    // node is not found, return true.
    //
    ret = TRUE;

    if (xd)
    {
        path = Xmasprintf("%s/%s", xd->frontend_path, node);
        if (!path)
        {
            TraceError (("Failed to allocate storage for path to compare node '%s'\n", node));
            ret = FALSE;  //since this is internal failure...nothing to do with the node
        }
        else
        {
            TraceNotice (("Comparing %s against xenstore\n", path));
            status = xenbus_read(XBT_NIL, path, &curr_data);
            if (strcmp(old_data, curr_data) || (!NT_SUCCESS(status)))
            {
                TraceInfo (("Node %s has changed%s: Old: %s, New: %s\n",
                    node, NT_SUCCESS(status)?"":" (Read Failed)", old_data, curr_data));
                ret = TRUE;
            }
            else
            {
                ret = FALSE;
            }
            XmFreeMemory(curr_data);
            XmFreeMemory(path);
        }
    }
    return ret;
}

static void
xenbus_device_backend_state_changed(void *ctxt)
{
    struct xenbus_device *xd = ctxt;
    SUSPEND_TOKEN Token;
    XENBUS_STATE state;
    BOOLEAN online;
    NTSTATUS status;
    BOOLEAN backend_gone = FALSE;

    ExAcquireFastMutex(&xd->devExt->xenbus_lock);
    ExAcquireFastMutex(&xd->pdo_lock);

    if (xd->pdo == NULL || !xd->pdo_ready) {
        xd->lost_watch_event = 1;
        ExReleaseFastMutex(&xd->pdo_lock);
        ExReleaseFastMutex(&xd->devExt->xenbus_lock);
        return;
    }

    Token = EvtchnAllocateSuspendToken(__FUNCTION__);

    state = null_XENBUS_STATE();
    online = FALSE;

    do {
        xenbus_transaction_t    xbt;
        char                    *backend_path;

        xenbus_transaction_start(&xbt);

        backend_path = FindBackendPath(xbt, xd);

        status = STATUS_INSUFFICIENT_RESOURCES;
        if (backend_path == NULL) {
            backend_gone = TRUE;
            (VOID) xenbus_transaction_end(xbt, 1);
            break;
        }

        status = xenbus_read_state(xbt, backend_path, "state", &state);
        if (!NT_SUCCESS(status)) {
            backend_gone = TRUE;
            XmFreeMemory(backend_path);
            (VOID) xenbus_transaction_end(xbt, 1);
            break;
        }

        xenbus_read_feature_flag(xbt, backend_path, "online", &online);

        XmFreeMemory(backend_path);
        status = xenbus_transaction_end(xbt, 0);
    } while (status == STATUS_RETRY);

    TraceVerbose(("%s/%s: state = %s, online = %d\n",
                xd->class->class, xd->name,
                XenbusStateName(state), online));


    if ((strcmp(xd->class->class, "vif") == 0) || (strcmp(xd->class->class, "vwif") == 0))
    {
        if (backend_gone)
        {
            if (xd->was_connected)
            {
                if (!xd->devExt->UninstEnabled)
                {
                    TraceNotice (("State indication failed; Requesting bus rescan (%s)\n", xd->class->class));
                    // Ask pnp to call us back to rescan the bus unless an uninstall is in progress
                    IoInvalidateDeviceRelations (xd->devExt->PhysicalDeviceObject, BusRelations);
                }
                else
                {
                    TraceNotice (("State indication failed; No rescan, uninstall in progress (%s)\n", xd->class->class));
                }
            }
        }
        else
        {
            TraceVerbose(("Writing shadow copy of backend state %d to %s/backend-state\n", 
                state, xd->frontend_path));
            xenbus_write_state (XBT_NIL, xd->frontend_path, "backend-state", state);

            if ((same_XENBUS_STATE(state, XENBUS_STATE_CLOSED)) && (xd->was_connected == TRUE))
            {
                if (!xd->devExt->UninstEnabled)
                {
                    TraceNotice (("Backend closed device: Requesting bus rescan (%s)\n", xd->class->class));
                    // Ask pnp to call us back to rescan the bus unless an uninstall is in progress
                    IoInvalidateDeviceRelations (xd->devExt->PhysicalDeviceObject, BusRelations);
                }
                else
                {
                    TraceNotice (("Backend closed device: No rescan, uninstall in progress (%s)\n", xd->class->class));
                }
            }
            else if (same_XENBUS_STATE(state, XENBUS_STATE_CONNECTED))
            {
                xd->was_connected = TRUE;
            }
            else if ((same_XENBUS_STATE(state, XENBUS_STATE_INITIALISING)) && (xd->was_connected == TRUE))
            {
                TraceNotice (("Backend re-enabled vif device...Rescanning xenbus\n"));
                xd->was_connected = FALSE;
                KeSetEvent(&xd->devExt->reprobe_xenbus_thread->event, IO_NO_INCREMENT, 0);
            }
        }
    }
    else if (strcmp(xd->class->class, "vusb") == 0)
    {
        if (!online &&
            (same_XENBUS_STATE(state, XENBUS_STATE_CLOSING) ||
             same_XENBUS_STATE(state, XENBUS_STATE_CLOSED))) {
            TraceNotice(("%s/%s: issuing an Invalidate on VUSB request\n", xd->class->class,
                         xd->name));
            if (!xd->devExt->UninstEnabled)
            {
                TraceNotice (("Backend closed device: Requesting bus rescan (%s) and surprise removal\n", xd->class->class));
                // Flag this device struct and in xenstore frontend path as surprise removed.
                xd->surprise_remove = 1;
                xenbus_set_surprise_removal(xd);
                // Ask pnp to call us back to rescan the bus unless an uninstall is in progress
                IoInvalidateDeviceRelations (xd->devExt->PhysicalDeviceObject, BusRelations);
            }
            else
            {
                TraceNotice (("Backend closed device: No rescan, uninstall in progress (%s)\n", xd->class->class));
            }
        }
    }
    else
    {
        if (!online &&
            (same_XENBUS_STATE(state, XENBUS_STATE_CLOSING) ||
             same_XENBUS_STATE(state, XENBUS_STATE_CLOSED))) {
            TraceNotice(("%s/%s: issuing eject request\n", xd->class->class,
                         xd->name));
            IoRequestDeviceEject(xd->pdo);
        }
    }

    EvtchnReleaseSuspendToken(Token);

    ExReleaseFastMutex(&xd->pdo_lock);
    ExReleaseFastMutex(&xd->devExt->xenbus_lock);
}

char *
FindBackendPath(xenbus_transaction_t xbt, struct xenbus_device *xd)
{
    char *path;
    char *backend;
    NTSTATUS stat;

    path = Xmasprintf("%s/backend", xd->frontend_path);
    if (!path) {
        return NULL;
    }
    stat = xenbus_read(xbt, path, &backend);
    if (!NT_SUCCESS(stat)) {
        TraceInfo(("Failed to read backend for %s/%s from %s.\n",
                   xd->class->class, xd->name, path));
        XmFreeMemory(backend);
        XmFreeMemory(path);
        return NULL;
    }
    XmFreeMemory(path);

    return backend;
}

static char *
FindFrontendPath(struct xenbus_device *xd)
{
    return Xmasprintf("device/%s/%s", xd->class->class, xd->name);
}

BOOLEAN
should_be_enumerated(struct xenbus_device *xd)
{
    XENBUS_STATE state;

    if ((xd) &&
        ((strcmp(xd->class->class, "vif") == 0) || (strcmp(xd->class->class, "vwif") == 0)) &&
        (xd->was_connected))  // If this is 0, it means we have never connected to it before...enumerate it!
    {
        state = read_backend_state(xd);
        //
        // This is where xd->was_connected is important. When devices first show up,
        // they appear as state closed. But this is only on the first enumeration. After
        // that, if the state is closed, then they shouldn't be enumerated.
        //
        if (same_XENBUS_STATE(state, XENBUS_STATE_CLOSED))
        {
            TraceInfo(("device/%s/%s closed\n", xd->class->class, xd->name));
            xd->enumerate = 0;
            xd->bus_rescan_needed = 1;
            xd->was_connected = FALSE;
            return FALSE;
        }
        if (is_null_XENBUS_STATE(state))
        {
            TraceInfo(("device/%s/%s backend or state node gone\n", xd->class->class, xd->name));
            if (xd->was_connected)
                xenbus_remove_frontend_node(xd, "backend");
            xd->enumerate = 0;
            xd->bus_rescan_needed = 1;
            xd->was_connected = FALSE;
            return FALSE;
        }
    }
    if (xd)
        xd->enumerate = 1;
    return TRUE;
}


/* Construct a xenbus_device structure.  Does not create the PDO or
   the xenbus watch. */
static struct xenbus_device *
ConstructDevice(PXENEVTCHN_DEVICE_EXTENSION pXevtdx,
                struct xenbus_device_class *class,
                char *instance)
{
    struct xenbus_device *xd;

    xd = XmAllocateZeroedMemory(sizeof(*xd));
    if (!xd)
        return NULL;
    xd->class = class;
    xd->name = xsstrdup(instance);
    xd->refcount = 1;
    xd->devExt = pXevtdx;
    xd->InstanceId = AnsiToWchar(instance);
    xd->HardwareId = MakeDeviceHwId(class->class);
    xd->DeviceId = MakeDeviceHwId(class->class);
    xd->present_in_xenbus = 1;
    xd->enumerate = 1;
    xd->was_connected = 0;
    xd->surprise_remove = 0;
    ExInitializeFastMutex(&xd->pdo_lock);

    if (xd->name)
        xd->frontend_path = FindFrontendPath(xd);

    if (!xd->name || !xd->InstanceId || !xd->HardwareId || !xd->DeviceId ||
        !xd->frontend_path) {
        XmFreeMemory(xd->frontend_path);
        XmFreeMemory(xd->name);
        XmFreeMemory(xd->InstanceId);
        XmFreeMemory(xd->HardwareId);
        XmFreeMemory(xd->DeviceId);
        XmFreeMemory(xd);
        return NULL;
    } else {
        return xd;
    }
}

static NTSTATUS
XenbusDeviceCreatePdo(struct xenbus_device *xd,
                      PXENEVTCHN_DEVICE_EXTENSION pXevtdx,
                      PDEVICE_OBJECT *pnewdev)
{
    PDEVICE_OBJECT newdev;
    struct PDO_DEVICE_EXTENSION *newDevExt;
    NTSTATUS status;

    TraceVerbose (("Creating new %s PDO\n", xd->class->class));

    InterlockedIncrement(&xd->refcount); /* PDO holds a reference. */

    status = IoCreateDevice(pXevtdx->DriverObject,
                            sizeof(*newDevExt),
                            NULL,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN|FILE_AUTOGENERATED_DEVICE_NAME,
                            FALSE,
                            &newdev);
    if (!NT_SUCCESS(status)) {
        TraceError (("IoCreateDevice() failed\n"));
        xenbus_device_deref(xd);
        return status;
    }

    newDevExt = newdev->DeviceExtension;
    memset(newDevExt, 0, sizeof(*newDevExt));
    newDevExt->Header.Signature = XENEVTCHN_PDO_SIGNATURE;
    newDevExt->dev = xd;
    newDevExt->fdo = pXevtdx;

    *pnewdev = newdev;

    ExAcquireFastMutex(&xd->pdo_lock);
    xd->pdo = newdev;
    ExReleaseFastMutex(&xd->pdo_lock);

    return STATUS_SUCCESS;
}

struct xenbus_device *
GetXenbusDeviceForPdo(PDEVICE_OBJECT pdo)
{
    struct PDO_DEVICE_EXTENSION *devExt = pdo->DeviceExtension;
    XM_ASSERT(devExt->Header.Signature == XENEVTCHN_PDO_SIGNATURE);
    return devExt->dev;
}

VOID
CloseFrontend(struct xenbus_device *xd, char *backend_path, SUSPEND_TOKEN token)
{
    char *frontend_path = xd->frontend_path;
    XENBUS_STATE frontend_state;
    XENBUS_STATE backend_state;
    NTSTATUS status;

    TraceNotice(("closing %s...\n", frontend_path));

    xenbus_read_state(XBT_NIL, backend_path, "state", &backend_state);

    // Get initial frontend state
    status = xenbus_read_state(XBT_NIL, frontend_path, "state", &frontend_state);
    if (!NT_SUCCESS(status))
        frontend_state = null_XENBUS_STATE();

    if (!same_XENBUS_STATE(backend_state, XENBUS_STATE_INITIALISING))
    {
        // Wait for the backend to stabilise
        backend_state = null_XENBUS_STATE();
        do {
            backend_state = XenbusWaitForBackendStateChange(backend_path, backend_state,
                                                            NULL, token);
        } while (same_XENBUS_STATE(backend_state, XENBUS_STATE_INITIALISING));
    }

    TraceVerbose(("%s: %s: backend state = %s, frontend state = %s\n",
                  __FUNCTION__,
                  frontend_path,
                  XenbusStateName(backend_state),
                  XenbusStateName(frontend_state)));

    frontend_state = XENBUS_STATE_CLOSING;
    while (!same_XENBUS_STATE(backend_state, XENBUS_STATE_CLOSING) &&
           !same_XENBUS_STATE(backend_state, XENBUS_STATE_CLOSED) &&
           !is_null_XENBUS_STATE(backend_state)) {
        xenbus_change_state(XBT_NIL, frontend_path, "state", frontend_state);
        backend_state = XenbusWaitForBackendStateChange(backend_path, backend_state,
                                                        NULL, token);
    }

    TraceVerbose(("%s: %s: backend state = %s, frontend state = %s\n",
                  __FUNCTION__,
                  frontend_path,
                  XenbusStateName(backend_state),
                  XenbusStateName(frontend_state)));

    frontend_state = XENBUS_STATE_CLOSED;
    while (!same_XENBUS_STATE(backend_state, XENBUS_STATE_CLOSED) &&
           !is_null_XENBUS_STATE(backend_state)) {
        xenbus_change_state(XBT_NIL, frontend_path, "state", frontend_state);
        backend_state = XenbusWaitForBackendStateChange(backend_path, backend_state,
                                                        NULL, token);
    }

    TraceVerbose(("%s: %s: backend state = %s, frontend state = %s\n",
                  __FUNCTION__,
                  frontend_path,
                  XenbusStateName(backend_state),
                  XenbusStateName(frontend_state)));

    TraceNotice(("%s closed\n", frontend_path));
}

/* Probe a specific device on the xenbus. */
static int
ProbeThisDevice(PXENEVTCHN_DEVICE_EXTENSION pXevtdx,
                struct xenbus_device_class *class,
                char *instance)
{
    struct xenbus_device *xd, *xd2;
    PDEVICE_OBJECT newdev;
    NTSTATUS status;
    SUSPEND_TOKEN token;
    char *backend_path;

    TraceDebug(("Probing device/%s/%s.\n", class->class, instance));

    ExAcquireFastMutex(&pXevtdx->xenbus_lock);
    xd = FindDevice(class, instance);
    if (xd)
    {
        should_be_enumerated(xd);
        if (!xd->enumerate)
        {
            ExReleaseFastMutex(&pXevtdx->xenbus_lock);
            xenbus_device_deref(xd);
            return xd->bus_rescan_needed;
        }
    }
    if (xd && !xd->present_in_xenbus) {
        /* The device was removed from xenbus, so we started the
           removal timeout, but it came back on xenbus before we got
           around to actually telling Windows that it was gone.  We
           need to re-probe xenbus once it's finally gone. */
        TraceInfo(("device/%s/%s came back?\n", class->class, instance));
    }
    ExReleaseFastMutex(&pXevtdx->xenbus_lock);
    if (xd) {
        TraceDebug(("Already had a device instance for device/%s/%s.\n",
                   class->class, instance));
        xenbus_device_deref(xd);
        return 0;
    }

    xd = ConstructDevice(pXevtdx, class, instance);
    if (!xd) {
        TraceError(("Cannot allocate device structure for %s/%s.\n",
                    class->class, instance));
        return 0;
    }

    /* Check for devices that were surprise removed and cannot be reconnected after they
       transition to closed. */
    if (xenbus_check_surprise_removal(xd)) {
        TraceNotice(("Device was surprise removed and cannot reconnect after close - %s/%s.\n",
                     class->class, instance));
        xd->present_in_xenbus = 0;
        xenbus_device_deref(xd);
        return 0;
    }

    /* We have problems if we suspend in the interval between reading
       the backend path and adding the new device to the list. */
    token = EvtchnAllocateSuspendToken("xenbus probe");
    backend_path = FindBackendPath(XBT_NIL, xd);
    if (backend_path) {
        char *t;

        t = Xmasprintf("%s/state", backend_path);
        if (t) {
            if (xd->bstate_watch)
            {
                xenbus_unregister_watch (xd->bstate_watch);
                xd->bstate_watch = NULL;
            }
            xd->bstate_watch = xenbus_watch_path(t,
                                                 xenbus_device_backend_state_changed,
                                                 xd);
            XmFreeMemory(t);
        }
    }
    else
    {
        TraceInfo (("Device either in disconnected state or backend missing\n"));
        xd->enumerate = 0;
        xd->present_in_xenbus = 0;
        if (!xd->reported_to_pnpmgr && !xd->pdo && !xd->present_in_xenbus)
            xenbus_device_deref(xd);
        return xd->bus_rescan_needed;
    }
    if (!xd->bstate_watch) {
        TraceError (("Failed to set up device %s/%s.\n",
                     class->class, instance));
        xd->present_in_xenbus = 0;
        XmFreeMemory(backend_path);
        EvtchnReleaseSuspendToken(token);
        xenbus_device_deref(xd);
        return 0;
    }
    TraceVerbose (("Watchpoint set on %s/state\n", backend_path));

    status = XenbusDeviceCreatePdo(xd, pXevtdx, &newdev);
    if (!NT_SUCCESS(status)) {
        TraceError(("Failed to create device object for %s/%s.\n",
                    class->class, instance));
        xd->present_in_xenbus = 0;
        XmFreeMemory(backend_path);
        EvtchnReleaseSuspendToken(token);
        xenbus_device_deref(xd);
        return 0;
    }

    ExAcquireFastMutex(&pXevtdx->xenbus_lock);
    xd2 = FindDevice(class, instance);
    if (xd2) {
        TraceVerbose (("Lost race trying to add device %s/%s.\n",
                       class->class, instance));
        ExReleaseFastMutex(&pXevtdx->xenbus_lock);
        xd->present_in_xenbus = 0;
        XmFreeMemory(backend_path);
        EvtchnReleaseSuspendToken(token);
        xenbus_device_deref(xd);
        return 0;
    }
    InsertTailList(&pXevtdx->devices, &xd->all_devices);
    InsertTailList(&class->devices, &xd->devices_this_class);

    TraceNotice(("Detected new device %s/%s.\n", class->class, instance));

    /* The device starts off in state closed, so that dom0 is allowed
       to unplug it even when no driver is present. */
    if (xenbus_frontend_node_changed(xd, "backend", backend_path))
    {
        TraceError(("Backend variable inconsistent with xenstore\n"));
    }
    CloseFrontend(xd, backend_path, token);
    ExReleaseFastMutex(&pXevtdx->xenbus_lock);

    XmFreeMemory(backend_path);
    EvtchnReleaseSuspendToken(token);

    newdev->Flags &= ~DO_DEVICE_INITIALIZING;

    return 1;
}

void
XsRequestInvalidateBus(PKDPC dpc, PVOID arg1, PVOID arg2, PVOID arg3)
{
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx = arg1;

    UNREFERENCED_PARAMETER(arg2);
    UNREFERENCED_PARAMETER(arg3);

    if (!pXevtdx->UninstEnabled)
    {
        TraceVerbose (("Invalidating device relations.\n"));
        IoInvalidateDeviceRelations(pXevtdx->PhysicalDeviceObject,
                                    BusRelations);
    }
    else
    {
        TraceNotice(("Invalidate DPC; No rescan, uninstall in progress \n"));
    }
}

static VOID
xenbus_class_changed(struct xenbus_device_class *xdc)
{
    struct xenbus_device *xd;
    NTSTATUS stat;
    char *p;
    char **instances;
    int x;
    int need_invalidate = 0;
    LIST_ENTRY *ple;

    TraceDebug (("did device class %s do something?\n", xdc->class));
    p = Xmasprintf("device/%s", xdc->class);
    if (!p) {
        TraceError (("Out of memory probing device/%s.\n", xdc->class));
        return;
    }
    stat = xenbus_ls(XBT_NIL, p, &instances);
    if (!NT_SUCCESS(stat)) {
        TraceError (("Cannot list %s.\n", p));
        if (stat == STATUS_OBJECT_NAME_NOT_FOUND) {
            /* The class area has disappeared from the store.
               Conclude that all of the instances have been
               removed. */
            TraceDebug(("Removing all instances of %s.\n", xdc->class));
            instances = XmAllocateMemory(sizeof(instances[0]));
            instances[0] = NULL;
        } else {
            XmFreeMemory(p);
            return;
        }
    }
    XmFreeMemory(p);

    /* Are there any new devices? */
    for (x = 0; instances[x]; x++)
        need_invalidate += ProbeThisDevice(xdc->devExt, xdc,
                                           instances[x]);

    /* Have any devices disappeared? */
retry:
    ExAcquireFastMutex(&xdc->devExt->xenbus_lock);
    for (ple = xdc->devices.Flink; ple != &xdc->devices;
         ple = ple->Flink) {
        xd = CONTAINING_RECORD(ple, struct xenbus_device,
                               devices_this_class);
        if (!xd->present_in_xenbus)
            continue;
        for (x = 0; instances[x] && strcmp(instances[x], xd->name); x++)
            ;
        if (instances[x])
            continue;
        if (xd->enumerate)
            continue;
        TraceVerbose (("%s/%s removed from xenbus.\n",
                       xd->class->class, xd->name));
        xd->present_in_xenbus = 0;
        KeQuerySystemTime(&xd->removal_time);
        xd->removal_time.QuadPart += XS_DELAY_REMOVAL_US * 10;
        TraceDebug (("Will be removed at %I64d.\n",
                    xd->removal_time.QuadPart));

        /* Request an invalidate a bit later */
        KeSetTimer(&xdc->devExt->xenbus_timer,
                   xd->removal_time,
                   &xdc->devExt->xenbus_dpc);

        ExReleaseFastMutex(&xdc->devExt->xenbus_lock);
        /* It's no longer in the xenbus list, so drop a reference. */
        xenbus_device_deref(xd);
        goto retry; /* We released the lock, have to start scanning
                       from beginning of list. */
    }
    ExReleaseFastMutex(&xdc->devExt->xenbus_lock);

    for (x = 0; instances[x]; x++)
        XmFreeMemory(instances[x]);
    XmFreeMemory(instances);

    if (need_invalidate) {
        /* We only get here when adding devices, not when removing
           them.  Removal is handled on a delay from a DPC.  Redundant
           calls to InvalidateDeviceRelations are safe since we fix it
           up from DoFdoQueryDeviceRelations */
        if (!xdc->devExt->UninstEnabled)
        {
            IoInvalidateDeviceRelations(xdc->devExt->PhysicalDeviceObject,
                                       BusRelations);
        }
        else
        {
            TraceNotice(("Need invalidate; No rescan, uninstall in progress \n"));
        }
    }
}

static struct xenbus_device_class *
FindDeviceClass(PXENEVTCHN_DEVICE_EXTENSION pXevtdx, const char *name)
{
    LIST_ENTRY *ple;
    struct xenbus_device_class *xdc;

    ple = pXevtdx->xenbus_device_classes.Flink;
    while (ple != &pXevtdx->xenbus_device_classes) {
        xdc = CONTAINING_RECORD(ple, struct xenbus_device_class,
                                classes);
        if (!strcmp(xdc->class, name))
            return xdc;
        ple = ple->Flink;
    }
    return NULL;
}

/* Construct a xenbus_device_class structure.  Does not check whether
   the class already exists, and does not create xenbus watches. */
static struct xenbus_device_class *
ConstructDeviceClass(PXENEVTCHN_DEVICE_EXTENSION pXevtdx, const char *class)
{
    struct xenbus_device_class *xdc;

    xdc = XmAllocateZeroedMemory(sizeof(*xdc));
    if (!xdc)
        return NULL;

    InitializeListHead(&xdc->devices);
    InitializeListHead(&xdc->classes);

    xdc->devExt = pXevtdx;

    xdc->class = xsstrdup(class);
    if (!xdc->class) {
        XmFreeMemory(xdc);
        return NULL;
    }

    return xdc;
}

/* Probe a particular device class on the bus */
static VOID
ProbeDeviceClass(PXENEVTCHN_DEVICE_EXTENSION pXevtdx, char *class)
{
    struct xenbus_device_class *xdc;

    if (!strcmp(class, "vbd") ||    // Handled by xenvbd
        !strcmp(class, "pci") ||    // Unhandled
        (!strcmp(class, "vif") && XenPVFeatureEnabled(DEBUG_NIC_EMULATED))) {
        TraceVerbose(("%s: ignoring class %s.\n", __FUNCTION__, class));
        return;
    }

    ExAcquireFastMutex(&pXevtdx->xenbus_lock);
    xdc = FindDeviceClass(pXevtdx, class);
    if (!xdc) {
        /* Class doesn't exist, construct it. */
        xdc = ConstructDeviceClass(pXevtdx, class);
        if (!xdc) {
            TraceError(("Error probing class %s.\n", class));
            ExReleaseFastMutex(&pXevtdx->xenbus_lock);
            return;
        }

        InsertTailList(&pXevtdx->xenbus_device_classes, &xdc->classes);
    }
    ExReleaseFastMutex(&pXevtdx->xenbus_lock);

    xenbus_class_changed(xdc);

    TraceVerbose (("Did stuff to class %s.\n", class));
    return;
}

static VOID
xenbus_probe(PXENEVTCHN_DEVICE_EXTENSION pXevtdx)
{
    char **dev_classes;
    NTSTATUS stat;
    int x;

    /* It's really not obvious what we should do if we hit an error
       here. */
    TraceDebug (("Probing xenbus.\n"));
    stat = xenbus_ls(XBT_NIL, "device", &dev_classes);
    if (!NT_SUCCESS(stat)) {
        TraceError (("Couldn't list device classes.\n"));
        return;
    }
    for (x = 0; dev_classes[x]; x++) {
        ProbeDeviceClass(pXevtdx, dev_classes[x]);
        XmFreeMemory(dev_classes[x]);
    }
    TraceDebug (("Done probe.\n"));
    XmFreeMemory(dev_classes);
}

static FAST_MUTEX
reread_backends_mux;

static void
_reread_backends_suspend_handler(PVOID ctxt)
{
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx = ctxt;
    LIST_ENTRY *le;
    struct xenbus_device *xd;
    int something_failed = 0;
    char *backend_path;

    ExAcquireFastMutex(&reread_backends_mux);

    ExAcquireFastMutex(&pXevtdx->xenbus_lock);

    /* Re-read all of the backend paths and re-register the watches.
       Note that we can't read xenbus while holding locks, so we have
       to back out and retry from the beginning quite a lot.  It's
       unfortunate that this makes an O(n) problem taken O(n^2), but
       it's rare and n is expected to be small, so it's not too
       bad. */
retry:
    for (le = pXevtdx->devices.Flink;
         le != &pXevtdx->devices;
         le = le->Flink) {
        xd = CONTAINING_RECORD(le,
                               struct xenbus_device,
                               all_devices);
        if (xd->failed || !xd->backend_watch_stale)
            continue;
        InterlockedIncrement(&xd->refcount);
        ExReleaseFastMutex(&pXevtdx->xenbus_lock);
        if (xd->bstate_watch)
            xenbus_unregister_watch(xd->bstate_watch);
        xd->bstate_watch = NULL;
        xd->backend_watch_stale = 0;

        /* We don't inhibit suspends here: if one comes in at a bad
           time, the worst that happens is that we temporarily get a
           watch on a bad path, and we'll recover when the suspend
           handler runs. */
        backend_path = FindBackendPath(XBT_NIL, xd);
        if (backend_path) {
            /* XXX watching the backend area rather than the state
             * node. */
            xd->bstate_watch =
                xenbus_watch_path(backend_path,
                                  xenbus_device_backend_state_changed,
                                  xd);
            if (!xd->bstate_watch) {
                xd->failed = 1;
                something_failed = 1;
                TraceWarning(("Could not watch %s for %s:%s on resume\n",
                              backend_path, xd->class->class, xd->name));
            }
            XmFreeMemory(backend_path);
        } else {
            xd->failed = 1;
            something_failed = 1;
            TraceWarning(("Could not read backend path for %s:%s on resume\n",
                          xd->class->class, xd->name));
        }
        xenbus_device_deref(xd);
        ExAcquireFastMutex(&pXevtdx->xenbus_lock);
        goto retry;
    }
    ExReleaseFastMutex(&pXevtdx->xenbus_lock);

    ExReleaseFastMutex(&reread_backends_mux);

    if (something_failed)
    {
        if (!pXevtdx->UninstEnabled)
        {
            IoInvalidateDeviceRelations(pXevtdx->PhysicalDeviceObject,
                                        BusRelations);
        }
        else
        {
            TraceNotice(("Something failed; No rescan, uninstall in progress \n"));
        }
    }

}

/* Invoked as a late suspend handler to re-read all of the backend
   paths, which may change across suspend/resume. */
static void
reread_backends(PXENEVTCHN_DEVICE_EXTENSION pXevtdx)
{
    LIST_ENTRY *le;
    struct xenbus_device *xd;

    ExAcquireFastMutex(&pXevtdx->xenbus_lock);
    /* First walk the list and set ->backend to NULL.  We know that
       nobody's going to be reading backend, since we're a suspend
       handler and you have to own a suspend token before accessing
       it, and this is kind of handy for spotting certain obscure
       bugs. */
    for (le = pXevtdx->devices.Flink;
         le != &pXevtdx->devices;
         le = le->Flink) {
        xd = CONTAINING_RECORD(le,
                               struct xenbus_device,
                               all_devices);
        xd->backend_watch_stale = 1;
    }
    ExReleaseFastMutex(&pXevtdx->xenbus_lock);

    XenQueueWork(_reread_backends_suspend_handler, pXevtdx);
}

static void
reread_backends_suspend_handler(void *ctxt, SUSPEND_TOKEN token)
{
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx = ctxt;
    PIO_ERROR_LOG_PACKET log_entry;

    UNREFERENCED_PARAMETER(token);

    log_entry = IoAllocateErrorLogEntry(XenevtchnDriver, sizeof(*log_entry));
    if (log_entry == NULL) {
        TraceWarning(("Could not allocate log entry to record that we suspended !\n"));
    } else {
        memset(log_entry, 0, sizeof(*log_entry));
        log_entry->ErrorCode = XEN_MIGRATED;
        IoWriteErrorLogEntry(log_entry);
    }

    reread_backends(pXevtdx);
}

void
PnpRecoverFromHibernate(PXENEVTCHN_DEVICE_EXTENSION pXevtdx)
{
    reread_backends(pXevtdx);
}

static NTSTATUS
XenevtchnMapResources (
    PXENEVTCHN_DEVICE_EXTENSION DeviceExtension, 
    PIRP Irp
    )
{
    ULONG count;
    ULONG i;
    BOOLEAN interruptFound;
    PIO_STACK_LOCATION irpStack;
    PHYSICAL_ADDRESS memoryBase = {0};
    PVOID memoryBaseVa;
    PCM_PARTIAL_RESOURCE_LIST partialResourceListRaw;
    PCM_PARTIAL_RESOURCE_LIST partialResourceListTranslated;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR resourceRaw;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR resourceTrans;
    NTSTATUS status;
    ULONG vector = 0;
    ULONG translatedVector = 0;
    KIRQL translatedIrql = 0;
    KAFFINITY translatedAffinity = 0;

    TraceVerbose(("XenevtchnMapResources\n"));
    status = STATUS_SUCCESS;
    irpStack = IoGetCurrentIrpStackLocation(Irp);
    if ((XenPVEnabled() != TRUE) ||
        (irpStack->Parameters.StartDevice.AllocatedResourcesTranslated == NULL) ||
        (irpStack->Parameters.StartDevice.AllocatedResources == NULL)) {

        status = STATUS_DEVICE_CONFIGURATION_ERROR;
        goto exit;
    }

    interruptFound = FALSE;
    count = 0;
    partialResourceListRaw = 
        &irpStack->Parameters.StartDevice.AllocatedResources->List[0].PartialResourceList;

    partialResourceListTranslated = 
        &irpStack->Parameters.StartDevice.AllocatedResourcesTranslated->List[0].PartialResourceList;

    resourceRaw = &partialResourceListRaw->PartialDescriptors[0];
    resourceTrans = &partialResourceListTranslated->PartialDescriptors[0];
    for (i = 0;
         i < partialResourceListTranslated->Count;
         i++, resourceTrans++, resourceRaw++) {

        switch (resourceTrans->Type) {
            case CmResourceTypeMemory:
                memoryBase = resourceTrans->u.Memory.Start;
                count = resourceTrans->u.Memory.Length;
                break;

            case CmResourceTypeInterrupt:
                if (interruptFound)
                    TraceWarning(("Found multiple interrupts?\n"));
                interruptFound = TRUE;
                translatedVector = resourceTrans->u.Interrupt.Vector;
                translatedIrql = (KIRQL)resourceTrans->u.Interrupt.Level;
                translatedAffinity = resourceTrans->u.Interrupt.Affinity;
                /* The interrupt is level triggered.  If Windows
                   doesn't believe that, it's going to explode
                   horribly. */
                XM_ASSERT(!(resourceTrans->Flags &
                            CM_RESOURCE_INTERRUPT_LATCHED));
                vector = resourceRaw->u.Interrupt.Vector;
                break;

            default:
                break;
        };
    }

    if ((interruptFound != TRUE) || (count == 0)) {
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    memoryBaseVa = MmMapIoSpace(memoryBase, count, MmNonCached);
    if (memoryBaseVa == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        TraceWarning(("Failed to map IO hole! (%x bytes at %I64x)\n",
                      count, memoryBase));
        goto exit;
    }

    XenevtchnInitIoHole(memoryBase, memoryBaseVa, count);

    RegisterBugcheckCallbacks();
    InitDebugHelpers();

    TraceVerbose (("Starting event channels.\n"));
    status = EvtchnStart();
    if (!NT_SUCCESS(status)) {
        goto exit;
    }

    TraceVerbose (("Starting grant table.\n"));
    status = GnttabInit();
    if (!NT_SUCCESS(status)) {
        EvtchnStop();
        goto exit;
    }

    TraceVerbose (("Starting xenbus.\n"));
    status = XenevtchnInitXenbus();
    if (!NT_SUCCESS(status)) {
        GnttabCleanup();
        EvtchnStop();
        goto exit;
    }

    if (XenPVFeatureEnabled(DEBUG_BALLOON)) {
        RTL_OSVERSIONINFOEXW verInfo;

        XenutilGetVersionInfo(&verInfo);

        if (verInfo.dwMajorVersion == 5 &&
            verInfo.dwMinorVersion == 0) {
            TraceNotice(("Ballooning not supported on Windows 2000.\n"));
        } else {
            TraceVerbose (("Starting balloon.\n"));
            BalloonInit();
        }
    }

    status = IoConnectInterrupt(&DeviceExtension->Interrupt,
                                EvtchnHandleInterrupt,
                                DeviceExtension,
                                NULL,
                                translatedVector,
                                translatedIrql,
                                translatedIrql,
                                LevelSensitive,
                                TRUE,
                                translatedAffinity,
                                FALSE);

    if (!NT_SUCCESS(status)) {
        TraceError(("Failed 0x%08x to connect interrupt %d.\n", 
                    status, translatedVector));
        goto exit;
    }

    EvtchnSetVector(vector);
    HvmSetCallbackIrq(vector);

    TraceNotice(("PV init. done\n"));

exit:
    return status;
}

/* Synthesise a fake network interface.  Assumes that there aren't any
   real vifs available on the bus. */
/* XXX Error paths leak */
static VOID
SynthesiseFakeNetif(PXENEVTCHN_DEVICE_EXTENSION pXevtdx)
{
    struct xenbus_device_class *xdc;
    struct xenbus_device *xd;
    PDEVICE_OBJECT newdev;

    if (!XenPVFeatureEnabled(DEBUG_NO_PARAVIRT)) {
        TraceError(("Cannot synthesis fake network interface in paravirtualised mode!\n"));
        return;
    }

    /* Create a netif device class */
    xdc = ConstructDeviceClass(pXevtdx, "vif");
    if (!xdc) {
        TraceError(("Failed to construct a device class for fake netif\n"));
        return;
    }
    ExAcquireFastMutex(&pXevtdx->xenbus_lock);
    InsertTailList(&pXevtdx->xenbus_device_classes, &xdc->classes);
    ExReleaseFastMutex(&pXevtdx->xenbus_lock);

    /* Create a vif/0 device */
    xd = ConstructDevice(pXevtdx, xdc, "0");
    if (!xd) {
        TraceError(("Failed to construct a device structure for fake netif\n"));
        return;
    }

    if (!NT_SUCCESS(XenbusDeviceCreatePdo(xd, pXevtdx, &newdev))) {
        TraceError(("Failed to construct a PDO for fake netif\n"));
        return;
    }

    ExAcquireFastMutex(&pXevtdx->xenbus_lock);
    InsertTailList(&pXevtdx->devices, &xd->all_devices);
    InsertTailList(&xdc->devices, &xd->devices_this_class);
    ExReleaseFastMutex(&pXevtdx->xenbus_lock);

    newdev->Flags &= ~DO_DEVICE_INITIALIZING;
}

static NTSTATUS
reprobe_xenbus_thread(struct xm_thread *this, void *_ctxt)
{
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx = _ctxt;
    struct xenbus_watch_handler *wh;

    wh = xenbus_watch_path_event("device", &this->event);
    if (wh == NULL) {
        /* Device hotplug won't work.  That's pretty bad, but not
           completely fatal.  Flag an error and try to
           continue. */
        TraceError(("Failed to watch xenbus device area!\n"));
    }

    while (XmThreadWait(this) >= 0) {
        xenbus_probe(pXevtdx);
        KeSetEvent(&pXevtdx->initial_probe_complete,
                   IO_NO_INCREMENT,
                   FALSE);
    }
    /* Shouldn't ever happen. */
    if (wh)
        xenbus_unregister_watch(wh);
    TraceError(("Xenbus reprobe thread exitting?\n"));
    return STATUS_SUCCESS;
}

//
// Handle request to start the target device.
//
static NTSTATUS
StartDeviceFdo(
    IN PDEVICE_OBJECT fdo,
    IN PIRP Irp
    )
{
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx = 
        (PXENEVTCHN_DEVICE_EXTENSION) fdo->DeviceExtension;
    NTSTATUS status;

    TraceNotice(("%s: ====>\n", __FUNCTION__));

    status = ForwardIrpSynchronously(fdo, Irp);
    if ( !NT_SUCCESS(status) ) {
        TraceError (("Failed to start lower drivers: %x.\n",
                status));
        goto exit;
    }

    if (!XenPVFeatureEnabled(DEBUG_NO_PARAVIRT)) {
        status = XenevtchnMapResources(pXevtdx, Irp);
        if (!NT_SUCCESS(status)) {
            goto exit;
        }

        ExInitializeFastMutex(&reread_backends_mux);
        KeInitializeEvent(&pXevtdx->initial_probe_complete,
                          NotificationEvent,
                          FALSE);

        pXevtdx->reprobe_xenbus_thread = XmSpawnThread(reprobe_xenbus_thread,
                                                       pXevtdx);
        if (!pXevtdx->reprobe_xenbus_thread) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto exit;
        }

        EvtchnRegisterSuspendHandler(reread_backends_suspend_handler,
                                     pXevtdx,
                                     "reread_backends_suspend_handler",
                                     SUSPEND_CB_LATE);
        //
        // Wait for watches to fire so we can report children in our
        // first IRP_MN_QUERY_DEVICE_RELATIONS (BusRelations).
        //
        KeSetEvent(&pXevtdx->reprobe_xenbus_thread->event,
                   IO_NO_INCREMENT,
                   FALSE);
        KeWaitForSingleObject(&pXevtdx->initial_probe_complete,
                              Executive,
                              KernelMode,
                              FALSE,
                              NULL);

        UpdateMachineName();
    }


    if (XenPVFeatureEnabled(DEBUG_FAKE_NETIF)) {
        TraceNotice(("Creating fake network interface.\n"));
        SynthesiseFakeNetif(pXevtdx);
    }

exit:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    TraceNotice(("%s: <==== (%08x)\n", __FUNCTION__, status));
    return status;
}

static NTSTATUS
StartDevicePdo(
    IN PDEVICE_OBJECT pdo,
    IN OUT PIRP Irp
    )
{
    unsigned need_kick;
    struct xenbus_device *xd;

    if (!xenbus_await_initialisation())
    {
        return TrivialIrpHandler(Irp, STATUS_NOT_SUPPORTED);
    }
    else
    {
        xd = GetXenbusDeviceForPdo(pdo);

        ExAcquireFastMutex(&xd->pdo_lock);
        xd->pdo_ready = 1;
        need_kick = xd->lost_watch_event;
        xd->lost_watch_event = 0;
        ExReleaseFastMutex(&xd->pdo_lock);

        if (need_kick)
            xenbus_trigger_watch(xd->bstate_watch);

        return TrivialIrpHandler(Irp, STATUS_SUCCESS);
    }
}

static NTSTATUS
StopDevice(
    PDEVICE_OBJECT fdo, 
    PIRP Irp
    )
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    return DefaultPnpHandler(fdo, Irp);
}

static NTSTATUS
QueryStopDeviceFdo(
    PDEVICE_OBJECT fdo, 
    PIRP Irp
    )
{
    TraceNotice(("%s\n", __FUNCTION__));

    Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_UNSUCCESSFUL;
}

// This should never get called since we failed the query
static NTSTATUS
StopDeviceFdo(
    PDEVICE_OBJECT fdo, 
    PIRP Irp
    )
{
    TraceNotice(("%s\n", __FUNCTION__));

    return StopDevice(fdo, Irp);
}

static NTSTATUS
QueryRemoveDeviceFdo(
    PDEVICE_OBJECT fdo, 
    PIRP Irp
    )
{
    TraceNotice(("%s\n", __FUNCTION__));

    Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_UNSUCCESSFUL;
}

// This should never get called since we failed the query
static NTSTATUS
RemoveDeviceFdo(
    PDEVICE_OBJECT fdo, 
    PIRP Irp
    )
{
    UNICODE_STRING linkName;
    NTSTATUS status;
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx = 
        (PXENEVTCHN_DEVICE_EXTENSION) fdo->DeviceExtension;

    TraceNotice(("%s\n", __FUNCTION__));

    status = StopDevice(fdo, Irp);
    if (!NT_SUCCESS(status)) {
        TraceWarning(("Uh oh, failed a STOP request, about to fail a REMOVE request.\n"));
    }
    IoDetachDevice(pXevtdx->LowerDeviceObject);

    RtlInitUnicodeString( &linkName, XENEVTCHN_FILE_NAME );
    IoDeleteSymbolicLink( &linkName );
    
    IoDeleteDevice(fdo);

    return status;
}

static NTSTATUS
RemoveDevicePdo(PDEVICE_OBJECT pdo, PIRP Irp)
{
    struct xenbus_device *xd = GetXenbusDeviceForPdo(pdo);
    PDEVICE_OBJECT p;
    struct xm_thread *reprobe_thread;

    if (!xd->reported_to_pnpmgr) {
        TraceNotice(("Final remove on %s/%s.\n", xd->class->class, xd->name));
        ExAcquireFastMutex(&xd->pdo_lock);
        p = xd->pdo;
        xd->pdo = NULL;
        ExReleaseFastMutex(&xd->pdo_lock);
        if (!p) {
            TraceWarning(("Tried to delete %s/%s from pnpmgr twice!\n",
                          xd->class->class, xd->name));
        } else {
            XM_ASSERT(p == pdo);
            ExAcquireFastMutex(&xd->devExt->xenbus_lock);
            RemoveEntryList(&xd->all_devices);
            RemoveEntryList(&xd->devices_this_class);
            ExReleaseFastMutex(&xd->devExt->xenbus_lock);

            TrivialIrpHandler(Irp, STATUS_SUCCESS);

            IoDeleteDevice(p);

            reprobe_thread = xd->devExt->reprobe_xenbus_thread;
            xenbus_device_deref(xd);

            /* Because if we couldn't build the reprobe thread we'd
               have failed the FDO START and we wouldn't have any PDOs
               to remove. */
            XM_ASSERT(reprobe_thread != NULL);

            /* Wake up the reprobe thread in case the device
               re-appeared while we were working. */
            KeSetEvent(&reprobe_thread->event, IO_NO_INCREMENT, 0);
        }
    } else {
        TraceDebug(("IRP_MN_REMOVE to still-live device %s/%s.\n",
                   xd->class->class, xd->name));
        TrivialIrpHandler(Irp, STATUS_SUCCESS);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
CancelRemoveFdo(
    PDEVICE_OBJECT fdo, 
    PIRP Irp
)
{
    TraceNotice(("%s\n", __FUNCTION__));

    Irp->IoStatus.Status = STATUS_SUCCESS;
    return DefaultPnpHandler(fdo, Irp);
}

static NTSTATUS
CancelRemovePdo(PDEVICE_OBJECT pdo, PIRP Irp)
{
    char* errorPath;
    XENBUS_STATE state;
    struct xenbus_device *xd = GetXenbusDeviceForPdo(pdo);

    state = read_backend_state(xd);
    if (same_XENBUS_STATE(state, XENBUS_STATE_CLOSING)) {
        errorPath = Xmasprintf("error/%s/error",
                                xd->frontend_path);

        if (errorPath) {
            xenbus_write(XBT_NIL, errorPath,
                         "Unplug failed due to open handle(s)!");

            XmFreeMemory(errorPath);
        }
    }
    TrivialIrpHandler(Irp, STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

static NTSTATUS
CancelStopFdo(
    PDEVICE_OBJECT fdo, 
    PIRP Irp
)
{
    TraceNotice(("%s\n", __FUNCTION__));

    Irp->IoStatus.Status = STATUS_SUCCESS;
    return DefaultPnpHandler(fdo, Irp);
}

static PDEVICE_RELATIONS
DoPdoQueryDeviceRelations(struct xenbus_device *dev)
{
    PDEVICE_RELATIONS newrel;
    newrel = ExAllocatePoolWithTag(PagedPool, sizeof(DEVICE_RELATIONS),
                                   XPNP_TAG);
    if (!newrel)
        return NULL;
    newrel->Count = 1;
    newrel->Objects[0] = dev->pdo;
    ObReferenceObject(dev->pdo);

    return newrel;
}

static PDEVICE_RELATIONS
DoFdoQueryDeviceRelations(PXENEVTCHN_DEVICE_EXTENSION pXevtdx)
{
    LIST_ENTRY *le;
    PDEVICE_RELATIONS newrel;
    int i;
    int nChildren;
    struct xenbus_device *xd;
    LARGE_INTEGER now;

    KeQuerySystemTime(&now);

    ExAcquireFastMutex(&pXevtdx->xenbus_lock);
    nChildren = 0;
    for (le = pXevtdx->devices.Flink;
         le != &pXevtdx->devices;
         le = le->Flink) {
        xd = CONTAINING_RECORD(le,
                               struct xenbus_device,
                               all_devices);
        should_be_enumerated(xd);
        if (!xd->failed && !xd->surprise_remove && xd->enumerate &&
            (xd->present_in_xenbus ||
             xd->removal_time.QuadPart > now.QuadPart))
            nChildren++;
    }

    newrel = ExAllocatePoolWithTag(PagedPool,
                                   FIELD_OFFSET(DEVICE_RELATIONS,Objects) +
                                       sizeof(newrel->Objects[0]) *
                                       nChildren,
                                   XPNP_TAG);
    if (!newrel) {
        ExReleaseFastMutex(&pXevtdx->xenbus_lock);
        return NULL;
    }

    i = 0;
    le = pXevtdx->devices.Flink;
    while (le != &pXevtdx->devices) {
        xd = CONTAINING_RECORD(le,
                               struct xenbus_device,
                               all_devices);
        if (xd->failed)
            TraceDebug(("%s/%s failed.\n", xd->class->class, xd->name));
        else if (!xd->enumerate)
            TraceNotice(("%s/%s not being enumerated.\n", xd->class->class,
                       xd->name));
        else if (xd->present_in_xenbus)
            TraceDebug(("%s/%s present.\n", xd->class->class,
                       xd->name));
        else if (xd->surprise_remove)
            TraceDebug(("%s/%s surprise remove.\n", xd->class->class,
                       xd->name));
        else if (xd->removal_time.QuadPart > now.QuadPart) {
            TraceDebug(("%s/%s is preserved: %I64d > %I64d.\n",
                       xd->class->class, xd->name,
                       xd->removal_time.QuadPart, now.QuadPart));
        } else
            TraceDebug(("%s/%s really gone.\n", xd->class->class,
                       xd->name));
        if (!xd->failed && !xd->surprise_remove && xd->enumerate &&
            (xd->present_in_xenbus ||
             xd->removal_time.QuadPart > now.QuadPart)) {
            XM_ASSERT(xd->pdo);
            XM_ASSERT(i < nChildren);
            newrel->Objects[i] = xd->pdo;
            ObReferenceObject(xd->pdo);
            xd->reported_to_pnpmgr = 1;
            i++;
        } else {
            xd->reported_to_pnpmgr = 0;
        }
        le = le->Flink;
    }
    ExReleaseFastMutex(&pXevtdx->xenbus_lock);

    newrel->Count = nChildren;

    return newrel;
}

static NTSTATUS
FdoQueryDeviceRelations(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    if (XenPVFeatureEnabled(DEBUG_HA_SAFEMODE)) {
        goto exit;
    }

    TraceDebug (("FDO (0x%x, %d)\n", 
                DeviceObject,
                stack->Parameters.QueryDeviceRelations.Type));
    //
    // This interface will be used to enumerate sub-devices on the
    // xenbus.
    //
    if (stack->Parameters.QueryDeviceRelations.Type == BusRelations) {
        Irp->IoStatus.Information =
            (ULONG_PTR)DoFdoQueryDeviceRelations(pXevtdx);
        if (!Irp->IoStatus.Information)
            return TrivialIrpHandler(Irp,
                         STATUS_INSUFFICIENT_RESOURCES);
        Irp->IoStatus.Status = STATUS_SUCCESS;

    }

exit:
    return DefaultPnpHandler(DeviceObject, Irp);
}

static NTSTATUS
PdoQueryDeviceRelations(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    struct xenbus_device *xd = GetXenbusDeviceForPdo(DeviceObject);
    NTSTATUS status = Irp->IoStatus.Status;

    TraceDebug (("PDO (0x%x, %d)\n",
                DeviceObject,
                stack->Parameters.QueryDeviceRelations.Type));

    if (stack->Parameters.QueryDeviceRelations.Type ==
        TargetDeviceRelation) {
        Irp->IoStatus.Information =
            (ULONG_PTR)DoPdoQueryDeviceRelations(xd);
        if (!Irp->IoStatus.Information)
            return TrivialIrpHandler(Irp,
                         STATUS_INSUFFICIENT_RESOURCES);
        status = STATUS_SUCCESS;
    }
    return TrivialIrpHandler(Irp, status);
}

static NTSTATUS
QueryId(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    struct xenbus_device *xd = GetXenbusDeviceForPdo(DeviceObject);
    PWCHAR identity;
    size_t nchars;
    size_t size;
    PWCHAR id;

    switch (stack->Parameters.QueryId.IdType) {
        case BusQueryInstanceID:
            TraceDebug (("QueryInstanceID (%p)\n", DeviceObject));

            identity = xd->InstanceId;
            break;
        case BusQueryDeviceID:
            TraceDebug (("QueryDeviceId (%p)\n", DeviceObject));
            identity = xd->DeviceId;
            break;
        case BusQueryHardwareIDs:
            TraceDebug (("QueryHardwareId (%p)\n", DeviceObject));
            identity = xd->HardwareId;
            break;
        default:
            TraceDebug (("Unsupported: (%p, %d)\n", 
                        DeviceObject, 
                        stack->Parameters.QueryId.IdType));
            Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_NOT_SUPPORTED;
    }
    TraceDebug (("Identity is %S.\n", identity));
    nchars = wcslen(identity);
    size = (nchars + 2) * sizeof(WCHAR);
    id = (PWCHAR)ExAllocatePoolWithTag(PagedPool, size, XPNP_TAG);
    if (!id) {
        Irp->IoStatus.Information = (ULONG_PTR)NULL;
        return TrivialIrpHandler(Irp, STATUS_INSUFFICIENT_RESOURCES);
    }
    RtlStringCbCopyW(id, (nchars + 2) * sizeof(WCHAR), identity);
    id[nchars+1] = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = (ULONG_PTR)id;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
QueryDeviceText(
    IN PDEVICE_OBJECT pdo,
    IN PIRP Irp
)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status;
    struct xenbus_device *xd = GetXenbusDeviceForPdo(pdo);

    switch (stack->Parameters.QueryDeviceText.DeviceTextType) {
        case DeviceTextDescription:
            if (!Irp->IoStatus.Information) {
                PWCHAR buffer;

                buffer = ExAllocatePoolWithTag(PagedPool, 128, XPNP_TAG);
                if (buffer == NULL) {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                    break;
                }

                if (!strcmp(xd->class->class, "vif")) {
                    RtlStringCbCopyW(buffer, 128,
                                     L"OpenXT PV Ethernet Adapter");  // This stuff should really be in XenStore
                } else if (!strcmp(xd->class->class, "vwif")) {
                    RtlStringCbCopyW(buffer, 128,
                                     L"OpenXT PV Wireless Ethernet Adapter");  // This stuff should really be in XenStore
                } else if (!strcmp(xd->class->class, "v4v")) {
                    RtlStringCbCopyW(buffer, 128,
                                     L"OpenXT Xen V4V Interdomain Communication");  // This stuff should really be in XenStore
				} else if (!strcmp(xd->class->class, "vusb")) {
                    RtlStringCbCopyW(buffer, 128,
                                     L"OpenXT Xen PV USB Controller");  // This stuff should really be in XenStore
                } else {
                    RtlStringCbCopyW(buffer, 128,
                                     L"Unrecognised PV device class ");
                    RtlStringCbCatW(buffer, 128, xd->DeviceId);
                }
                Irp->IoStatus.Information = (ULONG_PTR)buffer;
            } 
            status = STATUS_SUCCESS;
            break;
                
        default:
            status = Irp->IoStatus.Status;
            break;
    }
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS
SucceedRequest(
    IN PDEVICE_OBJECT pdo,
    IN OUT PIRP Irp
)
{
    return TrivialIrpHandler(Irp, STATUS_SUCCESS);
}

NTSTATUS
IgnoreRequest(
    IN PDEVICE_OBJECT pdo,
    IN OUT PIRP Irp
)
{
    return TrivialIrpHandler(Irp, Irp->IoStatus.Status);
}

static NTSTATUS
PdoQueryInterface(
    IN PDEVICE_OBJECT pdo,
    IN OUT PIRP Irp
)
{
    PIO_STACK_LOCATION stack;
    NTSTATUS status;
    const GUID *interfaceType;

    stack = IoGetCurrentIrpStackLocation(Irp);
    interfaceType = stack->Parameters.QueryInterface.InterfaceType;
    TraceDebug (("size %d, version %d.\n",
                stack->Parameters.QueryInterface.Size,
                stack->Parameters.QueryInterface.Version));
    TraceDebug (("Guid: %x %x %x, %x %x %x %x %x %x %x %x\n",
                interfaceType->Data1,
                interfaceType->Data2,
                interfaceType->Data3,
                interfaceType->Data4[0],
                interfaceType->Data4[1],
                interfaceType->Data4[2],
                interfaceType->Data4[3],
                interfaceType->Data4[4],
                interfaceType->Data4[5],
                interfaceType->Data4[6],
                interfaceType->Data4[7]));

    if (memcmp(interfaceType,&GUID_BUS_INTERFACE_STANDARD, sizeof(GUID)) ||
        stack->Parameters.QueryInterface.Version != 1 ||
        stack->Parameters.QueryInterface.Size < sizeof(xenbusBusInterface))
    {
        TraceDebug (("Not a supported interface.\n"));
        status = Irp->IoStatus.Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    xenbusBusInterface.InterfaceReference(pdo);
    memcpy(stack->Parameters.QueryInterface.Interface,
           &xenbusBusInterface,
           sizeof(xenbusBusInterface));

    stack->Parameters.QueryInterface.Interface->Context = pdo;

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = (ULONG_PTR)NULL;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
DeviceUsageNotificationFdo(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp
    )
{
    NTSTATUS            status;

    TraceInfo(("%s: ====>\n", __FUNCTION__));

    Irp->IoStatus.Status = STATUS_SUCCESS;
    status = ForwardIrpSynchronously(DeviceObject, Irp);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    TraceInfo(("%s: <==== (%08x)\n", __FUNCTION__, status));
    return status;
}

/* Invoked as a completion routine when an IRP generated by
   DelegateRequest completes.  This should complete the original IRP
   with the same status. */
static IO_COMPLETION_ROUTINE OnDelegateComplete;
static NTSTATUS
OnDelegateComplete(
    PDEVICE_OBJECT tdo,
    PIRP subirp,
    PVOID ignore
)
{
    PIO_STACK_LOCATION substack;
    PIRP Irp;

    UNREFERENCED_PARAMETER (ignore);

    TraceDebug (("==> \n"));

    ObDereferenceObject(tdo);

    substack = IoGetCurrentIrpStackLocation(subirp);
    Irp = (PIRP)substack->Parameters.Others.Argument1;

    if (subirp->IoStatus.Status != STATUS_NOT_SUPPORTED) {
        Irp->IoStatus = subirp->IoStatus;
    }
    IoFreeIrp(subirp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

/* Take the IRP, which was sent to one of our PDOs, duplicate it, and
   drop it in the top of the FDO stack.  The IRP is pended on the PDO
   stack, and is completed when the FDO IRP completes, with the same
   result code. */
static NTSTATUS
DelegateRequest(
    PDEVICE_OBJECT pdo,
    PIRP Irp
)
{
    struct xenbus_device *xd = GetXenbusDeviceForPdo(pdo);
    PDEVICE_OBJECT fdo = xd->devExt->DeviceObject;
    PDEVICE_OBJECT top_device_obj;
    PIO_STACK_LOCATION stack;
    PIRP subirp;
    PIO_STACK_LOCATION substack;

    stack = IoGetCurrentIrpStackLocation(Irp);

    /* Find the top of the FDO stack. */
    top_device_obj = IoGetAttachedDeviceReference(fdo);

    /* Clone the irp.  The topmost location on the stack is used by us
       to get a completion callback when the IRP finishes.  The next
       is used by the topmost driver in the FDO stack, and below that
       we don't care.*/
    subirp = IoAllocateIrp(top_device_obj->StackSize+1, FALSE);
    substack = IoGetNextIrpStackLocation(subirp);
    substack->DeviceObject = top_device_obj;
    substack->Parameters.Others.Argument1 = (PVOID)Irp;

    IoSetNextIrpStackLocation(subirp);
    substack = IoGetNextIrpStackLocation(subirp);

    RtlCopyMemory(substack, stack,
                  FIELD_OFFSET(IO_STACK_LOCATION, CompletionRoutine));
    substack->Control = 0;

    IoSetCompletionRoutine(subirp, OnDelegateComplete, NULL,
                           TRUE, TRUE, TRUE);

    subirp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    /* Pend the IRP and send it to the FDO stack. */
    IoMarkIrpPending(Irp);
    IoCallDriver(top_device_obj, subirp);

    return STATUS_PENDING;
}

PSTR
xenbus_find_frontend(PDEVICE_OBJECT pdo)
{
    struct xenbus_device *xd;
    size_t s;
    char *res;

    xd = GetXenbusDeviceForPdo(pdo);
    if (!xd->frontend_path)
        return NULL;
    s = strlen(xd->frontend_path) + 1;
    res = XmAllocateMemory(s);
    if (res)
        memcpy(res, xd->frontend_path, s);
    return res;
}

PSTR
xenbus_find_backend(PDEVICE_OBJECT pdo, SUSPEND_TOKEN token)
{
    struct xenbus_device *xd;

    xd = GetXenbusDeviceForPdo(pdo);
    if (!xd->frontend_path)
        return NULL;
    return FindBackendPath(XBT_NIL, xd);
}

//
// Plug and Play function vector table.
//
PNP_INFO pnpInfo[] = {
    {StartDeviceFdo,
     StartDevicePdo,
      "IRP_MN_START_DEVICE" },
    {QueryRemoveDeviceFdo,
     SucceedRequest,
      "IRP_MN_QUERY_REMOVE_DEVICE" },
    {RemoveDeviceFdo,
     RemoveDevicePdo,
      "IRP_MN_REMOVE_DEVICE"},
    {CancelRemoveFdo,
     CancelRemovePdo,
     "IRP_MN_CANCEL_REMOVE_DEVICE"},
    {StopDeviceFdo,
     SucceedRequest,
     "IRP_MN_STOP_DEVICE"},
    {QueryStopDeviceFdo,
     SucceedRequest,
     "IRP_MN_QUERY_STOP_DEVICE"},
    {CancelStopFdo,
     SucceedRequest,
     "IRP_MN_CANCEL_STOP_DEVICE"},
    {FdoQueryDeviceRelations,
     PdoQueryDeviceRelations,
     "IRP_MN_QUERY_DEVICE_RELATIONS"},
    {DefaultPnpHandler,
     PdoQueryInterface,
     "IRP_MN_QUERY_INTERFACE"},
    {DefaultPnpHandler,
     PdoHandleQueryCapabilities,
     "IRP_MN_QUERY_CAPABILITIES"},
    {DefaultPnpHandler,
     SucceedRequest,
     "IRP_MN_QUERY_RESOURCES"},
    {DefaultPnpHandler,
     SucceedRequest,
     "IRP_MN_QUERY_RESOURCE_REQUIREMENTS"},
    {DefaultPnpHandler,
     QueryDeviceText,
     "IRP_MN_QUERY_DEVICE_TEXT"},
    {DefaultPnpHandler,
     SucceedRequest,
     "IRP_MN_FILTER_RESOURCE_REQUIREMENTS"},
    {DefaultPnpHandler,
     SucceedRequest,
     "IRP_MN_UNDEF(14)"},
    {DefaultPnpHandler,
     FailRequestNotSupported,
     "IRP_MN_READ_CONFIG"},
    {DefaultPnpHandler,
     FailRequestNotSupported,
     "IRP_MN_WRITE_CONFIG"},
    {DefaultPnpHandler,
     FailRequestNotSupported,
     "IRP_MN_EJECT"},
    {DefaultPnpHandler,
     FailRequestNotSupported,
     "IRP_MN_SET_LOCK"},
    {DefaultPnpHandler,
     QueryId,
     "IRP_MN_QUERY_ID"},
    {FdoQueryDeviceState,
     PdoQueryDeviceState,
     "IRP_MN_QUERY_PNP_DEVICE_STATE"},
    {DefaultPnpHandler,
     PdoQueryBusInformation,
     "IRP_MN_QUERY_BUS_INFORMATION"},
    {DeviceUsageNotificationFdo,
     DelegateRequest,
     "IRP_MN_DEVICE_USAGE_NOTIFICATION"},
    {DefaultPnpHandler,
     SucceedRequest,
     "IRP_MN_SURPRISE_REMOVAL"},
    {DefaultPnpHandler,
     IgnoreRequest,
     "IRP_MN_QUERY_LEGACY_BUS_INFORMATION"}
};

