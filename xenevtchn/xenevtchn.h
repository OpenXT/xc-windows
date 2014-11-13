//
// xenevtchn.h
//
// Copyright (c) 2006 XenSource, Inc. - All rights reserved.
//

/*
 * Copyright (c) 2011 Citrix Systems, Inc.
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


#ifndef _XENEVTCHN_H_
#define _XENEVTCHN_H_

#define DEBUG 1

#define TEST_DEVICE_ENUMERATION 1

#define XENEVTCHN_VERSION "1.0"

#include "ntddk.h"
#include "wchar.h"
#include "xsapi.h"
#include "xs_ioctl.h"

#define XENEVTCHN_DEVICE_NAME L"\\Device\\xenevent"
#define XENEVTCHN_FILE_NAME  L"\\DosDevices\\XenBus"

#define XENEVTCHN_PDO_SIGNATURE 0x7556b3a5
#define XENEVTCHN_FDO_SIGNATURE 0x7556b3a6

typedef struct _XENEVTCHN_DEVICE_HDR {
    ULONG   Signature;
} XENEVTCHN_DEVICE_HDR, *PXENEVTCHN_DEVICE_HDR;

struct xenbus_device_class {
    struct _XENEVTCHN_DEVICE_EXTENSION *devExt;
    LIST_ENTRY classes; /* List of all device_classes, anchored at
                           DEVICE_EXTENSION::xenbus_device_classes */
    LIST_ENTRY devices; /* Anchor for list of devices in this class,
                           threaded through
                           xenbus_device::devices_this_class */
    char *class;
};

/* See xenbus_device_lifecycle.txt */
struct xenbus_device {
    struct _XENEVTCHN_DEVICE_EXTENSION *devExt;
    LIST_ENTRY devices_this_class; /* List of xenbus_device
                                      structures, anchored at
                                      xenbus_device_class::devices */
    LIST_ENTRY all_devices; /* List of xenbus_device structures,
                               anchored at
                               DEVICE_EXTENSION::devices */
    struct xenbus_device_class *class;
    char *name;
    LONG refcount;
    PDEVICE_OBJECT pdo;
    FAST_MUTEX pdo_lock;
    PWCHAR InstanceId;
    PWCHAR DeviceId;
    PWCHAR HardwareId;
    char *frontend_path; /* path to the frontend's area in the store. */
    struct xenbus_watch_handler *bstate_watch; /* Watch on
                                                * @backend_path/state */
    LARGE_INTEGER removal_time; /* Don't report the device as removed
                                   until this time, even if
                                   present_in_xenbus has gone to zero,
                                   to avoid races in Windows
                                   userspace. */
    unsigned present_in_xenbus:1;
    unsigned reported_to_pnpmgr:1;
    unsigned lost_watch_event:1;
    unsigned failed:1;
    unsigned backend_watch_stale:1;
    unsigned pdo_ready:1;
    unsigned enumerate:1;
    unsigned was_connected:1;
    unsigned bus_rescan_needed:1;
    unsigned surprise_remove:1;
};

#define XS_DELAY_REMOVAL_US 5000000

struct PDO_DEVICE_EXTENSION {
    XENEVTCHN_DEVICE_HDR Header;
    struct xenbus_device *dev;
    struct _XENEVTCHN_DEVICE_EXTENSION *fdo;
};

//
// The following structure contains device-specific information
// that is collected during the creation and activation process.
//
typedef struct _XENEVTCHN_DEVICE_EXTENSION {
    XENEVTCHN_DEVICE_HDR Header;
    PDRIVER_OBJECT DriverObject;
    PDEVICE_OBJECT DeviceObject;
    PDEVICE_OBJECT LowerDeviceObject;
    PDEVICE_OBJECT PhysicalDeviceObject;

    FAST_MUTEX xenbus_lock; /* Protects the device and device class
                               lists.  Leaf lock. */
    KEVENT initial_probe_complete;

    struct xm_thread *reprobe_xenbus_thread;

    LIST_ENTRY xenbus_device_classes;
    LIST_ENTRY devices;
    /* Device removal has to be delayed by a few milliseconds to work
       around a race in Windows userspace. */
    KTIMER xenbus_timer;
    KDPC xenbus_dpc;

    LIST_ENTRY ActiveHandles;
    ULONG      ActiveHandleCount;
    KSPIN_LOCK ActiveHandleLock;
    BOOLEAN UninstEnabled;
    PKINTERRUPT Interrupt;

    DEVICE_POWER_STATE PowerState;
} XENEVTCHN_DEVICE_EXTENSION, *PXENEVTCHN_DEVICE_EXTENSION;

/* A representation of a userspace watch. */
typedef struct _USER_WATCH_HANDLE {
    struct _USER_WATCH_HANDLE *next, *prev;
    int handle; /* Handle reported to userspace. */
    PKEVENT evt;
    struct xenbus_watch_handler *wh;
} USER_WATCH_HANDLE, *PUSER_WATCH_HANDLE;

typedef struct _XENEVTCHN_ACTIVE_HANDLE {
    LIST_ENTRY ListEntry; /* This must be the first field */
    PFILE_OBJECT FileObject;
    xenbus_transaction_t xbt;
    PKEVENT suspend_event;
    KSPIN_LOCK watches_lock; /* Leaf lock */
    PUSER_WATCH_HANDLE watches;
    BOOLEAN precious; /* Warn on close */

    FAST_MUTEX user_evtchns_mux;
    LIST_ENTRY user_evtchns; /* List of struct user_evtchns, threaded
                              * on the list field. */

} XENEVTCHN_ACTIVE_HANDLE, *PXENEVTCHN_ACTIVE_HANDLE;


ULONG64 HvmGetXenTime(void);


ULONG64 xm_strtoll(const char *buf, size_t len, unsigned base,
                   __inout int *err);

extern PDRIVER_OBJECT XenevtchnDriver;
extern int xenbusBusInterfaceRefcount;

extern const BUS_INTERFACE_STANDARD xenbusBusInterface;

NTSTATUS
InstallDumpDeviceCallback();

void XsRequestInvalidateBus(PKDPC dpc, PVOID arg1, PVOID arg2, PVOID arg3);

NTSTATUS UpdateMachineName();

void PnpRecoverFromHibernate(PXENEVTCHN_DEVICE_EXTENSION pXevtdx);

char *FindBackendPath(xenbus_transaction_t xbt, struct xenbus_device *xd);
struct xenbus_device *GetXenbusDeviceForPdo(PDEVICE_OBJECT pdo);

void InitUsermodeInterfaceEarly(void);
void InitUsermodeInterfaceLate(PXENEVTCHN_DEVICE_EXTENSION pXendx);
void FreezeXenbus(void);
void UnfreezeXenbus(PDEVICE_OBJECT DeviceObject);
void XevtchnProcessCleanup(void);
extern DRIVER_DISPATCH XenevtchnCreate;
extern DRIVER_DISPATCH XenevtchnClose;
extern DRIVER_DISPATCH XenevtchnDeviceControl;

#endif // _XENEVTCHN_H_

