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

/* Various power management bits and pieces. */
#include <wdm.h>
#include "ntddstor.h"
#pragma warning (push, 3)
#include "srb.h"
#include "classpnp.h"
#pragma warning (pop)
#include "xsapi.h"
#include "scsiboot.h"
#include "scsifilt.h"

/* Device power up processing.  The IRP gets dropped down to xenvbd,
   and then when it comes back to the completion routine we bounce it
   to the restart thread, which calls finish_power_up_irp() to
   complete it. */
void
finish_power_up_irp(struct scsifilt *sf, PIRP irp)
{
    IO_STACK_LOCATION *const isl = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status;

    TraceNotice(("Finish powering up %s.\n", sf->frontend_path));
    if (sf->current_power_state != PowerDeviceD0) {
        TraceNotice(("Connecting target %d.\n", sf->target_id));
        status = connect_scsifilt(sf);
        if (NT_SUCCESS(status)) {
            if (isl->Parameters.Power.Type == DevicePowerState)
                PoSetPowerState(sf->fdo, DevicePowerState,
                                isl->Parameters.Power.State);
            sf->current_power_state = PowerDeviceD0;
            sf->shutdown_type = PowerActionNone;

            unpause_datapath(sf);
            irp->IoStatus.Status = STATUS_SUCCESS;
        } else {
            irp->IoStatus.Status = status;
        }
    } else {
        TraceNotice(("Skipping connect to backend after power up.\n"));
        if (isl->Parameters.Power.Type == DevicePowerState)
            PoSetPowerState(sf->fdo, DevicePowerState,
                            isl->Parameters.Power.State);
        sf->current_power_state = PowerDeviceD0;
        irp->IoStatus.Status = STATUS_SUCCESS;
    }
    PoStartNextPowerIrp(irp);
    IoReleaseRemoveLock(&sf->remove_lock, irp);

    if (irp->PendingReturned)
        IoMarkIrpPending(irp);
    IoCompleteRequest(irp, IO_NO_INCREMENT);
}

static NTSTATUS
_handle_device_power_up(PDEVICE_OBJECT fdo, PIRP irp, PVOID ctxt)
{
    struct scsifilt *const sf = ctxt;
    IRP *old_irp;

    UNREFERENCED_PARAMETER(fdo);

    if (!NT_SUCCESS(irp->IoStatus.Status)) {
        TraceNotice(("Uh oh... xenvbd failed a power-up request (%x)\n",
                     irp->IoStatus.Status));
        if (irp->PendingReturned)
            IoMarkIrpPending(irp);
        PoStartNextPowerIrp(irp);
        IoReleaseRemoveLock(&sf->remove_lock, irp);
        return STATUS_SUCCESS;
    }

    old_irp = InterlockedExchangePointer(&sf->pending_power_up_irp, irp);
    KeSetEvent(&sf->restart_thread->event, IO_NO_INCREMENT, FALSE);

    /* Power manager is supposed to do sufficient synchronisation for
       us that we never have multiple power up IRPs outstanding. */
    XM_ASSERT3P(old_irp, ==, NULL);

    return STATUS_MORE_PROCESSING_REQUIRED;
}
/* Caution: this is also used by handle_system_desuspended(); see
   there for details. */
static void
handle_device_power_up(struct scsifilt *sf, PIRP irp)
{
    IO_STACK_LOCATION *const isl = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status;

    if (sf->current_power_state == PowerDeviceD0) {
        /* Already powered up -> nothing to do. */
        TraceInfo(("Nothing to do for device power up.\n"));
        PoStartNextPowerIrp(irp);
        PoSetPowerState(sf->fdo, DevicePowerState,
                        isl->Parameters.Power.State);
        ignore_irp(sf, irp, PoCallDriver);
        return;
    }
    if (isl->Parameters.Power.Type == DevicePowerState &&
        isl->Parameters.Power.State.DeviceState != PowerDeviceD0) {
        /* Non-D0 states are all off, so pretty much just ignore
         * this. */
        TraceInfo(("Power-up to intermediate state %d.\n",
                   isl->Parameters.Power.State.DeviceState));
        PoStartNextPowerIrp(irp);
        ignore_irp(sf, irp, PoCallDriver);
        return;
    }
    TraceNotice(("Power up %s\n", sf->frontend_path));
    status = IoAcquireRemoveLock(&sf->remove_lock, irp);
    if (!NT_SUCCESS(status)) {
        TraceWarning(("Can't get remove lock for power up.\n"));
        PoStartNextPowerIrp(irp);
        complete_irp(irp, status);
        return;
    }
    IoMarkIrpPending(irp);
    IoCopyCurrentIrpStackLocationToNext(irp);
    IoSetCompletionRoutine(irp, _handle_device_power_up, sf, TRUE, TRUE,
                           TRUE);
    status = PoCallDriver(sf->lower_do, irp);
    if (!NT_SUCCESS(status)) {
        TraceWarning(("xenvbd returned %x from PoCallDriver for _handle_device_power_up\n",
                      status));
    }
}

static void
handle_device_power_down(struct scsifilt *sf, PIRP irp)
{
    IO_STACK_LOCATION *const isl = IoGetCurrentIrpStackLocation(irp);

    if (sf->current_power_state != PowerDeviceD0 ||
        isl->Parameters.Power.State.DeviceState == sf->current_power_state) {
        TraceInfo(("Nothing to do for device power down.\n"));
        PoStartNextPowerIrp(irp);
        ignore_irp(sf, irp, PoCallDriver);
        return;
    }

    TraceNotice(("Power down %s\n", sf->frontend_path));
    sf->current_power_state = isl->Parameters.Power.State.DeviceState;
    sf->shutdown_type = isl->Parameters.Power.ShutdownType;

    pause_datapath(sf);
    close_scsifilt(sf);

    sf->target_stop(sf->target_id);
    sf->stopped = TRUE;

    if (isl->Parameters.Power.ShutdownType == PowerActionSleep)
        XmPrepForS3();

    PoStartNextPowerIrp(irp);
    PoSetPowerState(sf->fdo, DevicePowerState,
                    isl->Parameters.Power.State);
    ignore_irp(sf, irp, PoCallDriver);
}

static NTSTATUS
_handle_system_dehibernated(PDEVICE_OBJECT fdo, PIRP irp, PVOID ctxt)
{
    struct scsifilt *const sf = ctxt;

    UNREFERENCED_PARAMETER(fdo);

    PoStartNextPowerIrp(irp);

    /*
     * Power IRP processing seems to get stuck once we've finished handling all the
     * SystemPowerState IRPs unless we do some IO to SCSIport. Sending an IOCTL is sufficient.
     */
    wakeup_scsiport(sf, __FUNCTION__);

    IoReleaseRemoveLock(&sf->remove_lock, irp);
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_MORE_PROCESSING_REQUIRED;
}
static void
handle_system_dehibernate(struct scsifilt *sf, PIRP irp)
{
    NTSTATUS status;

    TraceNotice(("%s: Coming back from hibernation.\n",
                 sf->frontend_path));

    status = IoAcquireRemoveLock(&sf->remove_lock, irp);
    if (!NT_SUCCESS(status)) {
        complete_irp(irp, status);
        return;
    }
    IoCopyCurrentIrpStackLocationToNext(irp);
    IoSetCompletionRoutine(irp, _handle_system_dehibernated, sf, TRUE, TRUE,
                           TRUE);
    PoCallDriver(sf->lower_do, irp);
}

static NTSTATUS
_handle_system_desuspend(PDEVICE_OBJECT fdo, PIRP irp, PVOID ctxt)
{
    struct scsifilt *const sf = ctxt;

    UNREFERENCED_PARAMETER(fdo);

    PoStartNextPowerIrp(irp);

    /*
     * Power IRP processing seems to get stuck once we've finished handling all the
     * SystemPowerState IRPs unless we do some IO to SCSIport. Sending an IOCTL is sufficient.
     */
    wakeup_scsiport(sf, __FUNCTION__);

    IoReleaseRemoveLock(&sf->remove_lock, irp);
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_MORE_PROCESSING_REQUIRED;
}
static void
handle_system_desuspend(struct scsifilt *sf, PIRP irp)
{
    NTSTATUS status;

    TraceNotice(("%s: Coming back from suspend.\n",
                 sf->frontend_path));

    XmRecoverFromS3();

    status = IoAcquireRemoveLock(&sf->remove_lock, irp);
    if (!NT_SUCCESS(status)) {
        complete_irp(irp, status);
        return;
    }
    IoCopyCurrentIrpStackLocationToNext(irp);
    IoSetCompletionRoutine(irp, _handle_system_desuspend, sf, TRUE, TRUE,
                           TRUE);
    PoCallDriver(sf->lower_do, irp);
}

/* Second half of power IRP handling on the way down the stack.  This
 * does all the interesting stuff. */
void
handle_power_passive(struct scsifilt *sf, PIRP irp)
{
    IO_STACK_LOCATION *const isl = IoGetCurrentIrpStackLocation(irp);

    if (isl->MinorFunction != IRP_MN_QUERY_POWER) {
        if (isl->Parameters.Power.ShutdownType == PowerActionNone &&
            isl->Parameters.Power.Type == DevicePowerState &&
            isl->Parameters.Power.State.DeviceState == PowerDeviceD3) {
            BOOLEAN allow_power_down;

            // Note, this block is preventing disk idle power-downs that are sent due to power policy settings
            // that turn off disks after an idle interval. The check for PowerActionNone prevents this code
            // path from executing during a system power state change.
            xenbus_read_feature_flag(XBT_NIL, sf->backend_path, "feature-allow-power-down", &allow_power_down);
            TraceVerbose(("%s/%s == %s\n", sf->backend_path, "feature-allow-power-down", (allow_power_down) ? "TRUE" : "FALSE"));

            if (!allow_power_down) {
                TraceNotice(("Prevent disk idle power-down for target %d\n", sf->target_id));
                PoStartNextPowerIrp(irp);
                complete_irp(irp, STATUS_UNSUCCESSFUL);
                return;
            }
        }
    }

    if (isl->MinorFunction != IRP_MN_SET_POWER) {
        /* Don't need to do anything for non-SET_POWER power IRPs. */
        PoStartNextPowerIrp(irp);
        ignore_irp(sf, irp, PoCallDriver);
        return;
    }

    switch (isl->Parameters.Power.Type) {
    case SystemPowerState:
        if (sf->shutdown_type == PowerActionHibernate &&
            isl->Parameters.Power.State.SystemState == PowerSystemWorking) {
            handle_system_dehibernate(sf, irp);
            return;
        }
        if (sf->shutdown_type == PowerActionSleep &&
            isl->Parameters.Power.State.SystemState == PowerSystemWorking) {
            handle_system_desuspend(sf, irp);
            return;
        }
        break;

    case DevicePowerState:
        if (isl->Parameters.Power.State.DeviceState < sf->current_power_state) {
            handle_device_power_up(sf, irp);
        } else if (isl->Parameters.Power.State.DeviceState > sf->current_power_state) {
            handle_device_power_down(sf, irp);
        } else {
            PoStartNextPowerIrp(irp);
            TraceNotice(("%s: ignoring device power IRP\n", sf->frontend_path));
            ignore_irp(sf, irp, PoCallDriver);
        }
        return;
    default:
        TraceWarning(("Unknown set_power type %d\n",
                      isl->Parameters.Power.Type));
        break;
    }

    PoStartNextPowerIrp(irp);
    ignore_irp(sf, irp, PoCallDriver);
}

/* Kick everything to the restart thread so that we can do
   PASSIVE_LEVEL work. */
NTSTATUS
handle_power(PDEVICE_OBJECT fdo, PIRP irp)
{
    struct scsifilt *const sf = get_scsifilt(fdo);
    PIRP old_irp;

    IoMarkIrpPending(irp);

    old_irp = InterlockedExchangePointer(&sf->pending_power_irp, irp);
    /* Power manager is supposed to do sufficient synchronisation for
       us that we never have multiple power IRPs outstanding. */
    XM_ASSERT3P(old_irp, ==, NULL);
    KeSetEvent(&sf->restart_thread->event, IO_NO_INCREMENT, FALSE);

    return STATUS_PENDING;
}
