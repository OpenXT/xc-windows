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

#include "xenevtchn.h"
#include "scsiboot.h"
#include "xsapi.h"

#include "ntstrsafe.h"

#include "../xenutil/hvm.h"
#include "../xenutil/evtchn.h"
#include "../xenutil/balloon.h"

static const CHAR *
PowerSystemStateName(
    IN  SYSTEM_POWER_STATE  State
    )
{
#define _POWER_SYSTEM_NAME(_State)                               \
        case PowerSystem ## _State:                              \
            return #_State;

    switch (State) {
    _POWER_SYSTEM_NAME(Unspecified);
    _POWER_SYSTEM_NAME(Working);
    _POWER_SYSTEM_NAME(Sleeping1);
    _POWER_SYSTEM_NAME(Sleeping2);
    _POWER_SYSTEM_NAME(Sleeping3);
    _POWER_SYSTEM_NAME(Hibernate);
    _POWER_SYSTEM_NAME(Shutdown);
    _POWER_SYSTEM_NAME(Maximum);
    default:
        break;
    }

    return ("UNKNOWN");
#undef  _POWER_SYSTEM_NAME
}

static const CHAR *
PowerDeviceStateName(
    IN  DEVICE_POWER_STATE  State
    )
{
#define _POWER_DEVICE_NAME(_State)                               \
        case PowerDevice ## _State:                              \
            return #_State;

    switch (State) {
    _POWER_DEVICE_NAME(Unspecified);
    _POWER_DEVICE_NAME(D0);
    _POWER_DEVICE_NAME(D1);
    _POWER_DEVICE_NAME(D2);
    _POWER_DEVICE_NAME(D3);
    _POWER_DEVICE_NAME(Maximum);
    default:
        break;
    }

    return ("UNKNOWN");
#undef  _POWER_DEVICE_NAME
}

static const CHAR *
PowerShutdownTypeName(
    IN  POWER_ACTION    Type
    )
{
#define _POWER_ACTION_NAME(_Type)                               \
        case PowerAction ## _Type:                              \
            return #_Type;

    switch (Type) {
    _POWER_ACTION_NAME(None);
    _POWER_ACTION_NAME(Reserved);
    _POWER_ACTION_NAME(Sleep);
    _POWER_ACTION_NAME(Hibernate);
    _POWER_ACTION_NAME(Shutdown);
    _POWER_ACTION_NAME(ShutdownReset);
    _POWER_ACTION_NAME(ShutdownOff);
    _POWER_ACTION_NAME(WarmEject);
    default:
        break;
    }

    return ("UNKNOWN");
#undef  _POWER_ACTION_NAME
}

static NTSTATUS
XenevtchnFdoSystemPowerIrpCompletion(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID Context
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    TraceInfo(("%s: completing power IRP\n", __FUNCTION__));
    PoStartNextPowerIrp(Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS
XenevtchnHandleFdoSystemPowerIrp(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx = 
        (PXENEVTCHN_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    NTSTATUS status;
    static BOOLEAN hibernated;
    static BOOLEAN suspended;

    if (XenPVFeatureEnabled(DEBUG_NO_PARAVIRT))
        goto done;

    switch (stack->MinorFunction) {
    case IRP_MN_SET_POWER:
        TraceNotice(("%s: Setting power: %d:%s (%d:%s)\n", __FUNCTION__,
                        stack->Parameters.Power.State.SystemState,
                        PowerSystemStateName(stack->Parameters.Power.State.SystemState),
                        stack->Parameters.Power.ShutdownType,
                        PowerShutdownTypeName(stack->Parameters.Power.ShutdownType)));

        if (stack->Parameters.Power.State.SystemState == PowerSystemHibernate) {
            XenSetSystemPowerState(PowerSystemHibernate);
            FreezeXenbus();
            KillSuspendThread();
            hibernated = TRUE;
        } else if (stack->Parameters.Power.State.SystemState == PowerSystemSleeping3) {
            XenSetSystemPowerState(PowerSystemSleeping3);
            XmPrepForS3();
            suspended = TRUE;
        } else if (stack->Parameters.Power.State.SystemState == PowerSystemWorking) {
            if (hibernated) {
                UnfreezeXenbus(DeviceObject);
                BalloonThaw();
                PnpRecoverFromHibernate(pXevtdx);
                hibernated = FALSE;
            } else if (suspended) {
                XmRecoverFromS3();
                suspended = FALSE;
            }
            XenSetSystemPowerState(PowerSystemWorking);
        }
        break;

    case IRP_MN_QUERY_POWER:
        TraceNotice(("%s: Query power: %d:%s (%d:%s)\n", __FUNCTION__, 
                        stack->Parameters.Power.State.SystemState,
                        PowerSystemStateName(stack->Parameters.Power.State.SystemState),
                        stack->Parameters.Power.ShutdownType,
                        PowerShutdownTypeName(stack->Parameters.Power.ShutdownType)));

        if (stack->Parameters.Power.State.SystemState == PowerSystemHibernate) {
            RTL_OSVERSIONINFOEXW verInfo;
            XenutilGetVersionInfo(&verInfo);
            status = STATUS_SUCCESS;
            if (verInfo.dwMajorVersion == 5 &&
                verInfo.dwMinorVersion == 0) {

                TraceWarning(("Hibernation disabled on Windows 2000.\n"));
                status = STATUS_INSUFFICIENT_RESOURCES;
                Irp->IoStatus.Status = status;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return status;
            }

            // On any OS starting with Vista you cannot prevent hibernation by
            // failing a IRP_MN_QUERY_POWER IRP so it'd better work, even if
            // we're ballooned.
                
            //
            // Ensure balloon does not inflate from here on
            // until resume from hibernate.
            //
            BalloonFreeze();
        }
        break;

    default:
        break;
    }

done:
    IoMarkIrpPending(Irp);
    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, XenevtchnFdoSystemPowerIrpCompletion, NULL, TRUE, TRUE, TRUE);

    PoCallDriver(pXevtdx->LowerDeviceObject, Irp);

    return STATUS_PENDING;
}

static NTSTATUS
XenevtchnFdoDevicePowerIrpCompletion(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID Context
    )
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx = 
        (PXENEVTCHN_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    UNREFERENCED_PARAMETER(Context);

    if (pXevtdx->PowerState >= stack->Parameters.Power.State.DeviceState) {
        TraceNotice(("%s: Powering up from %d:%s to: %d:%s (%d:%s)\n", __FUNCTION__, 
                     pXevtdx->PowerState,
                     PowerDeviceStateName(pXevtdx->PowerState),
                     stack->Parameters.Power.State.DeviceState,
                     PowerDeviceStateName(stack->Parameters.Power.State.DeviceState),
                     stack->Parameters.Power.ShutdownType,
                     PowerShutdownTypeName(stack->Parameters.Power.ShutdownType)));

        PoSetPowerState(DeviceObject,
                        DevicePowerState,
                        stack->Parameters.Power.State);
        pXevtdx->PowerState = stack->Parameters.Power.State.DeviceState;
    }

    TraceInfo(("%s: completing power IRP\n", __FUNCTION__));
    PoStartNextPowerIrp(Irp);

    return STATUS_SUCCESS;
}

static NTSTATUS
XenevtchnHandleFdoDevicePowerIrp(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx = 
        (PXENEVTCHN_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    if (pXevtdx->PowerState < stack->Parameters.Power.State.DeviceState) {
        TraceNotice(("%s: Powering down from %d:%s to: %d:%s (%d:%s)\n", __FUNCTION__, 
                     pXevtdx->PowerState,
                     PowerDeviceStateName(pXevtdx->PowerState),
                     stack->Parameters.Power.State.DeviceState,
                     PowerDeviceStateName(stack->Parameters.Power.State.DeviceState),
                     stack->Parameters.Power.ShutdownType,
                     PowerShutdownTypeName(stack->Parameters.Power.ShutdownType)));

        PoSetPowerState(DeviceObject,
                        DevicePowerState,
                        stack->Parameters.Power.State);
        pXevtdx->PowerState = stack->Parameters.Power.State.DeviceState;
    }

    IoMarkIrpPending(Irp);
    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, XenevtchnFdoDevicePowerIrpCompletion, NULL, TRUE, TRUE, TRUE);

    PoCallDriver(pXevtdx->LowerDeviceObject, Irp);

    return STATUS_PENDING;
}

static NTSTATUS
XenevtchnHandlePdoPowerIrp(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status;

    switch (stack->MinorFunction) {
    case IRP_MN_SET_POWER:
        if (stack->Parameters.Power.Type == DevicePowerState) {
            TraceNotice(("%s: Setting power: %d:%s (%d:%s)\n", __FUNCTION__, 
                          stack->Parameters.Power.State.DeviceState,
                          PowerDeviceStateName(stack->Parameters.Power.State.DeviceState),
                          stack->Parameters.Power.ShutdownType,
                          PowerShutdownTypeName(stack->Parameters.Power.ShutdownType)));

            PoSetPowerState(DeviceObject,
                            DevicePowerState,
                            stack->Parameters.Power.State);
        }

        status = STATUS_SUCCESS;
        break;

    case IRP_MN_QUERY_POWER:
        status = STATUS_SUCCESS;
        break;

    default:
        status = STATUS_NOT_SUPPORTED;
        break;
    }

    PoStartNextPowerIrp(Irp);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS
XenevtchnDispatchPower(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PXENEVTCHN_DEVICE_EXTENSION pXevtdx = 
        (PXENEVTCHN_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    NTSTATUS status;

    if (pXevtdx->Header.Signature == XENEVTCHN_FDO_SIGNATURE) {
        if (stack->Parameters.Power.Type == SystemPowerState) {
            status = XenevtchnHandleFdoSystemPowerIrp(DeviceObject, Irp);
        } else {
            XM_ASSERT3U(stack->Parameters.Power.Type == SystemPowerState, ==, DevicePowerState);
            status = XenevtchnHandleFdoDevicePowerIrp(DeviceObject, Irp);
        }
    } else {
        status = XenevtchnHandlePdoPowerIrp(DeviceObject, Irp);
    }

    return status;
}
