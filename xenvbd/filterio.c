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

#pragma warning(push, 3)
#include "xenvbd.h"
#include "xsapi.h"
#include "scsiboot.h"
#include "xenvbd_ioctl.h"
#pragma warning(pop)

static void
XenvbdSwitchToFilter(ULONG target_id,
                     struct scsifilt *sf,
                     void (*redirect_srb)(struct scsifilt *sf,
                                          PSCSI_REQUEST_BLOCK srb))
{
    PXHBD_TARGET_INFO targetInfo;
    PFILTER_TARGET filter;
    KIRQL irql;

    TraceNotice(("target %d: %s\n", target_id, __FUNCTION__));

    irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    targetInfo = XenvbdTargetInfo[target_id];
    XM_ASSERT(targetInfo != NULL);

    filter = &targetInfo->FilterTarget;
    filter->scsifilt = sf;
    filter->redirect_srb = redirect_srb;

    release_irqsafe_lock(XenvbdTargetInfoLock, irql);
}

static void
XenvbdSwitchFromFilter(ULONG target_id)
{
    PXHBD_TARGET_INFO targetInfo;
    PFILTER_TARGET filter;
    KIRQL irql;

    TraceNotice(("target %d: %s\n", target_id, __FUNCTION__));

    irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    targetInfo = XenvbdTargetInfo[target_id];
    XM_ASSERT(targetInfo != NULL);

    filter = &targetInfo->FilterTarget;
    filter->scsifilt = NULL;

    release_irqsafe_lock(XenvbdTargetInfoLock, irql);
}

static void
XenvbdSetTargetInfo(ULONG target_id,
                    ULONG info)
{
    PXHBD_TARGET_INFO targetInfo;
    KIRQL irql;

    TraceNotice(("target %d: %s\n", target_id, __FUNCTION__));

    irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    targetInfo = XenvbdTargetInfo[target_id];
    XM_ASSERT(targetInfo != NULL);

    targetInfo->info = info;

    release_irqsafe_lock(XenvbdTargetInfoLock, irql);
}

static VOID
XenvbdTargetStart(ULONG target_id, char *backend_path, SUSPEND_TOKEN token)
{
    PXHBD_TARGET_INFO targetInfo;
    KIRQL irql;
    NTSTATUS status;

    TraceNotice(("target %d: %s\n", target_id, __FUNCTION__));

    irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    targetInfo = XenvbdTargetInfo[target_id];
    XM_ASSERT(targetInfo != NULL);

    targetInfo->References++;
    release_irqsafe_lock(XenvbdTargetInfoLock, irql);

    XM_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    ExAcquireFastMutex(&targetInfo->StateLock);

    XM_ASSERT(!targetInfo->Started);

    status = PrepareBackendForReconnect(targetInfo, backend_path, token);
    if (!NT_SUCCESS(status))
        goto fail1;

    targetInfo->Started = TRUE;

    ExReleaseFastMutex(&targetInfo->StateLock);

    irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    XM_ASSERT(targetInfo->References != 0);
    targetInfo->References--;
    release_irqsafe_lock(XenvbdTargetInfoLock, irql);

    return;

fail1:
    TraceError(("%s: fail1 (0x%08x)\n", __FUNCTION__, status));

    ExReleaseFastMutex(&targetInfo->StateLock);

    irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    XM_ASSERT(targetInfo->References != 0);
    targetInfo->References--;
    release_irqsafe_lock(XenvbdTargetInfoLock, irql);
}

static VOID
XenvbdTargetStop(ULONG target_id)
{
    PXHBD_TARGET_INFO targetInfo;
    KIRQL irql;

    TraceNotice(("target %d: %s\n", target_id, __FUNCTION__));

    irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    targetInfo = XenvbdTargetInfo[target_id];
    XM_ASSERT(targetInfo != NULL);
    
    targetInfo->References++;
    release_irqsafe_lock(XenvbdTargetInfoLock, irql);

    XM_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    ExAcquireFastMutex(&targetInfo->StateLock);
    targetInfo->Started = FALSE;
    ExReleaseFastMutex(&targetInfo->StateLock);

    irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    XM_ASSERT(targetInfo->References != 0);
    targetInfo->References--;
    release_irqsafe_lock(XenvbdTargetInfoLock, irql);
}

static VOID
XenvbdTargetResume(ULONG target_id, SUSPEND_TOKEN token)
{
    PXHBD_TARGET_INFO targetInfo;
    KIRQL irql;

    TraceNotice(("target %d: %s\n", target_id, __FUNCTION__));

    irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    targetInfo = XenvbdTargetInfo[target_id];
    XM_ASSERT(targetInfo != NULL);
    targetInfo->References++;

    if (targetInfo->Suspended) {
        targetInfo->Suspended = FALSE;
        targetInfo->Resuming = TRUE;
        release_irqsafe_lock(XenvbdTargetInfoLock, irql);

        ResumeTarget(targetInfo, token);
    } else {
        release_irqsafe_lock(XenvbdTargetInfoLock, irql);

        WaitTarget(targetInfo);
    }

    irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    XM_ASSERT(targetInfo->References != 0);
    targetInfo->References--;
    release_irqsafe_lock(XenvbdTargetInfoLock, irql);

}

static VOID
XenvbdCompleteRedirectedSrb(ULONG target_id,
                            PSCSI_REQUEST_BLOCK srb)
{
    PXHBD_TARGET_INFO targetInfo;
    PFILTER_TARGET filter;
    KIRQL irql;

    TraceNotice(("target %d: %s\n", target_id, __FUNCTION__));

    irql = acquire_irqsafe_lock(XenvbdTargetInfoLock);
    targetInfo = XenvbdTargetInfo[target_id];
    XM_ASSERT(targetInfo != NULL);

    filter = &targetInfo->FilterTarget;
    QueueSrbRaw(srb, &filter->pending_redirect_complete);
    XM_ASSERT(filter->outstanding_redirected_srbs != 0);

    release_irqsafe_lock(XenvbdTargetInfoLock, irql);
    /* Let the polling timer complete it later. */
}

NTSTATUS
XenvbdFilterSniff(PXHBD_TARGET_INFO targetInfo,
                  struct xenvbd_ioctl_sniff *sniff)
{
    if (!targetInfo->Started)
        return STATUS_UNSUCCESSFUL;

    sniff->header.ReturnCode = STATUS_SUCCESS;
    sniff->version = XENVBD_IOCTL_SNIFF_VERSION;
    sniff->target_id = targetInfo->targetId;

    sniff->switch_to_filter = XenvbdSwitchToFilter;
    sniff->switch_from_filter = XenvbdSwitchFromFilter;
    sniff->complete_redirected_srb = XenvbdCompleteRedirectedSrb;
    sniff->set_target_info = XenvbdSetTargetInfo;
    sniff->target_start = XenvbdTargetStart;
    sniff->target_stop = XenvbdTargetStop;
    sniff->target_resume = XenvbdTargetResume;

    sniff->frontend_path = targetInfo->xenbusNodeName;

    return STATUS_SUCCESS;
}

static void
XenvbdFilterRequestPoll(VOID)
{
    ScsiPortNotification(RequestTimerCall,
                         XenvbdDeviceExtension,
                         XenvbdTimerFunc,
                         10000);
}

void
XenvbdFilterPoll(PXHBD_TARGET_INFO targetInfo)
{
    PFILTER_TARGET filter = &targetInfo->FilterTarget;
    PSCSI_REQUEST_BLOCK srb;

    while ((srb = DequeueSrbRaw(&filter->pending_redirect_complete)) != NULL) {
        CompleteSrb(srb);
        filter->outstanding_redirected_srbs--;
    }
    /* Poll until scsifilt gives us the request back.  This is a slow
       path anyway, and forcing an ioctl through is just far too
       painful. */
    if (filter->outstanding_redirected_srbs != 0)
        XenvbdFilterRequestPoll();
}

void
XenvbdRedirectSrbThroughScsifilt(PXHBD_TARGET_INFO targetInfo,
                                 PSCSI_REQUEST_BLOCK srb)
{
    PFILTER_TARGET filter = &targetInfo->FilterTarget;

    filter->total_redirected_srbs++;
    filter->outstanding_redirected_srbs++;
    targetInfo->FilterTarget.redirect_srb(targetInfo->FilterTarget.scsifilt,
                                          srb);
    if (filter->outstanding_redirected_srbs == 1)
        XenvbdFilterRequestPoll();
}
