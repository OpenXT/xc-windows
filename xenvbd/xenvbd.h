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

#ifndef _XENVBD_H_
#define _XENVBD_H_

//#include "miniport.h"
//#include "scsi.h"
#pragma warning(disable:4005)
#include <ntddk.h>
#include <wdm.h>
#include <scsi.h>
#include <ntstatus.h>
#include <stierr.h>
#include <stdlib.h>

typedef LONG NTSTATUS;

#include "xenvbd_ioctl.h"

#include "xsapi.h"
#include "scsiboot.h"

#define XENVBD_VERSION "1.0boot"

/* You have to be careful here to make sure you don't run out of grant
   table slots.  Non-scsifilt operation needs far more, so has a lower
   MAX_DISKS. */
#define XENVBD_MAX_DISKS ((!AustereMode) ? 128 : 32)

#include "blkif.h"

#define DEBUG 0

#if DEBUG
#define DBGMSG(x) TraceVerbose(x)
#else
#define DBGMSG(x)
#endif

#define mb() XsMemoryBarrier()
#define wmb() XsMemoryBarrier()

#define PAGE_SHIFT      12
#define PAGE_SIZE       (1 << PAGE_SHIFT)
#define PAGE_OFFSET     (PAGE_SIZE - 1)
#define PAGE_MASK       ~(PAGE_OFFSET)

#define PHYS_TO_PFN(pa) (((pa).LowPart>>PAGE_SHIFT) | ((pa).HighPart<<(32-PAGE_SHIFT)))

#define SECTOR_SIZE(_target)    ((_target)->sector_size)
#define SECTOR_OFFSET(_target)  (SECTOR_SIZE(_target) - 1)
#define SECTOR_MASK(_target)    ~(SECTOR_OFFSET(_target))

#define NR_SECTORS_PER_PAGE(_target)  (PAGE_SIZE / SECTOR_SIZE(_target))

#define BLK_RING_SIZE __RING_SIZE((blkif_sring_t *)0, PAGE_SIZE)

#define MIN(a, b) ((a)<(b)?(a):(b))
#define MAX(a, b) ((a)>(b)?(a):(b))

struct scsi_inquiry_data;

/* SRB queues.  The _RAW is supposed to be a hint to the callers that
   they need to provide their own synchronisation. */
typedef struct _SRB_QUEUE_RAW {
    PSCSI_REQUEST_BLOCK head, tail;
    ULONG srbs_ever, srbs_cur, srbs_max;
} SRB_QUEUE_RAW, *PSRB_QUEUE_RAW;

typedef struct _FILTER_TARGET {
    struct scsifilt *scsifilt;
    void (*redirect_srb)(struct scsifilt *sf, PSCSI_REQUEST_BLOCK srb);
    SRB_QUEUE_RAW pending_redirect_complete;
    unsigned total_redirected_srbs;
    unsigned outstanding_redirected_srbs;
} FILTER_TARGET, *PFILTER_TARGET;

typedef struct _XHBD_TARGET_INFO {
    struct _XHBD_TARGET_INFO *Next;
    FILTER_TARGET   FilterTarget;
    DOMAIN_ID backendId;
    ULONG targetId;
    CHAR *targetPath;
    PCHAR xenbusNodeName;
    BOOLEAN removable;
    BOOLEAN NeedsWakeWhenBuffersAvail;

    FAST_MUTEX StateLock;
    BOOLEAN Started;
    BOOLEAN Connected;

    // Following group protected by global targets lock
    BOOLEAN Suspended;
    BOOLEAN Resuming;
    BOOLEAN Resumed;
    BOOLEAN EnumPending;
    BOOLEAN Disappeared;
    BOOLEAN Condemned;
    BOOLEAN Ejected;
    BOOLEAN SurpriseRemoved;

    BOOLEAN Paging;
    BOOLEAN Hibernation;
    BOOLEAN DumpFile;
    PDEVICE_OBJECT DeviceObject;
    ULONG References;

    struct SuspendHandler *EarlySuspendHandler;
    struct SuspendHandler *LateSuspendHandler;
    struct xenbus_watch_handler *BackendStateWatch;    

    KSPIN_LOCK EjectLock;
    BOOLEAN EjectRequested;
    BOOLEAN EjectPending;

    USHORT handle;
    BOOLEAN sring_single_page;
    ULONG sring_order;
    GRANT_REF ring_refs[MAX_RING_PAGES];
    blkif_sring_t *sring;
    blkif_front_ring_t ring;
    EVTCHN_PORT evtchn_port;
    ULONG sector_size;
    ULONG info;
    ULONG64 sectors;

    int granted_srbs, bounced_srbs;
    int completed_srbs, aborted_srbs;

    ULONG64 totSrb;

    SRB_QUEUE_RAW FreshSrbs;
    SRB_QUEUE_RAW PreparedSrbs;
    SRB_QUEUE_RAW SubmittedSrbs;
    SRB_QUEUE_RAW ShutdownSrbs;

    struct grant_cache *grant_cache;

    struct scsi_inquiry_data *inq_data;
} XHBD_TARGET_INFO, *PXHBD_TARGET_INFO;

#define _HW_DEVICE_EXTENSION_MAGIC 0x02121995

// This structure is zeroed on allocation by scsiport
#define XENVBD_HOST_TARGET_ID XENVBD_MAX_DISKS
typedef struct _HW_DEVICE_EXTENSION {
    ULONG Magic;

    BOOLEAN resetInProgress;

    LONG MaxRingPageOrder;

    BOOLEAN OverrideVendorId;
    CHAR VendorId[8];
    BOOLEAN OverrideProductId;
    CHAR ProductId[16];
    BOOLEAN OverrideProductRevisionLevel;
    CHAR ProductRevisionLevel[4];

    EVTCHN_DEBUG_CALLBACK DebugCallbackHandle;

    ULONG totInFlight;
    ULONG maxTotInFlight;

    struct irqsafe_lock InvalidateLock;
    BOOLEAN NeedInvalidate;

    struct irqsafe_lock RescanLock;
    BOOLEAN NeedRescan;
} HW_DEVICE_EXTENSION, *PHW_DEVICE_EXTENSION;

#define XENVBD_MAX_REQUESTS_PER_SRB 2
#define XENVBD_MAX_SEGMENTS_PER_REQUEST (BLKIF_MAX_SEGMENTS_PER_REQUEST)
#define XENVBD_MAX_SEGMENTS_PER_SRB (XENVBD_MAX_REQUESTS_PER_SRB * XENVBD_MAX_SEGMENTS_PER_REQUEST)

#define XENVBD_REQUEST_MASK ((1 << XENVBD_MAX_REQUESTS_PER_SRB) - 1)

typedef int BUFFER_ID;

typedef struct xenvbd_request {
    UCHAR           operation;
    USHORT          handle;
    ULONG_PTR       id;
    ULONG64         first_sector;
    ULONG64         last_sector;
    ULONG           nr_segments;
    struct xenvbd_request_segment {
        GRANT_REF   gref;
        ULONG       first_sect;
        ULONG       last_sect;
        BUFFER_ID   bid;
        ULONG       offset;
        ULONG       length;
    } seg[BLKIF_MAX_SEGMENTS_PER_REQUEST];
} xenvbd_request_t;

/* We keep the in-flight SRBs in a list so that we can restart them
   following a resume-from-suspend. */
/* NOTE NOTE NOTE: This must be bigger than the scsifilt srb
   extension, or very bad things happen. */
typedef struct _SRB_EXTENSION {
    PSCSI_REQUEST_BLOCK next;
    PSCSI_REQUEST_BLOCK prev;
    xenvbd_request_t request[XENVBD_MAX_REQUESTS_PER_SRB];
    ULONG nr_requests;
    BOOLEAN bounced;
    PSRB_QUEUE_RAW queued;
} SRB_EXTENSION, *PSRB_EXTENSION;

/* scsifilt extension is currently three pointers */
CASSERT(sizeof(SRB_EXTENSION) >= sizeof(PVOID)*3);

#include "scsiboot.h"

__declspec(inline) PSRB_EXTENSION
SrbExtension(PSCSI_REQUEST_BLOCK srb)
{
    return srb->SrbExtension;
}

NTSTATUS XenvbdStartSrb(PXHBD_TARGET_INFO ptargetInfo,
                        PSCSI_REQUEST_BLOCK srb,
                        PVOID DataBuffer);


VOID XenvbdDebugCallback(PVOID ctxt);

void ReleaseScsiInquiryData(PXHBD_TARGET_INFO ptargetInfo);

VOID XenvbdInquiry(PXHBD_TARGET_INFO ptargetInfo,
                   IN OUT PSCSI_REQUEST_BLOCK srb,
                   PVOID DataBuffer);
NTSTATUS ReadScsiInquiryData(PXHBD_TARGET_INFO ptargetInfo,
                             PCHAR backend_path);

void XenvbdModeSense(PXHBD_TARGET_INFO target, PSCSI_REQUEST_BLOCK srb,
                     PVOID DataBuffer);

PSCSI_REQUEST_BLOCK DequeueSrbRaw(PSRB_QUEUE_RAW queue);
PSCSI_REQUEST_BLOCK PeekSrb(PSRB_QUEUE_RAW queue);
void QueueSrbRaw(PSCSI_REQUEST_BLOCK srb, PSRB_QUEUE_RAW queue);
void QueueSrbAtHeadRaw(PSCSI_REQUEST_BLOCK srb, PSRB_QUEUE_RAW queue);
void RemoveSrbFromQueueRaw(PSCSI_REQUEST_BLOCK srb, PSRB_QUEUE_RAW queue);

void CompleteSrb(PSCSI_REQUEST_BLOCK srb);

VOID XenvbdEvtchnCallback(PVOID Context);
VOID XenvbdStartFastSrb(PSCSI_REQUEST_BLOCK srb,
                        PXHBD_TARGET_INFO ptargetInfo);

NTSTATUS XenvbdFilterSniff(PXHBD_TARGET_INFO ptargetInfo,
                       struct xenvbd_ioctl_sniff *sniff);

extern PHW_DEVICE_EXTENSION XenvbdDeviceExtension;
extern PXHBD_TARGET_INFO *XenvbdTargetInfo;
extern struct irqsafe_lock *XenvbdTargetInfoLock;

extern struct xenbus_watch_handler *device_area_watch;

NTSTATUS PrepareBackendForReconnect(PXHBD_TARGET_INFO ptargetInfo, PCHAR backend_path, SUSPEND_TOKEN token);
VOID CloseFrontend(PXHBD_TARGET_INFO ptargetInfo, PCHAR backend_path, SUSPEND_TOKEN token);

VOID XenbusDestroyTarget(PXHBD_TARGET_INFO TargetInfo);
VOID XenbusUpdateTargetUsage(PXHBD_TARGET_INFO Target);
VOID XenbusEjectTarget(PXHBD_TARGET_INFO TargetInfo);
VOID XenbusDisconnectBackend(PXHBD_TARGET_INFO TargetInfo);

VOID __XenvbdRequestInvalidate(const char *caller);
#define XenvbdRequestInvalidate()   \
        __XenvbdRequestInvalidate(__FUNCTION__)

VOID __XenvbdRequestRescan(const char *caller);
#define XenvbdRequestRescan()   \
        __XenvbdRequestRescan(__FUNCTION__)

extern BOOLEAN XenvbdUnloading;
void MaybeCompleteShutdownSrbs(PXHBD_TARGET_INFO targetInfo);

extern FAST_MUTEX XenvbdEnumLock;

VOID __XenvbdScanTargets(const CHAR *Caller);
#define XenvbdScanTargets() \
        __XenvbdScanTargets(__FUNCTION__)

VOID XenvbdSetupAustereTarget(VOID);

PCHAR find_backend_path(PXHBD_TARGET_INFO ptargetInfo, SUSPEND_TOKEN token);

void XenvbdRedirectSrbThroughScsifilt(PXHBD_TARGET_INFO targetInfo,
                                      PSCSI_REQUEST_BLOCK srb);
void XenvbdFilterPoll(PXHBD_TARGET_INFO targetInfo);
VOID XenvbdTimerFunc(PHW_DEVICE_EXTENSION devExt);

NTSTATUS    XenvbdConnectTarget(
                IN  XHBD_TARGET_INFO    *Target,
                IN  CHAR                *BackendPath,
                IN  SUSPEND_TOKEN       Token
                );

VOID        XenvbdDisconnectTarget(
                IN  XHBD_TARGET_INFO    *Target,
                IN  CHAR                *BackendPath,
                IN  SUSPEND_TOKEN       Token
                );

VOID        SuspendTarget(
                IN  XHBD_TARGET_INFO    *Target
                );

VOID        ResumeTarget(
                IN  XHBD_TARGET_INFO    *Target,
                IN  SUSPEND_TOKEN       Token
                );

VOID        WaitTarget(
                IN  XHBD_TARGET_INFO    *Target
                );

#endif 
