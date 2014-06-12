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

#ifndef SCSIFILT_H__
#define SCSIFILT_H__

#include "../xenvbd/blkif.h"
#include "xenvbd_ioctl.h"

/* The maximum number of pages which we'll accept in a single IRP.
   This should usually be a multiple of 11 (to fit nicely with the
   number of segments in a blkif request) minus 1 (to allow for
   misalignment).  You get a significant real-world win when the
   maximum IRP size reaches 64K (because that's what NT cache manager
   uses).  21 pages gives you a maximum request size of 84KB, which is
   about as conservative as you can get without actually turning
   scsifilt request splitting off.  8 blkif requests per IRP seems
   like a reasonable compromise, which corresponds to 87 pages (or
   348K) per IRP. */
#define MAX_PAGES_PER_REQUEST 87

struct scsifilt_request {
    /* What are we currently doing with the request?  This is kind of
       redundant, in the sense that if you're holding a request you
       know where it came from and hence can infer what state it's in,
       but it allows us to add some useful debugging assertions. */
    enum SfrState state;

    /* When did we copy this request to the ring, according to
     * rdtsc()? */
    ULONG64 submitted_to_backend;
    /* When did we get the request back from the backend, according to
     * rdtsc()? */
    ULONG64 returned_by_backend;

    /* The operation to be performed. */
    uint8_t operation; /* BLKIF_OP_??? */

    /* How many segments are there in this request? */
    uint8_t nr_segments;

    /* The result of the request.  This is only valid once the request
       has been completed by the backend. */
    int16_t result; /* BLKIF_RSP_??? */

    /* Whoever currently owns the request can use this field to thread
       the request onto a list.  When scsifilt first submits it to
       xenvbd, it goes on one of the scheduling lists.  When the
       request gets submitted to the backend, it moves to the live
       list.  When it gets completed, it moves to one of xenvbd's
       temporary pending finished lists.  When the pending finished
       list is processed by scsifilt, it moves to the scsifilt
       pending_completion list. */
    LIST_ENTRY list;

    /* The first disk sector which the request needs to touch. */
    uint64_t start_sector;

    /* A scatter-gather list describing the request.  This is very
       close to the format which the request will have on the shared
       ring, except using physical addresses rather than grant
       references (because we don't want scsifilt to know about grant
       tables). */
    struct {
        PFN_NUMBER pfn;
        GRANT_REF gref;
        uint8_t start_sect;
        uint8_t last_sect;
    } fragments[BLKIF_MAX_SEGMENTS_PER_REQUEST];
};

struct scsifilt_request_internal {
    struct scsifilt_request scsifilt_request;
    PIRP irp;

    /* The number of bytes in *this* scsifilt_request.  This is not
       necessarily the same as the number of bytes in the irp. */
    unsigned byte_count;

    /* Only for bounced requests: */
    PVOID bounce_buffer; /* XmAllocateMemory()ed */
    PVOID mdl_va; /* A mapping of the original buffer which
                     corresponds to this scsifilt_request.  This is
                     the MDL VA offset by the offset of the
                     scsifilt_request in the IRP.  This is a
                     non-owning pointer: we rely on the implicit unmap
                     of the MDL when the IRP completes. */
};

struct scsifilt_schedule {
    LIST_ENTRY cur_sched, next_sched;
    unsigned nr_scheduled;
};

#define SCSIFILT_MAGIC 0x26ce1c95
struct scsifilt {
    unsigned long magic;

    /* Always valid, never changes */
    PDEVICE_OBJECT fdo;

    /* Always valid, never changes */
    PDEVICE_OBJECT pdo;

    /* Protected by the remove lock */
    PDEVICE_OBJECT lower_do;

    /* We don't have proper synchronisation on these.  It doesn't
       matter too much, because they're only used to provide useful
       information in the debug callback. */
    LONG max_outstanding; /* Maximum number of requests outstanding
                             since the last debug dump */
    unsigned nr_requests; /* Total number of scsifilt requests
                             processed since the last debug dump */
    unsigned nr_irps; /* Total number of datapath IRPs processed since
                         the last debug dump. */
    unsigned nr_bounces; /* Total number of scsifilt requests which
                            needed bouncing since the last debug
                            dump. */
    RING_IDX last_notify_prod; /* Shared producer last time we
                                  notified the backend. */
    unsigned nr_sectors_transferred; /* Total number of sectors in all
                                        read and write requests since
                                        the last status dump. */
    unsigned nr_seeks; /* Estimate of the number of disk seeks which
                          we've forced to happen since the last status
                          dump. */
    ULONG64 seek_free_sector_nr; /* Sector which we can read without
                                    an implied seek. */

    /* Timing statistics for SFR processing, measured in whatever
       units rdtsc uses.  These are only used from the debug callback.
       They are running totals for the last @nr_requests requests. */
    ULONG64 arrive2submit; /* Time requests spend queued up waiting to
                              be sent to the backend */
    ULONG64 submit2return; /* Time requests spend waiting for the
                              backend to process them. */
    ULONG64 return2complete; /* Latency between a request being
                                completed by the backend and the
                                completion message getting processed
                                by scsifilt. */

    /* The number of scsifilt requests currently outstanding.  This
       should be modified with interlocked operations.  It is used to
       make sure we wait for outstanding requests to complete in
       response to a SRB_FUNCTION_SHUTDOWN request. */
    LONG cur_outstanding;

    /* Statistics for IRP processing, measured in whatever units rdtsc
       uses.  units rdtsc uses.  These are only used from the debug
       callback.  They are running totals for the last @nr_irps
       requests. */
    ULONG64 arrive2complete; /* Total time spent, between the IRP
                                arriving at scsifilt and
                                IoCompleteRequest() getting called. */

    EVTCHN_DEBUG_CALLBACK debug_cb;

    /* Suspend handlers.  Created very early in the life of the
       instance, and remain valid as long as it does. */
    BOOLEAN suspended;
    struct SuspendHandler *early_suspend_handler;
    struct SuspendHandler *late_suspend_handler;

    /* A remove lock protecting the scsifilt structure.  For datapath
       operations, this is acquired for every IRP rather than for
       every scsifilt_request.  Control path operations have their own
       rules, but are generally once-per-IRP when they need to acquire
       the lock at all. */
    IO_REMOVE_LOCK remove_lock;

    /* A lookaside list used for allocating scsifilt_request_internal
     * structures.  This is protected by the remove_lock: you have to
     * acquire the remove lock before allocating anything from it, and
     * not release the lock until after you've released the allocated
     * request.  We do an IoReleaseRemoveLockAndWait() before
     * releasing this lookaside list. */
    NPAGED_LOOKASIDE_LIST sfri_lookaside_list;

    /* Interface to xenvbd.  Synchronisation here is a bit funny: the
       interface is initialised the first time we get a START_DEVICE
       IRP, and is then protected by the remove lock. */
    BOOLEAN attached;
    ULONG target_id;
    void (*switch_from_filter)(ULONG target_id);
    void (*complete_redirected_srb)(ULONG target_id,
                                    PSCSI_REQUEST_BLOCK srb);
    void (*set_target_info)(ULONG target_id,
                            ULONG info);
    void (*target_start)(ULONG target_id, char *backend_path,
                         SUSPEND_TOKEN token);
    void (*target_stop)(ULONG target_id);
    void (*target_resume)(ULONG target_id, SUSPEND_TOKEN token);
    unsigned sector_size;
    BOOLEAN stopped;

    /* Bits and pieces for handling datapath requests which somehow
       make it past the filter and down to xenvbd.  This is a slow
       path, but is occasionally required for stupid programs like
       e.g. daemon tools. */
    struct irqsafe_lock redirect_lock;
    LIST_ENTRY redirect_srb_list; /* List of SRBs, threaded through
                                   * the srb extension */
    unsigned redirect_srb_list_len;
    LIST_ENTRY redirect_complete_list;
    unsigned redirect_complete_list_len;
    KDPC redirect_srb_dpc;
    unsigned redirect_srbs_outstanding;
    unsigned nr_redirected_srbs_ever;

    /* Protected by the power manager serialisation lock, so can only
       be accessed from the power IRP handler before
       PoStartNextPowerIrp() is called. */
    DEVICE_POWER_STATE current_power_state;
    POWER_ACTION shutdown_type;
    PIRP pending_power_up_irp;
    PIRP pending_power_irp;

    KSPIN_LOCK wakeup_lock;
    BOOLEAN need_wakeup;
    BOOLEAN wakeup_pending;

    /* Request replay stuff.  This is used for both hibernation and
       migration.  Entries on this list need to be re-issued as soon
       as we've reconnected to the backend.  They may or may not be
       granted; if they are granted, the grants need to be torn down
       and reconstructed. */
    KSPIN_LOCK request_replay_lock; /* Leaf lock */
    LIST_ENTRY requests_needing_replay;
    unsigned nr_replay_outstanding;


    /* Protected by the remove lock. */
    struct xm_thread *restart_thread;
    struct grant_cache *grant_cache;


    /* This may be NULL if the attach failed, or before the attach
     * completes.  Non-NULL to NULL transitions are protected by the
     * remove lock.  Note that this a pointer to part of the xenvbd
     * target structure, so it becomes invalid as soon as you detach
     * from xenvbd. */
    char *frontend_path;


    /* Non-NULL to NULL transitions of the shared ring pointer are
     * protected by the remove lock.  The actual contents of the ring
     * are protected by the ring lock. */
    blkif_sring_t *ring_shared;
    blkif_front_ring_t ring;

    /* A schedule of pending requests, in some suitable order.  The
     * requests in the schedule are all in state SfrStateQueued.
     * Protected by the ring lock. */
    struct scsifilt_schedule schedule;

    /* A list of all requests which are currently on the shared ring.
     * Such requests are in state SfrStateSubmitted.  Protected by the
     * ring lock. */
    /* Note that this is incorrect following hibernation and
     * migration, because the requests might have been submitted to
     * the wrong ring.  In that case, we have to rewind and
     * resubmit. */
    LIST_ENTRY inflight_requests;
    unsigned nr_inflight;

    /* A lock to protect the shared ring and related structures. */
    KSPIN_LOCK ring_lock;

    /* A DPC which is triggered to handel ring work.  This is only
     * accessed from the event channel handler, so doesn't need to be
     * synchronized. */
    KDPC dpc;

    /* The backend ``handle'' to use in requests.  Set at attach time
     * and then never changes. */
    uint16_t handle;

    /* If this is non-zero, we can't send stuff to the ring, and
     * should instead leave it languishing in the schedule.  Protected
     * by the ring lock.  The schedule will be restarted if it goes
     * from 1 -> 0. */
    ULONG pause_count;

    char *backend_path;

    /* Ignoring the very end of device shutdown, these are only
       touched by the suspend handlers and the power handlers.  They
       are effectively protected by the suspend lock.  The power
       handlers are synchronised by power management, and they
       allocate suspend tokens whenever they touch them, so you don't
       have to worry about power racing with suspend. */
    BOOLEAN single_page;
    ULONG ring_order;
    GRANT_REF ring_gref[MAX_RING_PAGES];
    EVTCHN_PORT evtchn_port;

    /* The remote domain which is allowed to access evtchn_port and
       ring_gref.  This is set to null_DOMAIN_ID() if they need to be
       rebuilt e.g. due to a hibernation or migration.  Same
       synchronisation scheme as those fields. */
    DOMAIN_ID backend_domid;
};

/* An overlay for the DriverContext member of an IRP tail which is
   used to hold all of our per-IRP data. */
struct scsifilt_irp_overlay {
    /* When was this IRP obtained from Windows, according to rdtsc?
       Used to maintain timing statistics, and for nothing else. */
    ULONG64 obtained_from_windows;
    /* How many scsifilt_requests are outstanding for this IRP?  We
       access this lock-free and non-interlocked, because we know
       that, once the IRP has been submitted it's only touched from
       our DPC, which is only run on one CPU at a time. */
    ULONG nr_outstanding;
};

CASSERT(sizeof(struct scsifilt_irp_overlay) <= RTL_FIELD_SIZE(IRP, Tail.Overlay.DriverContext));

#define BYTES_TO_PAGES_ROUND_UP(x) (((x) + PAGE_SIZE - 1) / PAGE_SIZE)

#define MIN(x, y) ((x) < (y) ? (x) : (y))

void finish_requests(struct scsifilt *sf, PLIST_ENTRY requests);
NTSTATUS filter_process_irp(struct scsifilt *sf, PIRP irp,
                            PSCSI_REQUEST_BLOCK srb);
void filter_wait_for_idle(struct scsifilt *sf);
NTSTATUS complete_irp(PIRP irp, NTSTATUS status);
NTSTATUS ignore_irp(struct scsifilt *sf, PIRP irp,
                    NTSTATUS (*call_driver)(PDEVICE_OBJECT dev, PIRP irp));
void completion_dpc(PKDPC dpc, PVOID ctxt, PVOID ignore1, PVOID ignore2);

NTSTATUS connect_scsifilt(struct scsifilt *sf);
void failed_eject(struct scsifilt *sf);
void schedule_requests(struct scsifilt *sf, PLIST_ENTRY requests);
void handle_evtchn(void *ctxt);
void handle_dpc(PKDPC dpc, void *ctxt, void *ignore1, void *ignore2);

struct scsifilt_request *get_next_request(struct scsifilt_schedule *sched);
void enqueue_request(struct scsifilt_schedule *sched,
                     struct scsifilt_request *sf);
void initialise_schedule(struct scsifilt_schedule *schedule);

NTSTATUS initialise_xenvbd_bits(struct scsifilt *sf);
void cleanup_xenvbd_bits(struct scsifilt *sf);
void close_scsifilt(struct scsifilt *sf);
void pause_datapath(struct scsifilt *sf);
void unpause_datapath(struct scsifilt *sf);
void datapath_notice_dehibernated(struct scsifilt *sf);
void replay_pending_requests(struct scsifilt *sf);
void abort_pending_requests(struct scsifilt *sf);

NTSTATUS filter_process_capacity_irp(struct scsifilt *sf, PIRP irp,
                                     PSCSI_REQUEST_BLOCK srb);
NTSTATUS filter_process_capacity_ex_irp(struct scsifilt *sf, PIRP irp,
                                        PSCSI_REQUEST_BLOCK srb);
void *map_srb_data_buffer(PSCSI_REQUEST_BLOCK srb, PMDL mdl,
                          MM_PAGE_PRIORITY prio);

NTSTATUS handle_power(PDEVICE_OBJECT fdo, PIRP irp);
void handle_power_passive(struct scsifilt *sf, PIRP irp);
void finish_power_up_irp(struct scsifilt *sf, PIRP irp);
struct scsifilt *get_scsifilt(PDEVICE_OBJECT fdo);
void init_redirection(struct scsifilt *sf);
void redirect_srb(struct scsifilt *sf, PSCSI_REQUEST_BLOCK srb);
void complete_redirected_srbs(struct scsifilt *sf);
void wakeup_scsiport(struct scsifilt *sf, const char *who);

#endif /* !SCSIFILT_H__ */
