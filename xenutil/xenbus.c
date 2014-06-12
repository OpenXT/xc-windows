/*
 * Copyright (c) 2013 Citrix Systems, Inc.
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

#define XSAPI_FUTURE_GRANT_MAP
#define XSAPI_LEGACY_WRITE_STATE
#define XSAPI_LEGACY_READ_INTEGER
#include "ntddk.h"
#include "xsapi.h"
#include "xsapi-future.h"
#include "xenbus.h"
#include "scsiboot.h"
#include "evtchn.h"
#include "gntmap.h"

#include <hvm_params.h>
#include <memory.h>
#include <xs_wire.h>
#include <xen.h>

#include "../xenutil/hvm.h"
#include "../xenutil/xenutl.h"

/* We implement a legacy API */
#include "xsapi-legacy.h"

struct xenbus_sg_segment {
    struct xenbus_sg_segment *next;
    const void *data;
    size_t len;
};

struct xenbus_pending_req {
    struct xenbus_pending_req *next, *prev;

    /* TX information */
    const struct xenbus_sg_segment *tx_io; /* Covers both the header
                                              and the payload. */
    const struct xenbus_sg_segment *next_tx_seg; /* First segment in
                                                    tx_io list which
                                                    hasn't been
                                                    completed. */
    unsigned tx_sg_off; /* How many bytes of next_tx_seg have been
                           transmitted already? */

    struct xsd_sockmsg reply_header;
    void *reply_payload;
    size_t reply_buf_size;
    size_t reply_payload_received; /* This *includes* stuff received
                                      from xenstore and then discarded
                                      due to lack of buffer space */

    BOOLEAN xenbus_replied; /* Set if the reply is finished and ready
                               to be used. */
    KEVENT completion_event;

    LONG id;
};

#define XENBUS_TRANSACTION_MAGIC 0xed8a0cd0

struct xenbus_transaction {
    struct xenbus_transaction *next, *prev;
    const char *caller;
    PKTHREAD thread;
    ULONG magic;
    NTSTATUS status;
    unsigned trans_id;
};

struct xenbus_watch_handler {
    struct xenbus_watch_handler *next, *prev;
    char *path;
    char token[17];

    BOOLEAN faulty; /* We tried to re-register this following
                       suspend/resume and failed.  Don't try to
                       register it again. */

    BOOLEAN needs_s3_recover; /* Needs to be unregistered and then
                                 registered again. */

    BOOLEAN currently_registered; /* Watch is currently registered
                                     with xenstore.  Protected by the
                                     watch lock. */

    int refcount;
    KEVENT safe_to_release;

    LARGE_INTEGER cb_start;
    const char *cb_name;
    void (*cb)(void *ctxt);
    void *ctxt;

    /* List of watches which have been fired by xenstored but not yet
       picked up by the watch thread.  Protected by the watch_lock.
       Getting put on this list counts as a reference from the point
       of view of the refcount. */
    LIST_ENTRY pending_list;
    BOOLEAN queued;
};

static void xenbus_dpc_func(PKDPC dpc, void *ignore1, void *ignore2,
                            void *ignore3);
static void reregister_all_watches(void);

/* List of all xenbus requests.  Protected by the ring lock. */
static struct xenbus_pending_req *
head_pending_xenbus_req, *
tail_pending_xenbus_req;
/* The request which we're currently receiving.  Protected by the ring
   lock. */
static struct xenbus_pending_req *
current_rx_req;
/* The request which we're currently transmitting.  Protected by the
   ring lock. */
static struct xenbus_pending_req *
current_tx_req;

/* We need to read and discard this many bytes from the incoming
   response ring to regain ring synchronisation. */
static unsigned
cons_response_discard_bytes;

/* List of open transactions.  Protected by the transaction lock. */
static struct xenbus_transaction *
head_open_transaction;
static KSPIN_LOCK
transaction_lock;

/* The buffer shared with xenstore.  Our bits are protected by the
   ring lock. */
static struct xenstore_domain_interface *
shared_buf;
static struct xenstore_domain_interface *
old_shared_buf;
EVTCHN_PORT
xenbus_evtchn;

static volatile LONG
xenbus_ring_lock;

static KSPIN_LOCK
watch_lock; /* Leaf lock. Nests inside the ring lock. */

/* The watch handler which the watch thread is currently dealing with.
   This is only ever used from the debug callback. */
static struct xenbus_watch_handler *
current_watch_handler;
static struct irqsafe_lock
current_watch_handler_lock; /* Leaf lock.  Acquired from the debug
                               handler. */

static EVTCHN_DEBUG_CALLBACK
xenbus_debug_callback;

/* List of watch_handlers threaded on pending_list. */
static LIST_ENTRY
pending_watches_list;
static struct xenbus_watch_handler *
head_watch_handler;
static struct xm_thread *
watch_thread;

/* Insertion is protected by xenbus_dpc_lock. */
static KDPC
xenbus_dpc;
static struct irqsafe_lock
xenbus_dpc_lock;

/* Variables used to keep the xenbus driver from becoming divergent.
 * MTC: This code is needed for Marathon Technologies' Lockstep Feature.
 */
static KSPIN_LOCK
xenbus_operation_lock;
static volatile LONG 
xenbus_outstanding_ctr = 0;
static volatile BOOLEAN 
allow_new_xenbus_operation = TRUE;
static volatile BOOLEAN 
allow_xenbus_watch_operation = TRUE;

struct xsd_errors
{
    int errnum;
    const char *errstring;
};
#define XSD_ERROR(e, s) { e, #s }
static const struct xsd_errors xsd_errors[] = {
    XSD_ERROR(STATUS_INVALID_PARAMETER, EINVAL),
    XSD_ERROR(STATUS_ACCESS_DENIED, EACCES),
    XSD_ERROR(STATUS_OBJECT_NAME_EXISTS, EEXIST),
    XSD_ERROR(STATUS_FILE_IS_A_DIRECTORY, EISDIR),
    XSD_ERROR(STATUS_OBJECT_NAME_NOT_FOUND, ENOENT),
    XSD_ERROR(STATUS_NO_MEMORY, ENOMEM),
    XSD_ERROR(STATUS_DISK_FULL, ENOSPC),
    XSD_ERROR(STATUS_DATA_ERROR, EIO),
    XSD_ERROR(STATUS_DIRECTORY_NOT_EMPTY, ENOTEMPTY),
    XSD_ERROR(STATUS_INVALID_SYSTEM_SERVICE, ENOSYS),
    XSD_ERROR(STATUS_INTERNAL_ERROR, EROFS), /* XXX */
    XSD_ERROR(STATUS_DEVICE_BUSY, EBUSY),
    XSD_ERROR(STATUS_RETRY, EAGAIN),
    XSD_ERROR(STATUS_CONNECTION_ACTIVE, EISCONN),
    XSD_ERROR(STATUS_DISK_FULL, E2BIG), /* XXX */
    {0, NULL}
};
#undef XSD_ERROR
static NTSTATUS
get_error(const char *msg)
{
    unsigned int i;

    for (i = 0; xsd_errors[i].errstring; i++) {
        if (!strcmp(msg, xsd_errors[i].errstring))
            return xsd_errors[i].errnum;
    }
    TraceWarning (("xen store gave: unknown error %s\n", msg));
    return STATUS_INTERNAL_ERROR;
}

static struct xenbus_transaction *
unwrap_xenbus_transaction_t(xenbus_transaction_t _xbt)
{
    struct xenbus_transaction *xbt;

    XM_ASSERT(!is_nil_xenbus_transaction_t(_xbt));
    XM_ASSERT(!is_null_xenbus_transaction_t(_xbt));
    xbt = __unwrap_xenbus_transaction_t(_xbt);
    XM_ASSERT(xbt->magic == XENBUS_TRANSACTION_MAGIC);
    return xbt;
}

/* Acquire the ring lock.  This is safe to call with interrupts
   disabled (i.e. at device IRQL), but not from within an interrupt
   handler. */
static BOOLEAN
__acquire_ring_lock(const char *caller, KIRQL *irql)
{
    KIRQL current_irql;

    if (AustereMode)
        return FALSE;

    current_irql = KeGetCurrentIrql();
    if (current_irql > DISPATCH_LEVEL) {
        TraceWarning(("%s: skipping xenbus ring lock (IRQL == %02x)\n", caller, current_irql));
        return FALSE;
    }

    KeRaiseIrql(DISPATCH_LEVEL, irql);
    while (InterlockedCompareExchange(&xenbus_ring_lock, 1, 0) != 0)
        _mm_pause();

    return TRUE;
}

#define acquire_ring_lock(_irql) \
        __acquire_ring_lock(__FUNCTION__, (_irql))

static BOOLEAN
try_acquire_ring_lock(KIRQL *irql)
{
    KIRQL current_irql;

    current_irql = KeGetCurrentIrql();
    if (current_irql <= DISPATCH_LEVEL)
        KeRaiseIrql(DISPATCH_LEVEL, irql);
    else
        *irql = current_irql;

    return (InterlockedCompareExchange(&xenbus_ring_lock, 1, 0) == 0) ? TRUE : FALSE;
}

static void
release_ring_lock(KIRQL irql)
{
    XM_ASSERT3U(xenbus_ring_lock, ==, 1);

    (VOID) InterlockedExchange(&xenbus_ring_lock, 0);         
    KeLowerIrql(irql);
}

/* You're not allowed to acquire spin locks from austere mode.
 * Fortunately for us, austere mode is uniprocessor, so it's okay. */
static void
acquire_lock_safe(KSPIN_LOCK *lock, KIRQL *irql)
{
    if (AustereMode)
        return;

    KeAcquireSpinLock(lock, irql);
}
static void
release_lock_safe(KSPIN_LOCK *lock, KIRQL irql)
{
    if (AustereMode)
        return;

     KeReleaseSpinLock(lock, irql);
}

/* Mark a transaction as failed with status @status.  No-op on null
   and nil transactions. */
void
xenbus_fail_transaction(xenbus_transaction_t xbt, NTSTATUS status)
{
    if (!is_null_xenbus_transaction_t(xbt) &&
        !is_nil_xenbus_transaction_t(xbt))
        InterlockedCompareExchange(&unwrap_xenbus_transaction_t(xbt)->status,
                                   status,
                                   STATUS_SUCCESS);
}

/* Get the current status of a transaction, which may be nil or
 * null. */
static NTSTATUS
transaction_status(xenbus_transaction_t xbt)
{
    if (is_nil_xenbus_transaction_t(xbt))
        return STATUS_SUCCESS;
    if (is_null_xenbus_transaction_t(xbt))
        return STATUS_INSUFFICIENT_RESOURCES;
    return unwrap_xenbus_transaction_t(xbt)->status;
}

/* Copy @size bytes from @Src to offset @idx in the circular buffer
   @Ring of size @ring_size.  @idx should be less than @ring_size. */
static void memcpy_to_ring(void *Ring,
                           const void *Src,
                           size_t size,
                           unsigned idx,
                           size_t ring_size)
{
    size_t c1, c2;
    char *ring = Ring;
    const char *src = Src;

    XM_ASSERT(idx < ring_size);
    XM_ASSERT(size <= ring_size);

    c1 = min(size, ring_size - idx);
    c2 = size - c1;
    memcpy(ring + idx, src, c1);
    memcpy(ring, src + c1, c2);
}

/* Copy @size bytes from offset @idx in ring buffer @Ring of size
   @ring_size to @Dest. */
static void memcpy_from_ring(const void *Ring,
                             void *Dest,
                             size_t size,
                             unsigned idx,
                             size_t ring_size)
{
    size_t c1, c2;
    const char *ring = Ring;
    char *dest = Dest;

    XM_ASSERT(size <= ring_size);
    XM_ASSERT(idx < ring_size);

    c1 = min(size, ring_size - idx);
    c2 = size - c1;
    memcpy(dest, ring + idx, c1);
    memcpy(dest + c1, ring, c2);
}

/* Map from a xenbus_transaction_t to the transaction identifier used
   to talk to xenbus. */
static uint32_t
get_transaction_id(xenbus_transaction_t xbt)
{
    XM_ASSERT(!is_null_xenbus_transaction_t(xbt));
    if (is_nil_xenbus_transaction_t(xbt))
        return 0;
    else
        return unwrap_xenbus_transaction_t(xbt)->trans_id;
}

/* Initialise an sg list for later transmission.  Sets up the header
   at the same time.  The varargs list is a list of (base, length)
   pairs, where base is a const void * and length is a size_t.  The
   list is terminated by (NULL, (size_t)0).  @sg should be the start
   of an array of pre-allocated sg segment structures.  It is the
   caller's responsibility to ensure that this array contains enough
   items. */
static void
initialise_sg_list(enum xsd_sockmsg_type type,
                   xenbus_transaction_t xbt,
                   struct xenbus_sg_segment *sg,
                   struct xsd_sockmsg *msg,
                   size_t msg_size,
                   ...)
{
    static LONG sequence_number;
    va_list args;
    void *data;
    size_t data_len;
    size_t len_acc = 0;

    msg->type = type;
    /* XXX: We assume that you never have enough requests outstanding
       at once for the 32 bit sequence numbers to wrap and cause
       problems.  This seems fairly safe. */
    msg->req_id = InterlockedIncrement(&sequence_number);
    if (msg->req_id == 0)
        TraceVerbose(("Xenbus request IDs just wrapped.\n"));
    msg->tx_id = get_transaction_id(xbt);

    XM_ASSERT(msg_size == sizeof(*msg));
    sg->next = NULL;
    sg->data = msg;
    sg->len = msg_size;
    va_start(args, msg_size);
    while (1) {
        data = va_arg(args, void *);
        if (!data)
            break;
        data_len = va_arg(args, size_t);
        sg->next = sg+1;
        sg = sg->next;
        sg->data = data;
        sg->len = data_len;
        sg->next = NULL;
        len_acc += data_len;
    }
    va_end(args);
    msg->len = (uint32_t)len_acc;
}

/* Initialise the pending request @req using the header @hdr and sg
   segment list @io, which will probably have been provided by
   initialise_sg_list(). */
static void
initialise_pending_req(struct xenbus_pending_req *req,
                       struct xsd_sockmsg *hdr,
                       struct xenbus_sg_segment *io)
{
    memset(req, 0, sizeof(*req));
    req->tx_io = io;
    req->next_tx_seg = io;
    req->id = hdr->req_id;
    KeInitializeEvent(&req->completion_event, NotificationEvent, FALSE);
}

/* Pre-set a reply buffer in a pending request.  By default, the reply
   buffer is allocated when needed; this can be used if you can't risk
   running out of memory at the wrong time.  The buffer must be large
   enough to receive any xenbus error message; 12 bytes at present. */
static void
set_reply_buffer(struct xenbus_pending_req *req, void *buf,
                 size_t size)
{
    XM_ASSERT(size >= 12);
    memset(buf, 0, size);
    req->reply_payload = buf;
    req->reply_buf_size = size;
}

/* Find the pending request with id @id.  Returns either the request
   or NULL on error.  Should be called under the ring lock. */
static struct xenbus_pending_req *
find_pending_rx_req(int id)
{
    struct xenbus_pending_req *xpr;

    for (xpr = head_pending_xenbus_req; xpr; xpr = xpr->next)
        if (xpr->id == id)
            return xpr;
    return NULL;
}

/* This function is to be called at the start of any xenbus operation.
 * It is meant to allow or reject the operation based on whether the
 * xenbus driver is allowed to take on new requests.
 * MTC: This code is needed for Marathon Technologies' Lockstep Feature.
 */
static NTSTATUS
start_operation(void)
{
    KIRQL irql;
    NTSTATUS status;
    
    acquire_lock_safe(&xenbus_operation_lock, &irql);

    /* Counter is incremented so that we know how many outstanding 
     * requests there are and that need to be finished before this 
     * driver can become "turned off"
     */
    if (allow_new_xenbus_operation) {
        xenbus_outstanding_ctr++;
        status = STATUS_SUCCESS;
    } else {
        status = STATUS_DEVICE_NOT_READY;
    }
    
    release_lock_safe(&xenbus_operation_lock, irql);
    return status;
}

/* Take a pre-initialised pending request structure @req and put it on
   the queue for transmission to the xenbus daemon, kicking off the
   DPC if appropriate. */
static NTSTATUS
submit_request(struct xenbus_pending_req *req)
{
    BOOLEAN locked;
    KIRQL irql;
    NTSTATUS status;
    
    status = start_operation();
    if (!NT_SUCCESS(status))
        return status;

    locked = acquire_ring_lock(&irql);

    req->prev = tail_pending_xenbus_req;
    req->next = NULL;
    if (tail_pending_xenbus_req)
        tail_pending_xenbus_req->next = req;
    else
        head_pending_xenbus_req = req;
    tail_pending_xenbus_req = req;
    if (!current_tx_req)
        current_tx_req = req;
    if (!is_null_EVTCHN_PORT(xenbus_evtchn))
        EvtchnRaiseLocally(xenbus_evtchn);

    if (locked)
        release_ring_lock(irql);

    return status;
}

/* Simply decrements the counter of oustanding operations.
 * MTC: This code is needed for Marathon Technologies' Lockstep Feature.
 */
static void
end_operation()
{
    KIRQL irql;
    acquire_lock_safe(&xenbus_operation_lock, &irql);
    xenbus_outstanding_ctr--;
    release_lock_safe(&xenbus_operation_lock, irql);
}

/* Wait for @req to be completed by xenbus, and return the results.
   The caller is still responsible for releasing the reply buffer.
   The reply buffer should be released even if an error is
   reported. */
/* This is really quite icky.

   -- First, DPCs don't work in austere mode.  We work around this by
   just calling the dpc function directly.

   -- Second, we sometimes end up hitting xenbus at raised irql.  This
   is actually really hard to avoid when coming back from hibernation,
   because the disk has to connect up while Windows is holding locks,
   and it's too early for work items and so forth.  If we try to
   access xenbus at raised irql, we pretend we're in austere mode.

   -- Third, we sometimes need to access xenbus before the interrupt
   is hooked up.  In that case, we back off 10ms and manually queue
   the DPC.
*/
/* This is where the bodies are buried. */
static NTSTATUS
get_request_results(struct xenbus_pending_req *req,
                    const char *who_am_i, const char *path)
{
    NTSTATUS res;
    LARGE_INTEGER t;
    BOOLEAN locked;
    KIRQL irql;
    int cntr = 0;

    t.QuadPart = -100000; /* 10ms */
    if (!AustereMode && KeGetCurrentIrql() < DISPATCH_LEVEL) {
        KeWaitForSingleObject(&req->completion_event,
                              Executive,
                              KernelMode,
                              FALSE,
                              &t);
    }
    while (!req->xenbus_replied) {
        if (AustereMode || KeGetCurrentIrql() >= DISPATCH_LEVEL) {
            xenbus_dpc_func(NULL, NULL, NULL, NULL);
        } else {
            irql = acquire_irqsafe_lock(&xenbus_dpc_lock);
            KeInsertQueueDpc(&xenbus_dpc, NULL, NULL);
            release_irqsafe_lock(&xenbus_dpc_lock, irql);
        }
        if (!AustereMode && KeGetCurrentIrql() < DISPATCH_LEVEL) {
            KeWaitForSingleObject(&req->completion_event,
                                  Executive,
                                  KernelMode,
                                  FALSE,
                                  &t);
            cntr++;
            if (cntr % 100 == 0)
                TraceNotice(("Waited %dms for xenstored to reply (%s, %s).\n",
                             cntr * 10,
                             who_am_i ? who_am_i : "<nobody>",
                             path ? path : "<nowhere>"));
        }
    }
    if (req->reply_header.type == XS_ERROR) {
        if (req->reply_payload)
            res = get_error(req->reply_payload);
        else
            res = STATUS_INSUFFICIENT_RESOURCES;
    } else {
        res = STATUS_SUCCESS;
    }

    /* Unhook from the pending list */
    locked = acquire_ring_lock(&irql);

    if (req->prev)
        req->prev->next = req->next;
    else
        head_pending_xenbus_req = req->next;
    if (req->next)
        req->next->prev = req->prev;
    else
        tail_pending_xenbus_req = req->prev;
    XM_ASSERT(current_tx_req != req);
    XM_ASSERT(current_rx_req != req);

    if (locked)
        release_ring_lock(irql);

    end_operation();

    return res;
}

/* Send a request to xenbus and wait for the result.  The result is
   returned.  The caller is responsible for releasing the reply
   buffer. */
/* We actually delegate most of the hard work to the DPC. */
static NTSTATUS
submit_request_and_await_result(struct xenbus_pending_req *req,
                                const char *who_am_i, const char *path)
{
    NTSTATUS    status;

    if (XenPVFeatureEnabled(DEBUG_NO_PARAVIRT))
        return STATUS_UNSUCCESSFUL;

    status = submit_request(req);
    if (NT_SUCCESS(status))
        status = get_request_results(req, who_am_i, path);

    return status;
}

/* Funnel data from @req onto the TX ring.  Returns TRUE if we made
   any progress and FALSE otherwise.  Should be called under the ring
   lock. */
static BOOLEAN
advance_tx_req(struct xenbus_pending_req *req)
{
    XENSTORE_RING_IDX cons;
    const struct xenbus_sg_segment *seg;
    unsigned off_in_segment;
    unsigned this_pass;
    unsigned prod;

    XM_ASSERT(shared_buf != NULL);

    seg = req->next_tx_seg;
    off_in_segment = req->tx_sg_off;
    prod = shared_buf->req_prod;

    cons = shared_buf->req_cons;
    XsMemoryBarrier(); /* Read req_cons before doing anything else. */

    while (seg &&
           prod != cons + XENSTORE_RING_SIZE) {
        /* How much are we going to copy this time around? */
        this_pass = (unsigned)(seg->len - off_in_segment);
        if (this_pass > cons + XENSTORE_RING_SIZE - prod)
            this_pass = cons + XENSTORE_RING_SIZE - prod;
        memcpy_to_ring(shared_buf->req,
                       (const void *)((ULONG_PTR)seg->data + off_in_segment),
                       this_pass,
                       MASK_XENSTORE_IDX(prod),
                       XENSTORE_RING_SIZE);
        prod += this_pass;
        off_in_segment += this_pass;
        if (off_in_segment == (unsigned)seg->len) {
            off_in_segment = 0;
            seg = seg->next;
        }
    }

    req->next_tx_seg = seg;
    req->tx_sg_off = off_in_segment;

    if (prod != shared_buf->req_prod) {

        /* Make sure all writes are committed before updating ring
         * index. */
        XsMemoryBarrier();
        shared_buf->req_prod = prod;

        return TRUE;
    } else {
        return FALSE;
    }
}

static void
_put_watch_handler(struct xenbus_watch_handler *wh)
{
    wh->refcount--;
    if (!wh->refcount)
        KeSetEvent(&wh->safe_to_release, IO_NO_INCREMENT, FALSE);
}

/* Drop a reference to a watch handler.  Acquires and releases the
   watch lock. */
static void
put_watch_handler(struct xenbus_watch_handler *wh)
{
    KIRQL irql;
    acquire_lock_safe(&watch_lock, &irql);
    _put_watch_handler(wh);
    release_lock_safe(&watch_lock, irql);
}

/* Get a reference to a watch handler.  The watch handler will not be
 * released until put_watch_handler() is called.  Called under the
 * watch lock. */
/* Be very careful about waiting for the watch thread while holding a
   reference, since a watch handler could call unregister_watch(),
   which will wait for the reference to be release.  Be even more
   careful taking out references while you're on the watch thread
   itself. */
static void
get_watch_handler(struct xenbus_watch_handler *wh)
{
    wh->refcount++;
    if (wh->refcount == 1)
        KeClearEvent(&wh->safe_to_release);
}

/* Register a watch with xenbus.  Returns 0 on success or <0 on
 * error. */
/* This is accessing xenbus, and so shouldn't really be called at
 * raised IRQL, but it's not actually possible to avoid that at the
 * moment without races. */
static int
register_watch_handler(struct xenbus_watch_handler *wh)
{
    struct xenbus_sg_segment sg[3];
    struct xenbus_pending_req req;
    struct xsd_sockmsg msg;
    NTSTATUS res;
    char reply_buffer[16];

    initialise_sg_list(XS_WATCH, XBT_NIL, sg,
                       &msg, sizeof(msg),
                       wh->path, strlen(wh->path) + 1,
                       wh->token, strlen(wh->token) + 1,
                       NULL, (size_t)0);
    initialise_pending_req(&req, &msg, sg);
    set_reply_buffer(&req, reply_buffer, sizeof(reply_buffer));

    res = submit_request_and_await_result(&req, "register_watch_handler",
                                          wh->path);
    /* If we try to register the same watch twice, xenstored will say
       EEXIST, which we translate to STATUS_OBJECT_NAME_EXISTS.  This
       can happen if we're unlucky coming back from suspend/resume. */
    if (!NT_SUCCESS(res) && res != STATUS_OBJECT_NAME_EXISTS) {
        return -1;
    } else {
        return 0;
    }
}

__checkReturn struct xenbus_watch_handler *
__xenbus_watch_path(PCSTR path,
                    const char *cb_name,
                    void (*cb)(void *data),
                    void *data)
{
    struct xenbus_watch_handler *wh;
    size_t s;
    KIRQL irql;

    XM_ASSERT(path != NULL);

    /* Watches don't work properly in austere mode. */
    XM_ASSERT(!AustereMode);

    wh = XmAllocateZeroedMemory(sizeof(*wh));
    if (!wh)
        return NULL;
    s = strlen(path);
    wh->path = XmAllocateMemory(s + 1);
    if (!wh->path) {
        XmFreeMemory(wh);
        return NULL;
    }
    memcpy(wh->path, path, s + 1);
    Xmsnprintf(wh->token, 17, "%I64x", (ULONG64)wh);
    KeInitializeEvent(&wh->safe_to_release, NotificationEvent, FALSE);

    wh->cb_name = cb_name;
    wh->cb = cb;
    wh->ctxt = data;

    /* This must happen *before* we actually register, so that we get
       re-registered if we're suspend/resume'd at the wrong time. */
    wh->currently_registered = TRUE;

    acquire_lock_safe(&watch_lock, &irql);
    wh->next = head_watch_handler;
    if (wh->next)
        wh->next->prev = wh;
    head_watch_handler = wh;
    release_lock_safe(&watch_lock, irql);

    if (register_watch_handler(wh) < 0) {
        TraceWarning(("Failed to register watch on %s.\n", wh->path));

        /* Not actually necessary, but makes things a bit easier to
           understand. */
        wh->currently_registered = FALSE;

        xenbus_unregister_watch(wh);
        return NULL;
    } else {
        if (wh->cb_name != NULL)
            TraceVerbose(("Registered watch on %s (watch handler: %s).\n", wh->path, wh->cb_name));
        else
            TraceVerbose(("Registered watch on %s (event).\n", wh->path));

        return wh;
    }
}

__checkReturn struct xenbus_watch_handler *
__xenbus_watch_path_anonymous(PCSTR path,
                              void (*cb)(void *data),
                              void *data)
{
    return __xenbus_watch_path(path, "unknown", cb, data);
}

/* This handler is special; see trigger_watch() for details. */
static void
set_event_handler(void *ctxt)
{
    PKEVENT evt = ctxt;
    KeSetEvent(evt, IO_NO_INCREMENT, FALSE);
}

__checkReturn struct xenbus_watch_handler *
xenbus_watch_path_event(PCSTR path, PKEVENT event)
{
    return __xenbus_watch_path(path, NULL, set_event_handler, event);
}

__checkReturn NTSTATUS
xenbus_redirect_watch(struct xenbus_watch_handler *wh, PCSTR path)
{
    KIRQL irql;
    char *old_path;
    char *new_path;
    size_t l;
    BOOLEAN old_registered;
    char reply_buffer[16];
    struct xenbus_sg_segment sg[3];
    struct xenbus_pending_req req;
    struct xsd_sockmsg msg;
    NTSTATUS res;

    l = strlen(path) + 1;
    new_path = XmAllocateMemory(l);
    if (!new_path)
        return STATUS_INSUFFICIENT_RESOURCES;
    memcpy(new_path, path, l);

    acquire_lock_safe(&watch_lock, &irql);
    old_path = wh->path;
    XM_ASSERT(old_path != NULL);
    if (!strcmp(old_path, new_path)) {
        release_lock_safe(&watch_lock, irql);
        XmFreeMemory(new_path);
        return STATUS_SUCCESS;
    }
    old_registered = wh->currently_registered;

    wh->path = new_path;
    /* We flag it as currently_registered slightly early, so as
       reregister_all_watches can't get in and cause problems if we
       suspend at the wrong place. */
    wh->currently_registered = TRUE;
    release_lock_safe(&watch_lock, irql);

    /* Register the new watch path with xenbus */
    if (register_watch_handler(wh) < 0) {
        /* Uh oh.  Go back to the old path */
        acquire_lock_safe(&watch_lock, &irql);
        wh->path = old_path;
        wh->currently_registered = old_registered;
        release_lock_safe(&watch_lock, irql);

        if (!old_registered) {
            /* This should be very rare, and means that we tried to
               redirect a watch before the late suspend handler had
               finished.  The late handler should re-register for us,
               but it might have gotten in while currently_registered
               was TRUE and so not actually do anything.  Make sure
               everything is good be calling reregister_all_watches()
               ourselves now that currently_registered has gone back
               to FALSE. */
            TraceWarning(("Bizarre race-with-suspend in error path of xenbus_redirect_watch()\n"));
            reregister_all_watches();
        }
        return STATUS_UNSUCCESSFUL;
    }

    if (old_registered) {
        /* Unregister the old one */
        initialise_sg_list(XS_UNWATCH, XBT_NIL, sg,
                           &msg, sizeof(msg),
                           old_path, strlen(old_path) + 1,
                           wh->token, strlen(wh->token) + 1,
                           NULL, (size_t)0);
        initialise_pending_req(&req, &msg, sg);
        set_reply_buffer(&req, reply_buffer, sizeof(reply_buffer));

        res = submit_request_and_await_result(&req,
                                              "xenbus_redirect_watch",
                                              old_path);
        if (!NT_SUCCESS(res)) {
            /* This shouldn't ever happen.  If it does it indicates either
               that the watch wasn't properly registered before the
               redirection or there's a bug in xenstored. */
            TraceError(("Failed to unregister old watch for xenbus_redirect_watch.\n"));
        }
    }
    XmFreeMemory(old_path);

    return STATUS_SUCCESS;
}

/* Cause the watch to fire soon.  Called under the watch lock. */
static void
trigger_watch(struct xenbus_watch_handler *wh)
{
    XM_ASSERT(wh != NULL);
    if (wh->cb_name != NULL)
        TraceVerbose(("Trigger watch on %s.\n", wh->path));
    else
        TraceVerbose(("Trigger watch on %s (event).\n", wh->path));
    if (!wh->queued) {
        if (wh->cb == set_event_handler) {
            /* Urk.  Event watches are special, because you need to be
               able to wait for the event from a late suspend handler.
               Unfortunately, some other suspend handlers sometimes
               allocate suspend tokens, and that means that when late
               suspend handlers are running the watch thread is
               potentially dead.  Work around this by setting the
               event directly from the xenbus DPC. */
            /* This is really horrible. */
            KeSetEvent(wh->ctxt, IO_NO_INCREMENT, FALSE);
        } else {
            wh->queued = TRUE;
            get_watch_handler(wh);
            InsertTailList(&pending_watches_list, &wh->pending_list);
            if (watch_thread)
                KeSetEvent(&watch_thread->event, IO_NO_INCREMENT, FALSE);
        }
    }
}

void
xenbus_trigger_watch(struct xenbus_watch_handler *wh)
{
    KIRQL irql;

    acquire_lock_safe(&watch_lock, &irql);
    trigger_watch(wh);
    release_lock_safe(&watch_lock, irql);
}

static void
unregister_watch_with_xenstored(struct xenbus_watch_handler *wh)
{
    struct xenbus_sg_segment sg[3];
    struct xenbus_pending_req req;
    struct xsd_sockmsg msg;
    char reply_buffer[16];
    NTSTATUS res;

    if (!wh->currently_registered)
        return;

    /* It's possible that we'll try and unwatch something which has
       already been unwatched if we race with suspend/resume.  This is
       harmless. */
    /* We do need to make sure that we don't get re-registered, but
       that's taken care of by removing us from the list and waiting
       for the refcount to drop above. */
    initialise_sg_list(XS_UNWATCH, XBT_NIL, sg,
                       &msg, sizeof(msg),
                       wh->path, strlen(wh->path) + 1,
                       wh->token, strlen(wh->token) + 1,
                       NULL, (size_t)0);
    initialise_pending_req(&req, &msg, sg);
    set_reply_buffer(&req, reply_buffer, sizeof(reply_buffer));

    res = submit_request_and_await_result(&req,
                                          "xenbus_unregister_watch",
                                          wh->path);
    if (!NT_SUCCESS(res)) {
        /* Not much we can actually do here. */
        TraceError (("Error %x unwatching %s\n", res, wh->path));
    }
}

/* This isn't allowed to fail, ever. */
void
xenbus_unregister_watch(struct xenbus_watch_handler *wh)
{
    KIRQL irql;

    /* Unhook from the watch list first.  This stops the watch from
       firing again, and also stops it from getting re-registered by
       the suspend handler. */
    acquire_lock_safe(&watch_lock, &irql);
    if (wh->next)
        wh->next->prev = wh->prev;
    if (wh->prev)
        wh->prev->next = wh->next;
    else
        head_watch_handler = wh->next;

    /* Remove ourselves from the pending list, if appropriate.  We
       might be on the watch thread, so waiting for it to do it really
       isn't a good idea. */
    if (wh->queued) {
        RemoveEntryList(&wh->pending_list);
        _put_watch_handler(wh);
    }
    release_lock_safe(&watch_lock, irql);

    /* Wait for any outstanding references on the handler to
       disappear.  We know that we're not waiting for the watch thread
       from the watch thread, because the only reference which the
       watch thread owns is the one for the watch being pending, and
       we've just cleared that.  More can't be created because we've
       removed the watch from the master list.

       The only other thing which takes out references is
       reregister_all_watches(), which never calls out to clients
       while holding a reference.  This means that we can be confident
       it'll finish fairly quickly, and without waiting on the watch
       thread (which could cause a deadlock).
    */
    while (wh->refcount)
        KeWaitForSingleObject(&wh->safe_to_release,
                              Executive,
                              KernelMode,
                              FALSE,
                              NULL);

    unregister_watch_with_xenstored(wh);

    XmFreeMemory(wh->path);
    XmFreeMemory(wh);
}

#pragma warning(push)
#pragma warning(disable: 4995) // strcpy marked as deprecated

NTSTATUS
xenbus_ls(xenbus_transaction_t xbt, PCSTR path, __out PSTR **Res)
{
    struct xenbus_sg_segment sg[2];
    struct xenbus_pending_req req;
    struct xsd_sockmsg msg;
    NTSTATUS stat;
    unsigned nr_entries;
    unsigned y;
    size_t x, z;
    char **res;
    char *reply;

    *Res = NULL;
    if (!NT_SUCCESS(transaction_status(xbt)))
        return transaction_status(xbt);

    TraceDebug(("xenbus_ls(%s, %p)\n", path, path));
    initialise_sg_list(XS_DIRECTORY, xbt, sg,
                       &msg, sizeof(msg),
                       path, strlen(path) + 1,
                       NULL, (size_t)0);
    initialise_pending_req(&req, &msg, sg);

    stat = submit_request_and_await_result(&req,
                                           "xenbus_ls",
                                           path);
    if (!NT_SUCCESS(stat)) {
        TraceVerbose(("xenstore_ls(%s) -> %x\n", path, stat));
        XmFreeMemory(req.reply_payload);
        xenbus_fail_transaction(xbt, stat);
        return stat;
    }

    reply = req.reply_payload;

    /* Count up how many entries we've got in the result list. */
    nr_entries = 0;
    for (x = 0; x < req.reply_header.len; x++)
        nr_entries += (reply[x] == '\0');

    res = XmAllocateMemory(sizeof(res[0]) * (nr_entries + 1));
    if (!res)
        goto fail;

    /* Split into strings and copy */
    y = 0;
    for (x = 0; x < req.reply_header.len; x++) {
        z = strlen(reply + x);
        res[y] = XmAllocateMemory(z+1);
        if (!res[y]) {
            y--;
            while (y) {
                XmFreeMemory(res[y]);
                y--;
            }
            XmFreeMemory(res);
            goto fail;
        }
        strcpy(res[y], reply + x);
        y++;
        x += z;
    }
    XmFreeMemory(reply);

    res[y] = NULL;

    for (y = 0; res[y]; y++)
        TraceDebug(("xenbus_ls(%s):%d -> %s\n", path, y, res[y]));
    *Res = res;
    return STATUS_SUCCESS;

fail:
    XmFreeMemory(reply);
    xenbus_fail_transaction(xbt, STATUS_INSUFFICIENT_RESOURCES);
    TraceVerbose(("xenstore_ls(%s) -> no memory\n", path));
    return STATUS_INSUFFICIENT_RESOURCES;
}

#pragma warning(pop)

static NTSTATUS
xenbus_read_bin_no_fail(xenbus_transaction_t xbt, PCSTR path, PCSTR node,
                        __out void **Res, __out size_t *len)
{
    struct xenbus_sg_segment sg[4];
    struct xenbus_pending_req req;
    struct xsd_sockmsg msg;
    NTSTATUS res;

    *Res = NULL;
    *len = 0;
    if (!NT_SUCCESS(transaction_status(xbt)))
        return transaction_status(xbt);

    if (node) {
        initialise_sg_list(XS_READ, xbt, sg,
                           &msg, sizeof(msg),
                           path, strlen(path),
                           "/", 1,
                           node, strlen(node) + 1,
                           NULL, (size_t)0);
    } else {
        initialise_sg_list(XS_READ, xbt, sg,
                           &msg, sizeof(msg),
                           path, strlen(path) + 1,
                           NULL, (size_t)0);
    }
    initialise_pending_req(&req, &msg, sg);

    res = submit_request_and_await_result(&req,
                                          "xenbus_read_bin",
                                          path);
    if (!NT_SUCCESS(res)) {
        TraceDebug(("xenbus_read_bin(%s, %s) => %x\n", path, node, res));
        XmFreeMemory(req.reply_payload);
    } else {
        *len = req.reply_header.len;
        *Res = req.reply_payload;
    }
    return res;
}

NTSTATUS
xenbus_read_bin(xenbus_transaction_t xbt, PCSTR path, PCSTR node,
                __out void **Res, __out size_t *len)
{
    NTSTATUS res;

    res = xenbus_read_bin_no_fail(xbt, path, node, Res, len);
    if (!NT_SUCCESS(res))
        xenbus_fail_transaction(xbt, res);
    return res;
}

NTSTATUS
xenbus_read(xenbus_transaction_t xbt, PCSTR path, __out PSTR *Res)
{
    size_t l;
    NTSTATUS stat;
    char *tmp;

    *Res = NULL;

    stat = xenbus_read_bin(xbt, path, NULL, &tmp, &l);
    if (!NT_SUCCESS(stat))
        return stat;

    /* Need to return a nul-terminated string. */
    *Res = XmAllocateMemory(l + 1);
    if (!*Res) {
        XmFreeMemory(tmp);
        xenbus_fail_transaction(xbt, STATUS_INSUFFICIENT_RESOURCES);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memcpy(*Res, tmp, l);
    (*Res)[l] = 0;
    XmFreeMemory(tmp);

    return STATUS_SUCCESS;
}

/* Not quite the usual strtoll: takes a length for the string, rather
   than assuming nul-termination, and sets an error flag when
   something goes wrong. */
ULONG64
xm_strtoll(const char *buf, size_t len, unsigned base, __inout int *err)
{
    ULONG64 acc = 0;
    unsigned digit;
    ULONG64 limit;
    unsigned off;

    *err = 0;

    XM_ASSERT(base == 10 || base == 16);
    limit = ~(0ull) / base;
    off = 0;
    while (off < len) {
        if (buf[off] >= '0' && buf[off] <= '9')
            digit = buf[off] - '0';
        else if (buf[off] >= 'a' && buf[off] <= 'f')
            digit = buf[off] - 'a' + 10;
        else if (buf[off] >= 'A' && buf[off] <= 'F')
            digit = buf[off] - 'A' + 10;
        else if ((buf[off] == '\0') && (off == len-1))
            break;
        else
            digit = base;
        if (digit >= base || acc > limit)
            *err = 1;
        acc *= base;
        if (acc + digit < acc)
            *err = 1;
        acc += digit;
        off++;
    }
    return acc;
}

static struct xenbus_watch_handler *
find_watch_by_ident(const char *ident)
{
    struct xenbus_watch_handler *wh;

    for (wh = head_watch_handler;
         wh != NULL && strcmp(ident, wh->token) != 0;
         wh = wh->next)
        ;
    return wh;
}

static void
fire_watch_by_ident(const char *path, const char *ident)
{
    KIRQL irql;
    struct xenbus_watch_handler *wh;

    XM_ASSERT(!AustereMode);

    acquire_lock_safe(&watch_lock, &irql);
    wh = find_watch_by_ident(ident);
    if (wh) {
        trigger_watch(wh);
    } else {
        TraceWarning(("spurious watch event (%s:%s).\n", ident, path));
    }
    release_lock_safe(&watch_lock, irql);
}

static XENSTORE_RING_IDX
memchr_ring(const char *ring, char chr, XENSTORE_RING_IDX start,
            XENSTORE_RING_IDX end, size_t ring_size)
{
    XENSTORE_RING_IDX res;

    for (res = start; res != end && ring[res % ring_size] != chr; res++)
        ;
    return res;
}

/* Receive some stuff from xenstored and transfer it to the
   appropriate reply area.  Called under the ring lock.  Returns TRUE
   if we made progress, in which case the caller should call us
   again. */
static BOOLEAN
receive_from_xenstored(void)
{
    unsigned bytes_avail;
    unsigned bytes_to_copy;
    struct xenbus_pending_req *req;
    unsigned bytes_rxed;
    struct xsd_sockmsg hdr;
    XENSTORE_RING_IDX cons, prod;

    XM_ASSERT(shared_buf != NULL);

    cons = shared_buf->rsp_cons;
    prod = shared_buf->rsp_prod;
    XsMemoryBarrier(); /* Make sure read of rsp_prod is before other
                        * reads */

    bytes_avail = prod - cons;

    /* If we crash while a xenstore operation is in progress, we may
       need to discard responses to operations initiated before the
       crash, in order to get a clean xenstore interface and write the
       crash dump. */
    if (cons_response_discard_bytes) {
        if (cons_response_discard_bytes > bytes_avail) {
            shared_buf->rsp_cons += bytes_avail;
            cons_response_discard_bytes -= bytes_avail;
        } else {
            shared_buf->rsp_cons += cons_response_discard_bytes;
            cons_response_discard_bytes = 0;
        }
        return TRUE;
    }

    if (current_rx_req) {
        /* Receive some more stuff into this request. */

        req = current_rx_req;
        bytes_rxed = (unsigned)req->reply_payload_received;

        /* Limit ourselves to just this request */
        if (bytes_avail > req->reply_header.len - bytes_rxed)
            bytes_avail = req->reply_header.len - bytes_rxed;

        if (req->reply_buf_size > bytes_rxed) {
            /* Still space left in the reply buffer.  Use some. */
            bytes_to_copy = bytes_avail;
            if (bytes_to_copy > req->reply_buf_size - bytes_rxed)
                bytes_to_copy = (unsigned)req->reply_buf_size - bytes_rxed;
            memcpy_from_ring(shared_buf->rsp,
                             (void *)((ULONG_PTR)req->reply_payload +
                                      bytes_rxed),
                             bytes_to_copy,
                             MASK_XENSTORE_IDX(cons),
                             XENSTORE_RING_SIZE);
        }

        /* If the message didn't fit in the RX buffer, just discard
           the remainder.  Callers who supply their own buffer are
           expected to handle this. */
        req->reply_payload_received += bytes_avail;
        cons += bytes_avail;
        
        XM_ASSERT(req->reply_payload_received <= req->reply_header.len);
        if (req->reply_payload_received == req->reply_header.len) {
            /* The reply is now complete.  Mark it as such. */
            req->xenbus_replied = 1;
            if (!AustereMode)
                KeSetEvent(&req->completion_event, IO_NO_INCREMENT, FALSE);
            current_rx_req = NULL;
        }
    } else /* if (!current_rx_req) */{
        if (bytes_avail < sizeof(struct xsd_sockmsg)) {
            /* Back off until the entire header is available. */
/**/        return FALSE;
        }

        /* Copy the header from the ring. */
        memcpy_from_ring(shared_buf->rsp,
                         &hdr,
                         sizeof(hdr),
                         MASK_XENSTORE_IDX(cons),
                         XENSTORE_RING_SIZE);

        if (hdr.type == XS_WATCH_EVENT) {
            XENSTORE_RING_IDX path_start, path_end;
            XENSTORE_RING_IDX ident_start, ident_end;
            XENSTORE_RING_IDX message_end;
            char watch_path[64];
            char watch_ident[17];

            if (bytes_avail < sizeof(hdr) + hdr.len) {
                /* Can't handle partial watch event messages.  Wait for the
                   whole thing to be available. */
/**/            return FALSE;
            }

            /* Watch event messages consist of the path, followed by a nul,
               followed by the watch identifier, followed by a nul. */
            message_end = cons + sizeof(hdr) + hdr.len;
            XM_ASSERT(message_end <= prod);

            if (AustereMode)    // Watches don't work in Austere mode
                goto done;

            path_end = path_start = cons + sizeof(hdr);
            while (shared_buf->rsp[MASK_XENSTORE_IDX(path_end)] != '\0') {
                if (path_end == message_end)
                    break;
                path_end++;
            }
            XM_ASSERT(path_end <= message_end);

            if (path_end == message_end) {
                TraceError(("%s: malformed watch event.\n", __FUNCTION__));
                goto done;
            }

            memcpy_from_ring(shared_buf->rsp,
                             watch_path,
                             min(path_end - path_start + 1, sizeof (watch_path)),
                             MASK_XENSTORE_IDX(path_start),
                             XENSTORE_RING_SIZE);
            watch_path[sizeof (watch_path) - 1] = '\0';

            ident_end = ident_start = path_end + 1; // skip over the nul

            while (shared_buf->rsp[MASK_XENSTORE_IDX(ident_end)] != '\0') {
                if (ident_end == message_end)
                    break;
                ident_end++;
            }
            XM_ASSERT(ident_end <= message_end);

            if (ident_end == message_end &&
                shared_buf->rsp[MASK_XENSTORE_IDX(ident_end)] != '\0') {
                TraceError(("%s: malformed watch event.\n", __FUNCTION__));
                goto done;
            }

            XM_ASSERT(ident_end - ident_start < sizeof (watch_ident));
            memcpy_from_ring(shared_buf->rsp,
                             watch_ident,
                             ident_end - ident_start + 1,
                             MASK_XENSTORE_IDX(ident_start),
                             XENSTORE_RING_SIZE);

            if (allow_xenbus_watch_operation)
                fire_watch_by_ident(watch_path, watch_ident);

done:
            cons = message_end;
        } else {
            /* Ordinary reply. */
            XM_ASSERT(!current_rx_req);

            if (hdr.type > XS_IS_DOMAIN_INTRODUCED) {
                TraceBugCheck(("Strange response type %d from xenstore!\n",
                               hdr.type));
            }
            current_rx_req = find_pending_rx_req(hdr.req_id);
            if (!current_rx_req) {
                /* This can sometimes happen when reinitialising for a
                   crash dump if we were halfway through a xenbus
                   operation when we failed.  Try to limp on, but flag
                   a warning (because this sort of error can lead to
                   getting completely incorrect responses to *other*
                   xenstore operations if you're really unlucky). */
                TraceError(("xenstored gave us an unexpected response with id %d\n",
                            hdr.req_id));
                cons_response_discard_bytes = hdr.len;
            } else {
                current_rx_req->reply_header = hdr;
                current_rx_req->reply_payload_received = 0;

                if (hdr.len > 8192)
                    TraceVerbose(("Very large xenbus reply, hdr.len=%d.\n",
                                  hdr.len));
                if (!current_rx_req->reply_payload) {
                    current_rx_req->reply_payload =
                        XmAllocateMemory(hdr.len);
                    if (current_rx_req->reply_payload) {
                        current_rx_req->reply_buf_size = hdr.len;
                    } else {
                        current_rx_req->reply_buf_size = 0;
                    }
                }
            }

            cons += sizeof(hdr);
        }
    }
    if (shared_buf->rsp_cons == cons) {
        /* Didn't manage to make any progress. */
        return FALSE;
    } else {
        XsMemoryBarrier(); /* Write to cons is after reads from
                            * ring. */
        shared_buf->rsp_cons = cons;
        return TRUE;
    }
}

static void
xenbus_dpc_func(PKDPC dpc, void *ignore1, void *ignore2, void *ignore3)
{
    BOOLEAN fire_evtchn = FALSE;
    BOOLEAN locked;
    KIRQL irql;

    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(ignore1);
    UNREFERENCED_PARAMETER(ignore2);
    UNREFERENCED_PARAMETER(ignore3);

    locked = acquire_ring_lock(&irql);

    if (shared_buf != NULL) {
        /* Transmit as much as we can. */
        while (current_tx_req &&
               advance_tx_req(current_tx_req)) {
            fire_evtchn = TRUE;
            if (current_tx_req->next_tx_seg == NULL)
                current_tx_req = current_tx_req->next;
        }

        /* Receive as much as we can. */
        while (receive_from_xenstored())
            fire_evtchn = TRUE;

        if (fire_evtchn && !is_null_EVTCHN_PORT(xenbus_evtchn))
            EvtchnNotifyRemote(xenbus_evtchn);
    }

    if (locked)
        release_ring_lock(irql);
}

NTSTATUS
xenbus_write_bin(xenbus_transaction_t xbt, const char *path, const char *node,
                 const void *data, size_t data_len)
{
    struct xenbus_sg_segment sg[5];
    struct xenbus_pending_req req;
    struct xsd_sockmsg msg;
    NTSTATUS res;

    if (!NT_SUCCESS(transaction_status(xbt)))
        return transaction_status(xbt);

    if (node) {
        initialise_sg_list(XS_WRITE, xbt, sg,
                           &msg, sizeof(msg),
                           path, strlen(path),
                           "/", 1,
                           node, strlen(node) + 1,
                           data, data_len,
                           NULL, (size_t)0);
    } else {
        initialise_sg_list(XS_WRITE, xbt, sg,
                           &msg, sizeof(msg),
                           path, strlen(path) + 1,
                           data, data_len,
                           NULL, (size_t)0);
    }
    initialise_pending_req(&req, &msg, sg);
    res = submit_request_and_await_result(&req, "xenbus_write_bin",
                                          path);
    if (!NT_SUCCESS(res))
        xenbus_fail_transaction(xbt, res);
    XmFreeMemory(req.reply_payload);

    TraceDebug(("xenbus_write_bin(%s,%s,%d) -> %x\n", path, node, data_len,
               res));

    if (res == STATUS_OBJECT_NAME_NOT_FOUND)
        TraceWarning(("xenbus_write_bin(%s,%s) failed with ENOENT?\n",
                      path, node));

    return res;
}

NTSTATUS
xenbus_write(xenbus_transaction_t xbt, const char *path, const char *data)
{
    return xenbus_write_bin(xbt, path, NULL, data, strlen(data));
}


NTSTATUS
xenbus_remove(xenbus_transaction_t xbt, const char *path)
{
    struct xenbus_sg_segment sg[2];
    struct xenbus_pending_req req;
    struct xsd_sockmsg msg;
    NTSTATUS res;

    if (!NT_SUCCESS(transaction_status(xbt)))
        return transaction_status(xbt);

    initialise_sg_list(XS_RM, xbt, sg,
                       &msg, sizeof(msg),
                       path, strlen(path) + 1,
                       NULL, (size_t)0);
    initialise_pending_req(&req, &msg, sg);

    res = submit_request_and_await_result(&req, "xenbus_remove", "path");
    if (!NT_SUCCESS(res))
        xenbus_fail_transaction(xbt, res);
    XmFreeMemory(req.reply_payload);

    TraceDebug(("xenbus_remove(%s) -> %x\n", path, res));
    return res;
}

/* Have to be a little bit careful here, in that we're not allowed to
   cause an error once we've submitted the request to the backend, so
   we have to allocate some memory in advance. */
NTSTATUS
__xenbus_transaction_start(__in const char *Caller, __out xenbus_transaction_t *Res)
{
    struct xenbus_sg_segment sg[2];
    struct xenbus_pending_req req;
    struct xsd_sockmsg msg;
    struct xenbus_transaction *work;
    NTSTATUS res;
    char reply_buffer[16];
    KIRQL irql;

    *Res = null_xenbus_transaction_t();

    work = XmAllocateZeroedMemory(sizeof(*work));
    if (!work)
        return STATUS_INSUFFICIENT_RESOURCES;
    work->magic = XENBUS_TRANSACTION_MAGIC;
    work->status = STATUS_SUCCESS;

    work->caller = Caller;
    work->thread = KeGetCurrentThread();

    /* Add the transaction to the list before submitting the start
       request to xenbus so as it gets properly aborted by
       suspend/resume. */
    acquire_lock_safe(&transaction_lock, &irql);
    work->next = head_open_transaction;
    if (head_open_transaction)
        head_open_transaction->prev = work;
    head_open_transaction = work;
    release_lock_safe(&transaction_lock, irql);

    /* xenstored gets unhappy if you send it a zero-length message, so
       add a nul byte of payload. */
    initialise_sg_list(XS_TRANSACTION_START, XBT_NIL, sg,
                       &msg, sizeof(msg),
                       "", (size_t)1,
                       NULL, (size_t)0);
    initialise_pending_req(&req, &msg, sg);
    set_reply_buffer(&req, reply_buffer, sizeof(reply_buffer));

    res = submit_request_and_await_result(&req, "xenbus_transaction_start",
                                          NULL);
    if (NT_SUCCESS(res)) {
        int err;
        ULONG64 tmp;

        XM_ASSERT(req.reply_payload == reply_buffer);
        XM_ASSERT(req.reply_header.len < sizeof(reply_buffer));

        tmp = xm_strtoll(reply_buffer, req.reply_header.len-1, 10, &err);

        /* Assert that xenbus gave us a valid id. */
        XM_ASSERT(!reply_buffer[req.reply_header.len-1]);
        XM_ASSERT(!err);
        XM_ASSERT(tmp == (uint32_t)tmp);

        work->trans_id = (uint32_t)tmp;
    } else {
        /* We're going to create the transaction structure anyway, so
           that we have somewhere to stash the error code.  Set the
           transaction id to a poison value so it's obvious if we use
           it by mistake. */
        work->trans_id = 0x66778899;
    }

    *Res = __wrap_xenbus_transaction_t(work);

    xenbus_fail_transaction(*Res, res);

    TraceDebug(("xenbus_transaction_start() -> %x\n", res));
    return res;
}

NTSTATUS
__xenbus_transaction_start_ntstatus(__out xenbus_transaction_t *Res)
{
    return __xenbus_transaction_start("unknown", Res);
}

void
__xenbus_transaction_start_void(__in const char *Caller, __out xenbus_transaction_t *Res)
{
    (void) __xenbus_transaction_start(Caller, Res);
}

/* This is not allowed to fail, unless the transaction has failed, in
   which case it must fail in the same way.  In any case, the
   transaction must be ended on the xenstore side. */
__checkReturn NTSTATUS
__xenbus_transaction_end(__in const char *caller, __in xenbus_transaction_t t, __in int abort)
{
    struct xenbus_sg_segment sg[2];
    struct xenbus_pending_req req;
    struct xsd_sockmsg msg;
    NTSTATUS res;
    struct xenbus_transaction *xbt;
    PKTHREAD thread;
    char reply_buffer[16];
    KIRQL irql;

    thread = KeGetCurrentThread();

    XM_ASSERT(!is_nil_xenbus_transaction_t(t));
    if (is_null_xenbus_transaction_t(t))
        return STATUS_INSUFFICIENT_RESOURCES;

    xbt = unwrap_xenbus_transaction_t(t);

    XM_ASSERT(IMPLY(strcmp(xbt->caller, "XenevtchnDeviceControl") != 0,
            strcmp(xbt->caller, caller) == 0));
    XM_ASSERT(IMPLY(strcmp(xbt->caller, "XenevtchnDeviceControl") != 0,
            (xbt->thread == thread)));

    if (!NT_SUCCESS(xbt->status))
        abort = 1;
    if (abort) {
        initialise_sg_list(XS_TRANSACTION_END, t, sg,
                           &msg, sizeof(msg),
                           "F", (size_t)2,
                           NULL, (size_t)0);
    } else {
        initialise_sg_list(XS_TRANSACTION_END, t, sg,
                           &msg, sizeof(msg),
                           "T", (size_t)2,
                           NULL, (size_t)0);
    }
    initialise_pending_req(&req, &msg, sg);
    set_reply_buffer(&req, reply_buffer, sizeof(reply_buffer));

    res = submit_request_and_await_result(&req, "xenbus_transaction_end",
                                          NULL);
    if (NT_SUCCESS(res)) {
        /* If xenstored successfully ended the transaction, pick up
           the status stored in the request, in case some previous
           operation failed.  Otherwise, use the error which xenstored
           gave us. */
        res = xbt->status;
    } else {
        if (res != STATUS_RETRY) {
            /* This really shouldn't happen: either we tried to end a bad
               transaction, or the transaction has stayed open when it
               really shouldn't have.  Either is pretty bad. */
            TraceWarning(("transaction %d: failed (started by %s:%p): %08x\n",
                          xbt->trans_id,
                          xbt->caller, xbt->thread,
                          res));
        } else {
            TraceInfo(("transaction %d: conflicted (started by %s:%p)\n",
                       xbt->trans_id,
                       xbt->caller, xbt->thread));
        }
    }

    acquire_lock_safe(&transaction_lock, &irql);
    if (xbt->prev)
        xbt->prev->next = xbt->next;
    if (xbt->next)
        xbt->next->prev = xbt->prev;
    if (xbt == head_open_transaction)
        head_open_transaction = xbt->next;
    release_lock_safe(&transaction_lock, irql);

    XmFreeMemory(xbt);

    TraceDebug(("xenbus_transaction_end() -> %x\n", res));

    return res;
}

__checkReturn NTSTATUS
__xenbus_transaction_end_anonymous(__in xenbus_transaction_t t, __in int abort)
{
    return __xenbus_transaction_end("unknown", t, abort);
}

NTSTATUS
xenbus_printf(xenbus_transaction_t xbt, const char *prefix,
              const char *node, const char *fmt, ...)
{
    char *str_buf;
    va_list args;
    NTSTATUS stat;

    va_start(args, fmt);
    str_buf = Xmvasprintf(fmt, args);
    va_end(args);

    if (!str_buf) {
        xenbus_fail_transaction(xbt, STATUS_INSUFFICIENT_RESOURCES);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    stat = xenbus_write_bin(xbt, prefix, node, str_buf, strlen(str_buf));
    XmFreeMemory(str_buf);
    return stat;
}

NTSTATUS
xenbus_read_int(xenbus_transaction_t xbt, PCSTR prefix,
                PCSTR node, ULONG64 *res)
{
    char *buf;
    ULONG64 r;
    NTSTATUS stat;
    size_t len;
    int err;

    *res = 0;
    stat = xenbus_read_bin(xbt, prefix, node, &buf, &len);
    if (!NT_SUCCESS(stat))
        return stat;
    r = xm_strtoll(buf, len, 10, &err);
    XmFreeMemory(buf);
    if (err) {
        xenbus_fail_transaction(xbt, STATUS_DATA_ERROR);
        return STATUS_DATA_ERROR;
    }
    *res = r;
    return STATUS_SUCCESS;
}

ULONG64
XenbusReadInteger(xenbus_transaction_t trans, const char *prefix,
                  const char *node)
{
    NTSTATUS stat;
    ULONG64 res;

    stat = xenbus_read_int(trans, prefix, node, &res);
    if (!NT_SUCCESS(stat))
        return (ULONG64)-1;

    return res;
}

NTSTATUS
xenbus_write_grant_ref(xenbus_transaction_t xbt, const char *prefix,
                       const char *node, GRANT_REF gref)
{
    return xenbus_printf(xbt, prefix, node, "%u", xen_GRANT_REF(gref));
}

NTSTATUS
xenbus_read_state(xenbus_transaction_t xbt, PCSTR prefix,
                  PCSTR node, XENBUS_STATE *state)
{
    NTSTATUS stat;
    ULONG64 res;

    *state = null_XENBUS_STATE();
    stat = xenbus_read_int(xbt, prefix, node, &res);
    if (!NT_SUCCESS(stat))
        return stat;
    if (res > _XENBUS_STATE_CLOSED || res == 0) {
        stat = STATUS_DATA_ERROR;
        xenbus_fail_transaction(xbt, STATUS_DATA_ERROR);
    } else {
        *state = wrap_XENBUS_STATE((int)res);
    }
    return stat;
}

/* Legacy API */
NTSTATUS
xenbus_write_state(xenbus_transaction_t xbt, PCSTR prefix,
                   PCSTR node, XENBUS_STATE state)
{
    return xenbus_printf(xbt, prefix, node, "%d", unwrap_XENBUS_STATE(state));
}

/* Change @prefix/@node to be @state, being careful not to recreate it
   if it doesn't already exist. */
/* This is a little bit tricky, because it needs to do the right thing
   whether or not @xbt is a valid transaction.  If it is a valid
   transaction, we use it, and if it's not we need to start a local
   one from here, and retry if anything goes wrong. */
NTSTATUS
xenbus_change_state(xenbus_transaction_t xbt, PCSTR prefix,
                    PCSTR node, XENBUS_STATE state)
{
    xenbus_transaction_t local_xbt;
    NTSTATUS status;
    XENBUS_STATE old_state;
    BOOLEAN need_local_xbt;

    need_local_xbt = is_nil_xenbus_transaction_t(xbt);
retry:
    if (need_local_xbt)
        xenbus_transaction_start(&local_xbt);
    else
        local_xbt = xbt;
    status = xenbus_read_state(local_xbt, prefix, node, &old_state);
    if (NT_SUCCESS(status))
        xenbus_write_state(local_xbt, prefix, node, state);
    if (need_local_xbt) {
        if (NT_SUCCESS(status)) {
            status = xenbus_transaction_end(local_xbt, 0);
            if (status == STATUS_RETRY)
                goto retry;
        } else
            (void)xenbus_transaction_end(local_xbt, 1);
    }

    return status;
}

NTSTATUS
xenbus_write_feature_flag(xenbus_transaction_t xbt, PCSTR prefix,
                          PCSTR node, BOOLEAN flag)
{
    TraceVerbose(("%s: %s/%s <- %s\n", __FUNCTION__, prefix, node, (flag) ? "TRUE" : "FALSE"));
    return xenbus_write_bin(xbt, prefix, node, (flag) ? "1" : "0", 1);
}

/* Getting this right is non-trivial, since we don't want to fail the
   transaction if the target node isn't present. */
NTSTATUS
xenbus_read_feature_flag(xenbus_transaction_t xbt, PCSTR prefix,
                         PCSTR node, BOOLEAN *Res)
{
    NTSTATUS res;
    char *buf;
    size_t len;

    *Res = FALSE;
    res = xenbus_read_bin_no_fail(xbt, prefix, node, &buf, &len);
    if (res == STATUS_OBJECT_NAME_NOT_FOUND)
        return STATUS_SUCCESS;
    if (!NT_SUCCESS(res)) {
        xenbus_fail_transaction(xbt, res);
        return res;
    }

    if (len == 1 && buf[0] == '0') {
        *Res = FALSE;
    } else if (len == 1 && buf[0] == '1') {
        *Res = TRUE;
    } else {
        TraceWarning(("Feature flag %s/%s was %.*s, should be 0 or 1\n",
                      prefix, node, len, buf));
        res = STATUS_DATA_ERROR;
        xenbus_fail_transaction(xbt, res);
    }
    XmFreeMemory(buf);
    return res;
}

NTSTATUS
xenbus_read_domain_id(xenbus_transaction_t xbt, PCSTR prefix,
                      PCSTR node, DOMAIN_ID *Res)
{
    NTSTATUS res;
    char *buf;
    size_t len;
    ULONG64 number;
    int err;

    *Res = null_DOMAIN_ID();

    res = xenbus_read_bin(xbt, prefix, node, &buf, &len);
    if (!NT_SUCCESS(res))
        return res;
    number = xm_strtoll(buf, len, 10, &err);
    if (number >= DOMID_FIRST_RESERVED) {
        res = STATUS_INVALID_PARAMETER;
        xenbus_fail_transaction(xbt, res);
    } else {
        *Res = wrap_DOMAIN_ID((int)number);
    }
    XmFreeMemory(buf);
    return res;
}

/* Walk the transaction list and abort them all with STATUS_RETRY.
 * Preserve the error code if they've already been aborted, though. */
/* Caller is expected to arrange that nobody else is accessing any
 * transaction when this is invoked. */
static void
abort_all_transactions(void)
{
    struct xenbus_transaction *xbt;
    unsigned count;

    if (AustereMode)
        TraceNotice(("Aborting transactions.\n"));
    count = 0;
    for (xbt = head_open_transaction; xbt; xbt = xbt->next) {
        if (NT_SUCCESS(xbt->status))
            xbt->status = STATUS_RETRY;
        count++;
        if (count % 10000 == 0)
            TraceWarning(("Suspiciously large number of xenbus transactions open (%d)\n",
                          count));
    }
}

static void
reset_requests(void)
{
    struct xenbus_pending_req *head_incomp, *tail_incomp,
        *head_comp, *tail_comp;
    struct xenbus_pending_req *p, *n;
    unsigned comp, incomp;

    /* Decide which requests need retransmission.  Anything which
       doesn't have a response needs to be retransmitted.  Things
       with partial responses also need to be retransmitted.

       This isn't entirely trivial, because xenstore could in
       principle have completed requests out of order.  We therefore
       need to segregate the bits of the pending list which are
       complete from the bits which aren't, and make sure that the
       complete requests are before the incomplete ones. */
    head_incomp = tail_incomp = head_comp = tail_comp = NULL;
    incomp = comp = 0;
    for (p = head_pending_xenbus_req; p; p = n) {
        n = p->next;
        p->next = NULL;
        if (p->xenbus_replied) {
            p->prev = tail_comp;
            if (tail_comp)
                tail_comp->next = p;
            else
                head_comp = p;
            tail_comp = p;
            comp++;
        } else {
            /* Reset transmission. */
            p->next_tx_seg = p->tx_io;
            p->tx_sg_off = 0;

            p->prev = tail_incomp;
            if (tail_incomp)
                tail_incomp->next = p;
            else
                head_incomp = p;
            tail_incomp = p;
            incomp++;
        }
    }

    TraceVerbose(("%s: %d complete, %d incomplete\n", __FUNCTION__, comp, incomp));

    /* Now splice the two lists together. */
    if (tail_comp)
        tail_comp->next = head_incomp;
    if (head_incomp)
        head_incomp->prev = tail_comp;

    /* Use the list we built as our pending request list */
    if (head_comp)
        head_pending_xenbus_req = head_comp;
    else
        head_pending_xenbus_req = head_incomp;

    if (tail_incomp)
        tail_pending_xenbus_req = tail_incomp;
    else
        tail_pending_xenbus_req = tail_comp;

    /* Restart transmission from here. */
    current_tx_req = head_incomp;

    /* We're not currently receiving anything */
    current_rx_req = NULL;
}

static void
reset_watches(void)
{
    struct xenbus_watch_handler *wh;
    unsigned count;

    /* None of our watches are registered with xenstore. */
    count = 0;
    for (wh = head_watch_handler; wh; wh = wh->next) {
        wh->currently_registered = FALSE;
        count++;
    }

    TraceVerbose(("%s: %d unregistered\n", __FUNCTION__, count));
}

static void
XenbusResumeEarly(void *ignore, SUSPEND_TOKEN token)
{
    UNREFERENCED_PARAMETER(ignore);
    UNREFERENCED_PARAMETER(token);

    abort_all_transactions();

    reset_requests();
    reset_watches();

    /* Prod the DPC */
    if (!is_null_EVTCHN_PORT(xenbus_evtchn))
        EvtchnRaiseLocally(xenbus_evtchn);
}

static void
reregister_all_watches(void)
{
    struct xenbus_watch_handler *wh;
    KIRQL irql;

retry:
    acquire_lock_safe(&watch_lock, &irql);
    for (wh = head_watch_handler; wh; wh = wh->next) {
        if (wh->currently_registered || wh->faulty)
            continue;
        get_watch_handler(wh);
        release_lock_safe(&watch_lock, irql);

        if (register_watch_handler(wh) < 0) {
            /* Can't re-register the watch.  This usually indicates
               that it's non-sensical in some way e.g. a watch on
               something to which we no longer have access.  Fire it
               one last time in the hope that our user can fix it
               up. */
            TraceVerbose(("Failed to register watch on %s.\n", wh->path));
            wh->faulty = TRUE;
            xenbus_trigger_watch(wh);
        } else {
            TraceVerbose(("Re-registered watch on %s.\n", wh->path));
            wh->currently_registered = TRUE;
        }

        put_watch_handler(wh);
        /* Dropped lock -> need to rescan the list */
        goto retry;
    }
    release_lock_safe(&watch_lock, irql);
}

void
xenbus_recover_from_s3(void)
{
    struct xenbus_watch_handler *wh;
    KIRQL irql;

    /* This is a bit skanky.  We may or may not have lost all of our
     * watches across an S3, so we walk the watch list and unregister
     * all of them, then do a reregister_all_watches().
     */
    acquire_lock_safe(&watch_lock, &irql);
    for (wh = head_watch_handler; wh; wh = wh->next)
        wh->needs_s3_recover = TRUE;

retry:
    for (wh = head_watch_handler; wh; wh = wh->next) {
        if (!wh->needs_s3_recover || wh->faulty)
            continue;
        get_watch_handler(wh);
        wh->needs_s3_recover = FALSE;
        release_lock_safe(&watch_lock, irql);

        unregister_watch_with_xenstored(wh);

        acquire_lock_safe(&watch_lock, &irql);
        wh->currently_registered = FALSE;
        _put_watch_handler(wh);
        /* Dropped lock -> need to rescan the list */
        goto retry;
    }
    release_lock_safe(&watch_lock, irql);

    reregister_all_watches();
}

static void
XenbusResumeLate(void *ignore, SUSPEND_TOKEN token)
{
    UNREFERENCED_PARAMETER(ignore);
    UNREFERENCED_PARAMETER(token);

    reregister_all_watches();
}

static void
xenbus_evtchn_handler(void *ctxt)
{
    KIRQL irql;
    UNREFERENCED_PARAMETER(ctxt);
    irql = acquire_irqsafe_lock(&xenbus_dpc_lock);
    KeInsertQueueDpc(&xenbus_dpc, NULL, NULL);
    release_irqsafe_lock(&xenbus_dpc_lock, irql);
}

static NTSTATUS
watch_thread_cb(struct xm_thread *t, void *ignore)
{
    KIRQL irql;
    struct xenbus_watch_handler *xwh;
    PLIST_ENTRY next;

    UNREFERENCED_PARAMETER(ignore);

    while (XmThreadWait(t) >= 0) {
        /* Careful: we release the lock in the main loop when running
           the handler. */
        acquire_lock_safe(&watch_lock, &irql);
        while (!IsListEmpty(&pending_watches_list)) {
            next = RemoveHeadList(&pending_watches_list);
            xwh = CONTAINING_RECORD(next, struct xenbus_watch_handler,
                                    pending_list);
            XM_ASSERT(xwh->queued);
            xwh->queued = FALSE;

            release_lock_safe(&watch_lock, irql);

            irql = acquire_irqsafe_lock(&current_watch_handler_lock);
            current_watch_handler = xwh;
            release_irqsafe_lock(&current_watch_handler_lock, irql);

            KeQuerySystemTime(&xwh->cb_start);

            TraceVerbose(("invoking watch handler: %s.\n", xwh->cb_name));
            xwh->cb(xwh->ctxt);

            irql = acquire_irqsafe_lock(&current_watch_handler_lock);
            current_watch_handler = NULL;
            release_irqsafe_lock(&current_watch_handler_lock, irql);

            /* Release the reference which we picked up when the
               handler was queued. */
            put_watch_handler(xwh);

            acquire_lock_safe(&watch_lock, &irql);
        }
        release_lock_safe(&watch_lock, irql);
    }

    TraceWarning(("Watch thread exitting.\n"));
    return STATUS_SUCCESS;
}

static void
xenbus_debug_dump_pending_req(const struct xenbus_pending_req *xpr)
{
    const struct xenbus_sg_segment *xss;
    const struct xsd_sockmsg *msg_hdr;

    TraceInternal(("Pending req %p\n", xpr));
    TraceInternal(("Next tx %p + %d\n", xpr->next_tx_seg, xpr->tx_sg_off));
    for (xss = xpr->tx_io; xss != NULL; xss = xss->next) {
        if (xss == xpr->next_tx_seg)
            TraceInternal(("<%d %p + %d>\n", xss->len, xss->data,
                         xpr->tx_sg_off));
        else
            TraceInternal((" %d %p \n", xss->len, xss->data));
    }
    TraceInternal(("reply_payload %d, reply_buf_size %d, reply_recvd %d\n",
                 xpr->reply_payload, xpr->reply_buf_size,
                 xpr->reply_payload_received));
    TraceInternal(("xenbus_replied %d, id %d.\n", xpr->xenbus_replied,
                 xpr->id));
    if (xpr->tx_io && xpr->tx_io->len >= sizeof(*msg_hdr)) {
        msg_hdr = xpr->tx_io->data;
        TraceInternal(("Header: type %d, req_id %d, tx_id %d, len %d\n",
                     msg_hdr->type, msg_hdr->req_id, msg_hdr->tx_id,
                     msg_hdr->len));
    }
}

static void
xenbus_debug_dump(void *ignore)
{
    KIRQL irql;
    NTSTATUS stat;
    BOOLEAN locked;
    struct xenbus_pending_req *xpr;

    UNREFERENCED_PARAMETER(ignore);

    /* We might have crashed while holding the current handler lock,
       in which case we'll deadlock if we try to acquire it again.  Do
       what we can. */
    stat = try_acquire_irqsafe_lock(&current_watch_handler_lock, &irql);
    if (!NT_SUCCESS(stat)) {
        TraceInternal(("Could not acquire current_watch_handler_lock, current_watch %p.\n",
                     current_watch_handler));
    } else {
        if (current_watch_handler) {
            LARGE_INTEGER now;
            ULONGLONG ms;

            KeQuerySystemTime(&now);
            ms = (now.QuadPart - current_watch_handler->cb_start.QuadPart) / 10000ull;

            TraceInternal(("Processing watch handler: %s\n", current_watch_handler->cb_name));
            TraceInternal(("On %s for %llums\n", current_watch_handler->path, ms));
        } else {
            TraceInternal(("Xenbus watch thread idle\n"));
        }
        release_irqsafe_lock(&current_watch_handler_lock, irql);
    }

    TraceInternal(("head_pending_xenbus_req %p, tail_pending_xenbus_req %p\n",
                 head_pending_xenbus_req, tail_pending_xenbus_req));
    TraceInternal(("current_tx_req %p, current_rx_req %p\n",
                 current_tx_req, current_rx_req));
    TraceInternal(("head_open_transaction %p\n", head_open_transaction));

    /* Try to acquire the ring lock.  Fail if it's already held, so
       that we don't risk a deadlock. */
    locked = try_acquire_ring_lock(&irql);
    if (locked) {
        /* Got it. */
        for (xpr = head_pending_xenbus_req; xpr != NULL; xpr = xpr->next) {
            TraceInternal(("Request %p\n", xpr));
            if (xpr == current_tx_req)
                TraceInternal(("<current tx request>\n"));
            xenbus_debug_dump_pending_req(xpr);
        }
        if (current_rx_req) {
            TraceInternal(("RX req:\n"));
            xenbus_debug_dump_pending_req(current_rx_req);
        }

        if (shared_buf) {
            TraceInternal(("shared_buf %p\n", shared_buf));
            TraceInternal(("req_cons %x, req_prod %x, rsp_cons %x, rsp_prod %x\n",
                         shared_buf->req_cons, shared_buf->req_prod,
                         shared_buf->rsp_cons, shared_buf->rsp_prod));
        }

        if (locked)
            release_ring_lock(irql);
    } else {
        TraceInternal(("Failed to acquire ring lock.\n"));
    }
}

static BOOLEAN XenbusStarted = FALSE;

/* Initialise xenbus.  Note that this is called from
   recover-from-hibernate as well as normal initialisation, so we may
   have outstanding watches and transactions. */
/* XXX the error paths leak */
NTSTATUS
XenevtchnInitXenbus(void)
{
    static struct SuspendHandler *esh;
    static struct SuspendHandler *lsh;
    PHYSICAL_ADDRESS phys_addr;
    PFN_NUMBER mfn;
    NTSTATUS status;
    EVTCHN_PORT port;
    BOOLEAN locked;
    KIRQL irql;

    if (!AustereMode && XenbusStarted) {
        TraceVerbose(("xenbus already started\n"));
        return STATUS_SUCCESS;
    }

    KeInitializeSpinLock(&watch_lock);
    KeInitializeSpinLock(&transaction_lock);
    KeInitializeDpc(&xenbus_dpc, xenbus_dpc_func, NULL);

    /* These two variables are used for enabling and disabling new operations
     * by the xenbus driver.  They are modified under lock.
     * MTC: This code is needed for Marathon Technologies' Lockstep Feature.
     */    
    KeInitializeSpinLock(&xenbus_operation_lock);
    allow_new_xenbus_operation = TRUE;
    allow_xenbus_watch_operation = TRUE;
    xenbus_outstanding_ctr = 0;

    if (is_null_EVTCHN_DEBUG_CALLBACK(xenbus_debug_callback) &&
        !AustereMode)
        xenbus_debug_callback =
            EvtchnSetupDebugCallback(xenbus_debug_dump, NULL);

    /* Only useful when we're coming back from hibernate, harmless
       when doing initial startup. */
    abort_all_transactions();

    reset_requests();
    reset_watches();

    if (AustereMode)
        TraceNotice(("Xenbus init phase 1 done.\n"));

    /* Map the shared ring, if necessary. */
    mfn = HvmGetParameter(HVM_PARAM_STORE_PFN);
    phys_addr.QuadPart = (ULONG64)mfn << 12;
    if (AustereMode) {
        PHYSICAL_ADDRESS pa;

        /* We don't like using MmMapIoSpace() in austere mode, because
           it can easily lock up if you're writing out a memory dump
           and you crashed in the memory manager.  In this case, we
           use an austere heap page and swizzle the P2M so that it
           points at the right place. */
        old_shared_buf = XmAllocatePhysMemory(PAGE_SIZE, &pa);
        if (old_shared_buf == NULL) {
            TraceError(("No memory for xenbus ring mapping!\n"));
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        /*
         * Xen 4.3: We have never had XENMAPSPACE_physical in XC;
         * presumably it is a XenServer patch from the dawn of time.
         * Since it has been harmelessly failing forever, we are just
         * leaving it alone.
         */
        /* Make it really obvious if Xen returns success on the
           swizzle but doesn't actually do it. */
        old_shared_buf->req_cons = 0x01020304;
        /* Xen 4.3: This crazy memspace is not present, don't do this. */
        /*if (AddPageToPhysmap((PFN_NUMBER)(pa.QuadPart >> PAGE_SHIFT),
                             XENMAPSPACE_physical,
                             (unsigned long)mfn) < 0) {*/
            TraceWarning(("Page swizzle to map xenbus ring failed, falling back to dynamic map...\n"));
            XmFreeMemory(old_shared_buf);
            old_shared_buf = MmMapIoSpace(phys_addr, PAGE_SIZE, MmCached);
            if (old_shared_buf == NULL) {
                TraceError (("Failed to map xenstore area.\n"));
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        /*} else {
            TraceNotice(("Mapped xenbus ring via P2M swizzle.\n"));
            if (old_shared_buf->req_cons == 0x01020304)
                TraceWarning(("Xen returned success on P2M swizzle but didn't actually do anything!\n"));
        }*/
    } else {
        if (old_shared_buf == NULL) {
            old_shared_buf = MmMapIoSpace(phys_addr, PAGE_SIZE, MmCached);
            if (old_shared_buf == NULL) {
                TraceError (("Failed to map xenstore area.\n"));
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
    }

    if (AustereMode)
        TraceNotice(("Xenbus init phase 2 done.\n"));

    if (!AustereMode && !watch_thread) {
        InitializeListHead(&pending_watches_list);
        watch_thread = XmSpawnThread(watch_thread_cb, NULL);
        if (!watch_thread) {
            TraceError(("Failed to start watch thread.\n"));
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (!esh)
        esh = EvtchnRegisterSuspendHandler(XenbusResumeEarly,
                                           NULL,
                                           "XenbusResumeEarly",
                                           SUSPEND_CB_EARLY);
    if (!lsh && !XenPVFeatureEnabled(DEBUG_MTC_PROTECTED_VM))
        lsh = EvtchnRegisterSuspendHandler(XenbusResumeLate,
                                           NULL,
                                           "XenbusResumeLate",
                                           SUSPEND_CB_LATE);
    if (AustereMode)
        TraceNotice(("Xenbus init phase 3 done.\n"));

    /* Re-register the event channel handler.  These aren't preserved
       across hibernation. */
    port =
        EvtchnRegisterHandler((int)HvmGetParameter(HVM_PARAM_STORE_EVTCHN),
                              xenbus_evtchn_handler,
                              NULL);

    if (AustereMode)
        TraceNotice(("Xenbus init phase 4 done.\n"));

    /* Okay, we're ready to go.  Make the ring available. */
    locked = acquire_ring_lock(&irql);

    shared_buf = old_shared_buf;
    old_shared_buf = NULL;
    xenbus_evtchn = port;

    if (locked)
        release_ring_lock(irql);

    if (AustereMode)
        TraceNotice(("Xenbus init phase 5 done.\n"));

    if (!AustereMode)
        reregister_all_watches();

    if (!AustereMode) {
        CHAR    *ProductString = NULL;
        BOOLEAN ProductStringPresent = FALSE;

        status = xenbus_read(XBT_NIL,
                             "/mh/XenSource-TM_XenEnterprise-TM",
                             &ProductString);
        if (NT_SUCCESS(status)) {
            if (!strcmp(ProductString,
                        "XenSource(TM) and XenEnterprise(TM) are registered trademarks of XenSource Inc."))
                ProductStringPresent = TRUE;

            XmFreeMemory(ProductString);
            ProductString = NULL;
        }
        XM_ASSERT(ProductString == NULL);

        if (!ProductStringPresent) {
            if (!XenPVFeatureEnabled(DEBUG_DISABLE_LICENSE_CHECK)) {
                TraceCritical(("XenEnterprise product string is not present\n"));
                if (watch_thread) {
                    XmKillThread(watch_thread);
                    watch_thread = NULL;
                }
                CleanupXenbus();
                return STATUS_UNSUCCESSFUL;
            } else {
                TraceNotice(("XenEnterprise product string is not present\n"));
            }
        } else {
            TraceNotice(("XenEnterprise product string is present\n"));
        }
    }

    if (AustereMode)
        TraceNotice(("Xenbus init phase 6 done.\n"));

    XenbusStarted = TRUE;

    return STATUS_SUCCESS;
}

VOID
CleanupXenbus(void)
{
    BOOLEAN locked;
    KIRQL irql;

    XenbusStarted = FALSE;

    /* This is sometimes called with interrupts off, but never from an
       actual interrupt handler, because scsiport is funny like that.
       Unfortunately, we have no good way of telling the difference
       between interrupt-handler and interrupts-off at run time. */
    locked = acquire_ring_lock(&irql);

    if (!is_null_EVTCHN_PORT(xenbus_evtchn)) {
        /* We don't close the event channel from here, since if we do
           then we can't reconnect later (e.g. for hibernation or
           crash dump).  We don't even free the handler, since we're
           at device IRQL.  If we're going down for hibernate, it'll
           be freed automatically when we come back; if we're going
           down for system halt, we don't care about leaking
           memory. */
        xenbus_evtchn = null_EVTCHN_PORT();
    }

    if (locked)    
        release_ring_lock(irql);
}

const CHAR *
XenbusStateName(
    IN  XENBUS_STATE    State
    )
{
    ULONG               Code = unwrap_XENBUS_STATE(State);

#define _XENBUS_STATE_NAME(_Code)       \
        case _XENBUS_STATE_ ## _Code:   \
            return #_Code;

    switch (Code) {
    _XENBUS_STATE_NAME(INITIALISING);
    _XENBUS_STATE_NAME(INITWAIT);
    _XENBUS_STATE_NAME(INITIALISED);
    _XENBUS_STATE_NAME(CONNECTED);
    _XENBUS_STATE_NAME(CLOSING);
    _XENBUS_STATE_NAME(CLOSED);
    default:
        return "UNKNOWN";
    }

#undef  _XENBUS_STATE_NAME
}

XENBUS_STATE
__XenbusWaitForBackendStateChange(
    const char *caller,
    const char *backend_path,
    XENBUS_STATE state,
    PLARGE_INTEGER timeout,
    SUSPEND_TOKEN token)
{
    LARGE_INTEGER now, deadline, *deadp, short_timeout;
    struct xenbus_watch_handler *watch = NULL;
    XENBUS_STATE backend_state;
    KEVENT event;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(token);

    if (timeout) {
        if (timeout->QuadPart >= 0) {
            deadline = *timeout;
        } else {
            KeQuerySystemTime(&now);
            deadline.QuadPart = now.QuadPart - timeout->QuadPart;
        }
        deadp = &deadline;
    } else {
        /* Ick.  xenvbd uses this function from its HwFindAdapter
           callback, which, despite what the scsiport documentation
           may think, is invoked before the interrupt is hooked up, so
           watches don't work so well.  We therefore give
           KeWaitForSingleObject() a five second timeout and retry if
           it fails. */
        short_timeout.QuadPart = -1     // Relative
                               * 10     // to us
                               * 1000   // to ms
                               * 1000   // to s
                               * 5;
        deadp = &short_timeout;
    }

    if (!AustereMode && KeGetCurrentIrql() < DISPATCH_LEVEL) {
        KeInitializeEvent(&event, NotificationEvent, FALSE);
        if (KeGetCurrentIrql() > APC_LEVEL &&
            (!timeout || timeout->QuadPart != 0)) {
            TraceWarning(("%s: waiting for backend at irql %d (%s).\n",
                          caller, KeGetCurrentIrql(), backend_path));
        } else {
            char *backend_state_path;
            backend_state_path = Xmasprintf("%s/state", backend_path);
            if (!backend_state_path)
                return null_XENBUS_STATE();
            watch = xenbus_watch_path_event(backend_state_path,  &event);
            XmFreeMemory(backend_state_path);
            if (!watch)
                return null_XENBUS_STATE();
        }
    }

    for(;;) {
        status = xenbus_read_state(XBT_NIL, backend_path, "state",
                                   &backend_state);
        if (!NT_SUCCESS(status) ||
            !same_XENBUS_STATE(backend_state, state))
            break;
        if (watch) {
            if (KeWaitForSingleObject(&event, Executive, KernelMode,
                                      FALSE, deadp) != STATUS_SUCCESS) {
                TraceWarning(("%s: timed out in XenbusWaitForBackendStateChange: "
                              "%s in state %s; retry.\n",
                              caller,
                              backend_path,
                              XenbusStateName(backend_state)));
            }
            KeClearEvent(&event);
        } else {
            /* Try to avoid killing other domains and xenstored by
               backing off for 10ms. */
            DescheduleVcpu(10);
        }
        if (timeout) {
            KeQuerySystemTime(&now);
            if (now.QuadPart > deadp->QuadPart)
                break;
        }
    }

    if (watch)
        xenbus_unregister_watch(watch);

    return backend_state;
}

XENBUS_STATE
__XenbusWaitForBackendStateChangeAnonymous(
    const char *backend_path,
    XENBUS_STATE state,
    PLARGE_INTEGER timeout,
    SUSPEND_TOKEN token)
{
    return __XenbusWaitForBackendStateChange("unknown", backend_path, state, timeout, token);
}

/* Wait for xenbus to become available.  We assume that the last stage
   of initialising the xsapi.h APIs is to set up xenbus_evtchn. */
BOOLEAN
xenbus_await_initialisation(void)
{
    BOOLEAN locked;
    KIRQL irql;

    XM_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
    if (!XenPVEnabled())
        return FALSE;

    /* MTC: Block initialization until driver is turned back on */
    acquire_lock_safe(&xenbus_operation_lock, &irql);
    if (!allow_new_xenbus_operation){
        release_lock_safe(&xenbus_operation_lock, irql);
        return FALSE;
    }
    release_lock_safe(&xenbus_operation_lock, irql);

    /* Bit of a hack: just back off for 100ms if xenbus isn't
       available yet.  This should only happen when loading drivers,
       and even then it should be *very* rare. */
    locked = acquire_ring_lock(&irql);
    while (is_null_EVTCHN_PORT(xenbus_evtchn)) {
        LARGE_INTEGER l;

        if (locked)
            release_ring_lock(irql);

        l.QuadPart = -1000000;
        TraceVerbose(("Waiting for xenbus...\n"));
        KeDelayExecutionThread(KernelMode, FALSE, &l);

        locked = acquire_ring_lock(&irql);
    }

    if (locked)
        release_ring_lock(irql);

    return TRUE;
}

/* This routine is to be invoked whenever the xenbus driver needs to be
 * turned off so it won't accept any more xenbus operations.
 * It must guarantee that no inflight xenbus operations to xenstore are 
 * taking place so that they won't be completed on the target of a migration, 
 * which would lead to divergence.
 * The routine can be called with IRQL <= DISPATCH.  At passive level, it
 * allows the outstanding xenbus operations to be completed by waiting for
 * the counter to be reach 0.
 * When the code is called at a high IRQL, the routine can't guarantee
 * that all outstanding xenbus operations have completed.  This may be
 * OK if the caller knows that no outstanding operations are possible.
 * MTC: This code is needed for Marathon Technologies' Lockstep Feature.
 */
void
xenbus_driver_off(void)
{
    LARGE_INTEGER delay;
    KIRQL irql;
    BOOLEAN print_warning = FALSE;

    TraceVerbose (("xenbus_driver_off: NOT allowing new transactions\n"));
    
    acquire_lock_safe(&xenbus_operation_lock, &irql);

    /* No new operations can be issued from now on.*/
    allow_new_xenbus_operation = FALSE;

    /* Ignore incoming watch events. */
    allow_xenbus_watch_operation = FALSE;

    /* Wait for the transactions in progress to complete */
    while(xenbus_outstanding_ctr && !print_warning) {
        
        release_lock_safe(&xenbus_operation_lock, irql);

        /* Wait for all threads to finish their transactions.
         * If we are being called in at high IRQL, then we can't
         * wait here so it is up to the caller to make sure that
         * no transactions can be outstanding!
         */ 
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            /* Wait 100ms and check again */
            delay.QuadPart = -1000000;
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
        else
        {
            print_warning = TRUE;
        }
        acquire_lock_safe(&xenbus_operation_lock, &irql);
    }
    

    release_lock_safe(&xenbus_operation_lock, irql);

    if (print_warning) {
        TraceWarning(("xenbus_driver_off() with operations still outstanding!\n"));
    } else {
        TraceVerbose (("xenbus_driver_off: all outstanding transactions now done\n"));
    }
}


/* Enables the xenbus driver so that new transactions can be used.
 * MTC: This code is needed for Marathon Technologies' Lockstep Feature.
 */
void
xenbus_driver_on(void)
{
    allow_new_xenbus_operation=TRUE;
    TraceVerbose (("xenbus_driver_on: allowing new transactions\n"));
}

/* Get xenbus driver state 
 * MTC: This code is needed for Marathon Technologies' Lockstep Feature.
 */
BOOLEAN
xenbus_get_allow_new_operation_state(void)
{
    TraceInfo (("Returning Xenbus Driver state\n"));
    return allow_new_xenbus_operation;
}

/* Allow drivers to become divergent by enabling xenbus
 * operations and re-registering all watches.
 * MTC: This code is needed for Marathon Technologies' Lockstep Feature.
 */
void
xenbus_mtc_allow_divergency(void)
{
    SUSPEND_TOKEN token = null_SUSPEND_TOKEN();
    TraceInfo (("xenbus is allowing divergency\n"));
    xenbus_driver_on();
    allow_xenbus_watch_operation=TRUE;
    /* Reregister all xenstore watches that we previously prevented.
     * Pass in bogus values since we know they are not used.
     */ 
    XenbusResumeLate(NULL, token);
    
}
