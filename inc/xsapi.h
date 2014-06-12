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

/* All of the supported APIs exported by xevtchn.sys in one convenient
 * place.  There are a bunch of others which are special-case hooks
 * for xenvbd and xennet, but they shouldn't be used by anyone
 * else. */
#ifndef XSAPI_H__
#define XSAPI_H__

#include "wrapper_types.h"
#include "types.h"
#include "specstrings.h"

#ifndef XSAPI
#define XSAPI DECLSPEC_IMPORT
#endif

/* Described later, under ``suspend handlers''. */
MAKE_WRAPPER_PUB(SUSPEND_TOKEN)

/* The state of either end of the Xenbus, i.e. the current communication
   status of initialisation across the bus.  States here imply nothing about
   the state of the connection between the driver and the kernel's device
   layers.  */
MAKE_WRAPPER_PUB(XENBUS_STATE)
MAKE_WRAPPER_PRIV(XENBUS_STATE, int)
#define _XENBUS_STATE_INITIALISING 1
#define XENBUS_STATE_INITIALISING wrap_XENBUS_STATE(_XENBUS_STATE_INITIALISING)
/* Finished early initialisation, but waiting for information from the
   peer or hotplug scripts. */
#define _XENBUS_STATE_INITWAIT 2
#define XENBUS_STATE_INITWAIT wrap_XENBUS_STATE(_XENBUS_STATE_INITWAIT)
/* Initialised and waiting for a connection from the peer. */
#define _XENBUS_STATE_INITIALISED 3
#define XENBUS_STATE_INITIALISED wrap_XENBUS_STATE(_XENBUS_STATE_INITIALISED)
#define _XENBUS_STATE_CONNECTED 4
#define XENBUS_STATE_CONNECTED wrap_XENBUS_STATE(_XENBUS_STATE_CONNECTED)
/* The device is being closed due to an error or an unplug event. */
#define _XENBUS_STATE_CLOSING 5
#define XENBUS_STATE_CLOSING wrap_XENBUS_STATE(_XENBUS_STATE_CLOSING)
#define _XENBUS_STATE_CLOSED 6
#define XENBUS_STATE_CLOSED wrap_XENBUS_STATE(_XENBUS_STATE_CLOSED)

/* Compare two XENBUS_STATEs.  Returns TRUE if @a and @b represent
 * the same xenbus state, or if they're both null, and FALSE otherwise.
 *
 * Can be called at any IRQL holding any combination of locks.
 */
static __inline BOOLEAN
same_XENBUS_STATE(XENBUS_STATE a, XENBUS_STATE b)
{
    if (unwrap_XENBUS_STATE(a) == unwrap_XENBUS_STATE(b))
        return TRUE;
    else
        return FALSE;
}

/* ----------------------- Initialisation -------------------------- */
/* Wait for the PV drivers to finish initialisation.  Returns TRUE
 * if the drivers are now available, or FALSE if initialisation
 * failed.
 *
 * Clients should wait for initialisation when they first load and
 * after recovering from hibernation.  They do not have to wait
 * following dom0-driven suspend/resume.
 *
 * Clients should not call any other APIs defined in this header until
 * this has returned TRUE.
 *
 * Call at PASSIVE_LEVEL.
 */
XSAPI BOOLEAN xenbus_await_initialisation(void);

/* ----------------------- Domain ID type -------------------------- */
/* A special type for domain IDs.  The aim here is to make it obvious
 * if someone's assumed that backends are always in dom0. */
MAKE_WRAPPER_PUB(DOMAIN_ID)
__MAKE_WRAPPER_PRIV(DOMAIN_ID, int)
/* Take an int and turn it into a DOMAIN_ID.  The 0xf001 is to make
 * uninitialised domain ids obvious.  I specifically don't want an
 * uninitialised id to show up as 0, since that's almost, but not
 * quite, always the right answer, so is unlikely to get spotted. */
static __inline DOMAIN_ID wrap_DOMAIN_ID(int x)
{
    return __wrap_DOMAIN_ID(x ^ 0xf001);
}
/* Given a DOMAIN_ID, return the integer domain id */
static __inline int unwrap_DOMAIN_ID(DOMAIN_ID x)
{
    return __unwrap_DOMAIN_ID(x) ^ 0xf001;
}
/* Construct a DOMAIN_ID for dom0. */
#define DOMAIN_ID_0() wrap_DOMAIN_ID(0)


/* --------------------------- Xenbus ------------------------------ */
/* All xenbus operations can, at present, be invoked at IRQL <=
 * DISPATCH_LEVEL.  I'd be happier if I could restrict that to
 * PASSIVE_LEVEL, though. */

/* Any operations performed inside a transaction will be exposed to
 * other domains atomically when the transaction ends (assuming it was
 * successful).  If any operation inside a transaction fails, the
 * whole transaction fails with the same error code.  These are not
 * the semantics which most people expect, and they are not those
 * exposed by the Linux equivalents of this API, but they do
 * drastically simplify error handling logic in most callers of it.
 *
 * xenbus_read() and xenbus_ls() operations performed inside a
 * transaction can, sometimes, invent results which have never
 * appeared in the store.  If this happens, the transaction will
 * always fail to commit, returning either STATUS_RETRY if no other
 * error occurs or an appropriate error value if one does.
 *
 * Most operations can be performed with a null transaction, including
 * xenbus_transaction_end(), in which case they return
 * STATUS_INSUFFICIENT_RESOURCES.
 */
MAKE_WRAPPER_PUB(xenbus_transaction_t)
struct xenbus_transaction;
__MAKE_WRAPPER_PRIV(xenbus_transaction_t, struct xenbus_transaction *)

/* The nil transaction.  Operations performed in this transaction are
 * exposed immediately and do not need an explicit transaction_end.
 * They are still atomic, however.
 *
 * Note that this is *not* the null transaction, which is reserved
 * for error situations.
 */
#define XBT_NIL __wrap_xenbus_transaction_t((struct xenbus_transaction *)1)

/* Check whether a transaction is XBT_NIL.  Returns TRUE if @xbt is
 * XBT_NIL, and FALSE otherwise.
 *
 * @xbt can be null, nil, or a valid transaction.
 *
 * Added in XE 4.1.
 */
static __inline BOOLEAN
is_nil_xenbus_transaction_t(xenbus_transaction_t xbt)
{
    if (__unwrap_xenbus_transaction_t(xbt) ==
        (struct xenbus_transaction *)1)
        return TRUE;
    else
        return FALSE;
}


/* Start a new transaction.  Returns the new transaction at *@Res.
 * This function always succeeds, and the returned transaction must
 * always be finished by xenbus_transaction_end().
 *
#ifdef XSAPI_LEGACY_XENBUS_TRANSACTION_START_RETURNS_NTSTATUS
 * The return value is somewhat subtle.  xenbus_transaction_start()
 * will always open a new transaction, and must therefore always be
 * followed by a call to xenbus_transaction_end().  However,
 * xenbus_transaction_start() may sometimes be able to detect that the
 * transaction is in some sense doomed to fail, and in that case it
 * will return a non-NT_SUCCESS() value which is the expected result
 * of trying to call xenbus_transaction_end() and committing the
 * transaction.  This is intended to allow the caller to optimise by
 * avoiding any time-consuming actions which will then be discarded
 * when the transaction aborts.  The caller is never required to look
 * at the return value of this function to achieve simple
 * correctness.
#endif
 */
XSAPI NTSTATUS __xenbus_transaction_start_ntstatus(__out xenbus_transaction_t *Res);
XSAPI VOID __xenbus_transaction_start_void(__in const char *caller, __out xenbus_transaction_t *Res);
#ifdef XSAPI_LEGACY_XENBUS_TRANSACTION_START_RETURNS_NTSTATUS
#define xenbus_transaction_start(_xbt) __xenbus_transaction_start_ntstatus(_xbt)
#else
#define xenbus_transaction_start(_xbt) __xenbus_transaction_start_void(__FUNCTION__, (_xbt))
#endif

/* End a transaction.  If @abort is 0, the transaction is committed;
 * otherwise, it is aborted, and no operations performed under it
 * will be visible to other users of the store.  This can return
 * STATUS_RETRY if some other domain made a conflicting update to
 * the store, in which case the caller should try the transaction
 * again.
 *
 * Even when this returns failure, the transaction is still finished,
 * and should not be used again.
 *
 * @t can be null but not nil.
 */
__checkReturn XSAPI NTSTATUS __xenbus_transaction_end_anonymous(xenbus_transaction_t t, int abort);
__checkReturn XSAPI NTSTATUS __xenbus_transaction_end(const char *caller,
                                                      xenbus_transaction_t t,
                                                      int abort);
#define xenbus_transaction_end(_xbt, _abort) \
        __xenbus_transaction_end(__FUNCTION__, (_xbt), (_abort))

/* XXX These should take a prefix and a node, rather than just a
   path. */

/* Write the nul-terminated string @data to @path as part of transaction
 * @xbt.
 *
 * @xbt can be null, nil, or a valid transaction.
 */
XSAPI NTSTATUS xenbus_write(xenbus_transaction_t xbt, PCSTR path, PCSTR data);

/* Write @size bytes from @data to @path/@node as part of transaction
 * @xbt.
 *
 * @path, @node, and @data must point at valid globally-mapped
 * non-pageable memory.
 *
 * @data can contain arbitrary binary data, including embedded nuls.
 *
 * @xbt can be null, nil, or a valid transaction.
 *
 * Added in XE 4.1
 */
XSAPI NTSTATUS xenbus_write_bin(xenbus_transaction_t xbt, PCSTR path,
                                PCSTR node, const void *data, size_t size);

/* Read a nul-terminated string from @path under transaction @xbt.
 * The result is returned as a nul-terminated string at *@Res, and
 * should be freed with XmFreeMemory() when you're finished with
 * it.
 *
 * @path must point at valid globally-mapped non-pageable memory.  The
 * buffer returned through *@Res will be non-pageable and globally
 * mapped.
 *
 * @xbt can be null, nil, or a valid transaction.
 */
XSAPI NTSTATUS xenbus_read(xenbus_transaction_t xbt, PCSTR path,
                           __out PSTR *Res);

/* Read arbitrary data from @path/@node under transaction @xbt.  The
 * result is returned as a newly-allocated buffer at *@Res, and should
 * be freed with XmFreeMemory() when you're finished with it.  The
 * length of the buffer is returned in *@size.
 *
 * Note that *@Res is not guaranteed to be nul-terminated, and can
 * contain embedded nuls.  This is different from xenbus_read().
 *
 * @path and @node must point at valid globally-mapped non-pageable
 * memory.  The buffer returned through *@Res will be non-pageable and
 * globally mapped.
 *
 * @xbt can be null, nil, or a valid transaction.
 */
XSAPI NTSTATUS xenbus_read_bin(xenbus_transaction_t xbt, PCSTR path,
                               PCSTR node, __out void **Res,
                               __out size_t *size);

/* List the sub-nodes of node @path under transaction @xbt.  The
 * result is returned as a NULL-terminated array of nul-terminated
 * strings at *@Res.  Both the array and the strings referred to
 * should be released with XmFreeMemory().
 *
 * @path must point at valid globally-mapped non-pageable memory.  The
 * buffer returned through *@Res will be globally-mapped and
 * non-pageable, as will all of the strings referenced by it.
 *
 * @xbt can be null, nil, or a valid transaction.
 */
XSAPI NTSTATUS xenbus_ls(xenbus_transaction_t xbt, PCSTR path,
                         __out PSTR **Res);

/* Interprets @fmt as a printf-style format string, processes it as
 * for sprintf(), and writes the result to @prefix/@node under the
 * transaction @xbt.
 *
 * @prefix, @node, @fmt, and any pointers in the argument list which
 * must be dereferenced to interpret @fmt must point at valid
 * globally-mapped non-pageable memory.
 *
 * @xbt can be null, nil, or a valid transaction.
 */
XSAPI NTSTATUS xenbus_printf(xenbus_transaction_t xbt, PCSTR prefix,
                             PCSTR node, PCSTR fmt, ...);

/* Read a decimal integer from @prefix/@node under transaction @xbt.
 * The transaction is considered to have failed if this function
 * encounters any errors, including errors parsing @prefix/@node.
 *
 * @prefix, @node, and @res must all point at valid globally-mapped
 * non-pageable memory.
 *
 * @xbt can be null, nil, or a valid transaction.
 */
XSAPI NTSTATUS xenbus_read_int(xenbus_transaction_t xbt, PCSTR prefix,
                               PCSTR node, ULONG64 *res);

/* Wait for a backend to leave state @state.  @backend_path is the
 * path to the backend area, and @timeout specifies a timeout with the
 * same semantics as KeWaitForSingleObject.  Returns the last observed
 * backend state, or null_XENBUS_STATE() on error.  Note that the
 * return value could be @state if the wait times out.
 *
 * The caller must provide a suspend token, since the backend path is
 * likely to change during dom0 suspend/resume.
 *
 * @backend_path must point at valid globally-mapped non-pageable
 * memory.  If @timeout is non-NULL, it must also point at
 * non-pageable memory.
 *
 * Must be invoked at PASSIVE_LEVEL if the timeout is non-zero, and at
 * IRQL <= DISPATCH_LEVEL otherwise.
 */
XSAPI XENBUS_STATE __XenbusWaitForBackendStateChangeAnonymous(PCSTR backend_path,
                                                              XENBUS_STATE state,
                                                              PLARGE_INTEGER timeout,
                                                              SUSPEND_TOKEN token);
XSAPI XENBUS_STATE __XenbusWaitForBackendStateChange(PCSTR caller,
                                                     PCSTR backend_path,
                                                     XENBUS_STATE state,
                                                     PLARGE_INTEGER timeout,
                                                     SUSPEND_TOKEN token);

#define XenbusWaitForBackendStateChange(_backend_path, _state, _timeout, _token) \
        __XenbusWaitForBackendStateChange(__FUNCTION__, (_backend_path), (_state), (_timeout), (_token))

struct xenbus_watch_handler;
/* Register a watch on @path in xenstore.  When @path changes, @cb
 * will be invoked from the xenbus thread with arguments @path and
 * @data.  The watch infrastructure takes a copy of @path, and so the
 * caller is free to release the storage used by its copy.  Returns a
 * pointer to a new watch handler structure on success, or NULL on
 * error.
 *
 * It is guaranteed that the watch will fire shortly after any change
 * to the node, barring errors.  It is not guaranteed that it fire
 * exactly once for every time the node is changed, or that it will
 * only fire when the node changes.
 *
 * Watches are preserved across dom0-driven save/restore.
 *
 * Watch callbacks are run at PASSIVE_LEVEL from a system thread.  Any
 * single watch handler will only be invoked from one thread at a
 * time.
 *
 * Implementation detail: At present, watch handlers are always run
 * from the same thread.  This means that only one handler can be
 * active at any time.  It is not guaranteed that this behaviour will
 * be preserved in future versions.
 *
 * Returns NULL on error.
 *
 * NOTE: __xenbus_watch_path_anonymous() is defined for ABI compatibility.
 *       New code should use the xenbus_watch_path() macro.
 */
XSAPI __checkReturn struct xenbus_watch_handler *__xenbus_watch_path_anonymous(PCSTR path,
                                                                               void (*cb)(void *data),
                                                                               void *data);
XSAPI __checkReturn struct xenbus_watch_handler *__xenbus_watch_path(PCSTR path,
                                                                     const char *cb_name,
                                                                     void (*cb)(void *data),
                                                                     void *data);
#define xenbus_watch_path(_path, _cb, _data) \
        __xenbus_watch_path((_path), #_cb, (_cb), (_data));

/* Register a watch on @path in xenstore, and arrange that
 * @evt is set whenever @path changes.  No priority increment is
 * applied.
 *
 * @path must point at valid non-pageable memory.
 *
 * @evt should usually be a notification event, rather than
 * synchronisation.  If a synchronisation event is used, note that
 * rapid changes will sometimes only signal the event once.  The event
 * can be signalled when path is unchanged, although this should be
 * rare.  @evt should remain valid until the watch is release with
 * xenbus_unregister_watch().  It is the caller's responsibility to
 * release the memory occupied by the event at that time.
 *
 * Watches are preserved across dom0 save/restore.
 *
 * Returns NULL on error.
 */
XSAPI __checkReturn struct xenbus_watch_handler *xenbus_watch_path_event(PCSTR path,
                                                                         struct _KEVENT *evt);

/* Re-direct a registered watch @wh so that it points at a new
 * location @path
 *
 * Returns STATUS_SUCCESS on success, or something else on error.  The
 * watch continues to use the old path on error.
 *
 * Note that this function does not wait for the watch to complete
 * before redirecting it, and so the watch can continue to fire on the
 * old location after xenbus_redirect_watch() completes.
 *
 * Call at IRQL < DISPATCH_LEVEL.
 */
XSAPI __checkReturn NTSTATUS xenbus_redirect_watch(struct xenbus_watch_handler *wh,
                                                   PCSTR path);

/* Release a watch allocated by xenbus_watch_path.  When this returns,
 * it is guaranteed that the final invocation of the callback due to
 * this watch has finished.
 *
 * This can be used to release watches allocated with either
 * xenbus_watch_path() or xenbus_watch_path_event().
 *
 * Be careful when unregistering watches from a late suspend handler
 * if the watch handler ever allocates a suspend token.  Allocating a
 * suspend token effectively waits for all suspend handlers to
 * complete, and before unregistering a watch you must wait for the
 * watch handler to complete, and so this can lead to deadlocks if the
 * watch handler is in its very early stages when the suspend starts.
 *
 * @wh must not be null.
 *
 * Must be invoked at PASSIVE_LEVEL.
 */
XSAPI void xenbus_unregister_watch(struct xenbus_watch_handler *wh);

/* Read a XENBUS_STATE from the store at @prefix/@node under the
 * transaction @xbt.  Returns STATUS_DATA_ERROR and fails the
 * transaction if @prefix/@node is readable but does not contain a
 * valid XENBUS_STATE.
 *
 * @prefix and @node must point at valid globally-mapped non-pageable
 * memory.
 *
 * @xbt may be nil, null, or a valid transaction.  @state should not
 * be NULL.
 *
 * On error, *@state will be set to null_XENBUS_STATE().
 *
 * Must be invoked at IRQL <= DISPATCH_LEVEL.
 */
XSAPI NTSTATUS xenbus_read_state(xenbus_transaction_t xbt,
                                 PCSTR prefix,
                                 PCSTR node,
                                 XENBUS_STATE *state);

/* Write the XENBUS_STATE @state to the store at @prefix/@node under
 * the transaction @xbt, provided @prefix/@node already exists.  If
 * @prefix/@node does not exist, return STATUS_OBJECT_NAME_NOT_FOUND
 * and fail the transaction.
 *
 * @prefix and @node must point at valid globally-mapped non-pageable
 * memory.
 *
 * @xbt may be nil, null, or a valid transaction.  @state should not
 * be null.
 *
 * Must be invoked at IRQL <= DISPATCH_LEVEL.
 */
XSAPI NTSTATUS xenbus_change_state(xenbus_transaction_t xbt,
                                   PCSTR prefix,
                                   PCSTR node,
                                   XENBUS_STATE state);

/* Cause the watch @wh to fire soon in its normal context.
 * @wh is triggered as if the thing which it is watching was modified.
 *
 * @wh must not be null.
 *
 * Must be invoked at PASSIVE_LEVEL.
 */
XSAPI void xenbus_trigger_watch(struct xenbus_watch_handler *wh);

/* Read a feature flag from the store at @prefix/@node, under the
 * transaction @xbt.  Sets @res to TRUE if the feature is available,
 * and FALSE otherwise.  The feature is considered unavailable if the
 * node does not exist or if it exists and has the value 0.  It is
 * available if it exists and has the value 1.  Anything else is
 * considered an error.
 *
 * The transaction will not be aborted simply because the node is not
 * present (unlike XenbusReadInteger or xenbus_read).  It will be
 * aborted as normal if there is any other error reading the node, or
 * if the node does not have the value "0" or the value "1".
 *
 * @prefix and @node must point at valid globally-mapped non-pageable
 * memory.
 *
 * *@res is set to FALSE on failure.
 *
 * @xbt may be nil, null, or a valid transaction.
 */
XSAPI NTSTATUS xenbus_read_feature_flag(xenbus_transaction_t xbt,
                                        PCSTR prefix, PCSTR node,
                                        BOOLEAN *res);

/* Set a flag in the store.  Sets @prefix/@node to 1 if @res is TRUE
 * and 0 if it is FALSE.
 *
 * @prefix and @node must point at valid globally-mapped non-pageable
 * memory.
 *
 * @xbt may be nil, null, or a valid transaction.
 */
XSAPI NTSTATUS xenbus_write_feature_flag(xenbus_transaction_t xbt,
                                         PCSTR prefix, PCSTR node,
                                         BOOLEAN res);

/* Read a domain ID from the store at @prefix/@node, under the
 * transaction @xbt.  Sets @res to the resulting domain ID, or
 * null_DOMAIN_ID() on error.
 *
 * Domain IDs are represented in the store by base-10 integers between
 * 0 and DOMID_FIRST_RESERVED-1, inclusive; if the value in the store
 * cannot be parsed as such, or if it is out of range, the call fails,
 * and so does the transaction.
 *
 * @prefix and @node must point at valid globally-mapped non-pageable
 * memory.
 *
 * @xbt may be nil, null, or a valid transaction.
 *
 * Added in XE 5.0.
 */
XSAPI NTSTATUS xenbus_read_domain_id(xenbus_transaction_t xbt,
                                     PCSTR prefix, PCSTR node,
                                     DOMAIN_ID *res);

/* ------------------ Xenbus enumerated devices -------------------- */
/* The xenbus driver enumerates devices in the device area of xenstore
 * and presents them to the Windows PnP manager, which will then load
 * suitable devices.
 *
 * For every directory ``device/${class}/${id}'', the bus driver will
 * create a PDO as a child of itself.  The PDO has instance ID ${id},
 * hardware ID XEN\${class}, and a single device ID which is also
 * XEN\${class}.  For example, the PDO for device ``device/vfb/12''
 * will have instance ID 12, and hardware and device IDs XEN\vfb.
 * Clients can install drivers for these IDs via the usual Windows PnP
 * mechanisms.
 *
 * Note that the vbd class is handled specially.  Users of this
 * library should not attempt to attach drivers to class vbd.
 *
 * The bus driver assumes that the frontend area will contain an entry
 * called ``backend'' which contains the path to the backend area for
 * the device, and that the backend area contains an entry called
 * ``state'' which gives the current state of the backend device.  The
 * bus driver will send an EJECT PNP IRP to the device stack when the
 * backend state changes to CLOSING, indicating that the frontend
 * should close and unload.  The PDO is still created if these xenbus
 * nodes are not present, but hot-remove will not be supported.
 *
 * The frontend path for a given PDO can be extracted with
 * xenbus_find_frontend(), and the backend with xenbus_find_backend().
 * These must be invoked on the PDO *only*, or they will bugcheck.
 */

/* Given a Xenbus PDO, determine the frontend path for the device.
 * Returns a newly-allocated nul-terminated string which should
 * be release with XmFreeMemory(), or NULL on error.
 *
 * @device must be a xenbus PDO.  Anything else will cause a bugcheck.
 * The caller is responsible for ensuring that the PDO remains valid
 * while this function is running, but there is no requirement for it
 * to remain valid once it has returned.  The returned string remains
 * valid until explicitly released.
 *
 * Invoke from PASSIVE_LEVEL.
 */
XSAPI PSTR xenbus_find_frontend(PDEVICE_OBJECT device);

/* Given a Xenbus PDO, determine the backend path for the device.
 * Returns a newly-allocated nul-terminated string which should be
 * released with XmFreeMemory(), or NULL on error.
 *
 * @device must be a xenbus PDO.  Anything else will cause a bugcheck.
 * The caller is responsible for ensuring that the PDO remains valid
 * while this function is running, but there is no requirement for it
 * to remain valid once it has returned.  The returned string remains
 * valid until explicitly released.
 *
 * Note that the backend path is likely to change across dom0
 * suspend/resume.  The caller is therefore required to provide
 * a suspend token when calling xenbus_find_backend().
 *
 * Invoke from PASSIVE_LEVEL.
 */
XSAPI PSTR xenbus_find_backend(PDEVICE_OBJECT device, SUSPEND_TOKEN token);

/* Read the feature flag @node from the xenstore backend area for the
 * device represented by @pdo, under the transaction @xbt.  Sets @res
 * to TRUE if the feature is available, and FALSE otherwise.  The
 * feature is considered unavailable if the node does not exist or if
 * it exists and has the value 0.  It is available if it exists and
 * has the value 1.  Anything else is considered an error.
 *
 * The transaction will not be aborted simply because the node is not
 * present (unlike XenbusReadInteger() or xenbus_read()).  It will be
 * aborted as normal if there is any other error reading the node, or
 * if the node does not have the value "0" or the value "1".
 *
 * @node must point at valid globally-mapped non-pageable memory.
 *
 * *@res is set to FALSE on failure.
 *
 * @xbt may be nil, null, or a valid transaction.
 *
 * Call from IRQL < DISPATCH_LEVEL.
 */
XSAPI NTSTATUS xenbus_read_backend_feature_flag(xenbus_transaction_t xbt,
                                                PDEVICE_OBJECT pdo,
                                                PCSTR node,
                                                BOOLEAN *res);

/* Read arbitrary data from the xenstore key @node in the backend area
 * corresponding to the device @pdo, under transaction @xbt.  The
 * result is returned as a newly-allocated buffer at *@Res, and should
 * be freed with XmFreeMemory() when you're finished with it.  The
 * length of the buffer is returned in *@size.
 *
 * Note that *@Res is not guaranteed to be nul-terminated, and can
 * contain embedded nuls.  This is different from xenbus_read().
 *
 * @node must point at valid globally-mapped non-pageable memory.  The
 * buffer returned at *@res will be globally-mapped and non-pageable.
 *
 * @xbt can be null, nil, or a valid transaction.
 *
 * Call from IRQL < DISPATCH_LEVEL.
 */
XSAPI NTSTATUS xenbus_read_backend_bin(xenbus_transaction_t xbt,
                                       PDEVICE_OBJECT pdo,
                                       PCSTR node,
                                       void **res,
                                       size_t *size);

/* Read a nul-terminated string from the xenstore key @node in the
 * backend area corresponding the device @pdo, under transaction @xbt.
 * The result is returned as a nul-terminated string at *@Res, and
 * should be freed with XmFreeMemory() when you're finished with it.
 *
 * @node must point at valid globally-mapped non-pageable memory.  The
 * buffer returned at *@res will be globally-mapped and non-pageable.
 *
 * @xbt can be null, nil, or a valid transaction.
 *
 * @pdo must be a xenbus device physical device object.
 *
 * Call from IRQL < DISPATCH_LEVEL.
 */
XSAPI NTSTATUS xenbus_read_backend(xenbus_transaction_t xbt,
                                   PDEVICE_OBJECT pdo,
                                   PCSTR node,
                                   PSTR *res);

/* ----------------------- Event channels -------------------------- */
/* Event channels are one of the primary Xen-provided inter-domain
 * communication mechanisms.  The only kind supported by xevtchn.sys
 * is an inter-domain event channel.  These have two ends in separate
 * domains and are, once established, basically symmetrical.  Either
 * end can notify over the event channel, which will cause a bit in
 * the other end's hypervisor shared info to be set and an interrupt
 * to be raised.  It is then up to the recipient domain to process the
 * event in a suitable fashion.
 *
 * Events can be temporarily masked by setting suitable bits in the
 * shared info structure.  This will prevent an interrupt being raised
 * for that event channel, but will not prevent the pending bit being
 * set.  Note that masking an event channel only prevents the local
 * event handler from being run; it is still possible to notify the
 * remote domain over the channel, and the remote event channel
 * handler will be invoked immediately (subject to masking in the
 * remote domain).
 *
 * If an event is raised several times before the recipient domain is
 * able to process it, the events will be combined and only delivered
 * once.
 *
 * EVTCHN_PORT structures remain valid across dom0-driven
 * save/restore, hibernation, and migration, but will not be
 * automatically communicated to device backends etc.  The Xen-side
 * event channel port number may change, but that should be invisible
 * to users of this API.
 */

MAKE_WRAPPER_PUB(EVTCHN_PORT)

/* Allocate a new Xen event channel and return an EVTCHN_PORT
 * describing it.  The domain @domid will be able to connect to this
 * port so that it can send and receive notifications over the event
 * channel.  When this port is notified by the remote domain, @cb will
 * be invoked with the single argument @context.  This callback will
 * be invoked directly from the event channel interrupt handler; it
 * must therefore be quick.  The callback can be invoked even when the
 * associated event has not been raised, although this should be rare.
 * Returns a null port on failure.
 *
 * The port should be released with EvtchnClose() when it is no longer
 * needed.
 *
 * Invoke from PASSIVE_LEVEL.
 */
typedef void EVTCHN_HANDLER_CB(void *Context);
typedef EVTCHN_HANDLER_CB *PEVTCHN_HANDLER_CB;
XSAPI EVTCHN_PORT EvtchnAllocUnbound(DOMAIN_ID domid, PEVTCHN_HANDLER_CB cb,
                                     void *context);

/* EvtchnAllocUnboundDpc() is analogous to EvtchnAllocUnbound(),
 * except that the callback is run from a DPC rather than directly
 * from the event channel interrupt handler.  The port can be raised
 * and notified as normal.
 *
 * There is no way to directly access a DPC port's DPC.  Several ports
 * may share a single Windows DPC; this should be transparent to
 * clients.  It is guaranteed that the callback will not be
 * simultaneously invoked on multiple CPUs.
 *
 * DPC ports cannot be masked and unmasked.  It is an error to call
 * EvtchnPortMask() or EvtchnPortUnmask() on such a port.
 *
 * Call from PASSIVE_LEVEL.
 *
 * Introduced in Orlando.
 */
XSAPI EVTCHN_PORT EvtchnAllocUnboundDpc(DOMAIN_ID domid,
                                        PEVTCHN_HANDLER_CB cb,
                                        void *context);

/* Close the event channel port @port, unregistering the handler.
 * When this returns, it is guaranteed that the last invocation of the
 * callback assigned with EvtchnAllocUnbound() or
 * EvtchnAllocUnboundDpc() has completed.
 *
 * It is not necessary to stop the port before closing it.
 *
 * @port may not be null.
 *
 * @port is invalid after this has been called.
 *
 * Invoke from PASSIVE_LEVEL.
 */
XSAPI void EvtchnClose(EVTCHN_PORT port);

/* Prevent any further invocations of the handler associated with @port,
 * and wait for any existing invocations to finish.
 *
 * It is not possible to re-start a port which has been stopped.  The
 * port must be closed with EvtchnClose() and re-created.
 *
 * EvtchnNotifyRemote(), EvtchnPortMask(), EvtchnPortUnmask(), and
 * EvtchnRaiseLocally() are all no-ops on a stopped port.
 * xenbus_write_evtchn_port() on a stopped port will return an error
 * and fail any transaction.
 *
 * @port may not be null.
 *
 * Invoke from PASSIVE_LEVEL.
 */
XSAPI void EvtchnPortStop(EVTCHN_PORT port);

/* Notify the remote domain connected to the event channel @port,
 * previously returned by EvtchnAllocUnbound().  The notification will
 * be discarded if there is no domain currently attached to the other
 * end of the event channel.
 *
 * @port may not be null.
 *
 * Can be invoked from any IRQL, holding any combination of locks.
 */
XSAPI void EvtchnNotifyRemote(__in EVTCHN_PORT port);

/* Cause an event channel to be raised locally.  Shortly after this is
 * called, the callback defined for the event will be invoked in its
 * usual context, exactly as if it had been raised in the remote
 * domain
 *
 * @port may not be null.
 *
 * Can be invoked from IRQL <= DISPATCH_LEVEL, holding any combination
 * of locks.
 */
XSAPI void EvtchnRaiseLocally(__in EVTCHN_PORT port);

/* Write the event channel port number @port to xenstore at
 * @prefix/@node under the transaction @xbt.  Users should not attempt
 * to interpret the contents of the EVTCHN_PORT structure
 * themselves.
 *
 * xenbus_write_evtchn_port() will fail the transaction and return an
 * error if @port was previously been passed to EvtchnPortStop().
 *
 * @prefix and @node must point at valid globally-mapped non-pageable
 * memory.
 *
 * @port must not be null.  @xbt may be nil, null, or a valid
 * transaction.
 */
XSAPI NTSTATUS xenbus_write_evtchn_port(xenbus_transaction_t xbt,
                                        PCSTR prefix, PCSTR node,
                                        EVTCHN_PORT port);

/* ----------------------- Debug callbacks ------------------------- */
MAKE_WRAPPER_PUB(EVTCHN_DEBUG_CALLBACK)

/* Register a handler for VIRQ_DEBUG.  When VIRQ_DEBUG is raised
 * against the current domain, @cb will be invoked with parameter @d.
 * This is usually used to dump debugging information to XenTrace.
 * The returned handle should be released with
 * EvtchnReleaseDebugCallback().  Returns null_EVTCHN_DEBUG_CALLBACK()
 * on error.
 *
 * The callback is invoked from the same context as an event channel
 * handler registered with EvtchnAllocUnbound().
 *
 * Debug callbacks may also be invoked immediately before the guest
 * bugchecks.  If so, they are invoked from the same context as a
 * KeRegisterBugCheckCallback() callback, and with XenTrace configured
 * to send every message to every available message consumer.  Debug
 * callbacks are not guaranteed to be invoked after every possible
 * crash.
 *
 * Note that the number of debug callbacks which can be registered is
 * quite limited.  They should not be allocated gratuitously, and
 * drivers must operate correctly when they are unable to allocate a
 * callback.
 *
 * VIRQ_DEBUG is automatically raised against all domains by
 * xen-bugtool, shortly before collecting the domain 0 logs.  This is,
 * however, no synchronisation between bugtool and the in-guest tools,
 * and so if a debug callback takes more than a few seconds the
 * collected logs may be truncated.
 *
 * Invoke from PASSIVE_LEVEL.
 */
XSAPI EVTCHN_DEBUG_CALLBACK __EvtchnSetupDebugCallbackAnonymous(VOID (*cb)(PVOID),
                                                                PVOID d);
XSAPI EVTCHN_DEBUG_CALLBACK __EvtchnSetupDebugCallback(const CHAR *module,
                                                       const CHAR *name,
                                                       VOID (*cb)(PVOID),
                                                       PVOID d);
#define EvtchnSetupDebugCallback(_cb, _d) \
        __EvtchnSetupDebugCallback(XENTARGET, #_cb, (_cb), (_d))

/* Release the debug callback handle previously returned by
 * EvtchnSetupDebugCallback().  @handle can be
 * null_EVTCHN_DEBUG_CALLBACK(); in that case, this is a no-op.
 *
 * Invoke from PASSIVE_LEVEL.
 */
XSAPI void EvtchnReleaseDebugCallback(EVTCHN_DEBUG_CALLBACK handle);

/* ------------------------- Grant tables -------------------------- */
/* Grant tables provide a mechanism by which domains can grant other
 * domains access to their memory in a controlled fashion.  Each grant
 * reference grants a particular foreign domain access to a particular
 * frame of physical memory in the local domain.  They can be either
 * read-only or read-write.
 *
 * We use a wrapper type, GRANT_REF, around the underlying
 * xen_grant_ref_t.  This has a couple of advantages:
 *
 * a) invalid grant references have an all-zero representation in
 * memory, so initialisation becomes much easier,
 * b) we can steal a few bits out of the bottom for flags, which
 * can then be used for checking that e.g. they're release back
 * to the right cache.
 * c) you get as much type safety as C can offer.
 *
 * GRANT_REFs are preserved across dom0-driver save/restore, and have
 * the same xen_grant_ref_t after recovery as they had before.
 */

/* Xen grant references are integers greater than or equal to 0.
 * GRANT_REFs are (grant_ref_t+1)<<10.  This makes sure that null
 * references are recognisable as such, and allows us to shove some
 * flags in the bottom few bits (mostly for debugging). */
/* As far as clients are concerned, the only operations on GRANT_REFs
 * are null_GRANT_REF, is_null_GRANT_REF, and xen_GRANT_REF.  They
 * cannot assume anything about the flags part of the reference. */
MAKE_WRAPPER_PUB(GRANT_REF)
__MAKE_WRAPPER_PRIV(GRANT_REF, ULONG_PTR)

typedef uint32_t xen_grant_ref_t;

/* Given a GRANT_REF, return the Xen grant_ref_t.  This is what needs
 * to be communicated to backends. */
static __inline xen_grant_ref_t xen_GRANT_REF(GRANT_REF g)
{
    ULONG_PTR res = __unwrap_GRANT_REF(g);
    return (xen_grant_ref_t)((res >> 10) - 1);
}

/* Make a GRANT_REF for a given Xen grant_ref_t, cache id,
 * and the current suspend count. Cache id should be set to
 * 0 for external callers */
static __inline GRANT_REF wrap_GRANT_REF(xen_grant_ref_t x, int cache)
{
    return __wrap_GRANT_REF(((x + 1) << 10) |
                            (cache & 3));
}

/* Grants have two possible modes: read-only or read-write. */
MAKE_WRAPPER_PUB(GRANT_MODE)
MAKE_WRAPPER_PRIV(GRANT_MODE, int)
#define GRANT_MODE_RW wrap_GRANT_MODE(0)
#define GRANT_MODE_RO wrap_GRANT_MODE(1)

/* Return a raw grant ref for situations where the client wants
 * to manage its own grant ref list.
 *
 * Can be called at any IRQL holding any combinations of locks.
 */
XSAPI GRANT_REF GnttabGetGrantRef(VOID);

/* See GnttabGrantForeignAccess but with a grant ref. See the
 * comments for that routine. The @ref parameter is acquired
 * using GnttabGetGrantRef().
 *
 * Can be invoked at any IRQL holding any combination of locks.
 */
XSAPI void GnttabGrantForeignAccessRef(DOMAIN_ID domid,
                                       PFN_NUMBER frame,
                                       GRANT_MODE mode,
                                       GRANT_REF ref);

/* Grants domain @domid access to physical frame @frame of our memory.
 * The domain is able to map the frame into its own address space, and
 * can also use it as the target or source of grant copy operations.
 * The grant can be either read-only or read-write, according to
 * @mode.  The grant reference should be released by calling
 * GnttabEndForeignAccess() when it is no longer needed.
 *
 * Can be invoked at any IRQL holding any combination of locks.
 */
XSAPI GRANT_REF GnttabGrantForeignAccess(DOMAIN_ID domid,
                                         PFN_NUMBER frame,
                                         GRANT_MODE mode);

/* Undo the effects of GnttabGrantForeignAccess(): Stop any further
 * accesses through the reference @ref, and return it to the pool of
 * free grant references.  This can fail if the grant is still in use
 * in the other domain; in that case, it returns STATUS_DEVICE_BUSY.
 * The grant reference is not released.  The caller may try again
 * later, but there is no way to release the reference if the granted
 * domain refuses to unmap it.
 *
 * @ref must not be null, since this is likely to be the only place
 * where we can check that the caller hasn't done something stupid
 * like accidentally pushing a null reference over a ring to a backend.
 *
 * Can be called at any IRQL holding any combinations of locks.
 */
XSAPI NTSTATUS GnttabEndForeignAccess(GRANT_REF ref);

/* ------------------------- Grant caches -------------------------- */
/* The largest component of the cost of GnttabGrantForeignAccess() is
 * the synchronisation around the pool of free grant references.  This
 * can be mitigated using grant caches, which allocate batches of
 * grant references from the main pool and then return them without
 * performing any additional synchronisation.  The caller is expected
 * to ensure that a single grant cache is never used on multiple CPUs
 * at the same time.
 *
 * The cache infrastructure is responsible for moving references
 * between the cache and the main pool when necessary.
 *
 */

struct grant_cache;

/* Allocate a new grant cache.  Returns a pointer to the new cache on
 * success or NULL on failure.  The cache should be released with
 * GnttabFreeCache() when no longer needed.
 *
 * If this succeeds, it is guaranteed that at least @min_population
 * grant references can be allocated from the cache without an error.
 * References returned to the cache with GnttabEndForeignAccessCache()
 * are returned to this pool, so that it is possible to allocate
 * up to the limit, release n entries, and then allocate another n,
 * and be guaranteed to succeed.
 *
 *
 * Call at PASSIVE_LEVEL.
 */
XSAPI struct grant_cache *GnttabAllocCache(ULONG min_population);

/* Release the grant cache @gc which was previously allocated with
 * GnttabInitCache().  All references which were allocated with
 * GnttabGrantForeignAccessCache() should have been released with
 * GnttabEndForeignAccessCache() before releasing the grant_cache.
 *
 * @gc must not be null.
 *
 * Call at PASSIVE_LEVEL.
 */
XSAPI void GnttabFreeCache(struct grant_cache *gc);

/* This is basically a faster version of GnttabGrantForeignAccess()
 * with more complicated synchronisation requirements.  The caller
 * must ensure that no other CPU is simultaneously accessing the
 * cache.  The returned GRANT_REF should be released using
 * GnttabEndForeignAccessCache().
 *
 * Can be called at any IRQL holding any locks.
 *
 * Returns null_GRANT_REF() on error.
 */
XSAPI GRANT_REF GnttabGrantForeignAccessCache(DOMAIN_ID domid,
                                              PFN_NUMBER frame,
                                              GRANT_MODE mode,
                                              __inout struct grant_cache *gc);

/* Stop any further accesses through the reference @ref, and return it
 * to @gc.  This can fail if the grant is still in use in the other
 * domain; in that case, it returns STATUS_DEVICE_BUSY.  The grant
 * reference is not released, and is not available to the cache.  The
 * caller may try again later, but there is no way to release the
 * reference if the granted domain refuses to unmap it.  The caller is
 * expected to ensure that no other CPU is simultaneously accessing
 * @gc.
 *
 * @ref must not be null.
 *
 * Can be called at any IRQL holding any combination of locks.
 */
XSAPI NTSTATUS GnttabEndForeignAccessCache(GRANT_REF ref,
                                           __inout struct grant_cache *gc);

/* Write the grant reference @gref to xenstore at @prefix/@node under
 * the transaction @xbt.  This handles unwrapping the grant reference
 * automatically.
 *
 * @prefix and @node must point at valid globally-mapped non-pageable
 * memory.
 */
XSAPI NTSTATUS xenbus_write_grant_ref(xenbus_transaction_t xbt, PCSTR prefix,
                                      PCSTR node, GRANT_REF gref);

/* ------------------------- Suspend handlers ------------------------- */
struct SuspendHandler;

/* Suspend recovery handlers.  These are invoked shortly after the
 * domain recovers from a dom0-initiated save/restore, and are
 * responsible for reconnecting to backends.
 *
 * There are two classes of suspend recovery handlers:
 *
 * -- Early handlers are run almost as soon as the domain recovers.
 * Only a single cpu is running at this time and interrupts are off.
 * These handlers are run in the order in which they are defined.  It
 * is guaranteed that no locks are held anywhere (including other
 * CPUs) when these handlers are invoked.  Early suspend handlers
 * should never acquire operating system spin locks; doing so is
 * redundant (because there are no other CPUs to synchronise with),
 * and incorrect (because KeAcquireSpinLock() can re-enable
 * interrupts, which is unsafe until all CPUs have been brought back
 * online).
 *
 * -- Late handlers are run a little while later.  Other CPUs have
 * been restarted at this point and the handler is invoked at
 * PASSIVE_LEVEL.  They can be invoked in any order, and potentially
 * in parallel.
 *
 * It is guaranteed that a new suspend will not be started until every
 * suspend handler has completed.
 *
 * Clients can temporarily inhibit suspend by allocating a suspend
 * token.  Any suspend requested by dom0 while a suspend token exists
 * somewhere in the system will be deferred until the last suspend
 * token is released, and any attempt to allocate a suspend token
 * whilst a suspend is in progress will be blocked until the last
 * suspend handler completes.
 */

MAKE_WRAPPER_PUB(SUSPEND_CB_TYPE)
MAKE_WRAPPER_PRIV(SUSPEND_CB_TYPE, int)

#define SUSPEND_CB_EARLY_TYPE   0
#define SUSPEND_CB_EARLY        wrap_SUSPEND_CB_TYPE(SUSPEND_CB_EARLY_TYPE)

#define SUSPEND_CB_LATE_TYPE    1
#define SUSPEND_CB_LATE         wrap_SUSPEND_CB_TYPE(SUSPEND_CB_LATE_TYPE)


/* Request a suspend recovery callback.  @cb will be invoked shortly
 * after recovering from a suspend with parameter @data.  The handler
 * is late if @type is SUSPEND_CB_LATE and early otherwise.  Returns
 * NULL on error, or a pointer to the new handler structure on
 * success.  The handler should be unregistered with
 * EvtchnUnregisterSuspendHandler() when no longer needed.
 *
 * @name is a nul-terminated string used for certain debug messages.
 * The caller should ensure that it remains valid as long as the
 * handler is registered.  It must be globally mapped and
 * non-pageable.
 *
 * When @cb is invoked, it is passed a suspend token.  The callback
 * should not attempt to release this token.
 *
 * Call from PASSIVE_LEVEL.
 *
 * Returns NULL on error.
 */
XSAPI struct SuspendHandler *EvtchnRegisterSuspendHandler(void (*cb)(void *data,
                                                                     SUSPEND_TOKEN token),
                                                          void *data,
                                                          char *name,
                                                          SUSPEND_CB_TYPE type);

/* Unregister a suspend handler @sh which was previously allocated by
 * EvtchnRegisterSuspendHandler().  It is guaranteed that the callback
 * will have finished running for the last time when this returns.
 *
 * @sh must not be NULL.
 *
 * Call from PASSIVE_LEVEL.
 */
XSAPI void EvtchnUnregisterSuspendHandler(struct SuspendHandler *sh);

/* Allocate a suspend token.  dom0-driven suspend/resume is inhibited
 * until the token is released with EvtchnReleaseSuspendToken().  It
 * is guaranteed that every suspend handler associated with any
 * previous suspend request has completed before this function
 * returns.
 *
 * This function always succeeds.
 *
 * The @name parameter is used in certain debug messages, but is
 * otherwise ignored.  The caller should ensure that it remains valid
 * until the token is released.  It must be globally mapped and
 * non-pageable.
 *
 * WARNING: Consumers of this API should take appropriate steps to
 * ensure that the token will be released.  In particular, if this
 * function is invoked from a user thread with APCs enabled it will be
 * possible for another userspace threads to call SuspendThread() on
 * the current thread, which may lead to deadlocks.  Suspend tokens
 * are normally only manipulated from system threads, which are not
 * exposed to this problem.  It is also safe to manipulate tokens in a
 * kernel critical section.
 *
 * Call at IRQL less than DISPATCH_LEVEL.
 */
XSAPI SUSPEND_TOKEN EvtchnAllocateSuspendToken(PCSTR name);

/* Release a suspend token, possibly unblocking dom0-driven
 * suspend/resume.  This must be called precisely once for every call
 * to EvtchnAllocateSuspendToken().
 *
 * If a suspend was requested while @token was extant, and it is the
 * only suspend token in the system, this will cause an immediate
 * suspend.
 *
 * Call at IRQL less than DISPATCH_LEVEL.
 */
XSAPI void EvtchnReleaseSuspendToken(SUSPEND_TOKEN token);

/* ----------------------- Tracing ------------------------------------- */
/* Trace messages can be configured to go to a couple of places:
 *
 * -- A ring buffer in xevtchn.sys
 * -- The kernel debugger (if IRQL <= DISPATCH_LEVEL)
 * -- dom0 syslog
 * -- The hypervisor serial console.
 *
 * By default, verbose and above go to the ring buffer and kernel
 * debugger, info and above go to Xen, and notice and above go to
 * dom0.  The message itself is a string, which is formatted using
 * printf-style percentos.  It is automatically prefixed with the
 * loglevel used and the value of the preprocessor macro XENTARGET.
 *
 * Note that you need to have guest_loglvl=all enabled to see the
 * hypervisor messages, since there's a potential denial of service
 * condition where a guest spams the hypervisor serial port with
 * useless messages.  Messages sent to dom0 are always rate limited;
 * if a guest exceeds that rate limiter, it will be paused for a few
 * milliseconds.  This will be noted in the dom0 log the first time it
 * happens for a particular guest.
 *
 * Trace messages can be generated from any irql, holding any
 * combination of locks.  However, messages to the debugger will be
 * discarded above DISPATCH_LEVEL.
 *
 * Message levels can be changed at run-time using the setloglevel
 * utility, or at boot time using boot.ini.  The xevtchn ring buffer
 * can be extracted using the getlogs utility.  Both setloglevel and
 * getlogs are included with the PV drivers package, and are installed
 * in the same place as the userspace agent.
 *
 * The trace infrastructure will attempt to copy the contents of the
 * ring buffer to the dom0 log when the guest crashes.  This may not
 * be possible for certain serious crashes.  The ring is also included
 * in kernel triage dumps where possible, and can be extracted using
 * the debugger's .enumtag command.
 *
 * Trace macros all have the form:
 *
 * TraceInfo((fmt, ...))
 *
 * where Info is the log level to use (one of Debug, Verbose, Info,
 * Notice, Warning, Error, and Critical), fmt is a printf-style format
 * string, and ... are printf-style arguments to go with fmt.
 * TraceDebug is compiled away to nothing in non-checked builds; use
 * __XenTraceDebug(fmt, ...) instead if you want to generate loud-level
 * messages in free builds.
 */
#include <stdarg.h>

typedef enum {
    XenTraceLevelDebug,     /* Debug messages */
    XenTraceLevelVerbose,   /* Tracing of normal operation */
    XenTraceLevelInfo,      /* General operational messages. */
    XenTraceLevelNotice,    /* Important operational messages. */
    XenTraceLevelWarning,   /* Something bad happened, trying to
                             * recover */
    XenTraceLevelError,     /* Something bad happened, reduced
                             * functionality */
    XenTraceLevelCritical,  /* Something bad happened, we're going to
                               crash soon. */
    XenTraceLevelBugCheck,  /* Something very bad happened, crash
                               immediately. */
    XenTraceLevels,         /* Number of levels with dispositions
                               that can be modified*/
    XenTraceLevelProfile,   /* Messages for WPP */
    XenTraceLevelInternal   /* Reserved for internal use only */
} XEN_TRACE_LEVEL;

XSAPI void ___XenTrace(XEN_TRACE_LEVEL lvl,
                       __in_ecount(module_size) PCSTR module,
                       size_t module_size,
                       PCSTR fmt,
                       va_list args);

#define TRACE_LEVEL(name)                                            \
static __inline void __XenTrace ## name (PCSTR fmt, ...)             \
{                                                                    \
    va_list args;                                                    \
    va_start(args, fmt);                                             \
    ___XenTrace( XenTraceLevel ## name , XENTARGET,                  \
               sizeof(XENTARGET) - 1, fmt, args);                    \
    va_end(args);                                                    \
}

TRACE_LEVEL(Debug)
TRACE_LEVEL(Verbose)
TRACE_LEVEL(Info)
TRACE_LEVEL(Notice)
TRACE_LEVEL(Warning)
TRACE_LEVEL(Error)
TRACE_LEVEL(Critical)
TRACE_LEVEL(BugCheck)
TRACE_LEVEL(Profile)
TRACE_LEVEL(Internal)
#undef TRACE_LEVEL

#if DBG
#define TraceDebug(_X_) __XenTraceDebug _X_
#else
#define TraceDebug(_X_) do {} while (FALSE)
#endif

#define TraceVerbose(_X_) __XenTraceVerbose _X_
#define TraceInfo(_X_) __XenTraceInfo _X_
#define TraceNotice(_X_) __XenTraceNotice _X_
#define TraceWarning(_X_) __XenTraceWarning _X_
#define TraceError(_X_) __XenTraceError _X_
#define TraceCritical(_X_) __XenTraceCritical _X_
#define TraceBugCheck(_X_) __XenTraceBugCheck _X_
#define TraceProfile(_X_) __XenTraceProfile _X_
#define TraceInternal(_X_) __XenTraceInternal _X_

BOOLEAN
XenDbgDisableKdLog(BOOLEAN);

#endif /* !XSAPI_H__ */
