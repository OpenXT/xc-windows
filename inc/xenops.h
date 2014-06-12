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

/* Various functions for doing hypervisor-level operations from
 * userspace. */
#ifndef XENOPS_H__
#define XENOPS_H__

#ifdef XENOPS_API_EXPORTS
#define XENOPS_API __declspec(dllexport)
#else
#define XENOPS_API __declspec(dllimport)
#endif

#include "wrapper_types.h"

/* An opaque handle to an instance of the library.  Almost all xenops
 * APIs require one of these.  They are created with xenops_open(),
 * and destroyed with xenops_close().
 *
 * No additional synchronisation is required for this structure.  Once
 * created, it can be safely moved to other threads, and used from
 * several threads at the same time.
 */
struct xenops_handle;

/* Open the library.  Returns a freshly-allocated xenops_handle which
 * can be used to communicate with the library, the kernel-space
 * driver, and, ultimately, with Xen itself.
 *
 * Returns NULL on error, in which case a more useful error code can
 * be obtained by calling GetLastError().
 */
XENOPS_API struct xenops_handle *xenops_open(void);

/* Close a handle to the library @xh which was previously opened with
 * xenops_open().  Once this has been called, no other operations are
 * valid on the handle.
 */
XENOPS_API void xenops_close(struct xenops_handle *xh);

/* ----------------------- Domain ID type -------------------------- */
/* A special type for domain IDs.  These are identical to the type of
 * the same name in xsapi.h, and are documented there.
 */
MAKE_WRAPPER_PUB(DOMAIN_ID)
__MAKE_WRAPPER_PRIV(DOMAIN_ID, int)

static __inline DOMAIN_ID wrap_DOMAIN_ID(int x)
{
    return __wrap_DOMAIN_ID(x ^ 0xf001);
}
static __inline int unwrap_DOMAIN_ID(DOMAIN_ID x)
{
    return __unwrap_DOMAIN_ID(x) ^ 0xf001;
}
#define DOMAIN_ID_0() wrap_DOMAIN_ID(0)

/* --------------------- Local grant tables ------------------------ */

/* A wrapper type for local grant references, analogous to the type of
 * the same name in xsapi.h.  A GRANT_REF is effectively a semi-opaque
 * capability which allows a specific domain to access a page of local
 * memory, which is one of Xen's fundamental inter-domain
 * communication mechanisms.
 *
 * This type should be regarded as opaque, except for the operations
 * defined in this header.
 */
MAKE_WRAPPER_PUB(GRANT_REF)
__MAKE_WRAPPER_PRIV(GRANT_REF, unsigned)

/* Xen-level grant references are simple integers, rather than the
 * type-safe wrapper defined above.
 */
typedef unsigned xenops_grant_ref_t;

/* Given a GRANT_REF, obtain the Xen-level grant reference contained
 * inside it.  This is what should be passed to the remote domain.
 */
static __inline xenops_grant_ref_t
xen_GRANT_REF(GRANT_REF g)
{
    unsigned res = __unwrap_GRANT_REF(g);
    return (xenops_grant_ref_t)((res ^ 0xdeadbeef) >> 10);
}

/* Grant the remote domain @domid read-only access to a page of local
 * memory, starting at the virtual address @start.  A new GRANT_REF is
 * allocated and stored in *@out.
 *
 * As an anti-foot-shooting measure, processes are, by default, not
 * allowed to grant access to more than 256 pages at any one time
 * (because granted pages are pinned in memory, and pinning too much
 * can lead to deadlocks).  Once that quota has been hit, any further
 * attempts to grant access to memory will fail.  The quota can be
 * adjusted by calling xenops_grant_set_quota(), and the current value
 * can be obtained by calling xenops_grant_get_quota().
 *
 * @start must be page-aligned, and must refer to a valid page of
 * populated virtual memory to which the current process has at least
 * read access.
 *
 * The GRANT_REF will be automatically released when the process
 * exits, and the process exit will be delayed as long as necessary to
 * end the grant.  It is *not* automatically released when the xenops
 * handle is closed.
 *
 * Returns TRUE on success, or FALSE on error.  On error, *@res is set
 * to null_GRANT_REF(), and an error code can be obtained by calling
 * GetLastError().
 */
XENOPS_API BOOL xenops_grant_readonly(struct xenops_handle *h,
                                      DOMAIN_ID domid,
                                      void *start,
                                      GRANT_REF *out);

/* Grant the remote domain @domid read-write access to a page of local
 * memory, starting at the virtual address @start.  A new GRANT_REF is
 * allocated and stored in *@out.
 *
 * As an anti-foot-shooting measure, processes are, by default, not
 * allowed to grant access to more than 256 pages at any one time
 * (because granted pages are pinned in memory, and pinning too much
 * can lead to deadlocks).  Once that quota has been hit, any further
 * attempts to grant access to memory will fail.  The quota can be
 * adjusted by calling xenops_grant_set_quota(), and the current value
 * can be obtained by calling xenops_grant_get_quota().
 *
 * @start must be page-aligned, and must refer to a valid page of
 * populated virtual memory to which the current process has at least
 * read-write access.
 *
 * The GRANT_REF will be automatically released when the process
 * exits, and the process exit will be delayed as long as necessary to
 * end the grant.  It is *not* automatically released when the xenops
 * handle is closed.
 *
 * Returns TRUE on success, or FALSE on error.  On error, *@res is set
 * to null_GRANT_REF(), and an error code can be obtained by calling
 * GetLastError().
 */
XENOPS_API BOOL xenops_grant_readwrite(struct xenops_handle *h,
                                       DOMAIN_ID domid,
                                       void *start,
                                       GRANT_REF *out);

/* Revoke the grant reference @gref.  Note that this can fail if the
 * remote domain currently has the grant reference mapped, in which
 * case there is no reliable way to revoke the grant reference.
 *
 * If this returns success, the remote domain no longer has any access
 * to the granted memory.
 *
 * @gref may be null, in which case no action is taken and success is
 * returned.
 *
 * Returns TRUE on success or FALSE on error.  On error, a further
 * error code can be obtained by calling GetLastError().
 */
XENOPS_API BOOL xenops_ungrant(struct xenops_handle *h,
                               GRANT_REF gref);

/* Set the process grant quota to @quota.  Note that the quota is
 * per-process, and not per-handle.
 *
 * This can set an arbitrarily large quota.  Exercise caution when
 * setting very large values, since excessive grant usage will
 * severely impact performance in the local domain.
 *
 * It is possible to reduce the quota using this function, provided
 * the number of grants currently outstanding the process is less than
 * the new quota.
 *
 * Returns TRUE on success or FALSE on error.  On error, a further
 * error code can be obtained by calling GetLastError().
 */
XENOPS_API BOOL xenops_grant_set_quota(struct xenops_handle *h,
                                       unsigned quota);

/* Get the current process grant quota.  This includes any grant
 * references currently outstanding.
 *
 * Always succeeds and returns the current quota.
 */
XENOPS_API unsigned xenops_grant_get_quota(struct xenops_handle *h);

/* --------------------- Remote grant tables ----------------------- */

/* A semi-opaque type representing a grant reference in a remote
 * domain, analogous to the type of the same name in xsapi-future.h.
 * The wrapped contents is a simple Xen-level grant reference.
 */
MAKE_WRAPPER_PUB(ALIEN_GRANT_REF)
MAKE_WRAPPER_PRIV(ALIEN_GRANT_REF, unsigned)

/* An opaque type which acts as a handle for extant grant mappings.
 * You get one of these whenever you map a grant reference, and you
 * need to use it in order to tear the mapping down.
 */
typedef struct {
    unsigned char bytes[8];
} GRANT_MAP_HANDLE;
static __inline GRANT_MAP_HANDLE null_GRANT_MAP_HANDLE(void)
{
    GRANT_MAP_HANDLE gmh = {{0}};
    return gmh;
}
static __inline BOOLEAN is_null_GRANT_MAP_HANDLE(GRANT_MAP_HANDLE gmh)
{
    if (*((ULONG64*)gmh.bytes) == 0)
        return TRUE;
    else
        return FALSE;
}

/* Map @nr_grefs alien grant references from domain @domid into
 * contigous virtual memory.  The grant references should be in a
 * simple array at @grefs, and @h should be a valid xenops handle.
 * *@map is set to the address of the mapping, which is read-only.
 * The behavious is undefined if the mapped memory is written to.
 *
 * A handle to the mapping is placed in *@handle.  This can be used to
 * unmap the memory using xenops_unmap_grant().
 *
 * The mapped memory is not automatically unmapped when the handle is
 * closed, but will be unmapped when the process exits.
 *
 * If the remote domain exits, migrates away, or is suspended, the
 * page is effectively forked, so that the local domain retains access
 * to it, but updates made by the remote domain will no longer be
 * visible.  The mapping must still be unmapped with
 * xenops_unmap_grant() when no longer needed.
 *
 * If the local domain migrates or is suspended and resumed, the
 * remote page is partially unmapped.  The contents of the memory
 * visible through the mapping becomes undefined, and will no longer
 * reflect updates made by the remote domain, but will not cause
 * faults when accessed.  The mapping must still be unmapped with
 * xenops_unmap_grant().
 *
 * XXX What about hibernation?
 *
 * Returns TRUE on success or FALSE on error.  On error, a further
 * error code can be obtained by calling GetLastError().
 */
XENOPS_API BOOL xenops_grant_map_readonly(struct xenops_handle *h,
                                          DOMAIN_ID domid,
                                          unsigned nr_grefs,
                                          ALIEN_GRANT_REF *grefs,
                                          GRANT_MAP_HANDLE *handle,
                                          volatile const void **map);

/* Map @nr_grefs alien grant references from domain @domid into
 * contigous virtual memory.  The grant references should be in a
 * simple array at @grefs, and @h should be a valid xenops handle.
 * *@map is set to the address of the mapping.  The map is writable;
 * it is an error to try to map a read-only grant reference using this
 * function.
 *
 * A handle to the mapping is placed in *@handle.  This can be used to
 * unmap the memory using xenops_unmap_grant().
 *
 * The mapped memory is not automatically unmapped when the handle is
 * closed, but will be unmapped when the process exits.
 *
 * If the remote domain exits, migrates away, or is suspended, the
 * page is effectively forked, so that the local domain retains access
 * to it, but updates made by the remote domain will no longer be
 * visible.  The mapping must still be unmapped with
 * xenops_unmap_grant() when no longer needed.
 *
 * If the local domain migrates or is suspended and resumed, the
 * remote page is partially unmapped.  The contents of the memory
 * visible through the mapping becomes undefined, and will no longer
 * reflect updates made by the remote domain, but will not cause
 * faults when accessed.  The mapping must still be unmapped with
 * xenops_unmap_grant().
 *
 * Returns TRUE on success or FALSE on error.  On error, a further
 * error code can be obtained by calling GetLastError().
 */
XENOPS_API BOOL xenops_grant_map_readwrite(struct xenops_handle *h,
                                           DOMAIN_ID domid,
                                           unsigned nr_grefs,
                                           ALIEN_GRANT_REF *grefs,
                                           GRANT_MAP_HANDLE *handle,
                                           volatile void **map);

/* Unmap a grant reference which was previously mapped with either
 * xenops_grant_map_readonly() or xenops_grant_map_readwrite().
 * @handle should be the handle which was returned by the mapping
 * call, and @h should be a valid xenops handle.  Once this returns,
 * the virtual addresses into which the grant references were mapped
 * is released, and attempts to access it will result in a page fault.
 *
 * @handle may be null, in which case no action is taken.
 */
XENOPS_API void xenops_unmap_grant(struct xenops_handle *h,
                                   GRANT_MAP_HANDLE handle);

/* ---------------------- Event channels -------------------------- */
/* A wrapper type for local event channel ports.  The wrapped value is
 * the Xen-level event channel port number.
 */
MAKE_WRAPPER_PUB(EVTCHN_PORT);
MAKE_WRAPPER_PRIV(EVTCHN_PORT, unsigned);

/* A wrapper type for remote event channel ports.  These are analogous
 * to the type of the same name in xsapi-future.h.  The wrapped value
 * is the Xen-level event channel port number.
 */
MAKE_WRAPPER_PUB(ALIEN_EVTCHN_PORT);
MAKE_WRAPPER_PRIV(ALIEN_EVTCHN_PORT, unsigned);

/* Allocate a local event channel port and start listening for
 * connections from domain @domid.  We arrange that the win32 event
 * object @event will be notified whenever the event channel is
 * signalled.  On success, the local event channel port is written to
 * *@evtchn_port.  @h should be a valid xenops handle.
 *
 * The remote domain @domid may connect and disconnect at will.  There
 * is no indication in the local domain that this has happened.
 *
 * There is no guarantee that the event will be notified precisely
 * once for every notification made by the remote domain, and it may
 * sometimes be notified when the remote domain hasn't done anything.
 * The only guarantee provided is that shortly after the remote domain
 * notifies the port, the event will be notified.
 *
 * The port remains open and listening when the local domain is
 * suspend/resumed, migrated, or hibernated.  The port also remains
 * open and listening when the remote domain goes through one of these
 * events, although the remote domain is likely to be disconnected.
 * This is not particularly useful: any of those events will change
 * the affected domain's ID, and so the port will need to be
 * renegotiated anyway.
 *
 * The returned event channel port will be closed automatically when
 * @h is closed.  It can also be closed by calling
 * xenops_evtchn_close().
 *
 * Returns TRUE on success or FALSE on failure, in which case
 * GetLastError() will provide a more detailed error code.
 */
XENOPS_API BOOL xenops_evtchn_listen(struct xenops_handle *h,
                                     DOMAIN_ID domid,
                                     HANDLE event,
                                     EVTCHN_PORT *evtchn_port);

/* Allocate a local event channel port in *@local_port and then bind
 * it @remote_port in remote domain @domid.  We arrange to notify the
 * Win32 event object @event shortly after the event channel is
 * notified.
 *
 * The port is automatically disconnected if either the local or
 * remote domains migrate, suspend/resume, hibernate, or shut down.
 * In this state, it is valid to send further notifications, but they
 * will be silently discarded by Xen.  There is no reliable way to
 * detect that this has happened.
 *
 * The returned event channel port will be closed automatically when
 * @h is closed.  It can also be closed by calling
 * xenops_evtchn_close().
 *
 * Returns TRUE on success or FALSE on failure, in which case
 * GetLastError() will provide a more detailed error code.
 */
XENOPS_API BOOL xenops_evtchn_connect(struct xenops_handle *h,
                                      DOMAIN_ID domid,
                                      ALIEN_EVTCHN_PORT remote_port,
                                      HANDLE event,
                                      EVTCHN_PORT *local_port);

/* Send a notification over port @evtchn_port, which should have been
 * obtained from xenops_evtchn_connect() or xenops_evtchn_listen().
 * This will always succeed (provided the port is valid), but the
 * notification may be discarded if the other end of the port is not
 * ready.
 */
XENOPS_API void xenops_evtchn_notify(struct xenops_handle *h,
                                     EVTCHN_PORT evtchn_port);

/* Close a local event channel port @evtchn_port.  The port is
 * disconnected and all local resources are freed.  If the port was
 * connected, the other end remains connected, but any further
 * notifications will be discarded.
 *
 * @evtchn_port may be null, in which case no action is taken.
 *
 * @evtchn_port should not be used again after this returns.
 */
XENOPS_API void xenops_evtchn_close(struct xenops_handle *h,
                                    EVTCHN_PORT evtchn_port);

#endif /* !XENOPS_H__ */
