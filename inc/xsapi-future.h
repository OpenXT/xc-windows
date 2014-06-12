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

#ifndef XSAPI_FUTURE_H__
#define XSAPI_FUTURE_H__

/* This header is for bits of the API which I'm not sure about and
 * which are subject to change without notice.  Access to the features
 * in here is controlled by a set of feature macros, so that nobody
 * uses them accidentally:
 *
 * XSAPI_FUTURE_GRANT_MAP -- Support for mapping grant references from
 * a remote domain into the local domain's address space, so that the
 * local domain has access to the remote domain's memory.  Note that
 * this is not necessary if all you want to do is allow a remote
 * domain to access local memory; for that, use the GRANT_REF APIs in
 * xsapi.h
 *
 * XSAPI_FUTURE_CONNECT_EVTCHN -- Support for connecting to an event
 * channel port exposed by a remote domain.  Note, again, that this is
 * not necessary if you only want to allow remote domains to connect
 * to event channels in the local domain; for that, use the
 * EVTCHN_PORT APIs in xsapi.h.
 */

#ifdef XSAPI_FUTURE_GRANT_MAP

/* A wrapper type for grant references which have been offered to us
 * by a remote domain.  Any given ALIEN_GRANT_REF is only meaningful
 * when interpreted with respect to a particular remote DOMAIN_ID, and
 * it is the caller's responsibility to track which domain a
 * particular grant reference is measured against.
 */
MAKE_WRAPPER_PUB(ALIEN_GRANT_REF)

/* When the library maps a batch of alien grant references, it returns
 * the results as an opaque struct grant_map_detail.  This can be used
 * to obtain an MDL describing the mapping or to unmap the references.
 * They cannot be used for any other purpose.
 */
struct grant_map_detail;


/* Read an alien grant reference from @prefix/@node under transaction
 * @xbt, and store it in *@gref.  @prefix/@node is expected to contain
 * a positive base-10 integer less than 2^32.  For Windows domains,
 * the value in the store should be whatever is returned by
 * xen_GRANT_REF(); for other operating systems, it will be something
 * appropriate for that OS.
 *
 * Note that a grant reference of 0 cannot be read by this routine.
 * While that is, strictly speaking, a valid reference, it is reserved
 * for use by Xen and toolstack, and should not be used by ordinary
 * drivers.
 *
 * On error, *@gref is set to null_ALIEN_GRANT_REF().
 *
 * @xbt may be nil, null, or a valid transaction.
 */
XSAPI NTSTATUS xenbus_read_grant_ref(xenbus_transaction_t xbt, PCSTR prefix,
                                     PCSTR node, ALIEN_GRANT_REF *gref);

/* Map a batch of @nr_grefs alien grant references drawn against
 * remote domain @domid into the local domain's physical address
 * space, and construct a grant_map_detail describing the mapping.
 * The grant references to map should be in a simple array at @grefs.
 * The mapping is read-only if @mode is GRANT_MODE_RO, and writable if
 * @mode is GRANT_MODE_RW.  The constructed grant_map_detail is
 * returned in *@detail.  It must be released by the caller with
 * GntmapUnmapGrants() when it is no longer needed.
 *
 * If the grant is mapped read-only and is then written to by the
 * local domain, the behaviour is undefined[1].
 *
 * On entry, the caller should ensure that *@detail is NULL.  *@detail
 * will remain NULL on error.
 *
 * This call either succeeds or fails; it will not partially succeed.
 * In particular, if *any* grant reference in @grefs is invalid, the
 * entire call fails, and no grant references are mapped.
 *
 * If the remote domain exits, migrates, or is suspended, the page is
 * effectively forked, so that the local domain retains access to it,
 * but updates made by the remote domain will no longer be visible.
 * The mapping must still be unmapped with GntmapUnmapGrants().
 *
 * If the local domain migrates or is suspended and resumed, the
 * remote page is partially unmapped.  The contents of the memory
 * visible through the mapping becomes undefined[2], and will no
 * longer reflect updates made by the remote domain, but will not
 * cause faults when accessed.  The mapping must still be unmapped
 * with GntmapUnmapGrants().
 *
 * XXX What about hibernation?
 *
 * Call from IRQL < DISPATCH_LEVEL.
 *
 * Returns STATUS_SUCCESS on success, or some other value x such that
 * NT_SUCCESS(x) is false on failure.
 *
 * [1] At present, Xen will either ignore the write completely, so the
 * memory remains unchanged, or raise a page fault against the local
 * domain.  It is not guaranteed that no other behaviours will be
 * introduced by future versions of Xen or this library.
 *
 * [2] At present, the memory will appear to be full of 0xff bytes,
 * and will ignore writes; this is subject to change in future
 * versions of Xen.
 */
XSAPI NTSTATUS GntmapMapGrants(DOMAIN_ID domid,
                               unsigned nr_grefs,
                               const ALIEN_GRANT_REF *grefs,
                               GRANT_MODE mode,
                               struct grant_map_detail **detail);

/* Unmap a batch of grant references which were previously mapped with
 * GntmapMapGrants().  The physical memory into which the grants were
 * mapped is repurposed, and accessing it will cause undefined
 * behaviour.
 *
 * @detail must be a grant_map_detail which was previously returned by
 * GntmapMapGrants() and which has not already been passed to
 * GntmapUnmapGrants().  It must not be NULL.
 *
 * The memory described by the detail structure must not be mapped
 * when this is called.  (i.e. any calls to MmMapLockedPages() on the
 * detail's MDL must have been balanced by calls to
 * MmUnmapLockedPages().)
 *
 * Call from IRQL < DISPATCH_LEVEL.
 */
XSAPI void GntmapUnmapGrants(struct grant_map_detail *detail);

/* Given a grant_map_detail @gmd which was previously returned by
 * GntmapMapGrants() and which has not already been passed to
 * GntmapUnmapGrants(), build an MDL describing the physical memory
 * into which the grants were mapped.
 *
 * The resulting MDL describes locked IO memory, and can be mapped
 * using MmMapLockedPages() or MmMapLockedPagesSpecifyCache() in the
 * usual way.  Likewise, the physical memory into which the grants
 * have been unmapped can be obtained via MmGetPfnArrayForMdl().
 *
 * The MDL must not be modified in any other way, and must not be
 * released (except via GntmapUnmapGrants()).  If the caller does map
 * the MDL, they must unmap them again before calling
 * GntmapUnmapGrants().
 *
 * It is not possible to re-grant memory which has been obtained in
 * this way.  In particular, if a PFN described by the mapping MDL is
 * passed to GnttabGrantForeignAccess() or
 * GnttabGrantForeignAccessCache(), the resulting GRANT_REF will not
 * be valid.
 *
 * The MDL is valid until the grant_map_detail is unmapped with
 * GntmapUnmapGrants().
 *
 * This routine never fails, and can be called at any IRQL.
 */
XSAPI PMDL GntmapMdl(struct grant_map_detail *gmd);

#endif /* !XSAPI_FUTURE_GRANT_MAP */

#ifdef XSAPI_FUTURE_CONNECT_EVTCHN

/* A wrapper type for event channel ports which have been offered to
 * us by a remote domain.  Any given ALIEN_EVTCHN_PORT is only
 * meaningful when interpreted with respect to a particular remote
 * DOMAIN_ID, and it is the caller's responsibility to track which
 * domain a particular grant reference is measured against.
 */
MAKE_WRAPPER_PUB(ALIEN_EVTCHN_PORT)

/* Read an alien event channel port from @prefix/@node under
 * transaction @xbt, and store it in *@port.  @prefix/@node is
 * expected to contain a non-negative base-10 integer less than 2^32,
 * and this is used as the remote port number when communicating with
 * Xen.  For remote Windows VMs, the store node should have been
 * populated with xenbus_write_evtchn_port(); other guest operating
 * systems will provide analogous APIs.
 *
 * On error, *@port is set to null_ALIEN_EVTCHN_PORT().
 *
 * @xbt may be nil, null, or a valid transaction.
 */
XSAPI NTSTATUS xenbus_read_evtchn_port(xenbus_transaction_t xbt, PCSTR prefix,
                                       PCSTR node, ALIEN_EVTCHN_PORT *port);

/* Bind the alien event channel port @port in domain @domid to a local
 * event channel port, and arrange that @cb will be called with
 * argument @context shortly after the remote domain notifies the
 * port.  The local event channel port is returned.
 *
 * The local port has semantics broadly analogous to those of
 * EvtchnAllocUnboundDpc():
 *
 * -- The port cannot be masked with EvtchnPortMask(), or unmasked with
 *    EvtchnPortUnmask().
 * -- The callback is run from a DPC.  The details of how this is done
 *    are not defined; in particular, there is no guarantee that there is
 *    a one-to-one correspondence between EVTCHN_PORTs and Windows DPCs.
 * -- It is guaranteed that a single port will only fire on one CPU at
 *    a time.  However, the library may fire different ports in parallel.
 * -- The port may be fired spuriously at any time.
 * -- There is no guarantee that every notification issued by the
 *    remote will cause precisely one invocation of the callback.  In
 *    particular, if the remote notifies the port several times in quick
 *    succession, the events may be aggregated into a single callback.
 *    There is no general way to detect that this has happened.
 *
 * There is no way to run a remote port callback directly from the
 * interrupt handler.
 *
 * The remote domain may close the alien event channel port at any
 * time.  If that happens before the call to EvtchnConnectRemotePort()
 * completes, it returns an error.  If it happens after the call
 * completes, there is no way for the local domain to tell, and
 * notifications to the port are simply dropped.
 *
 * If the local domain suspend and resumes, migrates, or hibernates
 * and restores, the library will attempt to automatically reconnect
 * the port.  This may, of course, fail, in which case we behave as if
 * the remote domain had closed the port.
 *
 * The port should be closed with EvtchnClose() once it is no longer
 * needed.
 *
 * Call at PASSIVE_LEVEL.
 */
XSAPI EVTCHN_PORT EvtchnConnectRemotePort(DOMAIN_ID domid,
                                          ALIEN_EVTCHN_PORT port,
                                          PEVTCHN_HANDLER_CB cb,
                                          void *context);
#endif /* XSAPI_FUTURE_CONNECT_EVTCHN */

#endif /* !XSAPI_FUTURE_H__ */
