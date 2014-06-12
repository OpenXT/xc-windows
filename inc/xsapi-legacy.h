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

/* Legacy APIs maintained for compatibility reasons.  These should not
   be used in new code. */

#include "xsapi.h"

/* All of these prototypes are gated on #defines, which are used to
   indicate which legacy APIs the client wants to use.

   XSAPI_LEGACY_PORT_MASK
   ----------------------
   Controls visibility of EvtchnPortMask() and EvtchnPortUnmask().
   New code should use EvtchnAllocUnboundDpc(), which does the same
   thing more efficiently and more cleanly, and which interacts badly
   with the port masking APIs.  These APIs were deprecated in Orlando.

   XSAPI_LEGACY_WRITE_STATE
   ------------------------
   Controls visibility of xenbus_write_state().  New code should use
   xenbus_change_state() instead.  xenbus_write_state() is difficult
   to use correctly because the device whose state is being changed
   could be hot-remove or even surprise-removed while it is running,
   and in that case xenbus_write_state() will re-create the state node
   in the store.  This causes the bus driver to think that the removed
   device has been re-introduced, but the control tools will not
   recreate the backend.  The device will therefore be present in a
   non-functional state, which is almost never the desired effect.

   XSAPI_LEGACY_READ_INTEGER
   -------------------------
   Controls visibility of XenbusReadInteger().  New code should use
   xenbus_read_int() instead, because XenbusReadInteger() doesn't
   allow the caller to reliably detect errors.  This API was
   deprecated in Midnight Ride.

   XSAPI_LEGACY_XENBUS_TRANSACTION_START_RETURNS_NTSTATUS
   ------------------------------------------------------
   Controls the return type of xenbus_transaction_start().  With this
   legacy control defined, it is NTSTATUS, whereas by default it is
   VOID.  The return value of this function should only ever be used
   for optimisations, but most callers try to use it for correctness.
   The optimisations enabled are usually very small, and so the return
   type was changed to void in Midnight Ride.

   This legacy control is implemented in xsapi.h, rather than in
   xsapi-legacy.h, because it changes a non-deprecated function rather
   than enabled a deprecated one.
*/

#ifdef XSAPI_LEGACY_PORT_MASK

/* Mask the event channel port @port.  Once this is called, the event
 * channel callback will not be run again until the next call to
 * EvtchnPortUnmask().  However, EvtchnPortMask() will *not* wait for
 * any current invocations of the callback to complete.
 *
 * This function is primarily used as an optimisation, and can
 * dramatically reduce the number of interrupts taken in some
 * workloads.
 *
 * DPC ports cannot be masked or unmasked.  It is an error to call
 * EvtchnPortMask() on a port allocated with EvtchnAllocUnboundDpc().
 *
 * @port may not be null.
 *
 * Can be invoked from any IRQL, holding any combination of locks.
 *
 * Deprecated in Orlando in favour of EvtchnAllocUnboundDpc().
 */
XSAPI void EvtchnPortMask(__in EVTCHN_PORT port);

/* Unmask the event channel port @port which was previously masked
 * by EvtchnPortMask().  Once this is called, notifications will
 * be received normally on this port.
 *
 * Note that if the port was raised whilst masked, the callback
 * will not be run automatically.  EvtchnPortUnmask() will return
 * TRUE in that case, and the caller is expected to recover
 * from this situation.  EvtchnPortUnmask() will otherwise
 * return FALSE.
 *
 * DPC ports cannot be masked or unmasked.  It is an error to call
 * EvtchnPortUnmask() on a port allocated with
 * EvtchnAllocUnboundDpc().
 *
 * @port may not be null.
 *
 * Can be invoked from any IRQL, holding any combination of locks.
 *
 * Deprecated in Orlando in favour of EvtchnAllocUnboundDpc().
 */
XSAPI BOOLEAN EvtchnPortUnmask(__in EVTCHN_PORT port);
#endif /* XSAPI_LEGACY_PORT_MASK */

#ifdef XSAPI_LEGACY_WRITE_STATE
/* Write the XENBUS_STATE @state to the store at @prefix/@node under
 * the transaction @xbt.
 *
 * @xbt may be nil, null, or a valid transaction.  @state should not
 * be null.
 *
 * Deprecated in George in favour of xenbus_change_state().
 */
XSAPI NTSTATUS xenbus_write_state(xenbus_transaction_t xbt, PCSTR prefix,
                                  PCSTR node, XENBUS_STATE state);
#endif /* XSAPI_LEGACY_WRITE_STATE */

#ifdef XSAPI_LEGACY_READ_INTEGER
/* Read a decimal integer from @prefix/@node under transaction @xbt.
 * The semantics are similar to xenbus_read_int() except that the
 * result is returned on success and -1 is returned on error; thus
 * this function cannot be safely used on a store node where -1 is
 * a valid value.
 *
 * Deprecated in Midnight Ride in favour of xenbus_read_int().
 */
XSAPI ULONG64 XenbusReadInteger(xenbus_transaction_t xbt, PCSTR prefix,
                                PCSTR node);
#endif /* XSAPI_LEGACY_READ_INTEGER */
