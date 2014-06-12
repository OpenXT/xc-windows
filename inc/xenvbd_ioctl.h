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

#ifndef XENVBD_IOCTL_H__
#define XENVBD_IOCTL_H__

#include "ntddscsi.h"
#include "types.h"
#include "xsapi.h"

#include "..\\xenvbd\\blkif.h"

#ifndef BLKIF_MAX_SEGMENTS_PER_REQUEST
#define BLKIF_MAX_SEGMENTS_PER_REQUEST 11
#endif

/* Shared rings can be up to 4 pages. */
#define MAX_RING_PAGE_ORDER 2
#define MAX_RING_PAGES (1 << MAX_RING_PAGE_ORDER)

/* Must be exactly 8 bytes, including the terminator */
#define XENVBD_IOCTL_SIGNATURE ((UCHAR *)"ctxxvbd")

#define XENVBD_IOCTL_SNIFF \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define XENVBD_IOCTL_WAKEUP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Forward declaration for xenvbd -> scsifilt calling context */
struct scsifilt;

enum {
    /* Request is new, and not yet initialised. */
    SfrStateFresh = 0x1279,
    /* Request has been initialised and is ready for xenvbd.  Bounce
       buffers have been allocated, but not grant references. */
    SfrStateInitialised,
    /* Request is in xenvbd's pending queue, but has not yet been to
       the backend. */
    SfrStateQueued,
    /* Request has been submitted to the backend. */
    SfrStateSubmitted,
    /* Request has come back from the backend. */
    SfrStateProcessed,
    /* The corresponding IRP has been completed and there is no more
       to do. */
    SfrStateComplete
} SfrState;

/* Xenvbd exposes four main functions to scsifilt:

   switch_to_filter() -- Switch the device from using xenvbd IO to
                         using scsifilt IO.  xenvbd detach from the
                         device and releases all associated resources.
                         Bad things will happen if any more data path
                         requests arrive through scsiport; scsifilt
                         *must* handle everything.  After issuing a
                         sniff ioctl, calling switch_to_filter() is
                         mandatory.  You must eventually call
                         switch_from_filter() after calling this.
                         Called at IRQL=PASSIVE_LEVEL holding no
                         locks.

   switch_from_filter() -- Detach from xenvbd.  Xenvbd may destroy the
                           target at its convenience once this has
                           been called.  Despite the name, this does
                           not allow xenvbd to process IO again, so it
                           should only be used once the device is
                           dead.  Called at IRQL=PASSIVE_LEVEL holding
                           no locks.

   pre_hibernate() -- scsifilt is required to call this just before it
                      hibernates, because scsiport doesn't give us any
                      suitable callbacks to shut the filter interface
                      down from.  Called at IRQL == PASSIVE_LEVEL.

   complete_redirected_srb() -- a SRB which was bounced back up to
                                scsifilt via redirect_srb() has now
                                completed.  Tell scsiport about it.
                                Called at IRQL == PASSIVE_LEVEL.

   Scsifilt exposes two functions to xenvbd:

   kick() -- Request that scsifilt send xenvbd a KICK ioctl soon.  This
             is called at irql <= DISPATCH_LEVEL holding some unknown
             set of locks.

   redirect_srb() -- A data-path request made it to xenvbd despite
                     scsifilt's best efforts.  Assemble an IRP and try
                     it again.  This is called at device IRQL holding
                     the targets lock for reading.

   Scsifilt provides its callbacks to xenvbd as parameters to the
   bind() function.  We use this approach rather than the more obvious
   scheme of putting the function pointers in the ioctl_sniff
   structure because scsiport's ioctl interface makes it difficult for
   xenvbd to confirm that an ioctl came from kernel space rather than
   userspace.  It seemed like a bad idea to allow xenvbd to jump to an
   arbitrary address in userspace, and this scheme prevents that.

   There's an asymmetry here: scsifilt knows that it sent the ioctl to
   the right place, so it can trust the results, but xenvbd doesn't
   know where it came from, so it can't trust the request.

   The results of this ioctl are valid until switch_from_target() is
   called.
*/

struct xenvbd_ioctl_sniff {
    SRB_IO_CONTROL header;
    unsigned version; /* Sanity check: we don't do forwards or
                         backwards compatibility on this interface,
                         but we can at least arrange that the crash is
                         easy to recognise. */
#define XENVBD_IOCTL_SNIFF_VERSION 8
    ULONG target_id;
    char *frontend_path;

    void (*switch_to_filter)(ULONG target_id,
                             struct scsifilt *sf,
                             void (*redirect_srb)(struct scsifilt *sf,
                                                  PSCSI_REQUEST_BLOCK srb));
    void (*switch_from_filter)(ULONG target_id);

    void (*complete_redirected_srb)(ULONG target_id,
                                    PSCSI_REQUEST_BLOCK srb);
    void (*set_target_info)(ULONG target_id,
                            ULONG info);
    void (*target_start)(ULONG target_id, char *backend_path,
                         SUSPEND_TOKEN token);
    void (*target_stop)(ULONG target_id);
    void (*target_resume)(ULONG target_id, SUSPEND_TOKEN token);
};

#endif /* !XENVBD_IOCTL_H__ */
