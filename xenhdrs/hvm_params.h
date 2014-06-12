/*
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef __XEN_PUBLIC_HVM_PARAMS_H__
#define __XEN_PUBLIC_HVM_PARAMS_H__

#include "xen.h"

/*
 * Xen 4.1: This file is a mix of values from several files from under:
 * xen/include/public/hvm
 *
 * A number of the HVM params and ops were obsolete (actually non-existent)
 * and were removed. Other HVM ops had their op numbers changed.
 *
 * Removed:
 * HVM_PARAM_32BIT
 * HVMOP_process_destroy_compat
 * HVMOP_process_destroy
 * HVMOP_set_driver_version
 * HVMOP_audit_world
 * HVMOP_wheres_my_memory
 * HVMOP_guest_crashing
 * 
 */

/* hvm/params.h */

/*
 * How should CPU0 event-channel notifications be delivered?
 * val[63:56] == 0: val[55:0] is a delivery GSI (Global System Interrupt).
 * val[63:56] == 1: val[55:0] is a delivery PCI INTx line, as follows:
 *                  Domain = val[47:32], Bus  = val[31:16],
 *                  DevFn  = val[15: 8], IntX = val[ 1: 0]
 * val[63:56] == 2: val[7:0] is a vector number, check for
 *                  XENFEAT_hvm_callback_vector to know if this delivery
 *                  method is available.
 * If val == 0 then CPU0 event-channel notifications are not delivered.
 */
#define HVM_PARAM_CALLBACK_IRQ 0

/*
 * These are not used by Xen. They are here for convenience of HVM-guest
 * xenbus implementations.
 */
#define HVM_PARAM_STORE_PFN    1
#define HVM_PARAM_STORE_EVTCHN 2

/* hvm/hvm_op.h */

#define HVMOP_set_param 0
#define HVMOP_get_param 1

struct xen_hvm_param {
    domid_t domid;
    unsigned index;
    ULONGLONG value;
};
typedef struct xen_hvm_param xen_hvm_param_t;

/*
 * Xen 4.3: HVMOP_get_time_compat collides with
 * HVMOP_track_dirty_vram. GetXenTime() should be fixed to not
 * use the compat op.
 */
/* Get the current Xen time, in nanoseconds since system boot. */
/*#define HVMOP_get_time_compat            6*/
#define HVMOP_get_time                   10
struct xen_hvm_get_time {
    ULONGLONG now;      /* OUT */
};
typedef struct xen_hvm_get_time xen_hvm_get_time_t;

/* Allows PV drivers to inject performance tracing. */
#define HVMOP_xentrace              11

/*
 * Xen 4.3: These seem to be missing and I don't see what
 * the event value for xentrace might be. It looks like this
 * will just be traced (or not) as possibly the wrong event.
 * I cannot find equivalent trace macros for these so I will just
 * leave them.
 */
/*
 * First extra element is a void *
 * Second extra element is the int
 */
#define HVM_EVENT_PROCESS_CREATE    1

/*
 * First extra element is a void *
 * Remaining extra bytes is ANSI process name.
 */
#define HVM_EVENT_IMAGE_LOAD        2

struct xen_hvm_xentrace {
    uint16_t event, extra_bytes;
    uint8_t extra[28];
};
typedef struct xen_hvm_xentrace xen_hvm_xentrace_t;

#endif
