/******************************************************************************
 * memory.h
 * 
 * Memory reservation and information.
 * 
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
 *
 * Copyright (c) 2005, Keir Fraser <keir@xensource.com>
 */

#ifndef __XEN_PUBLIC_MEMORY_H__
#define __XEN_PUBLIC_MEMORY_H__

#include "xen_types.h"

/*
 * Increase or decrease the specified domain's memory reservation. Returns the
 * number of extents successfully allocated or freed.
 * arg == addr of struct xen_memory_reservation.
 */
#define XENMEM_increase_reservation 0
#define XENMEM_decrease_reservation 1
#define XENMEM_populate_physmap     6

#if defined(XEN_GUEST_HANDLE)

/* 
 * Xen 4.3: The XENMEMF flags and address bits are not used
 * so the macros for setting them were left out.
 */

struct xen_memory_reservation {

    /*
     * XENMEM_increase_reservation:
     *   OUT: MFN (*not* GMFN) bases of extents that were allocated
     * XENMEM_decrease_reservation:
     *   IN:  GMFN bases of extents to free
     * XENMEM_populate_physmap:
     *   IN:  GPFN bases of extents to populate with memory
     *   OUT: GMFN bases of extents that were allocated
     *   (NB. This command also updates the mach_to_phys translation table)
     */
    XEN_GUEST_HANDLE(xen_pfn_t) extent_start;

    /* Number of extents, and size/alignment of each (2^extent_order pages). */
    xen_ulong_t    nr_extents;
    unsigned int   extent_order;

    /* XENMEMF flags. */
    unsigned int   mem_flags;

    /*
     * Domain whose reservation is being changed.
     * Unprivileged domains can specify only DOMID_SELF.
     */
    domid_t        domid;
};
typedef struct xen_memory_reservation xen_memory_reservation_t;
DEFINE_XEN_GUEST_HANDLE(xen_memory_reservation_t);

#endif

/* Xen 4.3: The XENMEM_* values were not used, so they were removed. */

/*
 * Xen 4.1: A number of the XENMAPSPACE_* operations below are obselete
 * (and were that way in Xen 3.4 also). A lot of the memory management
 * code in the PV drivers uses these values and has been operating without
 * issues. Given that, the following is being left as is. 
 */

/*
 * Xen 4.3: These are the real set of space values in 4.3,
 * some of which collide with the old XenServer values.
 */

/* Source mapping space. */
/* ` enum phys_map_space { */
#define XENMAPSPACE_shared_info  0 /* shared info page */
#define XENMAPSPACE_grant_table  1 /* grant table page */
#define XENMAPSPACE_gmfn         2 /* GMFN */
#define XENMAPSPACE_gmfn_range   3 /* GMFN range, XENMEM_add_to_physmap only. */
#define XENMAPSPACE_gmfn_foreign 4 /* GMFN from another dom,
                                    * XENMEM_add_to_physmap_range only.
                                    */
/* ` } */

/* Xen 4.3: These are the old source mapping space values. */

/* This is the same as XENMAPSPACE_shared_info and that should be used */
/*#define XENMAPSPACE_shared_info_compat 0*/ /* shared info page */

/* Just a duplicate */
/* #define XENMAPSPACE_grant_table 1*/ /* grant table page */

/* Never used, collides with XENMAPSPACE_gmfn, nuke it */
/*#define XENMAPSPACE_device_model 2*/ /* hypervisor device model shared area */

/* Danger Will Robinson, this is bad stuff */
/*#define XENMAPSPACE_rw_local_apic_compat 3*/ /* writable apic page (per processor), old location */

/* No longer use used because it collides with XENMAPSPACE_gmfn_foreign, nuke it */
/*#define XENMAPSPACE_shared_info_xs 4*/ /* old shared info page non-compat */

/* Never even present, some XenServer logic we never had, nuke it*/
/*#define XENMAPSPACE_rw_local_apic 0x80000000*/ /* writable apic page (per processor) */

/* More XenServer magic used to be a harmless op to fail in xenbus.c, but now it causes death and mayhem, nuke it */
/*#define XENMAPSPACE_physical 0x80000001*/ /* swizzle P2M map */

/*
 * Sets the GPFN at which a particular page appears in the specified guest's
 * pseudophysical address space.
 * arg == addr of xen_add_to_physmap_t.
 */
#define XENMEM_add_to_physmap      7
struct xen_add_to_physmap {
    /* Which domain to change the mapping for. */
    domid_t domid;

    /* Number of pages to go through for gmfn_range */
    uint16_t    size;

    unsigned int space; /* => enum phys_map_space */

    /* Index into source mapping space. */
    xen_ulong_t idx;

    /* GPFN where the source mapping page should appear. */
    xen_pfn_t     gpfn;
};
typedef struct xen_add_to_physmap xen_add_to_physmap_t;

/*
 * Xen 4.1: This thing no longer exists but it is used in the balloon
 * code so it is being left as is.
 */

/*
 * Force a PoD sweep
 */
#define	XENMEM_pod_sweep            63
struct xen_pod_sweep {
    /* IN */
    uint64_t limit;
    domid_t domid;
};
typedef struct xen_pod_sweep xen_pod_sweep_t;

#endif /* __XEN_PUBLIC_MEMORY_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
