/******************************************************************************
 * xen-x86_32.h
 * 
 * Guest OS interface to x86 32-bit Xen.
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
 * Copyright (c) 2004-2007, K A Fraser
 */

#ifndef __XEN_PUBLIC_ARCH_X86_32_H__
#define __XEN_PUBLIC_ARCH_X86_32_H__

/* Xen 4.1: Removed all of the unused defines - some of which had changed anyway */

/* Maximum number of virtual CPUs in legacy multi-processor guests. */
#define XEN_LEGACY_MAX_VCPUS 32 /* arch-x86/xen.h */
/* Maximum number of virtual CPUs in multi-processor guests. */
#define MAX_VIRT_CPUS XEN_LEGACY_MAX_VCPUS /* asm-x86/config.h */

typedef struct arch_shared_info {
    unsigned long max_pfn;                  /* max pfn that appears in table */
    /* Frame containing list of mfns containing list of mfns containing p2m. */
    xen_pfn_t     pfn_to_mfn_frame_list_list;
    unsigned long nmi_reason;
    uint64_t pad[32];
} arch_shared_info_t;

/*
 * Xen 4.3: Ok so the x64 one has been busted forever. On Windows
 * a long is 32b on both 32b/64b so you only get 1/2 the cr2 register.
 * Lucky for us a) they got the pad size right so vcpu_info_t comes
 * out right and b) they never use cr2 anywhere. I am torn about
 * fixing it since the less that is changed the better. I guess if
 * anyone ever tries to use this they will see this comment.
 */
#ifdef AMD64
typedef struct {
    unsigned long cr2;
    unsigned long pad[3]; /* sizeof(vcpu_info_t) == 64 */
} arch_vcpu_info_t;
#else
typedef struct {
    unsigned long cr2;
    unsigned long pad[5]; /* sizeof(vcpu_info_t) == 64 */
} arch_vcpu_info_t;
#endif

#endif

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
