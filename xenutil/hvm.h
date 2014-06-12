//
// hvm.h - Exports and prototypes for communicating with the xen
//         hypervisor.
//
// Copyright (c) 2006 XenSource, Inc. - All rights reserved.
//

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

#ifndef _HVM_H_
#define _HVM_H_

#include <ntddk.h>
#include <xen.h>

extern shared_info_t *HYPERVISOR_shared_info;
extern int HvmInterruptNumber;

//
// Function prototypes.
//
NTSTATUS
InitHvm(void);

VOID
CleanupHvm(
       VOID
);

int
AddPageToPhysmap(PFN_NUMBER pfn,
         unsigned space,
         unsigned long offset);

ULONG_PTR
HvmGetParameter(int param_nr);

ULONG_PTR _readcr3(VOID);

VOID _wrmsr(uint32_t msr, uint32_t lowbits, uint32_t highbits);

void UnquiesceSystem(KIRQL OldIrql);
KIRQL QuiesceSystem(VOID);

VOID KillSuspendThread(VOID);
VOID SuspendPreInit(VOID);

int __HvmSetCallbackIrq(const char *caller, int irq);
#define HvmSetCallbackIrq(_irq) __HvmSetCallbackIrq(__FUNCTION__, (_irq))

void DescheduleVcpu(unsigned ms);

NTSTATUS HvmResume(VOID *ignore, SUSPEND_TOKEN token);

extern void EvtchnLaunchSuspendThread(VOID);

#ifndef AMD64
/* Force a processor pipeline flush, so that self-modifying code
   becomes safe to run. */
#define FLUSH_PIPELINE() _asm { cpuid }

ULONG_PTR _readcr4(VOID);

/* Query whether VM is running with PAE */
BOOLEAN IsPAEEnabled(VOID);

#else
/* AMD64 -> no binary patches -> FLUSH_PIPELINE is a no-op */
#define FLUSH_PIPELINE() do {} while (0)
#endif

#endif /* _HVM_H_ */

