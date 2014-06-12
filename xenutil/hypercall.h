//
// hypercall.h
//
// Windows interface to the xen hypervisor.
//
// Copyright (c) 2006 XenSource, Inc.
//

/*
 * Copyright (c) 2011 Citrix Systems, Inc.
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


#ifndef __HYPERCALL_H__
#include <xen.h>

typedef char hypercall_trap_gate[32];

extern ULONG_PTR __hypercall2(unsigned long ordinal,
                              ULONG_PTR arg1,
                              ULONG_PTR arg2);
extern ULONG_PTR __hypercall3(unsigned long ordinal,
                              ULONG_PTR arg1,
                              ULONG_PTR arg2,
                              ULONG_PTR arg3);
extern ULONG_PTR __hypercall6(unsigned long ordinal,
                              ULONG_PTR arg1,
                              ULONG_PTR arg2,
                              ULONG_PTR arg3,
                              ULONG_PTR arg4,
                              ULONG_PTR arg5,
                              ULONG_PTR arg6);

#define _hypercall2(type, name, arg1, arg2) \
    ((type)__hypercall2(__HYPERVISOR_##name, (ULONG_PTR)arg1, (ULONG_PTR)arg2))
#define _hypercall3(type, name, arg1, arg2, arg3) \
    ((type)__hypercall3(__HYPERVISOR_##name, (ULONG_PTR)arg1, (ULONG_PTR)arg2, (ULONG_PTR)arg3))
#define _hypercall6(type, name, arg1, arg2, arg3, arg4, arg5, arg6) \
    ((type)__hypercall6(__HYPERVISOR_##name, (ULONG_PTR)arg1, (ULONG_PTR)arg2, (ULONG_PTR)arg3, (ULONG_PTR)arg4, (ULONG_PTR)arg5, (ULONG_PTR)arg6))

__declspec(inline) int
HYPERVISOR_event_channel_op(int cmd, void *op)
{
    return _hypercall2(int, event_channel_op, cmd, op);
}

__declspec(inline) int
HYPERVISOR_sched_op(
    int cmd, void *arg)
{
    return _hypercall2(int, sched_op, cmd, arg);
}

_declspec(inline) ULONG_PTR
HYPERVISOR_hvm_op(
    int op, void *arg)
{
    return _hypercall2(ULONG_PTR, hvm_op, op, arg);
}

_declspec(inline) int
HYPERVISOR_memory_op(
    unsigned int cmd, void *arg)
{
    return _hypercall2(int, memory_op, cmd, arg);
}

__declspec(inline) int
HYPERVISOR_grant_table_op(
    unsigned int cmd, void *arg, unsigned nr_operations)
{
    return _hypercall3(int, grant_table_op, cmd, arg, nr_operations);
}

__declspec(inline) int
HYPERVISOR_v4v_op(
    unsigned int cmd, void *arg2, void *arg3, void *arg4, ULONG32 arg5, ULONG32 arg6)
{
    return _hypercall6(int, v4v_op, cmd, arg2, arg3, arg4, arg5, arg6);
}

#endif /* __HYPERCALL_H__ */
