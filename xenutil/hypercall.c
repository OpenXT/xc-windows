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

#include <ntddk.h>
#include "xsapi.h"

#include "hypercall.h"

extern hypercall_trap_gate *hypercall_page;

__declspec(inline) ULONG_PTR
__hypercall2(
    unsigned long ordinal,
    ULONG_PTR arg1,
    ULONG_PTR arg2)
{
    ULONG_PTR retval;
    ULONG_PTR addr = (ULONG_PTR)&hypercall_page[ordinal];

    _asm
    {
        mov ecx, arg2;
        mov ebx, arg1;
        mov eax, addr;
        call eax;
        mov retval, eax;
    }
    return retval;
}

__declspec(inline) ULONG_PTR
__hypercall3(
    unsigned long ordinal,
    ULONG_PTR arg1,
    ULONG_PTR arg2,
    ULONG_PTR arg3)
{
    ULONG_PTR retval;
    ULONG_PTR addr = (ULONG_PTR)&hypercall_page[ordinal];

    _asm
    {
        mov edx, arg3;
        mov ecx, arg2;
        mov ebx, arg1;
        mov eax, addr;
        call eax;
        mov retval, eax;
    }
    return retval;
}

#pragma warning(push)
#pragma warning(disable: 4731)

__declspec(inline) ULONG_PTR
__hypercall6(
    unsigned long ordinal,
    ULONG_PTR arg1,
    ULONG_PTR arg2,
    ULONG_PTR arg3,
    ULONG_PTR arg4,
    ULONG_PTR arg5,
    ULONG_PTR arg6)
{
    ULONG_PTR retval;
    ULONG_PTR addr = (ULONG_PTR)&hypercall_page[ordinal];

    _asm
    {
        mov edi, arg5;
        mov esi, arg4;
        mov edx, arg3;
        mov ecx, arg2;
        mov ebx, arg1;
        mov eax, addr;
        /* Handle ebp carefully */
        push ebp;
        push arg6;
        pop ebp;
        call eax;
        pop ebp;
        mov retval, eax;
    }
    return retval;
}
#pragma warning(pop)
