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

#include "xenutl.h"

static void
xm_thread_func(void *data)
{
    struct xm_thread *me = data;

    PsTerminateSystemThread(me->cb(me, me->data));
}

struct xm_thread *
XmSpawnThread(NTSTATUS (*cb)(struct xm_thread *xt, void *d), void *d)
{
    struct xm_thread *work;
    NTSTATUS stat;
    HANDLE tmpHandle;

    work = XmAllocateMemory(sizeof(*work));
    if (!work) return NULL;
    work->exit = FALSE;
    KeInitializeEvent(&work->event, NotificationEvent, FALSE);
    work->cb = cb;
    work->data = d;
    stat = PsCreateSystemThread(&tmpHandle, THREAD_ALL_ACCESS, NULL,
                                INVALID_HANDLE_VALUE, NULL, xm_thread_func,
                                work);
    if (!NT_SUCCESS(stat)) {
        XmFreeMemory(work);
        return NULL;
    }
    stat = ObReferenceObjectByHandle(tmpHandle, SYNCHRONIZE, NULL,
                                     KernelMode, &work->thread,
                                     NULL);
    ZwClose(tmpHandle);
    if (!NT_SUCCESS(stat)) {
        /* We can't reliably kill the thread in this case, and
           therefore can't release memory.  Instruct it to exit soon
           and hope for the best. */
        work->exit = TRUE;
        KeSetEvent(&work->event, IO_NO_INCREMENT, FALSE);
        return NULL;
    }

    return work;
}

void
XmKillThread(struct xm_thread *t)
{
    if (!t)
        return;
    TraceDebug (("Killing thread %p.\n", t));
    XM_ASSERT(KeGetCurrentThread() != t->thread);
    t->exit = TRUE;
    KeSetEvent(&t->event, IO_NO_INCREMENT, FALSE);
    KeWaitForSingleObject(t->thread, Executive, KernelMode, FALSE,
                          NULL);
    ObDereferenceObject(t->thread);
    XmFreeMemory(t);
}

int
XmThreadWait(struct xm_thread *t)
{
    if (t->exit)
        return -1;
    KeWaitForSingleObject(&t->event,
                          Executive,
                          KernelMode,
                          FALSE,
                          NULL);
    KeClearEvent(&t->event);
    if (t->exit)
        return -1;
    else
        return 0;
}


