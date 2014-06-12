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

//
// Basic workitem implementation. This is intended to be roughly equivalent
// to the Windows IO_WORKITEM API but does not rely on a DEVICE_OBJECT.
//
#include <ntddk.h>
#include <xsapi.h>
#include <scsiboot.h>

typedef struct _XEN_WORKITEM    XEN_WORKITEM;
struct _XEN_WORKITEM {
    ULONG                   Magic;
    const CHAR              *Name;
    XEN_WORK_CALLBACK       Work;
    VOID                    *Context;
    LIST_ENTRY              List;
    LARGE_INTEGER           Start;
};
#define WORKITEM_MAGIC  0x02121996

static struct xm_thread *WorkItemThread;

static struct irqsafe_lock WorkItemDispatchLock;
static LIST_ENTRY  PendingWorkItems;
static XEN_WORKITEM *CurrentItem;

static VOID
XenWorkItemDump(
    IN  VOID    *Context
    )
{
    KIRQL       Irql;
    NTSTATUS    status;

    UNREFERENCED_PARAMETER(Context);

    status = try_acquire_irqsafe_lock(&WorkItemDispatchLock, &Irql);
    if (!NT_SUCCESS(status)) {
        TraceInternal(("Could not acquire WorkItemDispatchLock\n"));
        return;
    }

    if (CurrentItem != NULL) {
        LARGE_INTEGER   Now;
        ULONGLONG       Milliseconds;

        KeQuerySystemTime(&Now);
        Milliseconds = (Now.QuadPart - CurrentItem->Start.QuadPart) / 10000ull;

        TraceInternal(("Processing work item '%s' for %llums\n", CurrentItem->Name, Milliseconds));
    } else {
        TraceInternal(("No current work item\n"));
    }

    if (!IsListEmpty(&PendingWorkItems)) {
        PLIST_ENTRY Head;

        TraceInternal(("Pending work items:\n"));
        Head = PendingWorkItems.Flink;
        XM_ASSERT(Head != &PendingWorkItems);

        do {
            XEN_WORKITEM *Item;

            Item = CONTAINING_RECORD(Head, XEN_WORKITEM, List);
            TraceInternal(("%s\n", Item->Name));

            Head = Head->Flink;
        } while (Head != &PendingWorkItems);
    } else {
        TraceInternal(("No pending work items\n"));
    }

    release_irqsafe_lock(&WorkItemDispatchLock, Irql);
}

static NTSTATUS
XenWorkItemDispatch(
    IN  struct xm_thread    *pSelf,
    IN  VOID                *Argument
    )
{
    KIRQL                   Irql;

    UNREFERENCED_PARAMETER(Argument);

    while (XmThreadWait(pSelf) >= 0) {
        Irql = acquire_irqsafe_lock(&WorkItemDispatchLock);
        while (!IsListEmpty(&PendingWorkItems)) {
            PLIST_ENTRY Head;
            XEN_WORKITEM *Item;

            Head = RemoveHeadList(&PendingWorkItems);
            Item = CurrentItem = CONTAINING_RECORD(Head, XEN_WORKITEM, List);
            release_irqsafe_lock(&WorkItemDispatchLock, Irql);

            XM_ASSERT(CurrentItem->Magic == WORKITEM_MAGIC);

            KeQuerySystemTime(&Item->Start);

            TraceVerbose(("%s: invoking '%s'\n", __FUNCTION__, CurrentItem->Name));
            CurrentItem->Work(CurrentItem->Context);

            Irql = acquire_irqsafe_lock(&WorkItemDispatchLock);
            CurrentItem = NULL;
            release_irqsafe_lock(&WorkItemDispatchLock, Irql);

            XmFreeMemory(Item);

            Irql = acquire_irqsafe_lock(&WorkItemDispatchLock);
        }
        release_irqsafe_lock(&WorkItemDispatchLock, Irql);
    }

    TraceWarning(("%s: terminating.\n", __FUNCTION__));
    return STATUS_SUCCESS;
}

NTSTATUS
_XenQueueWork(
    IN  const CHAR          *Caller,
    IN  const CHAR          *Name,
    IN  XEN_WORK_CALLBACK   Work,
    IN  VOID                *Context
    )
{
    XEN_WORKITEM            *Item;
    KIRQL                   Irql;

    Item = XmAllocateZeroedMemory(sizeof(XEN_WORKITEM));
    if (!Item) {
        TraceError(("%s: %s() failed to queue %s\n", __FUNCTION__, Caller, Name));
        return STATUS_NO_MEMORY;
    }
    TraceVerbose(("%s: %s() queueing '%s'\n", __FUNCTION__, Caller, Name));

    Item->Magic = WORKITEM_MAGIC;
    Item->Name = Name;
    Item->Work = Work;
    Item->Context = Context;

    Irql = acquire_irqsafe_lock(&WorkItemDispatchLock);
    InsertTailList(&PendingWorkItems, &Item->List);
    release_irqsafe_lock(&WorkItemDispatchLock, Irql);

    KeSetEvent(&WorkItemThread->event, IO_NO_INCREMENT, FALSE);

    return STATUS_SUCCESS;
}

NTSTATUS
XenWorkItemInit(
    VOID)
{
    InitializeListHead(&PendingWorkItems);

    (VOID) EvtchnSetupDebugCallback(XenWorkItemDump, NULL);

    WorkItemThread = XmSpawnThread(XenWorkItemDispatch, NULL);
    if (!WorkItemThread) {
        TraceError(("Failed to spawn work item thread\n"));
        return STATUS_UNSUCCESSFUL;
    } else {
        return STATUS_SUCCESS;
    }
}
