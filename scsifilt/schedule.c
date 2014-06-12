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

#include "ntddk.h"
#include "ntddstor.h"
#pragma warning (push, 3)
#include "srb.h"
#include "classpnp.h"
#pragma warning (pop)
#include "xsapi.h"
#include "scsiboot.h"
#include "scsifilt.h"

#include "scsifilt_wpp.h"
#include "schedule.tmh"

struct scsifilt_request *
get_next_request(struct scsifilt_schedule *sched)
{
    struct scsifilt_request *res;
    PLIST_ENTRY ple;

    if (IsListEmpty(&sched->cur_sched)) {
        DoTraceMessage(FLAG_SCHEDULER, "%p flip schedule for dequeue", sched);
        XmListTransplant(&sched->cur_sched, &sched->next_sched);
    }
    if (IsListEmpty(&sched->cur_sched)) {
        DoTraceMessage(FLAG_SCHEDULER, "%p is empty", sched);
        return NULL;
    }
    ple = sched->cur_sched.Flink;
    res = CONTAINING_RECORD(ple, struct scsifilt_request, list);
    DoTraceMessage(FLAG_SCHEDULER, "%p next request is %p", sched, res);
    return res;
}

void
enqueue_request(struct scsifilt_schedule *sched, struct scsifilt_request *req)
{
    PLIST_ENTRY cur_head_ple;
    struct scsifilt_request *cur_head;
    struct scsifilt_request *other_req;
    PLIST_ENTRY target_list;
    PLIST_ENTRY ple;

    sched->nr_scheduled++;

    DoTraceMessage(FLAG_SCHEDULER,
                   "%p schedule %p operation %d start %I64d",
                   sched, req, req->operation, req->start_sector);

    req->state = SfrStateQueued;

    if (IsListEmpty(&sched->cur_sched)) {
        DoTraceMessage(FLAG_SCHEDULER, "%p flip schedule", sched);
        XmListTransplant(&sched->cur_sched, &sched->next_sched);
    }
    if (IsListEmpty(&sched->cur_sched)) {
        DoTraceMessage(FLAG_SCHEDULER, "%p insert in empty schedule", sched);
        InsertTailList(&sched->cur_sched, &req->list);
        return;
    }
    cur_head_ple = sched->cur_sched.Flink;
    cur_head = CONTAINING_RECORD(cur_head_ple, struct scsifilt_request, list);
    if (req->start_sector < cur_head->start_sector) {
        /* Inserting into the current schedule would mean a backwards
           seek -> insert into the next schedule. */
        target_list = &sched->next_sched;
    } else {
        /* Insert into the current schedule. */
        target_list = &sched->cur_sched;
    }

    /* Walk down the target list and find the place to insert the
     * request.  We maintain the schedules in order, so this means
     * right before the first request which has a start_sector >
     * req->start_sector, or at the end of the list if there is no
     * such request.  Because of the way linked lists are constructed,
     * inserting at the end of the list is equivalent to inserting
     * just before the anchoring list head. */
    for (ple = target_list->Flink; ple != target_list; ple = ple->Flink) {
        other_req = CONTAINING_RECORD(ple, struct scsifilt_request, list);
        if (other_req->start_sector > req->start_sector)
            break;
    }
    /* Insert directly before ple */
    req->list.Blink = ple->Blink;
    req->list.Flink = ple;
    ple->Blink->Flink = &req->list;
    ple->Blink = &req->list;
}

void
initialise_schedule(struct scsifilt_schedule *schedule)
{
    InitializeListHead(&schedule->cur_sched);
    InitializeListHead(&schedule->next_sched);
}
