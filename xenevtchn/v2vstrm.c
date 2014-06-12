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

#include <ntddk.h>
#include <ntstrsafe.h>
#define XSAPI_FUTURE_GRANT_MAP
#define XSAPI_FUTURE_CONNECT_EVTCHN
#include "xsapi.h"
#include "xsapi-future.h"

#define V2V_API_EXPORTS
#include "v2vk.h"

#include "v2v_private.h"

#define MAX_INLINE_BYTES 2048

#define STREAM_MSG_DATA 1
/* Message is just some inline data bytes */

/* We sometimes pull messages out of the ring before they're needed
   and buffer them locally.  */
struct queued_message {
    struct queued_message *next;
    void *payload;
    size_t size;
    unsigned type;
    unsigned flags;

    size_t bytes_already_used;
};

struct v2v_stream {
    struct v2v_channel *channel;

    PKEVENT receive_event;
    PKEVENT send_event;
    PKEVENT control_event;

    BOOLEAN nonpaged;

    struct {
        struct queued_message in_ring_message;
        struct queued_message *current_message;

        struct {
            struct queued_message *head;
            struct queued_message **tail;
        } queue;
    } recv_state;
};

static void
v2v_release_queued_message(struct v2v_stream *stream, struct queued_message *qm)
{
    if (qm != &stream->recv_state.in_ring_message)
        ExFreePoolWithTag(qm, V2V_TAG);
    else
        v2v_nc2_finish_message(stream->channel);
}

NTSTATUS
v2v_stream_attach(struct v2v_channel *channel, BOOLEAN np, struct v2v_stream **stream)
{
    struct v2v_stream *work;

    *stream = NULL;

    work = ExAllocatePoolWithTag(NonPagedPool, sizeof(*work), V2V_TAG);
    if (!work)
        return STATUS_NO_MEMORY;
    work->channel = channel;
    work->nonpaged = np;
    work->receive_event = v2v_get_receive_event(channel);
    work->send_event = v2v_get_send_event(channel);
    work->control_event = v2v_get_control_event(channel);
    work->recv_state.queue.tail = &work->recv_state.queue.head;

    *stream = work;
 
    return STATUS_SUCCESS;
}

void
v2v_stream_detach(const struct v2v_stream *_stream)
{
    struct v2v_stream *stream = (struct v2v_stream *)_stream;
    struct queued_message *qm;

    if (!stream)
        return;

    while (stream->recv_state.queue.head) {
        qm = stream->recv_state.queue.head;
        stream->recv_state.queue.head = qm->next;
        ExFreePoolWithTag(qm, V2V_TAG);
    }
    ExFreePoolWithTag(stream, V2V_TAG);
}

static BOOLEAN
v2v_remote_disconnect(struct v2v_stream *stream)
{
    enum v2v_endpoint_state rs;

    v2v_get_remote_state(stream->channel, &rs);
    if (rs == v2v_state_unknown || v2v_state_requests_disconnect(rs))
        return TRUE;
    else
        return FALSE;
}

/* This is a bit skanky.  If we're transmitting, and we need to block
   because the ring's full, we first pull all of the *incoming*
   messages off of the ring into local buffers.  This unblocks the
   remote, which helps to avoid deadlocks. */
static void
v2v_pull_incoming_messages(struct v2v_stream *stream)
{
    struct queued_message *qm;
    const volatile void *payload;
    size_t size;
    unsigned type;
    unsigned flags;

    /* If we're processing an in-ring message, copy it out of the ring
       and into the local queue. */
    if (stream->recv_state.current_message ==
        &stream->recv_state.in_ring_message) {       
		qm = ExAllocatePoolWithTag((stream->nonpaged ? NonPagedPool : PagedPool),
								   sizeof(*qm) + stream->recv_state.in_ring_message.size,
								   V2V_TAG);
        *qm = stream->recv_state.in_ring_message;
        qm->payload = qm + 1;
        _ReadWriteBarrier();
        RtlCopyMemory(qm->payload,
                      stream->recv_state.in_ring_message.payload,
                      qm->size);
        _ReadWriteBarrier();
        stream->recv_state.current_message = qm;

        v2v_nc2_finish_message(stream->channel);

        stream->recv_state.current_message = qm;
    }
    /* Pull all of the messages out of the ring and into the local
       queue. */
    while (v2v_nc2_get_message(stream->channel, &payload, &size,
                               &type, &flags) == STATUS_SUCCESS) {
		qm = ExAllocatePoolWithTag((stream->nonpaged ? NonPagedPool : PagedPool),
								   sizeof(*qm) + size,
								   V2V_TAG);
        qm->next = NULL;
        qm->size = size;
        qm->type = type;
        qm->flags = flags;
        qm->bytes_already_used = 0;
        qm->payload = qm + 1;
        _ReadWriteBarrier();
        RtlCopyMemory(qm->payload, (const void *)payload, size);
        _ReadWriteBarrier();
        v2v_nc2_finish_message(stream->channel);

        *stream->recv_state.queue.tail = qm;
        stream->recv_state.queue.tail = &qm->next;
    }
}

NTSTATUS
v2v_stream_send(struct v2v_stream *stream, const void *buf,
                size_t buf_len, size_t *_bytes_sent)
{
    NTSTATUS status = STATUS_SUCCESS;
    unsigned bytes_sent;
    unsigned short bytes_this_time;
    unsigned bytes_avail;
    volatile void *msg;
    HANDLE handles[3];

    handles[0] = stream->send_event;
    handles[1] = stream->control_event;
    handles[2] = stream->receive_event;

    for (bytes_sent = 0; bytes_sent < buf_len; bytes_sent += bytes_this_time){
        bytes_avail = v2v_nc2_producer_bytes_available(stream->channel);
        if (v2v_nc2_remote_requested_fast_wakeup(stream->channel))
            bytes_avail = MIN(MAX_INLINE_BYTES, bytes_avail);
        bytes_this_time = (unsigned short)MIN(bytes_avail,
                                              buf_len - bytes_sent);
        status = v2v_nc2_prep_message(stream->channel, bytes_this_time,
                                      STREAM_MSG_DATA, 0, &msg);
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_RETRY) {
                v2v_pull_incoming_messages(stream);
                if (bytes_sent != 0)
                    v2v_nc2_send_messages(stream->channel);
                status =
                    KeWaitForMultipleObjects(3, handles, WaitAny, Executive,
                                             KernelMode, FALSE, NULL, NULL);
                if (status == STATUS_WAIT_0 + 1 && v2v_remote_disconnect(stream)) {
                    status = STATUS_VIRTUAL_CIRCUIT_CLOSED;
                    break;
                }
                bytes_this_time = 0;
                continue;
            }
            break; /* end send with error status */
        }

        _ReadWriteBarrier();
        RtlCopyMemory((void *)msg,
                      (const void *)((ULONG_PTR)buf + bytes_sent),
                      bytes_this_time);
        _ReadWriteBarrier();
    }

    if (bytes_sent != 0)
        v2v_nc2_send_messages(stream->channel);
    *_bytes_sent = bytes_sent;

    return status;
}

static NTSTATUS
v2v_get_next_message(struct v2v_stream *stream)
{
    NTSTATUS status;
    struct queued_message *qm;

retry:
    if (stream->recv_state.queue.head) {
        qm = stream->recv_state.queue.head;
        stream->recv_state.queue.head = qm->next;
        if (stream->recv_state.queue.tail == &qm->next)
            stream->recv_state.queue.tail = &stream->recv_state.queue.head;
    } else {
        qm = &stream->recv_state.in_ring_message;
        status = 
            v2v_nc2_get_message(stream->channel,
                                (const volatile void *)&qm->payload,
                                &qm->size,
                                &qm->type,
                                &qm->flags);
        if (status != STATUS_SUCCESS) /* Could be STATUS_NO_MORE_ENTRIES */
            return status;
        qm->bytes_already_used = 0;
    }

    if (qm->type != STREAM_MSG_DATA) {
        /* Don't know what to do with this -> discard */
        v2v_release_queued_message(stream, qm);
        goto retry;
    }

    stream->recv_state.current_message = qm;

    return STATUS_SUCCESS;
}

NTSTATUS
v2v_stream_recv(struct v2v_stream *stream, void *buf, size_t buf_size,
                size_t *_bytes_received)
{
    NTSTATUS status = STATUS_SUCCESS;
    struct queued_message *qm;
    size_t bytes_received;
    size_t bytes_this_time;
    HANDLE handles[2];

    v2v_nc2_request_fast_receive(stream->channel);
    handles[0] = stream->receive_event;
    handles[1] = stream->control_event;

    for (bytes_received = 0;
         bytes_received < buf_size;
         bytes_received += bytes_this_time) {

        if (!stream->recv_state.current_message) {
            while ((status = v2v_get_next_message(stream)) != STATUS_SUCCESS) {
                if (bytes_received != 0 ||
                    status != STATUS_NO_MORE_ENTRIES)
                    goto out;

                status =
                    KeWaitForMultipleObjects(2, handles, WaitAny, Executive,
                                             KernelMode, FALSE, NULL, NULL);
                if (status == STATUS_WAIT_0 + 1 && v2v_remote_disconnect(stream)) {
                    status = STATUS_VIRTUAL_CIRCUIT_CLOSED;
                    goto out;
                }
            }         
        }

        qm = stream->recv_state.current_message;
        bytes_this_time = MIN(qm->size - qm->bytes_already_used,
                              buf_size - bytes_received);
        RtlCopyMemory((void *)((ULONG_PTR)buf + bytes_received),
                      (const void *)((ULONG_PTR)qm->payload + qm->bytes_already_used),
                      bytes_this_time);
        qm->bytes_already_used += bytes_this_time;
        if (qm->bytes_already_used == qm->size) {
            v2v_release_queued_message(stream, qm);
            stream->recv_state.current_message = NULL;
        }
    }
out:
    v2v_nc2_cancel_fast_receive(stream->channel);
    *_bytes_received = bytes_received;
    if (bytes_received == 0)
        return (!NT_SUCCESS(status) ? status : STATUS_UNSUCCESSFUL);
    else
        return STATUS_SUCCESS;
}
