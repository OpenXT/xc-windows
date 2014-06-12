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

#include <windows.h>

#define V2V_API_EXPORTS
#include "v2v.h"

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

    HANDLE receive_event;
    HANDLE send_event;
    HANDLE control_event;

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
release_queued_message(struct v2v_stream *stream, struct queued_message *qm)
{
    if (qm != &stream->recv_state.in_ring_message)
        HeapFree(GetProcessHeap(), 0, qm);
    else
        v2v_nc2_finish_message(stream->channel);
}

BOOL
v2v_stream_attach(struct v2v_channel *channel, struct v2v_stream **stream)
{
    struct v2v_stream *work;

    *stream = NULL;

    work = ymalloc(sizeof(*work));
    if (!work)
        return FALSE;
    work->channel = channel;
    work->receive_event = v2v_get_receive_event(channel);
    work->send_event = v2v_get_send_event(channel);
    work->control_event = v2v_get_control_event(channel);
    work->recv_state.queue.tail = &work->recv_state.queue.head;

    *stream = work;
    return TRUE;
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
        HeapFree(GetProcessHeap(), 0, qm);
    }
    yfree(stream);
}

static BOOL
remote_disconnect(struct v2v_stream *stream)
{
    enum v2v_endpoint_state rs;
    rs = v2v_get_remote_state(stream->channel);
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
pull_incoming_messages(struct v2v_stream *stream)
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
        qm = HeapAlloc(GetProcessHeap(), 0,
                       sizeof(*qm) + stream->recv_state.in_ring_message.size);
        *qm = stream->recv_state.in_ring_message;
        qm->payload = qm + 1;
        _ReadWriteBarrier();
        memcpy(qm->payload,
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
                               &type, &flags)) {
        qm = HeapAlloc(GetProcessHeap(), 0, sizeof(*qm) + size);
        qm->next = NULL;
        qm->size = size;
        qm->type = type;
        qm->flags = flags;
        qm->bytes_already_used = 0;
        qm->payload = qm + 1;
        _ReadWriteBarrier();
        memcpy(qm->payload, (const void *)payload, size);
        _ReadWriteBarrier();
        v2v_nc2_finish_message(stream->channel);

        *stream->recv_state.queue.tail = qm;
        stream->recv_state.queue.tail = &qm->next;
    }
}

BOOL
v2v_stream_send(struct v2v_stream *stream, const void *buf,
                size_t buf_len, size_t *_bytes_sent)
{
    unsigned bytes_sent;
    unsigned short bytes_this_time;
    unsigned bytes_avail;
    volatile void *msg;
    BOOL res;
    HANDLE handles[3];
    DWORD status;

    handles[0] = stream->send_event;
    handles[1] = stream->control_event;
    handles[2] = stream->receive_event;
    res = TRUE;
    for (bytes_sent = 0; bytes_sent < buf_len; bytes_sent += bytes_this_time){
        bytes_avail = v2v_nc2_producer_bytes_available(stream->channel);
        if (v2v_nc2_remote_requested_fast_wakeup(stream->channel))
            bytes_avail = MIN(MAX_INLINE_BYTES, bytes_avail);
        bytes_this_time = (unsigned short)MIN(bytes_avail,
                                              buf_len - bytes_sent);
        if (!v2v_nc2_prep_message(stream->channel, bytes_this_time,
                                  STREAM_MSG_DATA, 0, &msg)) {
            if (GetLastError() == ERROR_RETRY) {
                pull_incoming_messages(stream);
                if (bytes_sent != 0)
                    v2v_nc2_send_messages(stream->channel);
                status = WaitForMultipleObjects(3, handles, FALSE, INFINITE);
                if (status == WAIT_OBJECT_0 + 1 && remote_disconnect(stream)){
                    SetLastError(ERROR_VC_DISCONNECTED);
                    res = FALSE;
                    break;
                }
                bytes_this_time = 0;
                continue;
            }
            res = FALSE;
            break;
        }
        _ReadWriteBarrier();
        memcpy((void *)msg,
               (const void *)((ULONG_PTR)buf + bytes_sent),
               bytes_this_time);
        _ReadWriteBarrier();
    }

    if (bytes_sent != 0)
        v2v_nc2_send_messages(stream->channel);
    *_bytes_sent = bytes_sent;
    return res;
}

static BOOL
get_next_message(struct v2v_stream *stream)
{
    struct queued_message *qm;

retry:
    if (stream->recv_state.queue.head) {
        qm = stream->recv_state.queue.head;
        stream->recv_state.queue.head = qm->next;
        if (stream->recv_state.queue.tail == &qm->next)
            stream->recv_state.queue.tail = &stream->recv_state.queue.head;
    } else {
        qm = &stream->recv_state.in_ring_message;
        if (!v2v_nc2_get_message(stream->channel,
                                 (const volatile void *)&qm->payload,
                                 &qm->size,
                                 &qm->type,
                                 &qm->flags))
            return FALSE;
        qm->bytes_already_used = 0;
    }

    if (qm->type != STREAM_MSG_DATA) {
        /* Don't know what to do with this -> discard */
        release_queued_message(stream, qm);
        goto retry;
    }

    stream->recv_state.current_message = qm;
    return TRUE;
}

BOOL
v2v_stream_recv(struct v2v_stream *stream, void *buf, size_t buf_size,
                size_t *_bytes_received)
{
    struct queued_message *qm;
    size_t bytes_received;
    size_t bytes_this_time;
    HANDLE handles[2];
    DWORD status;

    v2v_nc2_request_fast_receive(stream->channel);
    handles[0] = stream->receive_event;
    handles[1] = stream->control_event;
    for (bytes_received = 0;
         bytes_received < buf_size;
         bytes_received += bytes_this_time) {
        if (!stream->recv_state.current_message) {
            while (!get_next_message(stream)) {
                if (bytes_received != 0 ||
                    GetLastError() != ERROR_NO_MORE_ITEMS)
                    goto out;
                status = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
                if (status == WAIT_OBJECT_0 + 1 && remote_disconnect(stream)){
                    SetLastError(ERROR_VC_DISCONNECTED);
                    goto out;
                }
            }
        }
        qm = stream->recv_state.current_message;
        bytes_this_time = MIN(qm->size - qm->bytes_already_used,
                              buf_size - bytes_received);
        memcpy( (void *)((ULONG_PTR)buf + bytes_received),
                (const void *)((ULONG_PTR)qm->payload +
                               qm->bytes_already_used),
                bytes_this_time);
        qm->bytes_already_used += bytes_this_time;
        if (qm->bytes_already_used == qm->size) {
            release_queued_message(stream, qm);
            stream->recv_state.current_message = NULL;
        }
    }
out:
    v2v_nc2_cancel_fast_receive(stream->channel);
    *_bytes_received = bytes_received;
    if (bytes_received == 0)
        return FALSE;
    else
        return TRUE;
}
