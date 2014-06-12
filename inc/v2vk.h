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

#ifndef V2VK_H__
#define V2VK_H__

#define V2V_API

/* An opaque type representing a low-level VM-to-VM communication
 * channel.  These are point-to-point, record-oriented connections
 * using shared memory and event channels.  They are created with
 * v2v_listen() and v2v_connect(), and should be destroyed with
 * v2v_disconnect() when no longer needed.
 *
 * They will not, in general, survive hibernation, suspend/resume, or
 * migration, and will become disconnected following any such events.
 * They must still be torn down in the usual way, but will not be
 * functional.
 */
struct v2v_channel;

/* Input structure used for initilializing asynchronous v2v 
 * comminucations.  The @receive_dpc and @send_dpc values must be provided.
 * These routines will be called back for receive and send event 
 * notification.  The @receive_ctx and @send_ctx will be passed in to the
 * associated DPC routine when called.  The @control_cb may or may not
 * be set depending on whether the caller wants to get control callbacks
 * or use the control event through returned by v2v_get_control_event to
 * process changes in control state.  The @control_ctx will be passed in to 
 * the control callback routine when called.
 *
 * Listening, connecting and accepting the v2v channel for asynchronous
 * operations is done the same way as for synchronous operations (except
 * for providing this structure to the APIs). Once the channel is established,
 * the client using v2v in asynchronous mode will be called back to indicate
 * receipt of data or space availability for further sending.
 */
struct v2v_async {
    void (*receive_dpc)(void *receive_ctx);
    void *receive_ctx;
    void (*send_dpc)(void *send_ctx);
    void *send_ctx;
    void (*control_cb)(void *control_ctx);
    void *control_ctx;
};

/* Start listening for incoming VM-to-VM connections using parameters
 * from the xenstore area @xenbus_prefix, which should have been
 * previously set up by the toolstack.  The newly constructed channel
 * is placed in *@channel.  The size of the outgoing message ring is
 * 2**@prod_ring_page_order pages, and the size of the incoming one
 * 2**@cons_ring_page_order pages.
 *
 * It is generally a mistake to have several processes listening on
 * the same xenbus prefix.
 *
 * Passing a valid @async_values structure to this routine will
 * initialize the endpoint for ascynchronous communications operation.
 * To use synchronous operations, NULL should be passed.
 *
 * IRQL = PASSIVE_LEVEL
 *
 * Returns STATUS_SUCCESS on success and an appropriate NTSTATUS 
 * error code on failure.
 */
V2V_API NTSTATUS v2v_listen(const char *xenbus_prefix,
                            struct v2v_channel **channel,
                            unsigned prod_ring_page_order,
                            unsigned cons_ring_page_order,
                            struct v2v_async *async_values);

/* Wait for a remote domain to connect to the channel @channel, which
 * should have been allocated with v2v_listen().
 *
 * IRQL = PASSIVE_LEVEL
 *
 * Returns STATUS_SUCCESS on success and an appropriate NTSTATUS error
 * code on failure.
 */
V2V_API NTSTATUS v2v_accept(struct v2v_channel *channel);

/* Connect to a VM-to-VM channel specified by @xenbus_prefix, which
 * should previously have been initialised by the tools, and place the
 * newly constructed channel structure in *@channel.  Note that
 * @xenbus_prefix specifies the *local* xenstore prefix, and not the
 * server prefix.
 *
 * Passing a valid @async_values structure to this routine will
 * initialize the endpoint for ascynchronous communications operation.
 * To use synchronous operations, NULL should be passed.
 *
 * IRQL = PASSIVE_LEVEL
 *
 * This will fail if the remote endpoint is not currently listening on
 * the specified channel.
 *
 * Returns STATUS_SUCCESS on success and an appropriate NTSTATUS error
 * code on failure.
 */
V2V_API NTSTATUS v2v_connect(const char *xenbus_prefix,
                             struct v2v_channel **channel,
                             struct v2v_async *async_values);

/* Disconnect from a VM-to-VM channel @channel which was previously
 * established using either v2v_connect() or v2v_listen().  The channel
 * is no longer valid once this returns, and should not be used.
 *
 * If the channel was constructued by v2v_connect(), this is
 * instaneous.  If it was constructed by v2v_listen(), and a remote
 * endpoint is currently connected, we must wait for the peer to call
 * v2v_disconnect() on their end of the connection before this can
 * return.  In that case, the local state is set to
 * v2v_endpoint_state_disconnecting, so as to encourage the remote to
 * disconnect quickly.
 *
 * Note that this can fail if the remote endpoint is misbehaving.  In
 * that case, there is no reliable way to destroy the connection, and
 * it must be leaked.
 *
 * IRQL = PASSIVE_LEVEL
 *
 * Returns STATUS_SUCCESS on success and an appropriate NTSTATUS error
 * code on failure.
 */
V2V_API NTSTATUS v2v_disconnect(const struct v2v_channel *channel);

/* An enumeration representing the states which a remote endpoint can
 * be in.  Obviously, the remote endpoint can change its state at any
 * time; if this happens, the local control event will be notified.
 */
enum v2v_endpoint_state {

    /* There was an error reading the remote endpoint state, and it is
     * currently unknown.
     */
    v2v_state_unknown,

    /* The remote endpoint is not ready yet, and doesn't appear to
     * have ever been ready.  New endpoints are placed in this state
     * before they connect or listen for the first time.  Note that if
     * the endpoint has previously connected and disconnected, the
     * state will be either v2v_state_disconnected or
     * v2v_state_crashed, and not v2v_state_unready.
     */
    v2v_state_unready = 0x123,

    /* The remote endpoint is currently listening for connections. */
    v2v_state_listening,

    /* The remote endpoint has connected, and is willing to accept any
     * messages which we send.
     */
    v2v_state_connected,

    /* The remote endpoint is connected, but is asking us to
     * disconnect as quickly as possible.  This is used as part of
     * connection teardown.
     */
    v2v_state_disconnecting,

    /* The remote endpoint has disconnected cleanly. */
    v2v_state_disconnected,

    /* The remote endpoint has disconnected uncleanly.  This should be
     * treated similarly to v2v_state_disconnected, except possibly
     * for providing more informative error messages.
     */
    v2v_state_crashed
};

/* TRUE if, upon seeing state @state, the local endpoint is supposed
 * to start disconnecting.
 *
 * IRQL ANY
 */
static __inline BOOLEAN
v2v_state_requests_disconnect(enum v2v_endpoint_state state)
{
    if (state >= v2v_state_disconnecting)
        return TRUE;
    else
        return FALSE;
}

/* Get the current remote state for channel @channel, which should
 * have been constructed with v2v_connect() or v2v_listen(). The
 * argument *@state receives the current state value. 
 *
 * The value of *@state will set to v2v_state_unknown when there
 * is no remote state returned internall or an error occurs.  This
 * includes when the remote end is not present.  In this case the
 * function will also return STATUS_OBJECT_NAME_NOT_FOUND.
 *
 * Note that there is no guarantee that the returned state will remain
 * valid after this returns.  However, we do guarantee to set the
 * channel's control event whenever the remote state changes.
 *
 * IRQL = PASSIVE_LEVEL
 *
 * Returns STATUS_SUCCESS on success. On failure an NTSTATUS error code
 * is returned.
 */
V2V_API NTSTATUS v2v_get_remote_state(struct v2v_channel *channel,
                                      enum v2v_endpoint_state *state);

/* Convert a v2v_endpoint_state @state to a string.  The resulting string
 * is static, and the caller should not attempt to modify it in any
 * way or to free it.
 *
 * IRQL ANY
 *
 * Always succeeds, provided that @state is a valid memory of the
 * v2v_endpoint_state enumeration.
 */
V2V_API const char *v2v_endpoint_state_name(enum v2v_endpoint_state state);

/* Get the receive event for channel @channel.  This is a Windows kernel
 * event which will be set if there are unprocessed incoming messages
 * on the channel, and will be cleared if we have observed there to be
 * none.  Note that it may sometimes be set when there are no messages
 * incoming, and will remain so until v2v_nc2_get_message() is called.
 *
 * For asynchronous operation, the @receive_dpc is called to indicate
 * receive data arrival. There is no associated receive event and this
 * routine will return NULL.
 *
 * IRQL ANY (the event object can be retrieved at any IRQL but not used)
 */
V2V_API PKEVENT v2v_get_receive_event(struct v2v_channel *channel);

/* Get the send event for channel @channel.  This is a manually
 * cleared Windows kernel event which will be set whenever space is
 * available in the ring to send messages, and cleared whenever
 * v2v_nc2_prep_message() fails due to a lack of outgoing ring space.
 * Note that this event being set does not imply that it will be
 * possible to send a message (because it doesn't tell you how *much*
 * space is available in the ring, which might not even be enough for
 * a header), but if it is possible to send a message then this event
 * will be set.
 *
 * For asynchronous operation, the @send_dpc is called to indicate
 * send space availability. There is no associated send event and this
 * routine will return NULL.
 *
 * IRQL ANY (the event object can be retrieved at any IRQL but not used)
 */
V2V_API PKEVENT v2v_get_send_event(struct v2v_channel *channel);

/* Get the control event for channel @channel.  This is a manually
 * cleared Windows kernel event which will be set whenever there is any
 * possibility that the remote endpoint state has changed.  Note that
 * it may also be set when the state has not changed.
 *
 * For asynchronous operation, the control event is still valid and
 * can be used to process control state changes.
 *
 * IRQL ANY (the event object can be retrieved at any IRQL but not used)
 */
V2V_API PKEVENT v2v_get_control_event(struct v2v_channel *channel);

/* Try to fetch a message from the incoming message queue.  On
 * success, *@payload is set to a pointer to the message payload,
 * *@size is set to its size, *@type is set to its type, and *@flags
 * is set to its flags.  Note thath *@payload will point at read-only
 * memory which is shared with the remote endpoint; it must not be
 * written to, and a malicious remote could cause its contents to
 * change at any time.
 *
 * When using asynchronous operations mode, the caller must provide 
 * locking (mutual exclusion) to this routine and the finalizing call 
 * to v2v_nc2_finish_message() within the same locked section (using the 
 * same synchronization object).
 *
 * Returns STATUS_SUCCESS on success.  If no more messages are available,
 * STATUS_NO_MORE_ENTRIES information code is returned.  Note that 
 * information codes test successfully when tested with NTSTATUS macros
 * like with NT_SUCCESS().  On failure an NTSTATUS error code is 
 * returned.
 *
 * IRQL <= DISPATCH_LEVEL
 *
 * Once the client has finished consuming the message, it should call
 * v2v_nc2_finish_message().
 */
V2V_API NTSTATUS v2v_nc2_get_message(struct v2v_channel *channel,
                                     const volatile void **payload,
                                     size_t *size,
                                     unsigned *type,
                                     unsigned *flags);

/* Finish consuming the message which was most recently returned by
 * v2v_nc2_get_message() on channel @channel.  The ring space is
 * released, so that the remote can use it to send another message,
 * and the channel advances to the next incoming message.
 *
 * When using asynchronous operations mode, the caller must provide 
 * locking (mutual exclusion) to this routine and the initializing call 
 * to v2v_nc2_get_message() within the same locked section (using the 
 * same synchronization object).
 *
 * IRQL <= DISPATCH_LEVEL
 *
 * The payload returned by v2v_nc2_get_message() must not be touched
 * once this returns.
 */
V2V_API void v2v_nc2_finish_message(struct v2v_channel *channel);

/* Prepare to send a message of size @msg_size on the ring, using type
 * @type and flags @flags.  Space for @msg_size bytes of payload is
 * allocated on the ring, and returned in *@payload.  Note that
 * *@payload will point to shared memory, and so the remote endpoint may
 * be able to modify it under certain circumstances.
 *
 * The message is not actually sent until v2v_nc2_send_messages() is
 * called.
 *
 * When using asynchronous operations mode, the caller must provide 
 * locking (mutual exclusion) to this routine and the finalizing call 
 * to v2v_nc2_send_messages() within the same locked section (using the 
 * same synchronization object).
 *
 * If there is insufficient space in the ring, this routine requests
 * that the remote endpoint set the local ring's send event when more
 * space becomes available, sets the NTSTATUS error code to STATUS_RETRY.
 *
 * IRQL <= DISPATCH_LEVEL
 *
 * On other errors, an appropriate NTSTATUS error code is returned.  On
 * success, returns STATUS_SUCCESS.
 */
V2V_API NTSTATUS v2v_nc2_prep_message(struct v2v_channel *channel,
                                      size_t msg_size,
                                      unsigned char type,
                                      unsigned char flags,
                                      volatile void **payload);

/* Flush the current batch of outgoing messages to the ring.  The
 * messages are made visible to the correctly behaving remote endpoint
 * (incorrectly behaving remote endpoints can always look ahead) and
 * the remote is woken up if appropriate.
 *
 * When using asynchronous operations mode, the caller must provide 
 * locking (mutual exclusion) to this routine and the initializing call 
 * to v2v_nc2_prep_message() within the same locked section (using the 
 * same synchronization object).
 *
 * IRQL <= DISPATCH_LEVEL
 *
 * The client must not touch the payload pointers returned by
 * v2v_nc2_prep_message() after calling this function.
 */
V2V_API void v2v_nc2_send_messages(struct v2v_channel *channel);

/* Estimate the largest message size which could be passed to
 * v2v_nc2_prep_message() such that it would succeed without
 * generating a large pad message.
 *
 * This is a lower bound on the message size.  Larger sends may
 * sometimes succeed.  It is guaranteed that a send at the returned
 * size will never fail.
 *
 * When using asynchronous operations mode, the caller must provide 
 * locking (mutual exclusion) to this routine using the same same 
 * synchronization object used for v2v_nc2_prep_message().  When called
 * to determine the availability of space for a following call to
 * v2v_nc2_prep_message() is should be within the same lock section.
 *
 * IRQL ANY
 */
V2V_API unsigned v2v_nc2_producer_bytes_available(struct v2v_channel *channel);

/* Check whether the remote endpoint is currently in fast-receive
 * mode.  Returns TRUE if they have and FALSE otherwise.
 *
 * Note that there is no way of preventing the remote's fast-receive
 * state from changing after this has been called, and so the value
 * returned is inherently inaccurate.  It should only be used for
 * performance tuning, and not for correctness.
 *
 * IRQL ANY
 */
V2V_API BOOLEAN v2v_nc2_remote_requested_fast_wakeup(struct v2v_channel *channel);

/* Enter fast-receive mode on channel @channel.  In this mode, we
 * optimise for latency rather than throughput, by, for instance,
 * flushing outgoing messages to the ring more aggressively (which
 * means they get sent sooner, but in smaller batches).  This is
 * generally worthwhile if the local endpoint is blocked waiting to
 * receive messages, but not during normal operation.
 *
 * Entering fast receive mode should never affect the correctness of
 * clients, but may have a significant performance impact.
 *
 * IRQL ANY
 */
V2V_API void v2v_nc2_request_fast_receive(struct v2v_channel *channel);

/* Exit fast-receive mode on channel @channel.  This will undo the
 * effects of v2v_nc2_request_fast_receive().  Fast-receive mode is
 * not reference counted in any way, and so calling
 * v2v_nc2_cancel_fast_receive() will cause the channel to leave
 * fast-receive mode regardless of how many times
 * v2v_nc2_request_fast_receive() has been called.
 *
 * IRQL ANY
 */
V2V_API void v2v_nc2_cancel_fast_receive(struct v2v_channel *channel);

/* ------------------------ Stream protocol ------------------------- */
/* A V2V stream can be layered on top of a V2V channel, and provides a
 * reliable bidirectional byte stream protocol, with semantics broadly
 * similar to TCP sockets.  In particular, record boundaries are not
 * preserved.
 *
 * When a stream is attached to a channel, it will consume all
 * incoming messages.  The low-level NC2 message functions should not
 * be used while the stream is attached.
 */
struct v2v_stream;

/* Allocate a new v2v_stream and attach it to channel @channel, which
 * should have been allocated with v2v_listen() or v2v_connect().  The
 * new stream is places in *@stream.  The stream should be torn down
 * with v2v_stream_detach() before the channel is disconnected.
 *
 * When transmitting, the stream library may internally queue incoming
 * messages. The @np flag indicates whether the stream library should 
 * use non-paged allocations internally for queuing.
 *
 * It is usually an error to use the low-level NC2 message functions
 * on a channel which has a stream attached.  However, the other
 * low-level functions are available; in particular,
 * v2v_get_{send,receive,control}_event() are valid on a channel with
 * a stream attached, as is v2v_get_remote_state().
 *
 * IRQL = PASSIVE_LEVEL
 *
 * Returns STATUS_SUCCESS on success and an appropriate NTSTATUS error
 * code on failure and *@stream is set to NULL.
 */
V2V_API NTSTATUS v2v_stream_attach(struct v2v_channel *channel,
                                   BOOLEAN np,
                                   struct v2v_stream **stream);

/* Detach the stream @stream from the underlying channel and destroy
 * @stream.  Once this has been called, the stream should not be
 * referenced again, although the underlying channel remains valid.
 *
 * Unreceived incoming data is discarded.  Any further attempts by the
 * remote to send stream data will show up as low-level NC2 messages
 * on the underlying channel.
 *
 * Clients should generally call v2v_disconnect() on the underlying
 * channel shortly after detaching the stream.
 *
 * IRQL = PASSIVE_LEVEL
 */
V2V_API void v2v_stream_detach(const struct v2v_stream *stream);

/* Send @buf_len bytes starting at @buf on stream @stream.  The total
 * number of bytes sent is stored in *@bytes_sent.  This routine will
 * block if necessary until the entire buffer has been sent;
 * therefore, on return, *@bytes_sent != bytes_sent if and only if an
 * error occurs.
 *
 * If the remote endpoint starts to disconnect, the send may fail with
 * the NTSTATUS error STATUS_VIRTUAL_CIRCUIT_CLOSED returned, after 
 * sending part of the buffer.  It may also ignore the disconnection, and
 * complete the entire transmission without returning an error.
 *
 * IRQL = PASSIVE_LEVEL
 *
 * Returns STATUS_SUCCESS if the entire send completes without error,
 * or an NTSTATUS error code if an error is encountered.
 */
V2V_API NTSTATUS v2v_stream_send(struct v2v_stream *stream,
                                 const void *buf,
                                 size_t buf_len,
                                 size_t *bytes_sent);

/* Receive up to @buf_size bytes from stream @stream, and copy them to
 * a buffer starting at @buf.  The total number of bytes received is
 * stored in *@bytes_received.  This will block until some data is
 * available, but, once that data has been copied to the destination,
 * will not block again.  It may, therefore, return less than
 * @buf_size bytes of data even when no error occurs.
 *
 * If the remote endpoint disconnects before a single byte of data has
 * been received, the call fails and returns the NTSTATUS error code 
 * STATUS_VIRTUAL_CIRCUIT_CLOSED.  If at least one byte has been received,
 * the call succeeds and returns a partially filled buffer.
 *
 * IRQL = PASSIVE_LEVEL
 *
 * Returns STATUS_SUCCESS on success and an appropriate NTSTATUS error 
 * code on failure.
 */
V2V_API NTSTATUS v2v_stream_recv(struct v2v_stream *stream,
                                 void *buf,
                                 size_t buf_size,
                                 size_t *bytes_received);

#endif /* !V2VH_H__ */
