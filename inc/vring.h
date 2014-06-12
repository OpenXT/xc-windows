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

#ifndef __XEN_PUBLIC_IO_URING_H__
#define __XEN_PUBLIC_IO_URING_H__

typedef unsigned RING_IDX;

#define NETCHANNEL2_MSG_PAD 255

#define barrier() _ReadWriteBarrier()
static __inline void
mb(void)
{
    _mm_mfence();
    _ReadWriteBarrier();
}
#define wmb() _WriteBarrier()
#define rmb() _ReadBarrier()

/* The sring structures themselves.  The _cons and _prod variants are
   different views of the same bit of shared memory, and are supposed
   to provide better checking of the expected use patterns.  Fields in
   the shared ring are owned by either the producer end or the
   consumer end.  If a field is owned by your end, the other end will
   never modify it.  If it's owned by the other end, the other end is
   allowed to modify it whenever it likes, and you can never do so.

   Fields owned by the other end are always const (because you can't
   change them).  They're also volatile, because there are a bunch
   of places where we go:

   local_x = sring->x;
   validate(local_x);
   use(local_x);

   and it would be very bad if the compiler turned that into:

   local_x = sring->x;
   validate(sring->x);
   use(local_x);

   because that contains a potential TOCTOU race (hard to exploit, but
   still present).  The compiler is only allowed to do that
   optimisation because it knows that local_x == sring->x at the start
   of the call to validate(), and it only knows that if it can reorder
   the read of sring->x over the sequence point at the end of the
   first statement.  In other words, it can only do the bad
   optimisation if it knows that reads of sring->x are side-effect
   free.  volatile stops it from making that assumption.

   We don't need a full memory barrier here, because it's sufficient
   to copy the volatile data into stable guest-local storage, and
   volatile achieves that.  i.e. we don't need local_x to be precisely
   sring->x, but we do need it to be a stable snapshot of some
   previous valud of sring->x.

   Note that there are still plenty of other places where we *do* need
   full barriers.  volatile just deals with this one, specific, case.

   We could also deal with it by putting compiler barriers in all over
   the place.  The downside of that approach is that you need to put
   the barrier()s in lots of different places (basically, everywhere
   which needs to access these fields), and it's easy to forget one.
   barrier()s also have somewhat heavier semantics than volatile
   (because they prevent all reordering, rather than just reordering
   on this one field), although that's pretty much irrelevant because
   gcc usually treats pretty much any volatile access as a call to
   barrier().
*/

/* Messages are sent over sring pairs.  Each sring in a pair provides
 * a unidirectional byte stream which can generate events when either
 * the producer or consumer pointers cross a particular threshold.
 *
 * We define both sring_prod and sring_cons structures.  The two
 * structures will always map onto the same physical bytes in memory,
 * but they provide different views of that memory which are
 * appropriate to either producers or consumers.
 *
 * Obviously, the endpoints need to agree on which end produces
 * messages on which ring.  The endpoint which provided the memory
 * backing the ring always produces on the first sring, and the one
 * which just mapped the ring produces on the second.  By convention,
 * these are known as the frontend and backend, respectively.
 */

/* For both rings, the producer (consumer) pointers point at the
 * *next* byte which is going to be produced (consumed).  An endpoint
 * must generate an event on the event channel port if it moves the
 * producer pointer (consumer pointer) across prod_event (cons_event).
 *
 * i.e if an endpoint ever updates a pointer so that the old pointer
 * is strictly less than the event, and the new pointer is greater
 * than or equal to the event then the remote must be notified.  If
 * the pointer overflows the ring, treat the new value as if it were
 * (actual new value) + (1 << 32).
 */
struct netchannel2_sring_fields {
        RING_IDX prod;
        RING_IDX prod_event;
        RING_IDX cons;
        RING_IDX cons_event;

        /* Setting consumer_waiting gives the other end a hint that it
           should flush messages more aggressively, because the other
           end is sitting waiting for them. */
        unsigned consumer_active;
        unsigned consumer_spinning;
        unsigned producer_active;
        unsigned char pad[36];
};
struct netchannel2_frontend_shared {
        struct netchannel2_sring_fields a;
        volatile const struct netchannel2_sring_fields b;
};
struct netchannel2_backend_shared {
        volatile const struct netchannel2_sring_fields b;
        struct netchannel2_sring_fields a;
};

struct nc2_ring_pair {
        volatile struct netchannel2_sring_fields *local_endpoint;
        volatile const struct netchannel2_sring_fields *remote_endpoint;

        void *producer_payload;
        volatile const void *consumer_payload;

        /* The previous value written to local_endpoint->prod */
        RING_IDX local_prod;

        /* Will get written to local_endpoint->prod next time
           we flush. */
        RING_IDX local_prod_pvt;

        /* The previous value written to local_endpoint->cons */
        RING_IDX local_cons;

        /* Will get written to local_endpoint->cons next time we
           finish. */
        RING_IDX local_cons_pvt;

        /* This is the number of bytes available after local_prod_pvt
           last time we checked, minus the number of bytes which we've
           consumed since then.  It's used to a avoid a bunch of
           memory barriers when checking for ring space. */
        unsigned local_prod_bytes_available;

        /* shadow of local_endpoint->producer_active */
        unsigned local_producer_active;

        unsigned producer_payload_bytes;
        unsigned consumer_payload_bytes;
};

/* A message header.  There is one of these at the start of every
 * message.  @type is one of the #define's below, and @size is the
 * size of the message, including the header and any padding.
 * size should be a multiple of 8 so we avoid unaligned memory copies.
 * structs defining message formats should have sizes multiple of 8
 * bytes and should use paddding fields if needed.
 */
struct netchannel2_msg_hdr {
        unsigned char type;
        unsigned char flags;
        unsigned short size;
};

static __inline const volatile void *
__nc2_incoming_message(struct nc2_ring_pair *ring)
{
        return (const volatile void *)((ULONG_PTR)ring->consumer_payload +
                                       (ring->local_cons_pvt &
                                        (ring->consumer_payload_bytes - 1)));
}

static __inline int
__nc2_contained_in_cons_ring(struct nc2_ring_pair *ring,
                             const volatile void *msg,
                             size_t size)
{
        if (msg < ring->consumer_payload ||
            size > ring->consumer_payload_bytes ||
            (ULONG_PTR)msg + size >
                (ULONG_PTR)ring->consumer_payload +
                ring->consumer_payload_bytes)
                return 0;
        else
                return 1;
}

static __inline volatile void *
__nc2_get_message_ptr(struct nc2_ring_pair *ncrp)
{
        return (volatile void *)((ULONG_PTR)ncrp->producer_payload +
                                 (ncrp->local_prod_pvt & (ncrp->producer_payload_bytes-1)));
}

static __inline void
__nc2_send_pad(struct nc2_ring_pair *ncrp, unsigned short nr_bytes)
{
        volatile struct netchannel2_msg_hdr *msg;
        msg = __nc2_get_message_ptr(ncrp);
        msg->type = NETCHANNEL2_MSG_PAD;
        msg->flags = 0;
        msg->size = nr_bytes;
        ncrp->local_prod_pvt += nr_bytes;
        ncrp->local_prod_bytes_available -= nr_bytes;
}

static __inline int
__nc2_ring_would_wrap(struct nc2_ring_pair *ring, unsigned short nr_bytes)
{
        RING_IDX mask;
        mask = ~(ring->producer_payload_bytes - 1);
        return (ring->local_prod_pvt & mask) != ((ring->local_prod_pvt + nr_bytes) & mask);
}

static __inline unsigned short
__nc2_pad_needed(struct nc2_ring_pair *ring)
{
        return (unsigned short)(ring->producer_payload_bytes -
                                (ring->local_prod_pvt &
                                 (ring->producer_payload_bytes - 1)));
}

static __inline void
__nc2_avoid_ring_wrap(struct nc2_ring_pair *ring, unsigned short nr_bytes)
{
        if (!__nc2_ring_would_wrap(ring, nr_bytes))
                return;
        __nc2_send_pad(ring, __nc2_pad_needed(ring));

}

/* A quick test of whether calling nc2_flush_ring() is likely to
   trigger an event channel notification.  This is *not* guaranteed to
   be correct, in either direction; constantly returning 0 and
   constantly returning 1 would both be correct implementations. */
static __inline int
__nc2_flush_would_trigger_event(const struct nc2_ring_pair *ring)
{
        if ( (RING_IDX)(ring->local_prod_pvt - ring->remote_endpoint->prod_event) <
             (RING_IDX)(ring->local_prod_pvt - ring->local_prod) )
                return 1;
        else
                return 0;
}

/* Copy the private producer pointer to the shared producer pointer,
 * with a suitable memory barrier such that all messages placed on the
 * ring are stable before we do the copy.  This effectively pushes any
 * messages which we've just sent out to the other end.  Returns 1 if
 * we need to notify the other end and 0 otherwise.
 */
static __inline int
nc2_flush_ring(struct nc2_ring_pair *ring)
{
        RING_IDX old_prod, new_prod;

        new_prod = ring->local_prod_pvt;
        old_prod = ring->local_prod;

        ring->local_endpoint->prod = new_prod;
        ring->local_prod = new_prod;

        /* Need to publish our new producer pointer before checking
           event. */
        mb();

        /* We notify if the producer pointer moves across the event
         * pointer. */
        if ( (RING_IDX)(new_prod - ring->remote_endpoint->prod_event) <
             (RING_IDX)(new_prod - old_prod) ) {
                return 1;
        } else {
                return 0;
        }
}

/* Copy the private consumer pointer to the shared consumer pointer,
 * with a memory barrier so that any previous reads from the ring
 * complete before the pointer is updated.  This tells the other end
 * that we're finished with the messages, and that it can re-use the
 * ring space for more messages.  Returns 1 if we need to notify the
 * other end and 0 otherwise.
 */
static __inline int
nc2_finish_messages(struct nc2_ring_pair *ring)
{
        RING_IDX old_cons, new_cons;

        old_cons = ring->local_cons;
        new_cons = ring->local_cons_pvt;

        ring->local_endpoint->cons = new_cons;
        ring->local_cons = new_cons;

        /* Need to publish our new consumer pointer before checking
           event. */
        mb();
        if ( (RING_IDX)(new_cons - ring->remote_endpoint->cons_event) <
             (RING_IDX)(new_cons - old_cons) )
                return 1;
        else
                return 0;
}

/* Check whether there are any unconsumed messages left on the shared
 * ring.  Returns 1 if there are, and 0 if there aren't.  If there are
 * no more messages, set the producer event so that we'll get a
 * notification as soon as another one gets sent.  It is assumed that
 * all messages up to @prod have been processed, and none of the ones
 * after it have been. */
static __inline int
nc2_final_check_for_messages(struct nc2_ring_pair *ring, RING_IDX prod)
{
        if (prod != ring->remote_endpoint->prod)
                return 1;
        /* Request an event when more stuff gets poked on the ring. */
        ring->local_endpoint->prod_event = prod + 1;

        /* Publish event before final check for responses. */
        mb();
        if (prod != ring->remote_endpoint->prod)
                return 1;
        else
                return 0;
}

/* Can we send a message with @nr_bytes payload bytes?  Returns 1 if
 * we can or 0 if we can't.  If there isn't space right now, set the
 * consumer event so that we'll get notified when space is
 * available. */
static __inline int
nc2_can_send_payload_bytes(struct nc2_ring_pair *ring,
                           unsigned short nr_bytes)
{
        unsigned space;
        RING_IDX cons;
        /* Times 2 because we might need to send a pad message */
        if (ring->local_prod_bytes_available > (unsigned)(nr_bytes * 2))
                return 1;
        if (__nc2_ring_would_wrap(ring, nr_bytes))
                nr_bytes = nr_bytes + __nc2_pad_needed(ring);
retry:
        cons = ring->remote_endpoint->cons;
        space = ring->producer_payload_bytes - (ring->local_prod_pvt - cons);
        if (space >= nr_bytes) {
                /* We have enough space to send the message. */

                /* No memory barrier: we need the read of cons to have
                   acquire semantics, which it does, because it's
                   volatile. */

                ring->local_prod_bytes_available = space;

                return 1;
        } else {
                /* Not enough space available.  Set an event pointer
                   when cons changes.  We need to be sure that the
                   @cons used here is the same as the cons used to
                   calculate @space above, and the volatile modifier
                   on sring->cons achieves that. */
                ring->local_endpoint->cons_event = cons + 1;

                /* Check whether more space became available while we
                   were messing about. */

                /* Need the event pointer to be stable before we do
                   the check. */
                mb();
                if (cons != ring->remote_endpoint->cons) {
                        /* Cons pointer changed.  Try again. */
                        goto retry;
                }

                /* There definitely isn't space on the ring now, and
                   an event has been set such that we'll be notified
                   if more space becomes available. */
                /* XXX we get a notification as soon as any more space
                   becomes available.  We could maybe optimise by
                   setting the event such that we only get notified
                   when we know that enough space is available.  The
                   main complication is handling the case where you
                   try to send a message of size A, fail due to lack
                   of space, and then try to send one of size B, where
                   B < A.  It's not clear whether you want to set the
                   event for A bytes or B bytes.  The obvious answer
                   is B, but that means moving the event pointer
                   backwards, and it's not clear that that's always
                   safe.  Always setting for a single byte is safe, so
                   stick with that for now. */
                return 0;
        }
}

#endif /* __XEN_PUBLIC_IO_URING_H__ */
