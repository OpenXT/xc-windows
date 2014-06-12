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

/* A simple abstraction for dealing with sets of ranges of integers. */
/* This needs to be #include'd into the using .c file, unfortunately.
 * Define range_set_index_t to be the type of integer you want to use
 * as an index before doing so. */

/* A range set entry (hereafter RSE) with Start s and End1 e
   represents a range of integers [s, e), where s is inclusive and e
   is exclusive.  An endpoint of 0 means that the range goes up to
   UINT_MAX.  If e != 0, e must be greater than s. */
/* The denotation of an RSE rse is

   [|rse|] = {x \in U | rse.Start <= x < rse.End1} if rse.End1 != 0 or
             {x \in U | rse.Start <= x} otherwise.
*/
/* Invariants:

   (RSE.nonempty) rse.End1 != 0 implies rse.End1 > rse.Start
*/
struct range_set_entry {
    LIST_ENTRY List;
    range_set_index_t Start;
    range_set_index_t End1; /* End + 1 */
};

/* A range set (RS) is a list of non-overlapping, non-touching ranges
 * in ascending order.  The RseCursor points at one element in the
 * list, or at the Entries list head, and is pretty much arbitrary;
 * it's just a plausible place to start any searches. */
/* The denotation of an RS rs is [|rs|] = union({[|e|] | e \in rs.Entries,
                                                         e != rs.dummy}),
   where rs.dummy is the dummy entry corresponding to Entries itself. */
/* Invariants:

   (RS.ascending) For all rse \in rs.Entries, if rse != rs.dummy and
                  rse->Flink != rs.dummy, rse->Flink->Start >= rse->End1.
   (RS.nontouching) For all rse \in rs.Entries, if rse != rs.dummy and
                    rse->Flink != rs.dummy, rse->Flink->Start != rse->End1.
   (RS.cursor_valid) rs.RseCursor \in rs.Entries

   plus all of the usual LIST_ENTRY invariants on Entries.

   Note that RS.ascending could be trivially rewritten to imply
   RS.nontouching.  We keep them separate because that makes some of
   the explanations clearer. */
/* Define a relationship before s.t.

   (rse1 `before` rse2) ===
       (rse1->Flink != rs->dummy &&
          (rse1->Flink == rse2 || rse1->Flink `before` rse2))

   Some lemmas:

   (RS.dummy_first) rs->dummy `before` rse2 for all rse2 != rs->dummy
                    in rs.  This starts walking rs from rs->dummy, and
                    stops when it hits res2 or dummy again.  If rse2
                    is in rs, it must hit that before it hits dummy,
                    by the list properties, so this is trivial.

   (RS.dummy_first2) !(rse1 `before` rs->dummy).  Trivial: the only
                     positive termination condition is rse1->Flink ==
                     rse2 == rs->dummy, but it's guarded by a negative
                     condition rse1->Flink != rs->dummy, so can't
                     happen.  Therefore, the only way out of the
                     recursion is negative, and the lemma holds.

   (RS.ascending2) (rse1 != rs->dummy && rse1 `before` rse2) implies
                   rse1.End1 < rse2.Start (and rse1.Start < rse2.Start
                   by RSE.nonempty).

                   Proof is tedious but straightforward by induction
                   on the structure of before.
*/
struct range_set {
    LIST_ENTRY Entries;
    PLIST_ENTRY RseCursor;

    /* We also keep a cache of range set entries, so that we can avoid
       running out of memory in various key places.  This is not part
       of the formal API. */
    LIST_ENTRY RseCache;

    /* Various statistics which are only used for debugging.  Not part
       of the formal API. */
    unsigned NrRSEs;
    range_set_index_t NrItems;
    unsigned NrRSEsCached;
};

#define RSE(c) CONTAINING_RECORD((c), struct range_set_entry, List)

/* Remove an RSE from the list and release, moving the cursor away if
   necessary. */
/* Put it in the RSE cache for rs */
static void
release_rse(struct range_set *rs, struct range_set_entry *rse)
{
    if (&rse->List == rs->RseCursor)
        rs->RseCursor = rse->List.Flink;
    RemoveEntryList(&rse->List);
    InsertTailList(&rs->RseCache, &rse->List);
    rs->NrRSEs--;
    rs->NrRSEsCached++;
}

static struct range_set_entry *
allocate_rse(struct range_set *rs)
{
    struct range_set_entry *rse;
    if (IsListEmpty(&rs->RseCache)) {
        rse = XmAllocateZeroedMemory(sizeof(*rse));
    } else {
        rse = RSE(rs->RseCache.Flink);
        RemoveEntryList(&rse->List);
        rs->NrRSEsCached--;
    }
    rs->NrRSEs++;
    return rse;
}

/* if rse = singleton_rse(idx), then either rse = NULL or [|rse|] = {idx} */
static struct range_set_entry *
singleton_rse(struct range_set *rs, range_set_index_t idx)
{
    struct range_set_entry *rse;

    rse = allocate_rse(rs);
    if (!rse)
        return NULL;
    rse->Start = idx;
    rse->End1 = idx + 1;
    return rse;
}

/* Assume that RS.nontouching holds throughout @rs except possibly at
   @rse (so @rse->End1 ?= @rse->Flink->Start, but for any other @rse
   in @rs RS.nontouching holds).  Restore RS.nontouching throughout
   @rs. */
static void
merge_forwards(struct range_set *rs, struct range_set_entry *rse)
{
    struct range_set_entry *next;

    if (&rse->List == &rs->Entries ||
        rse->List.Flink == &rs->Entries)
        return;
    next = RSE(rse->List.Flink);
    if (rse->End1 == next->Start) {
        rse->End1 = next->End1;
        release_rse(rs, next);
    }
}

static void
RangeSetDump(const struct range_set *rs)
{
    struct range_set_entry *rse;
    PLIST_ENTRY cursor;

    TraceInternal(("%p items in %d entries; %d cached\n",
                 rs->NrItems, rs->NrRSEs, rs->NrRSEsCached));
    if (rs->NrRSEs < 100) {
        for (cursor = rs->Entries.Flink;
             cursor != &rs->Entries;
             cursor = cursor->Flink) {
            rse = RSE(cursor);
            TraceInternal(("[%d-%d)\n", rse->Start, rse->End1));
        }
    } else {
        TraceInternal(("Too many RSEs to display.\n"));
    }
}

#define RS_ASSERT(rs, x, m)                                  \
do {                                                         \
    if (!(x)) {                                              \
        RangeSetDump(rs);                                    \
        TraceCritical(("RS_ASSERT: %s\n", #x));              \
        TraceBugCheck(m);                                    \
    }                                                        \
} while (0)

/* Set @idx in @rs.  It must not already be set.  Returns TRUE on
   success or FALSE on failure (out of memory, usually). */
/* On entry, there is no RSE @rse in rs such that @rse.Start <= idx
   and @rse.End1 > idx.  On exit, there is such an RSE.  Further,
   forall A != idx, A is in the output RS iff A is in the input RS. */
/* If rs1 is the original value of @rs and rs2 is its final value, we
   require on entry that @idx \notin [|rs1|].  If we return FALSE
   then [|rs2|] = [|rs1|].  If we return TRUE then
   [|rs2|] = [|rs1|] \union {idx}. */
static BOOLEAN
RangeSetAdd(struct range_set *rs, range_set_index_t idx)
{
    PLIST_ENTRY cursor;
    struct range_set_entry *rse;

    XM_ASSERT(rs != NULL);

    cursor = rs->RseCursor;
    rse = NULL;

    if (cursor == &rs->Entries) {
        cursor = cursor->Flink;
        if (cursor == &rs->Entries)
            goto insert_new;
    }

    /* @cursor is now an arbitrary non-dummy range set in @rs */

    /* Setting something which is already set is not allowed */
    RS_ASSERT(rs, RSE(cursor)->Start > idx || RSE(cursor)->End1 <= idx,
              ("idx %x, cursor start %x, cursor end %x\n", idx,
               RSE(cursor)->Start, RSE(cursor)->End1));

    if (RSE(cursor)->Start > idx) {
        /* cursor `before` rse implies idx < cursor->Start < rse->Start
           by RS.ascending2. */
        while (cursor != &rs->Entries && RSE(cursor)->Start > idx)
            cursor = cursor->Blink;
        /* Now, either cursor == rs->dummy or
           cursor->Start < idx < rse->Start, for all rse s.t.
           cursor `before` rse.  If cursor == rs->dummy then idx < rse->Start
           for all rse in rs.  cursor == rs->dummy iff idx is less than
           any value in [|rs|]. */
    } else {
        XM_ASSERT(RSE(cursor)->Start < idx);
        /* cursor->Start < idx.  By RS.ascending2, if rse `before` cursor,
           rse->Start < cursor->Start < idx. */
        while (cursor != &rs->Entries && RSE(cursor)->Start < idx)
            cursor = cursor->Flink;
        /* Either cursor == rs->Entries, or rse->Start < idx < cursor->Start
           for all rse `before` cursor.  If cursor == rs->Entries then
           idx is greater than any value in [|rs|].  Further,
           cursor->Start < rse->Start for all rse s.t. cursor `before` rse. */
        cursor = cursor->Blink;
        /* We know that cursor != rs->dummy.  The only way that could
           happen would have been if the previous cursor was the first
           element in the list.  That can't happen, because we know
           that cursor is not the dummy at the top of the enclosing if
           statement, and we know that we always advance at least one
           slot in the while loop (because cursor != rs->dummy on
           entry and cursor->Start < idx because of the if
           condition. */
        RS_ASSERT(rs, cursor != &rs->Entries, ("\n"));

        /* We now have cursor->Start < idx trivially.  We also have
           either cursor->Flink = rs->dummy or cursor->Flink->Start >
           idx, because of the loop termination condition and the list
           invariants.  That then gives us idx < rse->Start for all
           rse s.t. cursor `before` rse, by RS.ascending2.  i.e. the
           same condition on cursor holds here as held at the end
           of the other branch of the if. */
    }
    rs->RseCursor = cursor;

    if (cursor != &rs->Entries)
        XM_ASSERT(RSE(cursor)->End1 <= idx);
    if (cursor->Flink != &rs->Entries)
        XM_ASSERT(RSE(cursor->Flink)->Start > idx);

    /* We know that @idx is between @cursor and @cursor->Flink.
       Either:

       1) It's right at the end of @cursor (cursor->End1 == idx), or
       2) It's right at the beginning of @cursor->Flink
          (cursor->Flink->Start == idx), or
       3) neither 1 nor 2 hold, and it's somewhere in the middle not
          touching either.

       Handle each case in turn.
    */

    if (cursor != &rs->Entries &&
        RSE(cursor)->End1 == idx) {
        /* @idx is right at the end of an existing RSE.  Extend that
           RSE to cover it.  This discharges our obligation to the
           caller. */
        RSE(cursor)->End1++;
        /* It's possible that cursor->End1 == cursor->Flink->Start,
           i.e. we may have violated RS.nontouching.  Restore it. */
        merge_forwards(rs, RSE(cursor));
    } else if (cursor->Flink != &rs->Entries &&
               RSE(cursor->Flink)->Start == idx + 1 &&
               RSE(cursor->Flink)->Start != 0) {
        /* @idx is right at the start of an existing RSE.  Extend that
           RSE backwards.  We need to test ->Start != 0 to make
           sure this doesn't underflow (if Start had been equal to zero,
           then either

           a) This cursor->End1 == idx - 1, in which case we'd
           have merged in the first branch, or
           b) It doesn't, in which case we need a new RSE anyway.) */
        RSE(cursor->Flink)->Start--;
        /* Restore RS.nontouching. */
        merge_forwards(rs, RSE(cursor));
    } else {
        /* @idx doesn't touch any existing RSE, so we need to create a
           new one. */
    insert_new: /* (This is goto'd when there are no existing RSEs,
                   which trivially implies non-touching.) */
        rse = singleton_rse(rs, idx);
        if (!rse)
            return FALSE;
        rs->RseCursor = &rse->List;
        /* Insert the new RSE after the cursor.  This maintains
           RS.ascending, because cursor->End1 <= idx <
           cursor->Flink->Start, as checked above, and it maintains
           RS.nontouching because of the above conditionals. */
        InsertHeadList(cursor, &rse->List);
    }
    rs->NrItems++;
    return TRUE;
}

/* Add the range [start,end] (inclusive on both bounds) to the range
   set @rs.  It must be that none of the new indexes are set on entry.
   They all will be on exit.  Other indexes are unchanged. */
/* We require that [|rs1|] /\ [start,end] = {} on entry.  On exit,
   [|rs2|] = [|rs1| \/ [start,end] */
static BOOLEAN
RangeSetAddRange(struct range_set *rs, range_set_index_t start,
                 range_set_index_t end)
{
    struct range_set_entry *rse;

    /* Introduce the first index in the range. */
    if (!RangeSetAdd(rs, start))
        return FALSE;
    /* Singleton range -> all done. */
    if (start == end)
        return TRUE;
    /* We cheat a bit here and rely on the fact that RangeSetAdd
       leaves the cursor pointing at the RSE which it added the the
       new item to, so we can just extend that rather than having to
       add every index one at a time. */
    rse = RSE(rs->RseCursor);
    /* Make sure we've got the right one. */
    RS_ASSERT(rs, start == rse->End1-1,
              ("start %x, rse->End1 %x, end %x\n", start, rse->End1,
               end));
    /* Extend it. */
    rse->End1 = end + 1;
    /* Restore the non-touching invariant. */
    merge_forwards(rs, rse);
    rs->NrItems += end - start; /* Don't have to offset end, because
                                   RangeSetAdd() will have already
                                   done one. */
    return TRUE;
}

static unsigned
RangeSetAddItems(struct range_set *rs, const range_set_index_t *items,
                 unsigned nr_items)
{
    unsigned x;
    for (x = 0; x < nr_items; x++)
        if (!RangeSetAdd(rs, items[x]))
            return x;
    return nr_items;
}

/* Remove the range [start,end], inclusive on both bounds, from the
   range set rs. */
/* We require that [start,end] is a subset of [|rs1|] on entry, and
   set [|rs2|] = [|rs1|] - [start,end] on exit. */
static BOOLEAN
RangeSetRemoveRange(struct range_set *rs, range_set_index_t start,
                   range_set_index_t end)
{
    PLIST_ENTRY cursor;
    struct range_set_entry *new_rse;

    XM_ASSERT(rs != NULL);

    cursor = rs->RseCursor;
    if (cursor == &rs->Entries)
        cursor = cursor->Flink;
    XM_ASSERT(cursor != &rs->Entries); /* RS must not be empty */

    /* Move cursor to point at the RSE which contains the range.  We
       know it's in a single RSE because of RS.nontouching. */
    while (RSE(cursor)->Start > start ||
           RSE(cursor)->End1 <= start) {
        /* Hitting the end of the list means that some of [start,end]
           weren't set on entry. */
        XM_ASSERT(cursor != &rs->Entries);

        if (RSE(cursor)->Start > start)
            cursor = cursor->Blink;
        else
            cursor = cursor->Flink;
    }

    XM_ASSERT(RSE(cursor)->Start <= start);
    XM_ASSERT(RSE(cursor)->End1 == 0 || RSE(cursor)->End1 > start);

    if (RSE(cursor)->Start == start) {
        /* Easy case: just remove the start of the RSE. */
        RSE(cursor)->Start = end + 1;
        if (RSE(cursor)->Start == RSE(cursor)->End1)
            release_rse(rs, RSE(cursor));
    } else if (RSE(cursor)->End1 == end + 1) {
        /* Remove the end of the RSE */

        /* This won't undeflow.  It could only underflow if start were
           zero.  We know that RSE(cursor)->Start != start, because of
           the if () condition, and that cursor->Start <= start
           because of the loop exit condition, so cursor->Start < 0,
           which is a contradiction when using unsigned integers. */
        RSE(cursor)->End1 = start - 1;
        if (RSE(cursor)->Start == RSE(cursor)->End1)
            release_rse(rs, RSE(cursor));
    } else {
        /* Okay, we're going to have to do a split. */
        new_rse = allocate_rse(rs);
        if (!new_rse)
            return FALSE;
        new_rse->Start = end + 1;
        new_rse->End1 = RSE(cursor)->End1;
        RSE(cursor)->End1 = start - 1;
        InsertHeadList(cursor, &new_rse->List);
    }
    rs->NrItems -= end - start + 1;
    return TRUE;
}

static BOOLEAN
RangeSetRemove(struct range_set *rs, range_set_index_t idx)
{
    return RangeSetRemoveRange(rs, idx, idx);
}

static unsigned
RangeSetRemoveItems(struct range_set *rs, const range_set_index_t *items,
                    unsigned nr_items)
{
    unsigned x;

    for (x = 0; x < nr_items; x++)
        if (!RangeSetRemove(rs, items[x]))
            return x;
    return nr_items;
}

/* Remove the smallest index in the range set.  The range set must be
   non-empty. */
/* We require that [|rs1|] != {}.  We return the smallest x in [|rs1|],
   and set [|rs2|] = [|rs1|] - {x}. */
static range_set_index_t
RangeSetPopOne(struct range_set *rs)
{
    struct range_set_entry *h;
    range_set_index_t res;

    XM_ASSERT(rs != NULL);

    RS_ASSERT(rs, !IsListEmpty(&rs->Entries), ("\n"));

    h = RSE(rs->Entries.Flink);
    /* rse->Start > h->Start for all rse != h, by RS.ascending2, so
       h->Start is necessarily the smallest item in rs. */
    res = h->Start;
    /* Start could overflow to zero here, if h is a singleton RSE
       right at the end of the UINT range, which would invalidate
       RSE.nonempty.  That's okay, because in that case End1 will be
       zero as well, and we'll release the RSE and everything will be
       fine. */
    h->Start++;
    if (h->Start == h->End1)
        release_rse(rs, h);
    rs->NrItems--;
    return res;
}

/* Remove @nr_items of the smallest items in [|rs|] and store them in
   *@out, in ascending order.  Requires that [|rs|] contain at least
   @nr_items items.  The returned items are removed from rs. */
static void
RangeSetPopMany(struct range_set *rs, range_set_index_t *out,
                unsigned nr_items)
{
    unsigned x;

    for (x = 0; x < nr_items; x++)
        out[x] = RangeSetPopOne(rs);
}

/* Either:

   -- Find the smallest x such that x % alignment = 0 and [x, x + size)
      is a subset of [|rs1|].  Set *out to x, set [|rs2|] to
      [|rs1|] - [x, x + size), and return TRUE.  Or
   -- Return FALSE, leaving *out unchanged and setting [|rs2|] = [|rs1|]

   size and alignment must be non-zero.
*/
static BOOLEAN
RangeSetPopAlignedBlock(struct range_set *rs,
                        range_set_index_t alignment,
                        range_set_index_t size,
                        range_set_index_t *out)
{
    PLIST_ENTRY cursor;
    struct range_set_entry *rse;
    struct range_set_entry *new_rse;
    range_set_index_t aligned_start;

    XM_ASSERT(rs != NULL);
    XM_ASSERT(size != 0);
    XM_ASSERT(alignment != 0);

    /* Walk the entire list, starting from the beginning. */
    for (cursor = rs->Entries.Flink;
         cursor != &rs->Entries;
         cursor = cursor->Flink) {

        /* for all rse1 `before` cursor, there is no suitable range in
           rse1 */
        rse = RSE(cursor);
        if (rse->End1 - rse->Start < size) {
            /* This range trivially doesn't contain a suitable range,
               because it's too small. */
            continue;
        }
        if (rse->Start % alignment == 0) {
            /* rse->Start is a valid value of x.  Use it. */
            *out = rse->Start; /* result is rse->Start */
            /* Remove [rse->Start, rse->Start+size) from rs. */
            rse->Start += size;
            /* That may have caused rse->Start to be equal to
               rse->End1 (it can't be greater, because we know
               rse->End1 >= rse->Start + size before we changed
               rse->Start).  That would violate RSE.nonempty; restore
               it if necessary. */
            if (rse->Start == rse->End1)
                release_rse(rs, rse);
            rs->NrItems -= size;
            return TRUE;
        }
        if ((rse->End1 - size) % alignment == 0) {
            /* Similar -- rse->End1 - szie is a valid x. */
            *out = rse->End1 - size;
            /* Trim [rse->End1-size, rse->End1) from rs */
            rse->End1 -= size;
            /* Restore RSE.nonempty if necessary */
            if (rse->Start == rse->End1)
                release_rse(rs, rse);
            rs->NrItems -= size;
            return TRUE;
        }

        aligned_start = rse->Start + alignment - (rse->Start % alignment);
        if (rse->End1 - aligned_start < size) {
            /* Block is big enough, but it straddles an alignment
               boundary in a way which makes it unusable. */
            continue;
        }

        /* Okay, we're going to have to split this block and use part
           of it. */
        new_rse = allocate_rse(rs);
        if (!new_rse) {
            /* Try another block; maybe there'll be a trivial case
               further up. */
            /* XXX Note that this, strictly speak, doesn't satisfy our
               interface contract.  For what we want to use the API
               for it's probably better than just saying we can't find
               anything, though. */
            continue;
        }
        /* rse represents [rse->Start, rse->End1).  Split it into
           two ranges, [rse->Start, aligned_start) and
           [aligned_start+size, rse->End1).  These both satisfy
           RSE.nonempty because of the tests above, and putting
           them in rs will satisfy RS.nontouching because size != 0.
           Using them to replace rse has the effect of snipping
           [aligned_start, aligned_start+size) out of [|rs|], so we
           can use aligned_start as our result.
        */
        new_rse->End1 = rse->End1;
        new_rse->Start = aligned_start + size;
        rse->End1 = aligned_start;
        *out = aligned_start;

        InsertHeadList(&rse->List, &new_rse->List);

        rs->NrItems -= size;

        return TRUE;
    }

    return FALSE;
}

static void
RangeSetInit(struct range_set *rs)
{
    InitializeListHead(&rs->Entries);
    InitializeListHead(&rs->RseCache);
    rs->RseCursor = &rs->Entries;
}

static range_set_index_t
RangeSetItems(struct range_set *rs)
{
    return rs->NrItems;
}

static void
RangeSetDropRseCache(struct range_set *rs)
{
    struct range_set_entry *rse;

    while (!IsListEmpty(&rs->RseCache)) {
        rse = RSE(rs->RseCache.Flink);
        RemoveEntryList(&rse->List);
        XmFreeMemory(rse);
    }
    rs->NrRSEsCached = 0;
}
