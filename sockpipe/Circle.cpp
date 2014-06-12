/*
 * Copyright (c) 2014 Citrix Systems, Inc.
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
// Circular buffer.
//
// This class implements a circular buffer for data movement.  The buffer
// utilizes a pair of pointers, in and out, that chase each other.
//
// in is the offset of the next byte in the buffer where data can be inserted.
// out is the offset of the next byte in the buffer to be removed.
//
// in == out means the buffer is empty. in one behind out means the buffer is
// full.
//
// in is only ever updated by producers, out is only updated by consumers.  If 
// there are multiple producers, in must be protected by a lock, if there are
// multiple consumers, out must be protected by a lock.
//
// In the following, in > out, new data can be inserted at in and in can wrap
// around to but not catch up out.   Data from out to in is available.
//
// +------------------------------------------------------------+
// |    XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX                   |
// +------------------------------------------------------------+
//      ^out                                 ^in
//
// When in < out, the already inserted data wraps around the buffer.
//
// +------------------------------------------------------------+
// |XXXX                                    XXXXXXXXXXXXXXXXXXXX|
// +------------------------------------------------------------+
//      ^in                                 ^out
//

#include "stdafx.h"
#include <windows.h>
#include "plj_utils.h"
#include "circle.h"

Circle::Circle()
{
    buffer = NULL;
    in     = 0;
    out    = 0;
    length = 0;

    waitEvent = INVALID_HANDLE_VALUE;
    waitCount = 0;
}

Circle::~Circle()
{
    if (buffer != NULL)
    {
        delete buffer;
    }
}

bool Circle::Initialize(int size)
{
    buffer = new char[size];
    if (buffer == NULL)
    {
        die("failed to allocate circular buffer of %d bytes.", size);
    }
    length = size;

    waitEvent = CreateEvent(NULL, false, false, NULL);

    if (waitEvent == INVALID_HANDLE_VALUE)
    {
        // I don't think this can happen, but, ...
        die("failed to create wait handle for circular buffer.");
    }
    return true;
}

void Circle::WaitUntilNotFull()
{
    if (QueryInsertable() == 0)
    {
        InterlockedIncrement(&waitCount);
        WaitForSingleObject(waitEvent, INFINITE);
    }
}

int Circle::QueryInsertable()
{
    //
    // Calculate and return the number of bytes that can be inserted into the
    // buffer.  
    //
    // Note: The number of bytes that can be inserted is one less than the
    // number of free bytes.  This is so the 'in' pointer doesn't colide with 
    // the 'out' pointer, in == out is buffer empty, not buffer full.
    //

    int tin = in;
    int tout = out;

    if (tin == tout)
    {
        //
        // buffer is empty.
        //

        return length - 1;
    }
    if (tin > tout)
    {
        return tout + (length - tin) - 1;
    }

    // else (in < out)

    return tout - tin - 1;
}

int Circle::QueryRetrievable()
{
    int tin = in;
    int tout = out;

    if (tin >= tout)
    {
        return tin - tout;
    }

    // else (in < out)

    return tin + (length - tout);
}

int Circle::Insert(char * data, int len)
{
    //
    // Add data to the circular buffer.  This routine is non-blocking.
    // The amount of data added to the buffer is returned, that amount
    // can be less than provided.
    //
    // If multiple providers, 'in' must be protected by a lock.
    //

    int insert = QueryInsertable();
    int tin = in;
    char * to = buffer + tin;

    if (len < insert)
    {
        insert = len;
    }
    int inserted = insert;

    if (in >= out)
    {
        //
        // Determine if the insertion wraps around the end of the buffer in
        // which case we'll need to do two copies.
        //
    
        int here = length - tin;

        if (here < insert)
        {
            //
            // Need to split the insertion into two parts, the copy to the
            // top part of the buffer and the copy to the low.  Do the top
            // copy here and set things up to fall thru and do the bottom
            // part.
            //

            RtlCopyMemory(to, data, here);
            insert -= here;
            data += here;
            tin = 0;
            to = buffer;
        }
        else if (here == insert)
        {
            //
            // This insertion fits in the top of the buffer .. exactly ..
            // need to wrap the in pointer as the next time the insertion
            // will go to the start of the buffer.  Fall thru and do the
            // single copy below.
            //

            tin = -insert;
        }
    }
    tin += insert;
    ASSERT(tin < length);
    RtlCopyMemory(to, data, insert);
    in = tin;
    return inserted;
}

int Circle::Retrieve(char * bp, int len)
{
    int tin = in;
    int tout = out;
    int tlen;

    if (tin == tout)
    {
        return 0;
    }

    if (tin > tout)
    {
        //
        // +------------------------------------------------------------+
        // |    XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX                   |
        // +------------------------------------------------------------+
        //      ^out                                 ^in
        //

        tlen = tin - out;

        if (tlen > len)
        {
            tlen = len;
        }

        RtlCopyMemory(bp, buffer + tout, tlen);

        tout += tlen;
        if (tout == length) // can't happen
        {
            // N.B. This can't actually happen unless we change the algorithm
            // to allow in == length, currently that will always wrap to 0.
            // I want to actually check and see if the algorithm becomes cleaner
            // if we do that.
            tout = 0;
        }
    }
    else
    {
        //
        // +------------------------------------------------------------+
        // |XXXX                                    XXXXXXXXXXXXXXXXXXXX|
        // +------------------------------------------------------------+
        //      ^in                                 ^out
        //

        tlen = length - tout + tin;
        if (tlen > len)
        {
            tlen = len;
        }
        tout += tlen;
        
        if (tout > length)
        {
            tout -= length;
        }
    }
    out = tout;
    if ((tlen != 0) && (waitCount != 0))
    {
        InterlockedDecrement(&waitCount);
        SetEvent(waitEvent);
    }
    return tlen;
}

int Circle::QueryContiguousRetrievable(char ** datap)
{
    //
    // Non-copy optimization, return the number of bytes we can retrieve in a
    // straight line.  If the available buffer wraps, return from the current
    // position to the buffer end, the caller will call again for the stuff
    // at the front.
    //

    int        tout = out;
    int        tin  = in;
    int        len  = 0;

    if (tout <= tin)
    {
        len = tin - tout;
    }
    else
    {
        len = length - tout;
    }
    *datap = buffer + tout;
    return len;
}

int Circle::CommitRetrieved(int len)
{
    int        tout = out;
    int        tin  = in;

    // Make sure out won't overtake in.
    ASSERT((tin < tout) || ((tout + len) <= tin));

    tout += len;

    ASSERT(tout <= length);

    if (tout == length)
    {
        tout = 0;
    }
    out = tout;

    if ((len != 0) && (waitCount != 0))
    {
        InterlockedDecrement(&waitCount);
        SetEvent(waitEvent);
    }

    return len;
}

void Circle::Drain()
{
    //
    // Discard any data already in the buffer.
    //
    // Note: This is a Consumer function, that is, we pretend to have retrieved
    // all the data in the buffer.
    //

    int tout = out;
    int tin  = in;

    if (tin != tout)
    {
        in = tout;

        if (waitCount != 0)
        {
            InterlockedDecrement(&waitCount);
            SetEvent(waitEvent);
        }
    }
}

void Circle::TestPattern(HANDLE Writer)
{
    char    pattern[80];

    for (int i = 0; i < sizeof(pattern); i++)
    {
        pattern[i] = 0x30 + (i % 10);
    }

    for (;;)
    {
        for (int i = 0; i < sizeof(pattern); i++)
        {
            int j = i + 1;
            char old = pattern[i];
            pattern[i] = '\n';
            char * s = pattern;
            for (int n = 0; n < j; )
            {
                int d = Insert(s, i - n + 1);
                n += d;
                s += d;
                if (n < j)
                {
                    SetEvent(Writer);
                    WaitUntilNotFull();
                    continue;
                }
                ASSERT(n == j);
            }
            pattern[i] = old;
            if (QueryRetrievable() == j)
            {
                SetEvent(Writer);
            }
        }
        for (int i = sizeof(pattern) - 2; i > 0; i--)
        {
            int j = i + 1;
            char old = pattern[i];
            pattern[i] = '\n';
            char * s = pattern;
            for (int n = 0; n < j; )
            {
                int d = Insert(s, i - n + 1);
                n += d;
                s += d;
                if (n < j)
                {
                    SetEvent(Writer);
                    WaitUntilNotFull();
                    continue;
                }
                ASSERT(n == j);
            }
            pattern[i] = old;
            if (QueryRetrievable() == j)
            {
                SetEvent(Writer);
            }
        }
    }
}
