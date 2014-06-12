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

#include "stdafx.h"
#include <windows.h>
#include "plj_utils.h"
#include "spinlock.h"
#include "circle.h"
#include "threadcontrol.h"
#include "logger.h"
#include "connectoid.h"

#define MANUAL_RESET_EVENT  1

Channel::Channel()
{
    pended = false;

    RtlZeroMemory(Overlapped(), sizeof(overlap));
    overlap.hEvent = CreateEvent(NULL, MANUAL_RESET_EVENT, false, NULL);
    if (overlap.hEvent == INVALID_HANDLE_VALUE)
    {
        // Really, this can't possibly have happened.
        die("CreateEvent failed for OVERLAPPED structure for Channel constructor.");
    }
}

Channel::~Channel()
{
}

void Channel::SetOverlappedEvent()
{
    SetEvent(overlap.hEvent);
}

Connectoid::Connectoid()
{
    sender = NULL;
    log = NULL;
    tag[0] = tag[1] = tag[2] = 0;
    resetPacketIndex = 0;

#ifdef OUTBOUND_DROP_UNTIL_RESET_ONLY
    // N.B. resetAckExpected true will cause data from either end to be ignored.
    // We use this to silence the debugger until we've seen something from the
    // target.
    resetAckExpected = true;
#else
    // resetAckExpected starts false but will be set true by the first outbound
    // data seen on the pipe (from the debugger).  At that point, all data in
    // either direction will be dropped until a reset ack is seen from the
    // target.
    resetAckExpected = false;
#endif
    receiveDataSeen = false;
    connected = false;
}

Connectoid::~Connectoid()
{
}

bool Connectoid::Initialize(Logger * Logger, class Connectoid * Sender, char * Tag)
{
    log = Logger;
    sender = Sender;

    // Grr!  I'd have used strncpy to copy my 3 bytes here and allowing for
    // the possibility that the source string might be short ... but strncpy
    // is considered dangerous and strncpy_s whines if it can't fit the trailing
    // null.
    //

    for (int i = 0; i < sizeof(tag); i++)
    {
        if ((tag[i] = Tag[i]) == 0)
        {
            break;
        }
    }

    //
    // Copy this, er, pipe's read handle and the other one's write handle
    // into the array used by WaitForMultipleObjects for this thread.
    //

    waitHandles[0] = read.GetHandle();
    waitHandles[1] = sender->write.GetHandle();
    blocked[0] = blocked[1] = 0;

    return true;
}

void Connectoid::Wait()
{
    int wake;

    // The following need to be done directly when Pending is set.
    //blocked[0] = read.Pending();
    //blocked[1] = sender->write.Pending();

    if (blocked[0] == blocked[1])
    {
        //
        // we have zero or two waiters.
        //

        if (blocked[0])
        {
            //
            // two waiters.
            //

            log->Log(0, tag, "Wait multiple");
            wake = WaitForMultipleObjects(2, waitHandles, false, INFINITE);
            wake -= WAIT_OBJECT_0;

            ASSERT((wake >= 0) && (wake < 2));
            log->Log(0, tag, "Wait multiple woke %d (%s) %x", wake, wake ? "sender" : "reader", waitHandles[wake]);
            blocked[wake] = false;
#if MANUAL_RESET_EVENT
            ResetEvent(waitHandles[wake]);
#endif
        }
    }
    else
    {
        //
        // blocked[0] != blocked[1]
        //
        // One waiter.  This (should) mean the other side has nothing to do.
        // for example, we're waiting on a read and all writes have completed.
        //

        int which = blocked[1]; // if blocked[1] = 0 then blocked[0] must be 1.
                                // (overloading true/false as an index)
        HANDLE handle = waitHandles[which];
        log->Log(0, tag, "Wait single %d (%s) %x", which, which ? "sender" : "reader", waitHandles[which]);
        WaitForSingleObject(handle, INFINITE);
        log->Log(0, tag, "Wait single woke %d (%s) %x", which, which ? "sender" : "reader", waitHandles[which]);
#if MANUAL_RESET_EVENT
        ResetEvent(handle);
#endif
        blocked[which] = false;

#if 0
        if (blocked[0])
        {
            WaitForSingleObject(waitHandles[0], INFINITE);
            blocked[0] = false;
        }
        else
        {
            //
            // Reader has nothing to do but write side is blocked? This seems
            // odd.
            //

            fprintf(stderr, "%.3s write side (alone) blocked .. seems odd.\n");
            WaitForSingleObject(waitHandles[1], INFINITE);
            blocked[1] = false;
        }
#endif
    }
}

int Connectoid::Send(Circle *)
{
    die("default Connectoid::Send called.  This should be overridden.");
}

//
// This really doesn't have anything to do with the communications but,
// we need to do a little bit of stateful control when reset (aka resync)
// packets are being sent.  Specifically, we need to notice them outbound
// then discard anything inbound until we see the ack inbound.
//
// We *could* also ignore inbound acks if we haven't seen an outbound one
// because there's a bug in the protocol which makes an unexpected inbound
// ack send us into a reset loop forever.
//
// Note: This will fail to catch a reset packet that's preceeded by some random
// number of leader bytes 0x69.  So far that hasn't been a problem.  We could
// fix it by keeping a sliding window of the last 8 bytes received.
//
// This function returns the number of bytes consumed on this call before the
// packet was complete, zero otherwise.
//

char ResetPacket[8] = 
{
    0x69, 0x69, 0x69, 0x69, 0x06, 0x00, 0x00, 0x00
};

int Connectoid::CheckForResetPacket(char * Buffer, int Length)
{
    for (int count = 1; Length; count++, Length--)
    {
        if (*Buffer++ != ResetPacket[resetPacketIndex++])
        {
            resetPacketIndex = 0;
        }
        if (resetPacketIndex == sizeof(ResetPacket))
        {
            resetPacketIndex = 0;
            return count;
        }
    }
    return 0;
}

#if 0
int Connectoid::FetchResetPacket(char * Buffer)
{
    RtlCopyMemory(Buffer, ResetPacket, sizeof(ResetPacket));
    return sizeof(ResetPacket);
}
#endif

void Connectoid::InsertResetPacket(Circle * Buffer)
{
    Buffer->Insert(ResetPacket, sizeof(ResetPacket));
}
