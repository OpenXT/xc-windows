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
// SpinLock.  Generic procedural.
//

#include "stdafx.h"
#include <windows.h>
#include "plj_utils.h"
#include "spinlock.h"


void SpinLock::Acquire()
{
    for(;;)
    {
        while (value != 0)
        {
            //
            // Move to the back of the ready queue.  If this process had more
            // than two threads we might want to do something more interesting
            // but with only two, if the lock is held the other guy has it,
            // give him a turn on the processor.
            //

            Sleep(0);
        }

        //
        // Might want to use something more interesting than 1 for the lock value.
        // for example, the current thread id, or simply whether it's the reader
        // or writer.
        //

        if (InterlockedExchange(&value, 1) == 0)
        {
            return;
        }
    }
}

void SpinLock::Release()
{
    ASSERT(value != 0);
    value = 0;
}

bool SpinLock::TryToAcquire()
{
    if (value != 0)
    {
        return false;
    }

    if (InterlockedExchange(&value, 1) != 0)
    {
        return false;
    }
    return true;
}
