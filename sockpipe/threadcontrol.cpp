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
#include "threadcontrol.h"

DWORD WINAPI ThreadStart(void * inContext)
{
    //
    // Thunk from win32 C style entry to the containing C++ object's
    // ThreadEntry routine.
    //

    ((class ThreadControl *)inContext)->ThreadEntry(inContext);
    return 0;
}

bool ThreadControl::Start()
{
    //
    // Create thread and let it run.
    //
    // Note: Anything that needs to be done for this thread before it starts
    // needs to have been done before we get here.  This includes things like
    // initializing any events it might be supposed to wait on.
    //

    handle = CreateThread(NULL, 0, ThreadStart, this, 0, &id);
    if (handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    return true;
}


void ThreadControl::ThreadEntry(void * inContext)
{
    die("default ThreadEntry called.  This should be overridden.");
}

