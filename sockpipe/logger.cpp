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

#if 0
static char * asciiTable[0x20] =
{
    "<NUL>",
    "<SOH>",
    "<STX>",
    "<ETX>",
    "<EOT>",
    "<ENQ>",
    "<ACK>",
    "<BEL>",
    "<BS>",
    "<TAB>",
    "<LF>",
    "<VT>",
    "<FF>",
    "<CR>",
    "<SO>",
    "<SI>",
    "<DLE>",
    "<DC1>",
    "<DC2>",
    "<DC3>",
    "<DC4>",
    "<NAK>",
    "<SYN>",
    "<ETB>",
    "<CAN>",
    "<EM>",
    "<SUB>",
    "<ESC>",
    "<FS>",
    "<GS>",
    "<RS>",
    "<US>"
}

void
ToAcsii(char c, char * buf)
{
    if ((c & 0x80) != 0)
    {
        buf[0] = 0;
    }
    else if (c < 0x20)
    {
        strcpy(buf, asciiTable[c]);
    }
    else if (c < 0x7f)
    {
        buf[0] = c;
        buf[1] = 0;
    }
    else
    {
        strcpy(buf, "<DEL>");
    }
}
#endif

Logger::Logger()
{
    fileHandle = INVALID_HANDLE_VALUE;
    originalTime = GetTickCount();
}

Logger::~Logger()
{

#if LOGGING_ENABLED

    if (fileHandle != INVALID_HANDLE_VALUE)
    {
        int retries = 0;
        while (buffer.QueryRetrievable() != 0)
        {
            if (++retries > 10)
            {
                break;
            }
            SetEvent(writerEvent);
            Sleep(100);
        }
        CloseHandle(fileHandle);
        fileHandle = INVALID_HANDLE_VALUE;
    }

#endif

}

void Logger::ThreadEntry(void * inContext)
{
    printf("hello from Logger's thread entry!\n");

#if defined(SOCKPIPE_LOGGING)

    for (;;)
    {
        int     bytes;
        char  * data;
        DWORD   written;

        while ((bytes = buffer.QueryContiguousRetrievable(&data)) != 0)
        {
            WriteFile(fileHandle, data, bytes, &written, NULL);
            //
            // Error handling? What error handling?
            //

            buffer.CommitRetrieved(bytes);
        }
        WaitForSingleObject(writerEvent, INFINITE);
    }

#endif

}

bool Logger::Initialize()
{

#if LOGGING_ENABLED
    
    fileHandle = CreateFile(_T("sockpipe.log"), GENERIC_WRITE, FILE_SHARE_READ,
                            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                            NULL);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        die("failed to open log file \"sockpipe.log\".");
    }

    writerEvent = CreateEvent(NULL, false, false, NULL);

    if (writerEvent == INVALID_HANDLE_VALUE)
    {
        // I don't think this can happen, but, ...
        die("failed to create a writerEvent handle for the logger.");
    }

    threadHandle = CreateEvent(NULL, false, false, NULL);

    if (threadHandle == INVALID_HANDLE_VALUE)
    {
        die("failed to create threadHandle for the logger thread.");
    }

    lock.Initialize();

    if (!buffer.Initialize(4096))
    {
        die("failed to initialize circular buffer for logging.");
    }

    if (!Start())
    {
        die("failed to initialize/start log writer thread.");
    }

#if 0
    //
    // Unit test the Circular Buffer code.  Never returns.
    //

    buffer.TestPattern(writerEvent);
#endif
#endif

    return true;
}

char LogTags[] = 
{
    '.',
    'R',
    'X',
    'S',
    'r',
    'x',
    'u'
};

void Logger::htoa(char * in, char * out, int lengthIn)
{
    char * t = out;

    for (int i = 0; i < lengthIn; i++)
    {
        char c = ((in[i] >> 4) & 0xf) + '0';
        if (c > '9') c += ('a' - '0') - 10;
        *t = c;

        c = (in[i] & 0xf) + '0';
        if (c > '9') c += ('a' - '0')- 10;
        *(t + 1) = c;
        t += 2;
    }
}


void Logger::InsertToLogBuffer(char * buff, int len)
{

#if defined(SOCKPIPE_LOGGING)

    //
    // Log activity.  Could be receive of either type, or other 
    // interesting things (like a close).
    //

    for (int remaining = len; remaining; )
    {
        lock.Acquire();

        int done = buffer.Insert(buff, remaining);

        lock.Release();

        remaining -= done;

        if (remaining)
        {
            SetEvent(writerEvent);
            buffer.WaitUntilNotFull();
        }
    }

    //
    // Kick off the writer thread.  If there are more bytes in the buffer than
    // we just inserted, the thread will have been kicked already, less than or
    // equal and we can't tell.
    //

    if (buffer.QueryRetrievable() <= len)
    {
        SetEvent(writerEvent);
    }

#endif

}

void Logger::Flush()
{
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        return;
    }

    if (buffer.QueryRetrievable())
    {
        SetEvent(writerEvent);
    }

    //
    // Wait up to 3 seconds for the flush to complete.
    //

    for (int i = 0; (buffer.QueryRetrievable()) && (i < 30); i++)
    {
        Sleep(100);
    }
}


void Logger::Log(int direction, char * tag, int len, char * buff)
{
    ASSERT(len < (PUMP_BUFFER_SIZE * 2));
    ASSERT(direction < TAG_COUNT);

#if LOGGING_ENABLED

    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        return;
    }

    char tmpbuf[PUMP_BUFFER_SIZE * 4];
    char * t = tmpbuf;

#if defined(SAFESTR)
    t += sprintf_s(tmpbuf, sizeof(tmpbuf), "%08x %05d %c%.3s ", logTime(), len, LogTags[direction], tag);
#else
    t += sprintf(tmpbuf, "%08x %05d %c%.3s ", logTime(), len, LogTags[direction], tag);
#endif

//  if (buff && (direction <= TAG_READ)) // only dump buffer on read side (for the moment)
    if (buff && ((direction <= TAG_READ) || ((direction == TAG_SENT) && !strncmp(tag, "pip", 3))))
    {
        htoa(buff, t, len);
    }
    else
    {
        len = 0;
    }
    t += len << 1;
    *t = '\n';
    *(t + 1) = 0;
//  printf(tmpbuf);
    InsertToLogBuffer(tmpbuf, (int)(t - tmpbuf) + 1);

#endif

}


void Logger::Log(int direction, char * tag, char * buff, ...)
{
    ASSERT(direction < TAG_COUNT);

#if LOGGING_ENABLED

    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        return;
    }

    char tmpbuf[1024];
    va_list args;
    int l;
    int n;

    va_start(args, buff);
#if defined(SAFESTR)
    l = sprintf_s(tmpbuf, sizeof(tmpbuf), "%08x       %c%.3s ", logTime(), LogTags[direction], tag);
    n = vsnprintf_s(tmpbuf + l, sizeof(tmpbuf) - l - 1, sizeof(tmpbuf) - 1 - 2, buff, args);
#else
    l = sprintf(tmpbuf, "%08x       %c%.3s ", logTime(), LogTags[direction], tag);
    n = _vsnprintf(tmpbuf + l, sizeof(tmpbuf) - l - 1, buff, args);
#endif
    l += n;
    if (n < 0)
    {
        l = sizeof(tmpbuf) - 1;
    }
    
    tmpbuf[l] = '\n';
    InsertToLogBuffer(tmpbuf, l + 1);

#endif

}

void Logger::LogPrint(char * format, ...)
{

#if LOGGING_ENABLED

    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        return;
    }

    char tmpbuf[1024];
    va_list args;
    int l;

    va_start(args, format);
#if defined(SAFESTR)
    l = vsnprintf_s(tmpbuf, sizeof(tmpbuf), sizeof(tmpbuf) - 1, format, args);
#else
    l = _vsnprintf(tmpbuf, sizeof(tmpbuf), format, args);
#endif

    if (l < 0)
    {
        tmpbuf[sizeof(tmpbuf)-1] = '\n';
        l = sizeof(tmpbuf);
    }
    InsertToLogBuffer(tmpbuf, l);

#endif

}
