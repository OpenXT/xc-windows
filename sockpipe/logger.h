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

#if !defined(LOGGER_H)
#define LOGGER_H

#if !defined LOGGING_ENABLED
#define LOGGING_ENABLED 0
#endif

typedef enum
{
    TAG_INVALID,
    TAG_READ,
    TAG_SEND,
    TAG_SENT,
    TAG_READ_DBG,
    TAG_XMIT_DBG,
    TAG_COUNT
} TAG_TYPE;

#define SOCKPIPE_LOGGING    1
#define PUMP_BUFFER_SIZE    2048

class Logger : ThreadControl
{
public:
    Logger();
    ~Logger();
    bool Initialize();
    void Log(int direction, char * tag, int len, char * buff);
    void Log(int direction, char * tag, char * buff, ...);
    void LogPrint(char * format, ...);
    void Flush();

protected:
    virtual void ThreadEntry(void * inContext);

private:
    void        InsertToLogBuffer(char * buff, int len);
    void        htoa(char * in, char * out, int lengthIn);
    DWORD       logTime();
    HANDLE      fileHandle;
    SpinLock    lock;
    Circle      buffer;
    HANDLE      writerEvent;
    HANDLE      threadHandle;
    DWORD       originalTime;
};

inline DWORD Logger::logTime()
{
    return GetTickCount() - originalTime;
}

#endif
