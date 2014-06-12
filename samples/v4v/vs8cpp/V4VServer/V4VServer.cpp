/*
 * Copyright (c) 2010 Citrix Systems, Inc.
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

// V4VServer.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "V4VMsg.h"

void QueueRead(V4V_TEST_CONTEXT& ctx);
void QueueWrite(V4V_TEST_CONTEXT& ctx);

Data        filedata;
DataSize    buffsize;

VOID CALLBACK ListenComplete(DWORD error, DWORD bytes, LPOVERLAPPED lpOverlapped)
{
    ATLTRACE(__FUNCTION__ " Entry\n");

    V4V_OVERLAPPED* pov = reinterpret_cast<V4V_OVERLAPPED*>(lpOverlapped);
    _ASSERTE(pov);

    V4V_TEST_CONTEXT* pctx = pov->ctx;
    _ASSERTE(pctx);

    if (error)
    {
        ATLTRACE(__FUNCTION__ " Completion error:%d\n", error);
        pctx->error = error;
    }
    else if (bytes < sizeof(V4V_DATAGRAM_MSG))
    {
        ATLTRACE(__FUNCTION__ " Insufficient data:%d\n", bytes);
        _ASSERTE(false);
        pctx->error = ERROR_MORE_DATA;
    }
    else
    {
        V4V_DATAGRAM_MSG* msg = reinterpret_cast<V4V_DATAGRAM_MSG*>(&pctx->buffer[0]);
        pctx->rxSeq = msg->seq;

        unsigned short reply = VMT_RST;

        if (VMT_SYN == msg->type)
        {
            ATLTRACE(__FUNCTION__ " SYN addr:%d.%d Received\n", msg->addr.domain, msg->addr.port);

            V4V_CONTEXT ctx = { 0 };

            // Open a new context bound to the specific partner/port
            //
            if (Open(ctx, msg->addr.domain, msg->addr.port))
            {
                Close(*pctx);
                ::memcpy(pctx, &ctx, sizeof(V4V_CONTEXT));
                pctx->partner = msg->addr.domain;
                pctx->port = msg->addr.port;
                reply = VMT_ACK;
            }
        }
        else
        {
            ATLTRACE(__FUNCTION__ " Unexpected type received:%d\n", msg->type);
        }

        // Write an ACK or RST reply.
        //
        ATLTRACE(__FUNCTION__ " Write response type:%d\n", reply);

        SendCtl(*pctx, reply); 
        if (VMT_ACK == reply)
        {
            QueueRead(*pctx);
        }
    }

    ATLTRACE(__FUNCTION__ " Exit\n");
}

VOID CALLBACK ReadComplete(DWORD error, DWORD bytes, LPOVERLAPPED lpOverlapped)
{
    //ATLTRACE(__FUNCTION__ " Entry\n");

    V4V_OVERLAPPED* pov = reinterpret_cast<V4V_OVERLAPPED*>(lpOverlapped);
    _ASSERTE(pov);

    V4V_TEST_CONTEXT* pctx = pov->ctx;
    _ASSERTE(pctx);

    if (error)
    {
        ATLTRACE(__FUNCTION__ " Completion error:%d\n", error);
        pctx->error = error;
    }
    else if (bytes < sizeof(V4V_DATAGRAM_MSG))
    {
        ATLTRACE(__FUNCTION__ " Insufficient data:%d\n", bytes);
        _ASSERTE(false);
        pctx->error = ERROR_MORE_DATA;
    }
    else
    {
        long size = bytes - sizeof(V4V_DATAGRAM_MSG);
        _ASSERTE(bytes <= pctx->buffer.size());
        V4V_DATAGRAM_MSG* msg = reinterpret_cast<V4V_DATAGRAM_MSG*>(&pctx->buffer[0]);

        BYTE sum = Checksum((BYTE*)(msg + 1), msg->size);

        bool mismatch(false);
        if (size != msg->size)
        {
            mismatch = true;
            ATLTRACE(__FUNCTION__ " Message size error\n");
        }
        if (pctx->rxSeq + 1 != msg->seq)
        {
            mismatch = true;
            ATLTRACE(__FUNCTION__ " Message sequence error\n");
        }
        if (sum != msg->sum)
        {
            mismatch = true;
            ATLTRACE(__FUNCTION__ " Message checksum error\n");
        }

        if (mismatch)
        {
            ATLTRACE(__FUNCTION__ " MSG addr:%d.%d Type:%d seq:%d size:%d sum:%x\n", 
                msg->addr.domain, msg->addr.port, msg->type,
                msg->seq, msg->size, msg->sum);
            ATLTRACE(__FUNCTION__ " EXP seq:%d size:%d Sum:%x\n", pctx->rxSeq + 1, size, sum);
        }            

        pctx->rxSeq = msg->seq;
 
        if (VMT_DATA == msg->type)
        {
            filedata.push_back(pctx->buffer);
            buffsize.push_back(bytes);

            QueueRead(*pctx);

            if (1 == filedata.size())
            {
                QueueWrite(*pctx);
            }
        }
        else if (VMT_KEEPALIVE == msg->type)
        {
            ATLTRACE(__FUNCTION__ " KEEPALIVE received\n");
            QueueRead(*pctx);
        }
        else if (VMT_FIN == msg->type)
        {
            ATLTRACE(__FUNCTION__ " FIN received\n");

            SendCtl(*pctx, VMT_FIN);

            Close(*pctx);
        }
        else
        {
            ATLTRACE(__FUNCTION__ " Unexpected type received:%d\n", msg->type);

            // Unexpected message, set an error.
            //
            pctx->error = ERROR_INVALID_DATA;
        }
    } 

    //ATLTRACE(__FUNCTION__ " Exit\n");
}

void QueueRead(V4V_TEST_CONTEXT& ctx)
{
    //ATLTRACE(__FUNCTION__ " Entry\n");

    if (ctx.v4vHandle)
    {
        if (!::ReadFileEx(ctx.v4vHandle, &ctx.buffer[0], ctx.buffer.size(), &ctx.rov, ReadComplete))
        {
            ctx.error = ::GetLastError();
            ATLTRACE(__FUNCTION__ " Read error:%d\n", ctx.error);
        }
    }

    //ATLTRACE(__FUNCTION__ " Exit\n");
}

VOID CALLBACK WriteComplete(DWORD error, DWORD bytes, LPOVERLAPPED lpOverlapped)
{
    //ATLTRACE(__FUNCTION__ " Entry\n");

    V4V_OVERLAPPED* pov = reinterpret_cast<V4V_OVERLAPPED*>(lpOverlapped);
    _ASSERTE(pov);

    V4V_TEST_CONTEXT* pctx = pov->ctx;
    _ASSERTE(pctx);

    //Buffer& buff = filedata.front();
    DWORD& size = buffsize.front();

    if (error)
    {
        ATLTRACE(__FUNCTION__ " Completion error:%d\n", error);
        pctx->error = error;
    }
    else if (bytes < size)
    {
        ATLTRACE(__FUNCTION__ " Incomplete write:%d size:%d\n", bytes, size);
        pctx->error = ERROR_MORE_DATA;
    }
    else
    {
        filedata.pop_front();
        buffsize.pop_front();
        
        if (!filedata.empty())
        {
            QueueWrite(*pctx);
        }
    } 

    //ATLTRACE(__FUNCTION__ " Exit\n");
}

void QueueWrite(V4V_TEST_CONTEXT& ctx)
{
    //ATLTRACE(__FUNCTION__ " Entry\n");

    if (ctx.v4vHandle && !filedata.empty())
    {
        Buffer& buff = filedata.front();
        DWORD& size = buffsize.front();

        V4V_DATAGRAM_MSG* msg = reinterpret_cast<V4V_DATAGRAM_MSG*>(&buff[0]);
        msg->addr.domain = ctx.partner;
        msg->addr.port = ctx.port;
        msg->type = VMT_DATA;
        msg->seq = ++ctx.txSeq;
        msg->size = (unsigned short)(size - V4VHeaderSize);
        msg->sum = Checksum((BYTE*)(msg + 1), msg->size);
        msg->x = 0;

        if (!::WriteFileEx(ctx.v4vHandle, msg, size, &ctx.wov, WriteComplete))
        {
            ctx.error = ::GetLastError();
            ATLTRACE(__FUNCTION__ " Write error:%d\n", ctx.error);
        }
    }

    //ATLTRACE(__FUNCTION__ " Exit\n");
}

int _tmain(int argc, _TCHAR* argv[])
{
    ATLTRACE(__FUNCTION__ " Entry V4VHeaderSize:%d\n", V4VHeaderSize);

    uint32_t port = TestPort;

    for (int arg = 0; arg < argc; ++arg)
    {
        String str(argv[arg]);

        if (str.length() > 2)
        {
            if (str.substr(0, 2) == L"-p")
            {
                port = ::_wtol(str.substr(2).c_str());
            }
        }
    }

    if (port <= 0)
    {
        ATLTRACE(__FUNCTION__ " Invalid port no.:%d\n", port);
        return 1;
    }

    V4V_TEST_CONTEXT ctx;
    ::memset(&ctx, 0, sizeof(ctx));

    ::memset(&ctx.rov, 0, sizeof(OVERLAPPED));
    ctx.rov.ctx = &ctx; 

    ::memset(&ctx.wov, 0, sizeof(OVERLAPPED));
    ctx.wov.ctx = &ctx; 

    ctx.buffer.resize(4096, 0);

    for (;;)
    {
        ctx.rxSeq = ctx.txSeq = 0;
        if (!Open(ctx, V4V_DOMID_ANY, port))
        {
            break;
        }
        ctx.port = port;

        ATLTRACE(__FUNCTION__ " Listen\n");
        if (!::ReadFileEx(ctx.v4vHandle, &ctx.buffer[0], ctx.buffer.size(), &ctx.rov, ListenComplete))
        {
            ctx.error = ::GetLastError();
            ATLTRACE(__FUNCTION__ " Read error:%d\n", ctx.error);
        }
        else
        {
            ATLTRACE(__FUNCTION__ " Process connection \n");

            while ((0 == ctx.error) && (ctx.v4vHandle))
            {
                DWORD dwr = ::SleepEx(30000, true);
                if (WAIT_IO_COMPLETION != dwr)
                {
                    ATLTRACE(__FUNCTION__ " Timeout\n");
                }
            }

            ATLTRACE(__FUNCTION__ " Connection closed\n");
        }

        if (ctx.v4vHandle)
        {
            Close(ctx);
        }

        filedata.clear();
        buffsize.clear();
        ctx.error = 0;
    }

    ATLTRACE(__FUNCTION__ " Exit Result:%d\n", ctx.error);
    return ctx.error;
}
