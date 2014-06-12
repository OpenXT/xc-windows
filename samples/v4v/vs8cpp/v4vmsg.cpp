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


#include "stdafx.h"
#include "v4vmsg.h"


DWORD GetResult(V4V_CONTEXT& ctx, OVERLAPPED* pov, DWORD& bytes)
{
    ATLTRACE(__FUNCTION__ " Entry\n");

    DWORD error(0);

    bytes = 0;
    if (!::GetOverlappedResult(ctx.v4vHandle, pov, &bytes, true))
    {
        error = ::GetLastError();
    }

    ATLTRACE(__FUNCTION__ " Exit Result:%d\n", error);
    return error;    
}

bool Open(V4V_CONTEXT& ctx, domid_t partner, uint32_t port)
{
    ATLTRACE(__FUNCTION__ " Entry\n");

    DWORD error(0);
    DWORD bytes(0);

    OVERLAPPED ov = { 0 };
    ov.hEvent = ::CreateEvent(0, true, false, 0);

    ::memset(&ctx, 0, sizeof(V4V_CONTEXT));
    ctx.flags = V4V_FLAG_OVERLAPPED;

    ATLTRACE(__FUNCTION__ " V4vOpen\n");

    if (!V4vOpen(&ctx, RingSize, &ov))
    {
        error = ::GetLastError();
    }
    else 
    {
        error = GetResult(ctx, &ov, bytes);
    }

    if (error)
    {
        ATLTRACE(__FUNCTION__ " V4vOpen Error:%d\n", error);
    }
    else
    {
        v4v_ring_id_t v4vid = { 0 };
        v4vid.addr.domain = V4V_DOMID_NONE;
        v4vid.addr.port = port;
        v4vid.partner = partner;

        ATLTRACE(__FUNCTION__ " V4vBind\n");

        if (!V4vBind(&ctx, &v4vid, &ov))
        {
            error = ::GetLastError();
        }
        else
        {
            error = GetResult(ctx, &ov, bytes);
        }

        if (error)
        {
            ATLTRACE(__FUNCTION__ " V4vBind Error:%d\n", error);
        }
    }

    ::CloseHandle(ov.hEvent);

    ATLTRACE(__FUNCTION__ " Exit Result:%d\n", error);
    return (0 == error);
}

VOID Close(V4V_CONTEXT& ctx)
{
    ATLTRACE(__FUNCTION__ " Entry\n");

    ATLTRACE(__FUNCTION__ " V4vClose\n");

    ::CancelIo(ctx.v4vHandle);

    if (!V4vClose(&ctx))
    {
        ATLTRACE(__FUNCTION__ " V4vClose Error:%d", ::GetLastError());
    }

    ctx.v4vHandle = 0;
    ctx.recvEvent = 0;

    ATLTRACE(__FUNCTION__ " Exit\n");
}

DWORD SendCtl(V4V_TEST_CONTEXT& ctx, V4V_DATAGRAM_MSG& msg)
{
    ATLTRACE(__FUNCTION__ " Entry\n");

    DWORD error(0);
    DWORD bytes(0);

    if (!::WriteFile(ctx.v4vHandle, &msg, sizeof(msg), &bytes, &ctx.wov))
    {
        error = ::GetLastError();
        if (ERROR_IO_PENDING == error)
        {
            error = GetResult(ctx, &ctx.wov, bytes);
        }
    }

    if (0 == error)
    {
        _ASSERTE(bytes == sizeof(msg));
    }

    ATLTRACE(__FUNCTION__ " Exit Result:%d\n", error);
    return error;
}

VOID CALLBACK SendCtlComplete(DWORD error, DWORD bytes, LPOVERLAPPED lpOverlapped)
{
    // ATLTRACE(__FUNCTION__ " Entry\n");

    V4V_OVERLAPPED* pov = reinterpret_cast<V4V_OVERLAPPED*>(lpOverlapped);
    _ASSERTE(pov);

    V4V_TEST_CONTEXT* pctx = pov->ctx;
    _ASSERTE(pctx);

    if (error)
    {
        pctx->error = error;
    }
    else if (bytes < sizeof(V4V_DATAGRAM))
    {
        _ASSERTE(false);
        pctx->error = ERROR_MORE_DATA;
    }
    else
    {
        pctx->error = 0;
    }    
    
    // ATLTRACE(__FUNCTION__ " Exit\n");
}

bool SendCtl(V4V_TEST_CONTEXT& ctx, unsigned short type)
{
    // ATLTRACE(__FUNCTION__ " Entry\n");
    V4V_DATAGRAM_MSG ctl;
    memset(&ctl, 0, sizeof(ctl));
    ctl.addr.domain = ctx.partner;
    ctl.addr.port = ctx.port;
    ctl.type = type;
    ctl.seq = ++ctx.txSeq;

    if (!::WriteFileEx(ctx.v4vHandle, (BYTE*) &ctl, sizeof(ctl), &ctx.wov, SendCtlComplete))
    {
        ctx.error = ::GetLastError();
        ATLTRACE(__FUNCTION__ " WriteFileEx Error:%d\n", ctx.error);
    }
    else if (WAIT_IO_COMPLETION != ::SleepEx(30000, true))
    {
        ctx.error = ERROR_SERVICE_REQUEST_TIMEOUT;

        ATLTRACE(__FUNCTION__ " SleepEx Timeout\n");
    }

    // ATLTRACE(__FUNCTION__ " Exit Error:%d\n", ctx.error);
    return (0 == ctx.error);
}

BYTE Checksum(const BYTE* data, long size)
{
    BYTE sum = 0;
    for (long index = 0; index < size; ++index)
    {
        sum ^= data[index];
    }
    return sum;
}

void SaveFile(Data& data, LPCWSTR filename)
{
    ATLTRACE(__FUNCTION__ " Entry file:%S\n", filename);

    DWORD totalSize(0);

    HANDLE hFile = ::CreateFile(filename, 
                                GENERIC_WRITE,
                                0,
                                0,
                                CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL,
                                0);
    if (INVALID_HANDLE_VALUE != hFile)
    {
        while (!data.empty())
        {
            Buffer& buff = data.front();
            if (buff.size() > V4VHeaderSize)
            {
                DWORD size = buff.size() - V4VHeaderSize;
                DWORD bytes(0);
                if (!::WriteFile(hFile, &buff[V4VHeaderSize], size, &bytes, 0))
                {
                    ATLTRACE(__FUNCTION__ " WriteFile Error:%d\n", ::GetLastError());
                    break;
                }
                totalSize += bytes;
            }

            data.pop_front();
        }

        ::CloseHandle(hFile);
    }
    else
    {
        ATLTRACE(__FUNCTION__ " CreateFile:%S error:%d\n", filename, ::GetLastError());
    }

    data.clear();

    ATLTRACE(__FUNCTION__ " Exit Filesize:%d\n", totalSize);
}
