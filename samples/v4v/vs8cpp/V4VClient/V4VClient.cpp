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

// V4VClient.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "V4VMsg.h"

size_t offset(0);
long filenum(0);
Buffer filedata;
Buffer savedata;
Data   xml;

BYTE*  pva = 0;

void SendData(V4V_TEST_CONTEXT& ctx);
void QueueRead(V4V_TEST_CONTEXT& ctx);

bool LoadFile(LPCWSTR filename, Buffer& data)
{
    ATLTRACE(__FUNCTION__ " Entry\n");

    data.resize(0);

    HANDLE hFile = ::CreateFile(filename, 
                                GENERIC_READ,
                                0,
                                0,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL,
                                0);
    if (INVALID_HANDLE_VALUE != hFile)
    {
        DWORD size = ::GetFileSize(hFile, 0);
        if (INVALID_FILE_SIZE == size)
        {
            ATLTRACE(__FUNCTION__ " GetFileSize Error:%d\n", ::GetLastError());
        }
        else if (size > 0)
        {
            ATLTRACE(__FUNCTION__ " File size %d bytes\n", size);

            data.resize(size + V4VHeaderSize);

            DWORD bytes(0);
            if (!::ReadFile(hFile, &data[V4VHeaderSize], size, &bytes, 0))
            {
                ATLTRACE(__FUNCTION__ " File read error:%d\n", ::GetLastError());
                data.resize(0);
            }
        }

        ::CloseHandle(hFile);
    }
    else
    {
        ATLTRACE(__FUNCTION__ " CreateFile:%S error:%d\n", filename, ::GetLastError());
    }

    ATLTRACE(__FUNCTION__ " Exit\n");
    return (data.size() > 0);
}

VOID CALLBACK SendDataComplete(DWORD error, DWORD bytes, LPOVERLAPPED lpOverlapped)
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
    else if (bytes < V4VHeaderSize)
    {
        _ASSERTE(false);
        pctx->error = ERROR_MORE_DATA;
    }
    else
    {
        pctx->error = 0;

        size_t size = bytes - V4VHeaderSize;

        size_t mismatch(0);
        for (size_t index = 0; index < size; ++index)
        {
            if (pva[V4VHeaderSize + index] != filedata[offset + index])
            {
                mismatch = index;
                break;
            }
        }

        if (mismatch > 0)
        {
            V4V_DATAGRAM_MSG* pm = reinterpret_cast<V4V_DATAGRAM_MSG*>(&filedata[offset - V4VHeaderSize]);
            V4V_DATAGRAM_MSG* pvm = reinterpret_cast<V4V_DATAGRAM_MSG*>(pva);

            ATLTRACE(__FUNCTION__ " File: addr:%d.%d seq:%d Data:%.32s\n", 
                pm->addr.domain, pm->addr.port, pm->seq, &filedata[offset + mismatch]);

            ATLTRACE(__FUNCTION__ " WBuf: addr:%d.%d seq:%d Data:%.32s\n", 
                pvm->addr.domain, pvm->addr.port, pvm->seq, &pva[V4VHeaderSize + mismatch]);
        }

        // Advance the position within the file.
        //
        offset += size;
        if (offset < filedata.size())
        {
            SendData(*pctx);
        }
        else
        {
            ATLTRACE(__FUNCTION__ " Send FIN\n");
            if (!SendCtl(*pctx, VMT_FIN))
            {
                ATLTRACE(__FUNCTION__ " Send FIN failed:%d\n", pctx->error);
            }
        }
    }    
    
    // ATLTRACE(__FUNCTION__ " Exit\n");
}

void SendData(V4V_TEST_CONTEXT& ctx)
{
    const size_t blocksize = 4096;
    const size_t datasize = blocksize - V4VHeaderSize;

    if (offset >= filedata.size())
    {
        return;
    }

    long sendsize = min(datasize, filedata.size() - offset);

    V4V_DATAGRAM_MSG* msg = reinterpret_cast<V4V_DATAGRAM_MSG*>(&filedata[offset - V4VHeaderSize]);
    msg->addr.domain = ctx.partner;
    msg->addr.port = ctx.port;
    msg->type = VMT_DATA;
    msg->seq = ++ctx.txSeq;
    msg->size = (unsigned short) sendsize;
    msg->sum = Checksum((BYTE*)(msg + 1), msg->size);
    msg->x = 0;

    DWORD oldProtect(0);
    if (!::VirtualProtectEx(::GetCurrentProcess(), pva, 4096, PAGE_READWRITE, &oldProtect))
    {
        ATLTRACE(__FUNCTION__ " VirtualProtectEx(READWRITE) Error:%d\n", ::GetLastError());
    }

    ::memcpy(pva, &filedata[offset - V4VHeaderSize], sendsize + V4VHeaderSize);

    if (!::VirtualProtectEx(::GetCurrentProcess(), pva, 4096, PAGE_READONLY, &oldProtect))
    {
        ATLTRACE(__FUNCTION__ " VirtualProtectEx(READONLY) Error:%d\n", ::GetLastError());
    }

    // Test readonly....
    //
    //pva[10] = 0;

    if (!::WriteFileEx(ctx.v4vHandle, pva, sendsize + V4VHeaderSize, &ctx.wov, SendDataComplete))
    {
        ctx.error = ::GetLastError();
        ATLTRACE(__FUNCTION__ " WriteFileEx Error:%d\n", ctx.error);
    }
}

VOID CALLBACK ReadComplete(DWORD error, DWORD bytes, LPOVERLAPPED lpOverlapped)
{
    //ATLTRACE(__FUNCTION__ " Entry error:%d bytes:%d\n", error, bytes);

    V4V_OVERLAPPED* pov = reinterpret_cast<V4V_OVERLAPPED*>(lpOverlapped);
    _ASSERTE(pov);

    V4V_TEST_CONTEXT* pctx = pov->ctx;
    _ASSERTE(pctx);

    if (error)
    {
        pctx->error = error;
    }
    else if (bytes < sizeof(V4V_DATAGRAM_MSG))
    {
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

        if (VMT_ACK == msg->type)
        {
            // Connection accepted
            //
            pctx->error = ERROR_SUCCESS;
            ATLTRACE(__FUNCTION__ " ACK Received\n");
        }
        else if (VMT_DATA == msg->type)
        {
            xml.push_back(pctx->buffer);
            QueueRead(*pctx);
        }
        else if (VMT_KEEPALIVE == msg->type)
        {
            ATLTRACE(__FUNCTION__ " KEEPALIVE received\n");
            QueueRead(*pctx);
        }
        else if (VMT_FIN == msg->type)
        {
            ATLTRACE(__FUNCTION__ " FIN received\n");
            Close(*pctx);
        }
        else
        {
            // Unexpected reply, set an error.
            //
            pctx->error = ERROR_INVALID_DATA;
            ATLTRACE(__FUNCTION__ " Unexpected msg Type:%d\n", msg->type);
        }
    }  

    // ATLTRACE(__FUNCTION__ " Exit\n");
}

void QueueRead(V4V_TEST_CONTEXT& ctx)
{
    // ATLTRACE(__FUNCTION__ " Read\n");

    if (ctx.v4vHandle)
    {
        if (!::ReadFileEx(ctx.v4vHandle, &ctx.buffer[0], ctx.buffer.size(), &ctx.rov, ReadComplete))
        {
            ctx.error = ::GetLastError();
            ATLTRACE(__FUNCTION__ " Read error:%d\n", ctx.error);
        }
    }
}

bool WaitForReply(V4V_TEST_CONTEXT& ctx)
{
    // ATLTRACE(__FUNCTION__ " Entry\n");

    if (!::ReadFileEx(ctx.v4vHandle, &ctx.buffer[0], ctx.buffer.size(), &ctx.rov, ReadComplete))
    {
        ctx.error = ::GetLastError();
        ATLTRACE(__FUNCTION__ " ReadFileEx Error:%d\n", ctx.error);
    }
    else if (WAIT_IO_COMPLETION != ::SleepEx(30000, true))
    {
        ctx.error = ERROR_SERVICE_REQUEST_TIMEOUT;

        ATLTRACE(__FUNCTION__ " SleepEx Timeout\n");
    }

    // ATLTRACE(__FUNCTION__ " Exit\n");
    return (0 == ctx.error);
}

int _tmain(int argc, _TCHAR* argv[])
{
    ATLTRACE(__FUNCTION__ " Entry HeaderSize:%d\n", V4VHeaderSize);

    long repeat = 1;
    uint32_t port = TestPort;
    domid_t partner = 0;
    String filename;

    for (int arg = 0; arg < argc; ++arg)
    {
        String str(argv[arg]);

        if (str.length() > 2)
        {
            if (str.substr(0, 2) == L"-v")
            {
                partner = (domid_t) ::_wtol(str.substr(2).c_str());
            }
            else if (str.substr(0, 2) == L"-f")
            {
                filename = str.substr(2);
            }
            else if (str.substr(0, 2) == L"-r")
            {
                repeat = ::_wtol(str.substr(2).c_str());
            }
            else if (str.substr(0, 2) == L"-p")
            {
                port = ::_wtol(str.substr(2).c_str());
            }
        }
    }

    if (partner <= 0)
    {
        ATLTRACE(__FUNCTION__ " Invalid partner domid:%d\n", partner);
        return 1;
    }

    if (port <= 0)
    {
        ATLTRACE(__FUNCTION__ " Invalid port no.:%d\n", port);
        return 1;
    }

    if (filename.empty())
    {
        ATLTRACE(__FUNCTION__ " Missing filename\n");
        return 1;
    }

    if (!LoadFile(filename.c_str(), savedata))
    {
        ATLTRACE(__FUNCTION__ " LoadFile:%S failed\n", filename.c_str());
        return 1;
    }

    pva = (BYTE*) ::VirtualAllocEx(::GetCurrentProcess(), 0, 4096, MEM_COMMIT, PAGE_READONLY);
    if (0 == pva)
    {
        ATLTRACE(__FUNCTION__ " VirtualAlloc failed Error:%d\n", ::GetLastError());
        return 1;
    }

    V4V_TEST_CONTEXT ctx;
    ::memset(&ctx, 0, sizeof(ctx));

    ::memset(&ctx.rov, 0, sizeof(OVERLAPPED));
    ctx.rov.ctx = &ctx; 

    ::memset(&ctx.wov, 0, sizeof(OVERLAPPED));
    ctx.wov.ctx = &ctx; 

    ctx.buffer.resize(4096, 0);

    for (long count = 0; count < repeat; ++count)
    {
        xml.clear();

        ctx.rxSeq = ctx.txSeq = 0;
        if (Open(ctx, partner, port))
        {
            ctx.partner = partner;
            ctx.port = port;

            ATLTRACE(__FUNCTION__ " Connect\n");

            while (0 == ctx.error)
            {
                // Send the initial SYN message to create a connection.
                //
                if (!SendCtl(ctx, VMT_SYN))
                {
                    ATLTRACE(__FUNCTION__ " Send SYN failed:%d\n", ctx.error);
                }
                else if (!WaitForReply(ctx))
                {
                    ATLTRACE(__FUNCTION__ " Connect failed:%d\n", ctx.error);
                }
                else
                {
                    break;
                }

                if ((ERROR_VC_DISCONNECTED == ctx.error) ||
                    (ERROR_SERVICE_REQUEST_TIMEOUT == ctx.error))
                {
                    // If connection failed due to VC disconnected/timeout retry, server may not be present
                    //
                    ctx.error = 0;
                    ::SleepEx(10000, true);
                }
            }

            ATLTRACE(__FUNCTION__ " Connected\n");

            if (0 == ctx.error)
            {
                filedata = savedata;
                offset = V4VHeaderSize;
                SendData(ctx);
                QueueRead(ctx);

                while ((0 == ctx.error) && (ctx.v4vHandle))
                {
                    DWORD dwr = ::SleepEx(30000, true);
                    if (WAIT_IO_COMPLETION != dwr)
                    {
                        ATLTRACE(__FUNCTION__ " Timeout\n");
                    }
                }

                if ((0 == ctx.error) && (ctx.v4vHandle))
                {
                    ATLTRACE(__FUNCTION__ " Send FIN\n");
                    if (!SendCtl(ctx, VMT_FIN))
                    {
                        ATLTRACE(__FUNCTION__ " Send FIN failed:%d\n", ctx.error);
                    }
                }
            }

            Close(ctx);
        }

        if (ctx.error)
        {
            ATLTRACE(__FUNCTION__ " Fatal error:%d\n", ctx.error);
            break;
        }

        if (!xml.empty())
        {
            WCHAR fname[128];
            ::swprintf_s(fname, L"fdata%3.3d.xml", ++filenum);

            SaveFile(xml, fname);
        }

        ::Sleep(2000);
    }

    ::VirtualFreeEx(::GetCurrentProcess(), pva, 0, MEM_RELEASE);

    ATLTRACE(__FUNCTION__ " Exit\n");
	return 0;
}

