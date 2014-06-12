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


#pragma once

#include <list>
#include <string>

extern "C"
{
#include "v4vapi.h"
}

enum V4VMsgType
{
    VMT_DATA = 0,
    VMT_SYN  = 1,
    VMT_ACK  = 2,
    VMT_FIN  = 3,
    VMT_RST  = 4,
    VMT_KEEPALIVE  = 5
};

#pragma pack(push, 1)

struct V4V_DATAGRAM_MSG : public V4V_DATAGRAM
{
    unsigned short    type;           // Message type
    unsigned short    seq;            // Message sequence
    unsigned short    size;           // Message data size in bytes.
    BYTE              sum;            // Checksum
    BYTE              x;              // Unused
};

#pragma pack(pop)

const int TestPort = 4494;

const ULONG RingSize = 64 * 1024;

typedef std::vector<BYTE> Buffer;
typedef std::list<Buffer> Data;
typedef std::list<DWORD> DataSize;
typedef std::wstring String;

struct V4V_TEST_CONTEXT;

struct V4V_OVERLAPPED : public OVERLAPPED
{
    V4V_TEST_CONTEXT*   ctx;
};

struct V4V_TEST_CONTEXT : public V4V_CONTEXT
{
    domid_t             partner; 
    uint32_t            port;
    DWORD               error;
    unsigned short      rxSeq;
    unsigned short      txSeq;
    V4V_OVERLAPPED      rov;
    V4V_OVERLAPPED      wov;
    Buffer              buffer;
};

const long V4VHeaderSize = sizeof(V4V_DATAGRAM_MSG);

DWORD GetResult(V4V_CONTEXT& ctx, OVERLAPPED* pov, DWORD& bytes);
bool  Open(V4V_CONTEXT& ctx, domid_t partner, uint32_t port);
VOID  Close(V4V_CONTEXT& ctx);

VOID CALLBACK SendCtlComplete(DWORD error, DWORD bytes, LPOVERLAPPED lpOverlapped);
bool SendCtl(V4V_TEST_CONTEXT& ctx, unsigned short type);

BYTE Checksum(const BYTE* data, long size);

void SaveFile(Data& data, LPCWSTR filename);
