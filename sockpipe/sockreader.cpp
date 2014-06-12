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
#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include "plj_utils.h"
#include "spinlock.h"
#include "circle.h"
#include "threadcontrol.h"
#include "logger.h"
#include "sockreader.h"


bool
Printable(char c)
{
    if ((c >= 0x20) && (c <= 0x7e))
    {
        return true;
    }

    switch (c)
    {
        case 0x09:  // tab
        case 0x0a:  // line feed
        case 0x0d:  // carriage return
            return true;
        default:
            return false;
    }
}


SockReader::SockReader()
{
    listenSocket    = INVALID_SOCKET;
    connection      = INVALID_SOCKET;
    doCleanup       = false;
    initialPacketHeaderIndex = 0;
}

SockReader::~SockReader()
{
    if (listenSocket != INVALID_SOCKET)
    {
        closesocket(listenSocket);
        listenSocket = INVALID_SOCKET;
    }
    Close();
    if (doCleanup)
    {
        WSACleanup();
    }
}

void SockReader::Close()
{
    if (connection != INVALID_SOCKET)
    {
        closesocket(connection);
        connection = INVALID_SOCKET;
    }
}


bool SockReader::Initialize(_TCHAR * Address, _TCHAR * PortNumber, Logger * Logger, class Connectoid * Pipe, bool StartThread, char * Tag)
{
    u_long addr;
    u_short port = htons((u_short)_tstol(PortNumber));

    if (Address)
    {
        passive = false;

        addr = inet_addr(Address);
        if (addr == INADDR_ANY || addr == INADDR_NONE)
        {
            die("TCP: invalid address.");
        }
    }
    else
    {
        addr = INADDR_ANY;
        passive = true;
    }

    if (port == 0)
    {
        die("TCP: invalid port number.");
    }

    //
    // The sockaddr_in structure specifies the address family, IP address and
    // port number that will be bound.
    //

    RtlZeroMemory(&service, sizeof(service));
    service.sin_family      = AF_INET;
    service.sin_port        = port;
    service.sin_addr.s_addr = addr;

    Connectoid::Initialize(Logger, Pipe, Tag);
    receiveBuffer.Initialize(PUMP_BUFFER_SIZE);

    if (StartThread != false)
    {
        if (!Start())
        {
            die("failed to initialize/start socket reader thread.");
        }
    }

    return true;
}

void SockReader::ThreadEntry(void * inContext)
{
    while (g_shutdown == false)
    {
        //
        // Initialize Winsock.
        //
        // Note; We could set this puppy up to handle multiple sessions, probably
        // something we will want to do in the future.
        //

        printf("hello from the socket reader.\n");

        if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
        {
            die("WINSOCK2: Winsock startup failed.");
        }
        doCleanup = true;

        if (passive)
        {
            listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (listenSocket == INVALID_SOCKET)
            {
                // GetLastError would be useful here!
                die("TCP: Socket creation error.");
            }

            //
            // Bind it.  The main loop will listen, accept and process it.
            //

            if (bind(listenSocket, (SOCKADDR *)&service, sizeof(service)) == SOCKET_ERROR)
            {
                die("WINSOCK2: bind failed.");
            }

            if (listen(listenSocket, 1) == SOCKET_ERROR)
            {
                die("WINSOCK2: listen failed.");
            }

            shutdown = false;

            do
            {
                printf("socket accepting connections\n");
                connection = accept(listenSocket, NULL, NULL);
                if (connection == SOCKET_ERROR)
                {
                    printf("accept failed (SOCKET_ERROR = %d)\n", WSAGetLastError());
                }
            } while (connection == SOCKET_ERROR);

            printf("remote com emulator connected...\n");

            closesocket(listenSocket);
            listenSocket = INVALID_SOCKET;
        }
        else
        {
            shutdown = false;

            connection = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (connection == INVALID_SOCKET)
            {
                // GetLastError would be useful here!
                die("TCP: Socket creation error.");
            }

            do
            {
                printf("socket connecting...\n");
                if (connect(connection, (SOCKADDR *)&service, sizeof(service)) == SOCKET_ERROR)
                {
                    if (WSAGetLastError() != WSAECONNREFUSED &&
                        WSAGetLastError() != WSAENETUNREACH &&
                        WSAGetLastError() != WSAETIMEDOUT)
                    {
                        die("WINSOCK2: connect failed (SOCKET_ERROR = %d)\n", WSAGetLastError());
                    }

                    printf("connect failed (SOCKET_ERROR = %d)\n", WSAGetLastError());
                }
                else
                {
                    break;
                }
            } while (true);
        }

        //
        // We have no previously initiated read on this socket, clear up
        // (potentially left over status).  We should probably tear down
        // and reestablish the read side of the world but ... I didn't
        // write it in a way that makes that easy so, rudely, just fix it.
        //

        read.SetPending(false);

        //
        // Set TCP_NODELAY on the socket so TCP won't try to build bigger
        // packets.  On the target end this seems to be critical on this
        // end it may not be so important but still may help.
        //

        int opt = 1;
        setsockopt(connection, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt));

        Pump();

        Close();
        WSACleanup();
        doCleanup = false;

        //
        // Delay slightly before going around.  This is to give the world
        // time to clean up and shouldn't be needed at all ... but we'll 
        // see if it helps.
        //

        Sleep(314);
    }
}

int SockReader::Send(Circle * buffer)
{
    int     success;
    DWORD   sent;
    DWORD   previouslySent = 0;
    int     lastError = 0;
    DWORD   flags = 0;

    if (write.Pending())
    {
        //
        // Check the result from a previous send.
        //

        success = WSAGetOverlappedResult(connection, write.Overlapped(), &previouslySent, false, &flags);
        log->Log(TAG_XMIT_DBG, tag, "write: WSAGetOverlappedResult %d, oh = %p", success, write.GetHandle());

        if (!success)
        {
            lastError = WSAGetLastError();
            die("write: WSAGetOverlappedResult failed, error = %d", lastError);
        }
        write.SetPending(false);
        log->Log(TAG_SENT, tag, previouslySent, NULL);
        buffer->CommitRetrieved(previouslySent);
    }

    //
    // Initiate a write.
    //

    char * buff;
    int length = buffer->QueryContiguousRetrievable(&buff);

    if (length == 0)
    {
        //
        // Nothing available to send.
        //

        log->Log(TAG_XMIT_DBG, tag, "write: nothing to write");
        return 0;
    }

    log->Log(TAG_SEND, tag, length, NULL);
    log->Log(TAG_XMIT_DBG, tag, "initiate %d write on socket oh = %p", length, write.GetHandle());

    sent = 0;
    WSABUF  wsabuf;
    wsabuf.buf = buff;
    wsabuf.len = length;

    success = WSASend(connection, &wsabuf, 1, &sent, flags, write.Overlapped(), NULL);

    if (success == SOCKET_ERROR)
    {
        lastError = WSAGetLastError();

        if (lastError == WSA_IO_PENDING)
        {
            write.SetPending(true);
            sender->SetWriteWait(true);
            log->Log(TAG_XMIT_DBG, tag, "write: initiated send on socket %d bytes, pending oh = %p.", length, write.GetHandle());
            return previouslySent;
        }

        //
        // Um ... Write failed, we don't know why.  Assume the connection is probably
        // gone and return to caller ... it should all come tumbling down shortly.
        //

        shutdown = true;
        fprintf(stderr, "write socket failed %d\n", lastError);
        return previouslySent;
    }

    log->Log(TAG_SENT, tag, sent, NULL);
    buffer->CommitRetrieved(sent);

    return previouslySent + sent;
}


int SockReader::Receive(char * buffer, int length)
{

    BOOL    success;
    DWORD   received = 0;

    if (read.Pending())
    {
        //
        // Check result from previous read.
        //

        DWORD flags;
        
        success = WSAGetOverlappedResult(connection, read.Overlapped(), &received, false, &flags);
        log->Log(TAG_READ_DBG, tag, "read: WSAGetOverlappedResult returned %d for %d bytes\n", success, received);

        if (!success)
        {
            int lastError = WSAGetLastError();

            if (lastError == WSA_IO_INCOMPLETE)
            {
                log->Log(TAG_READ_DBG, tag, "read: WSA_IO_INCOMPLETE, this shouldn't happen, ignored.");
                return 0;
            }
            //
            // I've seen us die here with WSAECONNRESET when the socket goes away.  
            // Treat any unknown error here the same as if a read failed and cause
            // socket closure and possible reset.
            //
            
            fprintf(stderr, "WSAGetOverlappedResult failed, err %d, closing pipe.\n", lastError);
            shutdown = true;
            return 0;
        }
        read.SetPending(false);
        log->Log(TAG_READ_DBG, tag, "read: delayed read complete, received %d bytes.", received);
        return received;
    }

    DWORD flags = 0;
    WSABUF  wsabuf;
    wsabuf.buf = buffer;
    wsabuf.len = length;
    ASSERT(length);

    log->Log(TAG_READ_DBG, tag, "read: initiating socket receive %d bytes (max) oh = %p", length, read.GetHandle());
    success = WSARecv(connection, &wsabuf, 1, &received, &flags, read.Overlapped(), NULL);
    if (success == SOCKET_ERROR)
    {
        int lastError = WSAGetLastError();

        if (lastError == WSA_IO_PENDING)
        {
            log->Log(TAG_READ_DBG, tag, "read: pending.");
            read.SetPending(true);
            SetReadWait(true); // bleh
        }
        else
        {
            log->Log(TAG_READ, tag, "read failed, WSALastError == %d\n", lastError);
            fprintf(stderr, "read socket failed %d\n", lastError);
            shutdown = true;
        }
        return 0;
    }
    log->Log(TAG_READ_DBG, tag, "read: socket recv returned %d bytes immediately.", received);

    if (!received)
    {
        log->Log(TAG_READ_DBG, tag, "read: successful read of 0 bytes, graceful shutdown.");
        shutdown = true;
    }
    return received;
}

static char InitialPacketHeader[6] =
{
    0x30, 0x30, 0x30, 0x30, 0x07, 0x00
};

int SockReader::CheckForInitialPacketHeader(char * Buffer, int Length)
{
    for (int count = 1; Length; count++, Length--)
    {
        if (*Buffer++ != InitialPacketHeader[initialPacketHeaderIndex++])
        {
            initialPacketHeaderIndex = 0;
        }
        if (initialPacketHeaderIndex == sizeof(InitialPacketHeader))
        {
            initialPacketHeaderIndex = 0;
            return count;
        }
    }
    return 0;
}


void SockReader::Pump()
{
    //
    // We have a connection, pass data back and forth.
    //

    char    buf[PUMP_BUFFER_SIZE];
    int     avail = sizeof(buf);

    log->Log(TAG_READ_DBG, tag, "Socket is up, beginning socket pump.");

    //
    // Crude.  Push a reset packet onto the socket.  Only the other side is
    // supposed to write to the socket but until he sees the connected flag
    // he isn't going to do any such thing, so, do it.  Because we inserted
    // this packet we need to stop the reset ack from getting thru to the
    // debugger or it'll ack it and the loop is on forever.
    //
    // Trouble is, the easiest way to send something is to stick it in the
    // send buffer and we're really not supposed to mess with the other side's
    // buffer ... so ... really really gross, put it in our buffer!
    //

    receiveBuffer.Drain();
    InsertResetPacket(&receiveBuffer);
    int z = 0;
    receiveBuffer.Insert((char *)&z, sizeof(z));
    receiveBuffer.Insert((char *)&z, sizeof(z));
    Send(&receiveBuffer);
    receiveBuffer.Drain();
    SetResetAckExpected(true);
    bool killResetAck = true;

    connected = true;
    while (Shutdown() == false)
    {
        int received = 0;
        int sent = 0;

        if (!wait.read)
        {
            int receivable = receiveBuffer.QueryInsertable();
            
            if (receivable != 0)
            {
                if ((received = Receive(buf, receivable)) != 0)
                {
                    log->Log(TAG_READ, tag, received, buf);
                    if (receiveDataSeen == false)
                    {
                        //
                        // If some noisy piece of software (eg PXE) spews lots
                        // of data down the serial port we might think the
                        // target is talking to the debugger.  Debugger packets
                        // always contain some unprintable characters soooooo ..
                        // use that and the probability that anything spewed by
                        // something verbose is all printable as a heuristic to
                        // indicate whether or not we think we're hearing from
                        // the debugger.
                        //

                        for (int i = 0; i < received; i++)
                        {
                            if (!Printable(buf[i]))
                            {
                                receiveDataSeen = true;
                                printf("receiving data from debug target.\n");
                                log->Log(TAG_READ_DBG, tag, "Receive data from debug target.");
                                break;
                            }
#if 1
                            else
                            {
                                printf("%c", buf[i]);
                            }
#endif
                        }
                    }
                    if (sender->Connected() == false)
                    {
                        // Ignore all incoming data until there is something
                        // connected to send it to.
                        printf("sockreader: dropping %d bytes because pipe is not connected (ERROR)\n",
                                received);
                        log->Log(TAG_READ_DBG, tag,
                                "dropping %d bytes because pipe is not connected.\n",
                                received);
                        received = 0;
                    }
                    
                    int count;
                    
                    if (resetAckExpected)
                    {
                        count = CheckForInitialPacketHeader(buf, received);

                        if (count != 0)
                        {
                            // Initial packet seen.   This is as good as a reset.

                            log->Log(TAG_READ_DBG, tag, "Initial packet received from target.\n");
                            SetResetAckExpected(false);
                            receiveBuffer.Insert(InitialPacketHeader, sizeof(InitialPacketHeader));
                            receiveBuffer.Insert(buf + count, received - count);
                            received = 0;
                        }
                    }

                    count = CheckForResetPacket(buf, received);

                    if (count != 0)
                    {
                        // Reset packet seen, which is really a reset ack.
                        // Were we expecting one?

                        if (resetAckExpected)
                        {
                            log->Log(TAG_READ_DBG, tag, "Reset ACK received from target.\n");
                            printf("Reset ACK received from target.\n");
                            if (killResetAck == false)
                            {
                                InsertResetPacket(&receiveBuffer);
                            }
                            else
                            {
                                killResetAck = false;
                            }
                            SetResetAckExpected(false);
                            receiveBuffer.Insert(buf + count, received - count);
                            received = 0;
                        }
                        else
                        {
                            printf("unexpected reset-ack from debug target, probably a bad thing.\n");
                            log->Log(TAG_READ_DBG, tag, "unexpected reset ACK received from target, PROBABLY A BAD THING.\n");
                        }
                    }
                    else
                    {
                        if (resetAckExpected)
                        {
                            // Waiting for a reset packet, ignore (ie drop)
                            // anything else.
                            log->Log(TAG_READ_DBG, tag,
                                    "dropping %d bytes, waiting for reset ack.\n",
                                    received);
                            received = 0;
                        }
                    }
                    receiveBuffer.Insert(buf, received);
                }
            }
        }

        //
        // We received some data, yay.  Pass it along.
        //

        if (!wait.write)
        {
            sent = sender->Send(&receiveBuffer);
        }

        if (!(sent | received))
        {
            Wait();
        }
    }
    log->Log(TAG_READ_DBG, tag, "Socket is down.");
    receiveDataSeen = false;
    connected = false;
}

