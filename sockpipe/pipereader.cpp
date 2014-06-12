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
#include "plj_utils.h"
#include "spinlock.h"
#include "circle.h"
#include "threadcontrol.h"
#include "logger.h"
#include "pipereader.h"


PipeReader::PipeReader()
{
    pipe = INVALID_HANDLE_VALUE;
}

PipeReader::~PipeReader()
{
    if (pipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(pipe);
        pipe = INVALID_HANDLE_VALUE;
    }
}

bool PipeReader::Initialize(char * PipeName, Logger * Logger, class Connectoid * Sock, bool StartThread, bool Client, char * Tag)
{
    Connectoid::Initialize(Logger, Sock, Tag);
    client = Client;
    pipeName = PipeName;

    receiveBuffer.Initialize(PUMP_BUFFER_SIZE);

    //
    // If we are spinning a thread for this pipe, spin it.
    //

    if (StartThread != false)
    {
        if (!Start())
        {
            die("failed to initialize/start pipe reader thread.");
        }
    }
    return true;
}

int PipeReader::Send(Circle * buffer)
{
    BOOL    success;
    DWORD   written;
    DWORD   previouslyWritten = 0;

    if (!receiveDataSeen)
    {
        //
        // Drop incoming data on floor.
        //

        buffer->Drain();
        return 0;
    }

    int lastError = 0;

    if (write.Pending())
    {
        //
        // Check result from previous write.
        //

        success = GetOverlappedResult(pipe, write.Overlapped(), &previouslyWritten, false);
        log->Log(TAG_XMIT_DBG, tag, "write: GetOverlapResult returned %d, oh = %p", success, write.GetHandle());

        if (!success)
        {
            lastError = GetLastError();

            if (lastError == ERROR_IO_PENDING)
            {
                //
                // The previous write is not yet complete.  We can't
                // initiate another until it is.
                //

                log->Log(TAG_XMIT_DBG, tag, "write: GetOverlapResult returned ERROR_IO_PENDING, we shouldn't have come here!!!");
                return 0;
            }
            else
            {
                die("pipe write failed, error %d\n", lastError);
            }
        }
        write.SetPending(false);
//      log->Log(TAG_SENT, tag, previouslyWritten, NULL);
        {
            char * bufftmp;
            DWORD  lentmp;
            lentmp = buffer->QueryContiguousRetrievable(&bufftmp);
            ASSERT(lentmp >= previouslyWritten);
            log->Log(TAG_SENT, tag, previouslyWritten, bufftmp);
        }
        buffer->CommitRetrieved(previouslyWritten);
    }

    //
    // Initiate a write.
    //

    char * buff;
    int length = buffer->QueryContiguousRetrievable(&buff);

    if (length == 0)
    {
        //
        // Nothing available to be written just yet.
        //

        log->Log(TAG_XMIT_DBG, tag, "write: nothing to write");
        return 0;
    }

    log->Log(TAG_SEND, tag, length, NULL);
    log->Log(TAG_XMIT_DBG, tag, "initiate %d byte write oh = %p", length, write.GetHandle());

    success = WriteFile(pipe, buff, length, &written, write.Overlapped());
    if (success)
    {
//      log->Log(TAG_SENT, tag, written, NULL);
        log->Log(TAG_SENT, tag, written, buff);
        log->Log(TAG_XMIT_DBG, tag, "write: instant gratification %d bytes on oh = %p", written, write.GetHandle());
        return buffer->CommitRetrieved(written) + previouslyWritten;
    }

    lastError = GetLastError();

    if (lastError == ERROR_IO_PENDING)
    {
        write.SetPending(true);
        sender->SetWriteWait(true);
        log->Log(TAG_XMIT_DBG, tag, "write: initiated send %d bytes, new state == pending, oh = %p", length, write.GetHandle());
        return previouslyWritten;
    }
    g_shutdown = true;
    die("pipe write failed, error %d\n", lastError);
}

int PipeReader::Receive(char * buffer, int length)
{
    BOOL    success;
    DWORD   received = 0;

    if (read.Pending())
    {
        //
        // Check result from previous read.
        //

        success = GetOverlappedResult(pipe, read.Overlapped(), &received, false);
        log->Log(TAG_READ_DBG, tag, "read: GetOverlappedResult status %d, count %d, oh = %p", success, received, read.GetHandle());
        if (!success)
        {
            int lastError = GetLastError();

            if (lastError == ERROR_IO_PENDING)
            {
                //
                // The previous read is not yet complete.  We can't
                // initiate another until it is.
                //

                log->Log(TAG_READ_DBG, tag, "read: still pending, this shouldn't have happpened *****************");
                return 0;
            }
            if (lastError == ERROR_IO_INCOMPLETE)
            {
                log->Log(TAG_READ_DBG, tag, "read: ERROR_IO_INCOMPLETE, this shouldn't have happened ***************");
                fprintf(stderr, "E_IO_INCOMPLETE read from %.3s -- this shouldn't happen, ignoring.\n", tag);
                return 0;
            }
            else
            {
                die("pipe read failed, error %d\n", lastError);
            }
        }
        read.SetPending(false);
        log->Log(TAG_READ_DBG, tag, "read: delayed read complete, received %d bytes.", received);
        return received;
    }

    log->Log(TAG_READ_DBG, tag, "read: initiating read %d bytes (max) oh %p", length, read.GetHandle());
    success = ReadFile(pipe, buffer, length, &received, read.Overlapped());
    if (!success)
    {
        int lastError = GetLastError();

        if (lastError == ERROR_IO_PENDING)
        {
            log->Log(TAG_READ_DBG, tag, 0, "read: pending.");
            read.SetPending(true);
            SetReadWait(true); // ick, needs cleaning.
        }
        else if (lastError == ERROR_PIPE_LISTENING)
        {
            Sleep(500);
            log->Log(TAG_READ_DBG, tag, "read: nobody is listening.");
            read.SetOverlappedEvent();  // make sure the big wait will not wait for ever
        }
        else
        {
            fprintf(stderr, "read pipe failed %d\n", lastError);
            // For now, get us out of here.
            g_shutdown = true;
            my_exit(0);
        }
        return 0;
    }
    log->Log(TAG_READ_DBG, tag, "read: instantly returning %d bytes", received);
    return received;
}

void PipeReader::Pump()
{
    char    buf[PUMP_BUFFER_SIZE];
    bool    pljtmpOnce = 0;

    connected = true;

    while (g_shutdown == false)
    {
        int received = 0;
        int sent = 0;

        if (!wait.read)
        {
            //
            // If there's room in the recieve buffer, attempt to receive
            // some.

            int receivable = receiveBuffer.QueryInsertable();

            if (receivable != 0)
            {
                if ((received = Receive(buf, receivable)) != 0)
                {
                    if (receiveDataSeen == false)
                    {
                        printf("pipe connected.\n");
                        log->Log(TAG_READ_DBG, tag, "Recieve data from debugger.\n");
                        receiveDataSeen = true;
                    }
                    log->Log(TAG_READ, tag, received, buf);
                    if (sender->Connected() == false)
                    {
                        // Ignore all incoming data until there is something
                        // connected to send it to.
                        printf("pipereader: dropping %d bytes because socket is not connected.\n",
                                received);
                        log->Log(TAG_READ_DBG, tag,
                                "dropping %d bytes because socket is not connected.\n",
                                received);
                        received = 0;
                    }
                    if (resetAckExpected)
                    {
                        // Ignore all incoming data until the other side tells
                        // us a reset ack has been seen.
                        log->Log(TAG_READ_DBG, tag,
                                "dropping %d bytes, waiting for reset ack from target.\n",
                                received);
                        received = 0;
                    }

                    int count = CheckForResetPacket(buf, received);
                    if (count != 0)
                    {
                        log->Log(TAG_READ_DBG, tag, "RESET packet received.\n");
                        if (!resetAckExpected)
                        {
                            printf("debugger sent RESET.\n");
                        }
                        // Truncate received data to end of reset packet.  We
                        // discard all remaining data until we see a reset ack
                        // from the other end.  Note: On send the reset packet
                        // is usually followed by 8 bytes of zero, the target
                        // seems to depend on it ... and being as we truncated
                        // and we don't know we got them all yet anyway and we
                        // will drop all further data until we see something,
                        // better send the zeros along.
                        receiveBuffer.Insert(buf, count);
                        int z = 0;
                        receiveBuffer.Insert((char *)&z, sizeof(z));
                        receiveBuffer.Insert((char *)&z, sizeof(z));
                        received = 0;
                        SetResetAckExpected(true);
                    }
                    receiveBuffer.Insert(buf, received);
                }
            }
        }

        if (!wait.write)
        {
            //
            // Attempt to send. 
            //
            // Note: The Send routine will take care of the no data case.
            //

            sent = sender->Send(&receiveBuffer);
        }

        if (!(sent | received))
        {
            //
            // Nothing sent, nothing received, wait until something happens
            // on one end or the other.
            //

            Wait();
        }
    }
    connected = false;
}

void PipeReader::ThreadEntry(void * inContext)
{
    if (client == false)
    {
        //
        // Create pipe for server (that other end will connect to).
        //

        pipe = CreateNamedPipe(pipeName,
                               PIPE_ACCESS_DUPLEX 
//                             | FILE_FLAG_FIRST_PIPE_INSTANCE
//                             | FILE_FLAG_WRITE_THROUGH 
                               | FILE_FLAG_OVERLAPPED
                               ,
                               PIPE_TYPE_BYTE
//                             | PIPE_WAIT
                               ,
                               1,
                               4096,
                               4096,
                               INFINITE,
                               NULL);
        if (pipe == INVALID_HANDLE_VALUE)
        {
            die("failed to open pipe, err = %d.", GetLastError());
        }
    }
    else
    {
        //
        // Create pipe for client.  Use CreateFile because, oddly, CreateNamedPipe 
        // seems to fail if you use the \\servername\pipe\pipename format.  Sadly,
        // this too will fail if the other end doesn't exist so we need to do it
        // in the spun thread.  We did spin a thread right?
        //

        bool first = TRUE;

        do
        {
            pipe = CreateFile(pipeName,                     // pipe name
                              GENERIC_READ | GENERIC_WRITE, // read and write access
                              0,                            // no sharing
                              NULL,                         // default security
                              OPEN_ALWAYS,                  // sample says open existing
                              FILE_FLAG_WRITE_THROUGH       // push the data to the other end
                              | FILE_FLAG_OVERLAPPED        // don't wait
                              ,
                              NULL);                        // why would i want a template?
            if (pipe == INVALID_HANDLE_VALUE)
            {
                DWORD err = GetLastError();

                if (err != ERROR_FILE_NOT_FOUND)
                {
                    die("failed to open pipe, err = %d.", err);
                }

                if (first)
                {
                    printf("pipe client waiting for remote pipe to become available.\n");
                    first = false;
                }
                Sleep(1700);
            }
        } while (pipe == INVALID_HANDLE_VALUE);
    }

    printf("hello from the pipe reader.\n");

    //
    // Now pass data back and forth across the connections.
    //

    Pump();
}
