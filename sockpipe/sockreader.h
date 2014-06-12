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

#if !defined(SOCKREADER_H)
#define SOCKREADER_H

#include "connectoid.h"

class SockReader : public ThreadControl, public Connectoid
{
public:
                        SockReader();
                        ~SockReader();
    bool                Initialize(_TCHAR * Address,
                                   _TCHAR * PortNumber,
                                   Logger * Logger,
                                   class Connectoid * Pipe,
                                   bool StartThread,
                                   char * Tag);
    void                ThreadEntry(void * inContext);
    int                 Send(Circle * buffer);
    int                 Receive(char * buffer, int length);

private:
    void                Close();
    void                Pump();
    bool                Shutdown();
    int                 CheckForInitialPacketHeader(char *, int);
    bool                shutdown;
    bool                doCleanup;
    int                 initialPacketHeaderIndex;
    bool                passive;

    // winsock2 fields

    WSADATA             wsaData; 
    SOCKET              listenSocket;
    SOCKET              connection;
    sockaddr_in         service;
};

inline
bool
SockReader::Shutdown()
{
    return shutdown || g_shutdown;
}

#endif
