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

#if !defined(CONNECTOID_H)
#define CONNECTOID_H

extern char resetPacket[8];

class Channel
{
public:
                        Channel();
                        ~Channel();
    void                Wait();
    LPOVERLAPPED        Overlapped();
//  LPWSAOVERLAPPED     WSAOverlapped();
    bool                Pending();
    void                SetPending(bool);
    void                SetOverlappedEvent();
    HANDLE              GetHandle();
private:

    //
    // Currently OVERLAPPED and WSAOVERLAPPED are the same structure, what a
    // pity they're different types.
    //
    OVERLAPPED          overlap;
//  WSAOVERLAPPED       wsaoverlap;
    bool                pended;
};

inline void Channel::Wait()
{
    DWORD result = WaitForSingleObject(overlap.hEvent, INFINITE);
    ASSERT(result != WAIT_FAILED);
    return;
}

inline LPOVERLAPPED Channel::Overlapped()
{
    return &overlap;
}

#if 0
inline LPWSAOVERLAPPED Channel::WSAOverlapped()
{
    return &wsaoverlap;
}
#endif

inline bool Channel::Pending()
{
    return pended;
}

inline void Channel::SetPending(bool Pend)
{
    pended = Pend;
}

inline HANDLE Channel::GetHandle()
{
    return overlap.hEvent;
}


class Connectoid
{
public:
                        Connectoid();
                        ~Connectoid();
    bool                Initialize(Logger * Logger, class Connectoid * Connector, char * Tag);
//  virtual void        Send(char * buffer, int length);
    virtual int         Send(Circle *);
//  void                Receive(char * buffer, int length);
    void                Wait();
    void                SetReadWait(bool);
    void                SetWriteWait(bool);
    void                SetResetAckExpected(bool);
    bool                Connected();

protected:
    class Connectoid  * sender;
    class Logger      * log;
    Channel             read;
    Channel             write;
    HANDLE              waitHandles[2];
    union
    {
        char            blocked[2];
        struct
        {
            char        read;
            char        write;
        } wait;
    };
    char                tag[3];
    Circle              receiveBuffer;
    int                 resetPacketIndex;
    bool                resetAckExpected;
    bool                receiveDataSeen;
    bool                connected;
    int                 CheckForResetPacket(char *, int);
    void                ClearResetPacketIndex();
    void                InsertResetPacket(Circle *);
};

inline void Connectoid::SetReadWait(bool value)
{
    wait.read = value;
}

inline void Connectoid::SetWriteWait(bool value)
{
    wait.write = value;
}

inline void Connectoid::ClearResetPacketIndex()
{
    resetPacketIndex = 0;
}

inline void Connectoid::SetResetAckExpected(bool value)
{
    resetAckExpected = value;
    sender->resetAckExpected = value;
}

inline bool Connectoid::Connected()
{
    return connected;
}

#endif

