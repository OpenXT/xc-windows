/*
 * Copyright (c) 2012 Citrix Systems, Inc.
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

typedef struct _RECEIVER {
    RECEIVER_COMMON         Common;

    PNET_BUFFER_LIST        ReturnList;

    ULONG                   nRxInNdis;

    ULONG                   BroadcastOctets;
    ULONG                   BroadcastPkts;
    ULONG                   Errors;
    ULONG                   Interrupts;
    ULONG                   MulticastOctets;
    ULONG                   MulticastPkts;
    NDIS_HANDLE             NetBufferListPool;
    ULONG                   UcastOctets;
    ULONG                   UcastPkts;
    ULONG                   UninterestingFrames;
    ULONG                   RemoteNotifies;

    BOOLEAN                 UdpChecksumOffload;
    BOOLEAN                 TcpChecksumOffload;

    ULONG                   nRxTcpUdpCsumOffload;
    ULONG                   nRxTcpUdpCsumFixup;

#ifdef USE_V4V
    ULONG                   V4vBytesReceived;
    PMDL                    V4vRxBufMdl;
#endif

    /* Do we expect Windows to be able to handle a csum_blank
     * packet? */
    BOOLEAN                 CsumBlankSafe;
    /* Do we expect Windows to require that every single packet have
     * one of the RX csum offload flags set? */
    BOOLEAN                 ForceCsum;

    /* The pause state machine.  We cannot indicate any packets up to
       NDIS unless we're in state running; in the other states packets
       have to be diverted to the backlog list.  We make the
       transition from running to pausing as soon as we get a pause
       request from NDIS.  We make the transition from pausing paused
       as soon as the ReturnList is empty and nRxInNdis is zero.

       Going to paused is a two-step process.  First, we disable lazy
       return, so that nothing more can be added to the return list.
       Second, we wait for nRxInNdis to go to zero.  Once that
       happens, we're done.

       So, the procedure looks like this:

       (ReceiverStartPause)
       1) Acquire the receiver lock
       2) xchg ReturnList to RETURN_LIST_NO_LAZY_RETURNS
       3) Deal with the packets which were on the return list.
       4) Check nRxInNdis.  If it's zero, go to state paused and get
          out.
       5) Set state to pausing.
       6) Drop the receiver lock

       (MiniportReturn)
       1) If the return list is not RETURN_LIST_NO_LAZY_RETURNS,
          add the packet to the return list and get out.
       2) Acquire the receiver lock
       3) Decrement nRxInNdis.
       4) Drop the lock.
       5) If the decrement in step 3 hit zero and we're in state
          pausing, go to state paused.

       (ReceivePacket)
       1) Acquire the lock
       2) If state is not running, redirect to the backlog
       3) Otherwise increment nRxInNdis
       4) Drop the lock.

       So:

       -- We don't increment nRxInNdis once StartPause's critical
          section is done.
       -- We go to Paused as soon as nRxInNdis hits zero.
       -- nRxInNdis will eventually go to zero, because MiniportReturn
          does the decrement once lazy return is off.       
    */
    enum {
        ReceiverPauseRunning,
        ReceiverPausePausing,
        ReceiverPausePaused
    } PauseState;
} RECEIVER, *PRECEIVER;

VOID
ReceiverDebugDump (
    IN PRECEIVER Receiver
    );

VOID 
ReceiverCleanup (
    IN  PRECEIVER Receiver,
    BOOLEAN TearDown
    );

#ifdef USE_V4V
VOID
ReceiverHandleV4vPacket (
    IN PRECEIVER Receiver
    );
#endif

VOID
ReceiverHandleNotification (
    IN  PRECEIVER Receiver
    );

NDIS_STATUS
ReceiverInitialize (
    IN  PRECEIVER   Receiver,
    IN  PADAPTER    Adapter
    );

VOID 
ReceiverReturnNetBufferListList (
    IN  PRECEIVER           Receiver,
    IN  PNET_BUFFER_LIST    NetBufferLists,
    IN  ULONG               ReturnFlags
    );

VOID
ReceiverWaitForPacketReturn(
    IN  PRECEIVER Receiver,
    IN  BOOLEAN   Locked
    );

void ReceiverPause(PRECEIVER receiver);
void ReceiverUnpause(PRECEIVER receiver);
