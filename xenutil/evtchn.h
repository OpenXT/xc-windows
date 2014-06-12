//
// evtchn.h - General support declarations for communicating with the
// 	      Xen event channel PCI device.
//
// Copyright (c) 2006 XenSource, Inc. - All rights reserved.
//

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

#ifndef _EVTCHN_H_
#define _EVTCHN_H_

EVTCHN_PORT EvtchnBindVirq(int virq, PEVTCHN_HANDLER_CB handler, PVOID context);

EVTCHN_PORT EvtchnRegisterHandler(int xen_port,
                                  PEVTCHN_HANDLER_CB cb,
                                  void *Context);


BOOLEAN
EvtchnHandleInterrupt(
    IN PVOID Interrupt,
    IN OUT PVOID Context
    );

extern VOID
EvtchnSetVector(ULONG vector);

extern ULONG
EvtchnGetVector(VOID);

extern VOID
XenbusSetFrozen(BOOLEAN State);

extern BOOLEAN
XenbusIsFrozen(VOID);

extern VOID                 XenSetSystemPowerState(SYSTEM_POWER_STATE State);
extern SYSTEM_POWER_STATE   XenGetSystemPowerState(VOID);

#ifdef XSAPI_FUTURE_CONNECT_EVTCHN
__MAKE_WRAPPER_PRIV(ALIEN_EVTCHN_PORT, unsigned)
static __inline ALIEN_EVTCHN_PORT
wrap_ALIEN_EVTCHN_PORT(unsigned x)
{
    return __wrap_ALIEN_EVTCHN_PORT(x ^ 0xf001dead);
}
static __inline unsigned
unwrap_ALIEN_EVTCHN_PORT(ALIEN_EVTCHN_PORT x)
{
    return __unwrap_ALIEN_EVTCHN_PORT(x) ^ 0xf001dead;
}
#endif

extern unsigned
xen_EVTCHN_PORT(EVTCHN_PORT port);

extern NTSTATUS EvtchnStart(VOID);
extern VOID EvtchnStop(VOID);


#endif // _EVTCHN_H_
