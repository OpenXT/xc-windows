/********************************************************************************
**    Copyright (c) 1998-1999 Microsoft Corporation. All Rights Reserved.
**
**       Portions Copyright (c) 1998-1999 Intel Corporation
**
********************************************************************************/

#ifndef _DEBUG_H_
#define _DEBUG_H_

#if defined(__cplusplus)
extern "C" {
#endif // #if defined(__cplusplus)

#include <xsapi.h>

#if defined(__cplusplus)
}
#endif // #if defined(__cplusplus)

//
// Modified version of ksdebug.h to support runtime debug level changes.
//
const int DBG_NONE     = 0x00000000;
const int DBG_PRINT    = 0x00000001; // Blabla. Function entries for example
const int DBG_WARNING  = 0x00000002; // warning level
const int DBG_ERROR    = 0x00000004; // this doesn't generate a breakpoint

// specific debug output; you don't have to enable DBG_PRINT for this.
const int DBG_STREAM   = 0x00000010; // Enables stream output.
const int DBG_POWER    = 0x00000020; // Enables power management output.
const int DBG_DMA      = 0x00000040; // Enables DMA engine output.
const int DBG_REGS     = 0x00000080; // Enables register outout.
const int DBG_PROBE    = 0x00000100; // Enables hardware probing output.
const int DBG_SYSINFO  = 0x00000200; // Enables system info output.
const int DBG_VSR      = 0x00000400; // Enables variable sample rate output.
const int DBG_PROPERTY = 0x00000800; // Enables property handler output
const int DBG_POSITION = 0x00001000; // Enables printing of position on GetPosition
const int DBG_PINS     = 0x10000000; // Enables dump of created pins in topology
const int DBG_NODES    = 0x20000000; // Enables dump of created nodes in topology
const int DBG_CONNS    = 0x40000000; // Enables dump of the connections in topology
                                    
const int DBG_ALL      = 0xFFFFFFFF;

//
// The default statements that will print are warnings (DBG_WARNING) and
// errors (DBG_ERROR).
//
const int DBG_DEFAULT = 0x00000004;  // Errors only.

    
//
// Define global debug variable.
//
#ifdef DEFINE_DEBUG_VARS
unsigned long ulDebugOut = 0xFFFFFFFF;
#else
extern unsigned long ulDebugOut;
#endif


//
// Define the print statement.
//
#if defined(__cplusplus)
extern "C" {
#endif // #if defined(__cplusplus)

#include "ntstrsafe.h"

static __inline void __XenAudTraceDBG_WARNING (PCSTR fmt, ...)
{
    static char buf[256];
    char *msg;

    msg = buf;

    va_list args;
    va_start(args, fmt);
    RtlStringCbVPrintfA(msg, sizeof (buf) - (msg - buf), fmt, args);
    va_end(args);

    int t = (int)strlen(buf);
    if (t >= sizeof(buf)) t = sizeof(buf) - 1;
    if (buf[t-1] != '\n') buf[t-1] = '\n'; buf[t] = '0';

    TraceWarning ((buf));
}

static __inline void __XenAudTraceDBG_ERROR (PCSTR fmt, ...)
{
    static char buf[256];
    char *msg;

    msg = buf;

    va_list args;
    va_start(args, fmt);
    RtlStringCbVPrintfA(msg, sizeof (buf) - (msg - buf), fmt, args);
    va_end(args);

    int t = (int)strlen(buf);
    if (t >= sizeof(buf)) t = sizeof(buf) - 1;
    if (buf[t-1] != '\n') buf[t] = '\n'; buf[t+1] = '\0';

    TraceError ((buf));
}

static __inline void __XenAudTraceDBG_PRINT (PCSTR fmt, ...)
{
    static char buf[256];
    char *msg;

    msg = buf;

    va_list args;
    va_start(args, fmt);
    RtlStringCbVPrintfA(msg, sizeof (buf) - (msg - buf), fmt, args);
    va_end(args);

    int t = (int)strlen(buf);
    if (t >= sizeof(buf)) t = sizeof(buf) - 1;
    if (buf[t-1] != '\n') buf[t] = '\n'; buf[t+1] = '\0';

    TraceNotice ((buf));
}

static __inline void __XenAudTraceDBG_NONE (PCSTR fmt, ...)
{
    static char buf[256];
    char *msg;

    msg = buf;

    va_list args;
    va_start(args, fmt);
    RtlStringCbVPrintfA(msg, sizeof (buf) - (msg - buf), fmt, args);
    va_end(args);

    int t = (int)strlen(buf);
    if (t >= sizeof(buf)) t = sizeof(buf) - 1;
    if (buf[t-1] != '\n') buf[t] = '\n'; buf[t+1] = '\0';

    TraceInfo ((buf));
}

#define __XenAudTraceDBG_PROBE __XenAudTraceDBG_NONE
#define __XenAudTraceDBG_SYSINFO __XenAudTraceDBG_NONE
#define __XenAudTraceDBG_REGS __XenAudTraceDBG_NONE
#define __XenAudTraceDBG_VSR __XenAudTraceDBG_NONE
#define __XenAudTraceDBG_POWER __XenAudTraceDBG_NONE
#define __XenAudTraceDBG_PINS __XenAudTraceDBG_NONE
#define __XenAudTraceDBG_NODES __XenAudTraceDBG_NONE
#define __XenAudTraceDBG_CONNS __XenAudTraceDBG_NONE
#define __XenAudTraceDBG_PROPERTY __XenAudTraceDBG_NONE
#define __XenAudTraceDBG_STREAM __XenAudTraceDBG_NONE
#define __XenAudTraceDBG_DMA __XenAudTraceDBG_NONE
#define __XenAudTraceDBG_POSITION __XenAudTraceDBG_NONE

#define DOUT(lvl, strings)          \
    if ((lvl) & ulDebugOut)         \
    {                               \
    __XenAudTrace ## lvl strings;   \
    }

//#if (DBG)
//#define BREAK() DbgBreakPoint()
//#else
//#define BREAK()
//#endif


#if defined(__cplusplus)
}
#endif // #if defined(__cplusplus)


#endif

