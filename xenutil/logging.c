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

#include "xenutl.h"
#include "scsiboot.h"

/* We keep a ring buffer of recent messages which is included in
   kernel crashdumps. */
#define LOG_MSG_BUFFER_SIZE 8192
static char LogMessageBuffer[LOG_MSG_BUFFER_SIZE];
static ULONG LogMessageBufferPtr;

#define XENTRACE_KD         (1<<0) /* Messages go to kernel debugger */
#define XENTRACE_XEN        (1<<1) /* Messages go to Xen debug port */
#define XENTRACE_LOG        (1<<2) /* Messages go to ring buffer */
#define XENTRACE_DOM0       (1<<3) /* Messages go to dom0 logging port */
#define XENTRACE_WPP        (1<<4) /* Messages go to WPP */
#define XENTRACE_BUGCHECK   (1<<5) /* Messages go to buffer referenced by bugcheck */

/* Indexed by instances of XenTraceLevel */
static int XenTraceDispositions[] = {
    XENTRACE_WPP|XENTRACE_LOG,                                                            // DEBUG
    XENTRACE_WPP|XENTRACE_LOG|XENTRACE_KD,                                                // VERBOSE
    XENTRACE_WPP|XENTRACE_LOG|XENTRACE_KD|XENTRACE_XEN,                                   // INFO
    XENTRACE_WPP|XENTRACE_LOG|XENTRACE_KD|XENTRACE_XEN|XENTRACE_DOM0,                     // NOTICE
    XENTRACE_WPP|XENTRACE_LOG|XENTRACE_KD|XENTRACE_XEN|XENTRACE_DOM0,                     // WARNING
    XENTRACE_WPP|XENTRACE_LOG|XENTRACE_KD|XENTRACE_XEN|XENTRACE_DOM0,                     // ERROR
    XENTRACE_WPP|XENTRACE_LOG|XENTRACE_KD|XENTRACE_XEN|XENTRACE_DOM0,                     // CRITICAL
    XENTRACE_WPP|XENTRACE_LOG|XENTRACE_KD|XENTRACE_XEN|XENTRACE_DOM0|XENTRACE_BUGCHECK,   // BUGCHECK
    0,
    XENTRACE_WPP,                                                                         // PROFILE
    XENTRACE_DOM0|XENTRACE_XEN                                                            // INTERNAL
};

static VOID
PutCharToRing(
    IN CHAR c
    )
{
    ULONG ptr;

    ptr = (LogMessageBufferPtr++) % LOG_MSG_BUFFER_SIZE;
    *(LogMessageBuffer + ptr) = c;
}

static VOID
SendMessageToRing(IN PCHAR msg)
{
    CHAR c;

    PutCharToRing('>');
    PutCharToRing(' ');
    while ((c = *msg++) != '\0')
        PutCharToRing(c);
    PutCharToRing('\0');
}

static VOID *const xen_debug_port = (VOID *)(ULONG_PTR)0xe9;

static VOID
PutCharToXen(
    IN CHAR c
    )
{
    WRITE_PORT_UCHAR(xen_debug_port, c);
}

static VOID
SendMessageToXen(IN PCHAR msg)
{
    CHAR c;

    while ((c = *msg++) != '\0')
        PutCharToXen(c);
}

static VOID
PutCharToDom0(
    IN CHAR c
    )
{
    if (!dom0_debug_port)
        return;

    WRITE_PORT_UCHAR(dom0_debug_port, c);
}

static VOID
SendMessageToDom0(IN PCHAR msg)
{
    CHAR c;

    while ((c = *msg++) != '\0')
        PutCharToDom0(c);
}

static WPP_TRACE WppTrace;

static VOID
SendMessageToWpp(
    IN  XEN_TRACE_LEVEL Level,
    IN  CHAR            *Message)
{
    if (WppTrace != NULL)
        WppTrace(Level, Message);
}

static BOOLEAN XenLogToKdDisabled;

BOOLEAN
XenDbgDisableKdLog(
    IN  BOOLEAN disable
    )
{
    BOOLEAN old = XenLogToKdDisabled;
    XenLogToKdDisabled = disable;
    return old;
}

VOID
SetWppTrace(
    IN  WPP_TRACE Function
    )
{
    WppTrace = Function;
}

VDBG_PRINT_EX __XenvDbgPrintEx;

ULONG
__XenDbgPrint(
    IN PCHAR Format,
    ...
    )
{
    va_list Arguments;
    ULONG Code;

    va_start(Arguments, Format);
    Code = __XenvDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, Format, Arguments);
    va_end(Arguments);

    return Code;
}

DBG_PRINT XenDbgPrint = DbgPrint;

extern BOOLEAN
haveDebugPrintCallback;

#define MODULE_COL_WIDTH 8
void
___XenTrace(XEN_TRACE_LEVEL level, __in_ecount(module_size) PCSTR module,
            size_t module_size, PCSTR fmt, va_list args)
{
    /* 256 is about the upper end of what can safely be allocated on
       the stack. */
    char buf[256];
    char *msg;
    static struct irqsafe_lock lock;
    int Disposition;
    KIRQL irql = PASSIVE_LEVEL;

    if (!XenTraceDispositions[level])
        return;

    memset(buf, 0, sizeof (buf));

    msg = buf;
    if (level != XenTraceLevelInternal) {
        char *prefix;
        size_t prefix_size;

        if (module_size < MODULE_COL_WIDTH) {
            size_t blank_size;

            blank_size = MODULE_COL_WIDTH - module_size;
            memset(msg, ' ', blank_size);
            msg += blank_size;
        }

        memcpy(msg, module, module_size);
        msg += module_size;

        *msg++ = ':';
        *msg++ = ' ';

#define _DEFINE_PREFIX(_prefix)                 \
        {                                       \
            prefix = _prefix;                   \
            prefix_size = sizeof (_prefix) - 1; \
        }

        if (level == XenTraceLevelWarning) {
            _DEFINE_PREFIX("WARNING");
        } else if (level == XenTraceLevelError) {
            _DEFINE_PREFIX("ERROR");
        } else if (level == XenTraceLevelCritical) {
            _DEFINE_PREFIX("CRITICAL");
        } else if (level == XenTraceLevelBugCheck) {
            _DEFINE_PREFIX("BUG: ");
        } else {
            _DEFINE_PREFIX("");
        }

        if (prefix_size != 0) {
            memcpy(msg, prefix, prefix_size);
            msg += prefix_size;

            *msg++ = ':';
            *msg++ = ' ';
        }
    }
    Xmvsnprintf(msg, sizeof (buf) - (msg - buf), fmt, args);

    // Make sure the buffer is NUL terminated before we pass it on
    buf[sizeof(buf) - 1] = 0;

    Disposition = XenTraceDispositions[level];

#if DBG
    if ( (XenTraceDispositions[level] & XENTRACE_KD) &&
         (XenLogToKdDisabled == FALSE) ) {
        // If we've hooked the DbgPrint callback then any intenal logging
        // levels will be taken care of so remove them to prevent duplicate
        // logging, otherwise we need to add them in.
        if (haveDebugPrintCallback)
            Disposition &= ~XenTraceDispositions[XenTraceLevelInternal];
        else
            Disposition |= XenTraceDispositions[XenTraceLevelInternal];

        XenDbgPrint("%s", buf);
    }
#endif

    irql = acquire_irqsafe_lock(&lock);

    if ( Disposition & XENTRACE_XEN ) {
        SendMessageToXen(buf);
    }

    if ( Disposition & XENTRACE_LOG ) {
        SendMessageToRing(buf);
    }

    if ( (Disposition & XENTRACE_DOM0) &&
         dom0_debug_port > 0 ) {
        SendMessageToDom0(buf);
    }

    release_irqsafe_lock(&lock, irql);

    // Assume the OS handles synchronization for the following
    // two.

    if ( Disposition & XENTRACE_WPP ) {
        SendMessageToWpp(level, buf);
    }

    if ( Disposition & XENTRACE_BUGCHECK ) {
        KeBugCheckEx(XM_BUGCHECK_CODE(_TRACE), 0, (ULONG_PTR)buf, 0, 0);
    }
}

void
XenTraceSetMtcLevels(void)
{
    int x;

    XM_ASSERT(XenPVFeatureEnabled(DEBUG_MTC_PROTECTED_VM));

    // Remove any trace levels that may cause divergence
    for (x = 0; x <= XenTraceLevelInternal; x++)
        XenTraceDispositions[x] &= ~(XENTRACE_WPP|XENTRACE_LOG|XENTRACE_KD);
}

void
XenTraceSetLevels(const int *levels)
{
    int x;

    for (x = 0; x < XenTraceLevels; x++)
        XenTraceDispositions[x] = levels[x] & ~XENTRACE_BUGCHECK;
}

void
XenTraceSetBugcheckLevels(void)
{
    int x;

    for (x = 0; x < XenTraceLevels; x++)
        XenTraceDispositions[x] = XENTRACE_LOG|XENTRACE_XEN|XENTRACE_DOM0;
}

ULONG
HvmGetLogRingSize(void)
{
    if (LogMessageBufferPtr >= LOG_MSG_BUFFER_SIZE)
        return LOG_MSG_BUFFER_SIZE;
    else
        return LogMessageBufferPtr;
}

NTSTATUS
HvmGetLogRing(void *buffer, ULONG size)
{
    ULONG ptr;
    ptr = LogMessageBufferPtr;
    if (ptr > LOG_MSG_BUFFER_SIZE) {
        if (size != LOG_MSG_BUFFER_SIZE) {
            return STATUS_INVALID_USER_BUFFER;
        } else {
            ptr %= LOG_MSG_BUFFER_SIZE;
            memcpy(buffer, LogMessageBuffer + ptr, LOG_MSG_BUFFER_SIZE - ptr);
            memcpy((void *)((ULONG_PTR)buffer + LOG_MSG_BUFFER_SIZE - ptr),
                   LogMessageBuffer, ptr);
            return STATUS_SUCCESS;
        }
    } else {
        if (size != ptr) {
            return STATUS_INVALID_USER_BUFFER;
        } else {
            memcpy(buffer, LogMessageBuffer, ptr);
            return STATUS_SUCCESS;
        }
    }
}

/* Extract the last @max_size bytes from the log and copy them to
   @outbuf.  Returns the number of bytes copied. */
ULONG
XmExtractTailOfLog(char *outbuf, ULONG max_size)
{
    ULONG end, start;

    if (max_size > LOG_MSG_BUFFER_SIZE)
        max_size = LOG_MSG_BUFFER_SIZE;
    end = LogMessageBufferPtr;
    if (end > max_size) {
        start = end - max_size;
    } else {
        start = 0;
    }
    if (start / LOG_MSG_BUFFER_SIZE == end / LOG_MSG_BUFFER_SIZE) {
        memcpy(outbuf, LogMessageBuffer + (start % LOG_MSG_BUFFER_SIZE),
               end - start);
    } else {
        memcpy(outbuf, LogMessageBuffer + (start % LOG_MSG_BUFFER_SIZE),
               LOG_MSG_BUFFER_SIZE - (start % LOG_MSG_BUFFER_SIZE));
        memcpy(outbuf + LOG_MSG_BUFFER_SIZE - (start % LOG_MSG_BUFFER_SIZE),
               LogMessageBuffer,
               end % LOG_MSG_BUFFER_SIZE);
    }
    return end - start;
}

/* Dump the entire debug log ring to dom0 if possible. */
void
XenTraceFlush(void)
{
    unsigned x;
    ULONG ptr = LogMessageBufferPtr;

    SendMessageToXen("Log messages:\n");
    SendMessageToDom0("Log messages:\n");

    for (x = ptr; x < ptr + LOG_MSG_BUFFER_SIZE; x++) {
        if (LogMessageBuffer[x % LOG_MSG_BUFFER_SIZE] != '\0') {
            PutCharToXen(LogMessageBuffer[x % LOG_MSG_BUFFER_SIZE]);
            PutCharToDom0(LogMessageBuffer[x % LOG_MSG_BUFFER_SIZE]);
        }
    }

    SendMessageToXen("\n");
    SendMessageToDom0("\n");
}
