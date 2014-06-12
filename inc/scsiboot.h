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

/* Various wrappers so that we can share code between ordinary xenvbd
   and ntbootdd.sys xenvbd */
/* Note that the ntbootdd versions of these functions are often much
   less functional than the normal version.  In particular, WaitEvent
   always returns timeout and InsertQueueDpc runs the DPC immediately
   rather than deferring to anything.  It happens that this is the
   correct behaviour for all of the code which currently uses these
   wrappers. */
/* (Remember that you can't reschedule from ntbootdd) */
#ifndef SCSIBOOT_H__
#define SCSIBOOT_H__

#include <stdarg.h>

#include "verinfo.h"
#include "xscompat.h"

ULONG GetOperatingMode(VOID);
VOID SetOperatingMode(ULONG x);

#define NORMAL_MODE 0
#define HIBER_MODE 1
#define DUMP_MODE 2

#define AustereMode (GetOperatingMode() != NORMAL_MODE)

void XmRecoverFromS3(void);
void XmPrepForS3(void);

BOOLEAN CheckXenHypervisor(void);
VOID XenCpuid(ULONG leaf, ULONG *peax, ULONG *pebx, ULONG *pecx,
            ULONG *pedx);
VOID _cpuid(ULONG leaf, ULONG *peax, ULONG *pebx, ULONG *pecx,
            ULONG *pedx);
void XenTraceFlush(void);
void XenTraceSetLevels(const int *levels);
void XenTraceSetBugcheckLevels();

extern BOOLEAN haveDebugPrintCallback;

ULONG HvmGetLogRingSize(void);
NTSTATUS HvmGetLogRing(void *buffer, ULONG size);
ULONG XmExtractTailOfLog(char *outbuf, ULONG max_size);
void UnplugIoemu(void);
struct _OSVERSIONINFOEXW;
VOID XenutilGetVersionInfo(struct _OSVERSIONINFOEXW *out);

//
// XC-4394
//
// The following sttruct and function declaration are used by xenvbd
// when entering hibernate (and probably crash dump file generation).
// We must detect Win7 SP1 so we can avoid a problem in SCSIPORT
// that was introduced with SP1.
//
typedef struct _XEN_WINDOWS_VERSION {
    ULONG dwMajorVersion;
    ULONG dwMinorVersion;
    ULONG dwBuildNumber;
    ULONG dwPlatformId;
    USHORT wServicePackMajor;
    USHORT wServicePackMinor;
} XEN_WINDOWS_VERSION,*PXEN_WINDOWS_VERSION;

VOID XenutilGetOsVersionDuringAustere(PXEN_WINDOWS_VERSION WinVer);

/**********************************************************************/
/* Memory allocation functions */
PVOID _XmAllocateMemory(size_t size, const char *caller);
PVOID _XmAllocateZeroedMemory(size_t size, const char *caller);

/* Allocate x bytes of non-paged pool.  Guaranteed to be page aligned
   if x >= PAGE_SIZE. */
#define XmAllocateMemory(x) _XmAllocateMemory((x), __FUNCTION__)

/* Like XmAllocateMemory(), but zero the memory on success. */
#define XmAllocateZeroedMemory(x) _XmAllocateZeroedMemory((x), __FUNCTION__)

/* Like XmAllocateMemory, but also return the physical address of the
   memory. */
PVOID XmAllocatePhysMemory(size_t size, PHYSICAL_ADDRESS *pa);
/* XmFreeMemory(x) releases memory obtained via XmAllocateMemory or
   XmAllocatePhysMemory. */
VOID XmFreeMemory(PVOID ptr);


/*********************************************************************/
/* Standard debug support functions */

#define XM_BUGCHECK_SIGNATURE   'X'

#define XM_BUGCHECK_TYPE_TRACE      0x00
#define XM_BUGCHECK_TYPE_ASSERT     0x01
#define XM_BUGCHECK_TYPE_ASSERT3U   0x02
#define XM_BUGCHECK_TYPE_ASSERT3S   0x03
#define XM_BUGCHECK_TYPE_ASSERT3P   0x04

#define XM_BUGCHECK_CODE(_type)                     \
        (((ULONG)XM_BUGCHECK_SIGNATURE     << 24) | \
         ((ULONG)XM_BUGCHECK_TYPE ## _type << 16))

#define XM_ASSERT(_expr)                                    \
do {                                                        \
    if (!(_expr)) {                                         \
        const char *file = __FILE__;                        \
        USHORT line = __LINE__;                             \
        const char *expr = #_expr;                          \
                                                            \
        TraceInternal(("XM_ASSERT: %s at %s:%d\n",          \
                       expr, file, line));                  \
        KeBugCheckEx(XM_BUGCHECK_CODE(_ASSERT) | line,      \
                     (ULONG_PTR)file,                       \
                     (ULONG_PTR)expr,                       \
                     0,                                     \
                     0);                                    \
    }                                                       \
} while (FALSE)

#define XM_BUG()  XM_ASSERT(FALSE);

#define XM_ASSERT3U(_x, _op, _y)                            \
do {                                                        \
    ULONG_PTR lval = (ULONG_PTR)(_x);                       \
    ULONG_PTR rval = (ULONG_PTR)(_y);                       \
                                                            \
    if (!(lval _op rval)) {                                 \
        const char *file = __FILE__;                        \
        USHORT line = __LINE__;                             \
        const char *expr = #_x " " #_op " " #_y;            \
                                                            \
        TraceInternal(("XM_ASSERT: %s at %s:%d "            \
                       "(LVAL=%lu RVAL=%lu)\n",             \
                       expr, file, line,                    \
                       lval, rval));                        \
        KeBugCheckEx(XM_BUGCHECK_CODE(_ASSERT3U) | line,    \
                     (ULONG_PTR)file,                       \
                     (ULONG_PTR)expr,                       \
                     lval,                                  \
                     rval);                                 \
    }                                                       \
} while (FALSE)

#define XM_ASSERT3S(_x, _op, _y)                            \
do {                                                        \
    LONG_PTR lval = (LONG_PTR)(_x);                         \
    LONG_PTR rval = (LONG_PTR)(_y);                         \
                                                            \
    if (!(lval _op rval)) {                                 \
        const char *file = __FILE__;                        \
        USHORT line = __LINE__;                             \
        const char *expr = #_x " " #_op " " #_y;            \
                                                            \
        TraceInternal(("XM_ASSERT: %s at %s:%d "            \
                       "(LVAL=%ld RVAL=%ld)\n",             \
                       expr, file, line,                    \
                       lval, rval));                        \
        KeBugCheckEx(XM_BUGCHECK_CODE(_ASSERT3S) | line,    \
                     (ULONG_PTR)file,                       \
                     (ULONG_PTR)expr,                       \
                     (ULONG_PTR)lval,                       \
                     (ULONG_PTR)rval);                      \
    }                                                       \
} while (FALSE)

#pragma warning(disable:4054)

#define XM_ASSERT3P(_x, _op, _y)                            \
do {                                                        \
    UCHAR *lval = (PVOID)(_x);                              \
    UCHAR *rval = (PVOID)(_y);                              \
                                                            \
    if (!(lval _op rval)) {                                 \
        const char *file = __FILE__;                        \
        USHORT line = __LINE__;                             \
        const char *expr = #_x " " #_op " " #_y;            \
                                                            \
        TraceInternal(("XM_ASSERT: %s at %s:%d "            \
                       "(LVAL=0x%p RVAL=0x%p)\n",           \
                       expr, file, line,                    \
                       lval, rval));                        \
        KeBugCheckEx(XM_BUGCHECK_CODE(_ASSERT3S) | line,    \
                     (ULONG_PTR)file,                       \
                     (ULONG_PTR)expr,                       \
                     (ULONG_PTR)lval,                       \
                     (ULONG_PTR)rval);                      \
    }                                                       \
} while (FALSE)

/* Silly little trick for checking that certain conditions hold at
   compile time.  CASSERT(x) -> compile error if x is not a positive
   integer constant. */
#define CASSERT(_expr) typedef unsigned __cassert ## __LINE__ [(_expr)]

#define IMPLY(_x, _y)   (!(_x) || (_y))
#define EQUIV(_x, _y)   (IMPLY((_x), (_y)) && IMPLY((_y), (_x)))

/********************************************************************/
/* String manipulation functions */

size_t Xmvsnprintf(char *buf, size_t size, const char *fmt,
                   va_list args);
size_t Xmsnprintf(char *buf, size_t size, const char *fmt, ...);
char *Xmasprintf(const char *fmt, ...);
char *Xmvasprintf(const char *fmt, va_list args);

/* Locks which can be acquired from interrupt context. */
struct irqsafe_lock {
    LONG lock;
};

static __inline KIRQL
acquire_irqsafe_lock(struct irqsafe_lock *l)
{
    KIRQL irql;

    KeRaiseIrql(HIGH_LEVEL, &irql);

    while (InterlockedCompareExchange(&l->lock, 1, 0) != 0)
        _mm_pause();
    _ReadWriteBarrier();
    return irql;
}

static __inline VOID
release_irqsafe_lock(struct irqsafe_lock *l, KIRQL irql)
{
    _ReadWriteBarrier();
    InterlockedExchange(&l->lock, 0);
    KeLowerIrql(irql);
}

static __inline NTSTATUS
try_acquire_irqsafe_lock(struct irqsafe_lock *l, KIRQL *pirql)
{
    KIRQL irql;

    KeRaiseIrql(HIGH_LEVEL, &irql);

    if (InterlockedCompareExchange(&l->lock, 1, 0) == 0) {
        _ReadWriteBarrier();
        *pirql = irql;
        return STATUS_SUCCESS;
    }
    KeLowerIrql(irql);
    return STATUS_UNSUCCESSFUL;
}

/* The same, but multi-reader-single-writer, no bias */
struct xm_mrsw_irqsafe_lock {
#define XM_MRSW_WRITER_HELD 0x80000000
    /* Either a small +ve count of the number of readers, or
       XM_MRSW_WRITER_HELD. */
    volatile LONG lock;
};

static __inline VOID
acquire_mrsw_read(struct xm_mrsw_irqsafe_lock *l, KIRQL *irql)
{
    LONG lock;
    KeRaiseIrql(HIGH_LEVEL, irql);
    while (1) {
        lock = l->lock;
        if (lock & XM_MRSW_WRITER_HELD) {
            _mm_pause();
            continue;
        }
        if (InterlockedCompareExchange(&l->lock, lock + 1, lock) == lock)
            break;
    }
}

static __inline VOID
release_mrsw_read(struct xm_mrsw_irqsafe_lock *l, KIRQL irql)
{
    _ReadWriteBarrier();
    XM_ASSERT(l->lock);
    XM_ASSERT(!(l->lock & XM_MRSW_WRITER_HELD));
    InterlockedDecrement(&l->lock);
    KeLowerIrql(irql);
}

static __inline VOID
acquire_mrsw_write(struct xm_mrsw_irqsafe_lock *l, KIRQL *irql)
{
    while (l->lock)
        _mm_pause();
    KeRaiseIrql(HIGH_LEVEL, irql);
    while (1) {
        if (l->lock != 0) {
            _mm_pause();
            continue;
        }
        if (InterlockedCompareExchange(&l->lock, XM_MRSW_WRITER_HELD, 0) == 0)
            break;
    }
}

static __inline VOID
release_mrsw_write(struct xm_mrsw_irqsafe_lock *l, KIRQL irql)
{
    LONG t;

    /* InterlockedAnd() is in a different header to
     * InterlockedCompareExchange(), and I couldn't get them to both
     * be available in xenvbd.  Just use cmpx instead; it's not like
     * this is a hot path or anything. */
    t = InterlockedCompareExchange(&l->lock, 0, XM_MRSW_WRITER_HELD);
    XM_ASSERT3U(t, ==, XM_MRSW_WRITER_HELD);
    KeLowerIrql(irql);
}

static __inline NTSTATUS
try_acquire_mrsw_read(struct xm_mrsw_irqsafe_lock *l, KIRQL *pirql)
{
    KIRQL irql;
    LONG lock;
    KeRaiseIrql(HIGH_LEVEL, &irql);
    while (1) {
        lock = l->lock;
        if (lock & XM_MRSW_WRITER_HELD) {
            KeLowerIrql(irql);
            return STATUS_UNSUCCESSFUL;
        }
        if (InterlockedCompareExchange(&l->lock, lock + 1, lock) == lock) {
            *pirql = irql;
            return STATUS_SUCCESS;
        }
    }
}

/* Slightly easier-to-work-with abstraction around
 * PsCreateSystemThread */
struct xm_thread {
    BOOLEAN exit; /* TRUE if the thread should exit soon */
    KEVENT event; /* signalled whenever there's work for the thread to
                     do or when exit becomes TRUE */
    PKTHREAD thread;
    NTSTATUS (*cb)(struct xm_thread *st, void *data);
    void *data;
};

/* create a new thread, invoking cb(thread, @d) in it.  Calls
 * PsTerminateThread() automatically using the return value of @cb.
 * Returns NULL on error.
 */
struct xm_thread *XmSpawnThread(NTSTATUS (*cb)(struct xm_thread *,void*),
                                void *d);
/* Tell a thread to exit, wait for it to do so, and then release all
 * associated resources.  No-op if invoked on NULL. */
void XmKillThread(struct xm_thread *t);
/* Wait on the thread's event and then clear it.  Returns -1 if the
   thread should exit and 0 otherwise.  Intended to be called from the
   thread's main loop. */
int XmThreadWait(struct xm_thread *t);

/* A few functions for manipulating linked lists. */

/* Make the list anchored at @sublist appear at the end of the list
   anchored at @list.  @sublist itself does not appear in the new
   list.  @sublist is not a valid list when this returns. */
static __inline void
XmListSplice(PLIST_ENTRY list, PLIST_ENTRY sublist)
{
    PLIST_ENTRY sub_first, sub_last;

    if (IsListEmpty(sublist)) {
        /* sublist is empty -> nothing to do */
        return;
    }

    sub_first = sublist->Flink;
    sub_last = sublist->Blink;

    list->Blink->Flink = sub_first;
    sub_first->Blink = list->Blink;
    list->Blink = sub_last;
    sub_last->Flink = list;
}

/* Take all of the list elements in @src and move them to @dest.  @src
   is reinitialised as an empty list. */
static __inline void
XmListTransplant(PLIST_ENTRY dest, PLIST_ENTRY src)
{
    InitializeListHead(dest);
    XmListSplice(dest, src);
    InitializeListHead(src);
}

/*****************************************************************?
/* Private xenbus API
 */

const char  *XenbusStateName(XENBUS_STATE State);

/*****************************************************************/
/* Work item interface.
 */

typedef VOID    (*XEN_WORK_CALLBACK)(VOID *);

extern XSAPI NTSTATUS       _XenQueueWork(const CHAR *Caller,
                                          const CHAR *Name,
                                          XEN_WORK_CALLBACK Work,
                                          VOID *Context);

#define XenQueueWork(_Work, _Context)   \
        _XenQueueWork(__FUNCTION__,     \
                      #_Work,           \
                      (_Work),          \
                      (_Context))

/*****************************************************************/
/* Version checking.  We don't support running with mixed versions of
 * the drivers, but we can at least make the failure
 * comprehensible. */
#define XENUTIL_CURRENT_VERSION     VER_VERSION_STRING

BOOLEAN    _XmCheckXenutilVersionString(
    IN  const CHAR  *Driver,
    IN  BOOLEAN     Critical,
    IN  const CHAR  *ExpectedVersion
    );

#define XmCheckXenutilVersionString(_Critical, _ExpectedVersion) \
        _XmCheckXenutilVersionString(XENTARGET, (_Critical), (_ExpectedVersion))

/*****************************************************************/
/* Feature flags, controlled through boot.ini */
#define DEBUG_NO_PARAVIRT               0x00000001
#define DEBUG_UNUSED1                   0x00000002  // DEBUG_PATCH_PIT (removed in 4.2)             
#define DEBUG_UNUSED2                   0x00000004  // DEBUG_PATCH_CIRRUS (removed in 4.2)            
#define DEBUG_PATCH_BLUESCREEN          0x00000008
#define DEBUG_UNUSED3                   0x00000010  // DEBUG_DUMP_DEVICE_DOM0 (removed in 5.6)
#define DEBUG_UNUSED4                   0x00000020  // DEBUG_PATCH_HIBERNATE (removed in 4.2)
#define DEBUG_PATCH_APIC                0x00000040
#define DEBUG_NIC_FAST_AND_LOOSE        0x00000080
#define DEBUG_VERY_LOUD                 0x00000100
#define DEBUG_BALLOON                   0x00000200
#define DEBUG_VERY_QUIET                0x00000400
#define DEBUG_PATCH_TLB_FLUSH           0x00000800
#define DEBUG_PATCH_SPINLOCKS           0x00001000
#define DEBUG_FAKE_NETIF                0x00002000
#define DEBUG_NIC_8021_P                0x00004000  // xennet6 only
#define DEBUG_PATCH_KD_POLL             0x00008000
#define DEBUG_NIC_NO_TSO                0x00010000
#define DEBUG_NIC_NO_DMA                0x00020000
#define DEBUG_FORCE_EARLY_UNPLUG        0x00040000
#define DEBUG_PATCH_2K_IDLE_DELAY       0x00080000
#define DEBUG_HA_SAFEMODE               0x00100000  // xevtchn.sys loads in safe mode but no xennet or xenvbd.
#define DEBUG_BOOT_EMULATED             0x00200000  // Use an emulated c:
#define DEBUG_HCT_DP_HACKS              0x00400000  // Stupid HCT DP test hacks
#define DEBUG_TRACE_PROCESS_CREATE      0x00800000  // Traces PID and CR3 for a new process.
#define DEBUG_TRACE_IMAGE_LOAD          0x01000000  // Traces process name and PID on executable load.
#define DEBUG_INTERNAL_XENNET           0x02000000  // Report xennet on INTERNAL bus.
#define DEBUG_TRAP_DBGPRINT             0x04000000  // Try to trap calls to DbgPrint()
#define DEBUG_HCT_MODE                  0x08000000  // Lots of stupid HCT hacks
#define DEBUG_DISABLE_LICENSE_CHECK     0x10000000  // Don't check for the magic copyright string.
#define DEBUG_NIC_EMULATED              0x20000000  // Use emulated NICs
#define DEBUG_MTC_PROTECTED_VM          0x40000000  // Tells PV drivers this is a Marathon-protected VM.

BOOLEAN 
XenPVFeatureEnabled(
    ULONG FeatureFlag
    );

extern VOID XenevtchnSetDeviceUsage(
    IN  DEVICE_USAGE_NOTIFICATION_TYPE  Type,
    IN  BOOLEAN                         On
    );

#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#endif

#endif /* SCSIBOOT_H__ */
