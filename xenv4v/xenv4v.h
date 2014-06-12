/*
 * Copyright (c) 2013 Citrix Systems, Inc.
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

#if !defined(_XENV4V_H_)
#define _XENV4V_H_

#pragma warning(disable: 4127) // conditional expression is constant
#pragma warning(disable: 4201)

#include "xsapi.h"
#include "v4vapi.h"
#include "../xenutil/hypercall.h"
#include "../xenutil/evtchn.h"
#include "xen_types.h"

#define XENV4V_TAG 'v4vx'

// Allow for clients using the older DOMID_INVALID value
#define DOMID_INVALID_COMPAT (0x7FFFU)

#define XENV4V_ADDR_COMPARE(a, b) ((a.port == b.port)&&(a.domain == b.domain))
#define XENV4V_LARGEINT_DELAY(ms) (ULONG64) -(10000 * ((LONG32) (ms)))
#define XENV4V_SET_BOOL_PTR(b) if (b != NULL) {*b = TRUE;}
#define XENV4V_CLEAR_BOOL_PTR(b) if (b != NULL) {*b = FALSE;}

//#define XENV4V_NO_PROTOCOL_CHECK
#if defined(XENV4V_NO_PROTOCOL_CHECK) && defined(DBG)
#define XENV4V_PROTOCOL_TEST(p, v) (TRUE)
#else
#define XENV4V_PROTOCOL_TEST(p, v) (p == v)
#endif

//#define XENV4V_ENABLE_RWTRACE
#if defined(XENV4V_ENABLE_RWTRACE) && defined(DBG)
#define TraceReadWrite(_X_) __XenTraceVerbose _X_ 
#else
#define TraceReadWrite(_X_)
#endif

#define XENV4V_WRITE_RO_PROTECT

// Structure used both to form a list of IRPs for the same destination and
// to store a destination record for each IRP. The same struc is used so
// that it can be pulled for both purposes from the same lookaside list.
typedef struct _XENV4V_DESTINATION {
    LIST_ENTRY le;
    ULONG32    refc;
    ULONG      nextLength;
    PIRP       nextIrp;
    v4v_addr_t dst;    
} XENV4V_DESTINATION, *PXENV4V_DESTINATION;

#define XENV4V_MAGIC          0x228e471d
#define XENV4V_SYM_NAME_LEN   64
#define XENV4V_MAX_IRP_COUNT  65536
#define XENV4V_TIMER_INTERVAL 1000 // ms

#define XENV4V_DEV_STOPPED   0x00000000
#define XENV4V_DEV_STARTED   0x00000001

typedef struct _XENV4V_EXTENSION {
    ULONG magic;

    // Our fdo
    PDEVICE_OBJECT fdo;

    // Underlying physical device
    PDEVICE_OBJECT pdo;

    // Lower device - same as pdo really
    PDEVICE_OBJECT ldo;

    UNICODE_STRING symbolicLink;
    wchar_t symbolicLinkText[XENV4V_SYM_NAME_LEN];

    IO_REMOVE_LOCK removeLock;

    // The xenstore path for this device
    PCHAR frontendPath;

    // The device state flag
    LONG  state;

    // The last power state seen
    SYSTEM_POWER_STATE lastPoState;

    // V4V interrupt
    EVTCHN_PORT virqPort;
    KDPC        virqDpc;
    KSPIN_LOCK  virqLock;
    KSPIN_LOCK  dpcLock;

    // Device Timer
    KTIMER      timer;
    KDPC        timerDpc;
    KSPIN_LOCK  timerLock;
    BOOLEAN     timerCounter;

    // Active file context list
    LIST_ENTRY contextList;
    KSPIN_LOCK contextLock;
    LONG       contextCount;

    // Active ring object list
    LIST_ENTRY ringList;
    KSPIN_LOCK ringLock;

    // IRP queuing and cancel safe queues
    LIST_ENTRY pendingIrpQueue;
    LONG       pendingIrpCount;
    KSPIN_LOCK queueLock;
    IO_CSQ     csqObject;
    LIST_ENTRY destList;
    LONG       destCount;
    NPAGED_LOOKASIDE_LIST destLookasideList;

    // Seed for generating random-ish numbers for ports and conids
    ULONG seed;

} XENV4V_EXTENSION, *PXENV4V_EXTENSION;

#define XENV4V_RING_MULT 16

typedef struct _XENV4V_RING {
    // List and ref
    LIST_ENTRY le;
    ULONG32    refc;

    // Ring bits
    v4v_ring_t     *ring;
    v4v_pfn_list_t *pfnList;
    KSPIN_LOCK      lock;

    BOOLEAN registered;
    ULONG32 queueLength;
} XENV4V_RING, *PXENV4V_RING;

#define XENV4V_INVALID_CONNID      0xffffffffffffffff

#define XENV4V_STATE_UNINITIALIZED 0x00000000
#define XENV4V_STATE_IDLE          0x00000001
#define XENV4V_STATE_BOUND         0x00000002
#define XENV4V_STATE_LISTENING     0x00000010
#define XENV4V_STATE_CONNECTING    0x00000020
#define XENV4V_STATE_WAITING       0x00000040
#define XENV4V_STATE_ACCEPTING     0x00000080
#define XENV4V_STATE_CONNECTED     0x00000100
#define XENV4V_STATE_ACCEPTED      0x00000200
#define XENV4V_STATE_DISCONNECTED  0x00000400
#define XENV4V_STATE_PASSIVE       0x00000800
#define XENV4V_STATE_CLOSED        0x00001000

#define XENV4V_TYPE_UNSPECIFIED  0x00000000
#define XENV4V_TYPE_DATAGRAM     0x00000001
#define XENV4V_TYPE_LISTENER     0x00000010
#define XENV4V_TYPE_CONNECTOR    0x00000020
#define XENV4V_TYPE_ACCEPTER     0x00000040

#define XENV4V_FILE_TYPE_STREAM  (XENV4V_TYPE_LISTENER|XENV4V_TYPE_CONNECTOR|XENV4V_TYPE_ACCEPTER)

typedef struct _XENV4V_SYN {
    struct _XENV4V_SYN *next;
    struct _XENV4V_SYN *last;
    BOOLEAN             pending;
    v4v_addr_t          sdst;
    ULONG64             connId;
} XENV4V_SYN, *PXENV4V_SYN;

typedef struct _XENV4V_DATA {
    struct _XENV4V_DATA *next;
    UCHAR               *data;
    uint32_t             length;
} XENV4V_DATA, *PXENV4V_DATA;

typedef struct _XENV4V_CONTEXT {
    // List and ref
    LIST_ENTRY le;
    ULONG32    refc;

    // State and type
    LONG state;
    LONG type;

    // Ring pieces
    XENV4V_RING *ringObject;
    ULONG32      ringLength;

    // Event for user land receive notification
    KEVENT *kevReceive;

    // A backpointer to the owning file object
    FILE_OBJECT *pfoParent;

    // Stream types have a single dst setup at connect/accept time for
    // stream traffic (r/o after set).
    v4v_addr_t sdst;

    // A random-ish connection ID set once when we become a stream
    ULONG64 connId;

    // Safe place to point 0 length write buffer pointers w/ NULL MDLs
    UCHAR safe[4];

    // Context specific values
    union {
        struct {
            LONG        backlog;
            KSPIN_LOCK  synLock;
            XENV4V_SYN *synList;
            XENV4V_SYN *synHead;
            XENV4V_SYN *synTail;
            LONG        synCount;
        } listener;
        struct {
            struct _XENV4V_CONTEXT *listenerContext;
            KSPIN_LOCK              dataLock;
            XENV4V_DATA            *dataList;
            XENV4V_DATA            *dataTail;
        } accepter;
    } u;

} XENV4V_CONTEXT, *PXENV4V_CONTEXT;

typedef struct _XENV4V_CTRL_MSG {
    V4V_STREAM sh;    
} XENV4V_CTRL_MSG, *PXENV4V_CTRL_MSG;

#if defined(_WIN64)
#define XENV4V_RST_MAGIC 0x512862fb6f91f1bd
#else
#define XENV4V_RST_MAGIC 0x512862fb
#endif

typedef struct _XENV4V_RESET {    
    XENV4V_CTRL_MSG;    
    PIO_WORKITEM      pwi;
    XENV4V_EXTENSION *pde;
    FILE_OBJECT      *pfo;
    v4v_addr_t        dst;
} XENV4V_RESET, *PXENV4V_RESET;

#if defined(_WIN64)
#define XENV4V_ACK_MAGIC 0x9236baf013ce4bb9

#else
#define XENV4V_ACK_MAGIC 0x9236baf0
#endif

typedef struct _XENV4V_ACKNOWLEDGE {
    XENV4V_CTRL_MSG;
    PIO_WORKITEM      pwi;
    XENV4V_EXTENSION *pde;
    FILE_OBJECT      *pfo;
} XENV4V_ACKNOWLEDGE, *PXENV4V_ACKNOWLEDGE;

// The queue peek values are used to provide peek information for finding IRPs.
#define XENV4V_PEEK_DGRAM          0x00000001 // type
#define XENV4V_PEEK_STREAM         0x00000002 // type
#define XENV4V_PEEK_ANY_TYPE       0x0000ffff // type
#define XENV4V_PEEK_ACCEPT         0x00010000 // op
#define XENV4V_PEEK_SYN            0x00100000 // op
#define XENV4V_PEEK_ACK            0x00200000 // op
#define XENV4V_PEEK_RST            0x00400000 // op
#define XENV4V_PEEK_READ           0x01000000 // op
#define XENV4V_PEEK_WRITE          0x02000000 // op
#define XENV4V_PEEK_IOCTL          0x04000000 // op
#define XENV4V_PEEK_ANY_OP         0xffff0000 // op

typedef struct _XENV4V_QPEEK {
    FILE_OBJECT *pfo;
    ULONG_PTR    types;
    ULONG_PTR    ops;
    v4v_addr_t   dst;
} XENV4V_QPEEK, *PXENV4V_QPEEK;

#define XENV4V_PEEK_STREAM_FLAGS (XENV4V_PEEK_SYN|XENV4V_PEEK_ACK|XENV4V_PEEK_RST)

#define XENV4V_PAYLOAD_DATA_LEN(i, l) \
    if ((ULONG_PTR)i->Tail.Overlay.DriverContext[0] & XENV4V_PEEK_STREAM_FLAGS) \
        l = sizeof(V4V_STREAM); \
    else if ((ULONG_PTR)i->Tail.Overlay.DriverContext[0] & XENV4V_PEEK_STREAM) \
        l = (IoGetCurrentIrpStackLocation(i)->Parameters.Write.Length + sizeof(V4V_STREAM)); \
    else \
        l = (IoGetCurrentIrpStackLocation(i)->Parameters.Write.Length - sizeof(V4V_DATAGRAM));

typedef struct _XENV4V_INSERT {
    BOOLEAN insertHead;
} XENV4V_INSERT, *PXENV4V_INSERT;

// 32-bit thunk IOCTLs
#if defined(_WIN64)
typedef struct _V4V_INIT_VALUES_32 {
    VOID *POINTER_32 rxEvent;
    ULONG32 ringLength;
} V4V_INIT_VALUES_32, *PV4V_INIT_VALUES_32;

#define	V4V_IOCTL_INITIALIZE_32 CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_FUNC_INITIALIZE, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _V4V_ACCEPT_VALUES_32 {
    VOID *POINTER_32 fileHandle;
    VOID *POINTER_32 rxEvent;
    struct v4v_addr peerAddr;
    V4V_ACCEPT_PRIVATE priv;
} V4V_ACCEPT_VALUES_32, *PV4V_ACCEPT_VALUES_32;

#define	V4V_IOCTL_ACCEPT_32 CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_FUNC_ACCEPT, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

// Dispatch Routines
DRIVER_DISPATCH V4vDispatchCreate;
NTSTATUS NTAPI
V4vDispatchCreate(PDEVICE_OBJECT fdo, PIRP irp);

DRIVER_DISPATCH V4vDispatchCleanup;
NTSTATUS NTAPI
V4vDispatchCleanup(PDEVICE_OBJECT fdo, PIRP irp);

DRIVER_DISPATCH V4vDispatchClose;
NTSTATUS NTAPI
V4vDispatchClose(PDEVICE_OBJECT fdo, PIRP irp);

DRIVER_DISPATCH V4vDispatchDeviceControl;
NTSTATUS NTAPI
V4vDispatchDeviceControl(PDEVICE_OBJECT fdo, PIRP irp);

DRIVER_DISPATCH V4vDispatchRead;
NTSTATUS NTAPI
V4vDispatchRead(PDEVICE_OBJECT fdo, PIRP irp);

DRIVER_DISPATCH V4vDispatchWrite;
NTSTATUS NTAPI
V4vDispatchWrite(PDEVICE_OBJECT fdo, PIRP irp);

// Cancel Safe Queue Routines
NTSTATUS NTAPI
V4vCsqInsertIrpEx(PIO_CSQ csq, PIRP irp, PVOID insertContext);

VOID NTAPI
V4vCsqRemoveIrp(PIO_CSQ csq, PIRP irp);

PIRP NTAPI
V4vCsqPeekNextIrp(PIO_CSQ csq, PIRP irp, PVOID peekContext);

VOID NTAPI
V4vCsqAcquireLock(PIO_CSQ csq, PKIRQL irqlOut);

VOID NTAPI
V4vCsqReleaseLock(PIO_CSQ csq, KIRQL irql);

VOID NTAPI
V4vCsqCompleteCanceledIrp(PIO_CSQ csq, PIRP irp);

v4v_ring_data_t*
V4vCopyDestinationRingData(XENV4V_EXTENSION *pde);

VOID
V4vCancelAllFileIrps(XENV4V_EXTENSION *pde, FILE_OBJECT *pfo);

// Read/Write Routines
VOID
V4vFlushAccepterQueueData(XENV4V_CONTEXT *ctx);

VOID
V4vDisconnectStreamAndSignal(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx);

ULONG
V4vGetAcceptPrivate(ULONG code, VOID *buffer, V4V_ACCEPT_PRIVATE **ppriv, struct v4v_addr **ppeer);

VOID
V4vDoAccepts(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx);

VOID
V4vProcessNotify(XENV4V_EXTENSION *pde);

VOID
V4vProcessContextWrites(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx);

VOID
V4vProcessContextReads(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx);

// Send routines

VOID
V4vSendReset(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx, uint32_t connId, v4v_addr_t *dst, BOOLEAN noq);

NTSTATUS
V4vSendAcknowledge(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx);

// Hypercall Interface
NTSTATUS
V4vRegisterRing(XENV4V_RING *robj);

NTSTATUS
V4vUnregisterRing(XENV4V_RING *robj);

NTSTATUS
V4vNotify(v4v_ring_data_t *ringData);

NTSTATUS
V4vSend(v4v_addr_t *src, v4v_addr_t *dest, ULONG32 protocol, VOID *buf, ULONG32 length, ULONG32 *writtenOut);

NTSTATUS
V4vSendVec(v4v_addr_t *src, v4v_addr_t *dest, v4v_iov_t *iovec, ULONG32 nent, ULONG32 protocol, ULONG32 *writtenOut);

// Ring Routines
XENV4V_RING*
V4vAllocateRing(uint32_t ringLength);

VOID
V4vLinkToRingList(XENV4V_EXTENSION *pde, XENV4V_RING *robj);

ULONG32
V4vAddRefRing(XENV4V_EXTENSION *pde, XENV4V_RING *robj);

ULONG32
V4vReleaseRing(XENV4V_EXTENSION *pde, XENV4V_RING *robj);

uint32_t
V4vRandomPort(XENV4V_EXTENSION *pde);

uint32_t
V4vSparePortNumber(XENV4V_EXTENSION *pde, uint32_t port);

BOOLEAN
V4vRingIdInUse(XENV4V_EXTENSION *pde, struct v4v_ring_id *id);

VOID
V4vRecoverRing(XENV4V_CONTEXT *ctx);

VOID
V4vDumpRing(v4v_ring_t *r);

// Context Routines
ULONG32
V4vAddRefContext(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx);

ULONG32
V4vReleaseContext(XENV4V_EXTENSION *pde, XENV4V_CONTEXT *ctx);

XENV4V_CONTEXT**
V4vGetAllContexts(XENV4V_EXTENSION *pde, ULONG *countOut);

VOID
V4vPutAllContexts(XENV4V_EXTENSION *pde, XENV4V_CONTEXT** ctxList, ULONG count);

XENV4V_CONTEXT*
V4vGetContextByConnectionId(XENV4V_EXTENSION *pde, ULONG64 connId);

// Timer Routines
VOID
V4vStartConnectionTimer(XENV4V_EXTENSION *pde);

VOID
V4vStopConnectionTimer(XENV4V_EXTENSION *pde, BOOLEAN immediate);

// Inlines
static __inline PXENV4V_EXTENSION
V4vGetDeviceExtension(PDEVICE_OBJECT fdo)
{
    PXENV4V_EXTENSION pde = (PXENV4V_EXTENSION)fdo->DeviceExtension;
    ASSERT(pde->magic == XENV4V_MAGIC);
    return pde;
}

static __inline PXENV4V_EXTENSION
V4vCsqGetDeviceExtension(PIO_CSQ csq)
{
    PXENV4V_EXTENSION pde = CONTAINING_RECORD(csq, XENV4V_EXTENSION, csqObject);
    ASSERT(pde->magic == XENV4V_MAGIC);
    return pde;
}

static __inline VOID
V4vInitializeIrp(PIRP irp)
{
    // Initialize the bits of the IRP we will use
    irp->Tail.Overlay.DriverContext[0] = NULL;
    irp->Tail.Overlay.DriverContext[1] = NULL;
    InitializeListHead(&irp->Tail.Overlay.ListEntry);
}

static __inline NTSTATUS
V4vSimpleCompleteIrp(PIRP irp, NTSTATUS status)
{
    irp->IoStatus.Information = 0;
    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

#endif /*_XENV4V_H_*/
