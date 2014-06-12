/*
 * Copyright (c) 2011 Citrix Systems, Inc.
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

#ifndef __V4VAPI_H__
#define __V4VAPI_H__

#if !defined(XENV4V_DRIVER)
#define V4V_EXCLUDE_INTERNAL
#endif
#include "v4v.h"

/* This structure is used for datagram reads and writes. When sending a 
 * datagram, extra space must be reserved at the front of the buffer to
 * format the @addr values in the following structure to indicate the 
 * destination address. When receiving data, the receive buffer should also
 * supply the extra head room for the source information that will be 
 * returned by V4V. The size of the send/receive should include the extra 
 * space for the datagram structure.
 */
#pragma pack(push, 1)
typedef struct _V4V_DATAGRAM {
    v4v_addr_t addr;
    /* data starts here */
} V4V_DATAGRAM, *PV4V_DATAGRAM;
#pragma pack(pop)

/* Typedef for internal stream header structure */
typedef struct v4v_stream_header V4V_STREAM, *PV4V_STREAM;

/* ========================== IOCTL Interface ============================= */
#define V4V_DRIVER_NAME    L"xenv4v"
#define V4V_DEVICE_NAME    L"\\Device\\xenv4v"
#define V4V_SYMBOLIC_NAME  L"\\DosDevices\\Global\\v4vdev"
#define V4V_USER_FILE_NAME L"\\\\.\\Global\\v4vdev"
#define V4V_BASE_FILE_NAME L"v4vdev"

#define V4V_SYS_FILENAME   L"%SystemRoot%\\system32\\drivers\\xenv4v.sys"

/* Default internal max backlog length for pending connections */
#define V4V_SOMAXCONN 128

typedef struct _V4V_INIT_VALUES {
    VOID *rxEvent;
    ULONG32 ringLength;
} V4V_INIT_VALUES, *PV4V_INIT_VALUES;

typedef struct _V4V_BIND_VALUES {
    struct v4v_ring_id ringId;
} V4V_BIND_VALUES, *PV4V_BIND_VALUES;

typedef struct _V4V_LISTEN_VALUES {
    ULONG32 backlog;
} V4V_LISTEN_VALUES, *PV4V_LISTEN_VALUES;

typedef union _V4V_ACCEPT_PRIVATE {
    struct {
        ULONG32 a;
        ULONG32 b;
    } d;
    struct {
        ULONG64 a;
    } q;
} V4V_ACCEPT_PRIVATE, *PV4V_ACCEPT_PRIVATE;

typedef struct _V4V_ACCEPT_VALUES {
    VOID *fileHandle;
    VOID *rxEvent;
    struct v4v_addr peerAddr;
    V4V_ACCEPT_PRIVATE priv;
} V4V_ACCEPT_VALUES, *PV4V_ACCEPT_VALUES;

typedef struct _V4V_CONNECT_VALUES {
    V4V_STREAM sh;
    struct v4v_addr ringAddr;
} V4V_CONNECT_VALUES, *PV4V_CONNECT_VALUES;

typedef struct _V4V_WAIT_VALUES {
    V4V_STREAM sh;
} V4V_WAIT_VALUES, *PV4V_WAIT_VALUES;

typedef enum _V4V_GETINFO_TYPE {
    V4vInfoUnset    = 0,
    V4vGetLocalInfo = 1,
    V4vGetPeerInfo  = 2
} V4V_GETINFO_TYPE, *PV4V_GETINFO_TYPE;

typedef struct _V4V_GETINFO_VALUES {
    V4V_GETINFO_TYPE type;
    struct v4v_ring_id ringInfo;  
} V4V_GETINFO_VALUES, *PV4V_GETINFO_VALUES;

#if defined(_WIN64)
#define V4V_64BIT 0x800
#else
#define V4V_64BIT 0x000
#endif

/* V4V I/O Control Function Codes */
#define V4V_FUNC_INITIALIZE 0x10
#define V4V_FUNC_BIND       0x11
#define V4V_FUNC_LISTEN     0x12
#define V4V_FUNC_ACCEPT     0x13
#define V4V_FUNC_CONNECT    0x14
#define V4V_FUNC_WAIT       0x15
#define V4V_FUNC_DISCONNECT 0x16
#define V4V_FUNC_GETINFO    0x17
#define V4V_FUNC_DUMPRING   0x18

/* V4V I/O Control Codes */
#if defined(_WIN64)
#define V4V_IOCTL_INITIALIZE CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_FUNC_INITIALIZE|V4V_64BIT, METHOD_BUFFERED, FILE_ANY_ACCESS)
#else
#define	V4V_IOCTL_INITIALIZE CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_FUNC_INITIALIZE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#define	V4V_IOCTL_BIND       CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_FUNC_BIND, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	V4V_IOCTL_LISTEN     CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_FUNC_LISTEN, METHOD_BUFFERED, FILE_ANY_ACCESS)
#if defined(_WIN64)
#define V4V_IOCTL_ACCEPT     CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_FUNC_ACCEPT|V4V_64BIT, METHOD_BUFFERED, FILE_ANY_ACCESS)
#else
#define	V4V_IOCTL_ACCEPT     CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_FUNC_ACCEPT, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#define	V4V_IOCTL_CONNECT    CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_FUNC_CONNECT, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	V4V_IOCTL_WAIT       CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_FUNC_WAIT, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	V4V_IOCTL_DISCONNECT CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_FUNC_DISCONNECT, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	V4V_IOCTL_GETINFO    CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_FUNC_GETINFO, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	V4V_IOCTL_DUMPRING   CTL_CODE(FILE_DEVICE_UNKNOWN, V4V_FUNC_DUMPRING, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* =========================== User Mode API ============================== */

#if !defined(XENV4V_DRIVER)

/* The following must be included before this header:
 * #include <windows.h>
 * #include <winioctl.h>
 */

/* V4V for Windows uses the basic file I/O model standard Windows API 
 * functions. All access to the V4V device is accomplished through use of a
 * Windows file handle returned by a call to CreateFile() in V4vOpen().
 * Several other V4V calls can then be made to initialize the V4V file (which
 * represents a particular V4V channel) for the specific operations desired. 
 * Once open and configured, Windows API file functions can be used to 
 * read/write/control V4V file IO. The following are the functions that would
 * be used with V4V:
 *
 * ReadFile()/ReadFileEx()
 * WriteFile()/WriteFileEx()
 * CancelIo()/CancelIoEx()
 *
 * Note that V4V supports for file IO both synchronous blocking mode or
 * asynchronous mode through use of an OVERLAPPED structure or IO completion
 * routines. The caller should not attempt to manipulate the V4V device
 * directly with DeviceIoControl() calls. The proper IOCTLs are sent through
 * the set of functions in the V4V API below. The V4V API also returns an
 * event handle that is signalled when data arrives on a V4V channel. This
 * handle can be used in any Windows API functions that operate on events
 * (e.g. WaitForMultipleObjects() in conjunction with OVERLAPPED IO events).
 *
 * V4V supports both datagram/connectionless and sream/connection types of
 * communication.
 *
 * Datagrams:
 * A V4V channel must simply be bound to send and receive datagrams. When
 * reading datagrams, if the buffer is smaller than next message size the
 * extra bytes will be discarded. When writing, the message cannot exceed
 * the maximum message the V4V channel can accomodate and ERROR_MORE_DATA
 * is returned. If the destination does not exist, ERROR_VC_DISCONNECTED
 * is returned. If the channel is not bound then ERROR_INVALID_FUNCTION
 * will be returned for all IO operations.
 *
 * Streams:
 * V4vListen()/V4vAccept()/V4vConnect()/V4vConnectWait() are used to
 * establish a stream channel. Read operations will read the next chunk
 * of the stream data out of the V4V channel. Note the read length may
 * be less than the supplied buffer. Currently, if stream data chunk is
 * bigger than the supplied buffer, ERROR_MORE_DATA will be returned
 * indicating a bigger buffer should be used. When writing data chunks
 * the call will block or pend until enough room is available for the
 * send. The written chunk cannot exceed the maximum message the V4V 
 * channel can accomodate and ERROR_MORE_DATA is returned. Attempts
 * to read and write after a reset or disconnection will result in
 * ERROR_VC_DISCONNECTED being returned.
 */

/* Define V4V_USE_INLINE_API to specify inline for the V4V API below */
#if defined(V4V_USE_INLINE_API)
#define V4V_INLINE_API __inline
#else
#define V4V_INLINE_API
#endif

/* Default @ringId for V4vBind() to specify no specific binding information */
static const v4v_ring_id_t V4V_DEFAULT_CONNECT_ID = {{V4V_PORT_NONE, V4V_DOMID_NONE}, V4V_DOMID_NONE};

#define V4V_FLAG_NONE       0x00000000
#define V4V_FLAG_OVERLAPPED 0x00000001

/* Overlapped sanity check macro */
#define V4V_CHECK_OVERLAPPED(c, o) \
    if ((c->flags & V4V_FLAG_OVERLAPPED)&&(o == NULL)) { \
        SetLastError(ERROR_INVALID_PARAMETER); \
        return FALSE; \
    }

/* The following structure represents a V4V channel either opened with 
 * V4vOpen() or returned from a listening V4V channel in a call to
 * V4vAccept().
 * 
 * The @v4vHandle is the file handle for an open instance of the V4V device.
 * This value is used in subsequent calls to read and write. The
 * @recvEvent is a Windows auto-reset event handle that becomes signaled
 * when data arrived on the V4V channel associated with the open file.
 *
 * The @flags field can be set to V4V_FLAG_OVERLAPPED if the caller intends
 * to use overlapped or asynchronous file IO with the V4V handle. If blocking
 * IO mode is desired, then the flag should be set to V4V_FLAG_NONE. The 
 * should be set before any call to the V4V functions and should not @flags
 * later be changed.
 */
typedef struct _V4V_CONTEXT
{
    HANDLE v4vHandle; /* handle for open V4V file */
    HANDLE recvEvent; /* data arrival, new connection for accept */
    ULONG  flags;     /* configuration flags set by caller */
} V4V_CONTEXT, *PV4V_CONTEXT;

/* This routine opens a V4V file and associated channel. The @context
 * structure is passed in to the routine and if the call is successful, the
 * @v4vHandle and @recvEvent handles will be valid and ready for use in
 * further V4V calls to initialize the channel.
 *
 * The @ringSize argument indicates how large the local receive ring for the
 * channel should be in bytes.
 *
 * If the V4V file is being opened with the V4V_FLAG_OVERLAPPED flag set then 
 * the V4vOpen() operation must be done asynchronously using the @ov overlapped
 * value. Otherwise @ov should be NULL and accept call will block until the
 * open is complete.
 * 
 * The new open file handle and receive event are returned event though an
 * a overlapped call may not have yet completed. Until an overlapped call 
 * completes the values in the @context should not be use.
 *
 * Returns TRUE on success or FALSE on error, in which case more
 * information can be obtained by calling GetLastError().
 */
static V4V_INLINE_API BOOL
V4vOpen(V4V_CONTEXT *context, ULONG ringSize, OVERLAPPED *ov)
{
    HANDLE hd;
    V4V_INIT_VALUES init = {0};
    BOOL rc;
    DWORD br;

    if (context == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    V4V_CHECK_OVERLAPPED(context, ov);

    context->recvEvent = NULL;
    context->v4vHandle = INVALID_HANDLE_VALUE;

    hd = CreateFileW(V4V_USER_FILE_NAME, GENERIC_READ|GENERIC_WRITE,
                     FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                     FILE_ATTRIBUTE_NORMAL|((context->flags & V4V_FLAG_OVERLAPPED) ? FILE_FLAG_OVERLAPPED : 0),
                     NULL);
    if (hd == INVALID_HANDLE_VALUE)
        return FALSE;
   
    init.ringLength = ringSize;
    init.rxEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (init.rxEvent == NULL) {        
        CloseHandle(hd);
        return FALSE;
    }

    do {
        SetLastError(ERROR_SUCCESS);

        rc = DeviceIoControl(hd, V4V_IOCTL_INITIALIZE, &init, sizeof(V4V_INIT_VALUES), NULL, 0, &br, ov);
        if (context->flags & V4V_FLAG_OVERLAPPED) {
            if ((GetLastError() != ERROR_SUCCESS)&&(GetLastError() != ERROR_IO_PENDING)) {
                break;
            }
        }
        else if (!rc) {
            break;
        }

        context->v4vHandle = hd;
        context->recvEvent = init.rxEvent;

        return TRUE;
    } while (FALSE);

    CloseHandle(init.rxEvent);
    CloseHandle(hd);
    return FALSE;
}

/* All users of V4V must call V4vBind() before calling any of the other V4V
 * functions (excpetion V4vClose()) or before performing IO operations. When
 * binding, the @ringId->addr.domain field must be set to V4V_DOMID_NONE or
 * the bind operation will fail. Internally this value will be set to the
 * current domain ID.
 *
 * For V4V channels intended for datagram use, the @ringId->addr.port field
 * can be specified or not. If not specified, a random port number will be
 * assigned internally. The @ringId->partner value can be specified if 
 * datagrams are to only be received from a specific partner domain for the
 * current V4V channel. If V4V_DOMID_ANY is specified, then datagrams from
 * any domain can be recieved. Note that V4V will send datagrams to channels
 * that match a specific domain ID before sending them to one bound with 
 * (@ringId->partner == V4V_DOMID_ANY).
 * 
 * The above rules apply when binding to start a listener though in general
 * one would want to specify a well known port for a listener. When binding
 * to do a connect, V4V_DEFAULT_CONNECT_ID can be used to allow internal
 * values to be selected.
 *
 * If the V4V file was opened with the V4V_FLAG_OVERLAPPED flag set then the
 * V4vBind() operation must be done asynchronously using the @ov overlapped
 * value. Otherwise @ov should be NULL and accept call will block until the
 * bind is complete.
 *
 * Returns TRUE on success or FALSE on error, in which case more information
 * can be obtained by calling GetLastError(). ERROR_INVALID_FUNCTION will
 * be returned if the file is not in the proper state following a call to
 * V4vOpen().
 */
static V4V_INLINE_API BOOL
V4vBind(V4V_CONTEXT *context, v4v_ring_id_t *ringId, OVERLAPPED *ov)
{
    V4V_BIND_VALUES bind;
    DWORD br;
    BOOL rc;

    if ((context == NULL)||(ringId == NULL)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    V4V_CHECK_OVERLAPPED(context, ov);

    memcpy(&bind.ringId, ringId, sizeof(v4v_ring_id_t));
    SetLastError(ERROR_SUCCESS);

    rc = DeviceIoControl(context->v4vHandle, V4V_IOCTL_BIND, &bind, sizeof(V4V_BIND_VALUES), NULL, 0, &br, ov);
    if (context->flags & V4V_FLAG_OVERLAPPED) {
        if ((GetLastError() != ERROR_SUCCESS)&&(GetLastError() != ERROR_IO_PENDING)) {
            return FALSE;
        }
    }
    else if (!rc) {
        return FALSE;
    }
    return TRUE;
}

/* This routine starts a listening V4V channel. For listening channels, the
 * @context->recvEvent will become signaled when a new connection is ready to
 * be accepted with a call to V4vAccept().
 *
 * The @backlog argument specifies the maximum length of pending accepts
 * to maintain. If 0 is specified, the V4V_SOMAXCONN value is used. @backlog
 * cannot be greater than V4V_SOMAXCONN.
 *
 * If the V4V file was opened with the V4V_FLAG_OVERLAPPED flag set then the
 * V4vListen() operation must be done asynchronously using the @ov overlapped
 * value. Otherwise @ov should be NULL and accept call will block until the
 * listen is complete.
 *
 * If the listener @context is closed before all the accepted connections are
 * closed, the existing accepted connections will remain connected. No new
 * connections will be accepted for this rind ID.
 *
 * Returns TRUE on success or FALSE on error, in which case more information
 * can be obtained by calling GetLastError(). ERROR_INVALID_FUNCTION will
 * be returned if the file is not in the bound state following a call to
 * V4vBind().
 */
static V4V_INLINE_API BOOL
V4vListen(V4V_CONTEXT *context, ULONG backlog, OVERLAPPED *ov)
{
    V4V_LISTEN_VALUES listen;
    DWORD br;
    BOOL rc;

    if (context == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    V4V_CHECK_OVERLAPPED(context, ov);

    ZeroMemory(&listen, sizeof(V4V_LISTEN_VALUES));
    listen.backlog = backlog;
    SetLastError(ERROR_SUCCESS);

    rc = DeviceIoControl(context->v4vHandle, V4V_IOCTL_LISTEN, &listen, 
                         sizeof(V4V_LISTEN_VALUES), NULL, 0, &br, ov);
    if (context->flags & V4V_FLAG_OVERLAPPED) {
        if ((GetLastError() != ERROR_SUCCESS)&&(GetLastError() != ERROR_IO_PENDING)) {
            return FALSE;
        }
    }
    else if (!rc) {
        return FALSE;
    }
    return TRUE;
}

/* Once a listening channel is established, calls can be made to V4vAccept()
 * to accept new connections. The new connection context is returned in the
 * @newContextOut argument that the caller must allocate. The newly accepted 
 * V4V channel will be a stream connection.
 *
 * If the V4V file was opened with the V4V_FLAG_OVERLAPPED flag set then the
 * V4vAccept() operation must be done asynchronously using the @ov overlapped
 * value. Otherwise @ov should be NULL and accept call will block until there
 * is an incoming connection. Note the @context->recvEvent for the listening
 * channel will be signaled when incoming connections arrive.
 *
 * The new open file handle and receive event are returned event though an
 * a overlapped call may not have yet completed. Until an overlapped call 
 * completes the values in the @newContextOut should not be use.
 *
 * The caller must suppy the @acceptOut argument. Upon synchronous completion
 * of the call, this structure will have the @acceptOut.peerAddr field filled
 * in (the other fields should be ignored). For overlapped calls, the caller 
 * retain the @acceptOut structure until IO is completed (this is effectively
 * the output buffer for the IOCLT). During GetOverlappedResult() or in the 
 * FileIOCompletionRoutine the @acceptOut.peerAddr value can be fetched and
 * @acceptOut released etc.
 *
 * Returns TRUE on success or FALSE on error, in which case more information
 * can be obtained by calling GetLastError(). ERROR_INVALID_FUNCTION will
 * be returned if the file represented by the @context is not in the listen 
 * state following a call to V4vListen().
 */
static V4V_INLINE_API BOOL
V4vAccept(V4V_CONTEXT *context, V4V_CONTEXT *newContextOut, V4V_ACCEPT_VALUES *acceptOut, OVERLAPPED *ov)
{
    V4V_ACCEPT_VALUES accept;
    DWORD br;
    BOOL rc;

    if ((context == NULL)||(newContextOut == NULL)||(acceptOut == NULL)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    V4V_CHECK_OVERLAPPED(context, ov);

    ZeroMemory(&accept, sizeof(V4V_ACCEPT_VALUES));
    ZeroMemory(acceptOut, sizeof(V4V_ACCEPT_VALUES));
    accept.fileHandle = 
            CreateFileW(V4V_USER_FILE_NAME, GENERIC_READ|GENERIC_WRITE,
                        FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL|((context->flags & V4V_FLAG_OVERLAPPED) ? FILE_FLAG_OVERLAPPED : 0),
                        NULL);
    if (accept.fileHandle == INVALID_HANDLE_VALUE)        
        return FALSE;        

    accept.rxEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (accept.rxEvent == NULL) {
        CloseHandle(accept.fileHandle);
        return FALSE;
    }

    do {
        SetLastError(ERROR_SUCCESS);

        rc = DeviceIoControl(context->v4vHandle, V4V_IOCTL_ACCEPT, &accept, sizeof(V4V_ACCEPT_VALUES),
                             acceptOut, sizeof(V4V_ACCEPT_VALUES), &br, ov);
        if (context->flags & V4V_FLAG_OVERLAPPED) {
            if ((GetLastError() != ERROR_SUCCESS)&&(GetLastError() != ERROR_IO_PENDING)) {
                break;
            }
        }
        else if (!rc) {
            break;
        }

        newContextOut->v4vHandle = accept.fileHandle;
        newContextOut->recvEvent = accept.rxEvent;
        newContextOut->flags = context->flags;

        return TRUE;
    } while (FALSE);

    CloseHandle(accept.rxEvent);
    CloseHandle(accept.fileHandle);
    return FALSE;
}

/* This routine is used to connect V4V channel. The newly connected V4V 
 * channel will be a stream connection. The @ringAddr argument specifies
 * the destination address to connect to.
 *
 * If the V4V file was opened with the V4V_FLAG_OVERLAPPED flag set then the
 * V4vConnect() operation can be done asynchronously using the @ov overlapped
 * value. Otherwise @ov should be NULL and accept call will block until the
 * connection is established.
 *
 * Returns TRUE on success or FALSE on error, in which case more information
 * can be obtained by calling GetLastError(). ERROR_INVALID_FUNCTION will
 * be returned if the file is not in the bound state following a call to
 * V4vBind().
 */
static V4V_INLINE_API BOOL
V4vConnect(V4V_CONTEXT *context, v4v_addr_t *ringAddr, OVERLAPPED *ov)
{
    V4V_CONNECT_VALUES connect;
    DWORD br;
    BOOL rc;

    if ((context == NULL)||(ringAddr == NULL)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    V4V_CHECK_OVERLAPPED(context, ov);

    ZeroMemory(&connect, sizeof(V4V_CONNECT_VALUES));
    memcpy(&connect.ringAddr, ringAddr, sizeof(v4v_addr_t));
    SetLastError(ERROR_SUCCESS);

    rc = DeviceIoControl(context->v4vHandle, V4V_IOCTL_CONNECT, &connect,
                         sizeof(V4V_CONNECT_VALUES), NULL, 0, &br, ov);
    if (context->flags & V4V_FLAG_OVERLAPPED) {
        if ((GetLastError() != ERROR_SUCCESS)&&(GetLastError() != ERROR_IO_PENDING)) {
            return FALSE;
        }
    }
    else if (!rc) {
        return FALSE;
    }
    return TRUE;
}

/* This function provides an alternate means to make a stream connection.
 * The function will wait for an incoming connect from V4vConnect() and
 * establish a single stream channel. It is different from V4vListen() in
 * that it effectively listens and accepts only once. As the name implies,
 * the call (or IO pended) will block until the peer has connected.
 *
 * If the V4V file was opened with the V4V_FLAG_OVERLAPPED flag set then the
 * V4vListen() operation must be done asynchronously using the @ov overlapped
 * value. Otherwise @ov should be NULL and accept call will block until the
 * listen is complete.
 *
 * Returns TRUE on success or FALSE on error, in which case more information
 * can be obtained by calling GetLastError(). ERROR_INVALID_FUNCTION will
 * be returned if the file is not in the bound state following a call to
 * V4vBind().
 */
static V4V_INLINE_API BOOL
V4vConnectWait(V4V_CONTEXT *context, OVERLAPPED *ov)
{
    V4V_WAIT_VALUES wait;
    DWORD br;
    BOOL rc;

    if (context == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    V4V_CHECK_OVERLAPPED(context, ov);

    ZeroMemory(&wait, sizeof(V4V_WAIT_VALUES));
    SetLastError(ERROR_SUCCESS);

    rc = DeviceIoControl(context->v4vHandle, V4V_IOCTL_WAIT, &wait,
                         sizeof(V4V_WAIT_VALUES), NULL, 0, &br, ov);
    if (context->flags & V4V_FLAG_OVERLAPPED) {
        if ((GetLastError() != ERROR_SUCCESS)&&(GetLastError() != ERROR_IO_PENDING)) {
            return FALSE;
        }
    }
    else if (!rc) {
        return FALSE;
    }
    return TRUE;
}

/* This routine is used to disconnect V4V channel stream. The channel be a 
 * connected or accepted stream connection. The API can be used to perform
 * an orederly shutdown by explicity sending an RST before closing the
 * context with V4vClose(). 
 *
 * If the V4V file was opened with the V4V_FLAG_OVERLAPPED flag set then the
 * V4vConnect() operation can be done asynchronously using the @ov overlapped
 * value. Otherwise @ov should be NULL and accept call will block until the
 * connection is established.
 *
 * Returns TRUE on success or FALSE on error, in which case more information
 * can be obtained by calling GetLastError(). ERROR_INVALID_FUNCTION will
 * be returned if the file is not in the connected/accepted states.
 */
static V4V_INLINE_API BOOL
V4vDisconnect(V4V_CONTEXT *context, OVERLAPPED *ov)
{
    DWORD br;
    BOOL rc;

    if (context == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    V4V_CHECK_OVERLAPPED(context, ov);

    SetLastError(ERROR_SUCCESS);

    rc = DeviceIoControl(context->v4vHandle, V4V_IOCTL_DISCONNECT, NULL, 0, NULL, 0, &br, ov);
    if (context->flags & V4V_FLAG_OVERLAPPED) {
        if ((GetLastError() != ERROR_SUCCESS)&&(GetLastError() != ERROR_IO_PENDING)) {
            return FALSE;
        }
    }
    else if (!rc) {
        return FALSE;
    }
    return TRUE;
}

/* Information can be gotten about the local or peer address. If 
 * V4vGetLocalInfo is specified, @ringInfoOut will contain the ring
 * information that the channel is locally bound with. If V4vGetPeerInfo
 * is specified then @ringInfoOut->addr will contain the remote peer
 * address information. V4vGetPeerInfo can only be used on V4V channels in the
 * connected or accepted states.
 *
 * If the V4V file was opened with the V4V_FLAG_OVERLAPPED flag set then the
 * V4vGetInfo() operation can be done asynchronously using the @ov overlapped
 * value. Otherwise @ov should be NULL and accept call will block until the
 * get info operation completes.
 *
 * For non-overlapped calls, the @ringInfoOut value will be filled in at the
 * end of the call. For overlapped calls, the caller must fetch the 
 * V4V_GETINFO_VALUES structure during GetOverlappedResult() or in the 
 * FileIOCompletionRoutine.
 *
 * The caller must suppy the @infoOut argument. Upon synchronous completion
 * of the call, this structure will have the @infoOut.ringInfo field filled
 * in (the other fields should be ignored). For overlapped calls, the caller 
 * retain the @infoOut structure until IO is completed (this is effectively
 * the output buffer for the IOCLT). During GetOverlappedResult() or in the 
 * FileIOCompletionRoutine the @infoOut.ringInfo value can be fetched and
 * @acceptOut released etc.
 *
 * Returns TRUE on success or FALSE on error, in which case more information
 * can be obtained by calling GetLastError(). ERROR_INVALID_FUNCTION will
 * be returned if the file is not in the proper state following a call to
 * get the information.
 */
static V4V_INLINE_API BOOL
V4vGetInfo(V4V_CONTEXT *context, V4V_GETINFO_TYPE type, V4V_GETINFO_VALUES *infoOut, OVERLAPPED *ov)
{
    V4V_GETINFO_VALUES info = {V4vInfoUnset, {{V4V_PORT_NONE, V4V_DOMID_NONE}, V4V_DOMID_NONE}};
    DWORD br;
    BOOL rc;

    if ((context == NULL)||(infoOut == NULL)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    V4V_CHECK_OVERLAPPED(context, ov);

    info.type = type;
    ZeroMemory(infoOut, sizeof(V4V_GETINFO_VALUES));
    infoOut->type = V4vInfoUnset;
    SetLastError(ERROR_SUCCESS);

    rc = DeviceIoControl(context->v4vHandle, V4V_IOCTL_GETINFO,
                         &info, sizeof(V4V_GETINFO_VALUES), 
                         infoOut, sizeof(V4V_GETINFO_VALUES), &br, ov);
    if (context->flags & V4V_FLAG_OVERLAPPED) {
        if ((GetLastError() != ERROR_SUCCESS)&&(GetLastError() != ERROR_IO_PENDING)) {
            return FALSE;
        }
    }
    else if (!rc) {
        return FALSE;
    }   

    return TRUE;
}

/* This utility routine will dump the current state of the V4V ring to the
 * various driver trace targets (like KD, Xen etc).
 *
 * If the V4V file was opened with the V4V_FLAG_OVERLAPPED flag set then the
 * V4vGetInfo() operation can be done asynchronously using the @ov overlapped
 * value. Otherwise @ov should be NULL and accept call will block until the
 * get info operation completes.
 *
 * Returns TRUE on success or FALSE on error, in which case more information
 * can be obtained by calling GetLastError(). ERROR_INVALID_FUNCTION will
 * be returned if the file is not in the proper state following a call to
 * dump the ring.
 */
static V4V_INLINE_API BOOL
V4vDumpRing(V4V_CONTEXT *context, OVERLAPPED *ov)
{
    DWORD br;
    BOOL rc;

    if (context == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    V4V_CHECK_OVERLAPPED(context, ov);

    SetLastError(ERROR_SUCCESS);

    rc = DeviceIoControl(context->v4vHandle, V4V_IOCTL_DUMPRING, NULL, 0, NULL, 0, &br, ov);
    if (context->flags & V4V_FLAG_OVERLAPPED) {
        if ((GetLastError() != ERROR_SUCCESS)&&(GetLastError() != ERROR_IO_PENDING)) {
            return FALSE;
        }
    }
    else if (!rc) {
        return FALSE;
    }

    return TRUE;
}

/* This routine should be used to close the @context handles returned from a
 * call to V4vOpen(). It can be called at any time to close the file handle
 * and terminate all outstanding IO.
 *
 * Returns TRUE on success or FALSE on error, in which case more information
 * can be obtained by calling GetLastError().
 */
static V4V_INLINE_API BOOL
V4vClose(V4V_CONTEXT *context)
{
    BOOL rc = TRUE;

    if (context == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (context->recvEvent != NULL) {
        if (CloseHandle(context->recvEvent))
            context->recvEvent = NULL;
        else
            rc = FALSE;
    }

    if ((context->v4vHandle != INVALID_HANDLE_VALUE)&&(context->v4vHandle != NULL)) {
        if (CloseHandle(context->v4vHandle))
            context->v4vHandle = INVALID_HANDLE_VALUE;
        else
            rc = FALSE;
    }

    return rc;
}

#endif /* XENV4V_DRIVER */

#endif /* !__V4VAPI_H__ */
