/*
 * Copyright (c) 2009 Citrix Systems, Inc.
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

#if !defined(_V2V_COMMON_H_)
#define _V2V_COMMON_H_

typedef enum _V2V_MODE_TYPE {
    ModeTypeUnknown = 0,
    ModeTypeUser,
    ModeTypeKernel
} V2V_MODE_TYPE;

typedef enum _V2V_ROLE_TYPE {
    RoleTypeUnknown = 0,
    RoleTypeConnector,
    RoleTypeListener
} V2V_ROLE_TYPE;

typedef enum _V2V_XFER_TYPE {
    XferTypeUnknown = 0,
    XferTypeInternal,
    XferTypeFile
} V2V_XFER_TYPE;

#define V2V_RESPONSE_WAIT_TIMEOUT 2000

#define V2V_MESSAGE_TYPE_INTERNAL 10
#define V2V_MESSAGE_TYPE_FILE     15

#define V2V_MESSAGE_STATUS_OK        0
#define V2V_MESSAGE_STATUS_EOF       1
#define V2V_MESSAGE_STATUS_MORE      2
#define V2V_MESSAGE_STATUS_BADCS     0xFFFFF100
#define V2V_MESSAGE_STATUS_BADSEQ    0xFFFFF101
#define V2V_MESSAGE_STATUS_NODATA    0xFFFFF102
#define V2V_MESSAGE_STATUS_WRITE_ERR 0xFFFFF103

typedef struct _V2V_FRAME_HEADER {
    USHORT id;
    UCHAR  type;
    UCHAR  cs;
    ULONG  length;
} V2V_FRAME_HEADER, *PV2V_FRAME_HEADER;

typedef struct _V2V_POST_INTERNAL {
    V2V_FRAME_HEADER header;
    GUID guid;
    /* data */
} V2V_POST_INTERNAL, *PV2V_POST_INTERNAL;

typedef struct _V2V_RESP_INTERNAL {
    V2V_FRAME_HEADER header;
    ULONG status;
    GUID guid;
} V2V_RESP_INTERNAL, *PV2V_RESP_INTERNAL;

typedef struct _V2V_POST_FILE {
    V2V_FRAME_HEADER header;
    ULONG status;
    ULONG seqnum;
    /* file data */
} V2V_POST_FILE, *PV2V_POST_FILE;

typedef struct _V2V_RESP_FILE {
    V2V_FRAME_HEADER header;
    ULONG status;
    ULONG seqnum;
} V2V_RESP_FILE, *PV2V_RESP_FILE;

typedef struct _V2V_LISTENER_RESP_ITEM {    
    V2V_RESP_INTERNAL resp;
    struct _V2V_LISTENER_RESP_ITEM *next;
} V2V_LISTENER_RESP_ITEM, *PV2V_LISTENER_RESP_ITEM;

__inline UCHAR V2vChecksum(const UCHAR *ptr, ULONG length)
{
    ULONG count;
    UCHAR sum;

    for (count = 0, sum = 0; count < length; count++)
        sum = sum + ptr[count];

    return -sum;
}

#define MIN(x, y) ((x) < (y) ? (x) : (y))

#endif /*_V2V_COMMON_H_*/
