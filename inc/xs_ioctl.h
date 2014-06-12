//
// xs_ioctl.h
//
// Copyright (c) 2006 XenSource, Inc. - All rights reserved.
//

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


#ifndef _XS_IOCTL_H_
#define _XS_IOCTL_H_

#pragma warning (disable: 4200) // nonstandard extension used : zero-sized array

#define IOCTL_XS_TRANS_START \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_TRANS_END \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_READ \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_WRITE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_DIRECTORY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_REMOVE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_WATCH \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_UNWATCH \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_ENABLE_UNINST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_SET_LOGLEVEL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_LISTEN_SUSPEND \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80a, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_UNLISTEN_SUSPEND \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80b, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_GET_XEN_TIME \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80c, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_GET_LOG_SIZE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80d, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_GET_LOG \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80e, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_MAKE_PRECIOUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80f, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_UNMAKE_PRECIOUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_LOG \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_QUERY_BALLOON \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_XS_GRANT_ACCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_UNGRANT_ACCESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_XS_GRANT_MAP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x818, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_GRANT_UNMAP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x819, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_XS_EVTCHN_LISTEN \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81a, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_EVTCHN_CLOSE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81b, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_EVTCHN_CONNECT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81c, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_EVTCHN_KICK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81d, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_XS_WRITE_ON_CLOSE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81e, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_CANCEL_WRITE_ON_CLOSE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81f, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_XS_GRANT_SET_QUOTA \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_GRANT_GET_QUOTA \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_XS_UNINST_IN_PROGRESS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_XS_DIAG_ACPIDUMP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x823, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_DIAG_GETE820 \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x824, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_XS_DIAG_PCICONFIG \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x825, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define INITIAL_OUTBUF_SIZE 128

typedef struct {
    int len;
    char data[0]; // for write msg, it will contains the string path and data
} XS_READ_MSG, XS_WRITE_MSG;

typedef struct {
    int count;
    int len;
    char data[0];
} XS_DIR_MSG;

typedef struct {
    HANDLE event;
    char path[0];
} XS_WATCH_MSG;

typedef struct {
    ULONG event;
    char path[0];
} XS_WATCH_MSG_32;

typedef struct {
    HANDLE handle;
} XS_LISTEN_SUSPEND_MSG;


typedef struct {
    int dispositions[7];
} XS_LOGLEVEL_MSG;

typedef struct {
    unsigned max_pages;
    unsigned current_pages;
    unsigned target_pages;
    unsigned allocations_failed;
    unsigned partial_allocations;
    unsigned two_mb_allocations;
    BOOLEAN running;
    BOOLEAN shutdown_requested;
    BOOLEAN timer_fired;
    BOOLEAN timer_inserted;
    BOOLEAN watch_fired;
} XS_QUERY_BALLOON;

typedef struct {
    unsigned domid;
    BOOLEAN readonly;
    ULONG64 virt_addr;
} XS_GRANT_ACCESS_IN;

typedef struct {
    unsigned grant_reference;
} XS_GRANT_ACCESS_OUT;

typedef struct {
    unsigned grant_reference;
} XS_UNGRANT_ACCESS;

#define XS_GRANT_MAP_MAX_GREFS 256
typedef struct {
    unsigned domid;
    BOOLEAN readonly;
    unsigned nr_grefs;
    unsigned grant_refs[0];
} XS_GRANT_MAP_IN;

typedef struct {
    ULONG64 virt_addr;
    ULONG64 handle;
} XS_GRANT_MAP_OUT;

typedef struct {
    ULONG64 handle;
} XS_GRANT_UNMAP;

typedef struct {
    unsigned domid;
    ULONG64 event_handle;
} XS_EVTCHN_LISTEN_IN;

typedef struct {
    unsigned evtchn_port;
} XS_EVTCHN_LISTEN_OUT;

typedef struct {
    unsigned evtchn_port;
} XS_EVTCHN_CLOSE;

typedef struct {
    unsigned domid;
    unsigned remote_port;
    ULONG64 event_handle;
} XS_EVTCHN_CONNECT_IN;

typedef struct {
    unsigned evtchn_port;
} XS_EVTCHN_CONNECT_OUT;

typedef struct {
    unsigned evtchn_port;
} XS_EVTCHN_KICK;

typedef struct {
    ULONG64 path;
    ULONG64 data;
    ULONG data_len;
} XS_WRITE_ON_CLOSE_IN;

typedef struct {
    ULONG64 handle;
} XS_WRITE_ON_CLOSE_OUT;

typedef struct {
    ULONG64 handle;
} XS_CANCEL_WRITE_ON_CLOSE;

typedef struct {
    unsigned quota;
} XS_GRANT_QUOTA;

#pragma pack(push, 1)
typedef struct {
    ULONG64 addr;
    ULONG64 size;
    ULONG32 type;
} XS_DIAGS_E820_ENTRY;
#pragma pack(pop)

typedef struct {
    ULONG signature;
    ULONG entry_count;
    XS_DIAGS_E820_ENTRY entries[0];
} XS_DIAGS_E820;

#define XS_DIAGS_PCICONFIG_REV  1
#define XS_DIAGS_PCICONFIG_SIZE 256

#pragma pack(push, 1)
typedef struct {
    ULONG bus;
    ULONG device;
    ULONG function;
    UCHAR config_space[XS_DIAGS_PCICONFIG_SIZE];
} XS_DIAGS_PCICONFIG_ENTRY;

typedef struct {
    ULONG rev;
    ULONG count;
    XS_DIAGS_PCICONFIG_ENTRY entries[0];
} XS_DIAGS_PCICONFIG;
#pragma pack(pop)

#endif // _XS_IOCTL_H_
