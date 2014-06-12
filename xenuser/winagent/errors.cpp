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

/* Black-box data recorder.  This records stuff which is happening
   while the agent runs, and tries to push it out to dom0 syslog if we
   crash. */
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <winioctl.h>
#include "xs_ioctl.h"
#include "XService.h"

#define RING_SIZE 8192

struct message_ring {
    HANDLE handle;
    unsigned prod_idx;
    unsigned cons_idx;
    unsigned char payload[RING_SIZE];
};

static __declspec(thread) struct message_ring message_ring;

static char *
Xsvasprintf(const char *fmt, va_list args)
{
    char *work;
    int work_size;
    int r;

    work_size = 32;
    while (1) {
        work = (char *)malloc(work_size);
        if (!work)
            return work;
        r = _vsnprintf(work, work_size, fmt, args);
        if (r == 0) {
            free(work);
            return NULL;
        }
        if (r != -1 && r < work_size) {
            return work;
        }
        free(work);
        work_size *= 2;
    }
}

static char *
Xsasprintf(const char *fmt, ...)
{
    va_list args;
    char *res;

    va_start(args, fmt);
    res = Xsvasprintf(fmt, args);
    va_end(args);
    return res;
}

static void
copy_to_ring(const char *msg)
{
    size_t l;
    unsigned idx;

    l = strlen(msg);
    if (l >= RING_SIZE) {
        /* Truncate messages which would wrap around the ring */
        l = RING_SIZE - 1;
    }

    idx = message_ring.prod_idx % RING_SIZE;
    if (idx + l > RING_SIZE) {
        memset(message_ring.payload + idx,
               0,
               RING_SIZE - idx);
        message_ring.prod_idx += RING_SIZE - idx;
        idx = 0;
    }
    memcpy(message_ring.payload + idx, msg, l);

    message_ring.prod_idx += l;
    message_ring.payload[message_ring.prod_idx % RING_SIZE] = 0;
    message_ring.prod_idx++;
}

void
XsVLogMsg(const char *fmt, va_list args)
{
    char *msg;
    char *msg2;
    DWORD now;

    now = GetTickCount();

    msg = Xsvasprintf(fmt, args);
    if (!msg) {
        /* Can't format message -> log the format string and hope
           that's good enough */
        msg = (char *)fmt;
    }
    msg2 = Xsasprintf("%08x:%s", now, msg);
    if (msg2) {
        if (msg != fmt)
            free(msg);
    } else {
        /* Hmm... drop the timestamp and hope for the best */
        msg2 = msg;
    }
    copy_to_ring(msg2);
    if (msg2 != fmt)
        free(msg2);
}

void
XsLogMsg(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    XsVLogMsg(fmt, args);
    va_end(args);
}

void
XsInitPerThreadLogging(void)
{
    struct message_ring *ring = &message_ring;

    memset(ring, 0, sizeof(*ring));
    ring->handle = CreateFile("\\\\.\\XenBus",
                              GENERIC_READ | GENERIC_WRITE,
                              0,
                              NULL,
                              OPEN_EXISTING,
                              0,
                              NULL);
    if (ring->handle == INVALID_HANDLE_VALUE) {
        /* Not much we can do here.  This has to be handled in
           send_bytes_to_dom0(). */
    }
}

static void
send_bytes_to_dom0(struct message_ring *ring,
                   const unsigned char *bytes,
                   unsigned nr_bytes)
{
    BOOL bResult = FALSE;
    DWORD tmp;

    if (ring->handle == INVALID_HANDLE_VALUE ||
        ring->handle == NULL)
        return;
    DeviceIoControl(ring->handle,
                    IOCTL_XS_LOG,
                    (void *)bytes,
                    nr_bytes,
                    NULL,
                    0,
                    &tmp,
                    NULL);
}

/* Careful here.  This gets called as part of the cleanup from an
   unhandled exception, so the state of the world is almost completely
   unknown. */
void
XsDumpLogThisThread(void)
{
    struct message_ring *ring = &message_ring;
    unsigned end_idx;

    if (ring->prod_idx - ring->cons_idx > RING_SIZE) {
        /* The ring's wrapped since the last time we dumped it.
           Advance the consumer pointer to the next full message */
        ring->cons_idx = ring->prod_idx - RING_SIZE;
        while (ring->cons_idx != ring->prod_idx &&
               ring->payload[ring->cons_idx % RING_SIZE])
            ring->cons_idx++;
        if (ring->cons_idx != ring->prod_idx)
            ring->cons_idx++;
    }

    while (ring->cons_idx != ring->prod_idx) {
        for (end_idx = ring->cons_idx;
             end_idx != ring->prod_idx && ring->payload[end_idx % RING_SIZE] != 0;
             end_idx++)
            ;

        if (end_idx != ring->cons_idx) {
            send_bytes_to_dom0(ring,
                               ring->payload + (ring->cons_idx % RING_SIZE),
                               end_idx - ring->cons_idx);
        }
        if (end_idx == ring->prod_idx) {
            ring->cons_idx = end_idx;
        } else {
            ring->cons_idx = end_idx + 1;
        }
    }
}
