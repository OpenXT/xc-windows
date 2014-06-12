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

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <xs_private.h>
#include <v2v.h>

struct systemtimes {
    union {
        struct {
            FILETIME idle;
            FILETIME kernel;
            FILETIME user;
        } ft;
        struct {
            LONGLONG idle;
            LONGLONG kernel;
            LONGLONG user;
        } ll;
    } u;
};

struct chargen_message {
    unsigned number;
};

static void
dump_bytes(const volatile void *_bytes, size_t nr_bytes)
{
    const volatile unsigned char *bytes = _bytes;
    size_t x;

    x  = 0;
    if (nr_bytes >= 8) {
        for (; x < nr_bytes - 8; x += 8) {
            printf("%04x\t%02x %02x %02x %02x %02x %02x %02x %02x\n",
                   x,
                   bytes[x],
                   bytes[x+1],
                   bytes[x+2],
                   bytes[x+3],
                   bytes[x+4],
                   bytes[x+5],
                   bytes[x+6],
                   bytes[x+7]);
        }
    }
    printf("%04x\t", x);
    while (x < nr_bytes - 1) {
        printf("%02x ", bytes[x]);
        x++;
    }
    if (x < nr_bytes)
        printf("%02x", bytes[x]);
    printf("\n");
}

static void
start_systimes(struct systemtimes *times)
{
    if (!GetSystemTimes(&times->u.ft.idle, &times->u.ft.kernel,
                        &times->u.ft.user))
        xs_win_err(1, &xs_render_error_stderr,
                   "getting system times");
}

static void
finish_systimes(struct systemtimes *start)
{
    struct systemtimes end;
    if (!GetSystemTimes(&end.u.ft.idle, &end.u.ft.kernel, &end.u.ft.user))
        xs_win_err(1, &xs_render_error_stderr, "getting end times");
    start->u.ll.kernel = end.u.ll.kernel - start->u.ll.kernel;
    start->u.ll.user = end.u.ll.user - start->u.ll.user;
    start->u.ll.idle = end.u.ll.idle - start->u.ll.idle;
    start->u.ll.kernel -= start->u.ll.idle;
    printf("%fs kernel, %fs user, %fs idle\n",
           start->u.ll.kernel * 1e-7,
           start->u.ll.user * 1e-7,
           start->u.ll.idle * 1e-7);
}

static HANDLE
multiwait(DWORD timeout, ...)
{
    unsigned nr_handles;
    HANDLE *handles;
    HANDLE next_handle;
    va_list args;
    DWORD status;
    HANDLE res;

    nr_handles = 0;
    handles = malloc(0);
    va_start(args, timeout);
    next_handle = va_arg(args, HANDLE);
    while (next_handle) {
        nr_handles++;
        handles = realloc(handles, sizeof(handles[0]) * nr_handles);
        if (!handles)
            xs_errx(1, &xs_render_error_stderr,
                    "out of memory for %d handles", nr_handles);
        handles[nr_handles-1] = next_handle;
        next_handle = va_arg(args, HANDLE);
    }
    va_end(args);
    status = WaitForMultipleObjects(nr_handles, handles, FALSE, timeout);
    /* WAIT_OBJECT_0 == 0, so can't compare to status without a
       compile error */
    if (status < WAIT_OBJECT_0 + nr_handles) 
        res = handles[status - WAIT_OBJECT_0];
    else
        res = NULL;
    free(handles);
    return res;
}

static int
test_dump_server(int argc, char *argv[])
{
    struct v2v_channel *chan;
    volatile void *payload;
    size_t size;
    unsigned type;
    unsigned flags;
    HANDLE h;

    UNREFERENCED_PARAMETER(argc);

    if (!v2v_listen(argv[0], &chan, 0, 0))
        xs_win_err(1, &xs_render_error_stderr,
                   "listening on %s", argv[0]);
    printf("Listening...\n");
    if (!v2v_accept(chan))
        xs_win_err(1, &xs_render_error_stderr, "accepting");
    printf("Accepted.\n");
    while (1) {
        h = multiwait(INFINITE,
                      v2v_get_receive_event(chan),
                      v2v_get_control_event(chan),
                      NULL);
        if (!h)
            xs_win_err(1, &xs_render_error_stderr,
                       "waiting for something to happen");
        if (h == v2v_get_receive_event(chan)) {
            printf("Woke up.\n");
            while (v2v_nc2_get_message(chan, &payload, &size, &type,
                                       &flags)) {
                printf("Got message type %d size %d flags 0x%x\n", type, size,
                       flags);
                dump_bytes(payload, size);
                v2v_nc2_finish_message(chan);
            }
            if (GetLastError() != ERROR_NO_MORE_ITEMS)
                xs_win_err(1, &xs_render_error_stderr, "getting message");
        } else {
            printf("Other end status changed, now %s\n",
                   v2v_endpoint_state_name(v2v_get_remote_state(chan)));
            if (v2v_state_requests_disconnect(v2v_get_remote_state(chan)))
                break;
        }
    }
    printf("Disconnecting...\n");
    v2v_disconnect(chan);
    printf("Disconnected.\n");
    return 0;
}

static int
test_chargen_client(int argc, char *argv[])
{
    struct v2v_channel *chan;
    volatile struct chargen_message *msg;
    unsigned cntr;

    UNREFERENCED_PARAMETER(argc);

    if (!v2v_connect(argv[0], &chan))
        xs_win_err(1, &xs_render_error_stderr, "connecting to %s", argv[0]);

    cntr = 0;
    while (1) {
        if (!v2v_nc2_prep_message(chan, sizeof(*msg), 52, 0, &msg))
            xs_win_err(1, &xs_render_error_stderr, "allocating ring space");
        msg->number = 0xfee1dead + cntr;
        v2v_nc2_send_messages(chan);
        if (WaitForSingleObject(v2v_get_control_event(chan), 1000) ==
            WAIT_OBJECT_0) {
            printf("Other end status changed, now %s\n",
                   v2v_endpoint_state_name(v2v_get_remote_state(chan)));
            if (v2v_state_requests_disconnect(v2v_get_remote_state(chan)))
                break;
        }
        cntr++;
    }
    printf("Disconnecting...\n");
    v2v_disconnect(chan);
    printf("Disconnected.\n");
    return 0;
}

static int
test_disconnect_client(int argc, char *argv[])
{
    struct v2v_channel *chan;

    UNREFERENCED_PARAMETER(argc);

    if (!v2v_connect(argv[0], &chan))
        xs_win_err(1, &xs_render_error_stderr, "connecting to %s", argv[0]);

    if (!v2v_disconnect(chan))
        xs_win_err(1, &xs_render_error_stderr, "disconnecting");

    return 0;
}

static int
test_disconnect_server(int argc, char *argv[])
{
    struct v2v_channel *chan;

    UNREFERENCED_PARAMETER(argc);

    if (!v2v_listen(argv[0], &chan, 0, 0))
        xs_win_err(1, &xs_render_error_stderr, "connecting to %s", argv[0]);
    if (!v2v_accept(chan))
        xs_win_err(1, &xs_render_error_stderr, "accepting");
    if (!v2v_disconnect(chan))
        xs_win_err(1, &xs_render_error_stderr, "disconnecting");

    return 0;
}

static int
test_stream_dump_server(int argc, char *argv[])
{
    struct v2v_channel *chan;
    struct v2v_stream *stream;
    char buf[1000];
    size_t recved;

    UNREFERENCED_PARAMETER(argc);

    if (!v2v_listen(argv[0], &chan, 0, 0))
        xs_win_err(1, &xs_render_error_stderr,
                   "listening on %s", argv[0]);
    printf("Listening...\n");
    if (!v2v_accept(chan))
        xs_win_err(1, &xs_render_error_stderr, "accepting");
    printf("Accepted.\n");
    if (!v2v_stream_attach(chan, &stream))
        xs_win_err(1, &xs_render_error_stderr, "attaching stream");

    while (v2v_stream_recv(stream, buf, sizeof(buf), &recved))
        dump_bytes(buf, recved);
    if (GetLastError() != ERROR_VC_DISCONNECTED)
        xs_win_err(1, &xs_render_error_stderr, "receiving");
    v2v_stream_detach(stream);
    if (!v2v_disconnect(chan))
        xs_win_err(1, &xs_render_error_stderr, "disconnecting");
    return 0;
}

static int
test_stream_drop_server(int argc, char *argv[])
{
    struct v2v_channel *chan;
    struct v2v_stream *stream;
    char buf[65536];
    size_t recved;
    struct systemtimes systemtimes;

    UNREFERENCED_PARAMETER(argc);

    if (!v2v_listen(argv[0], &chan, 0, 3))
        xs_win_err(1, &xs_render_error_stderr,
                   "listening on %s", argv[0]);
    printf("Listening...\n");
    if (!v2v_accept(chan))
        xs_win_err(1, &xs_render_error_stderr, "accepting");
    printf("Accepted.\n");
    if (!v2v_stream_attach(chan, &stream))
        xs_win_err(1, &xs_render_error_stderr, "attaching stream");

    start_systimes(&systemtimes);
    while (v2v_stream_recv(stream, buf, sizeof(buf), &recved))
        ;
    if (GetLastError() != ERROR_VC_DISCONNECTED)
        xs_win_err(1, &xs_render_error_stderr, "receiving");
    finish_systimes(&systemtimes);
    v2v_stream_detach(stream);
    if (!v2v_disconnect(chan))
        xs_win_err(1, &xs_render_error_stderr, "disconnecting");
    return 0;
}

static int
test_stream_echo_server(int argc, char *argv[])
{
    struct v2v_channel *chan;
    struct v2v_stream *stream;
    char buf[1000];
    size_t recved;
    size_t sent;

    UNREFERENCED_PARAMETER(argc);

    if (!v2v_listen(argv[0], &chan, 2, 2))
        xs_win_err(1, &xs_render_error_stderr,
                   "listening on %s", argv[0]);
    printf("Listening...\n");
    if (!v2v_accept(chan))
        xs_win_err(1, &xs_render_error_stderr, "accepting");
    printf("Accepted.\n");
    if (!v2v_stream_attach(chan, &stream))
        xs_win_err(1, &xs_render_error_stderr, "attaching stream");

    while (v2v_stream_recv(stream, buf, sizeof(buf), &recved) &&
           v2v_stream_send(stream, buf, recved, &sent))
        ;
    if (GetLastError() != ERROR_VC_DISCONNECTED)
        xs_win_err(1, &xs_render_error_stderr, "receiving or sending");
    v2v_stream_detach(stream);
    if (!v2v_disconnect(chan))
        xs_win_err(1, &xs_render_error_stderr, "disconnecting");
    return 0;
}

static int
test_stream_chargen_client(int argc, char *argv[])
{
    struct v2v_channel *chan;
    struct v2v_stream *stream;
    char buf[700];
    unsigned x;
    unsigned seq;
    size_t sent;
    size_t sent_this_time;

    UNREFERENCED_PARAMETER(argc);

    seq = 0;

    if (!v2v_connect(argv[0], &chan))
        xs_win_err(1, &xs_render_error_stderr,
                   "listening on %s", argv[0]);
    printf("Connected.\n");
    if (!v2v_stream_attach(chan, &stream))
        xs_win_err(1, &xs_render_error_stderr, "attaching stream");
    printf("Accepted.\n");
    while (1) {
        for (x = 0; x < sizeof(buf); x++)
            buf[x] = (unsigned char)(seq++);
        for (sent = 0; sent < sizeof(buf); sent += sent_this_time) {
            if (!v2v_stream_send(stream, buf + sent, sizeof(buf) - sent,
                                 &sent_this_time))
                xs_win_err(1, &xs_render_error_stderr, "sending %d bytes",
                           sizeof(buf) - sent);
        }
    }
}

static int
test_stream_blast_client(int argc, char *argv[])
{
    struct v2v_channel *chan;
    struct v2v_stream *stream;
    char buf[65536];
    size_t sent_this_time;
    DWORD start;
    DWORD now;
    unsigned long long total_sent;
    struct systemtimes systemtimes;
    double pre_bw;
    unsigned delay;

    if (argc == 1) {
        delay = 60;
    } else if (argc == 2) {
        delay = atoi(argv[1]);
    } else {
        xs_errx(1, &xs_render_error_stderr, "strange number of arguments");
        delay = 99;
    }

    memset(buf, 0, sizeof(buf));
    if (!v2v_connect(argv[0], &chan))
        xs_win_err(1, &xs_render_error_stderr,
                   "listening on %s", argv[0]);
    printf("Connected.\n");
    if (!v2v_stream_attach(chan, &stream))
        xs_win_err(1, &xs_render_error_stderr, "attaching stream");
    printf("Accepted.\n");
    total_sent = 0;
    start_systimes(&systemtimes);
    start = GetTickCount();
    while (1) {
        now = GetTickCount();
        if (now - start > delay * 1000)
            break;
        if (!v2v_stream_send(stream, buf, sizeof(buf), &sent_this_time))
            xs_win_err(1, &xs_render_error_stderr, "sending %d bytes",
                       sizeof(buf));
        total_sent += sent_this_time;
    }
    finish_systimes(&systemtimes);
    pre_bw = (double)total_sent/1e6;
    printf("Bandwidth %fMB/s (user %fMB/s, kernel %fMB/s, CPU %fMB/s)\n",
           pre_bw/delay, pre_bw*1e7/systemtimes.u.ll.user,
           pre_bw*1e7/systemtimes.u.ll.kernel,
           pre_bw*1e7/(systemtimes.u.ll.user + systemtimes.u.ll.kernel));
    v2v_stream_detach(stream);
    if (!v2v_disconnect(chan))
        xs_win_err(1, &xs_render_error_stderr, "disconnecting");
    return 0;
}

static void
perf_test_size(struct v2v_stream *stream, unsigned size,
               unsigned nr_iterations, unsigned targ_nr_bounces)
{
    char *buf;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    LARGE_INTEGER perf_freq;
    LONGLONG minticks;
    LONGLONG maxticks;
    LONGLONG ticks;
    LONGLONG ticks_this_iter;
    double ticks_mean;
    unsigned iteration_nr;
    unsigned bounce_nr;
    size_t received;
    size_t received_this_time;
    unsigned nr_bounces;
    DWORD_PTR old_affinity;
    size_t ignore;
    unsigned seq;
    unsigned x;

    buf = malloc(size);
    memset(buf, 0xab, size);
    old_affinity = SetThreadAffinityMask(GetCurrentThread(), 1);
    if (!old_affinity)
        xs_win_err(1, &xs_render_error_stderr, "binding to cpu 0");

    /* Shut the compiler up */
    minticks = 0;
    maxticks = 0;

    seq = 0;
    ticks = 0;
    for (iteration_nr = 0; iteration_nr < nr_iterations; iteration_nr++) {
        QueryPerformanceCounter(&start);
        for (bounce_nr = 0; bounce_nr < targ_nr_bounces; bounce_nr++) {
            for (x = 0; x + 3 < size; x += 4)
                ((unsigned *)buf)[x/4] = seq + x;
            if (!v2v_stream_send(stream, buf, size, &ignore))
                xs_win_err(1, &xs_render_error_stderr,
                           "sending %d bytes", size);
            memset(buf, 0, size);
            for (received = 0;
                 received != size;
                 received += received_this_time) {
                if (!v2v_stream_recv(stream,
                                     (void *)((ULONG_PTR)buf + received),
                                     size - received,
                                     &received_this_time))
                    xs_win_err(1, &xs_render_error_stderr,
                               "receiving %d bytes (got %d + %d)",
                               size, received, received_this_time);
            }
            for (x = 0; x + 3 < size; x += 4) {
                if (((unsigned *)buf)[x/4] != seq + x) {
                    printf("sequence number screw up: should be %d, was %d\n",
                           seq + x, ((unsigned *)buf)[x/4]);
                    exit(1);
                }
            }
            seq += x;
        }
        QueryPerformanceCounter(&end);
        ticks_this_iter = end.QuadPart - start.QuadPart;
        if (iteration_nr == 0) {
            minticks = maxticks = ticks_this_iter;
        } else {
            if (ticks_this_iter < minticks)
                minticks = ticks_this_iter;
            if (ticks_this_iter > maxticks)
                maxticks = ticks_this_iter;
        }
        ticks += ticks_this_iter;
    }

    nr_bounces = nr_iterations * targ_nr_bounces;
    ticks_mean = (double)ticks / nr_bounces;
    QueryPerformanceFrequency(&perf_freq);
    printf("%8d %e %e %e\n",
           size,
           ticks_mean / perf_freq.QuadPart,
           (double)minticks / (targ_nr_bounces * perf_freq.QuadPart),
           (double)maxticks / (targ_nr_bounces * perf_freq.QuadPart));

    SetThreadAffinityMask(GetCurrentThread(), old_affinity);
}

static void
perf_test_size_range(struct v2v_stream *stream, unsigned low, unsigned high)
{
    unsigned x;
#define NR_ITERATIONS 10
#define NR_BOUNCES 1000
    for (x = low; x <= high; x++)
        perf_test_size(stream, x, NR_ITERATIONS, NR_BOUNCES);
}

static int
test_stream_perf_client(int argc, char *argv[])
{
    struct v2v_channel *chan;
    struct v2v_stream *stream;
    unsigned x;

    UNREFERENCED_PARAMETER(argc);

    if (!v2v_connect(argv[0], &chan))
        xs_win_err(1, &xs_render_error_stderr,
                   "listening on %s", argv[0]);
    if (!v2v_stream_attach(chan, &stream))
        xs_win_err(1, &xs_render_error_stderr, "attaching stream");

    perf_test_size_range(stream, 1, 16);
    perf_test_size_range(stream, 127, 128);
    perf_test_size_range(stream, 1023, 1025);
    perf_test_size_range(stream, 2047, 2049);
    perf_test_size_range(stream, 3071, 3073);
    perf_test_size_range(stream, 3327, 3329);
    perf_test_size_range(stream, 3583, 3584);
    perf_test_size_range(stream, 3839, 3841);
    perf_test_size_range(stream, 4095, 4097);
    for (x = 8192; x <= 131072; x *= 2)
        perf_test_size_range(stream, x-1, x+1);
    v2v_stream_detach(stream);
    if (!v2v_disconnect(chan))
        xs_win_err(1, &xs_render_error_stderr, "disconnecting");
    return 0;
}


static int
test_stream_rtt_client(int argc, char *argv[])
{
    struct v2v_channel *chan;
    struct v2v_stream *stream;

    UNREFERENCED_PARAMETER(argc);

    if (!v2v_connect(argv[0], &chan))
        xs_win_err(1, &xs_render_error_stderr,
                   "listening on %s", argv[0]);
    if (!v2v_stream_attach(chan, &stream))
        xs_win_err(1, &xs_render_error_stderr, "attaching stream");
    perf_test_size(stream, 1, 10, 100000);
    v2v_stream_detach(stream);
    if (!v2v_disconnect(chan))
        xs_win_err(1, &xs_render_error_stderr, "disconnecting");
    return 0;
}

struct test {
    const char *name;
    const char *help;
    int (*worker)(int argc, char *argv[]);
} tests[] = {
    { "dump_server",
      "dump server.  Listen on argv[0], and dump everything which arrives",
      test_dump_server },
    { "chargen_client",
      "chargen_client.  Send trivial messages to argv[0]",
      test_chargen_client },
    { "disconnect_client",
      "Connect to argv[0], then immediately disconnect",
      test_disconnect_client },
    { "disconnect_server",
      "Listen on argv[0], wait for a client to arrive, and then immediately disconnect",
      test_disconnect_server },
    { "stream_dump_server",
      "Accept a connection, attach a stream to it, and then dump everything",
      test_stream_dump_server },
    { "stream_drop_server",
      "Accept a connection, attach a stream to it, and then discard everything",
      test_stream_drop_server },
    { "stream_chargen_client",
      "Accept a connection, attach a stream to it, and then send stuff to it",
      test_stream_chargen_client },
    { "stream_echo_server",
      "Accept a connection, attach a stream to it, and then echo everything received on it.",
      test_stream_echo_server },
    { "stream_perf_client",
      "Connect to an echo server and run some performance tests",
      test_stream_perf_client },
    { "stream_rtt_client",
      "Connect to an echo server and try to estimate the single-byte message RTT",
      test_stream_rtt_client },
    { "stream_blast_client",
      "Connect to a drop server and blast it with data",
      test_stream_blast_client },
};

#define NR_TESTS (sizeof(tests)/sizeof(tests[0]))

static struct test *
find_test(const char *name)
{
    unsigned x;
    for (x = 0; x < NR_TESTS; x++)
        if (!strcmp(tests[x].name, name))
            return &tests[x];
    return NULL;
}

static void
usage(void)
{
    unsigned x;

    printf("v2v_test {test_name} {test_arguments}\n");
    printf("where {test_name} is one of:\n");
    for (x = 0; x < NR_TESTS; x++)
        printf("\t%s\n", tests[x].name);
    printf("v2v_test /? {test_name} gives help for individual tests\n");
    exit(1);
}

int __cdecl
main(int argc, char *argv[])
{
    struct test *t;

    if (argc == 1)
        usage();
    if (!strcmp(argv[1], "/?")) {
        if (argc != 3)
            usage();
        t = find_test(argv[2]);
        if (!t)
            xs_errx(1, &xs_render_error_stderr,
                    "can't find test %s", argv[2]);
        printf("%s", t->help);
        return 0;
    } else {
        t = find_test(argv[1]);
        if (!t)
            xs_errx(1, &xs_render_error_stderr,
                    "can't find test %s", argv[1]);
        return t->worker(argc-2, argv+2);
    }
}
