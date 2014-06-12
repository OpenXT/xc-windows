/******************************************************************************
 * sched.h
 *
 * Scheduler state interactions
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (c) 2005, Keir Fraser <keir@xensource.com>
 */

#ifndef __XEN_PUBLIC_SCHED_H__
#define __XEN_PUBLIC_SCHED_H__

/*
 * Prototype for this hypercall is:
 *  int sched_op(int cmd, unsigned long arg)
 * @cmd == SCHEDOP_??? (scheduler operation).
 * @arg == Operation-specific extra argument(s).
 */

/*
 * Voluntarily yield the CPU.
 * @arg == 0.
 */
#define SCHEDOP_yield       0

/*
 * Block execution of this VCPU until an event is received for processing.
 * If called with event upcalls masked, this operation will atomically
 * reenable event delivery and check for pending events before blocking the
 * VCPU. This avoids a "wakeup waiting" race.
 * @arg == 0.
 */
#define SCHEDOP_block       1

/*
 * Halt execution of this domain (all VCPUs) and notify the system controller.
 * @arg == SHUTDOWN_??? (reason for shutdown).
 */
#define SCHEDOP_shutdown    2
struct sched_shutdown {
    unsigned int reason; /* SHUTDOWN_* */
};


/*
 * Poll a set of event-channel ports. Return when one or more are pending. An
 * optional timeout may be specified.
 * @arg == pointer to sched_poll structure.
 */
#define SCHEDOP_poll        3
struct sched_poll {
    uint32_t *ports;
/* XC-7783 Do not pad the structure for 32b. 64b Xen uses compat 32b code to deal
 * with differences in bit-edness in guests. This was effectively making the timeout
 * zero and causing hangs.
#ifndef AMD64
    uint32_t pad;
#endif
 */
    unsigned int nr_ports;
    ULONGLONG timeout;
};
typedef struct sched_poll sched_poll_t;

/* 
 * Xen 4.3: Not sure where that crazy feeb came from but
 * the code that uses it uses the compat value which matches
 * the stuff in 4.3.
 */
#define SCHEDOP_shutdown_code_compat 5
#define SCHEDOP_shutdown_code        0xfeeb0000

/*
 * Reason codes for SCHEDOP_shutdown. These may be interpreted by controller
 * software to determine the appropriate action. For the most part, Xen does
 * not care about the shutdown code.
 */
#define SHUTDOWN_poweroff   0  /* Domain exited normally. Clean up and kill. */
#define SHUTDOWN_reboot     1  /* Clean up, kill, and then restart.          */
#define SHUTDOWN_suspend    2  /* Clean up, save suspend info, kill.         */
#define SHUTDOWN_crash      3  /* Tell controller we've crashed.             */

#endif /* __XEN_PUBLIC_SCHED_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
