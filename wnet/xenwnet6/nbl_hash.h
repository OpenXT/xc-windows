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

/* A big hash table from NET_BUFFER_LIST addresses to debug
 * information.  We can't store this directly in the NBL because
 * a) it's too big, and b) we need to get at it after we've
 * handed the NBL back to NDIS. */
#ifndef NBL_HASH__
#define NBL_HASH__

#include "scsiboot.h"
#include "config.h"

/* Disable the non-constant aggregate initialiser warning, because it
   fires basically every time you use nbl_log. */
#pragma warning(disable:4204)

#if ENABLE_NBL_LOG
void _nbl_log(ULONG_PTR nbl,
              const ULONG_PTR *params,
              unsigned nr_params);
#else
/* Use a static inline to force the parameters to be evaluated all the
   way, so we get the same side-effects and type checking regardless
   of whether ENABLE_NBL_LOG is actually defined. */
static __inline void _nbl_log(ULONG_PTR nbl,
                              const ULONG_PTR *params,
                              unsigned nr_params)
{
    UNREFERENCED_PARAMETER(nbl);
    UNREFERENCED_PARAMETER(params);
    UNREFERENCED_PARAMETER(nr_params);
}
#endif

#define nbl_log(_nbl, ...)                                           \
do {                                                                 \
    ULONG_PTR _nbl_log_params[] = { __VA_ARGS__ };                   \
    /* Check the type of _nbl. */                                    \
    XM_ASSERT( (_nbl) == (PNET_BUFFER_LIST)(_nbl) );                 \
    _nbl_log((ULONG_PTR)(_nbl),                                      \
             _nbl_log_params,                                        \
             sizeof(_nbl_log_params)/sizeof(ULONG_PTR));             \
} while (0);

void nbl_hash_init(void);
void nbl_hash_deinit(void);

#define NBL_ADAPTER_SEND                                   0x01
#define NBL_ADAPTER_SEND_RES                               0x02
#define NBL_TRANSMITTER_BOUNCE_BUFFER                      0x03
#define NBL_TRANSMITTER_BOUNCE_FAILED                      0x04
#define NBL_TRANSMITTER_BUFFER_COMPLETE                    0x05
#define NBL_TRANSMITTER_FIXUP_IP_CSUM                      0x06
#define NBL_TRANSMITTER_MAYBE_CLEANUP                      0x07
#define NBL_TRANSMITTER_MAYBE_CLEANUP_DO                   0x08
#define NBL_TRANSMITTER_MAYBE_CLEANUP_DONT                 0x09
#define NBL_TRANSMITTER_PREPARE                            0x0a
#define NBL_TRANSMITTER_PREPARE_BUFFER                     0x0b
#define NBL_TRANSMITTER_PREPARE_BUFFER2                    0x0c
#define NBL_TRANSMITTER_PREPARE_FAILED                     0x0d
#define NBL_TRANSMITTER_RESUME_EARLY                       0x0e
#define NBL_TRANSMITTER_RESUME_EARLY_BUFFER                0x0f
#define NBL_TRANSMITTER_RESUME_LATE                        0x10
#define NBL_TRANSMITTER_RESUME_LATE_BUFFER                 0x11
#define NBL_TRANSMITTER_SANITY_CHECK                       0x12
#define NBL_TRANSMITTER_SANITY_CHECK_BUFFER                0x13
#define NBL_TRANSMITTER_SEND                               0x14
#define NBL_TRANSMITTER_SEND2                              0x15
#define NBL_TRANSMITTER_SEND2_BUFFER                       0x16
#define NBL_TRANSMITTER_SEND_BUFFER                        0x17
#define NBL_TRANSMITTER_SEND_FAILED                        0x18
#define NBL_TRANSMITTER_TOO_BUSY                           0x19
#define NBL_TRANSMITTER_SANITY_SHADOW                      0x1a
#define NBL_TRANSMITTER_EMPTY_BUFFER                       0x1b
#define NBL_TRANSMITTER_FIXUP_TCP_CSUM                     0x1c

#endif /* !NBL_HASH__ */
