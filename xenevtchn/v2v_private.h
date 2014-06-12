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

#ifndef V2V_PRIVATE_H__
#define V2V_PRIVATE_H__

int v2v_string_to_num(const char *str, int *val);

char *v2v_string_dup(const char *src, BOOLEAN np);

NTSTATUS v2v_xenstore_readv_string(char **val_out, xenbus_transaction_t xbt, ...);

NTSTATUS v2v_xenstore_printfv(xenbus_transaction_t xbt, ...);

NTSTATUS v2v_xenstore_watchv(struct xenbus_watch_handler **xwh_out, PKEVENT event, ...);
NTSTATUS v2v_xenstore_watchv_cb(struct xenbus_watch_handler **xwh_out, void (*watch_cb)(void *), void *ctx, ...);

enum xenstore_scatter_type {
    xenstore_scatter_type_bad,
    xenstore_scatter_type_grant_ref = 0xbeef,
    xenstore_scatter_type_evtchn_port,
    xenstore_scatter_type_string,
    xenstore_scatter_type_int
};
NTSTATUS v2v_xenstore_scatter(xenbus_transaction_t xbt, const char *prefix, ...);

enum xenstore_gather_type {
    xenstore_gather_type_bad,
    xenstore_gather_type_alien_grant_ref = 0xfeeb,
    xenstore_gather_type_alien_evtchn_port,
    xenstore_gather_type_int
};
NTSTATUS v2v_xenstore_gather(xenbus_transaction_t xbt, const char *prefix, ...);

NTSTATUS v2v_xenops_grant_map(volatile void **map_out,
                              struct grant_map_detail **detail_out,
                              DOMAIN_ID domid,
                              unsigned nr_grefs,
                              ALIEN_GRANT_REF *grefs,
                              BOOLEAN readonly);
void v2v_xenops_grant_unmap(void *map, struct grant_map_detail *detail);

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define PHYS_TO_PFN(pa) (((pa).LowPart>>PAGE_SHIFT) | ((pa).HighPart<<(32-PAGE_SHIFT)))
#define V2V_TAG 'v2vx'

#endif /* !V2V_PRIVATE_H__ */
