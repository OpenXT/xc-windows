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

#include "xenevtchn.h"
#include "xsapi.h"
#include "scsiboot.h"

#include "../xenutil/xenbus.h"

static NTSTATUS
WithBackendPath(xenbus_transaction_t xbt,
                struct xenbus_device *xd,
                NTSTATUS (*cb)(xenbus_transaction_t xbt,
                               void *ctxt,
                               char *backend_path),
                void *ctxt)
{
    BOOLEAN end_transaction;
    NTSTATUS result;
    char *backend;

retry:

    /* We always need to do this inside a transaction, in case the
       backend moves underneath us. */
    if (is_nil_xenbus_transaction_t(xbt)) {
        end_transaction = TRUE;
        xenbus_transaction_start(&xbt);
    } else {
        end_transaction = FALSE;
    }

    backend = FindBackendPath(xbt, xd);
    if (backend == NULL) {
        result = STATUS_INSUFFICIENT_RESOURCES;
    } else {
        result = cb(xbt, ctxt, backend);
        XmFreeMemory(backend);
    }

    if (end_transaction) {
        result = xenbus_transaction_end(xbt, FALSE);
        if (result == STATUS_RETRY) {
            xbt = XBT_NIL;
            goto retry;
        }
    }

    return result;
}

struct xenbus_read_backend_feature_flag_ctxt {
    PCSTR node;
    BOOLEAN *res;
};

static NTSTATUS
_xenbus_read_backend_feature_flag(xenbus_transaction_t xbt,
                                  void *_ctxt,
                                  char *backend)
{
    struct xenbus_read_backend_feature_flag_ctxt *ctxt = _ctxt;
    return xenbus_read_feature_flag(xbt, backend, ctxt->node, ctxt->res);
}

XSAPI NTSTATUS
xenbus_read_backend_feature_flag(xenbus_transaction_t xbt,
                                 PDEVICE_OBJECT pdo,
                                 PCSTR node,
                                 BOOLEAN *res)
{
    struct xenbus_read_backend_feature_flag_ctxt ctxt;
    NTSTATUS stat;

    XM_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    ctxt.node = node;
    ctxt.res = res;

    stat = WithBackendPath(xbt,
                           GetXenbusDeviceForPdo(pdo),
                           _xenbus_read_backend_feature_flag,
                           &ctxt);
    if (!NT_SUCCESS(stat))
        *res = FALSE;
    return stat;
}


struct xenbus_read_backend_bin_ctxt {
    PCSTR node;
    void **res;
    size_t *size;
};

static NTSTATUS
_xenbus_read_backend_bin(xenbus_transaction_t xbt,
                         void *_ctxt,
                         char *backend)
{
    struct xenbus_read_backend_bin_ctxt *ctxt = _ctxt;

    return xenbus_read_bin(xbt, backend, ctxt->node, ctxt->res, ctxt->size);
}

XSAPI NTSTATUS
xenbus_read_backend_bin(xenbus_transaction_t xbt,
                        PDEVICE_OBJECT pdo,
                        PCSTR node,
                        void **res,
                        size_t *size)
{
    struct xenbus_read_backend_bin_ctxt ctxt;
    NTSTATUS stat;

    XM_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);

    *res = NULL;
    *size = 0;
    ctxt.node = node;
    ctxt.res = res;
    ctxt.size = size;

    stat = WithBackendPath(xbt,
                           GetXenbusDeviceForPdo(pdo),
                           _xenbus_read_backend_bin,
                           &ctxt);
    if (!NT_SUCCESS(stat)) {
         XmFreeMemory(*res);
         *res = NULL;
         *size = 0;
    }
    return stat;
}

XSAPI NTSTATUS
xenbus_read_backend(xenbus_transaction_t xbt,
                    PDEVICE_OBJECT pdo,
                    PCSTR node,
                    PSTR *pres)
{
    void *raw, *cooked;
    NTSTATUS stat;
    size_t raw_size;

    *pres = NULL;

    stat = xenbus_read_backend_bin(xbt, pdo, node, &raw, &raw_size);
    if (!NT_SUCCESS(stat))
        return stat;
    cooked = XmAllocateMemory(raw_size + 1);
    if (!cooked) {
        XmFreeMemory(raw);
        xenbus_fail_transaction(xbt, STATUS_INSUFFICIENT_RESOURCES);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memcpy(cooked, raw, raw_size);
    ((char *)cooked)[raw_size] = 0;
    *pres = cooked;
    XmFreeMemory(raw);
    return STATUS_SUCCESS;
}
