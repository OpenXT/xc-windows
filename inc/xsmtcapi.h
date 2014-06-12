/* All of the MTC-private APIs exported by xevtchn.sys in one convenient
 * place.
 * Copyright 2009 Marathon Technologies, Inc
 */
#ifndef XSMTCAPI_H__
#define XSMTCAPI_H__

/* We have a dependency on xsapi.h, so make sure it is included first */
#include "xsapi.h"

/* Used to make callbacks right before the domain is suspended.
 * System is not quiesced (interrupts are still taking place and
 * other CPUs are active).  Callback is called at passive level.
 */
#define PRE_SUSPEND_CB_EARLY_TYPE   4
#define PRE_SUSPEND_CB_EARLY    wrap_SUSPEND_CB_TYPE(PRE_SUSPEND_CB_EARLY_TYPE)

/* Used to make callbacks when the system has been quiesced.
 * Only one VCPU is running and its IRQL is HIGH.
 */ 
#define PRE_SUSPEND_CB_LATE_TYPE    5
#define PRE_SUSPEND_CB_LATE     wrap_SUSPEND_CB_TYPE(PRE_SUSPEND_CB_LATE_TYPE)

/* Allows the xenbus driver to work on new requests.
 * Call from IRQL <= DISPATCH_LEVEL.
 */
XSAPI void xenbus_driver_on(void);

/* Prevents xenbus driver from working on new requests.
 * It waits for outstanding requests to finish before returning if
 * called at IRQL < DISPATCH_LEVEL
 *
 * Call from IRQL <= DISPATCH_LEVEL.
 */
XSAPI void xenbus_driver_off(void);

/* Allow PV driver code to become divergent by letting xenbus accept
 * new requests.
 * MTC: This code is needed for Marathon Technologies' Lockstep Feature.
 */
void
xenbus_mtc_allow_divergency(void);

/*
 * Set non-divergent trace levels
 */
void
XenTraceSetMtcLevels();

#endif /* !XSMTCAPI_H__ */
