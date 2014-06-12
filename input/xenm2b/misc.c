/*
 * Copyright (c) 2012 Citrix Systems, Inc.
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

// Xen Windows PV M2B Bus Driver misc helper routines.

#include <ntddk.h>
#include <ntstrsafe.h>
#include <hidport.h>
#include "xmou.h"
#include "input.h"
#include "xenm2b.h"

VOID
XenM2BSetPnPState(PXENM2B_DEVICE_PNP_STATE pDevicePnPState,
                  XENM2B_PNP_STATE PnPState)
{
    ExAcquireFastMutex(&pDevicePnPState->PnPStateMutex);

    // We can never transition out of the deleted state
    ASSERT(pDevicePnPState->CurrentPnPState != PnPStateDeleted);

    pDevicePnPState->PreviousPnPState = pDevicePnPState->CurrentPnPState;
    pDevicePnPState->CurrentPnPState = PnPState;

    ExReleaseFastMutex(&pDevicePnPState->PnPStateMutex);
}

BOOLEAN
XenM2BRestorePnPState(PXENM2B_DEVICE_PNP_STATE pDevicePnPState,
                      XENM2B_PNP_STATE PnPState)
{
    BOOLEAN Restored = FALSE;

    ExAcquireFastMutex(&pDevicePnPState->PnPStateMutex);

    if (pDevicePnPState->CurrentPnPState == PnPState) {
        pDevicePnPState->CurrentPnPState = pDevicePnPState->PreviousPnPState;
        Restored = TRUE;
    }

    ExReleaseFastMutex(&pDevicePnPState->PnPStateMutex);

    return Restored;
}

XENM2B_PNP_STATE
XenM2BGetPnPState(PXENM2B_DEVICE_PNP_STATE pDevicePnPState)
{
    XENM2B_PNP_STATE PnPState;

    ExAcquireFastMutex(&pDevicePnPState->PnPStateMutex);
    PnPState = pDevicePnPState->CurrentPnPState;
    ExReleaseFastMutex(&pDevicePnPState->PnPStateMutex);

    return PnPState;
}

#if defined(NO_XENUTIL)
XSAPI VOID
___XenTrace(XEN_TRACE_LEVEL level,
            __in_ecount(module_size) PCSTR module,
            size_t module_size,
            PCSTR fmt,
            va_list args)
{
#define MODULE_COL_WIDTH 8
    NTSTATUS status;
    char buf[256];
    char *msg;
    char *prefix;
    size_t prefix_size;

    // Just the bits that print to DbgPrint()
    memset(buf, 0, sizeof (buf));

    msg = buf;

    if (module_size < MODULE_COL_WIDTH) {
        size_t blank_size;

        blank_size = MODULE_COL_WIDTH - module_size;
        memset(msg, ' ', blank_size);
        msg += blank_size;
    }

    memcpy(msg, module, module_size);
    msg += module_size;

    *msg++ = ':';
    *msg++ = ' ';

#define _DEFINE_PREFIX(_prefix)             \
    {                                       \
        prefix = _prefix;                   \
        prefix_size = sizeof (_prefix) - 1; \
    }

    if (level == XenTraceLevelWarning) {
        _DEFINE_PREFIX("WARNING");
    } else if (level == XenTraceLevelError) {
        _DEFINE_PREFIX("ERROR");
    } else if (level == XenTraceLevelCritical) {
        _DEFINE_PREFIX("CRITICAL");
    } else if (level == XenTraceLevelBugCheck) {
        _DEFINE_PREFIX("BUG: ");
    } else {
        _DEFINE_PREFIX("");
    }

    if (prefix_size != 0) {
        memcpy(msg, prefix, prefix_size);
        msg += prefix_size;

        *msg++ = ':';
        *msg++ = ' ';
    }

    status = RtlStringCbVPrintfA(msg, sizeof (buf) - (msg - buf), fmt, args);
    if (!NT_SUCCESS(status)) {
        return;
    }

    // Make sure the buffer is NUL terminated before we pass it on
    buf[sizeof(buf) - 1] = 0;

    DbgPrint("%p %s", KeGetCurrentThread(), buf);
}
#endif

#if defined(M2B_DEBUG_EVENT_TRACE)

static int g_EnableDebugEventTrace = 1;

typedef struct _XENM2B_CODE_STRING {
    USHORT      Code;
    const char *pString;
} XENM2B_CODE_STRING;

static const XENM2B_CODE_STRING SynStrings[] = {
    {XMOU_CODE_SYN_REPORT, "SYN_REPORT"},
    {XMOU_CODE_SYN_MT_REPORT, "SYN_MT_REPORT"},
    {0xffff, NULL}
};

static const XENM2B_CODE_STRING BtnStrings[] = {
    {XMOU_CODE_BTN_LEFT, "BTN_LEFT"},
    {XMOU_CODE_BTN_RIGHT, "BTN_RIGHT"},
    {XMOU_CODE_BTN_MIDDLE, "BTN_MIDDLE"},
    {XMOU_CODE_BTN_SIDE, "BTN_SIDE"},
    {XMOU_CODE_BTN_EXTRA, "BTN_EXTRA"},
    {XMOU_CODE_BTN_FORWARD, "BTN_FORWARD"},
    {XMOU_CODE_BTN_BACK, "BTN_BACK"},
    {XMOU_CODE_BTN_TASK, "BTN_TASK"},
    {XMOU_CODE_BTN_TOOL_PEN, "BTN_PEN"},
    {XMOU_CODE_BTN_TOOL_RUBBER, "BTN_RUBBER"},
    {XMOU_CODE_BTN_TOOL_BRUSH, "BTN_BRUSH"},
    {XMOU_CODE_BTN_TOOL_PENCIL, "BTN_PENCIL"},
    {XMOU_CODE_BTN_TOOL_AIRBRUSH, "BTN_AIRBRUSH"},
    {XMOU_CODE_BTN_TOOL_FINGER, "BTN_FINGER"},
    {XMOU_CODE_BTN_TOOL_MOUSE, "BTN_MOUSE"},
    {XMOU_CODE_BTN_TOOL_LENS, "BTN_LENS"},
    {XMOU_CODE_BTN_TOUCH, "BTN_TOUCH"},
    {XMOU_CODE_BTN_STYLUS, "BTN_STYLUS"},
    {XMOU_CODE_BTN_STYLUS2, "BTN_STYLUS2"},
    {0xffff, NULL}
};

static const XENM2B_CODE_STRING RelStrings[] = {
    {XMOU_CODE_REL_X, "REL_X"},
    {XMOU_CODE_REL_Y, "REL_Y"},
    {XMOU_CODE_REL_WHEEL, "REL_WHEEL"},
    {0xffff, NULL}
};

static const XENM2B_CODE_STRING AbsStrings[] = {
    {XMOU_CODE_ABS_X, "ABS_X"},
    {XMOU_CODE_ABS_Y, "ABS_Y"},
    {XMOU_CODE_ABS_PRESSURE, "ABS_PESSURE"},
    {XMOU_CODE_ABS_MT_SLOT, "ABS_MT_SLOT"},
    {XMOU_CODE_ABS_MT_POSITION_X, "ABS_MT_POSITION_X"},
    {XMOU_CODE_ABS_MT_POSITION_Y, "ABS_MT_POSITION_Y"},
    {XMOU_CODE_ABS_MT_TRACKING_ID, "ABS_MT_TRACKING_ID"},
    {XMOU_CODE_ABS_MT_PRESSURE, "ABS_MT_PRESSURE"},
    {0xffff, NULL}
};

static const XENM2B_CODE_STRING DevStrings[] = {
    {XMOU_CODE_DEV_SET, "DEV_SET"},
    {XMOU_CODE_DEV_CONF, "DEV_CONF"},
    {XMOU_CODE_DEV_RESET, "DEV_RESET"},
    {0xffff, NULL}
};

static const char*
XenM2BCodeString(ULONG TypeCode)
{
    const XENM2B_CODE_STRING *pStringArr;

    switch (XENMOU2_GET_TYPE(TypeCode)) {
    case XMOU_TYPE_EV_SYN:
        pStringArr = SynStrings;
        break;
    case XMOU_TYPE_EV_KEY:
        pStringArr = BtnStrings;
        break;
    case XMOU_TYPE_EV_REL:
        pStringArr = RelStrings;
        break;
    case XMOU_TYPE_EV_ABS:
        pStringArr = AbsStrings;
        break;
    case XMOU_TYPE_EV_DEV:
        pStringArr = DevStrings;
        break;
    default:
        return "UNKNOWN";
    };

    while (pStringArr->pString != NULL) {
        if (pStringArr->Code == XENMOU2_GET_CODE(TypeCode))
            return pStringArr->pString;
        pStringArr++;
    }

    return "UNKOWN";
}

VOID
XenM2BDebugEventTrace(PXENMOU2_EVENT pEvent)
{
    if (g_EnableDebugEventTrace == 0)
        return;

    switch (XENMOU2_GET_TYPE(pEvent->TypeCode)) {
    case XMOU_TYPE_EV_SYN:
        DbgPrint("***SYN:%s TC: 0x%x V: %d\n", XenM2BCodeString(pEvent->TypeCode),
                 pEvent->TypeCode, pEvent->Value);
        break;
    case XMOU_TYPE_EV_KEY:
        if (XENMOU2_GET_CODE(pEvent->TypeCode) > XMOU_CODE_KEY_RESERVED) {
            DbgPrint("***BTN:%s TC: 0x%x V: %d\n", XenM2BCodeString(pEvent->TypeCode),
                     pEvent->TypeCode, pEvent->Value);            
            break;
        }        
        // Else it is a KB key
        DbgPrint("***KEY:%x TC: 0x%x V: %d\n", XENMOU2_GET_CODE(pEvent->TypeCode),
                 pEvent->TypeCode, pEvent->Value);
        break;
    case XMOU_TYPE_EV_REL:
        DbgPrint("***REL:%s TC: 0x%x V: %d\n", XenM2BCodeString(pEvent->TypeCode),
                 pEvent->TypeCode, pEvent->Value);
        break;
    case XMOU_TYPE_EV_ABS:
        DbgPrint("***ABS:%s TC: 0x%x V: %d\n", XenM2BCodeString(pEvent->TypeCode),
                 pEvent->TypeCode, pEvent->Value);
        break;
    case XMOU_TYPE_EV_DEV:
        DbgPrint("***DEV:%s TC: 0x%x V: %d\n", XenM2BCodeString(pEvent->TypeCode),
                 pEvent->TypeCode, pEvent->Value);
        break;
    default:
        DbgPrint("***UNK:UNKOWN TC: 0x%x V: %d\n", pEvent->TypeCode, pEvent->Value);
    };
}

#endif
