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

// device.c - Xen Windows PV M2B Bus interface

#include <ntddk.h>
#include <ntstrsafe.h>
#include <hidport.h>
#include "input.h"
#include "xmou.h"
#include "xenm2b.h"
#include "hid_defs.h"

typedef struct _XENM2B_HID_REPORTS {
    // Device pointer reports
    MouseReportData Mouse;
    TabletReportData Tablet;
    // Multitouch digitizer report
    MultitouchReportData Multitouch;
    // Digitizer report set
    StylusReportData Stylus;
    PuckReportData Puck;
    FingerReportData Finger;

} XENM2B_HID_REPORTS, *PXENM2B_HID_REPORTS;

typedef struct _XENM2B_MT_STATE {
    MultiFingerData Finger;
    BOOLEAN FingerDown;
    BOOLEAN Lifted;
} XENM2B_MT_STATE;

typedef struct _XENM2B_HID_CONTEXT {
    // Backpointer to PDO owner extension
    PXENM2B_PDO_EXTENSION pOwnerExt;

    // The HID device types this actual device supports
    ULONG DevTypes;

    // Device reports
    XENM2B_HID_REPORTS Reports;

    // Current report ID, the next to be sent.
    ULONG CurrentReportID;

    // Current Digitizer RepordID, the last tools selected.
    ULONG CurrentDigitizerID;

    // Current MT Slot (Finger) in use.
    ULONG CurrentMTSlot;

    // MT Current Tracking ID
    UCHAR CurrentMTTrackingID;

    // MT current mode
    UCHAR CurrentMTMode;

    // MT Max contact count value (Feature)
    UCHAR ContactCountMax;

    // Track the state of finger presses and moves from XENMOU2 interface
    XENM2B_MT_STATE FingersState[MT_FINGER_MAX_COUNT];

    // XENMOU2 Device state
    XENMOU2_DEV_CONFIG DevConfig;
    ULONG              SlotNumber;

    // Reference counter
    LONG      RefCount;

    // The basic HID descriptors
    HID_DEVICE_ATTRIBUTES HidAttributes;
    HID_DESCRIPTOR        HidDescriptor;

    // Report descriptor (possibly built from multiple descriptors
    // from above) is loaded at the end of the HID context block.
    ULONG ReportDescriptorLength;
    UCHAR ReportDescriptor[0];
} XENM2B_HID_CONTEXT, *PXENM2B_HID_CONTEXT;

typedef struct _XENM2B_DEV_CONTEXT {
    BOOLEAN      Create; // TRUE->DEV_CONF, FALSE->DEV_RESET
    ULONG        SlotNumber;
    PIO_WORKITEM pWorkItem;
} XENM2B_DEV_CONTEXT, *PXENM2B_DEV_CONTEXT;

static BOOLEAN
XenM2BIsMouseButton(ULONG Button)
{
    return (BOOLEAN)(Button >= MOUSE_BUTTON_START && Button < (MOUSE_BUTTON_START + 7));
}

static UCHAR
XenM2BSetButtonFlags(UCHAR Base, ULONG Button, UCHAR State)
{
    if (Button > 8)
        return (UCHAR)Base;
    if (State)
        return (UCHAR)(Base | (1 << (UCHAR)Button));
    else
        return (UCHAR)(Base & ~(1 << (UCHAR)Button));
}

static BOOLEAN
XenM2BIsModifierKey(UCHAR Usage)
{
    return (Usage >= USAGE_LEFT_SHIFT && Usage <= USAGE_RIGHT_WINDOWS);
}

static UCHAR
XenM2BKeyToUsage(ULONG key)
{
    int i;

    // Map linux\input.h KEY_* to HID usages
    for (i = 0; KeyMap[i]; i += 2) {
        if (KeyMap[i + 1] == key)
            return KeyMap[i];
    }

    return 0;
}
static int
XenM2BUpdateKeyArray(PUCHAR Array, UCHAR Usage, UCHAR State)
{
    int i, ret = 0;

    for (i = 0; i < 6; ++i) {
        if (Array[i] == Usage) {
            if (!State)
                ret = 1;
            Array[i] = 0;
        }
    }

    if (State) {
        for (i = 0; i < 6; ++i) {
            if (Array[i] == 0) {
                Array[i] = Usage;
                ret = 1;
                break;
            }
        }
    }

    return ret;
}

static NTSTATUS
XenM2BSendReport(PXENM2B_HID_CONTEXT pHidCtx, PVOID pBuffer, ULONG Length)
{
    PXENM2B_INTERFACE pInterface;
    NTSTATUS          Status;
    KIRQL             Irql;

    pInterface = &pHidCtx->pOwnerExt->Interface;

    // All report activity is synchronized in the DPC so there is no lock
    // here. If the FDO for a given PDO that M2B owns is going away, the
    // bus will know about it beforehand because it has set the Missing flag
    // so there is no chance of a call to a xenhid FDO that disappeared.
    //
    // TODO: the SendReport handler in the xenhid driver supports being
    // called at DPC level. But this seems to cause a crash at DISPATCH_IRQL
    // in DispatchInternalIoctl in xenhid.sys. Need to investigate.    
    if ((pHidCtx->pOwnerExt->Missing)||(!pInterface->Referenced)) {
        // The Bus is removing the PDO or the Interface was dereferenced
        // by the xenhid FDO.        
        return STATUS_UNSUCCESSFUL;
    }

    Status = pInterface->pXenHidOperations->pSendReport(pInterface->pXenHidContext,
                                                        pBuffer,
                                                        Length);
    return Status;
}

PHID_DEVICE_ATTRIBUTES
XenM2BGetHidAttributes(PXENM2B_HID_CONTEXT pHidCtx)
{
    return &pHidCtx->HidAttributes;
}

PHID_DESCRIPTOR
XenM2BGetHidDescriptor(PXENM2B_HID_CONTEXT pHidCtx)
{
    return &pHidCtx->HidDescriptor;
}

PUCHAR
XenM2BGetReportDescriptor(PXENM2B_HID_CONTEXT pHidCtx, PULONG pLengthOut)
{
    *pLengthOut = pHidCtx->ReportDescriptorLength;
	return (PUCHAR)(&pHidCtx->ReportDescriptor[0]);
}

NTSTATUS
XenM2BGetFeature(PXENM2B_HID_CONTEXT pHidCtx, PHID_XFER_PACKET pHidPacket, ULONG_PTR *pLength)
{
    NTSTATUS Status = STATUS_NOT_SUPPORTED;

    TraceDebug(("%s: Entry Name:%s Report:%d\n", __FUNCTION__, pHidCtx->DevConfig.Name, pHidPacket->reportId));

    *pLength = 0;

    // At present only multitouch devices have any features to query.
    if (pHidCtx->DevTypes == DEVICE_TYPE_MULTITOUCH) {
        if (pHidPacket->reportBufferLen > 0) {

            switch (pHidPacket->reportId) {
            
            case REPORT_ID_MT_MAX_COUNT:
                pHidPacket->reportBuffer[0] = pHidCtx->ContactCountMax;
                *pLength = 1;
                Status = STATUS_SUCCESS;
                break;

            case REPORT_ID_CONFIG:
                pHidPacket->reportBuffer[0] = pHidCtx->CurrentMTMode;
                *pLength = 1;
                Status = STATUS_SUCCESS;
                break;

            default:
                Status = STATUS_NOT_SUPPORTED;
                break;
            }
        }
    }

    TraceDebug(("%s: Exit Status:%x\n", __FUNCTION__, Status));
    return Status;
}

NTSTATUS
XenM2BSetFeature(PXENM2B_HID_CONTEXT pHidCtx, PHID_XFER_PACKET pHidPacket, ULONG_PTR *pLength)
{
    NTSTATUS Status = STATUS_NOT_SUPPORTED;

    TraceDebug(("%s: Entry Name:%s Report:%d\n", __FUNCTION__, pHidCtx->DevConfig.Name, pHidPacket->reportId));

    *pLength = 0;

    // At present only multitouch devices have any features to set.
    if (pHidCtx->DevTypes == DEVICE_TYPE_MULTITOUCH) {
        if (pHidPacket->reportBufferLen > 0) {

            switch (pHidPacket->reportId) {
            
            //case REPORT_ID_MT_MAX_COUNT:
            //    pHidPacket->reportBuffer[0] = pHidCtx->ContactCountMax;
            //    *pLength = 1;
            //    Status = STATUS_SUCCESS;
            //    break;

            case REPORT_ID_CONFIG:
                if (pHidPacket->reportBuffer[0] <= 2) {
                    pHidCtx->CurrentMTMode = pHidPacket->reportBuffer[0];
                    *pLength = 1;
                    Status = STATUS_SUCCESS;
                }
                break;

            default:
                Status = STATUS_NOT_SUPPORTED;
                break;
            }
        }
    }

    TraceDebug(("%s: Exit Status:%x\n", __FUNCTION__, Status));
    return Status;
}

NTSTATUS
XenM2BGetString(ULONG StringId, PUCHAR* pString, ULONG_PTR* pLength)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    USHORT HidId = (USHORT) StringId & 0xff;
    ULONG Index;

    for (Index = 0; CitrixHidStrings[Index].Id != 0; ++Index) {
        if (HidId == CitrixHidStrings[Index].Id) {
            if (*pLength >= CitrixHidStrings[Index].Length) {
                *pString = CitrixHidStrings[Index].String;
                *pLength = CitrixHidStrings[Index].Length;
                Status = STATUS_SUCCESS;
            }
            else {
                Status = STATUS_INVALID_BUFFER_SIZE;
            }
            break;
        }
    }
    return Status;
}

static VOID
XenM2BAddRefHidContext(PXENM2B_HID_CONTEXT pHidCtx)
{
    InterlockedIncrement(&pHidCtx->RefCount);
}

VOID
XenM2BReleaseHidContext(PXENM2B_HID_CONTEXT pHidCtx)
{
    ULONG Count = InterlockedDecrement(&pHidCtx->RefCount);
    
    ASSERT(pHidCtx->RefCount >= 0);

    if (Count == 0)
        ExFreePoolWithTag(pHidCtx, XENM2B_POOL_TAG);
}

static VOID
XenM2BResetDigitizerTools(PXENM2B_HID_REPORTS pReports)
{
    pReports->Stylus.X = pReports->Stylus.Y = WORD_NULL_VALUE;
    pReports->Stylus.Buttons = 0;
    pReports->Puck.X = pReports->Puck.Y = WORD_NULL_VALUE;
    pReports->Puck.Buttons = 0;
    pReports->Finger.X = pReports->Finger.Y = WORD_NULL_VALUE;
    pReports->Finger.Buttons = 0;
}

static VOID
XenM2BClassifyReport(PXENM2B_FDO_EXTENSION pFdoExt)
{
    PXENM2B_HID_CONTEXT pHidCtx = pFdoExt->pActiveHidCtx;

    if (pHidCtx) {
        switch (pHidCtx->DevTypes) {
        case DEVICE_TYPE_MOUSE:
            pHidCtx->CurrentReportID = REPORT_ID_MOUSE;
            break;

        case DEVICE_TYPE_TABLET:
            pHidCtx->CurrentReportID = REPORT_ID_TABLET;
            break;

        case DEVICE_TYPE_MULTITOUCH:
            // For the multi touch device we need to check the current Device mode and set the report 
            // id accordingly, we may switch between REPORT_ID_MULTITOUCH and REPORT_ID_FINGER
            if (0 == pHidCtx->CurrentMTMode)
                pHidCtx->CurrentReportID = REPORT_ID_FINGER;
            else                
                pHidCtx->CurrentReportID = REPORT_ID_MULTITOUCH;
            break;

        case DEVICE_TYPE_DIGITIZER:
            pHidCtx->CurrentReportID = pHidCtx->CurrentDigitizerID;
            break;

        default:
            pHidCtx->CurrentReportID = REPORT_ID_INVALID;
            break;
        }
    }
}

static VOID
XenM2BPrepareMTReport(PXENM2B_HID_CONTEXT pHidCtx)
{
    PXENM2B_HID_REPORTS pReports;
    ULONG               i, j;
    MultiFingerData*    pFinger;

    pReports = &pHidCtx->Reports;

    for (i = 0, j = 0; i < MT_FINGER_MAX_COUNT; i++) {
        if ((pHidCtx->FingersState[i].FingerDown)||
            (pHidCtx->FingersState[i].Lifted)) {
            // Copy the state for this slot. Note that each Finger
            // report must be placed sequentially in the Report for
            // Windows.
            // Report lift action too with buttons cleared and last
            // X/Y position.
            RtlCopyMemory(&pReports->Multitouch.Fingers[j],
                          &pHidCtx->FingersState[i].Finger,
                          sizeof(MultiFingerData));
            j++;
            pHidCtx->FingersState[i].Lifted = FALSE;
        }
    }
    pReports->Multitouch.ScanTime += 10;    // 1 millisec
    pReports->Multitouch.ContactCount = (UCHAR)j;

    //TraceDebug(("%s: ReportID:%x Count:%d\n", __FUNCTION__,
    //    pReports->Multitouch.ReportID, pReports->Multitouch.ContactCount));
    //for (i = 0; i < pReports->Multitouch.ContactCount; ++i) {
    //    pFinger = &pHidCtx->Reports.Multitouch.Fingers[i];
    //    TraceDebug(("%s: Finger:%d %x X:%x Y:%x\n", __FUNCTION__, 
    //        pFinger->ContactID, pFinger->Buttons, pFinger->X, pFinger->Y));
    //}
}

static BOOLEAN
XenM2BProcessSyn(PXENM2B_FDO_EXTENSION pFdoExt, XENMOU2_EVENT *pEvent)
{
    PXENM2B_HID_CONTEXT pHidCtx = pFdoExt->pActiveHidCtx;
    PXENM2B_HID_REPORTS pReports;
    NTSTATUS            Status;

    // Might happen if we got spurious events with no PDOs configured.
    if (pHidCtx == NULL)
        return TRUE;

    if (XENMOU2_GET_CODE(pEvent->TypeCode) != XMOU_CODE_SYN_REPORT)
        return TRUE; // not sure what to do with anything else

    switch (pHidCtx->CurrentReportID) {

    case REPORT_ID_MOUSE:
        //TraceDebug(("%s: REPORT_ID_MOUSE X:%x Y:%x Btn:%x\n", __FUNCTION__,
        //    pHidCtx->Reports.Mouse.X, pHidCtx->Reports.Mouse.Y, pHidCtx->Reports.Mouse.Buttons));
        Status = XenM2BSendReport(pHidCtx,
                                  &pHidCtx->Reports.Mouse,
                                  sizeof(MouseReportData));
        break;

    case REPORT_ID_TABLET:
        //TraceDebug(("%s: REPORT_ID_TABLET X:%x Y:%x Btn:%x\n", __FUNCTION__,
        //    pHidCtx->Reports.Tablet.X, pHidCtx->Reports.Tablet.Y, pHidCtx->Reports.Tablet.Buttons));
        Status = XenM2BSendReport(pHidCtx,
                                  &pHidCtx->Reports.Tablet,
                                  sizeof(TabletReportData));
        break;

    case REPORT_ID_MULTITOUCH:
        //TraceDebug(("%s: REPORT_ID_MULTITOUCH\n", __FUNCTION__));
        XenM2BPrepareMTReport(pHidCtx);
        Status = XenM2BSendReport(pHidCtx,
                                  &pHidCtx->Reports.Multitouch,
                                  sizeof(MultitouchReportData));
        break;

    case REPORT_ID_STYLUS:
        Status = XenM2BSendReport(pHidCtx,
                                  &pHidCtx->Reports.Stylus,
                                  sizeof(StylusReportData));
        break;

    case REPORT_ID_PUCK:
        Status = XenM2BSendReport(pHidCtx,
                                  &pHidCtx->Reports.Puck,
                                  sizeof(PuckReportData));
        break;

    case REPORT_ID_FINGER:
        Status = XenM2BSendReport(pHidCtx,
                                  &pHidCtx->Reports.Finger,
                                  sizeof(FingerReportData));
        break;

    default:
        Status = STATUS_UNSUCCESSFUL;
        break;
    };

    // The only return status that changes the processing flow is STATUS_DEVICE_NOT_READY
    // which indicates there are no IO packets queue in xenhid to be loaded. All other
    // failure cases including STATUS_INVALID_BUFFER_SIZE allow processing to continue.
    if (Status == STATUS_DEVICE_NOT_READY)
        return FALSE;

    // The SYN was completed and the report sent; reset the reports for the next event.
    // Only reset the report that was just sent. In most cases this means clearing the
    // co-ordinate values and preserving the Buttons and Report ID.
    pReports = &pHidCtx->Reports;
    switch (pHidCtx->CurrentReportID) {

    case REPORT_ID_MOUSE:
        pReports->Mouse.X = pReports->Mouse.Y = pReports->Mouse.Z = 0;
        break;

    case REPORT_ID_TABLET:
        pReports->Tablet.X = pReports->Tablet.Y = pReports->Tablet.Z = 0;
        break;

    case REPORT_ID_MULTITOUCH:
        // Clear all the finger values, reset ContactCount.
        RtlZeroMemory(&pReports->Multitouch.Fingers[0], MT_FINGER_MAX_COUNT * sizeof(MultiFingerData));
        pReports->Multitouch.ContactCount = 0;
        // State of finger contacts tracked in the FingersState block
        break;

    case REPORT_ID_STYLUS:
        pReports->Stylus.X = pReports->Stylus.Y = 0;
        break;

    case REPORT_ID_PUCK:
        pReports->Puck.X = pReports->Puck.Y = 0;
        break;

    case REPORT_ID_FINGER:
        pReports->Finger.X = pReports->Finger.Y = 0;
        break;

    default:
        break;
    };

    // Reset the CurrentReportID for the next reporting cycle. The CurrentDigitizerID
    // and CurrentMTSlot are carried over to the next report.
    pHidCtx->CurrentReportID = DWORD_NULL_VALUE;

    return TRUE;
}

static VOID
XenM2BProcessKey(PXENM2B_FDO_EXTENSION pFdoExt, XENMOU2_EVENT *pEvent)
{
    UNREFERENCED_PARAMETER(pFdoExt);
    UNREFERENCED_PARAMETER(pEvent);
    // Not currently processing keyboard input - quietly pass it by.
}

static VOID
XenM2BProcessBtn(PXENM2B_FDO_EXTENSION pFdoExt, XENMOU2_EVENT *pEvent)
{
    PXENM2B_HID_CONTEXT pHidCtx = pFdoExt->pActiveHidCtx;
    PXENM2B_HID_REPORTS pReports;
    UCHAR               ButtonBits = 0;
    PUCHAR              pCurrentDigitizerButtons;

    if (pHidCtx == NULL)
        return;

    if (pHidCtx->CurrentReportID == DWORD_NULL_VALUE)
        XenM2BClassifyReport(pFdoExt);

    if (pHidCtx->CurrentDigitizerID == REPORT_ID_PUCK)
        pCurrentDigitizerButtons = &pHidCtx->Reports.Stylus.Buttons;
    if (pHidCtx->CurrentDigitizerID == REPORT_ID_FINGER)
        pCurrentDigitizerButtons = &pHidCtx->Reports.Finger.Buttons;
    else
        pCurrentDigitizerButtons = &pHidCtx->Reports.Stylus.Buttons; // default

    pReports = &pHidCtx->Reports;

    switch (XENMOU2_GET_CODE(pEvent->TypeCode)) {
    case XMOU_CODE_BTN_LEFT:
    case XMOU_CODE_BTN_RIGHT:
    case XMOU_CODE_BTN_MIDDLE:
    case XMOU_CODE_BTN_SIDE:
    case XMOU_CODE_BTN_EXTRA:
    case XMOU_CODE_BTN_FORWARD:
    case XMOU_CODE_BTN_BACK:
        ButtonBits = 1 << ((XENMOU2_GET_CODE(pEvent->TypeCode) - MOUSE_BUTTON_START));
        if (pHidCtx->CurrentReportID == REPORT_ID_MOUSE) {
            if (pEvent->Value > 0)
                pReports->Mouse.Buttons |= ButtonBits;
            else
                pReports->Mouse.Buttons &= ~ButtonBits;
        }
        else if (pHidCtx->CurrentReportID == REPORT_ID_TABLET) {
            if (pEvent->Value > 0)
                pReports->Tablet.Buttons |= ButtonBits;
            else
                pReports->Tablet.Buttons &= ~ButtonBits;
        }
        break;

    case XMOU_CODE_BTN_TASK:
        // Don't know what to do with it
        break;

    case XMOU_CODE_BTN_TOOL_BRUSH:
    case XMOU_CODE_BTN_TOOL_PENCIL:
    case XMOU_CODE_BTN_TOOL_AIRBRUSH:
        // These can all behave like a stylus
    case XMOU_CODE_BTN_TOOL_PEN:
        // Switch to stylus/pen and reset all digitizers. Note that the
        // default tool is a stylus so on a Value == 0, it stays the same.
        pHidCtx->CurrentDigitizerID = REPORT_ID_STYLUS;
        XenM2BResetDigitizerTools(pReports);
        break;

    case XMOU_CODE_BTN_TOOL_RUBBER:
        ButtonBits = 1 << DIGITIZER_ERASER_SWITCH;
        // This is a button bit when using the pen tool to enable/disable eraser.
        if (pHidCtx->CurrentDigitizerID == REPORT_ID_STYLUS) {
            if (pEvent->Value > 0)
                *pCurrentDigitizerButtons |= ButtonBits;
            else
                *pCurrentDigitizerButtons &= ~ButtonBits;
        }
        break;

    case XMOU_CODE_BTN_TOOL_FINGER:
        // Swith to a Finger tool or back to the default stylus tool. Always
        // reset the digitizers on switching tools.
        if (pEvent->Value > 0)
            pHidCtx->CurrentDigitizerID = REPORT_ID_FINGER;
        else
            pHidCtx->CurrentDigitizerID = REPORT_ID_STYLUS;
        XenM2BResetDigitizerTools(pReports);
        break;

    case XMOU_CODE_BTN_TOOL_LENS:
        // This may be like a puck - a lens that sits on a screen with a cross-hair
    case XMOU_CODE_BTN_TOOL_MOUSE:
        // Swith to a Finger tool or back to the default stylus tool. Always
        // reset the digitizers on switching tools.
        if (pEvent->Value > 0)
            pHidCtx->CurrentDigitizerID = REPORT_ID_PUCK;
        else
            pHidCtx->CurrentDigitizerID = REPORT_ID_STYLUS;
        XenM2BResetDigitizerTools(pReports);
        break;

    case XMOU_CODE_BTN_TOUCH:
        ButtonBits = ((1 << DIGITIZER_TIP_SWITCH)|(1 << DIGITIZER_IN_RANGE)|(1 << DIGITIZER_TOUCH_VALID));
        // This becomes Tip Switch which means contact including in the Finger
        // case. Since Z axis is not supported, In Range will always accompany Tip Switch.
        if (pEvent->Value > 0) {
            *pCurrentDigitizerButtons |= ButtonBits;
        }
        else {
            *pCurrentDigitizerButtons &= ~ButtonBits;
        }
        break;

    case XMOU_CODE_BTN_STYLUS:
        ButtonBits = 1 << DIGITIZER_BARREL_SWITCH;
        // Try this out as the Barrel Switch.
        if (pHidCtx->CurrentDigitizerID == REPORT_ID_STYLUS) {
            if (pEvent->Value > 0)
                *pCurrentDigitizerButtons |= ButtonBits;
            else
                *pCurrentDigitizerButtons &= ~ButtonBits;
        }
        break;

    case XMOU_CODE_BTN_STYLUS2:
        // TODO not sure what to do with this bad boy
        break;

    default:
        break;
    };
}

static VOID
XenM2BProcessRel(PXENM2B_FDO_EXTENSION pFdoExt, XENMOU2_EVENT *pEvent)
{
    PXENM2B_HID_CONTEXT pHidCtx = pFdoExt->pActiveHidCtx;
    PXENM2B_HID_REPORTS pReports;

    if (pHidCtx == NULL)
        return;

    if (pHidCtx->CurrentReportID == DWORD_NULL_VALUE)
        XenM2BClassifyReport(pFdoExt);

    pReports = &pHidCtx->Reports;

    switch (XENMOU2_GET_CODE(pEvent->TypeCode)) {
    case XMOU_CODE_REL_X:
        //TraceDebug(("%s: XMOU_CODE_REL_X:%x\n", __FUNCTION__, pEvent->Value));
        pReports->Mouse.X = (UCHAR)pEvent->Value;
        break;

    case XMOU_CODE_REL_Y:
        //TraceDebug(("%s: XMOU_CODE_REL_Y:%x\n", __FUNCTION__, pEvent->Value));
        pReports->Mouse.Y = (UCHAR)pEvent->Value;
        break;

    case XMOU_CODE_REL_WHEEL:
        if (pHidCtx->CurrentReportID == REPORT_ID_MOUSE)
            pReports->Mouse.Z = (UCHAR)pEvent->Value;
        else if (pHidCtx->CurrentReportID == REPORT_ID_TABLET)
            pReports->Tablet.Z = (UCHAR)pEvent->Value;
        break;

    default:
        break;
    };
}

static VOID
XenM2BProcessAbs(PXENM2B_FDO_EXTENSION pFdoExt, XENMOU2_EVENT *pEvent)
{
    static const UCHAR ButtonBits = ((1 << DIGITIZER_TIP_SWITCH) | (1 << DIGITIZER_TOUCH_VALID) | (1 << DIGITIZER_IN_RANGE));

    PXENM2B_HID_CONTEXT pHidCtx = pFdoExt->pActiveHidCtx;
    PXENM2B_HID_REPORTS pReports;
    USHORT              Code;

    if (pHidCtx == NULL)
        return;

    if (pHidCtx->CurrentReportID == DWORD_NULL_VALUE)
        XenM2BClassifyReport(pFdoExt);

    pReports = &pHidCtx->Reports;
    Code = XENMOU2_GET_CODE(pEvent->TypeCode);

    switch (Code) {
    case XMOU_CODE_ABS_X:
        //TraceDebug(("%s: XMOU_CODE_ABS_X:%x\n", __FUNCTION__, pEvent->Value));
        if (pHidCtx->CurrentReportID == REPORT_ID_TABLET)
            pReports->Tablet.X = (USHORT)pEvent->Value;
        else if (pHidCtx->CurrentReportID == REPORT_ID_STYLUS)
            pReports->Stylus.X = (USHORT)pEvent->Value;
        else if (pHidCtx->CurrentReportID == REPORT_ID_PUCK)
            pReports->Puck.X = (USHORT)pEvent->Value;
        else if (pHidCtx->CurrentReportID == REPORT_ID_FINGER)
            pReports->Finger.X = (USHORT)pEvent->Value;
        break;

    case XMOU_CODE_ABS_Y:
        //TraceDebug(("%s: XMOU_CODE_ABS_Y:%x\n", __FUNCTION__, pEvent->Value));
        if (pHidCtx->CurrentReportID == REPORT_ID_TABLET)
            pReports->Tablet.Y = (USHORT)pEvent->Value;
        else if (pHidCtx->CurrentReportID == REPORT_ID_STYLUS)
            pReports->Stylus.Y = (USHORT)pEvent->Value;
        else if (pHidCtx->CurrentReportID == REPORT_ID_PUCK)
            pReports->Puck.Y = (USHORT)pEvent->Value;
        else if (pHidCtx->CurrentReportID == REPORT_ID_FINGER)
            pReports->Finger.Y = (USHORT)pEvent->Value;
        break;

    case XMOU_CODE_ABS_PRESSURE:
        break;

    case XMOU_CODE_ABS_MT_SLOT:
        //ASSERT(pEvent->Value < MT_FINGER_MAX_COUNT);
        // Switch active MT Slot (may or may not be in use yet)
        if (pEvent->Value < MT_FINGER_MAX_COUNT) {
            //TraceDebug(("%s: XMOU_CODE_ABS_MT_SLOT:%d\n", __FUNCTION__, pEvent->Value));
            pHidCtx->CurrentMTSlot = pEvent->Value;
        }
        break;

    // ...If multitouch device is in mouse mode, update the Tablet coords instead of the finger values (finger 0 only ?)
    // 
    case XMOU_CODE_ABS_MT_POSITION_X:
        ASSERT(pHidCtx->CurrentMTSlot < MT_FINGER_MAX_COUNT);
        //TraceDebug(("%s: XMOU_CODE_ABS_MT_POSITION_X:%x\n", __FUNCTION__, pEvent->Value));

        if (0 == pHidCtx->CurrentMTMode) {
            if (0 == pHidCtx->CurrentMTSlot) {
                pReports->Finger.X = (USHORT)pEvent->Value;
                pReports->Finger.Buttons = ButtonBits;
            }
        }
        else {
            // Store value in state staging area
            pHidCtx->FingersState[pHidCtx->CurrentMTSlot].Finger.X = (USHORT)pEvent->Value;
        }
        break;

    case XMOU_CODE_ABS_MT_POSITION_Y:
        ASSERT(pHidCtx->CurrentMTSlot < MT_FINGER_MAX_COUNT);
        //TraceDebug(("%s: XMOU_CODE_ABS_MT_POSITION_Y:%x\n", __FUNCTION__, pEvent->Value));

        if (0 == pHidCtx->CurrentMTMode) {
            if (0 == pHidCtx->CurrentMTSlot) {
                pReports->Finger.Y = (USHORT)pEvent->Value;
                pReports->Finger.Buttons = ButtonBits;
            }
        }
        else {
            // Store value in state staging area
            pHidCtx->FingersState[pHidCtx->CurrentMTSlot].Finger.Y = (USHORT)pEvent->Value;
        }
        break;

    case XMOU_CODE_ABS_MT_TRACKING_ID:
        ASSERT(pHidCtx->CurrentMTSlot < MT_FINGER_MAX_COUNT);

        //TraceDebug(("%s: XMOU_CODE_ABS_MT_TRACKING_ID:%x Slot:%d\n", __FUNCTION__, pEvent->Value, pHidCtx->CurrentMTSlot));

        // When a tracking ID is set for an MT Slot, this indicates the slot
        // is newly in use because a Finger started touching the screen.        
        if (pEvent->Value != (ULONG)-1) {
            // When a Finger first goes down, set a unique Tacking ID.
            if (!pHidCtx->FingersState[pHidCtx->CurrentMTSlot].FingerDown) {
                pHidCtx->CurrentMTTrackingID++;
                if (pHidCtx->CurrentMTTrackingID == 0)
                    pHidCtx->CurrentMTTrackingID = 1;
                pHidCtx->FingersState[pHidCtx->CurrentMTSlot].Finger.ContactID = pHidCtx->CurrentMTTrackingID;
                pHidCtx->FingersState[pHidCtx->CurrentMTSlot].FingerDown = TRUE;
            }

            // Toggle Tip Switch to indicate contact.
            pHidCtx->FingersState[pHidCtx->CurrentMTSlot].Finger.Buttons = ButtonBits;            
            pHidCtx->FingersState[pHidCtx->CurrentMTSlot].Lifted = FALSE;
            break;
        }

        // When the Tracking ID is cleared, it means the Finger has lifted. The first
        // time it is cleared the lift action must be reported.
        pHidCtx->FingersState[pHidCtx->CurrentMTSlot].Finger.Buttons = 0;
        if (pHidCtx->FingersState[pHidCtx->CurrentMTSlot].FingerDown)
            pHidCtx->FingersState[pHidCtx->CurrentMTSlot].Lifted = TRUE;
        pHidCtx->FingersState[pHidCtx->CurrentMTSlot].FingerDown = FALSE;
        break;

    case XMOU_CODE_ABS_MT_PRESSURE:
        break;

    default:
        TraceDebug(("%s: Invalid Code:%d for Report:%d\n", __FUNCTION__, Code, pHidCtx->CurrentReportID));
        break;
    };
}

static VOID
XenM2BProcessDevSet(PXENM2B_FDO_EXTENSION pFdoExt, ULONG SlotNumber)
{
    PXENM2B_PDO_EXTENSION pPdoExt;
    PXENM2B_HID_CONTEXT   pHidCtx = pFdoExt->pActiveHidCtx;
    PLIST_ENTRY           pEntry;
    KIRQL                 Irql;

    // Drop any existing HID context reference and find the new one.
    if (pHidCtx != NULL) {
        pFdoExt->pActiveHidCtx = NULL;
        XenM2BReleaseHidContext(pHidCtx);
        pHidCtx = NULL;
    }

    KeAcquireSpinLock(&pFdoExt->PdoListLock, &Irql);

    ListForEach(pEntry, &pFdoExt->PdoList) {
        pPdoExt = CONTAINING_RECORD(pEntry, XENM2B_PDO_EXTENSION, ListEntry);
        if (pPdoExt->pHidCtx->SlotNumber == SlotNumber) {
            pHidCtx = pFdoExt->pActiveHidCtx = pPdoExt->pHidCtx;
            XenM2BAddRefHidContext(pHidCtx);
            break;
        }
    }

    KeReleaseSpinLock(&pFdoExt->PdoListLock, Irql);

    if (pHidCtx == NULL) {
        TraceError(("%s: No device to SET active in slot number: %d\n",
                    __FUNCTION__, SlotNumber));
    }
    else {
        TraceDebug(("%s: device SET to Slot:%d\n", __FUNCTION__, SlotNumber));
    }
}

static ULONG
XenM2BClassifyDev(PXENMOU2_DEV_CONFIG pDevConfig, PULONG pReportDescriptorLength)
{
    static const ULONG EvtAbsMask = 1 << XMOU_TYPE_EV_ABS;
    static const ULONG EvtRelMask = 1 << XMOU_TYPE_EV_REL;
    static const ULONG EvtBtnMask = 1 << XMOU_TYPE_EV_KEY;
    static const ULONG RelMouseMask = ((1 << XMOU_CODE_REL_X)|(1 << XMOU_CODE_REL_Y));
    static const ULONG AbsTabletMask = ((1 << XMOU_CODE_ABS_X)|(1 << XMOU_CODE_ABS_Y));
    static const ULONG AbsMTMask = ((1 << (XMOU_CODE_ABS_MT_POSITION_X - 32))|
									(1 << (XMOU_CODE_ABS_MT_POSITION_Y - 32)));
    static const ULONG BtnPenMask = ((1 << (XMOU_CODE_BTN_TOOL_PEN - XMOU_BTN_REBASE - 64))|
									 (1 << (XMOU_CODE_BTN_TOUCH - XMOU_BTN_REBASE - 64)));

    ULONG DevTypes = DEVICE_TYPE_UNKNOWN;

    TraceDebug(("%s: Entry Config Name:%s Ev:%x Abs:%x %x Rel:%x Btn:%x %x %x\n", __FUNCTION__, 
                pDevConfig->Name,
                pDevConfig->EvBits,
                pDevConfig->AbsBits[1], pDevConfig->AbsBits[0],
                pDevConfig->RelBits,
                pDevConfig->BtnBits[2], pDevConfig->BtnBits[1], pDevConfig->BtnBits[0]));

    // TODO
    // There will be a lot more to come in this function as we try to sort
    // out what types of reports a device may generate. Also the bit ordinal
    // scheme for identifying what events are sent may need some work. For now
    // only tablet/rel mouse device type is used.
    //
    // Not sure how strict the classifying will need to be...
    //
    // Also the BitMask utility routines in the DDK should be helpful for these
    // multi-DWORD bitmasks.

	// The device must provide Abs, Rel or Key events, not just SYN or DEV events

    if ((pDevConfig->AbsBits[1] == 0x7fff00) && (pDevConfig->AbsBits[0] == 0) && (pDevConfig->RelBits == 0)) {
        // Audio device coming through from XENMOU2 on a Samsung Slate, skip it here for now until XENMOU2 is fixed.
    }

    // Relative mouse
    else if ((pDevConfig->EvBits & EvtRelMask) && (pDevConfig->RelBits & RelMouseMask)) {
	    *pReportDescriptorLength = MouseDescriptorLength;
	    DevTypes = DEVICE_TYPE_MOUSE;
    }
    // Tablet/Absolute mouse
    else if ((pDevConfig->EvBits & EvtAbsMask) && (pDevConfig->AbsBits[0] & AbsTabletMask)) {
	    *pReportDescriptorLength = TabletDescriptorLength;
	    DevTypes = DEVICE_TYPE_TABLET;
    }
    else if ((pDevConfig->EvBits & EvtAbsMask) && (pDevConfig->AbsBits[1] & AbsMTMask)) {
	    *pReportDescriptorLength = MultitouchDescriptorLength;
	    DevTypes = DEVICE_TYPE_MULTITOUCH;
    }
    else if ((pDevConfig->EvBits & EvtBtnMask) && (pDevConfig->BtnBits[2] & BtnPenMask)) {
	    *pReportDescriptorLength = DigitizerDescriptorLength;
	    DevTypes = DEVICE_TYPE_DIGITIZER;
    }

    TraceDebug(("%s: Exit Name:%s Type:%x\n", __FUNCTION__, pDevConfig->Name, DevTypes));
    return DevTypes;
}

static VOID
XenM2BProcessDevConf(PXENM2B_FDO_EXTENSION pFdoExt, ULONG SlotNumber)
{
    PXENM2B_PDO_EXTENSION pPdoExt;
    PXENMOU2_DEV_CONFIG   pDevConfig;
    CHAR                  pDeviceName[XENMOU2_NAME_LENGTH + 1];
    PDEVICE_OBJECT        pPdo;
    PXENM2B_HID_CONTEXT   pHidCtx;
    ULONG                 DevTypes;
    ULONG                 DescLength = 0;
    ULONG                 i;

    TraceDebug(("%s: Entry SlotNumber:%d\n", __FUNCTION__, SlotNumber));

	// Processing a DEV:DEV_CONF event. A new device has appeared on the XENMOU2
    // bus. The M2B bus driver will create a new child PDO to represent. The HIDClass
    // framework will create an FDO device instance in our XENHID Minidriver above
    // this new PDO. That new FDO representing a HID device will be attached to
    // this PDOs stack and will send a queury interface IRP down. The two devices
    // will connect w/ eachother using the 2 ends of the XENM2B_CLIENT_INTERFACE
    // they exchange.

    if (SlotNumber >= XMOU_DEV_CONFIG_INVALID_SLOT) {
        TraceError(("%s: Invalid slot number: %d\n",
                   __FUNCTION__, SlotNumber));
        return;
    }

    // First locate the device configuration block for this new device and copy its name.
    pDevConfig = (PXENMOU2_DEV_CONFIG)(pFdoExt->pConfigRegs + (SlotNumber * pFdoExt->ConfigSize));
    RtlZeroMemory(&pDeviceName[0], XENMOU2_NAME_LENGTH + 1);
    RtlCopyMemory(&pDeviceName[0], &pDevConfig->Name[0], XENMOU2_NAME_LENGTH);

    DevTypes = XenM2BClassifyDev(pDevConfig, &DescLength);
    if (DevTypes == DEVICE_TYPE_UNKNOWN) {
        TraceError(("%s: Unknown XENMOU2 device %s\n",
                   __FUNCTION__, pDeviceName));
        return;
    }

    // Create the internal HID context structure where all the action occurs.
    pHidCtx = ExAllocatePoolWithTag(NonPagedPool,
                                    (sizeof(XENM2B_HID_CONTEXT) + DescLength),
                                    XENM2B_POOL_TAG);
    if (pHidCtx == NULL) {
        TraceError(("%s: Failed to allocate HID context for XENMOU2 device %s\n",
                   __FUNCTION__, pDeviceName));
        return;
    }

    // Initialize the HID context block.
    RtlZeroMemory(pHidCtx, sizeof(XENM2B_HID_CONTEXT) + DescLength);
    pHidCtx->DevTypes = DevTypes;
    pHidCtx->SlotNumber = SlotNumber;
    RtlCopyMemory(&pHidCtx->DevConfig, pDevConfig, sizeof(XENMOU2_DEV_CONFIG));
    RtlCopyMemory(&pHidCtx->HidAttributes, &HidAttributes, sizeof(HID_DEVICE_ATTRIBUTES));
    RtlCopyMemory(&pHidCtx->HidDescriptor, &HidDescriptor, sizeof(HID_DESCRIPTOR));
    pHidCtx->ReportDescriptorLength = DescLength;
    pHidCtx->HidDescriptor.DescriptorList[0].wReportLength = (USHORT)DescLength;

    // Clear all the reports and set the reporting IDs.
    RtlZeroMemory(&pHidCtx->Reports, sizeof(XENM2B_HID_REPORTS));
    pHidCtx->Reports.Mouse.ReportID = REPORT_ID_MOUSE;
    pHidCtx->Reports.Tablet.ReportID = REPORT_ID_TABLET;
    pHidCtx->Reports.Multitouch.ReportID = REPORT_ID_MULTITOUCH;
    pHidCtx->Reports.Stylus.ReportID = REPORT_ID_STYLUS;
    pHidCtx->Reports.Puck.ReportID = REPORT_ID_PUCK;
    pHidCtx->Reports.Finger.ReportID = REPORT_ID_FINGER;

    // The number of contacts starts at zero.
    pHidCtx->Reports.Multitouch.ContactCount = 0;

    // Maintain a unique Tracking ID internally because the one that is reported
    // by devices on the M2B bus keeps changing.
    pHidCtx->CurrentMTTrackingID = 1;

    // Current Multitouch mode, 0 - Mouse mode, 1 - single touch, 2 - multi touch
    pHidCtx->CurrentMTMode = 2;

    // Multitouch must report the max contacts as a Feature.
    // TODO make this dynamic later with values from the config.
    pHidCtx->ContactCountMax = MT_FINGER_MAX_COUNT;

    // Default to a pen/stylus
    pHidCtx->CurrentDigitizerID = REPORT_ID_STYLUS;

    // None set yet
    pHidCtx->CurrentReportID = DWORD_NULL_VALUE;

    // Start on first Finger, Note that FingersState is all zero.
    pHidCtx->CurrentMTSlot = 0;

    // Build the report descriptor now that there is space at the end of the
    // context block. Note some may be composit devices and 2 or more descriptors
    // will be copied in.
    if (pHidCtx->DevTypes == DEVICE_TYPE_MOUSE) {
        // Simple relative mouse
        RtlCopyMemory(&pHidCtx->ReportDescriptor[0], &MouseReportDescriptor[0], MouseDescriptorLength);
    }
    else if (pHidCtx->DevTypes == DEVICE_TYPE_TABLET) {
        // Simple absolute mouse/tablet
        RtlCopyMemory(&pHidCtx->ReportDescriptor[0], &TabletReportDescriptor[0], TabletDescriptorLength);
    }
    else if (pHidCtx->DevTypes == DEVICE_TYPE_MULTITOUCH) {
        RtlCopyMemory(&pHidCtx->ReportDescriptor[0], &MultitouchReportDescriptor[0], MultitouchDescriptorLength);
    }
    else if (pHidCtx->DevTypes == DEVICE_TYPE_DIGITIZER) {
        RtlCopyMemory(&pHidCtx->ReportDescriptor[0], &DigitizerReportDescriptor[0], DigitizerDescriptorLength);
    }
    else {
        TraceError(("%s: Invalid configuration for XENMOU2 device %s devtypes: 0x%x\n",
                   __FUNCTION__, pDeviceName, DevTypes));
        ExFreePoolWithTag(pHidCtx, XENM2B_POOL_TAG);
        return;
    }

    // Create a new PDO child
    pPdo = XenM2BPdoCreate(pFdoExt, pDeviceName, (UCHAR)SlotNumber);
    if (pPdo == NULL) {
        TraceError(("%s: Failed to create new PDO for XENMOU2 device %s\n",
                   __FUNCTION__, pDeviceName));
        ExFreePoolWithTag(pHidCtx, XENM2B_POOL_TAG);
        return;
    }

    pPdoExt = (PXENM2B_PDO_EXTENSION)pPdo->DeviceExtension;

    // Link things together and add one ref for the owner extension
    XenM2BAddRefHidContext(pHidCtx);
    pPdoExt->pHidCtx = pHidCtx;
    pHidCtx->pOwnerExt = pPdoExt;

    // And finally, link the device to the FDO's list and invalidate
    // bus relations which kickstart all the PnP stuffs.
    XenM2BPdoLink(pFdoExt, pPdoExt, FALSE);
    TraceDebug(("%s: invalidating BusRelations\n", __FUNCTION__));
    IoInvalidateDeviceRelations(pFdoExt->pBusPdo, BusRelations);

	TraceDebug(("%s: Exit\n", __FUNCTION__));
}

static VOID
XenM2BProcessDevResetAll(PXENM2B_FDO_EXTENSION pFdoExt)
{
    PXENM2B_PDO_EXTENSION *pPdoExtList = NULL;
    PXENM2B_PDO_EXTENSION  pPdoExt = NULL;
    PLIST_ENTRY            pEntry;
    ULONG                  Count = 0, i;
    BOOLEAN                NeedInvalidate = FALSE;
    KIRQL                  Irql;
    XENM2B_PNP_STATE       PnPState;

    TraceDebug(("%s: Entry\n", __FUNCTION__));

    // Start the removal process for a single XEMOU2 device or for all devices
    KeAcquireSpinLock(&pFdoExt->PdoListLock, &Irql);

    ListForEach(pEntry, &pFdoExt->PdoList) {
        pPdoExt = CONTAINING_RECORD(pEntry, XENM2B_PDO_EXTENSION, ListEntry);
        Count++;
    }

    if (Count == 0) {
        TraceDebug(("%s: No devices to remove\n", __FUNCTION__));
        // A DEV_RESET received, but no devices to remove.
        KeReleaseSpinLock(&pFdoExt->PdoListLock, Irql);
        return;
    }

    pPdoExtList = ExAllocatePoolWithTag(NonPagedPool,
                                        (Count * sizeof(PXENM2B_PDO_EXTENSION)),
                                        XENM2B_POOL_TAG);
    if (pPdoExtList == NULL) {
        TraceError(("%s: Failed to allocate XEMOU2 reset list\n", __FUNCTION__));
        KeReleaseSpinLock(&pFdoExt->PdoListLock, Irql);
        return;
    }

    Count = 0;
    ListForEach(pEntry, &pFdoExt->PdoList) {
        pPdoExtList[Count++] = CONTAINING_RECORD(pEntry, XENM2B_PDO_EXTENSION, ListEntry);
    }

    KeReleaseSpinLock(&pFdoExt->PdoListLock, Irql);

    // Outside the lock, each PDO can be processed.
    // If the PDO has not yet been enumerated then we can go ahead and destroy
    // it, otherwise we need to notify PnP manager and wait for the REMOVE_DEVICE IRP.
    for (i = 0; i < Count; i++) {
        pPdoExt = pPdoExtList[i];
        PnPState = XenM2BGetPnPState(&pPdoExt->DevicePnPState);

        if (PnPState == PnPStatePresent) {
            TraceDebug(("%s: PnpState:%d Delete\n", __FUNCTION__, PnPState));
            XenM2BPdoUnlink(pPdoExt, FALSE);			// Spinlock released at this point.
            XenM2BPdoDeleteDevice(pPdoExt->pDevice);
        }
        else {
            TraceDebug(("%s: PnpState:%d Set missing\n", __FUNCTION__, PnPState));
            pPdoExt->Missing = TRUE;
            NeedInvalidate = TRUE;
        }
    }

    ExFreePoolWithTag(pPdoExtList, XENM2B_POOL_TAG);

    if (NeedInvalidate) {
        TraceDebug(("%s: InvalidateDeviceRelations\n", __FUNCTION__));
        IoInvalidateDeviceRelations(pFdoExt->pBusPdo, BusRelations);
    }

    TraceDebug(("%s: Exit\n", __FUNCTION__));
}

static VOID
XenM2BProcessDevReset(PXENM2B_FDO_EXTENSION pFdoExt, ULONG SlotNumber)
{
    PXENM2B_PDO_EXTENSION  pPdoExtTemp = NULL;
    PXENM2B_PDO_EXTENSION  pPdoExt = NULL;
    PLIST_ENTRY            pEntry;
    ULONG                  Count = 0, i;
    KIRQL                  Irql;
    XENM2B_PNP_STATE       PnPState;

    TraceDebug(("%s: Entry SlotNumber:%d\n", __FUNCTION__, SlotNumber));

    if (SlotNumber >= XMOU_DEV_CONFIG_INVALID_SLOT) {
        XenM2BProcessDevResetAll(pFdoExt);
        return;
    }

    // Start the removal process for a single XEMOU2 device
    KeAcquireSpinLock(&pFdoExt->PdoListLock, &Irql);

    ListForEach(pEntry, &pFdoExt->PdoList) {
        pPdoExtTemp = CONTAINING_RECORD(pEntry, XENM2B_PDO_EXTENSION, ListEntry);
        if (pPdoExtTemp->pHidCtx->SlotNumber == SlotNumber) {
            pPdoExt = pPdoExtTemp;
            break;
        }
    }

    KeReleaseSpinLock(&pFdoExt->PdoListLock, Irql);

    if (pPdoExt != NULL) {
        // If the PDO has not yet been enumerated then we can go ahead and destroy
        // it, otherwise we need to notify PnP manager and wait for the REMOVE_DEVICE IRP.
        PnPState = XenM2BGetPnPState(&pPdoExt->DevicePnPState);
        if (PnPState == PnPStatePresent) {
            TraceDebug(("%s: Delete Device\n", __FUNCTION__));
            XenM2BPdoUnlink(pPdoExt, FALSE);
            XenM2BPdoDeleteDevice(pPdoExt->pDevice);
        }
        else {
            TraceDebug(("%s: Invalidate DeviceState\n", __FUNCTION__));
            pPdoExt->Missing = TRUE;
            IoInvalidateDeviceRelations(pFdoExt->pBusPdo, BusRelations);
        }
    }

    TraceDebug(("%s: Exit\n", __FUNCTION__));
}

//static IO_WORKITEM_ROUTINE XenM2BDevWorkRoutine;
static VOID NTAPI
XenM2BDevWorkItem(PDEVICE_OBJECT pDeviceObject, PVOID pContext)
{
    PXENM2B_DEV_CONTEXT   pDevCtx = pContext;
    PXENM2B_FDO_EXTENSION pFdoExt = (PXENM2B_FDO_EXTENSION)pDeviceObject->DeviceExtension;

    if (pDevCtx->Create)
        XenM2BProcessDevConf(pFdoExt, pDevCtx->SlotNumber);
    else
        XenM2BProcessDevReset(pFdoExt, pDevCtx->SlotNumber);

    IoFreeWorkItem(pDevCtx->pWorkItem);
    ExFreePoolWithTag(pDevCtx, XENM2B_POOL_TAG);
}

static VOID
XenM2BProcessDev(PXENM2B_FDO_EXTENSION pFdoExt, XENMOU2_EVENT *pEvent)
{
    PXENM2B_DEV_CONTEXT pDevCtx;
    BOOLEAN             Create = TRUE;
    BOOLEAN             IsEmpty = FALSE;
    USHORT              TypeCode = XENMOU2_GET_CODE(pEvent->TypeCode);

    if (TypeCode == XMOU_CODE_DEV_SET) {
        if (pEvent->Value < XMOU_DEV_CONFIG_INVALID_SLOT)
            XenM2BProcessDevSet(pFdoExt, pEvent->Value);

        return; // Else not usable, go on.
    }

    if (TypeCode == XMOU_CODE_DEV_CONF) {
        Create = TRUE;
    }
    else if (TypeCode == XMOU_CODE_DEV_RESET) {
        // The vHW sends a banket reset of all devices when it is first
        // enabled before there are any PDOs on this bus. Ignore it now 
		// rather than waiting for the queued work item, in case a DEV_CONF is
		// processed a the same time.
	    KeAcquireSpinLockAtDpcLevel(&pFdoExt->PdoListLock);
		IsEmpty = IsListEmpty(&pFdoExt->PdoList);
		KeReleaseSpinLockFromDpcLevel(&pFdoExt->PdoListLock);
		if (IsEmpty) {
	        TraceDebug(("%s: DEV_RESET with no devices\n", __FUNCTION__));
			return;
		}

		Create = FALSE;
    }
    else {
        TraceError(("%s: Unknown DEV code:%x\n", __FUNCTION__, TypeCode));
        return; // Unkown code
    }

    // Device creation or removal
    pDevCtx = ExAllocatePoolWithTag(NonPagedPool,
                                    sizeof(XENM2B_DEV_CONTEXT),
                                    XENM2B_POOL_TAG);
    if (pDevCtx == NULL) {
        TraceError(("%s: Failed to allocate XENM2B_DEV_CONTEXT\n", __FUNCTION__));
        return; // Not much we can do here...
    }

    pDevCtx->pWorkItem = IoAllocateWorkItem(pFdoExt->pDevice);
    if (pDevCtx == NULL) {
        TraceError(("%s: Failed to allocate WorkItem\n", __FUNCTION__));
        ExFreePoolWithTag(pDevCtx, XENM2B_POOL_TAG);
        return; // Or here...
    }

    pDevCtx->Create = Create;
    pDevCtx->SlotNumber = pEvent->Value;
    IoQueueWorkItem(pDevCtx->pWorkItem, XenM2BDevWorkItem, DelayedWorkQueue, pDevCtx);
}

VOID
XenM2BEventDpc(KDPC *pDpc, VOID *pDeferredContext, VOID *pSysArg1, VOID *pSysArg2)
{
#define XenM2BGetEventTypeCode(p, r) (p->pEventRegs + p->RWRegSize + (r*p->EventSize))
#define XenM2BGetEventValue(p, r) (p->pEventRegs + p->RWRegSize + (r*p->EventSize) + sizeof(ULONG))
    static BOOLEAN TraceOnce = FALSE;
    PDEVICE_OBJECT        pDeviceObject = (PDEVICE_OBJECT)pDeferredContext;
    PXENM2B_FDO_EXTENSION pFdoExt;
    ULONG                 ReadPointer;
    ULONG                 WritePointer;
    ULONG                 EventCount;
    XENMOU2_EVENT         Event;
    BOOLEAN               NotReady = FALSE;
    KLOCK_QUEUE_HANDLE    LockHandle;

    UNREFERENCED_PARAMETER(pDpc);
    UNREFERENCED_PARAMETER(pSysArg1);
    UNREFERENCED_PARAMETER(pSysArg2);

    pFdoExt = (PXENM2B_FDO_EXTENSION)pDeviceObject->DeviceExtension;
    EventCount = pFdoExt->EventCount;

    // Ensure that only 1 Dpc executes at a time.
    KeAcquireInStackQueuedSpinLockAtDpcLevel(&pFdoExt->DpcSpinLock, &LockHandle);

    // Main event loop processes events up to one of these conditions:
    // a. Run out of events in ring
    // b. SendReport() fails, IO not ready
    // In either case the processing may be in mid-stream before a SYN. The HID context
    // is left in whatever state it is in when the loop ends. Further processing will
    // pick up at that point when the DPC runs again.
    do {
        ReadPointer = READ_REGISTER_ULONG((PULONG)(pFdoExt->pEventRegs + XMOU_READ_PTR));
        WritePointer = READ_REGISTER_ULONG((PULONG)(pFdoExt->pEventRegs + XMOU_WRITE_PTR));

        if (ReadPointer == WritePointer)
            break;

        Event.TypeCode = READ_REGISTER_ULONG((PULONG)XenM2BGetEventTypeCode(pFdoExt, ReadPointer));
        Event.Value = READ_REGISTER_ULONG((PULONG)XenM2BGetEventValue(pFdoExt, ReadPointer));

#if defined(M2B_DEBUG_EVENT_TRACE)
        XenM2BDebugEventTrace(&Event);
#endif

        switch (XENMOU2_GET_TYPE(Event.TypeCode)) {
        case XMOU_TYPE_EV_SYN:
            NotReady = !XenM2BProcessSyn(pFdoExt, &Event);
            break;

        case XMOU_TYPE_EV_KEY:
            if (XENMOU2_GET_CODE(Event.TypeCode) > XMOU_CODE_KEY_RESERVED)
                XenM2BProcessBtn(pFdoExt, &Event);
            else
                XenM2BProcessKey(pFdoExt, &Event);
            break;

        case XMOU_TYPE_EV_REL:
            XenM2BProcessRel(pFdoExt, &Event);
            break;

        case XMOU_TYPE_EV_ABS:
            XenM2BProcessAbs(pFdoExt, &Event);
            break;

        case XMOU_TYPE_EV_DEV:
            XenM2BProcessDev(pFdoExt, &Event);
            break;

        default:
            if (TraceOnce)
                break;
            TraceOnce = TRUE;
            TraceWarning(("%s: Unkown Event - TypeCode: 0x%x Value: 0x%x\n",
                          __FUNCTION__, Event.TypeCode, Event.Value));
        };

        if (NotReady) {
            // No IRPs waiting at the station, have to come back later. Leave the context in
            // the current state and drop out of the DPC. Also leave the SYN in the ring so
            // that on resume, we attempt to send it again.
            break;
        }

        ReadPointer++;
        ReadPointer %= EventCount;

        WRITE_REGISTER_ULONG((PULONG)(pFdoExt->pEventRegs + XMOU_READ_PTR), ReadPointer);

    } while (TRUE);

    // Release the lock for the next Dpc
    KeReleaseInStackQueuedSpinLockFromDpcLevel(&LockHandle);
}
