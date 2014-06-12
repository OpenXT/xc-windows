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

//
// Crash dumps via QEMU
//
// To enable this code add DEBUG_DUMP_DEVICE_DOM0 (0x00000010) to your boot flags. Then in dom0 you need to
// customize /opt/xensource/libexec/qemu-dm-wrapper to add the following arguments to the qemu command line:
//
// -priv -dumpdir <directory> -dumpquota <quota>
//
// <directory> is best pointed at an empty directory. Files will be created with numeric names starting at 0.
// <quota> should be the total size in MB of all possible crash dump files. I.e. once sufficient crash dumps have
// occurred to fill this quota, no more will be allowed until sufficient space is cleared in <directory>. This is
// to prevent dump files (which can be very large) from overrunning dom0's filesystem.
//

#include <ntddk.h>
#include "xsapi.h"
#include "scsiboot.h"

#define DUMP_IO_PORT_CTRL   ((PUCHAR)0xeb)
#define DUMP_IO_PORT_WRITE  ((PULONG)0xec)

#define DUMP_VERSION        ((UCHAR)0x01)

#define DUMP_IO_REGISTERED  ((UCHAR)0x00)
#define DUMP_IO_OPEN        ((UCHAR)0x01)
#define DUMP_IO_CLOSE       ((UCHAR)0x02)

// We use a hard-coded port number in here, which upsets prefast,
// since it thinks we should be querying the PnP manager to find out
// which port to use.  We know better, so disable the warning. */
#pragma warning(disable : 28138)

static KBUGCHECK_REASON_CALLBACK_RECORD    BugcheckCallbackRecord;
static KBUGCHECK_DUMP_IO_TYPE              DumpIoType = KbDumpIoInvalid;
static BOOLEAN                             DumpCallbackIsInstalled = FALSE;

static VOID
DumpPortOpen(
    VOID
    )
{
    TraceDebug(("%s: ==>\n", __FUNCTION__));
    WRITE_PORT_UCHAR(DUMP_IO_PORT_CTRL, DUMP_IO_OPEN);   
    TraceDebug(("%s: <==\n", __FUNCTION__));
}

static VOID
DumpPortClose(
    VOID
    )
{
    TraceDebug(("%s: ==>\n", __FUNCTION__));
    WRITE_PORT_UCHAR(DUMP_IO_PORT_CTRL, DUMP_IO_CLOSE);   
    TraceDebug(("%s: <==\n", __FUNCTION__));
}

#define IS_PAGE_ALIGNED(_Address)   (((ULONG_PTR)(_Address) & (PAGE_SIZE - 1)) == 0)

static VOID
DumpPortWrite(
    IN  ULONG64         Offset,
    IN  PVOID           Buffer,
    IN  ULONG           Length
    )
{
    PHYSICAL_ADDRESS    Address;

    TraceDebug(("%s: ==> [0x%p]+%08x\n", __FUNCTION__,
                Buffer, Length));

    XM_ASSERT(Offset == (ULONG64)-1);
    XM_ASSERT(IS_PAGE_ALIGNED(Buffer));
    XM_ASSERT(IS_PAGE_ALIGNED(Length));

    // Sometimes Windows passes us virtual addresses, sometimes it passes
    // physical addresses. It doesn't tell us which it's handing us, and
    // how this plays with PAE is anybody's guess.
    // Fortunately doing MmGetPhysicalAddress() on a physical address yields
    // 
    Address = MmGetPhysicalAddress(Buffer);
    if (Address.QuadPart == 0) {
        Address.QuadPart = (ULONG_PTR)Buffer;
    } else {
        TraceDebug(("0x%p -> %08x.%08x\n", Buffer,
                    Address.HighPart, Address.LowPart));
    }

    Address.QuadPart >>= PAGE_SHIFT;
    XM_ASSERT3U(Address.HighPart, ==, 0);

    for (Length >>= PAGE_SHIFT; Length != 0; Length--)
        WRITE_PORT_ULONG(DUMP_IO_PORT_WRITE, Address.LowPart++);

    TraceDebug(("%s: <==\n", __FUNCTION__));
}

static CONST CHAR *
DumpIoTypeName(
    IN  KBUGCHECK_DUMP_IO_TYPE  Type
    )
{
#define _IO_TYPE_NAME(_Type)    \
        case KbDumpIo ## _Type: \
            return #_Type;

    switch (Type) {
    _IO_TYPE_NAME(Invalid);
    _IO_TYPE_NAME(Header);
    _IO_TYPE_NAME(Body);
    _IO_TYPE_NAME(SecondaryData);
    _IO_TYPE_NAME(Complete);
    default:
        break;
    }

    return "UNKNOWN";

#undef  _IO_TYPE_NAME
}

static VOID
BugcheckDumpIoCallback(
    IN  KBUGCHECK_CALLBACK_REASON           Reason,
    IN  PKBUGCHECK_REASON_CALLBACK_RECORD   Record,
    IN  OUT PVOID                           ReasonSpecificData,
    IN  ULONG                               ReasonSpecificDataLength 
    )
{   
    PKBUGCHECK_DUMP_IO                      DumpIo = (PKBUGCHECK_DUMP_IO)ReasonSpecificData;

    TraceDebug(("%s: ==> (%s)\n", __FUNCTION__, DumpIoTypeName(DumpIo->Type)));

    UNREFERENCED_PARAMETER(ReasonSpecificDataLength);
    
    XM_ASSERT(Reason == KbCallbackDumpIo);
    XM_ASSERT(Record == &BugcheckCallbackRecord);
    XM_ASSERT(DumpIo != NULL);
    
    switch (DumpIo->Type) {
        case KbDumpIoHeader:
            XM_ASSERT3U(DumpIoType, ==, KbDumpIoInvalid);
            DumpIoType = KbDumpIoHeader;
                 
            DumpPortOpen();

            DumpPortWrite(DumpIo->Offset, DumpIo->Buffer, DumpIo->BufferLength);
            break;

        case KbDumpIoBody:
            XM_ASSERT(DumpIoType == KbDumpIoHeader ||
                      DumpIoType == KbDumpIoBody);
            DumpIoType = KbDumpIoBody;

            DumpPortWrite(DumpIo->Offset, DumpIo->Buffer, DumpIo->BufferLength);
            break;

        case KbDumpIoSecondaryData:
            XM_ASSERT(DumpIoType == KbDumpIoBody ||
                      DumpIoType == KbDumpIoSecondaryData);
            DumpIoType = KbDumpIoSecondaryData;
                 
            DumpPortWrite(DumpIo->Offset, DumpIo->Buffer, DumpIo->BufferLength);
            break;

        case KbDumpIoComplete:
            XM_ASSERT3U(DumpIoType, ==, KbDumpIoSecondaryData);
            DumpIoType = KbDumpIoComplete;
            
            DumpPortClose();
            break;
        
        case KbDumpIoInvalid:
        default:
            XM_ASSERT(FALSE);
            break;  
    }

    TraceDebug(("%s: <==\n", __FUNCTION__));
}

typedef BOOLEAN
(*PKE_REGISTER_BUG_CHECK_REASON_CALLBACK)(PKBUGCHECK_REASON_CALLBACK_RECORD,
                                          PKBUGCHECK_REASON_CALLBACK_ROUTINE,
                                          KBUGCHECK_CALLBACK_REASON,
                                          PCHAR);

NTSTATUS
InstallDumpDeviceCallback(
    VOID
    )
{
    UCHAR                                   Version;
    UNICODE_STRING                          Name;
    PKE_REGISTER_BUG_CHECK_REASON_CALLBACK  Function;
    NTSTATUS                                status;

    TraceDebug(("%s: ==>\n", __FUNCTION__));

    if (DumpCallbackIsInstalled) {
        TraceNotice(("%s: already done\n", __FUNCTION__));
        goto done;
    }

    Version = READ_PORT_UCHAR(DUMP_IO_PORT_CTRL);

    if (Version != DUMP_VERSION) {
        TraceNotice(("%s: version mismatch (%u != %u)\n", __FUNCTION__,
                     Version, DUMP_VERSION));
        goto done;
    }

    RtlInitUnicodeString(&Name, L"KeRegisterBugCheckReasonCallback");
    Function =
        (PKE_REGISTER_BUG_CHECK_REASON_CALLBACK)(ULONG_PTR)
        MmGetSystemRoutineAddress(&Name);

    if (Function == NULL) {
        TraceNotice(("%s: not available\n", __FUNCTION__));
        goto done;
    }

    KeInitializeCallbackRecord(&BugcheckCallbackRecord);

    status = STATUS_UNSUCCESSFUL;
    if (!Function(&BugcheckCallbackRecord,
                  BugcheckDumpIoCallback,
                  KbCallbackDumpIo,
                  __FUNCTION__))
        goto fail;

    DumpCallbackIsInstalled = TRUE;
    WRITE_PORT_UCHAR(DUMP_IO_PORT_CTRL, DUMP_IO_REGISTERED);

    TraceNotice(("%s: done\n", __FUNCTION__));

done:
    TraceDebug(("%s: <==\n", __FUNCTION__));

    return STATUS_SUCCESS;

fail:
    TraceError(("%s: fail (%08x)\n", __FUNCTION__, status));

    TraceDebug(("%s: <==\n", __FUNCTION__));
    return status;
}
