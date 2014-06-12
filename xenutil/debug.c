/*
 * Copyright (c) 2011 Citrix Systems, Inc.
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

/* Various utility functions intended to make debugging a bit
 * easier. */
#define INITGUID
#include "ntddk.h"
#include "xsapi.h"
#include "scsiboot.h"
#include "aux_klib.h"

#include "hypercall.h"
#include "evtchn.h"
#include "xenutl.h"
#include "debug.h"

#include <sched.h>
#include <hvm_params.h>

DEFINE_GUID(BugcheckAuxDataGuid,
0xf2a47958, 0x9d2f, 0x4064, 0x91, 0xb9, 0x23, 0x38, 0x69, 0xaf, 0xc7, 0x3c);

__MAKE_WRAPPER_PRIV(EVTCHN_DEBUG_CALLBACK, int)
#define wrap_EVTCHN_DEBUG_CALLBACK(x) __wrap_EVTCHN_DEBUG_CALLBACK((x)+1)
#define unwrap_EVTCHN_DEBUG_CALLBACK(x) (__unwrap_EVTCHN_DEBUG_CALLBACK(x)-1)

#define NR_DEBUG_CALLBACKS 32
static struct irqsafe_lock DebugCallbackLock;

struct DebugCallback {
    CHAR module[16];
    CHAR name[64];
    VOID (*cb)(VOID *);
    VOID *data;
};
static struct DebugCallback DebugCallbacks[NR_DEBUG_CALLBACKS];

static KBUGCHECK_CALLBACK_RECORD BugcheckCallbackRecord;
static BOOLEAN haveBugcheckCallback;
static KBUGCHECK_REASON_CALLBACK_RECORD BugcheckReasonCallbackRecord;
static BOOLEAN haveBugcheckReasonCallback;

/* The bugcheck reason bits don't exist on 2k, so we need to get at
   them through MmGetSystemRoutineAddress().  Unfortunately, we need
   to unregister from DISPATCH_LEVEL, so MmGetSystemRoutineAddress()
   won't work.  Work around this by finding the exports at register
   time and stashing them in global variables. */
typedef NTKERNELAPI BOOLEAN
keDeregisterBugCheckReasonCallback_t(PKBUGCHECK_REASON_CALLBACK_RECORD);
static keDeregisterBugCheckReasonCallback_t *
keDeregisterBugCheckReasonCallback;
typedef NTKERNELAPI BOOLEAN
keRegisterBugCheckReasonCallback_t(PKBUGCHECK_REASON_CALLBACK_RECORD,
                                   PKBUGCHECK_REASON_CALLBACK_ROUTINE,
                                   KBUGCHECK_CALLBACK_REASON,
                                   PUCHAR);
static keRegisterBugCheckReasonCallback_t *
keRegisterBugCheckReasonCallback;

/* This only exists on Vista+ */
typedef void
DEBUGPRINT_CALLBACK_FUNCTION(PANSI_STRING, ULONG, ULONG);
typedef DEBUGPRINT_CALLBACK_FUNCTION *
PDEBUGPRINT_CALLBACK_FUNCTION;
typedef NTKERNELAPI NTSTATUS
dbgSetDebugPrintCallback_t(PDEBUGPRINT_CALLBACK_FUNCTION,
                           BOOLEAN mode);
static dbgSetDebugPrintCallback_t *
dbgSetDebugPrintCallback;

BOOLEAN
haveDebugPrintCallback;

static EVTCHN_PORT
DebugVirqPort;

static struct irqsafe_lock
ModuleTableLock;
static PAUX_MODULE_EXTENDED_INFO
ModuleTable;
static ULONG
NrModulesInTable;

static struct irqsafe_lock
ImageNameLock;
static CHAR *
LastImageName;

static EVTCHN_DEBUG_CALLBACK
LastModuleCallback;

static BOOLEAN
haveImageLoadNotify;

static VOID
DebugIrqHandler(PVOID Context)
{
    KIRQL irql;
    int x;

    UNREFERENCED_PARAMETER(Context);

    irql = acquire_irqsafe_lock(&DebugCallbackLock);
    for (x = 0; x < NR_DEBUG_CALLBACKS; x++) {
        if (DebugCallbacks[x].cb) {
            TraceInternal(("%s:%s ====>\n", DebugCallbacks[x].module, DebugCallbacks[x].name));
            DebugCallbacks[x].cb(DebugCallbacks[x].data);
            TraceInternal(("%s:%s <====\n", DebugCallbacks[x].module, DebugCallbacks[x].name));
        }
    }
    release_irqsafe_lock(&DebugCallbackLock, irql);
}

EVTCHN_DEBUG_CALLBACK
__EvtchnSetupDebugCallback(const CHAR *module, const CHAR *name, VOID (*cb)(PVOID), PVOID d)
{
    int x;
    KIRQL irql;

    irql = acquire_irqsafe_lock(&DebugCallbackLock);
    for (x = 0; x < NR_DEBUG_CALLBACKS; x++) {
        if (DebugCallbacks[x].cb == NULL) {
            strncpy(DebugCallbacks[x].module, module, sizeof (DebugCallbacks[x].module));
            DebugCallbacks[x].module[sizeof (DebugCallbacks[x].module) - 1] = '\0';

            strncpy(DebugCallbacks[x].name, name, sizeof (DebugCallbacks[x].name));
            DebugCallbacks[x].name[sizeof (DebugCallbacks[x].name) - 1] = '\0';

            DebugCallbacks[x].data = d;
            DebugCallbacks[x].cb = cb;
            break;
        }
    }
    release_irqsafe_lock(&DebugCallbackLock, irql);
    if (x == NR_DEBUG_CALLBACKS)
        return null_EVTCHN_DEBUG_CALLBACK();
    else
        return wrap_EVTCHN_DEBUG_CALLBACK(x);
}

EVTCHN_DEBUG_CALLBACK
__EvtchnSetupDebugCallbackAnonymous(VOID (*cb)(PVOID), PVOID d)
{
    return __EvtchnSetupDebugCallback("unknown", "unknown", cb, d);
}

static void
DumpExceptionRecord(PEXCEPTION_RECORD exr)
{
    unsigned x;

    if (exr == NULL) {
        TraceInternal(("Null exception record?\n"));
        return;
    }
    TraceInternal(("Exception code %x, flags %x, record %p, address %p, %d parameters.\n",
                 exr->ExceptionCode, exr->ExceptionFlags,
                 exr->ExceptionRecord, exr->ExceptionAddress,
                 exr->NumberParameters));
    for (x = 0;
         x < exr->NumberParameters && x < EXCEPTION_MAXIMUM_PARAMETERS;
         x++)
        TraceInternal(("Param %d -> %x\n", x, exr->ExceptionInformation[x]));
}

static CHAR DumpBuffer[256];

#ifdef AMD64
static void
DumpContextRecord(PCONTEXT cxr)
{
    if (cxr == NULL) {
        TraceInternal(("Null context record?\n"));
        return;
    }
    TraceInternal(("Context flags %x, MxCsr %x\n", cxr->ContextFlags,
                 cxr->MxCsr));
    if (cxr->ContextFlags & CONTEXT_SEGMENTS)
        TraceInternal(("gs %x, fs %x, es %x, ds %x\n",
                     cxr->SegGs, cxr->SegFs, cxr->SegEs, cxr->SegDs));
    if (cxr->ContextFlags & CONTEXT_INTEGER) {
        TraceInternal(("rax %lx, rbx %lx, rcx %lx, rdx %lx, rbp %lx, rsi %lx, rdi %lx\n",
                     cxr->Rax,
                     cxr->Rbx,
                     cxr->Rcx,
                     cxr->Rdx,
                     cxr->Rbp,
                     cxr->Rsi,
                     cxr->Rdi));
        TraceInternal(("r8 %lx, r9 %lx, r10 %lx, r11 %lx, r12 %lx, r13 %lx, r14 %lx, r15 %lx\n",
                     cxr->R8,
                     cxr->R9,
                     cxr->R10,
                     cxr->R11,
                     cxr->R12,
                     cxr->R13,
                     cxr->R14,
                     cxr->R15));
    }
    if (cxr->ContextFlags & CONTEXT_CONTROL) {
        TraceInternal(("ss %x, rsp %lx, cs %lx, rip %lx, flags %x\n",
                     cxr->SegSs, cxr->Rsp, cxr->SegCs, cxr->Rip,
                     cxr->EFlags));
        PrintAddress(cxr->Rip, DumpBuffer, sizeof (DumpBuffer));
        TraceInternal(("%s\n", DumpBuffer));
    }
}
#else
static void
DumpContextRecord(PCONTEXT cxr)
{
    if (cxr == NULL) {
        TraceInternal(("Null context record?\n"));
        return;
    }
    TraceInternal(("Context flags %x\n", cxr->ContextFlags));
    if (cxr->ContextFlags & CONTEXT_SEGMENTS)
        TraceInternal(("gs %x, fs %x, es %x, ds %x\n",
                     cxr->SegGs, cxr->SegFs, cxr->SegEs, cxr->SegDs));
    if (cxr->ContextFlags & CONTEXT_INTEGER)
        TraceInternal(("edi %x, esi %x, ebx %x, edx %x, ecx %x, eax %x\n",
                     cxr->Edi, cxr->Esi, cxr->Ebx, cxr->Edx, cxr->Ecx,
                     cxr->Eax));
    if (cxr->ContextFlags & CONTEXT_CONTROL) {
        TraceInternal(("ebp %x, eip %x, cs %x, flags %x, esp %x, ss %x\n",
                     cxr->Ebp, cxr->Eip, cxr->SegCs, cxr->EFlags,
                     cxr->Esp, cxr->SegSs));
        PrintAddress(cxr->Eip, DumpBuffer, sizeof (DumpBuffer));
        TraceInternal(("%s\n", DumpBuffer));
    }
}
#endif

static void
DumpIoStatusBlock(PIO_STATUS_BLOCK iosb)
{
    TraceInternal(("IO Status block: info %p, pointer %p.\n",
                 iosb->Information, iosb->Pointer));
}

static void
DumpDeviceObject(PDEVICE_OBJECT dev)
{
    if (dev == NULL) {
        TraceInternal(("Null device object\n"));
        return;
    }
    if (dev->Type != IO_TYPE_DEVICE) {
        TraceInternal(("Device had wrong type (%d vs %d).\n", dev->Type,
                     IO_TYPE_DEVICE));
        return;
    }
    TraceInternal(("Device: Driver %p, next device %p, attached device %p, current irp %p.\n",
                 dev->DriverObject, dev->NextDevice, dev->AttachedDevice,
                 dev->CurrentIrp));
    TraceInternal(("Timer %p, flags %x, characteristics %x, vpb %p, dev ext %p, type %d\n",
                 dev->Timer, dev->Flags, dev->Characteristics,
                 dev->Vpb, dev->DeviceExtension, dev->DeviceType));
    TraceInternal(("Stack %d, queue.le %p %p, align %x\n",
                 dev->StackSize, dev->Queue.ListEntry.Flink,
                 dev->Queue.ListEntry.Blink, dev->AlignmentRequirement));
}

static void
DumpIoStackLocation(PIO_STACK_LOCATION isl)
{
    if (isl == NULL) {
        TraceInternal(("NULL io stack location?\n"));
        return;
    }
    TraceInternal(("Major %d, minor %d, flags %x, control %x\n",
                 isl->MajorFunction, isl->MinorFunction, isl->Flags,
                 isl->Control));
    TraceInternal(("Arguments %p %p %p %p\n",
                 isl->Parameters.Others.Argument1,
                 isl->Parameters.Others.Argument2,
                 isl->Parameters.Others.Argument3,
                 isl->Parameters.Others.Argument4));
    TraceInternal(("Device %p, file %p, complete %p, ctxt %p.\n",
                 isl->DeviceObject, isl->FileObject, isl->CompletionRoutine,
                 isl->Context));
    DumpDeviceObject(isl->DeviceObject);
}

static void
DumpIrp(PIRP irp)
{
    PIO_STACK_LOCATION isl;

    if (irp == NULL) {
        TraceInternal(("NULL irp.\n"));
        return;
    }
    if (irp->Type != IO_TYPE_IRP) {
        TraceInternal(("Expected an irp (type %d), got type %d.\n",
                     IO_TYPE_IRP, irp->Type));
        return;
    }
    TraceInternal(("IRP %p: MdlAddress %p, flags %x, assoc %p, tle %p,%p.\n",
                 irp,
                 irp->MdlAddress, irp->Flags, irp->AssociatedIrp.SystemBuffer,
                 irp->ThreadListEntry.Flink, irp->ThreadListEntry.Blink));
    DumpIoStatusBlock(&irp->IoStatus);
    TraceInternal(("RequestorMode %d, pr %d, stackcount %d, stackloc %d, cancel %d\n",
                 irp->RequestorMode, irp->PendingReturned, irp->StackCount,
                 irp->CurrentLocation, irp->Cancel));
    TraceInternal(("Cancel irql %d, apc env %d alloc flags %x, iosb %p, event %p.\n",
                 irp->CancelIrql, irp->ApcEnvironment, irp->AllocationFlags,
                 irp->UserIosb, irp->UserEvent));
    TraceInternal(("Overlay %p, %p, cancel routine %p, user buffer %p\n",
                 irp->Overlay.AsynchronousParameters.IssuingProcess,
                 irp->Overlay.AsynchronousParameters.UserApcContext,
                 irp->CancelRoutine, irp->UserBuffer));
    PrintAddress((ULONG_PTR)irp->CancelRoutine, DumpBuffer, sizeof (DumpBuffer));
    TraceInternal(("%s\n", DumpBuffer));
    TraceInternal(("Driver context %p %p %p %p, thread %p, aux %p, le %p %p, csl %p, orig file %p\n",
                 irp->Tail.Overlay.DriverContext[0],
                 irp->Tail.Overlay.DriverContext[1],
                 irp->Tail.Overlay.DriverContext[2],
                 irp->Tail.Overlay.DriverContext[3],
                 irp->Tail.Overlay.Thread,
                 irp->Tail.Overlay.AuxiliaryBuffer,
                 irp->Tail.Overlay.ListEntry.Flink,
                 irp->Tail.Overlay.ListEntry.Blink,
                 irp->Tail.Overlay.CurrentStackLocation));

    for (isl = irp->Tail.Overlay.CurrentStackLocation - 1;
         isl < irp->Tail.Overlay.CurrentStackLocation + 1;
         isl++)
        DumpIoStackLocation(isl);
}

void
EvtchnReleaseDebugCallback(EVTCHN_DEBUG_CALLBACK handle)
{
    KIRQL irql;
    int h;

    if (is_null_EVTCHN_DEBUG_CALLBACK(handle))
        return;
    h = unwrap_EVTCHN_DEBUG_CALLBACK(handle);
    irql = acquire_irqsafe_lock(&DebugCallbackLock);
    DebugCallbacks[h].data = NULL;
    DebugCallbacks[h].cb = NULL;
    release_irqsafe_lock(&DebugCallbackLock, irql);
}

static PAUX_MODULE_EXTENDED_INFO
AddressToModule(ULONG_PTR addr)
{
    PAUX_MODULE_EXTENDED_INFO table;
    ULONG x;

    table = ModuleTable;
    if (table == NULL)
        return NULL;

    for (x = 0; x < NrModulesInTable; x++) {
        if (addr >= (ULONG_PTR)table[x].BasicInfo.ImageBase &&
            addr < (ULONG_PTR)table[x].BasicInfo.ImageBase +
                       table[x].ImageSize)
            return &table[x];
    }
    return NULL;
}

void
PrintAddress(ULONG_PTR addr, CHAR *buffer, ULONG length)
{
    PAUX_MODULE_EXTENDED_INFO module;

    module = AddressToModule(addr);
    if (module == NULL) {
        Xmsnprintf(buffer, length, "%p", (void *)addr);
    } else {
        Xmsnprintf(buffer, length, "%p [%.*s + %p]",
                   addr, AUX_KLIB_MODULE_PATH_LEN, module->FullPathName,
                   addr - (ULONG_PTR)module->BasicInfo.ImageBase);
    }
    return;
}

/* Populate ModuleTable based on the currently-loaded drivers. */
static void
UpdateModuleTable(void)
{
    ULONG buffer_size;
    NTSTATUS status;
    PAUX_MODULE_EXTENDED_INFO module_table;
    ULONG nr_modules_in_table;
    PAUX_MODULE_EXTENDED_INFO old_module_table;
    KIRQL irql;

    status = AuxKlibQueryModuleInformation(&buffer_size,
                                           sizeof(AUX_MODULE_EXTENDED_INFO),
                                           NULL);
    if (!NT_SUCCESS(status)) {
        TraceError(("Cannot get size of module table (%x)\n", status));
        return;
    }

    module_table = NULL;
    do {
        XmFreeMemory(module_table);
        module_table = XmAllocateMemory(buffer_size);
        if (module_table == NULL) {
            TraceError(("Cannot allocate %d bytes for module table.\n",
                        buffer_size));
            return;
        }
        status = AuxKlibQueryModuleInformation(&buffer_size,
                                               sizeof(AUX_MODULE_EXTENDED_INFO),
                                               module_table);
        if (!NT_SUCCESS(status))
            TraceWarning(("Cannot get module table (%x)!\n", status));
    } while (status == STATUS_BUFFER_TOO_SMALL);
    if (!NT_SUCCESS(status)) {
        XmFreeMemory(module_table);
        TraceError(("Error %x getting module table\n", status));
        return;
    }

    nr_modules_in_table = buffer_size / sizeof(module_table[0]);

    irql = acquire_irqsafe_lock(&ModuleTableLock);
    old_module_table = ModuleTable;
    ModuleTable = module_table;
    NrModulesInTable = nr_modules_in_table;
    release_irqsafe_lock(&ModuleTableLock, irql);

    XmFreeMemory(old_module_table);
}

static void
ReleaseModuleTable(void)
{
    KIRQL irql;
    PAUX_MODULE_EXTENDED_INFO mod_table;

    irql = acquire_irqsafe_lock(&ModuleTableLock);
    mod_table = ModuleTable;
    ModuleTable = NULL;
    NrModulesInTable = 0;
    release_irqsafe_lock(&ModuleTableLock, irql);

    XmFreeMemory(mod_table);
}

static VOID
DumpModuleTable(
    VOID
    )
{
    KIRQL       irql;
    ULONG       x;
    NTSTATUS    status;

    TraceInternal(("%s: ====>\n", __FUNCTION__));

    status = try_acquire_irqsafe_lock(&ModuleTableLock, &irql);
    if (!NT_SUCCESS(status)) {
        TraceInternal(("Count not acquire ModuleTableLock\n"));
        goto done;
    }

    TraceInternal(("%d module(s) loaded\n", NrModulesInTable));

    for (x = 0; x < NrModulesInTable; x++) {
        TraceInternal(("%d: [%p, %p): %s\n", 
                       x,
                       ModuleTable[x].BasicInfo.ImageBase,
                       (ULONG_PTR)ModuleTable[x].BasicInfo.ImageBase +
                       ModuleTable[x].ImageSize,
                       ModuleTable[x].FullPathName));
    }
    release_irqsafe_lock(&ModuleTableLock, irql);

done:
    TraceInternal(("%s: <====\n", __FUNCTION__));
}

static void
ImageLoadNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId,
                PIMAGE_INFO ImageInfo)
{
    ANSI_STRING full_image_name;
    CHAR *new_image_name;
    CHAR *old_image_name;
    KIRQL irql;

    UNREFERENCED_PARAMETER(ImageInfo);

    if (ProcessId != NULL)
        return; // Not interested in user process DLLs

    RtlUnicodeStringToAnsiString(&full_image_name, FullImageName, TRUE);

    new_image_name = XmAllocateMemory(full_image_name.Length + 1);
    if (new_image_name == NULL) {
        TraceError(("%s: No memory for module name\n", __FUNCTION__));
        RtlFreeAnsiString(&full_image_name);
        return;
    }

    memcpy(new_image_name, full_image_name.Buffer, full_image_name.Length);
    new_image_name[full_image_name.Length] = '\0';

    RtlFreeAnsiString(&full_image_name);

    irql = acquire_irqsafe_lock(&ImageNameLock);
    old_image_name = LastImageName;
    LastImageName = new_image_name;
    release_irqsafe_lock(&ImageNameLock, irql);

    if (old_image_name != NULL)
        XmFreeMemory(old_image_name);

    UpdateModuleTable();
}

static VOID
DumpLastModule(VOID *Context)
{
    KIRQL irql;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Context);

    status = try_acquire_irqsafe_lock(&ImageNameLock, &irql);
    if (!NT_SUCCESS(status)) {
        TraceInternal(("Count not acquire ImageNameLock\n"));
        return;
    }

    if (LastImageName != NULL)
        TraceInternal(("Last module loaded: %s\n", LastImageName));

    release_irqsafe_lock(&ImageNameLock, irql);
}

static VOID
DumpLog(
    VOID
    )
{
    TraceInternal(("%s: ====>\n", __FUNCTION__));

    XenTraceFlush();

    TraceInternal(("%s: <====\n", __FUNCTION__));
}

/* This is invoked when the system is about to bugcheck. */
static VOID
BugcheckCallback(
    IN PVOID buffer,
    IN ULONG length
)
{
    struct sched_shutdown sched_shutdown;
    int ret;
    extern PULONG_PTR KiBugCheckData;
    ULONG code;
    ULONG_PTR param1, param2, param3, param4;
    ULONG_PTR base_sp;
    ULONG_PTR sp;

    UNREFERENCED_PARAMETER(length);

    XenTraceSetBugcheckLevels();

    TraceInternal(("%s: ====>\n", __FUNCTION__));

    DumpModuleTable();
    DumpLog();
    DebugIrqHandler(NULL);

    sched_shutdown.reason = SHUTDOWN_crash;
    ret = HYPERVISOR_sched_op(SCHEDOP_shutdown_code, &sched_shutdown);
    if (ret < 0) {
        ret = HYPERVISOR_sched_op(SCHEDOP_shutdown_code_compat,
                                  &sched_shutdown);
        if (ret < 0)
            TraceInternal(("Failed to set shutdown code (%d).\n", ret));
        else
            TraceInternal(("Used compatibility shutdown operation.\n"));
    }

    code = (ULONG)KiBugCheckData[0];
    param1 = KiBugCheckData[1];
    param2 = KiBugCheckData[2];
    param3 = KiBugCheckData[3];
    param4 = KiBugCheckData[4];

    if ((UCHAR)(code >> 24) == XM_BUGCHECK_SIGNATURE) {
        UCHAR       Type = (UCHAR)(code >> 16);

        switch (Type) {
        case XM_BUGCHECK_TYPE_TRACE: {
            const CHAR  *Expr = (const CHAR *)param2;

            TraceInternal(("%s\n", Expr));
            break;
        }
        case XM_BUGCHECK_TYPE_ASSERT: {
            USHORT      Line = (USHORT)(code & 0xFFFF);
            const CHAR  *File = (const CHAR *)param1;
            const CHAR  *Expr = (const CHAR *)param2;

            TraceInternal(("XM_ASSERT: %s at %s:%d\n",
                           Expr, File, Line));
            break;
        }
        case XM_BUGCHECK_TYPE_ASSERT3U: {
            USHORT      Line = (USHORT)(code & 0xFFFF);
            const CHAR  *File = (const CHAR *)param1;
            const CHAR  *Expr = (const CHAR *)param2;
            ULONG_PTR   Lval = param3;
            ULONG_PTR   Rval = param4;

            TraceInternal(("XM_ASSERT: %s at %s:%d "
                           "(LVAL=%lu RVAL=%lu)\n",
                           Expr, File, Line,
                           Lval, Rval));
            break;
        }
        case XM_BUGCHECK_TYPE_ASSERT3S: {
            USHORT      Line = (USHORT)(code & 0xFFFF);
            const CHAR  *File = (const CHAR *)param1;
            const CHAR  *Expr = (const CHAR *)param2;
            LONG_PTR    Lval = param3;
            LONG_PTR    Rval = param4;

            TraceInternal(("XM_ASSERT: %s at %s:%d "
                           "(LVAL=%ld RVAL=%ld)\n",
                           Expr, File, Line,
                           Lval, Rval));
            break;
        }
        case XM_BUGCHECK_TYPE_ASSERT3P: {
            USHORT      Line = (USHORT)(code & 0xFFFF);
            const CHAR  *File = (const CHAR *)param1;
            const CHAR  *Expr = (const CHAR *)param2;
            UCHAR       *Lval = (UCHAR *)param3;
            UCHAR       *Rval = (UCHAR *)param4;

            TraceInternal(("XM_ASSERT: %s at %s:%d "
                           "(LVAL=%p RVAL=%p)\n",
                           Expr, File, Line,
                           Lval, Rval));
            break;
        }
        }
    } else {
        switch (code) {
        case 0x0000000A:
            TraceInternal(("IRQL_NOT_LESS_OR_EQUAL\n"));
            PrintAddress(param1, DumpBuffer, sizeof (DumpBuffer));
            TraceInternal(("%s\n", DumpBuffer));
            PrintAddress(param4, DumpBuffer, sizeof (DumpBuffer));
            TraceInternal(("%s\n", DumpBuffer));
            break;
        case 0x0000002A:
            TraceInternal(("INCONSISTENT_IRP\n"));
            DumpIrp((PIRP)param1);
            break;
        case 0x0000003B:
            TraceInternal(("SYSTEM_SERVICE_EXCEPTION\n"));
            DumpExceptionRecord((PEXCEPTION_RECORD)param2);
            DumpContextRecord((PCONTEXT)param3);
            break;
        case 0x00000050:
            TraceInternal(("PAGE_FAULT_IN_NONPAGED_AREA\n"));
            PrintAddress(param1, DumpBuffer, sizeof (DumpBuffer));
            TraceInternal(("%s\n", DumpBuffer));
            PrintAddress(param3, DumpBuffer, sizeof (DumpBuffer));
            TraceInternal(("%s\n", DumpBuffer));
            break;
        case 0x0000007B: {
            PUSHORT p = (PUSHORT)param1;
            if (*p == 3) {
                TraceInternal(("Cannot find boot device, but device object exists.\n"));
                DumpDeviceObject((PDEVICE_OBJECT)param1);
            } else {
                PUNICODE_STRING pus = (PUNICODE_STRING)p;
                TraceInternal(("Cannot find boot device.\n"));
                TraceInternal(("Name length %d.\n", pus->Length));
                if ((pus->Length&1) == 0 && (pus->Length < pus->MaximumLength)) {
                    int x;
                    for (x = 0; x < pus->Length / 2; x++)
                        TraceInternal(("%c\n", pus->Buffer[x]));
                }
            }
            break;
        }
        case 0x0000007E:
            TraceInternal(("System thread exception not handled.\n"));
            DumpExceptionRecord((PEXCEPTION_RECORD)param3);
            DumpContextRecord((PCONTEXT)param4);
            break;
        case 0x000000C9:
            if (param1 == 0x231) {
                TraceInternal(("Completed IRP_MJ_POWER instead of passing it down.\n"));
                DumpIrp((PIRP)param3);
            }
            break;
        case 0x000000F4:
            TraceInternal(("CRITICAL_OBJECT_TERMINATION, image %s, message %s\n",
                           (char *)param3, (char *)param4));
            break;
        default:
            TraceInternal(("BUGCHECK %08x: %p, %p, %p, %p\n",
                         code, param1, param2, param3, param4));
            break;
        }
    }

    base_sp = (ULONG_PTR)&buffer;
    TraceInternal(("Stack from %p:\n", base_sp));
    TraceInternal(("-----\n"));
    for (sp = base_sp;
         (sp & ~(PAGE_SIZE-1)) == (base_sp & ~(PAGE_SIZE-1));
         sp += sizeof(ULONG_PTR)) {
        PrintAddress(*(ULONG_PTR *)sp, DumpBuffer, sizeof (DumpBuffer));
        TraceInternal(("%p -> %s\n", sp, DumpBuffer));
    }
    TraceInternal(("-----\n"));

    TraceInternal(("%s: <====\n", __FUNCTION__));
}

/* This is called while we're writing out a dump file, and is supposed
   to capture some ``interesting'' information about the crash.  For
   us, that means the log ring. */
static void
BugcheckReasonCallback(KBUGCHECK_CALLBACK_REASON reason,
                       PKBUGCHECK_REASON_CALLBACK_RECORD record,
                       PVOID specific_data,
                       ULONG specific_length)
{
    static BOOLEAN haveToldXen;
    PKBUGCHECK_SECONDARY_DUMP_DATA data;
    ULONG max_buffer_size;

    UNREFERENCED_PARAMETER(record);

    TraceInternal(("%s: ====>\n", __FUNCTION__));

    if (!haveToldXen) {
        /* Tell Xen that we're crashing, and see if it can figure out
           why. */
        /* Xen 4.1: obsolete HVM_op
        HYPERVISOR_hvm_op(HVMOP_audit_world, NULL);*/
        haveToldXen = TRUE;
    }

    if (reason != KbCallbackSecondaryDumpData ||
        specific_length < sizeof(KBUGCHECK_SECONDARY_DUMP_DATA)) {
        TraceInternal(("Strange dump callback: reason %d, size %d.\n",
                      reason, specific_length));
        return;
    }

    data = specific_data;

    max_buffer_size = data->InBufferLength;
    if (max_buffer_size > data->MaximumAllowed)
        max_buffer_size = data->MaximumAllowed;

    data->Guid = BugcheckAuxDataGuid;
    data->OutBuffer = data->InBuffer;
    data->OutBufferLength = XmExtractTailOfLog((void *)data->OutBuffer,
                                               max_buffer_size);

    TraceInternal(("%s: <====\n", __FUNCTION__));
}

/* Be very careful in here.  You need to make sure that *nothing* you
   call ends up back in DbgPrint(), which is a bit tricky, because
   RtlStringVPrintf (and hence __XenTrace*()) can end up calling into
   it for certain format strings.  In particular, %z is not
   allowed. */
static void
DbgPrintCallback(PANSI_STRING msg, ULONG component, ULONG level)
{
    /* cdrom.sys polls the CD drive every second and, if it's found to
       be non-empty, sends a message to the debugger saying so.  This
       is pretty much maximally non-useful, so filter them out from
       here. */
    if (component == DPFLTR_CDROM_ID && level == DPFLTR_WARNING_LEVEL) {
        static const char stupidCdromMessage[] =
            "Will not retry; Sense/ASC/ASCQ of 02/3a/00";

        if (msg->Length == sizeof(stupidCdromMessage) &&
            memcmp(msg->Buffer, stupidCdromMessage,
                   sizeof(stupidCdromMessage)-1) == 0) {
            /* It's a stupid CDROM message.  Drop it. */
            return;
        }
    }

    TraceInternal(("%.*s", msg->Length, msg->Buffer));
}

void
RegisterBugcheckCallbacks(void)
{
    if (AustereMode)
        return;

    if (!haveBugcheckCallback) {
        TraceInfo(("Installing bugcheck callback\n"));

        KeInitializeCallbackRecord(&BugcheckCallbackRecord);
        if (KeRegisterBugCheckCallback(&BugcheckCallbackRecord,
                                       BugcheckCallback,
                                       NULL,
                                       0,
                                       (PUCHAR)"BugcheckCallback")) {
            haveBugcheckCallback = TRUE;
        } else {
            TraceWarning(("Failed to install bugcheck callback\n"));
        }
    } else {
        TraceWarning(("Bugcheck callback already installed\n"));
    }    

    if (keRegisterBugCheckReasonCallback == NULL) {
        UNICODE_STRING reg;

        RtlInitUnicodeString(&reg, L"KeRegisterBugCheckReasonCallback");

        keRegisterBugCheckReasonCallback =
            (keRegisterBugCheckReasonCallback_t *)(ULONG_PTR)MmGetSystemRoutineAddress(&reg);
        if (keRegisterBugCheckReasonCallback == NULL)
            TraceWarning(("failed to find system routine: KeRegisterBugCheckReasonCallback\n"));
    }

    if (keDeregisterBugCheckReasonCallback == NULL) {
        UNICODE_STRING dereg;

        RtlInitUnicodeString(&dereg, L"KeDeregisterBugCheckReasonCallback");

        keDeregisterBugCheckReasonCallback =
            (keDeregisterBugCheckReasonCallback_t *)(ULONG_PTR)MmGetSystemRoutineAddress(&dereg);
        if (keDeregisterBugCheckReasonCallback == NULL)
            TraceWarning(("failed to find system routine: KeDeregisterBugCheckReasonCallback\n"));
    }

    if (!haveBugcheckReasonCallback) {
        if (keRegisterBugCheckReasonCallback != NULL &&
            keDeregisterBugCheckReasonCallback != NULL) {

            TraceInfo(("Installing bugcheck reason callback\n"));

            KeInitializeCallbackRecord(&BugcheckReasonCallbackRecord);
            if (keRegisterBugCheckReasonCallback(&BugcheckReasonCallbackRecord,
                                                 BugcheckReasonCallback,
                                                 KbCallbackSecondaryDumpData,
                                                 (PUCHAR)"SecondaryDumpData")) {
                haveBugcheckReasonCallback = TRUE;
            } else {
                TraceWarning(("Failed to install bugcheck reason callback\n"));
            }
        } else {
            TraceInfo(("Bugcheck reason callback not supported\n"));
        }
    } else {
        TraceWarning(("Bugcheck reason callback already installed\n"));
    }
}

void
DeregisterBugcheckCallbacks(void)
{
    if (haveBugcheckCallback) {
        KeDeregisterBugCheckCallback(&BugcheckCallbackRecord);
        haveBugcheckCallback = FALSE;
    }

    if (haveBugcheckReasonCallback) {
        XM_ASSERT(keDeregisterBugCheckReasonCallback != NULL);
        keDeregisterBugCheckReasonCallback(&BugcheckReasonCallbackRecord);
        haveBugcheckReasonCallback = FALSE;
    }
}

void
ConnectDebugVirq(void)
{
    if (is_null_EVTCHN_PORT(DebugVirqPort))
        DebugVirqPort = EvtchnBindVirq(VIRQ_DEBUG, DebugIrqHandler, NULL);
    else
        TraceWarning (("Debug VIRQ alread connected?\n"));
}


void
DisconnectDebugVirq(void)
{
    if (!is_null_EVTCHN_PORT(DebugVirqPort)) {
        EvtchnClose(DebugVirqPort);
        DebugVirqPort = null_EVTCHN_PORT();
    }
}

void
InitDebugHelpers(void)
{
    NTSTATUS status;

    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        return;

    if (XenPVFeatureEnabled(DEBUG_TRAP_DBGPRINT) &&
        !haveDebugPrintCallback) {
        RTL_OSVERSIONINFOEXW verInfo;

        /* Some versions of Windows have a bug in
         * MmGetSystemRoutineAddress() which makes them crash if you
         * try to look up a function which doesn't exist
         * (http://www.osronline.com/article.cfm?article=494).  This
         * only happens for certain symbols, though.
         * DbgSetDebugPrintCallback seems to be one of the bad ones,
         * so only look it up if we're on a version of Windows where
         * that will succeed. */

        XenutilGetVersionInfo(&verInfo);

        if (verInfo.dwMajorVersion >= 6) {
            UNICODE_STRING name;
            RtlInitUnicodeString(&name, L"DbgSetDebugPrintCallback");
            dbgSetDebugPrintCallback =
                (dbgSetDebugPrintCallback_t *)(ULONG_PTR)MmGetSystemRoutineAddress(&name);
            if (dbgSetDebugPrintCallback != NULL) {
                status = dbgSetDebugPrintCallback(DbgPrintCallback, TRUE);
                if (NT_SUCCESS(status)) {
                    haveDebugPrintCallback = TRUE;
                    XenDbgPrint("DbgPrint() hooking enabled\n");
                }
            }
        }
    }

    UpdateModuleTable();

    if (is_null_EVTCHN_DEBUG_CALLBACK(LastModuleCallback))
        LastModuleCallback = EvtchnSetupDebugCallback(DumpLastModule, NULL);

    if (!haveImageLoadNotify) {
        status = PsSetLoadImageNotifyRoutine(ImageLoadNotify);
        if (NT_SUCCESS(status)) {
            haveImageLoadNotify = TRUE;
        } else {
            TraceError(("Cannot register image load notify routine.\n"));
        }
    }
}

void
CleanupDebugHelpers(void)
{
    if (!is_null_EVTCHN_DEBUG_CALLBACK(LastModuleCallback))
        EvtchnReleaseDebugCallback(LastModuleCallback);

    ReleaseModuleTable();

    if (LastImageName != NULL) {
        XmFreeMemory(LastImageName);
        LastImageName = NULL;
    }

    if (haveDebugPrintCallback) {
        XM_ASSERT(dbgSetDebugPrintCallback != NULL);
        dbgSetDebugPrintCallback(DbgPrintCallback, FALSE);
        haveDebugPrintCallback = FALSE;
    }
}

/*
 * This appears to be an orphan function, but it may be that Symantec have
 * have linked against a .lib that incorporates it, thus it needs to
 * stick around even though we don't use it.
 */
void
__XenTrace(XEN_TRACE_LEVEL level, __in_ecount(module_size) PCSTR module,
           size_t module_size, PCSTR fmt, va_list args)
{
    ___XenTrace(level, module, module_size, fmt, args);
}
