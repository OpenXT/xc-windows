//
// xengfx_wdk.c - WDK support routines
//
// Copyright (c) 2008 Citrix, Inc.
//

/*
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


#include <ntddk.h>
#include <ntstrsafe.h>
#include "xengfx_shared.h"
#include "xengfx_regs.h"

PVOID NTAPI XenGfxCreateCallback(const wchar_t *pCallback)
{
    PCALLBACK_OBJECT pCallbackObject = NULL;
    NTSTATUS NtStatus;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING CallbackName;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    RtlInitUnicodeString(&CallbackName, pCallback);
    InitializeObjectAttributes(&oa, &CallbackName, OBJ_CASE_INSENSITIVE|OBJ_PERMANENT, NULL, NULL);

    NtStatus = ExCreateCallback(&pCallbackObject, &oa, TRUE, TRUE);
    if (NtStatus != STATUS_SUCCESS) {
        TraceError(("ExCreateCallback failed - Status: 0x%x\n", NtStatus));
        return NULL;
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return pCallbackObject;    
}

PVOID NTAPI XenGfxRegisterCallback(PVOID pCallbackObject, CallbackFuncion_t pCallbackFuncion, PVOID pContext)
{
    PVOID pCallbackHandle;

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    pCallbackHandle = ExRegisterCallback(pCallbackObject, pCallbackFuncion, pContext);
    if (pCallbackHandle == NULL) {
        TraceError(("ExRegisterCallback failed\n"));
        return NULL;
    }

    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));

    return pCallbackHandle;
}

VOID NTAPI XenGfxNotifyCallback(PVOID pCallbackObject, PVOID pContext)
{
    if (pCallbackObject != NULL)
        ExNotifyCallback((PCALLBACK_OBJECT)pCallbackObject, pContext, (PVOID)NULL);
}

VOID NTAPI XenGfxUnregisterCallback(PVOID pCallbackHandle)
{
    if (pCallbackHandle != NULL)
        ExUnregisterCallback(pCallbackHandle);
}

VOID NTAPI XenGfxDestroyCallback(PVOID pCallbackObject)
{
    if (pCallbackObject != NULL)
        ObDereferenceObject(pCallbackObject);
}

KIRQL NTAPI XenGfxRaiseIrqlToDpcLevel()
{
    return KeRaiseIrqlToDpcLevel();
}

VOID NTAPI XenGfxLowerIrql(KIRQL Irql)
{
    KeLowerIrql(Irql);
}

PVOID XenGfxAllocateContiguousPages(ULONG Count)
{
    PHYSICAL_ADDRESS PhysAddr;

    if (Count == 0)
        return NULL;

    // For a single page we can use the standard allocators (much preferred).
    if (Count == 1)
        return ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, XENGFX_TAG);

    PhysAddr.QuadPart = (ULONGLONG)-1;
    return MmAllocateContiguousMemory(Count*PAGE_SIZE, PhysAddr);
}

VOID XenGfxFreeContiguousPages(PVOID pPages, ULONG Count)
{
    KIRQL Irql;

    if (Count == 1)
        ExFreePoolWithTag(pPages, XENGFX_TAG);

    if (Count > 1) {
        KeRaiseIrql(APC_LEVEL, &Irql);
        MmFreeContiguousMemory(pPages);
        KeLowerIrql(Irql);
    }
}

typedef struct _XENGFX_MEMCTX {
    PVOID pMappingAddress;
    PMDL pMappingMdl;
    PVOID pMemPtr;
    BOOLEAN Locked;
} XENGFX_MEMCTX, *PXENGFX_MEMCTX;

VOID XenGfxFreeSystemPages(PVOID pContext)
{
    XENGFX_MEMCTX *pMemCtx = (XENGFX_MEMCTX*)pContext;

    if (pMemCtx == NULL)
        return;

    if (pMemCtx != NULL) {        
        if (pMemCtx->pMappingMdl != NULL) {
            if (pMemCtx->pMemPtr != NULL)
                MmUnmapReservedMapping(pMemCtx->pMemPtr, XENGFX_TAG, pMemCtx->pMappingMdl);
            MmFreePagesFromMdl(pMemCtx->pMappingMdl);
        }
        if (pMemCtx->pMappingAddress != NULL)
            MmFreeMappingAddress(pMemCtx->pMappingAddress, XENGFX_TAG);
        ExFreePoolWithTag(pMemCtx, XENGFX_TAG);
    }
}


PVOID XenGfxAllocateSystemPages(ULONG Count, PVOID *ppContex)
{
    XENGFX_MEMCTX *pMemCtx;
    PHYSICAL_ADDRESS lowAddr;
    PHYSICAL_ADDRESS highAddr;
    PHYSICAL_ADDRESS skip;

    if (ppContex == NULL)
        return NULL;
    *ppContex = NULL;

    do {
        pMemCtx = ExAllocatePoolWithTag(NonPagedPool, sizeof(XENGFX_MEMCTX), XENGFX_TAG);
        if (pMemCtx == NULL)
            break;
        RtlZeroMemory(pMemCtx, sizeof(XENGFX_MEMCTX));

        pMemCtx->pMappingAddress = MmAllocateMappingAddress(Count, XENGFX_TAG);
        if (pMemCtx->pMappingAddress == NULL)
            break;

        lowAddr.QuadPart = 0;
        highAddr.QuadPart = 0xFFFFFFFFFFFFFFFF;
        skip.QuadPart = PAGE_SIZE;
        pMemCtx->pMappingMdl = MmAllocatePagesForMdl(lowAddr, highAddr, skip, Count);
        if (pMemCtx->pMappingMdl == NULL) {
            break;
        }

        pMemCtx->pMemPtr = 
            MmMapLockedPagesWithReservedMapping(pMemCtx->pMappingAddress,
                                                XENGFX_TAG,
                                                pMemCtx->pMappingMdl,
                                                MmNonCached);
        if (pMemCtx->pMemPtr == NULL)
            break;

        *ppContex = pMemCtx;
    } while (FALSE);

    if (*ppContex != pMemCtx)
        XenGfxFreeSystemPages(pMemCtx);
    return pMemCtx->pMemPtr;
}

VOID XenGfxMemoryBarrier()
{
    _mm_mfence();
    _ReadWriteBarrier();
}

PHYSICAL_ADDRESS XenGfxGetPhysicalAddress(PVOID pVirtualAddress)
{
    return MmGetPhysicalAddress(pVirtualAddress);
}

BOOLEAN XenGfxGetPhysicalAddressess(PVOID pVirtualAddress, PHYSICAL_ADDRESS *pPhysArray, ULONG PageCount)
{
    PUCHAR pPtr = (PUCHAR)pVirtualAddress;
    PHYSICAL_ADDRESS *pSlot = &pPhysArray[0];
    ULONG i;

    if (((ULONG64)pVirtualAddress % PAGE_SIZE) != 0)
        return FALSE;

    for (i = 0; i < PageCount; i++, pSlot++) {
        *pSlot = MmGetPhysicalAddress(pPtr);
        pPtr += PAGE_SIZE;
    }

    return TRUE;
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

    DbgPrint("%s", buf);
}
#endif
