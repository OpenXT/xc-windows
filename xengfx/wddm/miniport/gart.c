//
// gart.c - Xen Windows PV WDDM Miniport Driver GART routines.
//
// Copyright (c) 2010 Citrix, Inc. - All rights reserved.
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


#include "xengfxwd.h"

BOOLEAN
XenGfxGartInitialize(XENGFX_DEVICE_EXTENSION *pXenGfxExtension)
{
    ULONG32 *pGartReg = pXenGfxExtension->pGartBaseReg;
    ULONG i;

    // T & S Level 3
    ASSERT(pXenGfxExtension->pGartBaseReg != NULL);

    // Fetch some GART specific values from the global registers
    pXenGfxExtension->GartPfns = READ_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_GART_SIZE));
    pXenGfxExtension->GartPfns *= PAGE_SIZE;
    pXenGfxExtension->VideoPfns = pXenGfxExtension->GartPfns;
    pXenGfxExtension->VideoSegmentOffset = 0;
    pXenGfxExtension->StolenPfns = READ_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_STOLEN_SIZE));
    pXenGfxExtension->StolenBase = READ_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_STOLEN_BASE));

    // Sanity check GART values
    if (pXenGfxExtension->GartPfns > XENGFX_MAX_GART_PFNS) {
        TraceError(("%s Aperture size too big! - PFNs: %d (0x%x)\n",
                    __FUNCTION__, pXenGfxExtension->GartPfns, pXenGfxExtension->GartPfns));
        return FALSE;
    }

    if (pXenGfxExtension->StolenPfns > (pXenGfxExtension->GartPfns >> 1)) {
        // More than 1/2 the GART?
        TraceError(("%s Stolen memory size too big! - PFNs: %d (0x%x)\n",
                    __FUNCTION__, pXenGfxExtension->StolenPfns, pXenGfxExtension->StolenPfns));
        return FALSE;
    }

    if (pXenGfxExtension->StolenBase == ~0) {
        // Something wrong with backend
        TraceError(("%s Invalid stolen base PFN value!\n", __FUNCTION__));
        return FALSE;
    }
    
    // Loop and clear all GART registers to put the GART into an initial state
    for (i = 0; i < pXenGfxExtension->GartPfns; i++)
        pGartReg[i] = XGFX_GART_CLEAR_PFN;

    // Invalidate the GART to flush the changes
    (VOID)READ_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_INVALIDATE_GART));

    return TRUE;
}

VOID
XenGfxGartInitializeCursorSegment(XENGFX_DEVICE_EXTENSION *pXenGfxExtension)
{
    ULONG32 *pGartReg = pXenGfxExtension->pGartBaseReg;
    PHYSICAL_ADDRESS PhysAddr;
    ULONG i, Size, Pfns;
    UCHAR *pBuf;

    // T & S Level 3
    pXenGfxExtension->AdapterCursorSupported = TRUE;
    pXenGfxExtension->AdapterMaxCursorHeight = ~0;
    pXenGfxExtension->AdapterMaxCursorWidth = ~0;

    // A lock is not needed to access cursor registers for the VCRTCs. Loop
    // and find global adapter cursor values.
    for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) {
        if (!pXenGfxExtension->ppVCrtcBanks[i]->CursorSupported) {
            // If any do not support HW cursors then it will be disabled for the whole adapter.
            pXenGfxExtension->AdapterCursorSupported = FALSE;
            pXenGfxExtension->AdapterMaxCursorHeight = 0;
            pXenGfxExtension->AdapterMaxCursorWidth = 0;
            break;
        }
        if (pXenGfxExtension->ppVCrtcBanks[i]->MaxCursorHeight < pXenGfxExtension->AdapterMaxCursorHeight)
            pXenGfxExtension->AdapterMaxCursorHeight = pXenGfxExtension->ppVCrtcBanks[i]->MaxCursorHeight;
        if (pXenGfxExtension->ppVCrtcBanks[i]->MaxCursorWidth < pXenGfxExtension->AdapterMaxCursorWidth)
            pXenGfxExtension->AdapterMaxCursorWidth = pXenGfxExtension->ppVCrtcBanks[i]->MaxCursorWidth;
    }

    if (!pXenGfxExtension->AdapterCursorSupported)
        return;

    // At this point the largest cursor will be limited by the smallest values reported by all the
    // VCRTCs. The directx kernel will be given this value. For each VCRTC a chunk of aperture space will
    // be allocated and populated with system memory for copying cursor bitmaps into.
    Size = 4*pXenGfxExtension->AdapterMaxCursorHeight*pXenGfxExtension->AdapterMaxCursorWidth;    
    Size = XENGFX_MASK_ALIGN(Size, XENGFX_PAGE_ALIGN_MASK); // size of each VCRTC cursor allocation
    Pfns = Size/PAGE_SIZE;

    // Allocate system memory to back the cursor GART segment.
    pXenGfxExtension->CursorsBufferSize = Size*pXenGfxExtension->VCrtcCount;
    pXenGfxExtension->pCursorsBuffer = 
        XenGfxAllocateSystemPages(pXenGfxExtension->CursorsBufferSize,
                                  &pXenGfxExtension->pCursorsBufferContext);
    if (pXenGfxExtension->pCursorsBuffer == NULL) {     
        TraceError(("%s Failed to allocate system memory for the cursors GART segment!\n", __FUNCTION__));
        // Disable HW cursors and go on (thought probably not much further).
        pXenGfxExtension->AdapterCursorSupported = FALSE;
        pXenGfxExtension->AdapterMaxCursorHeight = 0;
        pXenGfxExtension->AdapterMaxCursorWidth = 0;
        return;
    }
    pBuf = (UCHAR*)pXenGfxExtension->pCursorsBuffer;

    // Make a segment right at the beginning and map in the system allocation.
    pXenGfxExtension->CursorSegmentOffset = 0;
    pXenGfxExtension->CursonPfns = Pfns*pXenGfxExtension->VCrtcCount;
    pXenGfxExtension->VideoSegmentOffset = pXenGfxExtension->CursonPfns*PAGE_SIZE;
    pXenGfxExtension->VideoPfns -= pXenGfxExtension->CursonPfns;

    for (i = 0; i < pXenGfxExtension->CursonPfns; i++) {
        XenGfxGetPhysicalAddressess(pBuf, &PhysAddr, 1);
        pGartReg[i] = XGFX_GART_REG_MASK & (XGFX_GART_VALID_PFN | (ULONG32)(PhysAddr.QuadPart/PAGE_SIZE));
        pBuf += PAGE_SIZE;
    }

    // Invalidate the GART to flush the changes
    (VOID)READ_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_INVALIDATE_GART));

    // Give a cursor buffer in the cursor GART segment to each VCRTC.
    for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) {
        pXenGfxExtension->ppVCrtcBanks[i]->pCursorBase = pXenGfxExtension->pCursorsBuffer + (i*Size);
        pXenGfxExtension->ppVCrtcBanks[i]->CursorSize = Size;
        pXenGfxExtension->ppVCrtcBanks[i]->CursorOffset = (i*Size);
    }
}

VOID
XenGfxGartReset(XENGFX_DEVICE_EXTENSION *pXenGfxExtension)
{
    ULONG32 *pGartReg = pXenGfxExtension->pGartBaseReg;
    ULONG i;

    // T & S Level 3
    ASSERT(pXenGfxExtension->pGartBaseReg != NULL);
    
    // Loop and reset the GART including the restoration of the stolen PFNs
    for (i = 0; i < pXenGfxExtension->GartPfns; i++) {
        if (i < pXenGfxExtension->StolenPfns)
            pGartReg[i] = XGFX_GART_REG_MASK & (XGFX_GART_VALID_PFN |(pXenGfxExtension->StolenPfns + i));
        else
            pGartReg[i] = XGFX_GART_CLEAR_PFN;
    }

    // Invalidate the GART to flush the changes
    (VOID)READ_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_INVALIDATE_GART));

    // Release any cursor segment system memory.
    if (pXenGfxExtension->pCursorsBufferContext != NULL)
        XenGfxFreeSystemPages(pXenGfxExtension->pCursorsBufferContext);

    // Reset all GART related state in the context.
    pXenGfxExtension->CursorSegmentOffset = 0;
    pXenGfxExtension->CursonPfns = 0;
    pXenGfxExtension->VideoSegmentOffset = 0;
    pXenGfxExtension->VideoPfns = 0;
    pXenGfxExtension->pCursorsBufferContext = NULL;
    pXenGfxExtension->pCursorsBuffer = NULL;
    pXenGfxExtension->CursorsBufferSize = 0;
}
static void
qadUpdatePrimary(XENGFX_DEVICE_EXTENSION * pXenGfxExtension, BOOLEAN flag)
{
    unsigned int i;
    for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) {
        XENGFX_VCRTC * pVCrtc = pXenGfxExtension->ppVCrtcBanks[i];
        if (pVCrtc->primary)
           XenGfxSetPrimaryForVCrtc(pXenGfxExtension, pVCrtc); // start scanning source
    }
}

NTSTATUS
XenGfxGartMapApertureSegment(XENGFX_DEVICE_EXTENSION *pXenGfxExtension,
                             SIZE_T OffsetInPages,
                             SIZE_T NumberOfPages,
                             PMDL pMdl,
                             UINT MdlOffset)
{
    KIRQL Irql;
    ULONG i;
    ULONG32 *pGartReg;
    PPFN_NUMBER pPfn;

    // N. B. I think I was overdoing what needs to be done to track GART allocations.
    // The DDI adapter info and allocation routines return information to the video memory
    // manager that it uses to create allocations in the aperture segment. This manager must
    // keep track of these allocations.
    //
    // So working under that assumption I will just keep it simple and not make a whole
    // mess of complicated allocation tracking machinery in here. If we need some of that
    // stuffs later then we can add it.

    // Sanity check, in the (unlikely) case that the stride alignment requirements
    // exceed the size of a page that the page offset matches what we reported as
    // the byte alignment requirements during allocation creation.
    if (pXenGfxExtension->MaxStrideAlignment > XENGFX_PAGE_ALIGN_MASK) {
        if ((pXenGfxExtension->MaxStrideAlignment & (OffsetInPages * PAGE_SIZE)) != 0) {
            // This SNO
            TraceError(("%s Invalid aperture alignment requested - OffsetInPages: 0x%x\n",
                        __FUNCTION__, OffsetInPages));
            return STATUS_INVALID_PARAMETER;
        }
    }

    // Sanity check the requested aperture segment does not overrun the entire aperture.
    if ((OffsetInPages + NumberOfPages) > pXenGfxExtension->VideoPfns) {
        // This SNO
        TraceError(("%s Invalid aperture size requested - OffsetInPages: 0x%x NumberOfPages: 0x%x\n",
                    __FUNCTION__, OffsetInPages, NumberOfPages));
        return STATUS_INVALID_PARAMETER;
    }
    
    pGartReg = pXenGfxExtension->pGartBaseReg + OffsetInPages; // already checked alignment
    pPfn = &MmGetMdlPfnArray(pMdl)[MdlOffset];
    
    KeAcquireSpinLock(&pXenGfxExtension->GartLock, &Irql);

    // Map the pages into the GART
    for (i = 0; i < NumberOfPages; i++) {
        pGartReg[i] = XGFX_GART_REG_MASK & (XGFX_GART_VALID_PFN | (ULONG32)(pPfn[i])); 
    }

    // Invalidate the GART to flush the changes
    (VOID)READ_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_INVALIDATE_GART));

    KeReleaseSpinLock(&pXenGfxExtension->GartLock, Irql);
    if (OffsetInPages)
        qadUpdatePrimary(pXenGfxExtension, TRUE);
    return STATUS_SUCCESS;
}

NTSTATUS
XenGfxGartUnmapApertureSegment(XENGFX_DEVICE_EXTENSION *pXenGfxExtension,
                               SIZE_T OffsetInPages,
                               SIZE_T NumberOfPages,
                               PHYSICAL_ADDRESS DummyPage)
{
    KIRQL Irql;
    ULONG i;
    ULONG32 *pGartReg;
    ULONG32 DummyPfn;

    // Sanity check the requested aperture segment does not overrun the entire aperture.
    if ((OffsetInPages + NumberOfPages) > pXenGfxExtension->VideoPfns) {
        // This SNO
        TraceError(("%s Invalid aperture size requested - OffsetInPages: 0x%x NumberOfPages: 0x%x\n",
                    __FUNCTION__, OffsetInPages, NumberOfPages));
        return STATUS_INVALID_PARAMETER;
    }

    pGartReg = pXenGfxExtension->pGartBaseReg + OffsetInPages; // don't really care about alignment for clearing
    DummyPfn = (ULONG32)(DummyPage.QuadPart/PAGE_SIZE);

    KeAcquireSpinLock(&pXenGfxExtension->GartLock, &Irql);

    // The docs are not clear but it seems likely that the video memory manager would also want to
    // free PFNs in the GART. If this is the case it seems likely the dummy page would be set to 0.

    if (DummyPfn != 0) {
        for (i = 0; i < NumberOfPages; i++) {
            pGartReg[i] = XGFX_GART_UNMAP_MASK & DummyPfn;
        }
    }
    else {
        for (i = 0; i < NumberOfPages; i++) {
            pGartReg[i] = XGFX_GART_CLEAR_PFN;
        }
    }

    // Invalidate the GART to flush the changes
    (VOID)READ_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_INVALIDATE_GART));

    KeReleaseSpinLock(&pXenGfxExtension->GartLock, Irql);
    if (OffsetInPages)
        qadUpdatePrimary(pXenGfxExtension, FALSE);

    return STATUS_SUCCESS;
}

NTSTATUS
XenGfxGartTransfer(XENGFX_DEVICE_EXTENSION *pXenGfxExtension,
                   MDL *pMdlSrc,
                   LARGE_INTEGER PhysSrc,
                   MDL *pMdlDst,
                   LARGE_INTEGER PhysDst,
                   UINT TransferOffset,
                   UINT MdlOffset,
                   SIZE_T TransferSize)
{
    UCHAR *pSrc = NULL, *pDst = NULL;
    PHYSICAL_ADDRESS Addr;

    // This current implementation is a simple approach to doing this transfer
    // operation. If it turns out to be a performance issue, we should implement
    // something in the virtual HW interface to do these transfers in a DMAish
    // fashion.
    do {
        if (pMdlSrc != NULL) {
            // Get a virtual address for the system source memory.
            pSrc = (UCHAR*)MmGetSystemAddressForMdlSafe(pMdlSrc, HighPagePriority);
            if (pSrc == NULL) {
                TraceError(("%s Failed to get system address for source MDL!\n", __FUNCTION__));
                break;
            }
            // Advance pointer over MdlOffset offset retaining the byte offset for the MDL
            pSrc += (MdlOffset*PAGE_SIZE);
        }
        else {
            Addr = pXenGfxExtension->GraphicsApertureDescriptor.u.Memory.Start;
            Addr.QuadPart += (PhysSrc.QuadPart + TransferOffset);
            // Map in the physical source pages at the offset in our aperture.
            pSrc = MmMapIoSpace(Addr, TransferSize, MmNonCached);
            if (pSrc == NULL) {
                TraceError(("%s Failed to map aperture address for source offset!\n", __FUNCTION__));
                break;
            }
        }

        if (pMdlDst != NULL) {
            // Get a virtual address for the system destination memory.
            pDst = (UCHAR*)MmGetSystemAddressForMdlSafe(pMdlDst, HighPagePriority);
            if (pDst == NULL) {
                TraceError(("%s Failed to get system address for destination MDL!\n", __FUNCTION__));
                break;
            }
            // Advance pointer over MdlOffset offset retaining the byte offset for the MDL
            pDst += (MdlOffset*PAGE_SIZE);
        }
        else {
            Addr = pXenGfxExtension->GraphicsApertureDescriptor.u.Memory.Start;
            Addr.QuadPart += (PhysDst.QuadPart + TransferOffset);
            // Map in the physical destination pages at the offset in our aperture.
            pDst = MmMapIoSpace(Addr, TransferSize, MmNonCached);
            if (pDst == NULL) {
                TraceError(("%s Failed to map aperture address for destination offset!\n", __FUNCTION__));
                break;
            }
        }

        // Transfer
        RtlMoveMemory(pDst, pSrc, TransferSize);
    } while (FALSE);

    if ((pSrc != NULL)&&(pMdlSrc == NULL))
        MmUnmapIoSpace(pSrc, TransferSize);
    
    if ((pDst != NULL)&&(pMdlDst == NULL))
        MmUnmapIoSpace(pDst, TransferSize);

    return STATUS_SUCCESS;
}
