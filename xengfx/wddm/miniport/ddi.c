//
// ddi.c - Xen Windows PV WDDM Miniport Driver DDI routines.
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

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE,XenGfxControlEtwLogging)
#pragma alloc_text(PAGE,XenGfxQueryAdapterInfo)
#pragma alloc_text(PAGE,XenGfxCreateDevice)
#pragma alloc_text(PAGE,XenGfxCreateAllocation)
#pragma alloc_text(PAGE,XenGfxDestroyAllocation)
#pragma alloc_text(PAGE,XenGfxDescribeAllocation)
#pragma alloc_text(PAGE,XenGfxGetStandardAllocationDriverData)
#pragma alloc_text(PAGE,XenGfxAcquireSwizzlingRange)
#pragma alloc_text(PAGE,XenGfxReleaseSwizzlingRange)
#pragma alloc_text(PAGE,XenGfxBuildPagingBuffer)
#pragma alloc_text(PAGE,XenGfxSetPalette)
#pragma alloc_text(PAGE,XenGfxSetPointerPosition)
#pragma alloc_text(PAGE,XenGfxSetPointerShape)
#pragma alloc_text(PAGE,XenGfxEscape)
#pragma alloc_text(PAGE,XenGfxQueryCurrentFence)
#pragma alloc_text(PAGE,XenGfxGetScanLine)
#pragma alloc_text(PAGE,XenGfxStopCapture)
#pragma alloc_text(PAGE,XenGfxControlInterrupt)
#pragma alloc_text(PAGE,XenGfxDestroyDevice)
#pragma alloc_text(PAGE,XenGfxOpenAllocation)
#pragma alloc_text(PAGE,XenGfxCloseAllocation)
#pragma alloc_text(PAGE,XenGfxRender)
#pragma alloc_text(PAGE,XenGfxPresent)
#pragma alloc_text(PAGE,XenGfxCreateContext)
#pragma alloc_text(PAGE,XenGfxDestroyContext)
#endif

#pragma pack(push, 2)
typedef struct {
    union {
        struct {
            SHORT YPos;
            SHORT XPos;
        };
        INT Pos;
    };
} XENGFX_CURSOR_POS;

typedef struct {
    union {
        struct {
            USHORT YSize;
            USHORT XSize;
        };
        ULONG Size;
    };
} XENGFX_CURSOR_SIZE;
#pragma pack(pop)

static PXENGFX_MAPPED_MEMORY
XenGfxMapFB(PXENGFX_DEVICE_EXTENSION pXenGfxExtension, PXENGFX_DRIVER_ALLOCATION pDrvAllocation)
{
    RECT                    pRect;
    PHYSICAL_ADDRESS        Addr;
    PXENGFX_MAPPED_MEMORY   pMappedMemory;

    pMappedMemory = (PXENGFX_MAPPED_MEMORY)ExAllocatePoolWithTag(NonPagedPool, sizeof(XENGFX_MAPPED_MEMORY), XENGFX_TAG);
    if (!pMappedMemory) {
        TraceError(( "%s out of memory", __FUNCTION__));
        return NULL;
    }

    Addr = pXenGfxExtension->GraphicsApertureDescriptor.u.Memory.Start;
    Addr.QuadPart += pDrvAllocation->AllocationBase.QuadPart;

    pMappedMemory->mapSize = pDrvAllocation->SurfaceDesc.YResolution * pDrvAllocation->SurfaceDesc.Stride;
    pMappedMemory->pAddr = (PUCHAR) MmMapIoSpace(Addr, pMappedMemory->mapSize, MmNonCached);

    if (!pMappedMemory->pAddr) {
        ExFreePoolWithTag(pMappedMemory, XENGFX_TAG);
        TraceError (("%s failed to mapped rectangle from framebuffer", __FUNCTION__));
        return NULL;
    }
    return pMappedMemory;   
}

static void 
XenGfxFreeMappedMemory(PXENGFX_MAPPED_MEMORY  pMappedMemory)
{
    MmUnmapIoSpace(pMappedMemory->pAddr, pMappedMemory->mapSize);
    ExFreePoolWithTag(pMappedMemory, XENGFX_TAG);
}

static __inline PUCHAR
XenGfxStartRectAddress(PXENGFX_MAPPED_MEMORY pMM, PXENGFX_DRIVER_ALLOCATION pDrvAllocation, PRECT pRect)
{
    return pMM->pAddr + (pRect->top * pDrvAllocation->SurfaceDesc.Stride) + 
        (pRect->left *pDrvAllocation->SurfaceDesc.BytesPerPixel);
}

static void 
XenGfxSubRectBlt(PXENGFX_DMA_PRESENT pDmaPresent, PUCHAR pDst, PUCHAR pSrc,  int subRect, BOOLEAN vOverlap, BOOLEAN hOverlap)
{
    PXENGFX_DRIVER_ALLOCATION   pSrcDrvAllocation = pDmaPresent->pSourceAllocation;    
    PXENGFX_DRIVER_ALLOCATION   pDstDrvAllocation = pDmaPresent->pDestinationAllocation;    
    ULONG                       width; 
    ULONG                       i;
    PXENGFX_DMA_SUBRECT         pSubRect = (PXENGFX_DMA_SUBRECT)(pDmaPresent + 1) + subRect;
    LONG                        deltaX, overlap;
    
    width = pSubRect->width * pSrcDrvAllocation->SurfaceDesc.BytesPerPixel;

    //Copy bottom up
    if (vOverlap) {
        pSrc += ((pSubRect->top + pSubRect->height - 1) * pSrcDrvAllocation->SurfaceDesc.Stride) + 
            (pSubRect->left * pSrcDrvAllocation->SurfaceDesc.BytesPerPixel);
        pDst += ((pSubRect->top + pSubRect->height - 1) * pDstDrvAllocation->SurfaceDesc.Stride) + 
            (pSubRect->left * pSrcDrvAllocation->SurfaceDesc.BytesPerPixel);
    
    //Copy top to bottom
    }else {
        pSrc += (pSubRect->top * pSrcDrvAllocation->SurfaceDesc.Stride ) + 
            (pSubRect->left * pSrcDrvAllocation->SurfaceDesc.BytesPerPixel);

        pDst += (pSubRect->top * pDstDrvAllocation->SurfaceDesc.Stride ) +
            (pSubRect->left * pDstDrvAllocation->SurfaceDesc.BytesPerPixel);
    }

    if (hOverlap) {
        deltaX =  (pDmaPresent->DestinationRect.left - pDmaPresent->SourceRect.left )* pDstDrvAllocation->SurfaceDesc.BytesPerPixel;
        overlap = width - deltaX;
        if (overlap < 0) hOverlap = FALSE;
    }

    for ( i = 0; i < pSubRect->height; i++) {
        //Copy left to right
        if (!hOverlap)
            RtlCopyMemory(pDst, pSrc, width);

        //Copy in to non-overlapping right to left segments
        else {
            PUCHAR pFrom, pTo;
            pFrom = pDst;
            pTo = pDst + deltaX ;
            RtlCopyMemory(pTo, pFrom, overlap);

            pTo = pDst;
            pFrom = pSrc;
            RtlCopyMemory(pTo, pFrom, deltaX);
        }
        pDst += pDstDrvAllocation->SurfaceDesc.Stride * (vOverlap? -1 : 1);
        pSrc += pSrcDrvAllocation->SurfaceDesc.Stride * (vOverlap? -1 : 1);
    }
}

static void 
XenGfxBlt( PXENGFX_DEVICE_EXTENSION pXenGfxExtension, PXENGFX_DMA_PRESENT pDmaPresent)
{
    PXENGFX_MAPPED_MEMORY       pSrcMappedMemory, pDstMappedMemory;
    PXENGFX_DRIVER_ALLOCATION   pSrcAllocation, pDstAllocation;
    ULONG                       length;   
    BOOLEAN                     hOverlap, vOverlap;
    ULONG                        i;
    PUCHAR                      pSrc, pDst;

    XenGfxEnter(__FUNCTION__, 1);


    pSrcAllocation = pDmaPresent->pSourceAllocation;
    pDstAllocation = pDmaPresent->pDestinationAllocation;

    pSrcMappedMemory =  XenGfxMapFB(pXenGfxExtension, pSrcAllocation);
    if (!pSrcMappedMemory) {
        TraceError (("%s failed to map framebuffer ", __FUNCTION__));
        return;
    }

    pDstMappedMemory = XenGfxMapFB(pXenGfxExtension, pDstAllocation);
    if (!pDstMappedMemory) {
        TraceError (("%s failed to map framebuffer \n", __FUNCTION__));
        return;
    }

    pSrc = XenGfxStartRectAddress(pSrcMappedMemory, pSrcAllocation, &pDmaPresent->SourceRect);
    pDst = XenGfxStartRectAddress(pDstMappedMemory, pDstAllocation, &pDmaPresent->DestinationRect);

    //Determine direction of bitblt
    vOverlap = FALSE;
    hOverlap = FALSE;
    if (pDstAllocation == pSrcAllocation ) {
        if (pDmaPresent->SourceRect.top < pDmaPresent->DestinationRect.top) 
            vOverlap = TRUE;
        else if (pDmaPresent->SourceRect.top == pDmaPresent->DestinationRect.top && 
            pDmaPresent->SourceRect.left < pDmaPresent->DestinationRect.left &&
            pDmaPresent->SourceRect.left + pDmaPresent->SourceRect.right > pDmaPresent->DestinationRect.left)
            hOverlap = TRUE;  
    }

    for (i = 0; i < pDmaPresent->SubRectsCount; i++) {
        XenGfxSubRectBlt(pDmaPresent, pDst, pSrc, i, vOverlap, hOverlap);
    }

    XenGfxFreeMappedMemory(pSrcMappedMemory);
    XenGfxFreeMappedMemory(pDstMappedMemory);

    XenGfxLeave(__FUNCTION__);
}

static void
XenGfxFlipDebug(PXENGFX_DEVICE_EXTENSION pXenGfxExtension, PXENGFX_DMA_PRESENT pDmaPresent)
{
    ULONG               i;
    PXENGFX_VCRTC       pVcrtc = NULL;
    PHYSICAL_ADDRESS    SaveAddress;
    SIZE_T              fbSize;
    ULONG               debug = 1;
    ULONG               flip = 0;

    for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) {
        if (pXenGfxExtension->ppVCrtcBanks[i]->VidPnSourceId != pDmaPresent->pDestinationAllocation->VidPnSourceId) continue;
        pVcrtc = pXenGfxExtension->ppVCrtcBanks[i];
        SaveAddress = pVcrtc->PrimaryAddress;
        break;
    }
    if (!pVcrtc) return;

    fbSize = (SIZE_T)pDmaPresent->pSourceAllocation->AllocationBase.QuadPart;

    while (debug) {
        SIZE_T offset;

        offset = 0;
        if (flip)  offset = fbSize;
        flip = 1 - flip;
        pVcrtc->PrimaryAddress.QuadPart = SaveAddress.QuadPart + offset;
        XenGfxSetPrimaryForVCrtc(pXenGfxExtension, pVcrtc);
    }
    if (pVcrtc) pVcrtc->PrimaryAddress    = SaveAddress;
}

static NTSTATUS
XenGfxDoCommand(PXENGFX_DEVICE_EXTENSION pXenGfxExtension, PHYSICAL_ADDRESS dmaAddr, SIZE_T length)
{
    int                     debug = 0;
    UINT                    i;
    PXENGFX_DMA_PRESENT     pDmaPresent;

    // Map the DMA buffer
    pDmaPresent = (PXENGFX_DMA_PRESENT)MmMapIoSpace(dmaAddr, length, MmNonCached);
    if (pDmaPresent == NULL) {
        TraceError(("%s Out of Memory", __FUNCTION__));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (debug) XenGfxFlipDebug(pXenGfxExtension, pDmaPresent);

    if (pDmaPresent->Flags.Flip) {        
        for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) {
            if (pXenGfxExtension->ppVCrtcBanks[i]->VidPnSourceId != pDmaPresent->pSourceAllocation->VidPnSourceId)  continue;
            XenGfxSetPrimaryForVCrtc(pXenGfxExtension, pXenGfxExtension->ppVCrtcBanks[i]);
        }
    } else if (pDmaPresent->Flags.Blt) {
        //Do the blit 
        XenGfxBlt(pXenGfxExtension, pDmaPresent );
    }

    MmUnmapIoSpace(pDmaPresent, length);
    return STATUS_SUCCESS;
}

VOID APIENTRY
XenGfxControlEtwLogging(BOOLEAN Enable, ULONG Flags, UCHAR Level)
{
    UNREFERENCED_PARAMETER(Enable);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(Level);
    PAGED_CODE();

    XenGfxEnter(__FUNCTION__, 3);

    // Not using ETW logging at this point.

    XenGfxLeave(__FUNCTION__);
}

NTSTATUS APIENTRY
XenGfxQueryAdapterInfo(CONST HANDLE hAdapter, CONST DXGKARG_QUERYADAPTERINFO *pQueryAdapterInfo)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    NTSTATUS Status = STATUS_SUCCESS;
    DXGK_DRIVERCAPS* pDriverCaps;
    DXGK_QUERYSEGMENTOUT* pQuerySegmentOut;
    PHYSICAL_ADDRESS ApertureGpuBase = {0};
    PHYSICAL_ADDRESS CpuTranslatedAddress = {0};
    PAGED_CODE();

    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pQueryAdapterInfo))
        return STATUS_INVALID_PARAMETER;

    switch (pQueryAdapterInfo->Type) {
    case DXGKQAITYPE_UMDRIVERPRIVATE:
        if (pQueryAdapterInfo->OutputDataSize < sizeof(XENGFX_UMDRIVERPRIVATE)) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        // Copy over the private data for our display driver
        RtlMoveMemory(pQueryAdapterInfo->pOutputData,
                      &pXenGfxExtension->PrivateData,
                      sizeof(XENGFX_UMDRIVERPRIVATE));
        break;
    case DXGKQAITYPE_DRIVERCAPS:
        pDriverCaps = (DXGK_DRIVERCAPS*)pQueryAdapterInfo->pOutputData;

        // TODO some of these fields need more investigation
        pDriverCaps->HighestAcceptableAddress.QuadPart = (ULONG64)-1;
        pDriverCaps->MaxAllocationListSlotId = 74;
        pDriverCaps->ApertureSegmentCommitLimit = 0;
        if (pXenGfxExtension->AdapterCursorSupported) {
            pDriverCaps->MaxPointerWidth = pXenGfxExtension->AdapterMaxCursorWidth;
            pDriverCaps->MaxPointerHeight = pXenGfxExtension->AdapterMaxCursorHeight;
            pDriverCaps->PointerCaps.Value = 0;
            pDriverCaps->PointerCaps.Color = 1;
            pDriverCaps->PointerCaps.MaskedColor = 1;
        }
        else {      
            pDriverCaps->MaxPointerWidth = 0;
            pDriverCaps->MaxPointerHeight = 0;
            pDriverCaps->PointerCaps.Value = 0; // no cursor support
        }
        pDriverCaps->InterruptMessageNumber = 0;
        pDriverCaps->NumberOfSwizzlingRanges = 0; // none for now
        pDriverCaps->MaxOverlays = 0;
        pDriverCaps->GammaRampCaps.Value = 0;
        pDriverCaps->GammaRampCaps.Gamma_Rgb256x3x16 = 1;
        pDriverCaps->PresentationCaps.Value = 0;
        pDriverCaps->MaxQueuedFlipOnVSync = 1;
        pDriverCaps->FlipCaps.Value = 0;
        pDriverCaps->FlipCaps.FlipOnVSyncWithNoWait = 1;
        pDriverCaps->FlipCaps.FlipOnVSyncMmIo = 1;
        pDriverCaps->SchedulingCaps.Value = 0;
        pDriverCaps->SchedulingCaps.MultiEngineAware = 1;
        pDriverCaps->MemoryManagementCaps.Value = 0;
        pDriverCaps->MemoryManagementCaps.PagingNode = 0;
        pDriverCaps->GpuEngineTopology.NbAsymetricProcessingNodes = 2;

        break;
    case DXGKQAITYPE_QUERYSEGMENT:
        pQuerySegmentOut = (DXGK_QUERYSEGMENTOUT*)pQueryAdapterInfo->pOutputData;

        if (pQuerySegmentOut->pSegmentDescriptor == NULL) {
            // First call
            pQuerySegmentOut->NbSegment = 1;
            break;
        }

        RtlZeroMemory(pQuerySegmentOut->pSegmentDescriptor,
                      pQuerySegmentOut->NbSegment * sizeof(DXGK_SEGMENTDESCRIPTOR));

        // Skip the cursor segment if present. This portion of the aperture is hidden from the
        // directx memory manager.
        CpuTranslatedAddress = pXenGfxExtension->GraphicsApertureDescriptor.u.Memory.Start;
        CpuTranslatedAddress.QuadPart += pXenGfxExtension->VideoSegmentOffset;
        ApertureGpuBase.QuadPart += pXenGfxExtension->VideoSegmentOffset;

        // Setup one linear aperture-space segment
        pQuerySegmentOut->pSegmentDescriptor[0].BaseAddress = ApertureGpuBase;
        pQuerySegmentOut->pSegmentDescriptor[0].CpuTranslatedAddress = CpuTranslatedAddress;
        pQuerySegmentOut->pSegmentDescriptor[0].Size = PAGE_SIZE*pXenGfxExtension->VideoPfns;
        pQuerySegmentOut->pSegmentDescriptor[0].CommitLimit = PAGE_SIZE*pXenGfxExtension->VideoPfns;
        pQuerySegmentOut->pSegmentDescriptor[0].Flags.Value = 0;
        pQuerySegmentOut->pSegmentDescriptor[0].Flags.CpuVisible = 1;
        pQuerySegmentOut->pSegmentDescriptor[0].Flags.Aperture = 1;
        pQuerySegmentOut->PagingBufferSegmentId = 0;
        pQuerySegmentOut->PagingBufferSize = 64 * 1024; // TODO 
        pQuerySegmentOut->PagingBufferPrivateDataSize = 0;
        break;
    default:
        TraceWarning(("DXGKARG_QUERYADAPTERINFO type unrecognized - type: %d\n", pQueryAdapterInfo->Type));
        Status = STATUS_NOT_SUPPORTED;
    };

    XenGfxLeave(__FUNCTION__);

    return Status;
}

NTSTATUS APIENTRY
XenGfxCreateDevice(CONST HANDLE hAdapter, DXGKARG_CREATEDEVICE *pCreateDevice)
{
    XENGFX_D3D_DEVICE *pD3DDevice;
    PAGED_CODE();

    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pCreateDevice))
        return STATUS_INVALID_PARAMETER;

    pD3DDevice = ExAllocatePoolWithTag(NonPagedPool,
                                       sizeof(XENGFX_D3D_DEVICE),
                                       XENGFX_TAG);
    if (pD3DDevice == NULL)
        return STATUS_NO_MEMORY;

    RtlZeroMemory(pD3DDevice, sizeof(XENGFX_D3D_DEVICE));

    pD3DDevice->hDevice  = pCreateDevice->hDevice;
    pD3DDevice->pDeviceExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;

    pCreateDevice->hDevice = pD3DDevice;

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}
static void
XenGfxSetDriverAllocation(PXENGFX_DEVICE_EXTENSION pXenGfxExtension, D3DDDI_VIDEO_PRESENT_SOURCE_ID sourceID,
                          PXENGFX_DRIVER_ALLOCATION pDrvAllocation, BOOLEAN flag)
{
    KIRQL Irql;

    KeAcquireSpinLock(&pXenGfxExtension->SourcesLock, &Irql);
    if (flag && pXenGfxExtension->pSources[sourceID].InUse) {
        TraceError (("%s Failed to associate primary allocation with a VidPN source - source %d in use?\n",
            __FUNCTION__, sourceID));
    }else {
        pXenGfxExtension->pSources[sourceID].InUse = flag;
        pXenGfxExtension->pSources[sourceID].pPrimaryAllocation = pDrvAllocation;
        if (pDrvAllocation) 
            pDrvAllocation->State |= XENGFX_ALLOCATION_STATE_ASSIGNED;
    }
    KeReleaseSpinLock(&pXenGfxExtension->SourcesLock, Irql);
}

NTSTATUS APIENTRY
XenGfxCreateAllocation(CONST HANDLE hAdapter, DXGKARG_CREATEALLOCATION *pCreateAllocation)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    XENGFX_D3D_ALLOCATION *pD3dAllocation;
    XENGFX_DRIVER_ALLOCATION *pDriverAllocation;
    DXGK_ALLOCATIONINFO *pAllocInfo;
    ULONG i;
    NTSTATUS Status = STATUS_SUCCESS;
    PAGED_CODE();

    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pCreateAllocation))
        return STATUS_INVALID_PARAMETER;

    pAllocInfo = pCreateAllocation->pAllocationInfo;

    // Not using outer pPrivateDriverData struct, loop and fill in allocations.
    for (i = 0; i < pCreateAllocation->NumAllocations; i++, pAllocInfo++) {
        pDriverAllocation = 
            (XENGFX_DRIVER_ALLOCATION*)ExAllocatePoolWithTag(NonPagedPool,
                                                            sizeof(XENGFX_DRIVER_ALLOCATION),
                                                            XENGFX_TAG);
        if (pDriverAllocation == NULL) {
            Status = STATUS_NO_MEMORY;
            break;
        }
        RtlZeroMemory(pDriverAllocation, sizeof(XENGFX_DRIVER_ALLOCATION));
        pAllocInfo->hAllocation = (HANDLE)pDriverAllocation;

        // Get the allocation private data passed in from UM or as a standard
        // allocation from the directx kernel and copy the bits the driver needs.
        pD3dAllocation = (XENGFX_D3D_ALLOCATION*)pAllocInfo->pPrivateDriverData;
        if ((pD3dAllocation == NULL)||
            (pAllocInfo->PrivateDriverDataSize < sizeof(XENGFX_D3D_ALLOCATION))) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        // Validate the allocation information passed in
        if ((pD3dAllocation->SurfaceDesc.BytesPerPixel == 0)||
            (pD3dAllocation->SurfaceDesc.XResolution == 0)||
            (pD3dAllocation->SurfaceDesc.YResolution == 0)) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        // Should always be using MaxStrideAlignment + 1 for all allocations. Note that though
        // the source ID is known at this point, the target is potentially not yet known or
        // could change. Only during the DxgkDdiCommitVidPn are sources tied to targets.
        if (pD3dAllocation->ByteAlignment != (pXenGfxExtension->MaxStrideAlignment + 1)) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        // Update the driver allocation structure that is now associated with this particular
        // dx kernel allocation.
        pDriverAllocation->Type = pD3dAllocation->Type;
        pDriverAllocation->State = XENGFX_ALLOCATION_STATE_NONE;
        pDriverAllocation->VidPnSourceId = pD3dAllocation->VidPnSourceId;
        pDriverAllocation->SurfaceDesc = pD3dAllocation->SurfaceDesc;
        pDriverAllocation->ByteAlignment = pD3dAllocation->ByteAlignment;

        // If this is a primary allocation, it will have an association with a VidPN source so
        // set this up here.
        if (pD3dAllocation->Primary) {
            ASSERT(pD3dAllocation->VidPnSourceId < pXenGfxExtension->VCrtcCount);
            XenGfxSetDriverAllocation(pXenGfxExtension, pD3dAllocation->VidPnSourceId, pDriverAllocation, TRUE);
        }

        // Fill in allocation information
        pAllocInfo->Alignment = pDriverAllocation->ByteAlignment;
        pAllocInfo->Size = pD3dAllocation->SurfaceDesc.Stride * pD3dAllocation->SurfaceDesc.YResolution;
        pAllocInfo->PitchAlignedSize = 0;
        pAllocInfo->HintedBank.Value = 0;
        pAllocInfo->PreferredSegment.Value = 0;
        pAllocInfo->SupportedReadSegmentSet = 1;
        pAllocInfo->SupportedWriteSegmentSet = 1;
        pAllocInfo->EvictionSegmentSet = 0;
        pAllocInfo->MaximumRenamingListLength = 0;
        pAllocInfo->pAllocationUsageHint = NULL;
        pAllocInfo->Flags.Value = 0;
        pAllocInfo->Flags.CpuVisible = 1;
        pAllocInfo->AllocationPriority = D3DDDI_ALLOCATIONPRIORITY_NORMAL;       
    }

    // NOTE not using hResource now

    if (!NT_SUCCESS(Status)) {
        pAllocInfo = pCreateAllocation->pAllocationInfo;
        for (i = 0; i < pCreateAllocation->NumAllocations; i++, pAllocInfo++) {
            if (pAllocInfo->hAllocation != NULL) {
                ExFreePoolWithTag(pAllocInfo->hAllocation, XENGFX_TAG);
                pAllocInfo->hAllocation = NULL;
            }
        }
    }

    XenGfxLeave(__FUNCTION__);

    return Status;
}

NTSTATUS APIENTRY
XenGfxDestroyAllocation(CONST HANDLE hAdapter, CONST DXGKARG_DESTROYALLOCATION *pDestroyAllocation)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    XENGFX_DRIVER_ALLOCATION *pDriverAllocation;
    KIRQL Irql;
    ULONG i;
    PAGED_CODE();

    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pDestroyAllocation))
        return STATUS_INVALID_PARAMETER;

    for (i = 0; i < pDestroyAllocation->NumAllocations; i++) {
        // Primary allocations have associated VidPN sources that need to be freed
        pDriverAllocation = (XENGFX_DRIVER_ALLOCATION*)pDestroyAllocation->pAllocationList[i];
        if (pDriverAllocation->VidPnSourceId != D3DDDI_ID_UNINITIALIZED) {
            ASSERT(pDriverAllocation->VidPnSourceId < pXenGfxExtension->VCrtcCount);
            XenGfxSetDriverAllocation(pXenGfxExtension, pDriverAllocation->VidPnSourceId, NULL, FALSE);
        }

        ExFreePoolWithTag(pDestroyAllocation->pAllocationList[i], XENGFX_TAG);
    }

    if ((pDestroyAllocation->Flags.DestroyResource != 0)&&
        (pDestroyAllocation->hResource))
        ExFreePoolWithTag(pDestroyAllocation->hResource, XENGFX_TAG);

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxDescribeAllocation(CONST HANDLE hAdapter, DXGKARG_DESCRIBEALLOCATION *pDescribeAlloc)
{
    XENGFX_DRIVER_ALLOCATION *pDriverAllocation;
    PAGED_CODE();

    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pDescribeAlloc))
        return STATUS_INVALID_PARAMETER;

    pDriverAllocation = (XENGFX_DRIVER_ALLOCATION*)pDescribeAlloc->hAllocation;
    if (pDriverAllocation == NULL)
        return STATUS_INVALID_PARAMETER;

    pDescribeAlloc->Width = pDriverAllocation->SurfaceDesc.XResolution;
    pDescribeAlloc->Height = pDriverAllocation->SurfaceDesc.YResolution;
    pDescribeAlloc->Format = pDriverAllocation->SurfaceDesc.Format;
    pDescribeAlloc->RefreshRate = pDriverAllocation->SurfaceDesc.RefreshRate;

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxGetStandardAllocationDriverData(CONST HANDLE hAdapter,
                                      DXGKARG_GETSTANDARDALLOCATIONDRIVERDATA *pStandardAllocationDriverData)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    XENGFX_D3D_ALLOCATION *pD3dAllocation;
    PAGED_CODE();

    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pStandardAllocationDriverData))
        return STATUS_INVALID_PARAMETER;

    // Size reguest
    if (pStandardAllocationDriverData->pAllocationPrivateDriverData == NULL) {
        pStandardAllocationDriverData->AllocationPrivateDriverDataSize = sizeof(XENGFX_D3D_ALLOCATION);
        return STATUS_SUCCESS;
    }

    if (pStandardAllocationDriverData->AllocationPrivateDriverDataSize != sizeof(XENGFX_D3D_ALLOCATION))
        return STATUS_INVALID_PARAMETER;

    // This routine is used to describe the private data passed to standard allocations when
    // the XenGfx display DLL is not the source of the allocation. The non-primary surfaces below
    // use the max stride and alignment values for all vCRTC so they are usable for any target.
    pD3dAllocation = (XENGFX_D3D_ALLOCATION*)pStandardAllocationDriverData->pAllocationPrivateDriverData;    
    pStandardAllocationDriverData->ResourcePrivateDriverDataSize = 0;

    switch (pStandardAllocationDriverData->StandardAllocationType)
    {
    case D3DKMDT_STANDARDALLOCATION_SHAREDPRIMARYSURFACE:
    {
        D3DKMDT_SHAREDPRIMARYSURFACEDATA *pSPSD;
        pSPSD = pStandardAllocationDriverData->pCreateSharedPrimarySurfaceData;

        pD3dAllocation->Type = XENGFX_SHAREDPRIMARYSURFACE_TYPE;
        pD3dAllocation->Primary = TRUE;
        pD3dAllocation->VidPnSourceId = pSPSD->VidPnSourceId;
        pD3dAllocation->SurfaceDesc.XResolution = pSPSD->Width;
        pD3dAllocation->SurfaceDesc.YResolution = pSPSD->Height;
        pD3dAllocation->SurfaceDesc.BytesPerPixel = XenGfxBppFromDdiFormat(pSPSD->Format) >> 3;
        pD3dAllocation->SurfaceDesc.Stride = \
            XENGFX_MASK_ALIGN((pD3dAllocation->SurfaceDesc.BytesPerPixel*pSPSD->Width),
                              pXenGfxExtension->MaxStrideAlignment);           
        pD3dAllocation->SurfaceDesc.Format = pSPSD->Format;
        pD3dAllocation->SurfaceDesc.RefreshRate = pSPSD->RefreshRate;
        pD3dAllocation->ByteAlignment = pXenGfxExtension->MaxStrideAlignment + 1;
        return STATUS_SUCCESS;
    }
    case D3DKMDT_STANDARDALLOCATION_SHADOWSURFACE:
    {
        D3DKMDT_SHADOWSURFACEDATA *pSSD;
        pSSD = pStandardAllocationDriverData->pCreateShadowSurfaceData;

        pD3dAllocation->Type = XENGFX_SHADOWSURFACE_TYPE;
        pD3dAllocation->Primary = FALSE;
        pD3dAllocation->VidPnSourceId = D3DDDI_ID_UNINITIALIZED;
        pD3dAllocation->SurfaceDesc.XResolution = pSSD->Width;
        pD3dAllocation->SurfaceDesc.YResolution = pSSD->Height;
        pD3dAllocation->SurfaceDesc.BytesPerPixel = XenGfxBppFromDdiFormat(pSSD->Format) >> 3;
        pD3dAllocation->SurfaceDesc.Stride = \
            XENGFX_MASK_ALIGN((pD3dAllocation->SurfaceDesc.BytesPerPixel*pSSD->Width),
                              pXenGfxExtension->MaxStrideAlignment);
        pD3dAllocation->SurfaceDesc.Format = pSSD->Format;
        pD3dAllocation->SurfaceDesc.RefreshRate.Numerator = 60000;
        pD3dAllocation->SurfaceDesc.RefreshRate.Denominator = 1000;
        pD3dAllocation->ByteAlignment = pXenGfxExtension->MaxStrideAlignment + 1;

        // Return the stride/pitch requirement
        pSSD->Pitch = pD3dAllocation->SurfaceDesc.Stride;
        return STATUS_SUCCESS;
    }
    case D3DKMDT_STANDARDALLOCATION_STAGINGSURFACE:
    {
        D3DKMDT_STAGINGSURFACEDATA *pSSD;
        pSSD = pStandardAllocationDriverData->pCreateStagingSurfaceData;

        pD3dAllocation->Type = XENGFX_STAGINGSURFACE_TYPE;
        pD3dAllocation->Primary = FALSE;
        pD3dAllocation->VidPnSourceId = D3DDDI_ID_UNINITIALIZED;
        pD3dAllocation->SurfaceDesc.XResolution = pSSD->Width;
        pD3dAllocation->SurfaceDesc.YResolution = pSSD->Height;
        pD3dAllocation->SurfaceDesc.BytesPerPixel = XenGfxBppFromDdiFormat(D3DDDIFMT_X8R8G8B8) >> 3;
        pD3dAllocation->SurfaceDesc.Stride = \
            XENGFX_MASK_ALIGN((pD3dAllocation->SurfaceDesc.BytesPerPixel*pSSD->Width),
                               pXenGfxExtension->MaxStrideAlignment);
        pD3dAllocation->SurfaceDesc.Format = D3DDDIFMT_X8B8G8R8;
        pD3dAllocation->SurfaceDesc.RefreshRate.Numerator = 60000;
        pD3dAllocation->SurfaceDesc.RefreshRate.Denominator = 1000;
        pD3dAllocation->ByteAlignment = pXenGfxExtension->MaxStrideAlignment + 1;

        // Return the stride/pitch requirement
        pSSD->Pitch = pD3dAllocation->SurfaceDesc.Stride;
        return STATUS_SUCCESS;
    }
    default :
        return STATUS_INVALID_PARAMETER;
    }

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxAcquireSwizzlingRange(CONST HANDLE hAdapter,
                            DXGKARG_ACQUIRESWIZZLINGRANGE *pAcquireSwizzlingRange)
{
    PAGED_CODE();
    // T & S Level 1 (Swizzling)
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pAcquireSwizzlingRange))
        return STATUS_INVALID_PARAMETER;

    // TODO implement later.

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxReleaseSwizzlingRange(CONST HANDLE hAdapter,
                            CONST DXGKARG_RELEASESWIZZLINGRANGE *pReleaseSwizzlingRange)
{
    PAGED_CODE();
    // T & S Level 1 (Swizzling)
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pReleaseSwizzlingRange))
        return STATUS_INVALID_PARAMETER;

    // TODO implement later.

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxPatch(CONST HANDLE hAdapter,
            CONST DXGKARG_PATCH *pPatch)
{
    XENGFX_DMA_PRESENT *pDmaPresent;
    ULONG DmaUsedSize;

    // T & S Level 1 (GPU)
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pPatch))
        return STATUS_INVALID_PARAMETER;

    // No patching locations or allocation list for paging operations.
    if (pPatch->Flags.Paging == 1)
        return STATUS_SUCCESS;

    // Patching addresses for source and destination that were potentially mapped in in
    // a call to XenGfxBuildPagingBuffer() prior to this call being made.
    ASSERT(pPatch->AllocationListSize == 3);
    ASSERT(pPatch->pAllocationList[DXGK_PRESENT_SOURCE_INDEX].SegmentId == 1);
    ASSERT(pPatch->pAllocationList[DXGK_PRESENT_DESTINATION_INDEX].SegmentId == 1);

    DmaUsedSize = pPatch->DmaBufferSubmissionEndOffset - pPatch->DmaBufferSubmissionStartOffset;
    pDmaPresent = (XENGFX_DMA_PRESENT*)pPatch->pDmaBuffer;
    if (pDmaPresent->Size != DmaUsedSize) {
        TraceVerbose(("%s Invalid DMA buffer size: 0x%x expecting: 0x%x\n",
                      __FUNCTION__, DmaUsedSize, pDmaPresent->Size));
        return STATUS_UNSUCCESSFUL;
    }

    // N.B. store the physical address of the allocation. Not currently used.
    pDmaPresent->pSourceAllocation->AllocationBase = pPatch->pAllocationList[DXGK_PRESENT_SOURCE_INDEX].PhysicalAddress;
    pDmaPresent->pDestinationAllocation->AllocationBase = pPatch->pAllocationList[DXGK_PRESENT_DESTINATION_INDEX].PhysicalAddress;

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxSubmitCommand(CONST HANDLE hAdapter,
                    CONST DXGKARG_SUBMITCOMMAND *pSubmitCommand)
{
    XENGFX_DEVICE_EXTENSION *           pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    DXGKARGCB_NOTIFY_INTERRUPT_DATA     NotifyInt = {0};
    PHYSICAL_ADDRESS                    Addr;
    SIZE_T                              length;

    // T & S Level 1 (GPU)
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pSubmitCommand))
        return STATUS_INVALID_PARAMETER;
    
    //Get DMA Address and length
    Addr = pSubmitCommand->DmaBufferPhysicalAddress;
    Addr.QuadPart += pXenGfxExtension->GraphicsApertureDescriptor.u.Memory.Start.QuadPart;
    Addr.QuadPart += pSubmitCommand->DmaBufferSubmissionStartOffset;    
    length  = pSubmitCommand->DmaBufferSubmissionEndOffset -
              pSubmitCommand->DmaBufferSubmissionStartOffset;

    XenGfxDoCommand(pXenGfxExtension, Addr, length);

    pXenGfxExtension->CurrentFence = pSubmitCommand->SubmissionFenceId;
    NotifyInt.InterruptType = DXGK_INTERRUPT_DMA_COMPLETED;
    NotifyInt.DmaCompleted.SubmissionFenceId = pSubmitCommand->SubmissionFenceId;
    pXenGfxExtension->DxgkInterface.DxgkCbNotifyInterrupt(pXenGfxExtension->hDxgkHandle, &NotifyInt);
    pXenGfxExtension->DxgkInterface.DxgkCbQueueDpc(pXenGfxExtension->hDxgkHandle);

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxPreemptCommand(CONST HANDLE hAdapter,
                    CONST DXGKARG_PREEMPTCOMMAND *pPreemptCommand)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    DXGKARGCB_NOTIFY_INTERRUPT_DATA NotifyInt = {0};

    // T & S Level 1 (GPU)
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pPreemptCommand))
        return STATUS_INVALID_PARAMETER;

    NotifyInt.InterruptType = DXGK_INTERRUPT_DMA_PREEMPTED;
    NotifyInt.DmaPreempted.PreemptionFenceId = pPreemptCommand->PreemptionFenceId;
    NotifyInt.DmaPreempted.LastCompletedFenceId = pXenGfxExtension->CurrentFence;
    NotifyInt.DmaPreempted.NodeOrdinal = pPreemptCommand->NodeOrdinal;
    NotifyInt.DmaPreempted.EngineOrdinal = pPreemptCommand->EngineOrdinal;
    pXenGfxExtension->DxgkInterface.DxgkCbNotifyInterrupt(pXenGfxExtension->hDxgkHandle, &NotifyInt);
    pXenGfxExtension->DxgkInterface.DxgkCbQueueDpc(pXenGfxExtension->hDxgkHandle);

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxBuildPagingBuffer(CONST HANDLE hAdapter,
                        DXGKARG_BUILDPAGINGBUFFER *pBuildPagingBuffer)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    NTSTATUS Status = STATUS_SUCCESS;
    MDL *pMdlSrc = NULL, *pMdlDst = NULL;
    LARGE_INTEGER PhysSrc = {0}, PhysDst = {0};
    PAGED_CODE();

    // T & S Level 1 (GPU)
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pBuildPagingBuffer))
        return STATUS_INVALID_PARAMETER;

    switch (pBuildPagingBuffer->Operation) {
    case DXGK_OPERATION_TRANSFER:
        if (pBuildPagingBuffer->Transfer.TransferSize == 0)
            break; // nothing to do

        if ((pBuildPagingBuffer->Transfer.Source.SegmentId != 0)&&
            (pBuildPagingBuffer->Transfer.Source.SegmentId != 1)) {
            // This is bad, SNO
            ASSERT(((pBuildPagingBuffer->Transfer.Source.SegmentId == 0)||
                    (pBuildPagingBuffer->Transfer.Source.SegmentId == 1)));
            TraceError(("DXGK_OPERATION_TRANSFER invalid source segment %d specified.\n",
                        pBuildPagingBuffer->Transfer.Source.SegmentId));
            break;
        }

        if ((pBuildPagingBuffer->Transfer.Destination.SegmentId != 0)&&
            (pBuildPagingBuffer->Transfer.Destination.SegmentId != 1)) {
            // This is bad, SNO
            ASSERT(((pBuildPagingBuffer->Transfer.Destination.SegmentId == 0)||
                    (pBuildPagingBuffer->Transfer.Destination.SegmentId == 1)));
            TraceError(("DXGK_OPERATION_TRANSFER invalid destination segment %d specified.\n",
                        pBuildPagingBuffer->Transfer.Destination.SegmentId));
            break;
        }

        // Not expecting any swizzle flags set
        if ((pBuildPagingBuffer->Transfer.Flags.Swizzle == 1)||
            (pBuildPagingBuffer->Transfer.Flags.Unswizzle == 1)) {
            ASSERT(((pBuildPagingBuffer->Transfer.Flags.Swizzle == 0)&&
                    (pBuildPagingBuffer->Transfer.Flags.Unswizzle == 0)));
            TraceError(("DXGK_OPERATION_TRANSFER unexpected flags set: 0x%x.\n",
                        pBuildPagingBuffer->Transfer.Flags));
            break;
        }

        // Call routine to do the transfer
        if (pBuildPagingBuffer->Transfer.Source.SegmentId == 0)
            pMdlSrc = pBuildPagingBuffer->Transfer.Source.pMdl;
        else
            PhysSrc = pBuildPagingBuffer->Transfer.Source.SegmentAddress;

        if (pBuildPagingBuffer->Transfer.Destination.SegmentId == 0)
            pMdlDst = pBuildPagingBuffer->Transfer.Destination.pMdl;
        else
            PhysDst = pBuildPagingBuffer->Transfer.Destination.SegmentAddress;

        Status = XenGfxGartTransfer(pXenGfxExtension,
                                    pMdlSrc,
                                    PhysSrc,
                                    pMdlDst,
                                    PhysDst,
                                    pBuildPagingBuffer->Transfer.TransferOffset,
                                    pBuildPagingBuffer->Transfer.MdlOffset,
                                    pBuildPagingBuffer->Transfer.TransferSize);

        // This should not fail unless something is seriously wrong.
        ASSERT(NT_SUCCESS(Status));
        break;
    case DXGK_OPERATION_FILL:
        // This SNO since there is only an aperture segment for which this is never requested.
        ASSERT(pBuildPagingBuffer->Operation != DXGK_OPERATION_FILL);
        TraceError(("Illegal DXGK_OPERATION_FILL operation specified for aperture segment.\n"));
        break;
    case DXGK_OPERATION_DISCARD_CONTENT:
        // Not needed
        break;
    case DXGK_OPERATION_READ_PHYSICAL:
    case DXGK_OPERATION_WRITE_PHYSICAL:
        // The WDK documentation is vague on this but these are actually memory barrier
        // reads and writes for GPU access to the AGP aperture. We do not use AGP so...
        break;
    case DXGK_OPERATION_MAP_APERTURE_SEGMENT:
        // Map operation - should be for segment 1, cache-coherent not set.
        if (pBuildPagingBuffer->MapApertureSegment.SegmentId != 1) {
            // This is bad, SNO
            ASSERT(pBuildPagingBuffer->MapApertureSegment.SegmentId == 1);
            TraceError(("DXGK_OPERATION_MAP_APERTURE_SEGMENT invalid segment %d specified.\n",
                        pBuildPagingBuffer->MapApertureSegment.SegmentId));
            break;
        }
        if (pBuildPagingBuffer->MapApertureSegment.Flags.CacheCoherent == 1) {
            // This is bad, SNO
            ASSERT(pBuildPagingBuffer->MapApertureSegment.Flags.CacheCoherent != 1);
            TraceError(("Invalid CacheCoherent flag set for aperture segment 1.\n"));
            break;
        }

        // Map the requested segment into the GART.
        Status = XenGfxGartMapApertureSegment(pXenGfxExtension,
                                              pBuildPagingBuffer->MapApertureSegment.OffsetInPages,
                                              pBuildPagingBuffer->MapApertureSegment.NumberOfPages,
                                              pBuildPagingBuffer->MapApertureSegment.pMdl,
                                              pBuildPagingBuffer->MapApertureSegment.MdlOffset);
        // This should not fail unless something is seriously wrong.
        ASSERT(NT_SUCCESS(Status));
        break;
    case DXGK_OPERATION_UNMAP_APERTURE_SEGMENT:
        // Map operation - should be for segment 1
        if (pBuildPagingBuffer->UnmapApertureSegment.SegmentId != 1) {
            // This is bad, SNO
            ASSERT(pBuildPagingBuffer->UnmapApertureSegment.SegmentId == 1);
            TraceError(("DXGK_OPERATION_UNMAP_APERTURE_SEGMENT invalid segment %d specified.\n",
                        pBuildPagingBuffer->MapApertureSegment.SegmentId));
            break;
        }

        // Unmap the requested segment in the GART setting to the dummy page if present.
        Status = XenGfxGartUnmapApertureSegment(pXenGfxExtension,
                                                pBuildPagingBuffer->UnmapApertureSegment.OffsetInPages,
                                                pBuildPagingBuffer->UnmapApertureSegment.NumberOfPages,
                                                pBuildPagingBuffer->UnmapApertureSegment.DummyPage);
        // This should not fail unless something is seriously wrong.
        ASSERT(NT_SUCCESS(Status));
        break;
    case DXGK_OPERATION_SPECIAL_LOCK_TRANSFER:
        // Not using UseAlternateVA
        break;
    default:
        break;
    };

    XenGfxLeave(__FUNCTION__);

    // Always return success - any failures (which should not occur) will be traced.
    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxSetPalette(CONST HANDLE hAdapter,
                 CONST DXGKARG_SETPALETTE *pSetPalette)
{
    PAGED_CODE();
    // T & S Level 2
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pSetPalette))
        return STATUS_INVALID_PARAMETER;

    // TODO may not have to deal with this

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxSetPointerPosition(CONST HANDLE hAdapter,
                         CONST DXGKARG_SETPOINTERPOSITION *pSetPointerPosition)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    XENGFX_CURSOR_POS Pos;
    XENGFX_VCRTC *pVCrtc;
    ULONG ControlReg, i;
    PAGED_CODE();

    // T & S Level 1 (Pointer)
    XenGfxEnter(__FUNCTION__, 2);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pSetPointerPosition))
        return STATUS_INVALID_PARAMETER;

    if (!pXenGfxExtension->AdapterCursorSupported)
        return STATUS_NOT_SUPPORTED;

    for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) {
        pVCrtc = pXenGfxExtension->ppVCrtcBanks[i];

        // N.B. only non-cursor related bit of the vCRTC referenced
        if (pVCrtc->VidPnSourceId != pSetPointerPosition->VidPnSourceId)
            continue;

        ControlReg = READ_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_CURSOR_CONTROL));
        if (pSetPointerPosition->Flags.Visible == 1) {
            if ((ControlReg & XGFX_VCRTC_CURSOR_CONTROL_SHOW) == 0) {
                ControlReg |= XGFX_VCRTC_CURSOR_CONTROL_SHOW;
                WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_CURSOR_CONTROL), ControlReg);
            }
            Pos.YPos = (SHORT)pSetPointerPosition->Y;
            Pos.XPos = (SHORT)pSetPointerPosition->X;
            WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_CURSOR_POS), Pos.Pos);
        }
        else {
            if ((ControlReg & XGFX_VCRTC_CURSOR_CONTROL_SHOW) != 0) {
                ControlReg &= ~XGFX_VCRTC_CURSOR_CONTROL_SHOW;
                WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_CURSOR_CONTROL), ControlReg);
            }
        }
    }

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxSetPointerShape(CONST HANDLE hAdapter,
                      CONST DXGKARG_SETPOINTERSHAPE *pSetPointerShape)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    XENGFX_CURSOR_SIZE Size;
    XENGFX_VCRTC *pVCrtc;
    ULONG i;
    PAGED_CODE();

    // T & S Level 1 (Pointer)
    XenGfxEnter(__FUNCTION__, 2);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pSetPointerShape))
        return STATUS_INVALID_PARAMETER;

    if (!pXenGfxExtension->AdapterCursorSupported)
        return STATUS_NOT_SUPPORTED;

    ASSERT(pSetPointerShape->Flags.Monochrome == 0);

    for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) {
        pVCrtc = pXenGfxExtension->ppVCrtcBanks[i];

        // N.B. only non-cursor related bit of the vCRTC referenced
        if (pVCrtc->VidPnSourceId != pSetPointerShape->VidPnSourceId)
            continue;

        // Copy the cursor into the GART cursor buffer.
        RtlMoveMemory(pVCrtc->pCursorBase,
                      pSetPointerShape->pPixels,
                      pSetPointerShape->Height*pSetPointerShape->Pitch);

        Size.YSize = (USHORT)pSetPointerShape->Height;
        Size.XSize = (USHORT)pSetPointerShape->Width;
        WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_CURSOR_SIZE), Size.Size);
        WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_CURSOR_BASE), pVCrtc->CursorOffset);
    }

    XenGfxLeave(__FUNCTION__);

    // No cursor support
    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY CALLBACK
XenGfxResetFromTimeout(CONST HANDLE hAdapter)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    ULONG ControlReg;

    // T & S Level 3
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter))
        return STATUS_INVALID_PARAMETER;

    // TODO future additions like any vGPU DMAing support may need to be synced with
    // this reset.

    // For now just disable the interrupt so nothing is going on during the TDR reset.
    ControlReg = READ_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_CONTROL));
    WRITE_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_CONTROL), (ControlReg & ~(XGFX_CONTROL_INT_EN)));

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY CALLBACK
XenGfxRestartFromTimeout(CONST HANDLE hAdapter)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    ULONG ControlReg;

    // T & S Level 3
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter))
        return STATUS_INVALID_PARAMETER;

    // Between the reset and restart calls, the OS will will cleanup graphics resources
    // like allocations and aperture mappings. At this point, just re-enable the interrupt.
    ControlReg = READ_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_CONTROL));
    WRITE_REGISTER_ULONG((PULONG)(pXenGfxExtension->pGlobalRegs + XGFX_CONTROL), (ControlReg | XGFX_CONTROL_INT_EN));

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxEscape(CONST HANDLE hAdapter, CONST DXGKARG_ESCAPE *pEscape)
{
    PAGED_CODE();
    // T & S Level 2
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pEscape))
        return STATUS_INVALID_PARAMETER;

    // TODO this may be useful later to send stuffs between the mp and user land
    // display driver.

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxCollectDbgInfo(HANDLE hAdapter,
                     CONST DXGKARG_COLLECTDBGINFO *pCollectDbgInfo)
{
#define XENGFX_DBG_INFO_UNKNOWN_REASON "************: XenGfx - Unknown reason."
    ULONG *pBuf;

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pCollectDbgInfo))
        return STATUS_INVALID_PARAMETER;

    if (pCollectDbgInfo->BufferSize >= sizeof(XENGFX_DBG_INFO_UNKNOWN_REASON)) {
        RtlCopyMemory(pCollectDbgInfo->pBuffer,
                      XENGFX_DBG_INFO_UNKNOWN_REASON,
                      sizeof(XENGFX_DBG_INFO_UNKNOWN_REASON));

        pBuf = (ULONG*)pCollectDbgInfo->pBuffer;
        pBuf[0] = DXGK_SECONDARY_BUCKETING_TAG;
        pBuf[1] = 0xBADC0DE;
        pBuf[2] = pCollectDbgInfo->Reason;

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}

NTSTATUS APIENTRY
XenGfxQueryCurrentFence(CONST HANDLE hAdapter,
                        DXGKARG_QUERYCURRENTFENCE *pCurrentFence)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    PAGED_CODE();

    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pCurrentFence))
        return STATUS_INVALID_PARAMETER;

    pCurrentFence->CurrentFence = pXenGfxExtension->CurrentFence;

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxGetScanLine(CONST HANDLE hAdapter,
                  DXGKARG_GETSCANLINE *pGetScanLine)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    XENGFX_VCRTC *pVCrtc;
    PAGED_CODE();

    XenGfxEnter(__FUNCTION__, 2);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pGetScanLine))
        return STATUS_INVALID_PARAMETER;

    ASSERT(pGetScanLine->VidPnTargetId < pXenGfxExtension->VCrtcCount);
    pVCrtc = pXenGfxExtension->ppVCrtcBanks[pGetScanLine->VidPnTargetId];

    // Check the vertical retrace and scanline counter state for the current
    // this target/vCRTC. Don't bother with the lock - it is read-only and the
    // hot-plugged state should already be known.
    if ((READ_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_STATUS)) & XGFX_VCRTC_STATUS_RETRACE) == 0) {
        pGetScanLine->InVerticalBlank = FALSE;
        pGetScanLine->ScanLine = READ_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_SCANLINE));
    }
    else {
        pGetScanLine->InVerticalBlank = TRUE;
        pGetScanLine->ScanLine = XENGFX_UNDEFINED_SCANLINE;
    }
    // N.B. it seems reasonable that the scan line value will not matter while the retrace is in progress
    // so use the XENGFX_UNDEFINED_SCANLINE value. This is also the value returnded by a vCRTC when reporting
    // the scanline counter is unimplemented.

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxStopCapture(CONST HANDLE hAdapter,
                  CONST DXGKARG_STOPCAPTURE *pStopCapture)
{
    PAGED_CODE();
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter)||!ARGUMENT_PRESENT(pStopCapture))
        return STATUS_INVALID_PARAMETER;

    // Probably don't care about this one.

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxControlInterrupt(CONST HANDLE hAdapter,
                       CONST DXGK_INTERRUPT_TYPE InterruptType,
                       BOOLEAN Enable)
{
    XENGFX_DEVICE_EXTENSION *pXenGfxExtension = (XENGFX_DEVICE_EXTENSION*)hAdapter;
    XENGFX_VCRTC *pVCrtc;
    ULONG i, StatusInt;
    PAGED_CODE();

    // T & S Level 2
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hAdapter))
        return STATUS_INVALID_PARAMETER;

    // Only one supported right now - toggle retrace interrupt in virtual HW. Not
    // concerned with locking the vCRTCs since this is only making HW changes.
    if (InterruptType == DXGK_INTERRUPT_CRTC_VSYNC) {        
        for (i = 0; i < pXenGfxExtension->VCrtcCount; i++) {
            pVCrtc = pXenGfxExtension->ppVCrtcBanks[i];
            StatusInt = READ_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_STATUS_INT));
            if (Enable)
                StatusInt |= XGFX_VCRTC_STATUS_INT_RETRACE_EN;
            else
                StatusInt &= ~XGFX_VCRTC_STATUS_INT_RETRACE_EN;
            WRITE_REGISTER_ULONG((PULONG)(pVCrtc->pVCrtcRegs + XGFX_VCRTC_STATUS_INT), StatusInt);
        }
    }

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxDestroyDevice(CONST HANDLE hDevice)
{
    PAGED_CODE();
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hDevice))
        return STATUS_INVALID_PARAMETER;

    ExFreePoolWithTag(hDevice, XENGFX_TAG);

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxOpenAllocation(CONST HANDLE hDevice,
                     CONST DXGKARG_OPENALLOCATION *pOpenAllocation)
{
    XENGFX_D3D_DEVICE *pD3DDevice = (XENGFX_D3D_DEVICE*)hDevice;
    XENGFX_D3D_ALLOCATION *pD3dAllocation;
    XENGFX_DRIVER_ALLOCATION *pDriverAllocation;
    DXGK_OPENALLOCATIONINFO *pOpenAllocationInfo;
    DXGKARGCB_GETHANDLEDATA HandleData = {0, DXGK_HANDLE_ALLOCATION, 0};
    ULONG i;
    NTSTATUS Status = STATUS_SUCCESS;
    PAGED_CODE();

    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hDevice)||!ARGUMENT_PRESENT(pOpenAllocation))
        return STATUS_INVALID_PARAMETER;

    pOpenAllocationInfo = pOpenAllocation->pOpenAllocation;

    for (i = 0; i < pOpenAllocation->NumAllocations; i++, pOpenAllocationInfo++) {
        // Get the allocation private data passed in from UM or as a standard
        // allocation from the directx kernel and copy the bits the driver needs.
        // This is really just a sanity check at this point.
        pD3dAllocation = (XENGFX_D3D_ALLOCATION*)pOpenAllocationInfo->pPrivateDriverData;
        if ((pD3dAllocation == NULL)||
            (pOpenAllocationInfo->PrivateDriverDataSize < sizeof(XENGFX_D3D_ALLOCATION))) {
            Status = STATUS_INVALID_PARAMETER;
            break;
        }
        HandleData.hObject = pOpenAllocationInfo->hAllocation;
        pDriverAllocation = \
            (XENGFX_DRIVER_ALLOCATION*)pD3DDevice->pDeviceExtension->DxgkInterface.DxgkCbGetHandleData(&HandleData);
        pOpenAllocationInfo->hDeviceSpecificAllocation = (HANDLE)pDriverAllocation;
        pDriverAllocation->hAllocation = pOpenAllocationInfo->hAllocation;
    }

     if (!NT_SUCCESS(Status)) {
        pOpenAllocationInfo = pOpenAllocation->pOpenAllocation;
        for (i = 0; i < pOpenAllocation->NumAllocations; i++, pOpenAllocationInfo++) {
            // Undo it all if anything failed
            HandleData.hObject = pOpenAllocationInfo->hAllocation;
            pDriverAllocation = \
                (XENGFX_DRIVER_ALLOCATION*)pD3DDevice->pDeviceExtension->DxgkInterface.DxgkCbGetHandleData(&HandleData);
            pOpenAllocationInfo->hDeviceSpecificAllocation = NULL;
            pDriverAllocation->hAllocation = 0;
        }
    }

    XenGfxLeave(__FUNCTION__);

    return Status;
}

NTSTATUS APIENTRY
XenGfxCloseAllocation(CONST HANDLE hDevice,
                      CONST DXGKARG_CLOSEALLOCATION *pCloseAllocation)
{
    PAGED_CODE();
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hDevice)||!ARGUMENT_PRESENT(pCloseAllocation))
        return STATUS_INVALID_PARAMETER;

    // Nothing to do. The allocation is going to be destroyed so the open mapping
    // done above will just go away.

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxRender(CONST HANDLE hContext,
             DXGKARG_RENDER *pRender)
{
    PAGED_CODE();
    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hContext)||!ARGUMENT_PRESENT(pRender))
        return STATUS_INVALID_PARAMETER;

    // N.B. This routine can be skipped for now since this will never be called 
    // by GDI (only XenGfxPresent is used). For a full 3D implementation, this will
    // need to be implemented.

    XenGfxLeave(__FUNCTION__);

    return STATUS_NOT_IMPLEMENTED;
}

static void XenGfxPackDMASubRects(PXENGFX_DMA_SUBRECT pDMASubrects, DXGKARG_PRESENT * pPresent)
{
    ULONG i = 0;
    ULONG SourceWidth = pPresent->SrcRect.right - pPresent->SrcRect.left;
    ULONG SourceHeight = pPresent->SrcRect.bottom - pPresent->SrcRect.top;

    for (i = 0; i < pPresent->SubRectCnt; i++) {
        pDMASubrects[i].left    = min((ULONG) pPresent->pDstSubRects[i].left - pPresent->DstRect.left, SourceWidth);
        pDMASubrects[i].top     = min((ULONG) pPresent->pDstSubRects[i].top - pPresent->DstRect.top, SourceHeight);
        pDMASubrects[i].width   = min((ULONG) pPresent->pDstSubRects[i].right - pPresent->pDstSubRects[i].left, SourceWidth);
        pDMASubrects[i].height  = min((ULONG) pPresent->pDstSubRects[i].bottom - pPresent->pDstSubRects[i].top, SourceHeight);;
    }
}

NTSTATUS APIENTRY
XenGfxPresent(CONST HANDLE hContext,
              DXGKARG_PRESENT *pPresent)
{
    XENGFX_D3D_CONTEXT          *pD3DContext = (XENGFX_D3D_CONTEXT*)hContext;
    XENGFX_DMA_PRESENT          *pDmaPresent;
    UINT                        Size, SubRectsSize;
    PXENGFX_DEVICE_EXTENSION    pXenGfxExtension = pD3DContext->pD3DDevice->pDeviceExtension;
    PXENGFX_VCRTC               pVcrtc = NULL;
    RECT *                      pSubRects;
    PAGED_CODE();

    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hContext)||!ARGUMENT_PRESENT(pPresent))
        return STATUS_INVALID_PARAMETER;

    // TODO support these later?
    if (pPresent->pAllocationList[DXGK_PRESENT_SOURCE_INDEX].hDeviceSpecificAllocation == NULL) {
        TraceVerbose(("%s ColorFill operation not supported, Flags=0x%x\n", __FUNCTION__, pPresent->Flags));
        return STATUS_ILLEGAL_INSTRUCTION;
    }
    else if (pPresent->pAllocationList[DXGK_PRESENT_DESTINATION_INDEX].hDeviceSpecificAllocation == NULL) {
        TraceVerbose(("%s Flip operation not supported, Flags=0x%x\n", __FUNCTION__, pPresent->Flags));
        return STATUS_ILLEGAL_INSTRUCTION;
    }

    if (pPresent->pDmaBuffer == NULL) {
        // This SNO since FLIPCAPS specify no HW flip support right now.
        TraceWarning(("%s HW MMIO Flip operation not supported, Flags=0x%x\n", __FUNCTION__, pPresent->Flags));
        return STATUS_ILLEGAL_INSTRUCTION;
    }

    // TODO check allocation types (shared primary only)?

    // Allocate a DMA buffer to hold all the values for this present operation.
    SubRectsSize = pPresent->SubRectCnt * sizeof(XENGFX_DMA_SUBRECT);
    Size = sizeof(XENGFX_DMA_PRESENT) + SubRectsSize;
    if (pPresent->DmaSize <= Size) { 
        TraceVerbose(("%s pDmaBuffer too small, size=0x%x\n", __FUNCTION__, pPresent->DmaSize));
        return STATUS_GRAPHICS_INSUFFICIENT_DMA_BUFFER;
    }

    // Allocate DMA chunk and advance the buffer
    pDmaPresent = (XENGFX_DMA_PRESENT*)pPresent->pDmaBuffer;
    pPresent->pDmaBuffer = (UCHAR*)pPresent->pDmaBuffer + Size;

    // Copy the present values into the DMA buffer
    pDmaPresent->Size = Size;
    pDmaPresent->pSourceAllocation = pPresent->pAllocationList[DXGK_PRESENT_SOURCE_INDEX].hDeviceSpecificAllocation;
    pDmaPresent->pDestinationAllocation = pPresent->pAllocationList[DXGK_PRESENT_DESTINATION_INDEX].hDeviceSpecificAllocation;
    pDmaPresent->SourceRect = pPresent->SrcRect;
    pDmaPresent->DestinationRect = pPresent->DstRect;
    pDmaPresent->SubRectsCount = pPresent->SubRectCnt;
    pDmaPresent->Flags = pPresent->Flags;
    pSubRects = (RECT*)((UCHAR*)pDmaPresent + sizeof(XENGFX_DMA_PRESENT));

    XenGfxPackDMASubRects((PXENGFX_DMA_SUBRECT)((PCHAR)pDmaPresent + sizeof(XENGFX_DMA_PRESENT)),  pPresent);

    // Set the patch locations and advance the location counter
    RtlZeroMemory(pPresent->pPatchLocationListOut, 2*sizeof (D3DDDI_PATCHLOCATIONLIST));
    pPresent->pPatchLocationListOut[0].AllocationIndex = DXGK_PRESENT_SOURCE_INDEX;
    pPresent->pPatchLocationListOut[1].AllocationIndex = DXGK_PRESENT_DESTINATION_INDEX;
    pPresent->pPatchLocationListOut += 2;
    
    
    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxCreateContext(CONST HANDLE hDevice,
                    DXGKARG_CREATECONTEXT *pCreateContext)
{
    XENGFX_D3D_DEVICE  *pD3DDevice = (XENGFX_D3D_DEVICE*)hDevice;
    XENGFX_D3D_CONTEXT *pD3DContext;
    PAGED_CODE();

    XenGfxEnter(__FUNCTION__, 1);

    if (!ARGUMENT_PRESENT(hDevice)||!ARGUMENT_PRESENT(pCreateContext))
        return STATUS_INVALID_PARAMETER;

    pD3DContext = ExAllocatePoolWithTag(NonPagedPool,
                                        sizeof(XENGFX_D3D_CONTEXT),
                                        XENGFX_TAG);
    if (pD3DContext == NULL)
        return STATUS_NO_MEMORY;

    RtlZeroMemory(pD3DContext, sizeof(XENGFX_D3D_CONTEXT));

    pD3DContext->pD3DDevice = pD3DDevice;
    if (pCreateContext->Flags.SystemContext != 0)
        pD3DContext->Type = XENGFX_CONTEXT_TYPE_SYSTEM;
    else
        pD3DContext->Type = XENGFX_CONTEXT_TYPE_NONE;
    pD3DContext->NodeOrdinal = pCreateContext->NodeOrdinal;
    pD3DContext->EngineAffinity = pCreateContext->EngineAffinity;

    // Return context and DMA allocation values.
    pCreateContext->hContext = pD3DContext;
    pCreateContext->ContextInfo.DmaBufferSize = XENGFX_DMA_BUFFER_SIZE;
    
    //Allocates the DMA buffer in the gart.
    pCreateContext->ContextInfo.DmaBufferSegmentSet = 1;
    pCreateContext->ContextInfo.AllocationListSize = XENGFX_ALLOCATION_LIST_SIZE;
    pCreateContext->ContextInfo.PatchLocationListSize = XENGFX_PATCH_LOCATION_LIST_SIZE;
    pCreateContext->ContextInfo.DmaBufferPrivateDataSize = 128;

    // TODO Revisit these values. The XENGFX_DMA_BUFFER_SIZE was taken from ICA 
    // driver - seems a bit big. The private data size seems wrong too. The VBox
    // driver uses a struct for this.

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}

NTSTATUS APIENTRY
XenGfxDestroyContext(CONST HANDLE hContext)
{
    XenGfxEnter(__FUNCTION__, 1);
    PAGED_CODE();

    if (!ARGUMENT_PRESENT(hContext))
        return STATUS_INVALID_PARAMETER;

    ExFreePoolWithTag(hContext, XENGFX_TAG);

    XenGfxLeave(__FUNCTION__);

    return STATUS_SUCCESS;
}
