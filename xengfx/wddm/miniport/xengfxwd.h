//
// xengfxwd.h - Xen Windows WDDM Miniport Driver
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


#ifndef XENGFXWD_H
#define XENGFXWD_H

#include <ntddk.h>
#include <ntstrsafe.h>
#include <dispmprt.h>
#include <dderror.h>
#include <devioctl.h>
#include "xengfx_shared.h"
#include "xengfx_regs.h"
#include "d3d.h"

#define XENGFX_DEFAULT_VCRTC_COUNT   4
#define XENGFX_DEFAULT_VSYNC         60
#define XENGFX_MAX_GART_PFNS         0x40000 // PFNs for 4K pages maps 1G
#define XENGFX_MAX_STRIDE_ALIGNMENT  (0x400000 - 1) // 4M
#define XENGFX_MAX_CURSOR_DIMENSION  1024
#define XENGFX_LOGNAME_LENGTH        256

// Registry values
#define XENGFX_REG_CHILDDEVICECOUNT  L"ChildDeviceCount" // DWORD child device count override
#define XENGFX_REG_VIDPNTRACING      L"VidPnTracing"     // DWORD enable/disable VidPn debug tracing
#define XENGFX_REG_DEBUGLOGNAME      L"DebugLogName"     // SZ debug tracing log file name

typedef struct _XENGFX_FORMAT_ENTRY {
    D3DDDIFORMAT DdiFormat;
    ULONG XgfxFormat;
    ULONG BitsPerPixel;
} XENGFX_FORMAT_ENTRY, *PXENGFX_FORMAT_ENTRY;

// Supported formats in preferential order. Note the order of this list is very
// important. RGBX should be found first for XGFX formats and then alpha formats
// should be preferred for reporting to Windows. In particular when the XENGFX D3D 
// DLL is not reporting format capabilities, Windows and GDI will default to
// D3DDDIFMT_A8R8G8B8.
//
// A bit more on formats and notation. Though the Windows names for 32b formats
// deviate from those seen elsewhere, a format like D3DDDIFMT_X8R8G8B8 is the same
// is XGFX_VCRTC_VALID_FORMAT_RGBX8888. The X (or A) reserved byte is still in the
// 24th bit position with R/G/B in 0/8/16 positions. See the FourCC site for 
// more info: http://www.fourcc.org/fourcc.php
static const XENGFX_FORMAT_ENTRY g_XenGfxFormatMap[XENGFX_D3D_FORMAT_COUNT] = {
    {D3DDDIFMT_A8R8G8B8, XGFX_VCRTC_VALID_FORMAT_BGRX8888, 32},
    {D3DDDIFMT_X8R8G8B8, XGFX_VCRTC_VALID_FORMAT_BGRX8888, 32},
    {D3DDDIFMT_A8R8G8B8, XGFX_VCRTC_VALID_FORMAT_BGRX8888, 32},
    {D3DDDIFMT_X8R8G8B8, XGFX_VCRTC_VALID_FORMAT_BGRX8888, 32},
    {D3DDDIFMT_R8G8B8,   XGFX_VCRTC_VALID_FORMAT_RGB888,   24},
    {D3DDDIFMT_R5G6B5,   XGFX_VCRTC_VALID_FORMAT_RGB565,   16},
    {D3DDDIFMT_X1R5G5B5, XGFX_VCRTC_VALID_FORMAT_RGB555,   16}
};

typedef struct _XENGFX_DRIVER_ALLOCATION {
    XENGFX_STANDARDALLOCATION_TYPE Type;
    ULONG State;
    D3DDDI_VIDEO_PRESENT_SOURCE_ID VidPnSourceId;
    XENGFX_SURFACE_DESC SurfaceDesc;
    ULONG ByteAlignment; // StrideAlignment + 1 for alignment bytes
    D3DKMT_HANDLE hAllocation; // current allocation binding from open allocation
    PHYSICAL_ADDRESS AllocationBase;
} XENGFX_DRIVER_ALLOCATION, *PXENGFX_DRIVER_ALLOCATION;

typedef struct _XENGFX_SOURCE
{
    BOOLEAN InUse;
    XENGFX_DRIVER_ALLOCATION *pPrimaryAllocation;
} XENGFX_SOURCE, *PXENGFX_SOURCE;

typedef struct _XENGFX_MODE_SET
{
    ULONG ChildUid;
    ULONG RefCount;
    ULONG ModeCount;
    XENGFX_MODE *pModes;    
} XENGFX_MODE_SET, *PXENGFX_MODE_SET;

#define XENV4V_CONNECTED         1
#define XENV4V_DISCONNECTED      0

#define XENGFX_STAGED_FLAG_UNSET 0x00000000
#define XENGFX_STAGED_FLAG_CLEAR 0x00000001
#define XENGFX_STAGED_FLAG_SKIP  0x00000002

typedef struct _XENGFX_VCRTC
{
    PUCHAR pVCrtcRegs;
    ULONG ChildUid;
    volatile LONG Connected;

    ULONG MaxHorizontal;
    ULONG MaxVertical;
    ULONG StrideAlignment;
    ULONG PreferredPixelFormat;

    // Ref counted set of modes and EDID information. Note this data
    // is transient and changes during hotplug events.
    XENGFX_MODE_SET *pModeSet;    
    XENGFX_EDID *pEdid;
    PHYSICAL_ADDRESS EdidPageBase;
    ULONG EdidSize;
    
    XENGFX_MODE CurrentMode;
    ULONG CurrentModeIndex;

    BOOLEAN CursorSupported;
    ULONG MaxCursorHeight;
    ULONG MaxCursorWidth;
    // Aperture space for this VCRTC's cursor.
    PVOID pCursorBase;
    ULONG CursorSize;
    ULONG CursorOffset;

    // The same as the ChildUid 0 - (N - 1)
    D3DDDI_VIDEO_PRESENT_TARGET_ID VidPnTargetId;

    // Unset or the current associated source 0 - (N - 1)
    D3DDDI_VIDEO_PRESENT_SOURCE_ID VidPnSourceId;

    PHYSICAL_ADDRESS PrimaryAddress;

    // Staging values for new modes/sources
    ULONG StagedModeIndex;
    D3DDDI_VIDEO_PRESENT_SOURCE_ID StagedVidPnSourceId;
    ULONG StagedPixelFormat;
    BOOLEAN StagedFlags;

    //QAD scan back buffer
    BOOLEAN primary;

} XENGFX_VCRTC, *PXENGFX_VCRTC;

typedef struct _XENGFX_DEVICE_EXTENSION
{
    volatile LONG Initialized;
    BOOLEAN XgfxMode;

    // WDDM
    HANDLE hDxgkHandle;
    DXGK_START_INFO DxgkStartInfo;
    DXGKRNL_INTERFACE DxgkInterface;
    UINT CurrentFence;

    // XGFX
    PDEVICE_OBJECT pPhysicalDeviceObject;
    XENGFX_UMDRIVERPRIVATE PrivateData;

    CM_PARTIAL_RESOURCE_DESCRIPTOR XgfxRegistersDescriptor;
    PUCHAR pXgfxRegs;
    PUCHAR pGlobalRegs;
    PUCHAR pVCrtcsRegs;
    PUCHAR pGartRegs;

    CM_PARTIAL_RESOURCE_DESCRIPTOR GraphicsApertureDescriptor;    

    ULONG VCrtcRegistryCount;
    ULONG VCrtcMaxCount;
    ULONG VCrtcCount;
    KSPIN_LOCK VCrtcLock;
    XENGFX_VCRTC **ppVCrtcBanks;
    ULONG MaxStrideAlignment;
    KDPC ChildStatusDpc;
    KSPIN_LOCK SourcesLock;
    XENGFX_SOURCE *pSources;
    BOOLEAN AdapterCursorSupported;
    ULONG AdapterMaxCursorHeight;
    ULONG AdapterMaxCursorWidth;
    
    PULONG32 pGartBaseReg;
    KSPIN_LOCK GartLock;
    ULONG GartPfns;
    ULONG VideoSegmentOffset;
    ULONG VideoPfns;
    ULONG CursorSegmentOffset;
    ULONG CursonPfns;
    ULONG StolenBase;
    ULONG StolenPfns;

    PUCHAR pCursorsBuffer;
    PVOID pCursorsBufferContext;
    ULONG CursorsBufferSize;

    // Debug
    BOOLEAN VidPnTracing;
    WCHAR DebugLogName[XENGFX_LOGNAME_LENGTH];
    HANDLE hDebugLog;

} XENGFX_DEVICE_EXTENSION, *PXENGFX_DEVICE_EXTENSION;

#define XENGFX_DMA_BUFFER_SIZE          (64 * 1024) 
#define XENGFX_ALLOCATION_LIST_SIZE     (3 * 1024)
#define XENGFX_PATCH_LOCATION_LIST_SIZE (3 * 1024)

typedef enum _XENGFX_CONTEXT_TYPE {
    XENGFX_CONTEXT_TYPE_NONE    = 0,
    XENGFX_CONTEXT_TYPE_SYSTEM  = 1,
    XENGFX_CONTEXT_TYPE_GDI     = 2
} XENGFX_CONTEXT_TYPE;

typedef struct _XENGFX_D3D_DEVICE {
    HANDLE hDevice;
    XENGFX_DEVICE_EXTENSION *pDeviceExtension;
} XENGFX_D3D_DEVICE, *PXENGFX_D3D_DEVICE;

typedef struct _XENGFX_D3D_CONTEXT {
    XENGFX_D3D_DEVICE *pD3DDevice;
    XENGFX_CONTEXT_TYPE Type;
    UINT NodeOrdinal;
    UINT EngineAffinity;
} XENGFX_D3D_CONTEXT, *PXENGFX_D3D_CONTEXT;

typedef struct _XENGFX_DMA_PRESENT {
    UINT Size;
    XENGFX_DRIVER_ALLOCATION *pSourceAllocation;
    XENGFX_DRIVER_ALLOCATION *pDestinationAllocation;
    RECT SourceRect;
    RECT DestinationRect;
    UINT SubRectsCount;
    DXGK_PRESENTFLAGS Flags;
} XENGFX_DMA_PRESENT, *PXENGFX_DMA_PRESENT;

typedef struct _XENGFX_MAPPED_MEMORY {
    PUCHAR pAddr;
    SIZE_T mapSize;
}XENGFX_MAPPED_MEMORY, *PXENGFX_MAPPED_MEMORY;

typedef struct _XENGFX_DMA_SUBRECT {
    ULONG left;
    ULONG top;
    ULONG width;
    ULONG height;
} XENGFX_DMA_SUBRECT, *PXENGFX_DMA_SUBRECT;

// Macros
#define XenGfxChildMaxUid(x) (x->VCrtcCount - 1)
#define XenGfxMonitorConnected(v) ((InterlockedExchangeAdd(&v->Connected, 0) == XENV4V_CONNECTED) ? TRUE : FALSE)
#define XenGfxCompare2DRegion(r1, r2) (((r1.cx == r2.cx)&&(r1.cy == r2.cy)) ? TRUE : FALSE)

#if defined(DBG)
#define XenGfxEnter(s, n) _XenGfxEnter(s, n)
#define XenGfxLeave(s)    _XenGfxLeave(s)
#else
#define XenGfxEnter(s, n)
#define XenGfxLeave(s)
#endif

// MISC routines
NTSTATUS
XenGfxReadConfigSpace(PDEVICE_OBJECT pDeviceObject,
                      PVOID pBuffer,
                      ULONG Offset,
                      ULONG Length);

VOID
XenGfxReadRegistryValues(XENGFX_DEVICE_EXTENSION *pXenGfxExtension,
                         PUNICODE_STRING pDeviceRegistryPath);

VOID
XenGfxGetPrivateData(XENGFX_DEVICE_EXTENSION *pXenGfxExtension);

VOID
XenGfxFreeResources(XENGFX_DEVICE_EXTENSION *pXenGfxExtension);

VOID
XenGfxChangeXgfxMode(XENGFX_DEVICE_EXTENSION *pXenGfxExtension, BOOLEAN Enable);

ULONG
XenGfxBppFromDdiFormat(D3DDDIFORMAT DdiFormat);

ULONG
XenGfxXgfxFormatFromDdiFormat(D3DDDIFORMAT DdiFormat);

D3DDDIFORMAT
XenGfxDdiFormatFromXgfxFormat(ULONG XgfxFormat);

VOID
_XenGfxEnter(const char *pFunction, ULONG Level);

VOID
_XenGfxLeave(const char *pFunction);

// VCRTC routines
BOOLEAN
XenGfxSupportedVCrtcFormat(XENGFX_VCRTC *pVCrtc, D3DDDIFORMAT DdiFormat);

BOOLEAN
XenGfxAllocateVCrtcBanks(XENGFX_DEVICE_EXTENSION *pXenGfxExtension);

VOID
XenGfxFreeVCrtcBanks(XENGFX_DEVICE_EXTENSION *pXenGfxExtension);

BOOLEAN
XenGfxEnableVCrtcs(XENGFX_DEVICE_EXTENSION *pXenGfxExtension);

VOID
XenGfxDisableVCrtcs(XENGFX_DEVICE_EXTENSION *pXenGfxExtension);

VOID
XenGfxDetectChildStatusChanges(XENGFX_DEVICE_EXTENSION *pXenGfxExtension);

VOID
XenGfxSetPrimaryForVCrtc(XENGFX_DEVICE_EXTENSION *pXenGfxExtension, XENGFX_VCRTC *pVCrtc);

VOID
XenGfxClearPrimaryForVCrtc(XENGFX_DEVICE_EXTENSION *pXenGfxExtension, XENGFX_VCRTC *pVCrtc);

XENGFX_MODE_SET*
XenGfxGetModeSet(XENGFX_DEVICE_EXTENSION *pXenGfxExtension, ULONG ChildUid);

VOID
XenGfxPutModeSet(XENGFX_DEVICE_EXTENSION *pXenGfxExtension, XENGFX_MODE_SET *pModeSet);


VOID
XenGfxChildStatusChangeDpc(KDPC *pDpc,
                           VOID *pDeferredContext,
                           VOID *pSystemArgument1,
                           VOID *pSystemArgument2);

// GART routines
BOOLEAN
XenGfxGartInitialize(XENGFX_DEVICE_EXTENSION *pXenGfxExtension);

VOID
XenGfxGartInitializeCursorSegment(XENGFX_DEVICE_EXTENSION *pXenGfxExtension);

VOID
XenGfxGartReset(XENGFX_DEVICE_EXTENSION *pXenGfxExtension);

NTSTATUS
XenGfxGartMapApertureSegment(XENGFX_DEVICE_EXTENSION *pXenGfxExtension,
                             SIZE_T OffsetInPages,
                             SIZE_T NumberOfPages,
                             PMDL pMdl,
                             UINT MdlOffset);

NTSTATUS
XenGfxGartUnmapApertureSegment(XENGFX_DEVICE_EXTENSION *pXenGfxExtension,
                               SIZE_T OffsetInPages,
                               SIZE_T NumberOfPages,
                               PHYSICAL_ADDRESS DummyPage);

NTSTATUS
XenGfxGartTransfer(XENGFX_DEVICE_EXTENSION *pXenGfxExtension,
                   MDL *pMdlSrc,
                   LARGE_INTEGER PhysSrc,
                   MDL *pMdlDst,
                   LARGE_INTEGER PhysDst,
                   UINT TransferOffset,
                   UINT MdlOffset,
                   SIZE_T TransferSize);

// Miniport routines
NTSTATUS APIENTRY
XenGfxAddDevice(CONST PDEVICE_OBJECT pPhysicalDeviceObject,
                PVOID *ppMiniportDeviceContext);

NTSTATUS APIENTRY
XenGfxStartDevice(CONST PVOID pMiniportDeviceContext,
                  PDXGK_START_INFO pDxgkStartInfo,
                  PDXGKRNL_INTERFACE pDxgkInterface,
                  PULONG pNumberOfViews,
                  PULONG pNumberOfChildren);

NTSTATUS APIENTRY
XenGfxStopDevice(CONST PVOID pMiniportDeviceContext);

NTSTATUS APIENTRY
XenGfxRemoveDevice(CONST PVOID pMiniportDeviceContext);

NTSTATUS APIENTRY
XenGfxDispatchIoRequest(CONST PVOID pMiniportDeviceContext,
                        ULONG ViewIndex,
                        PVIDEO_REQUEST_PACKET pVideoRequestPacket);

BOOLEAN APIENTRY
XenGfxInterruptRoutine(CONST PVOID pMiniportDeviceContext, ULONG MessageNumber);

VOID APIENTRY
XenGfxDpcRoutine(CONST PVOID pMiniportDeviceContext);

NTSTATUS APIENTRY
XenGfxQueryChildRelations(CONST PVOID pMiniportDeviceContext,
                          PDXGK_CHILD_DESCRIPTOR pChildRelations,
                          ULONG ChildRelationsSize);

NTSTATUS APIENTRY
XenGfxQueryChildStatus(CONST PVOID pMiniportDeviceContext,
                       PDXGK_CHILD_STATUS pChildStatus,
                       BOOLEAN NonDestructiveOnly);

NTSTATUS APIENTRY
XenGfxQueryDeviceDescriptor(CONST PVOID pMiniportDeviceContext,
                            ULONG ChildUid,
                            PDXGK_DEVICE_DESCRIPTOR pDeviceDescriptor);

NTSTATUS APIENTRY
XenGfxSetPowerState(CONST PVOID pMiniportDeviceContext,
                    ULONG HardwareUid,
                    DEVICE_POWER_STATE DevicePowerState,
                    POWER_ACTION ActionType);

VOID APIENTRY
XenGfxResetDevice(CONST PVOID pMiniportDeviceContext);

VOID APIENTRY
XenGfxUnload(VOID);

NTSTATUS APIENTRY
XenGfxQueryInterface(CONST PVOID pMiniportDeviceContext,
                     PQUERY_INTERFACE pQueryInterface);

NTSTATUS
DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);

// DDI routines
VOID
XenGfxControlEtwLogging(BOOLEAN Enable, ULONG Flags, UCHAR Level);

NTSTATUS APIENTRY
XenGfxQueryAdapterInfo(CONST HANDLE hAdapter,
                       CONST DXGKARG_QUERYADAPTERINFO *pQueryAdapterInfo);

NTSTATUS APIENTRY
XenGfxCreateDevice(CONST HANDLE hAdapter,
                   DXGKARG_CREATEDEVICE *pCreateDevice);

NTSTATUS APIENTRY
XenGfxCreateAllocation(CONST HANDLE hAdapter,
                       DXGKARG_CREATEALLOCATION *pCreateAllocation);

NTSTATUS APIENTRY
XenGfxDestroyAllocation(CONST HANDLE hAdapter,
                        CONST DXGKARG_DESTROYALLOCATION *pDestroyAllocation);

NTSTATUS APIENTRY
XenGfxDescribeAllocation(CONST HANDLE hAdapter,
                         DXGKARG_DESCRIBEALLOCATION *pDescribeAlloc);

NTSTATUS APIENTRY
XenGfxGetStandardAllocationDriverData(CONST HANDLE hAdapter,
                                      DXGKARG_GETSTANDARDALLOCATIONDRIVERDATA *pStandardAllocationDriverData);

NTSTATUS APIENTRY
XenGfxAcquireSwizzlingRange(CONST HANDLE hAdapter,
                            DXGKARG_ACQUIRESWIZZLINGRANGE *pAcquireSwizzlingRange);

NTSTATUS APIENTRY
XenGfxReleaseSwizzlingRange(CONST HANDLE hAdapter,
                            CONST DXGKARG_RELEASESWIZZLINGRANGE *pReleaseSwizzlingRange);

NTSTATUS APIENTRY
XenGfxPatch(CONST HANDLE hAdapter,
            CONST DXGKARG_PATCH *pPatch);

NTSTATUS APIENTRY
XenGfxSubmitCommand(CONST HANDLE hAdapter,
                    CONST DXGKARG_SUBMITCOMMAND *pSubmitCommand);

NTSTATUS APIENTRY
XenGfxPreemptCommand(CONST HANDLE hAdapter,
                    CONST DXGKARG_PREEMPTCOMMAND *pPreemptCommand);

NTSTATUS APIENTRY
XenGfxBuildPagingBuffer(CONST HANDLE hAdapter,
                        DXGKARG_BUILDPAGINGBUFFER *pBuildPagingBuffer);

NTSTATUS APIENTRY
XenGfxSetPalette(CONST HANDLE hAdapter,
                 CONST DXGKARG_SETPALETTE *pSetPalette);

NTSTATUS APIENTRY
XenGfxSetPointerPosition(CONST HANDLE hAdapter,
                         CONST DXGKARG_SETPOINTERPOSITION *pSetPointerPosition);

NTSTATUS APIENTRY
XenGfxSetPointerShape(CONST HANDLE hAdapter,
                      CONST DXGKARG_SETPOINTERSHAPE *pSetPointerShape);

NTSTATUS APIENTRY CALLBACK
XenGfxResetFromTimeout(CONST HANDLE hAdapter);

NTSTATUS APIENTRY CALLBACK
XenGfxRestartFromTimeout(CONST HANDLE hAdapter);

NTSTATUS APIENTRY
XenGfxEscape(CONST HANDLE hAdapter, CONST DXGKARG_ESCAPE *pEscape);

NTSTATUS APIENTRY
XenGfxCollectDbgInfo(HANDLE hAdapter,
                     CONST DXGKARG_COLLECTDBGINFO *pCollectDbgInfo);

NTSTATUS APIENTRY
XenGfxQueryCurrentFence(CONST HANDLE hAdapter,
                        DXGKARG_QUERYCURRENTFENCE *pCurrentFence);

NTSTATUS APIENTRY
XenGfxGetScanLine(CONST HANDLE hAdapter,
                  DXGKARG_GETSCANLINE *pGetScanLine);

NTSTATUS APIENTRY
XenGfxStopCapture(CONST HANDLE hAdapter,
                  CONST DXGKARG_STOPCAPTURE *pStopCapture);

NTSTATUS APIENTRY
XenGfxControlInterrupt(CONST HANDLE hAdapter,
                       CONST DXGK_INTERRUPT_TYPE InterruptType,
                       BOOLEAN Enable);

NTSTATUS APIENTRY
XenGfxDestroyDevice(CONST HANDLE hDevice);

NTSTATUS APIENTRY
XenGfxOpenAllocation(CONST HANDLE hDevice,
                     CONST DXGKARG_OPENALLOCATION *pOpenAllocation);

NTSTATUS APIENTRY
XenGfxCloseAllocation(CONST HANDLE hDevice,
                      CONST DXGKARG_CLOSEALLOCATION *pCloseAllocation);

NTSTATUS APIENTRY
XenGfxRender(CONST HANDLE hContext,
             DXGKARG_RENDER *pRender);

NTSTATUS APIENTRY
XenGfxPresent(CONST HANDLE hContext,
              DXGKARG_PRESENT *pPresent);

NTSTATUS APIENTRY
XenGfxCreateContext(CONST HANDLE hDevice,
                    DXGKARG_CREATECONTEXT *pCreateContext);

NTSTATUS APIENTRY
XenGfxDestroyContext(CONST HANDLE hContext);

// VidPN routines
NTSTATUS APIENTRY
XenGfxIsSupportedVidPn(CONST HANDLE  hAdapter,
                       DXGKARG_ISSUPPORTEDVIDPN *pIsSupportedVidPn);

NTSTATUS APIENTRY
XenGfxRecommendFunctionalVidPn(CONST HANDLE hAdapter,
                               CONST DXGKARG_RECOMMENDFUNCTIONALVIDPN *CONST pRecommendFunctionalVidPn);

NTSTATUS APIENTRY
XenGfxEnumVidPnCofuncModality(CONST HANDLE hAdapter,
                              CONST DXGKARG_ENUMVIDPNCOFUNCMODALITY *CONST pEnumCofuncModality);

NTSTATUS APIENTRY
XenGfxSetVidPnSourceAddress(CONST HANDLE hAdapter,
                            CONST DXGKARG_SETVIDPNSOURCEADDRESS *pSetVidPnSourceAddress);

NTSTATUS APIENTRY
XenGfxSetVidPnSourceVisibility(CONST HANDLE hAdapter,
                               CONST DXGKARG_SETVIDPNSOURCEVISIBILITY *pSetVidPnSourceVisibility);

NTSTATUS APIENTRY
XenGfxCommitVidPn(CONST HANDLE hAdapter,
                  CONST DXGKARG_COMMITVIDPN *CONST pCommitVidPn);

NTSTATUS APIENTRY
XenGfxUpdateActiveVidPnPresentPath(CONST HANDLE hAdapter,
                                   CONST DXGKARG_UPDATEACTIVEVIDPNPRESENTPATH *CONST pUpdateActiveVidPnPresentPath);

NTSTATUS APIENTRY
XenGfxRecommendMonitorModes(CONST HANDLE hAdapter,
                            CONST DXGKARG_RECOMMENDMONITORMODES *CONST pRecommendMonitorModes);

NTSTATUS APIENTRY
XenGfxRecommendVidPnTopology(CONST HANDLE hAdapter,
                             CONST DXGKARG_RECOMMENDVIDPNTOPOLOGY *CONST pRecommendVidPnTopology);

// Debug routines

VOID
XenGfxOpenDebugLog(XENGFX_DEVICE_EXTENSION *pXenGfxExtension);

VOID
XenGfxCloseDebugLog(XENGFX_DEVICE_EXTENSION *pXenGfxExtension);

#endif //XENGFXWD_H
