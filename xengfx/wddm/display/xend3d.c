//
// xengfxd3d.c - Xen Windows PV WDDM D3D Display Driver
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


#include <windows.h>
#include <d3d9types.h>
#include <d3dumddi.h>
#include <d3dhal.h>
#include <assert.h>
#include "xend3d.h"

static BOOL g_XenGfx2D = TRUE;

// TODO need to revisit and posible change FORMAT OPS for each.

// GetCaps D3DDDICAPS_GETFORMATDATA will report all possible formats and each
// VidPN will indicate what source modes can be set.
static FORMATOP g_XenGfxD3dFormats[XENGFX_D3D_FORMAT_COUNT] = {
    {D3DDDIFMT_X1R5G5B5, // XGFX_FORMAT_RGB555 16 BPP
     (FORMATOP_TEXTURE|FORMATOP_VOLUMETEXTURE|FORMATOP_CUBETEXTURE|
      FORMATOP_OFFSCREEN_RENDERTARGET|FORMATOP_SAME_FORMAT_RENDERTARGET|
      FORMATOP_CONVERT_TO_ARGB|FORMATOP_OFFSCREENPLAIN|
      FORMATOP_MEMBEROFGROUP_ARGB|FORMATOP_VERTEXTEXTURE),
     0, 0, 0},

    {D3DDDIFMT_R5G6B5, // XGFX_FORMAT_RGB565 16 BP
     (FORMATOP_TEXTURE|FORMATOP_VOLUMETEXTURE|FORMATOP_CUBETEXTURE|
      FORMATOP_OFFSCREEN_RENDERTARGET|FORMATOP_SAME_FORMAT_RENDERTARGET|
      FORMATOP_DISPLAYMODE|FORMATOP_3DACCELERATION|
      FORMATOP_CONVERT_TO_ARGB|FORMATOP_OFFSCREENPLAIN|
      FORMATOP_MEMBEROFGROUP_ARGB|FORMATOP_VERTEXTEXTURE),
     0, 0, 0},

    {D3DDDIFMT_R8G8B8, // XGFX_FORMAT_RGB888 24 BPP
     (FORMATOP_TEXTURE|FORMATOP_VOLUMETEXTURE|FORMATOP_CUBETEXTURE|
      FORMATOP_OFFSCREEN_RENDERTARGET|FORMATOP_SAME_FORMAT_RENDERTARGET|
      FORMATOP_DISPLAYMODE|FORMATOP_3DACCELERATION|FORMATOP_CONVERT_TO_ARGB|
      FORMATOP_OFFSCREENPLAIN|FORMATOP_SRGBREAD|FORMATOP_MEMBEROFGROUP_ARGB|
      FORMATOP_SRGBWRITE|FORMATOP_VERTEXTEXTURE),
     0, 0, 0},

    {D3DDDIFMT_X8R8G8B8, // XGFX_FORMAT_RGBX8888 32 BPP
     (FORMATOP_TEXTURE|FORMATOP_VOLUMETEXTURE|FORMATOP_CUBETEXTURE|
      FORMATOP_OFFSCREEN_RENDERTARGET|FORMATOP_SAME_FORMAT_RENDERTARGET|
      FORMATOP_DISPLAYMODE|FORMATOP_3DACCELERATION|FORMATOP_CONVERT_TO_ARGB|
      FORMATOP_OFFSCREENPLAIN|FORMATOP_SRGBREAD|FORMATOP_MEMBEROFGROUP_ARGB|
      FORMATOP_SRGBWRITE|FORMATOP_VERTEXTEXTURE),
     0, 0, 0},

    {D3DDDIFMT_X8B8G8R8, // XGFX_FORMAT_BGRX8888 32 BPP
     (FORMATOP_TEXTURE|FORMATOP_VOLUMETEXTURE|FORMATOP_CUBETEXTURE|
      FORMATOP_OFFSCREEN_RENDERTARGET|FORMATOP_SAME_FORMAT_RENDERTARGET|
      FORMATOP_DISPLAYMODE|FORMATOP_3DACCELERATION|FORMATOP_CONVERT_TO_ARGB|
      FORMATOP_OFFSCREENPLAIN|FORMATOP_SRGBREAD|FORMATOP_MEMBEROFGROUP_ARGB|
      FORMATOP_SRGBWRITE|FORMATOP_VERTEXTEXTURE),
     0, 0, 0},

    {D3DDDIFMT_A8R8G8B8, // XGFX_FORMAT_BGRX8888 32 BPP (preserve Alpha)
     (FORMATOP_TEXTURE|FORMATOP_VOLUMETEXTURE|FORMATOP_CUBETEXTURE|
      FORMATOP_OFFSCREEN_RENDERTARGET|FORMATOP_SAME_FORMAT_RENDERTARGET|
      FORMATOP_DISPLAYMODE|FORMATOP_3DACCELERATION|FORMATOP_CONVERT_TO_ARGB|
      FORMATOP_OFFSCREENPLAIN|FORMATOP_SRGBREAD|FORMATOP_MEMBEROFGROUP_ARGB|
      FORMATOP_SRGBWRITE|FORMATOP_VERTEXTEXTURE),
     0, 0, 0},

    {D3DDDIFMT_A8B8G8R8, // XGFX_FORMAT_BGRX8888 32 BPP (preserve Alpha)
     (FORMATOP_TEXTURE|FORMATOP_VOLUMETEXTURE|FORMATOP_CUBETEXTURE|
      FORMATOP_OFFSCREEN_RENDERTARGET|FORMATOP_SAME_FORMAT_RENDERTARGET|
      FORMATOP_DISPLAYMODE|FORMATOP_3DACCELERATION|FORMATOP_CONVERT_TO_ARGB|
      FORMATOP_OFFSCREENPLAIN|FORMATOP_SRGBREAD|FORMATOP_MEMBEROFGROUP_ARGB|
      FORMATOP_SRGBWRITE|FORMATOP_VERTEXTEXTURE),
     0, 0, 0}

};

static HRESULT APIENTRY
XenD3dSetRenderState(HANDLE hDevice, CONST D3DDDIARG_RENDERSTATE *pSetRenderState)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dUpdateWInfo(HANDLE hDevice, CONST D3DDDIARG_WINFO *pUpdateWInfo)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dValidateDevice(HANDLE hDevice, D3DDDIARG_VALIDATETEXTURESTAGESTATE *pValidateTextureStageState)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetTextureStageState(HANDLE hDevice, CONST D3DDDIARG_TEXTURESTAGESTATE *pSetTextureStageState)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetTexture(HANDLE hDevice, UINT Stage, HANDLE hTexture)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetPixelShader(HANDLE hDevice, HANDLE hShader)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetPixelShaderConst(HANDLE hDevice, CONST D3DDDIARG_SETPIXELSHADERCONST *pSetPixelShaderConst, CONST FLOAT *pRegisters)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetStreamSourceUm(HANDLE hDevice, CONST D3DDDIARG_SETSTREAMSOURCEUM *pSetStreamSourceUm, CONST VOID *pUmBuffer)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetIndices(HANDLE hDevice, CONST D3DDDIARG_SETINDICES *pSetIndices)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetIndicesUm(HANDLE hDevice, UINT IndexSize, CONST VOID *pUmBuffer)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDrawPrimitive(HANDLE hDevice, CONST D3DDDIARG_DRAWPRIMITIVE *pDrawPrimitive, CONST UINT *pFlagBuffer)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDrawIndexedPrimitive(HANDLE hDevice, CONST D3DDDIARG_DRAWINDEXEDPRIMITIVE *pDrawIndexedPrimitive)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDrawRectPatch(HANDLE hDevice, CONST D3DDDIARG_DRAWRECTPATCH *pDrawRectPatch, CONST D3DDDIRECTPATCH_INFO *pInfo, CONST FLOAT *pPatch)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDrawTriPatch(HANDLE hDevice, CONST D3DDDIARG_DRAWTRIPATCH *pDrawTriPatch, CONST D3DDDITRIPATCH_INFO *pInfo, CONST FLOAT *pPatch)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDrawPrimitive2(HANDLE hDevice, CONST D3DDDIARG_DRAWPRIMITIVE2 *pDrawPrimitive2)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDrawIndexedPrimitive2(HANDLE hDevice, CONST D3DDDIARG_DRAWINDEXEDPRIMITIVE2 *pDrawIndexedPrimitive2, UINT IndicesSize, CONST VOID *pIndexBuffer, CONST UINT *pFlagBuffer)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dVolBlt(HANDLE hDevice, CONST D3DDDIARG_VOLUMEBLT *pVolumeBlt)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dBufBlt(HANDLE hDevice, CONST D3DDDIARG_BUFFERBLT *pBufferBlt)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dTexBlt(HANDLE hDevice, CONST D3DDDIARG_TEXBLT *pTextBlt)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dStateSet(HANDLE hDevice, D3DDDIARG_STATESET *pStateSet)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetPriority(HANDLE hDevice, CONST D3DDDIARG_SETPRIORITY *pSetPriority)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dClear(HANDLE hDevice, CONST D3DDDIARG_CLEAR *pClear, UINT NumRect, CONST RECT *pRect)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dUpdatePalette(HANDLE hDevice, CONST D3DDDIARG_UPDATEPALETTE *pUpdatePalette, CONST PALETTEENTRY *pPaletteEntry)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetPalette(HANDLE hDevice, CONST D3DDDIARG_SETPALETTE *pSetPalette)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetVertexShaderConst(HANDLE hDevice, CONST D3DDDIARG_SETVERTEXSHADERCONST *pSetVertexShaderConst, CONST VOID *pRegisters)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dMultiplyTransform(HANDLE hDevice, CONST D3DDDIARG_MULTIPLYTRANSFORM *pMultiplyTransform)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetTransform(HANDLE hDevice, CONST D3DDDIARG_SETTRANSFORM *pSetTransform)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetViewport(HANDLE hDevice, CONST D3DDDIARG_VIEWPORTINFO *pViewPortInfo)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetZRange(HANDLE hDevice, CONST D3DDDIARG_ZRANGE *pZRange)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetMaterial(HANDLE hDevice, CONST D3DDDIARG_SETMATERIAL *pSetMaterial)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetLight(HANDLE hDevice, CONST D3DDDIARG_SETLIGHT *pSetLight, CONST D3DDDI_LIGHT *pLight)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dCreateLight(HANDLE hDevice, CONST D3DDDIARG_CREATELIGHT *pCreateLight)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDestroyLight(HANDLE hDevice, CONST D3DDDIARG_DESTROYLIGHT *pDestroyLight)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetClipPlane(HANDLE hDevice, CONST D3DDDIARG_SETCLIPPLANE *pSetClipPlane)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dGetInfo(HANDLE hDevice, UINT DevInfoID, VOID *pDevInfoStruct, UINT DevInfoSize)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dLock(HANDLE hDevice, D3DDDIARG_LOCK *pLock)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dUnlock(HANDLE hDevice, CONST D3DDDIARG_UNLOCK *pUnlock)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dCreateResource(HANDLE hDevice, D3DDDIARG_CREATERESOURCE *pCreateResource)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDestroyResource(HANDLE hDevice, HANDLE hResource)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetDisplayMode(HANDLE hDevice, CONST D3DDDIARG_SETDISPLAYMODE *pSetDisplayMode)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dPresent(HANDLE hDevice, CONST D3DDDIARG_PRESENT *pPresent)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dFlush(HANDLE hDevice)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dCreateVertexShaderDecl(HANDLE hDevice, D3DDDIARG_CREATEVERTEXSHADERDECL *pCreateVertexShaderDecl, CONST D3DDDIVERTEXELEMENT *pVertexElements)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetVertexShaderDecl(HANDLE hDevice, HANDLE hShader)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDeleteVertexShaderDecl(HANDLE hDevice, HANDLE hShader)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dCreateVertexShaderFunc(HANDLE hDevice, D3DDDIARG_CREATEVERTEXSHADERFUNC *pCreateVertexShaderFunc, CONST UINT *pCode)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetVertexShaderFunc(HANDLE hDevice, HANDLE hShader)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDeleteVertexShaderFunc(HANDLE hDevice, HANDLE hShader)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetVertexShaderConstI(HANDLE hDevice, CONST D3DDDIARG_SETVERTEXSHADERCONSTI *pSetVertexShaderConstI, CONST INT *pRegisters)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetVertexShaderConstB(HANDLE hDevice, CONST D3DDDIARG_SETVERTEXSHADERCONSTB *pSetVertexShaderConstB, CONST BOOL *pRegisters)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetScissorRect(HANDLE hDevice, CONST RECT *pRect)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetStreamSource(HANDLE hDevice, CONST D3DDDIARG_SETSTREAMSOURCE *pSetStreamSource)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetStreamSourceFreq(HANDLE hDevice, CONST D3DDDIARG_SETSTREAMSOURCEFREQ *pSetStreamSourceFreq)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetConvolutionKernelMono(HANDLE hDevice, CONST D3DDDIARG_SETCONVOLUTIONKERNELMONO *pdSetConvolutionKernelMono)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dComposeRects(HANDLE hDevice, CONST D3DDDIARG_COMPOSERECTS *pComposeRects)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dBlt(HANDLE hDevice, CONST D3DDDIARG_BLT *pBlt)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dColorFill(HANDLE hDevice, CONST D3DDDIARG_COLORFILL *pColorFill)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDepthFill(HANDLE hDevice, CONST D3DDDIARG_DEPTHFILL *pDepthFill)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dCreateQuery(HANDLE hDevice, D3DDDIARG_CREATEQUERY *pCreateQuery)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDestroyQuery(HANDLE hDevice, HANDLE hQuery)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dIssueQuery(HANDLE hDevice, CONST D3DDDIARG_ISSUEQUERY *pIssueQuery)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY 
XenD3dGetQueryData(HANDLE hDevice, CONST D3DDDIARG_GETQUERYDATA *pGetQueryData)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetRenderTarget(HANDLE hDevice, CONST D3DDDIARG_SETRENDERTARGET *pSetRenderTarget)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetDepthStencil(HANDLE hDevice, CONST D3DDDIARG_SETDEPTHSTENCIL *pSetDepthStencil)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dGenerateMipSubLevels(HANDLE hDevice, CONST D3DDDIARG_GENERATEMIPSUBLEVELS *pGenerateMipSubLevels)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetPixelShaderConstI(HANDLE hDevice, CONST D3DDDIARG_SETPIXELSHADERCONSTI* pData, CONST INT *pRegisters)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetPixelShaderConstB(HANDLE hDevice, CONST D3DDDIARG_SETPIXELSHADERCONSTB *pSetPixelShaderConstB, CONST BOOL *pRegisters)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dCreatePixelShader(HANDLE hDevice, D3DDDIARG_CREATEPIXELSHADER *pCreatePixelShader, CONST UINT *pCode)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDeletePixelShader(HANDLE hDevice, HANDLE hShader)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dCreateDecodeDevice(HANDLE hDevice, D3DDDIARG_CREATEDECODEDEVICE *pCreateDecodeDevice)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDestroyDecodeDevice(HANDLE hDevice, HANDLE hDecodeDevice)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetDecodeRenderTarget(HANDLE hDevice, CONST D3DDDIARG_SETDECODERENDERTARGET *pSetDecodeRenderTarget)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDecodeBeginFrame(HANDLE hDevice, D3DDDIARG_DECODEBEGINFRAME *pDecodeBeginFrame)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDecodeEndFrame(HANDLE hDevice, D3DDDIARG_DECODEENDFRAME *pDecodeEndFrame)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDecodeExecute(HANDLE hDevice, CONST D3DDDIARG_DECODEEXECUTE *pDecodeExecute)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDecodeExtensionExecute(HANDLE hDevice, CONST D3DDDIARG_DECODEEXTENSIONEXECUTE *pDecodeExtensionExecute)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dCreateVideoProcessDevice(HANDLE hDevice, D3DDDIARG_CREATEVIDEOPROCESSDEVICE *pCreateVideoProcessDevice)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDestroyVideoProcessDevice(HANDLE hDevice, HANDLE hVideoProcessor)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dVideoProcessBeginFrame(HANDLE hDevice, HANDLE hVideoProcessor)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dVideoProcessEndFrame(HANDLE hDevice, D3DDDIARG_VIDEOPROCESSENDFRAME *pVideoProcessEndFrame)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetVideoProcessRenderTarget(HANDLE hDevice, CONST D3DDDIARG_SETVIDEOPROCESSRENDERTARGET *pSetVideoProcessRenderTarget)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dVideoProcessBlt(HANDLE hDevice, CONST D3DDDIARG_VIDEOPROCESSBLT *pVidoeProcessBlt)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dCreateExtensionDevice(HANDLE hDevice, D3DDDIARG_CREATEEXTENSIONDEVICE *pCreateExtensionDevice)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDestroyExtensionDevice(HANDLE hDevice, HANDLE hExtension)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dExtensionExecute(HANDLE hDevice, CONST D3DDDIARG_EXTENSIONEXECUTE *pExtensionExecute)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDestroyDevice(HANDLE hDevice)
{
    XenD3dTraceDebug(("====> '%s'.\n", __FUNCTION__));
    
    assert(hDevice != NULL);

    free(hDevice);

    XenD3dTraceDebug(("<==== '%s'.\n", __FUNCTION__));

    return S_OK;
}

static HRESULT APIENTRY
XenD3dCreateOverlay(HANDLE hDevice, D3DDDIARG_CREATEOVERLAY *pCreateOverlay)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dUpdateOverlay(HANDLE hDevice, CONST D3DDDIARG_UPDATEOVERLAY *pUpdateOverlay)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dFlipOverlay(HANDLE hDevice, CONST D3DDDIARG_FLIPOVERLAY *pFlipOverlay)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dGetOverlayColorControls(HANDLE hDevice, D3DDDIARG_GETOVERLAYCOLORCONTROLS *pGetOverlayColorControls)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dSetOverlayColorControls(HANDLE hDevice, CONST D3DDDIARG_SETOVERLAYCOLORCONTROLS *pSetOverlayColorControls)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dDestroyOverlay(HANDLE hDevice, CONST D3DDDIARG_DESTROYOVERLAY *pDestroyOverlay)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dQueryResourceResidency(HANDLE hDevice, CONST D3DDDIARG_QUERYRESOURCERESIDENCY *pQueryResourceResidency)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dOpenResource(HANDLE hDevice, D3DDDIARG_OPENRESOURCE *pOpenResource)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dGetCaptureAllocationHandle(HANDLE hDevice, D3DDDIARG_GETCAPTUREALLOCATIONHANDLE *pGetCaptureAllocationHandle)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dCaptureToSysMem(HANDLE hDevice, CONST D3DDDIARG_CAPTURETOSYSMEM *pCaptureToSystem)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dLockAsync(HANDLE hDevice, D3DDDIARG_LOCKASYNC *pLockAsync)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dUnlockAsync(HANDLE hDevice, CONST D3DDDIARG_UNLOCKASYNC *pUnlockAsync)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dRename(HANDLE hDevice, CONST D3DDDIARG_RENAME *pRename)
{
    return E_NOTIMPL;
}

static HRESULT APIENTRY
XenD3dGetCaps(HANDLE hAdapter, CONST D3DDDIARG_GETCAPS *pGetCaps)
{

    XenD3dTraceDebug(("====> '%s'.\n", __FUNCTION__));

    if ((hAdapter == NULL)||(pGetCaps == NULL))
        return E_INVALIDARG;

    if (g_XenGfx2D) {
        // Flags set, just fail to fall back to 2D and GDI
        XenD3dTraceDebug(("%s 2D support only.\n", __FUNCTION__));
        return E_FAIL;
    }

    // TODO 3D driver reports capabilities here

    XenD3dTraceDebug(("<==== '%s'.\n", __FUNCTION__));

    return S_OK; 
}

static HRESULT APIENTRY
XenD3dCreateDevice(HANDLE hAdapter, D3DDDIARG_CREATEDEVICE *pCreateData)
{
    XENGFX_D3D_ADAPTER *pXenD3dAdapter = (XENGFX_D3D_ADAPTER*)hAdapter;
    XENGFX_D3D_DEVICE *pXenD3dDevice;

    XenD3dTraceDebug(("====> '%s'.\n", __FUNCTION__));

    if ((hAdapter == NULL)||(pCreateData == NULL))
        return E_INVALIDARG;

    // Create a device object
    pXenD3dDevice = (XENGFX_D3D_DEVICE*)malloc(sizeof(XENGFX_D3D_DEVICE));
    if (pXenD3dDevice == NULL) {
        XenD3dTraceDebug(("Failed to create device object.\n"));
        return E_OUTOFMEMORY;
    }
    ZeroMemory(pXenD3dDevice, sizeof(XENGFX_D3D_DEVICE));
    pXenD3dDevice->pXenD3dAdapter = pXenD3dAdapter;

    // Copy the input values
    pXenD3dDevice->hDevice = pCreateData->hDevice;
    pXenD3dDevice->Interface = pCreateData->Interface;
    pXenD3dDevice->Version = pCreateData->Version;
    pXenD3dDevice->DeviceCallbacks = *pCreateData->pCallbacks;
    pXenD3dDevice->Flags = pCreateData->Flags;

    // Set the output values
    pCreateData->hDevice = pXenD3dDevice;

    pCreateData->pDeviceFuncs->pfnSetRenderState                = XenD3dSetRenderState;
    pCreateData->pDeviceFuncs->pfnUpdateWInfo                   = XenD3dUpdateWInfo;
    pCreateData->pDeviceFuncs->pfnValidateDevice                = XenD3dValidateDevice;
    pCreateData->pDeviceFuncs->pfnSetTextureStageState          = XenD3dSetTextureStageState;
    pCreateData->pDeviceFuncs->pfnSetTexture                    = XenD3dSetTexture;
    pCreateData->pDeviceFuncs->pfnSetPixelShader                = XenD3dSetPixelShader;
    pCreateData->pDeviceFuncs->pfnSetPixelShaderConst           = XenD3dSetPixelShaderConst;
    pCreateData->pDeviceFuncs->pfnSetStreamSourceUm             = XenD3dSetStreamSourceUm;
    pCreateData->pDeviceFuncs->pfnSetIndices                    = XenD3dSetIndices;
    pCreateData->pDeviceFuncs->pfnSetIndicesUm                  = XenD3dSetIndicesUm;
    pCreateData->pDeviceFuncs->pfnDrawPrimitive                 = XenD3dDrawPrimitive;
    pCreateData->pDeviceFuncs->pfnDrawIndexedPrimitive          = XenD3dDrawIndexedPrimitive;
    pCreateData->pDeviceFuncs->pfnDrawRectPatch                 = XenD3dDrawRectPatch;
    pCreateData->pDeviceFuncs->pfnDrawTriPatch                  = XenD3dDrawTriPatch;
    pCreateData->pDeviceFuncs->pfnDrawPrimitive2                = XenD3dDrawPrimitive2;
    pCreateData->pDeviceFuncs->pfnDrawIndexedPrimitive2         = XenD3dDrawIndexedPrimitive2;
    pCreateData->pDeviceFuncs->pfnVolBlt                        = XenD3dVolBlt;
    pCreateData->pDeviceFuncs->pfnBufBlt                        = XenD3dBufBlt;
    pCreateData->pDeviceFuncs->pfnTexBlt                        = XenD3dTexBlt;
    pCreateData->pDeviceFuncs->pfnStateSet                      = XenD3dStateSet;
    pCreateData->pDeviceFuncs->pfnSetPriority                   = XenD3dSetPriority;
    pCreateData->pDeviceFuncs->pfnClear                         = XenD3dClear;
    pCreateData->pDeviceFuncs->pfnUpdatePalette                 = XenD3dUpdatePalette;
    pCreateData->pDeviceFuncs->pfnSetPalette                    = XenD3dSetPalette;
    pCreateData->pDeviceFuncs->pfnSetVertexShaderConst          = XenD3dSetVertexShaderConst;
    pCreateData->pDeviceFuncs->pfnMultiplyTransform             = XenD3dMultiplyTransform;
    pCreateData->pDeviceFuncs->pfnSetTransform                  = XenD3dSetTransform;
    pCreateData->pDeviceFuncs->pfnSetViewport                   = XenD3dSetViewport;
    pCreateData->pDeviceFuncs->pfnSetZRange                     = XenD3dSetZRange;
    pCreateData->pDeviceFuncs->pfnSetMaterial                   = XenD3dSetMaterial;
    pCreateData->pDeviceFuncs->pfnSetLight                      = XenD3dSetLight;
    pCreateData->pDeviceFuncs->pfnCreateLight                   = XenD3dCreateLight;
    pCreateData->pDeviceFuncs->pfnDestroyLight                  = XenD3dDestroyLight;
    pCreateData->pDeviceFuncs->pfnSetClipPlane                  = XenD3dSetClipPlane;
    pCreateData->pDeviceFuncs->pfnGetInfo                       = XenD3dGetInfo;
    pCreateData->pDeviceFuncs->pfnLock                          = XenD3dLock;
    pCreateData->pDeviceFuncs->pfnUnlock                        = XenD3dUnlock;
    pCreateData->pDeviceFuncs->pfnCreateResource                = XenD3dCreateResource;
    pCreateData->pDeviceFuncs->pfnDestroyResource               = XenD3dDestroyResource;
    pCreateData->pDeviceFuncs->pfnSetDisplayMode                = XenD3dSetDisplayMode;
    pCreateData->pDeviceFuncs->pfnPresent                       = XenD3dPresent;
    pCreateData->pDeviceFuncs->pfnFlush                         = XenD3dFlush;
    pCreateData->pDeviceFuncs->pfnCreateVertexShaderFunc        = XenD3dCreateVertexShaderFunc;
    pCreateData->pDeviceFuncs->pfnDeleteVertexShaderFunc        = XenD3dDeleteVertexShaderFunc;
    pCreateData->pDeviceFuncs->pfnSetVertexShaderFunc           = XenD3dSetVertexShaderFunc;
    pCreateData->pDeviceFuncs->pfnCreateVertexShaderDecl        = XenD3dCreateVertexShaderDecl;
    pCreateData->pDeviceFuncs->pfnDeleteVertexShaderDecl        = XenD3dDeleteVertexShaderDecl;
    pCreateData->pDeviceFuncs->pfnSetVertexShaderDecl           = XenD3dSetVertexShaderDecl;
    pCreateData->pDeviceFuncs->pfnSetVertexShaderConstI         = XenD3dSetVertexShaderConstI;
    pCreateData->pDeviceFuncs->pfnSetVertexShaderConstB         = XenD3dSetVertexShaderConstB;
    pCreateData->pDeviceFuncs->pfnSetScissorRect                = XenD3dSetScissorRect;
    pCreateData->pDeviceFuncs->pfnSetStreamSource               = XenD3dSetStreamSource;
    pCreateData->pDeviceFuncs->pfnSetStreamSourceFreq           = XenD3dSetStreamSourceFreq;
    pCreateData->pDeviceFuncs->pfnSetConvolutionKernelMono      = XenD3dSetConvolutionKernelMono;
    pCreateData->pDeviceFuncs->pfnComposeRects                  = XenD3dComposeRects;
    pCreateData->pDeviceFuncs->pfnBlt                           = XenD3dBlt;
    pCreateData->pDeviceFuncs->pfnColorFill                     = XenD3dColorFill;
    pCreateData->pDeviceFuncs->pfnDepthFill                     = XenD3dDepthFill;
    pCreateData->pDeviceFuncs->pfnCreateQuery                   = XenD3dCreateQuery;
    pCreateData->pDeviceFuncs->pfnDestroyQuery                  = XenD3dDestroyQuery;
    pCreateData->pDeviceFuncs->pfnIssueQuery                    = XenD3dIssueQuery;
    pCreateData->pDeviceFuncs->pfnGetQueryData                  = XenD3dGetQueryData;
    pCreateData->pDeviceFuncs->pfnSetRenderTarget               = XenD3dSetRenderTarget;
    pCreateData->pDeviceFuncs->pfnSetDepthStencil               = XenD3dSetDepthStencil;
    pCreateData->pDeviceFuncs->pfnGenerateMipSubLevels          = XenD3dGenerateMipSubLevels;
    pCreateData->pDeviceFuncs->pfnSetPixelShaderConstI          = XenD3dSetPixelShaderConstI;
    pCreateData->pDeviceFuncs->pfnSetPixelShaderConstB          = XenD3dSetPixelShaderConstB;
    pCreateData->pDeviceFuncs->pfnCreatePixelShader             = XenD3dCreatePixelShader;
    pCreateData->pDeviceFuncs->pfnDeletePixelShader             = XenD3dDeletePixelShader;
    pCreateData->pDeviceFuncs->pfnCreateDecodeDevice            = XenD3dCreateDecodeDevice;
    pCreateData->pDeviceFuncs->pfnDestroyDecodeDevice           = XenD3dDestroyDecodeDevice;
    pCreateData->pDeviceFuncs->pfnSetDecodeRenderTarget         = XenD3dSetDecodeRenderTarget;
    pCreateData->pDeviceFuncs->pfnDecodeBeginFrame              = XenD3dDecodeBeginFrame;
    pCreateData->pDeviceFuncs->pfnDecodeEndFrame                = XenD3dDecodeEndFrame;
    pCreateData->pDeviceFuncs->pfnDecodeExecute                 = XenD3dDecodeExecute;
    pCreateData->pDeviceFuncs->pfnDecodeExtensionExecute        = XenD3dDecodeExtensionExecute;
    pCreateData->pDeviceFuncs->pfnCreateVideoProcessDevice      = XenD3dCreateVideoProcessDevice;
    pCreateData->pDeviceFuncs->pfnDestroyVideoProcessDevice     = XenD3dDestroyVideoProcessDevice;
    pCreateData->pDeviceFuncs->pfnVideoProcessBeginFrame        = XenD3dVideoProcessBeginFrame;
    pCreateData->pDeviceFuncs->pfnVideoProcessEndFrame          = XenD3dVideoProcessEndFrame;
    pCreateData->pDeviceFuncs->pfnSetVideoProcessRenderTarget   = XenD3dSetVideoProcessRenderTarget;
    pCreateData->pDeviceFuncs->pfnVideoProcessBlt               = XenD3dVideoProcessBlt;
    pCreateData->pDeviceFuncs->pfnCreateExtensionDevice         = XenD3dCreateExtensionDevice;
    pCreateData->pDeviceFuncs->pfnDestroyExtensionDevice        = XenD3dDestroyExtensionDevice;
    pCreateData->pDeviceFuncs->pfnExtensionExecute              = XenD3dExtensionExecute;
    pCreateData->pDeviceFuncs->pfnCreateOverlay                 = XenD3dCreateOverlay;
    pCreateData->pDeviceFuncs->pfnUpdateOverlay                 = XenD3dUpdateOverlay;
    pCreateData->pDeviceFuncs->pfnFlipOverlay                   = XenD3dFlipOverlay;
    pCreateData->pDeviceFuncs->pfnGetOverlayColorControls       = XenD3dGetOverlayColorControls;
    pCreateData->pDeviceFuncs->pfnSetOverlayColorControls       = XenD3dSetOverlayColorControls;
    pCreateData->pDeviceFuncs->pfnDestroyOverlay                = XenD3dDestroyOverlay;
    pCreateData->pDeviceFuncs->pfnDestroyDevice                 = XenD3dDestroyDevice;
    pCreateData->pDeviceFuncs->pfnQueryResourceResidency        = XenD3dQueryResourceResidency;
    pCreateData->pDeviceFuncs->pfnOpenResource                  = XenD3dOpenResource;
    pCreateData->pDeviceFuncs->pfnGetCaptureAllocationHandle    = XenD3dGetCaptureAllocationHandle;
    pCreateData->pDeviceFuncs->pfnCaptureToSysMem               = XenD3dCaptureToSysMem;
    pCreateData->pDeviceFuncs->pfnLockAsync                     = XenD3dLockAsync;
    pCreateData->pDeviceFuncs->pfnUnlockAsync                   = XenD3dUnlockAsync;
    pCreateData->pDeviceFuncs->pfnRename                        = XenD3dRename;

    XenD3dTraceDebug(("<==== '%s'.\n", __FUNCTION__));

    return S_OK; 
}

static HRESULT APIENTRY
XenD3dCloseAdapter(HANDLE hAdapter)
{
    XenD3dTraceDebug(("====> '%s'.\n", __FUNCTION__));
    
    assert(hAdapter != NULL);

    free(hAdapter);

    XenD3dTraceDebug(("<==== '%s'.\n", __FUNCTION__));

    return S_OK;
}

HRESULT APIENTRY
OpenAdapter(D3DDDIARG_OPENADAPTER *pOpenData)
{
    HRESULT hr;
    XENGFX_D3D_ADAPTER *pXenD3dAdapter;
    D3DDDICB_QUERYADAPTERINFO QueryAdapterInfo;
    XENGFX_UMDRIVERPRIVATE UMDriverPrivate;

    XenD3dTraceDebug(("====> '%s'.\n", __FUNCTION__));

    // Handshake with our driver
    QueryAdapterInfo.pPrivateDriverData = &UMDriverPrivate;
    QueryAdapterInfo.PrivateDriverDataSize = sizeof(XENGFX_UMDRIVERPRIVATE);
    hr = pOpenData->pAdapterCallbacks->pfnQueryAdapterInfoCb(pOpenData->hAdapter, &QueryAdapterInfo);
    if (FAILED(hr)) {
        XenD3dTraceDebug(("pfnQueryAdapterInfoCb failed - hr: 0x%x\n", hr));
        return hr;
    }

    if ((UMDriverPrivate.Magic != XENGFX_D3D_MAGIC)||(UMDriverPrivate.Version != XENGFX_D3D_MAGIC)) {
        XenD3dTraceDebug(("Invalid driver magic %x or version %d failed\n",
                          UMDriverPrivate.Magic, UMDriverPrivate.Version));
        return E_FAIL;
    }

    // Create an adapter object
    pXenD3dAdapter = (XENGFX_D3D_ADAPTER*)malloc(sizeof(XENGFX_D3D_ADAPTER));
    if (pXenD3dAdapter == NULL) {
        XenD3dTraceDebug(("Failed to create adapter object.\n"));
        return E_OUTOFMEMORY;
    }
    ZeroMemory(pXenD3dAdapter, sizeof(XENGFX_D3D_ADAPTER));

    pXenD3dAdapter->hAdapter = pOpenData->hAdapter;
    pXenD3dAdapter->Interface = pOpenData->Interface;
    pXenD3dAdapter->Version = pOpenData->Version;
    pXenD3dAdapter->AdapterCallbacks = *pOpenData->pAdapterCallbacks;
    pXenD3dAdapter->UMDriverPrivate = UMDriverPrivate;

    pOpenData->hAdapter = pXenD3dAdapter;
    pOpenData->pAdapterFuncs->pfnGetCaps = XenD3dGetCaps;
    pOpenData->pAdapterFuncs->pfnCreateDevice = XenD3dCreateDevice;
    pOpenData->pAdapterFuncs->pfnCloseAdapter = XenD3dCloseAdapter;
    pOpenData->DriverVersion = D3D_UMD_INTERFACE_VERSION;

    XenD3dTraceDebug(("<==== '%s'.\n", __FUNCTION__));
    
    return S_OK;
}
