//
// xenvesa.c - Xen Windows Vesa Miniport Driver
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


#include <ntstatus.h>
#include <miniport.h>
#include <ntddvdeo.h>
#include <video.h>
#include <devioctl.h>
#include <dderror.h>

typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

#include "xenvesa-miniport.h"

typedef struct 
{
	XEN_VESA_DEVICE_EXTENSION Public;

    VIDEO_PORT_INT10_INTERFACE Int10Interface;
    USHORT Int10MemSeg;
    USHORT Int10MemOffset;

} XEN_VESA_DEVICE_EXTENSION_PRIVATE, *PXEN_VESA_DEVICE_EXTENSION_PRIVATE;

VP_STATUS __stdcall XenVesaFindAdapter(PVOID  HwDeviceExtension,
                             PVOID  HwContext,    
                             PWSTR  ArgumentString,    
                             PVIDEO_PORT_CONFIG_INFO  ConfigInfo,    
                             PUCHAR  Again);

BOOLEAN  __stdcall XenVesaInitialize(PVOID  HwDeviceExtension);

BOOLEAN  __stdcall XenVesaStartIO(PVOID  HwDeviceExtension,
                                  PVIDEO_REQUEST_PACKET  RequestPacket);

VP_STATUS  __stdcall XenVesaSetPowerState(PVOID  HwDeviceExtension,
                                          ULONG  HwId,
                                          PVIDEO_POWER_MANAGEMENT  VideoPowerControl);

VP_STATUS  __stdcall XenVesaGetPowerState(PVOID  HwDeviceExtension,
                                          ULONG  HwId,
                                          PVIDEO_POWER_MANAGEMENT  VideoPowerControl);

VP_STATUS __stdcall XenVesaGetVideoChildDescriptor(IN PVOID HwDeviceExtension, 
                    IN PVIDEO_CHILD_ENUM_INFO ChildEnumInfo, OUT PVIDEO_CHILD_TYPE VideoChildType,
                    OUT PUCHAR pChildDescriptor, OUT PULONG UId, OUT PULONG pUnused);

BOOLEAN __stdcall XenVesaSetCurrentMode(PXEN_VESA_DEVICE_EXTENSION_PRIVATE DeviceExtension,
                    PVIDEO_MODE RequestedMode, PSTATUS_BLOCK StatusBlock);

BOOLEAN __stdcall XenVesaResetDevice(PXEN_VESA_DEVICE_EXTENSION_PRIVATE DeviceExtension, 
                                     PSTATUS_BLOCK StatusBlock);

BOOLEAN __stdcall XenVesaMapVideoMemory(PXEN_VESA_DEVICE_EXTENSION_PRIVATE DeviceExtension,
                PVIDEO_MEMORY RequestedAddress, PVIDEO_MEMORY_INFORMATION MapInformation,
                PSTATUS_BLOCK StatusBlock);

BOOLEAN __stdcall XenVesaUnmapVideoMemory(PXEN_VESA_DEVICE_EXTENSION_PRIVATE DeviceExtension,
                PVIDEO_MEMORY VideoMemory, PSTATUS_BLOCK StatusBlock);

BOOLEAN __stdcall XenVesaQueryNumAvailableModes(PXEN_VESA_DEVICE_EXTENSION_PRIVATE DeviceExtension,
                PVIDEO_NUM_MODES AvailableModes, PSTATUS_BLOCK StatusBlock);

BOOLEAN __stdcall XenVesaQueryAvailableModes(PXEN_VESA_DEVICE_EXTENSION_PRIVATE DeviceExtension,
                PVIDEO_MODE_INFORMATION ReturnedModes, PSTATUS_BLOCK StatusBlock);

BOOLEAN __stdcall XenVesaQueryCurrentMode(PXEN_VESA_DEVICE_EXTENSION_PRIVATE DeviceExtension,
                PVIDEO_MODE_INFORMATION VideoModeInfo, PSTATUS_BLOCK StatusBlock);

void XenVesaGetModeInfo(PVBE_MODE_INFO VbeModeInfo, PVIDEO_MODE_INFORMATION ModeInfo, ULONG Index);
VP_STATUS XenVesaInt10Initialize(PXEN_VESA_DEVICE_EXTENSION_PRIVATE XenVesaExt);
VP_STATUS XenVesaGetVBEControllerInfo(PXEN_VESA_DEVICE_EXTENSION_PRIVATE XenVesaExt);
ULONG XenVesaGetPotentialModeCount(PXEN_VESA_DEVICE_EXTENSION_PRIVATE XenVesaExt);
VP_STATUS XenVesaInitializeSuitableModeInfo(PXEN_VESA_DEVICE_EXTENSION_PRIVATE XenVesaExt, ULONG PotentialModeCount);
void XenVesaFreeResources(PXEN_VESA_DEVICE_EXTENSION_PRIVATE XenVesaExt);

//
// DriverEntry
//
ULONG DriverEntry(PVOID Context1, PVOID Context2)
{
    ULONG Ret;
    VIDEO_HW_INITIALIZATION_DATA  VideoInitData;

    VideoPortDebugPrint(Info, "XenVesa:  DriverEntry\n");
    VideoPortZeroMemory(&VideoInitData, sizeof(VideoInitData));
    VideoInitData.HwInitDataSize = sizeof(VIDEO_HW_INITIALIZATION_DATA);
    VideoInitData.HwFindAdapter = XenVesaFindAdapter;
    VideoInitData.HwInitialize = XenVesaInitialize;  
    VideoInitData.HwStartIO = XenVesaStartIO;  
    VideoInitData.HwDeviceExtensionSize = sizeof(XEN_VESA_DEVICE_EXTENSION_PRIVATE);  
    VideoInitData.HwSetPowerState = XenVesaSetPowerState;  
    VideoInitData.HwGetPowerState = XenVesaGetPowerState;  
    VideoInitData.HwGetVideoChildDescriptor = XenVesaGetVideoChildDescriptor;  

    if ((Ret = VideoPortInitialize(Context1, Context2, &VideoInitData, NULL)) != 0) {
        VideoPortDebugPrint(Error, "VideoPortInitialize failed - %d\n", Ret);
        return STATUS_UNSUCCESSFUL;
    }

    return NO_ERROR;
}

//
// XenVesaFindAdapter
//
VP_STATUS __stdcall XenVesaFindAdapter(PVOID  HwDeviceExtension, 
                                       PVOID  HwContext, PWSTR ArgumentString, 
                                       PVIDEO_PORT_CONFIG_INFO ConfigInfo,
                                       PUCHAR  Again)
{
    //NOTE:  For Int10* calls to succeed, the below fields must be set.
    //If not set, Int10AllocateBuffer returns success but the buffer returned is
    //bogus and the rest of the Int10* calls that use this buffer will obviously fail.
    ConfigInfo->VdmPhysicalVideoMemoryAddress.LowPart  = XEN_VESA_FRAME_BUFFER;
    ConfigInfo->VdmPhysicalVideoMemoryAddress.HighPart = 0;
    ConfigInfo->VdmPhysicalVideoMemoryLength           = XEN_VESA_FRAME_BUFFER_LENGTH;

#if 0
    VideoPortWritePortUshort((PUSHORT)VBE_IO_INDEX_PORT, VBE_DISPI_INDEX_ID);
    VideoPortWritePortUshort((PUSHORT)VBE_IO_DATA_PORT, VBE_DISPI_ID0 );
    if  ( VideoPortReadPortUshort((PUSHORT)VBE_IO_DATA_PORT) != VBE_DISPI_ID0 )
        return ERROR_DEV_NOT_EXIST;
#endif
    // Get the VideoString for this driver so we can write the preferred 
    // resolution to the registry
    XenVesaGetRegistryPath(HwDeviceExtension, ConfigInfo->DriverRegistryPath);
    return NO_ERROR;    
}

//
// XenVesaInitialize
//
BOOLEAN  __stdcall XenVesaInitialize(PVOID HwDeviceExtension)
{
    VP_STATUS Status;
    ULONG PotentialModeCount = 0;
    PXEN_VESA_DEVICE_EXTENSION_PRIVATE XenVesaExt = 
        (PXEN_VESA_DEVICE_EXTENSION_PRIVATE) HwDeviceExtension; 
    NTSTATUS NtStatus;

    VideoPortDebugPrint(Info, "XenVesa: XenVesaInitialize\n");

	XenVesaExt->Public.Private = XenVesaExt;

    Status = XenVesaInt10Initialize(XenVesaExt);
    if ( Status != NO_ERROR ) {
        return FALSE;
    }
    
    Status = XenVesaGetVBEControllerInfo(XenVesaExt);
    if ( Status != NO_ERROR ) {
        XenVesaFreeResources(XenVesaExt);
        return FALSE;
    }

    PotentialModeCount = XenVesaGetPotentialModeCount(XenVesaExt);
    if ( PotentialModeCount <= 0 ) {
        VideoPortDebugPrint(Error, "Potential mode count is zero!\n");
        XenVesaFreeResources(XenVesaExt);
        return FALSE;
    }

    //As the display miniport driver is resident once loaded, the below resource
    //could be referred as needed and thus not freed unless we encounter failure
    //during initialization.
    XenVesaExt->Public.VbeModeInfo = VideoPortAllocatePool(HwDeviceExtension, VpPagedPool, 
                PotentialModeCount * sizeof(VBE_MODE_INFO), XENVESA_TAG);
    XenVesaExt->Public.VbeModeNumbers = VideoPortAllocatePool(HwDeviceExtension, VpPagedPool, 
       PotentialModeCount * sizeof(USHORT), XENVESA_TAG);

    if ( XenVesaExt->Public.VbeModeInfo == NULL || XenVesaExt->Public.VbeModeNumbers == NULL ) {
        VideoPortDebugPrint(Error, "XenVesa: Insufficient resources\n");
        XenVesaFreeResources(XenVesaExt);
        return FALSE;
    }

    Status = XenVesaInitializeSuitableModeInfo(XenVesaExt, PotentialModeCount);
    if ( Status != NO_ERROR ) {
        XenVesaFreeResources(XenVesaExt);
        return FALSE;
    }   
    
    return TRUE;    
}

//
// XenVesaStartIO
//
BOOLEAN  __stdcall XenVesaStartIO(PVOID  HwDeviceExtension, PVIDEO_REQUEST_PACKET  RequestPacket)
{
    VideoPortDebugPrint(Info, "XenVesa: XenVesaStartIO\n");
    RequestPacket->StatusBlock->Status = STATUS_NOT_IMPLEMENTED;

    switch (RequestPacket->IoControlCode)
    {
      case IOCTL_VIDEO_MAP_VIDEO_MEMORY:
          VideoPortDebugPrint(Info, "XenVesaStartIO - Map video memory\n");
          if ( RequestPacket->InputBufferLength < sizeof(VIDEO_MEMORY) ) {
              VideoPortDebugPrint(Error, "XenVesaStartIO - invalid input parameter\n");
              RequestPacket->StatusBlock->Status = STATUS_INVALID_PARAMETER;
              return FALSE;
          }       
          if ( RequestPacket->OutputBufferLength < sizeof(VIDEO_MEMORY_INFORMATION) ) {
              VideoPortDebugPrint(Error, "XenVesaStartIO - Insufficent output buffer\n");
              RequestPacket->StatusBlock->Status = STATUS_INSUFFICIENT_RESOURCES;
              return FALSE;
          }
          return XenVesaMapVideoMemory(
              (PXEN_VESA_DEVICE_EXTENSION_PRIVATE)HwDeviceExtension,
              (PVIDEO_MEMORY)RequestPacket->InputBuffer, 
              (PVIDEO_MEMORY_INFORMATION)RequestPacket->OutputBuffer, 
              RequestPacket->StatusBlock);        
      case IOCTL_VIDEO_UNMAP_VIDEO_MEMORY:
          VideoPortDebugPrint(Info, "XenVesaStartIO - Unmap video memory\n");
          if (RequestPacket->InputBufferLength < sizeof(VIDEO_MEMORY)) {
              RequestPacket->StatusBlock->Status = STATUS_INVALID_PARAMETER;
              return FALSE;
          }
          return XenVesaUnmapVideoMemory(
              (PXEN_VESA_DEVICE_EXTENSION_PRIVATE)HwDeviceExtension,
              (PVIDEO_MEMORY)RequestPacket->InputBuffer, RequestPacket->StatusBlock);
          break;
      case IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES:
          VideoPortDebugPrint(Info, "XenVesaStartIO - Query available modes\n");
          if (RequestPacket->OutputBufferLength < sizeof(VIDEO_NUM_MODES)) {
              RequestPacket->StatusBlock->Status = STATUS_INVALID_PARAMETER;
              return FALSE;
          }
          return XenVesaQueryNumAvailableModes(
              (PXEN_VESA_DEVICE_EXTENSION_PRIVATE)HwDeviceExtension,
              (PVIDEO_NUM_MODES)RequestPacket->OutputBuffer,RequestPacket->StatusBlock);
      case IOCTL_VIDEO_QUERY_AVAIL_MODES:
          VideoPortDebugPrint(Info, "XenVesaStartIO - Query mode info\n");
          if (RequestPacket->OutputBufferLength <
             ((PXEN_VESA_DEVICE_EXTENSION_PRIVATE)HwDeviceExtension)->Public.VbeModeCount * 
              sizeof(VIDEO_MODE_INFORMATION)){
                  RequestPacket->StatusBlock->Status = STATUS_INSUFFICIENT_RESOURCES;
                  return FALSE;
          }
          return XenVesaQueryAvailableModes(
              (PXEN_VESA_DEVICE_EXTENSION_PRIVATE)HwDeviceExtension,
              (PVIDEO_MODE_INFORMATION)RequestPacket->OutputBuffer, 
              RequestPacket->StatusBlock);        
      case IOCTL_VIDEO_SET_CURRENT_MODE:
          VideoPortDebugPrint(Info, "XenVesaStartIO - Set current mode\n");
          if (RequestPacket->InputBufferLength < sizeof(VIDEO_MODE)) {
              VideoPortDebugPrint(Error, "Set current mode - invalid parameter\n");
              RequestPacket->StatusBlock->Status = STATUS_INVALID_PARAMETER;
              return FALSE;
          }
          return XenVesaSetCurrentMode(
              (PXEN_VESA_DEVICE_EXTENSION_PRIVATE)HwDeviceExtension,
              (PVIDEO_MODE)RequestPacket->InputBuffer, RequestPacket->StatusBlock); 
      case IOCTL_VIDEO_QUERY_CURRENT_MODE:
          VideoPortDebugPrint(Info, "XenVesaStartIO - Query current mode\n");
          if (RequestPacket->OutputBufferLength < sizeof(VIDEO_MODE_INFORMATION)) {
              RequestPacket->StatusBlock->Status = STATUS_INSUFFICIENT_RESOURCES;
              return FALSE;
          }
          return XenVesaQueryCurrentMode(
             (PXEN_VESA_DEVICE_EXTENSION_PRIVATE)HwDeviceExtension,
             (PVIDEO_MODE_INFORMATION)RequestPacket->OutputBuffer,
             RequestPacket->StatusBlock);        
      case IOCTL_VIDEO_RESET_DEVICE:
          VideoPortDebugPrint(Info, "XenVesaStartIO - Reset device\n");
          return XenVesaResetDevice((PXEN_VESA_DEVICE_EXTENSION_PRIVATE)HwDeviceExtension,
                RequestPacket->StatusBlock);
      default:
          VideoPortDebugPrint(Info, "XenVesaStartIO - Unknown IOCTL - 0x%08x\n", 
              RequestPacket->IoControlCode);          
          break;
    }
    
    return FALSE;
}

//
// XenVesaSetPowerState
//
VP_STATUS  __stdcall XenVesaSetPowerState(PVOID  HwDeviceExtension, 
                                          ULONG  HwId, 
                                          PVIDEO_POWER_MANAGEMENT  VideoPowerControl)
{ 
//Once our VBE backend starts supporting DPMS (ax=0x4f10), uncomment the below
#if 0
    //Note: Per MSDN XenVesaSetPowerState should always return success.
    VP_STATUS Status;
    STATUS_BLOCK StatusBlock;
    INT10_BIOS_ARGUMENTS Int10BiosArgs;
    PXEN_VESA_DEVICE_EXTENSION_PRIVATE DeviceExtension = 
        (PXEN_VESA_DEVICE_EXTENSION_PRIVATE)HwDeviceExtension;

    VideoPortDebugPrint(Info, "XenVesa: XenVesaSetPowerState\n");
    if (VideoPowerControl->PowerState == VideoPowerHibernate)
      return NO_ERROR;
    
    VideoPortZeroMemory(&Int10BiosArgs, sizeof(Int10BiosArgs));
    Int10BiosArgs.Eax = VBE_POWER_MANAGEMENT_EXTENSIONS;
    Int10BiosArgs.Ebx = 1;
    switch (VideoPowerControl->PowerState) {
        case VideoPowerOn:
          Int10BiosArgs.Ebx |= DPMS_MODE_POWERON;
          break;
        case VideoPowerStandBy: 
          Int10BiosArgs.Ebx |= DPMS_MODE_STANDBY; 
          break;
        case VideoPowerSuspend: 
          Int10BiosArgs.Ebx |= DPMS_MODE_SUSPEND; 
          break;
        case VideoPowerOff: 
          Int10BiosArgs.Ebx |= DPMS_MODE_POWEROFF; 
          break;
        default:
          return NO_ERROR;
    }
    Status = DeviceExtension->Int10Interface.Int10CallBios(
        DeviceExtension->Int10Interface.Context,&Int10BiosArgs);
    if ( Status != NO_ERROR || (Int10BiosArgs.Eax & 0xffff) != VBE_SUCCESS ) {
        VideoPortDebugPrint(Error, "XenVesaSetPowerState failed\n");
    }
#endif
    return NO_ERROR;
}

//
// XenVesaGetPowerState
//
VP_STATUS  __stdcall XenVesaGetPowerState(PVOID  HwDeviceExtension, 
                                          ULONG  HwId, 
                                          PVIDEO_POWER_MANAGEMENT  VideoPowerControl)
{
    //Once our VBE backend starts supporting DPMS (ax=0x4f10), uncomment the below
#if 0
    VP_STATUS Status;
    INT10_BIOS_ARGUMENTS Int10BiosArgs;
    PXEN_VESA_DEVICE_EXTENSION_PRIVATE DeviceExtension = 
        (PXEN_VESA_DEVICE_EXTENSION_PRIVATE)HwDeviceExtension;
    USHORT Capabilities;

    VideoPortDebugPrint(Info, "XenVesa: XenVesaGetPowerState\n");
    VideoPortZeroMemory(&Int10BiosArgs, sizeof(Int10BiosArgs));
    Int10BiosArgs.Eax = VBE_POWER_MANAGEMENT_EXTENSIONS;
    Int10BiosArgs.Ebx = 0;
    
    Status = DeviceExtension->Int10Interface.Int10CallBios(
             DeviceExtension->Int10Interface.Context,&Int10BiosArgs);
    if ( Status != NO_ERROR || (Int10BiosArgs.Eax & 0xffff) != VBE_SUCCESS ) {
        VideoPortDebugPrint(Error, "XenVesaGetPowerState failed\n");
        return ERROR_DEVICE_REINITIALIZATION_NEEDED;
    }

    Capabilities = (USHORT) Int10BiosArgs.Ebx >> 8;
    switch (VideoPowerControl->PowerState)
    {
        case VideoPowerStandBy: 
            if ( (Capabilities & 4)  == 0 )
                Status = ERROR_DEVICE_REINITIALIZATION_NEEDED;
            break;
        case VideoPowerSuspend: 
            if ( (Capabilities & 2)  == 0 )
                Status = ERROR_DEVICE_REINITIALIZATION_NEEDED;
            break;
        case VideoPowerOff: 
            if ( (Capabilities & 1)  == 0 )
                Status = ERROR_DEVICE_REINITIALIZATION_NEEDED;
            break;
    }

    return Status;
#endif
    return NO_ERROR;
}

static VP_STATUS XenVesaSetPreferredResolution(PXEN_VESA_DEVICE_EXTENSION_PRIVATE XenVesaExt, PUCHAR pEdid)
{
    int             XRes = (int)(pEdid[58]>>4)<<8 | pEdid[56];
    int             YRes = (int)(pEdid[61]>>4)<<8 | pEdid[59];
    PVBE_MODE_INFO  VbeModeInfo;
    ULONG           Index = 0, Depth = 0;
    USHORT          Mode;
    VP_STATUS       Status;

    for (Index = 0; Index < XenVesaExt->Public.VbeModeCount; ++Index)
    {
        VbeModeInfo = &XenVesaExt->Public.VbeModeInfo[Index];
        
        if (VbeModeInfo->XResolution != XRes || 
            VbeModeInfo->YResolution != YRes ) continue;
        if (VbeModeInfo->BitsPerPixel >= Depth) {
                Depth = VbeModeInfo->BitsPerPixel;
                Mode = (USHORT)Index;
        }
    }
    if (Depth == 0) {
        VideoPortDebugPrint(Info, 
            "XenVesa: %s failed to file preferred resolution of (%d x %d) in mode list\n");
        return ERROR_INVALID_PARAMETER;
    }
    XenVesaExt->Public.VbeCurrentMode = Mode;
    if (XenVesaSetRegistryDeviceResolution(&XenVesaExt->Public) != STATUS_SUCCESS)
		return STATUS_UNSUCCESSFUL;

    return NO_ERROR;
}
//
// XenVesaGetVideoChildDescriptor
//
VP_STATUS __stdcall XenVesaGetVideoChildDescriptor(IN PVOID HwDeviceExtension, 
                    IN PVIDEO_CHILD_ENUM_INFO ChildEnumInfo, 
                    OUT PVIDEO_CHILD_TYPE VideoChildType,
                    OUT PUCHAR pChildDescriptor, OUT PULONG UId, 
                    OUT PULONG pUnused)
{
    VP_STATUS Status;
    INT10_BIOS_ARGUMENTS Int10BiosArgs;
    PXEN_VESA_DEVICE_EXTENSION_PRIVATE DeviceExtension =
        (PXEN_VESA_DEVICE_EXTENSION_PRIVATE)HwDeviceExtension;

    VideoPortDebugPrint(Info, "XenVesa:" __FUNCTION__ " Entry\n");

    if ( ChildEnumInfo->ChildIndex == DISPLAY_ADAPTER_HW_ID )
        return ERROR_NO_MORE_DEVICES;
 
    *VideoChildType = Monitor;
    *UId = ChildEnumInfo->ChildIndex;
    *pUnused = 0;

    if ( (pChildDescriptor == NULL) || (ChildEnumInfo->ChildDescriptorSize < VBE_EDID_SIZE) )
        return ERROR_NO_MORE_DEVICES;
 
    VideoPortZeroMemory(&Int10BiosArgs, sizeof(Int10BiosArgs));
    Int10BiosArgs.Eax = VBE_DISPLAY_IDENTIFICATION;
    Int10BiosArgs.Ebx = VBE_READ_EDID;
    Int10BiosArgs.Edx = 1;
    Int10BiosArgs.Edi = DeviceExtension->Int10MemOffset;
    Int10BiosArgs.SegEs = DeviceExtension->Int10MemSeg;

    Status = DeviceExtension->Int10Interface.Int10CallBios(
             DeviceExtension->Int10Interface.Context, &Int10BiosArgs);
    if ( (Int10BiosArgs.Eax & 0xffff) != VBE_SUCCESS || Status != NO_ERROR ) {
        VideoPortDebugPrint(Error,
            "XenVesaGetVideoChildDescriptor - Unable to get EDID info from backend\n");
        return ERROR_NO_MORE_DEVICES;
    }

    Status = DeviceExtension->Int10Interface.Int10ReadMemory(
             DeviceExtension->Int10Interface.Context, DeviceExtension->Int10MemSeg,
             DeviceExtension->Int10MemOffset, pChildDescriptor,
             VBE_EDID_SIZE);
    if ( Status != NO_ERROR ) {
        VideoPortDebugPrint(Error, "Int10ReadMemory failed - 0x%08x\n", Status);
        return ERROR_NO_MORE_DEVICES;
    }

    VideoPortDebugPrint(Info, "XenVesa:" __FUNCTION__ " Exit Uid:%d\n", ChildEnumInfo->ChildIndex);

    //Set Preferred resolution
    XenVesaSetPreferredResolution(DeviceExtension, pChildDescriptor);
    return ERROR_NO_MORE_DEVICES;
}

//
// XenVesaSetCurrentMode
//
BOOLEAN __stdcall XenVesaSetCurrentMode(PXEN_VESA_DEVICE_EXTENSION_PRIVATE DeviceExtension,
                    PVIDEO_MODE RequestedMode, PSTATUS_BLOCK StatusBlock)
{
    VP_STATUS Status;
    INT10_BIOS_ARGUMENTS Int10BiosArgs;
    //Per MSDN the two high-order bits of RequestedMode can be set to request special behavior
    ULONG ModeRequested = RequestedMode->RequestedMode & 0x3fffffff;    

    VideoPortDebugPrint(Info, "XenVesa:" __FUNCTION__ " Entry\n");

    if ( ModeRequested >= DeviceExtension->Public.VbeModeCount) {
        VideoPortDebugPrint(Error,"XenVesaSetCurrentMode - invalid parameter\n");
        StatusBlock->Status = STATUS_INVALID_PARAMETER;
        return FALSE;
    }

    VideoPortZeroMemory(&Int10BiosArgs, sizeof(Int10BiosArgs));
    Int10BiosArgs.Eax = VBE_SET_VBE_MODE;
    Int10BiosArgs.Ebx = DeviceExtension->Public.VbeModeNumbers[ModeRequested];
    //Set VIDEO_MODE_ZERO_MEMORY  and VIDEO_MODE_MAP_MEM_LINEAR flags if requested.
    Int10BiosArgs.Ebx |= (RequestedMode->RequestedMode >> 16) & 0xc000;
    Status = DeviceExtension->Int10Interface.Int10CallBios(
             DeviceExtension->Int10Interface.Context, &Int10BiosArgs);
    if ( (Int10BiosArgs.Eax & 0xffff) != VBE_SUCCESS || Status != NO_ERROR ) {
        VideoPortDebugPrint(Error,
            "XenVesaSetCurrentMode - Vbe set current mode failed - Eax: 0x%x Status: 0x%x\n", Int10BiosArgs.Eax, Status);
        StatusBlock->Status = STATUS_UNSUCCESSFUL;
        return FALSE;
    }

    DeviceExtension->Public.VbeCurrentMode = (USHORT) ModeRequested;
    (VOID)XenVesaSetRegistryDeviceResolution(&DeviceExtension->Public);
    StatusBlock->Status = NO_ERROR;

    VideoPortDebugPrint(Info, "XenVesa:" __FUNCTION__ " Exit Mode:%d\n", ModeRequested);
    return TRUE;
}

//
// XenVesaResetDevice
//
BOOLEAN __stdcall XenVesaResetDevice(PXEN_VESA_DEVICE_EXTENSION_PRIVATE DeviceExtension, 
                                     PSTATUS_BLOCK StatusBlock)
{
    VP_STATUS Status;
    INT10_BIOS_ARGUMENTS Int10BiosArgs;

    VideoPortDebugPrint(Info, "XenVesa:" __FUNCTION__ " Entry\n");

    StatusBlock->Status = NO_ERROR;

    VideoPortDebugPrint(Info, "XenVesa:" __FUNCTION__ " Exit\n");
    return TRUE;
}

//
// XenVesaMapVideoMemory
//
BOOLEAN __stdcall XenVesaMapVideoMemory(PXEN_VESA_DEVICE_EXTENSION_PRIVATE DeviceExtension,
                                        PVIDEO_MEMORY RequestedAddress, 
                                        PVIDEO_MEMORY_INFORMATION MapInformation,
                                        PSTATUS_BLOCK StatusBlock)
{
    VP_STATUS Status;
    PHYSICAL_ADDRESS VideoMemory;
    ULONG MemSpace = VIDEO_MEMORY_SPACE_MEMORY;

    VideoPortDebugPrint(Info, "XenVesa:" __FUNCTION__ " Entry\n");

    if (DeviceExtension->Public.VbeModeInfo[DeviceExtension->Public.VbeCurrentMode].ModeAttributes & VBE_MODEATTR_LINEAR) 
    {
        VideoMemory.QuadPart = DeviceExtension->Public.VbeModeInfo[DeviceExtension->Public.VbeCurrentMode].PhysBasePtr;

        MapInformation->VideoRamBase = RequestedAddress->RequestedVirtualAddress;
        MapInformation->VideoRamLength =
            DeviceExtension->Public.VbeModeInfo[DeviceExtension->Public.VbeCurrentMode].LinBytesPerScanLine *
            DeviceExtension->Public.VbeModeInfo[DeviceExtension->Public.VbeCurrentMode].YResolution;
    } 
    else 
    {
        VideoPortDebugPrint(Warn, "VBE_MODEATTR_LINEAR not set!\n");
        VideoMemory.QuadPart = XEN_VESA_FRAME_BUFFER;
        MapInformation->VideoRamBase = RequestedAddress->RequestedVirtualAddress;
        MapInformation->VideoRamLength = XEN_VESA_FRAME_BUFFER_LENGTH;
    }
    
    Status = VideoPortMapMemory(DeviceExtension, VideoMemory, &MapInformation->VideoRamLength, &MemSpace, &MapInformation->VideoRamBase);
    if ( Status != NO_ERROR ) 
    {
        VideoPortDebugPrint(Error, "XenVesaMapVideoMemory - VideoPortMapMemory failed status:%x\n", Status);
        StatusBlock->Status = Status;
        return FALSE;
    }

    MapInformation->FrameBufferBase = MapInformation->VideoRamBase;
    MapInformation->FrameBufferLength = MapInformation->VideoRamLength;
    StatusBlock->Information = sizeof(VIDEO_MEMORY_INFORMATION);
    StatusBlock->Status = NO_ERROR;

    VideoPortDebugPrint(Info, "XenVesa:" __FUNCTION__ " Exit VideoRamBase: %p VideoRamLength: %x PhysBasePtr: 0x%x\n",
        MapInformation->VideoRamBase, MapInformation->VideoRamLength, (ULONG)VideoMemory.QuadPart);
    return TRUE;
}

//
// XenVesaUnmapVideoMemory
//
BOOLEAN __stdcall XenVesaUnmapVideoMemory(PXEN_VESA_DEVICE_EXTENSION_PRIVATE DeviceExtension,
                PVIDEO_MEMORY VideoMemory, PSTATUS_BLOCK StatusBlock)
{
    VP_STATUS Status;

    VideoPortDebugPrint(Info, "XenVesa:" __FUNCTION__ " Entry VideoRamBase:%p\n", VideoMemory->RequestedVirtualAddress);

    Status = VideoPortUnmapMemory(DeviceExtension, VideoMemory->RequestedVirtualAddress, NULL);
    if (Status != NO_ERROR)
    {
        VideoPortDebugPrint(Error, "XenVesa:" __FUNCTION__ " Failed to unmap memory:%p Status:%x\n", VideoMemory->RequestedVirtualAddress, Status);
    }

    StatusBlock->Status = Status;

    VideoPortDebugPrint(Info, "XenVesa:" __FUNCTION__ " Exit status:%x\n", Status);
    return (Status == NO_ERROR);
}

//
// XenVesaQueryAvailableModes
// 
BOOLEAN __stdcall XenVesaQueryNumAvailableModes(PXEN_VESA_DEVICE_EXTENSION_PRIVATE DeviceExtension,
                                                PVIDEO_NUM_MODES AvailableModes, PSTATUS_BLOCK StatusBlock)
{
    AvailableModes->NumModes = DeviceExtension->Public.VbeModeCount;
    AvailableModes->ModeInformationLength = sizeof(VIDEO_MODE_INFORMATION);
    StatusBlock->Information = sizeof(VIDEO_NUM_MODES);
    StatusBlock->Status = NO_ERROR;
    return TRUE;
}

//
// XenVesaQueryAvailableModes
//
BOOLEAN __stdcall XenVesaQueryAvailableModes(PXEN_VESA_DEVICE_EXTENSION_PRIVATE DeviceExtension,
                                             PVIDEO_MODE_INFORMATION ReturnedModes, 
                                             PSTATUS_BLOCK StatusBlock)
{   
    ULONG Count;
    PVBE_MODE_INFO VbeModeInfo;
    PVIDEO_MODE_INFORMATION ModeInfo;

    for (Count = 0, VbeModeInfo=DeviceExtension->Public.VbeModeInfo, 
        ModeInfo = ReturnedModes; Count < DeviceExtension->Public.VbeModeCount; 
        Count++, VbeModeInfo++, ModeInfo++) {
        VideoPortZeroMemory(ModeInfo, sizeof(VIDEO_MODE_INFORMATION));
        XenVesaGetModeInfo(VbeModeInfo, ModeInfo, Count);
    }

    StatusBlock->Information = 
        sizeof(VIDEO_MODE_INFORMATION) * DeviceExtension->Public.VbeModeCount;
    StatusBlock->Status = NO_ERROR;
    return TRUE;
}

//
// XenVesaQueryCurrentMode
//
BOOLEAN __stdcall XenVesaQueryCurrentMode(PXEN_VESA_DEVICE_EXTENSION_PRIVATE DeviceExtension,
                                          PVIDEO_MODE_INFORMATION VideoModeInfo, 
                                          PSTATUS_BLOCK StatusBlock)
{
    PVBE_MODE_INFO VbeModeInfo;

    if ( DeviceExtension->Public.VbeCurrentMode > DeviceExtension->Public.VbeModeCount ) {
        StatusBlock->Status = STATUS_INVALID_PARAMETER;
        return FALSE;
    }
    
    VbeModeInfo = &DeviceExtension->Public.VbeModeInfo[DeviceExtension->Public.VbeCurrentMode];
    VideoPortZeroMemory(VideoModeInfo, sizeof(VIDEO_MODE_INFORMATION));
    XenVesaGetModeInfo(VbeModeInfo, VideoModeInfo, DeviceExtension->Public.VbeCurrentMode);
    StatusBlock->Information = sizeof(VIDEO_MODE_INFORMATION);
    StatusBlock->Status = NO_ERROR;
    return TRUE;
}

//
// XenVesaGetModeInfo
//
void XenVesaGetModeInfo(PVBE_MODE_INFO VbeModeInfo, PVIDEO_MODE_INFORMATION ModeInfo, ULONG Index)
{
    ModeInfo->ModeIndex = Index;
    ModeInfo->Length = sizeof(VIDEO_MODE_INFORMATION);
    //Subtract the below by offscreen info if necessary.
    ModeInfo->VisScreenWidth = VbeModeInfo->XResolution; 
    ModeInfo->VisScreenHeight = VbeModeInfo->YResolution;
    ModeInfo->ScreenStride = VbeModeInfo->LinBytesPerScanLine;
    ModeInfo->NumberOfPlanes = VbeModeInfo->NumberOfPlanes;
    ModeInfo->BitsPerPlane = VbeModeInfo->BitsPerPixel / VbeModeInfo->NumberOfPlanes;
    ModeInfo->Frequency = 75;

    //Populate the shared control block with the stride too.
    //VesaControlBlock.Stride = (ULONG) VbeModeInfo->LinBytesPerScanLine;
    
    //960 DPI appears to be common.
    ModeInfo->XMillimeter = VbeModeInfo->XResolution * 254 / 960;
    ModeInfo->YMillimeter = VbeModeInfo->YResolution * 254 / 960;
    ModeInfo->VideoMemoryBitmapHeight = VbeModeInfo->YResolution;
    ModeInfo->VideoMemoryBitmapWidth = VbeModeInfo->XResolution;            
    ModeInfo->AttributeFlags = 
        VIDEO_MODE_GRAPHICS | VIDEO_MODE_COLOR | VIDEO_MODE_NO_OFF_SCREEN;
    if ( VbeModeInfo->BitsPerPixel <= 8 )
        ModeInfo->AttributeFlags |= 
        VIDEO_MODE_PALETTE_DRIVEN | VIDEO_MODE_MANAGED_PALETTE; 

    if ( VbeModeInfo->MemoryModel == VBE_MEMORYMODEL_DIRECTCOLOR ) {
        ModeInfo->NumberRedBits = VbeModeInfo->LinRedMaskSize;
        ModeInfo->NumberGreenBits = VbeModeInfo->LinGreenMaskSize;
        ModeInfo->NumberBlueBits = VbeModeInfo->LinBlueMaskSize;
        ModeInfo->RedMask = 
            ((1 << VbeModeInfo->LinRedMaskSize) - 1) << VbeModeInfo->LinRedFieldPosition;
        ModeInfo->GreenMask = 
            ((1 << VbeModeInfo->GreenMaskSize) - 1) << VbeModeInfo->LinGreenFieldPosition;
        ModeInfo->BlueMask = 
            ((1 << VbeModeInfo->BlueMaskSize) - 1) << VbeModeInfo->LinBlueFieldPosition;
    }   
}

//
// XenVesaInt10Initialize
//
VP_STATUS XenVesaInt10Initialize(PXEN_VESA_DEVICE_EXTENSION_PRIVATE XenVesaExt)
{
    VP_STATUS Status;
    ULONG Length = 1024;

    XenVesaExt->Int10Interface.Size = sizeof(VIDEO_PORT_INT10_INTERFACE);
    XenVesaExt->Int10Interface.Version = VIDEO_PORT_INT10_INTERFACE_VERSION_1;
    Status = VideoPortQueryServices(XenVesaExt, VideoPortServicesInt10,
             (PINTERFACE)&XenVesaExt->Int10Interface);
    if ( Status != NO_ERROR ) {
        VideoPortDebugPrint(Error, 
            "XenVesa: Unable to query int10 interface info - 0x%08x\n",
            Status);
        return Status;
    }

    Status = XenVesaExt->Int10Interface.Int10AllocateBuffer( 
        XenVesaExt->Int10Interface.Context, &XenVesaExt->Int10MemSeg, 
        &XenVesaExt->Int10MemOffset, &Length);
    if ( Status != NO_ERROR ) {
        VideoPortDebugPrint(Error, 
            "XenVesa: Unable to allocate int10 memory - 0x%08x\n", Status);     
    }
    return Status;
}

//
// XenVesaGetVBEControllerInfo
//
VP_STATUS XenVesaGetVBEControllerInfo(PXEN_VESA_DEVICE_EXTENSION_PRIVATE XenVesaExt)
{
    VP_STATUS Status;
    INT10_BIOS_ARGUMENTS Int10BiosArg;

    Status = XenVesaExt->Int10Interface.Int10WriteMemory(
             XenVesaExt->Int10Interface.Context, XenVesaExt->Int10MemSeg, 
             XenVesaExt->Int10MemOffset, "VBE2", 4);
    if ( Status != NO_ERROR ) {
        VideoPortDebugPrint(Error, 
            "XenVesa: Int10WriteMemory failed - 0x%08x\n", Status);
        return Status;
    }

    VideoPortZeroMemory(&Int10BiosArg, sizeof(Int10BiosArg));
    Int10BiosArg.Eax = VBE_GET_CONTROLLER_INFORMATION;
    Int10BiosArg.SegEs = XenVesaExt->Int10MemSeg;
    Int10BiosArg.Edi = XenVesaExt->Int10MemOffset;    
    Status = XenVesaExt->Int10Interface.Int10CallBios(
             XenVesaExt->Int10Interface.Context, &Int10BiosArg);
    if ( Status != NO_ERROR || (Int10BiosArg.Eax & 0xffff) != VBE_SUCCESS ) {
        VideoPortDebugPrint(Error, "XenVesa: Unable to get VBE controller info\n");
        return Status;
    }

    Status = XenVesaExt->Int10Interface.Int10ReadMemory(
             XenVesaExt->Int10Interface.Context, XenVesaExt->Int10MemSeg, 
             XenVesaExt->Int10MemOffset, &XenVesaExt->Public.VbeExtInfo,
             sizeof(XenVesaExt->Public.VbeExtInfo));
    if ( Status != NO_ERROR ) {
        VideoPortDebugPrint(Error, 
            "XenVesa: Int10ReadMemory failed - 0x%08x\n", Status);
        return Status;
    }

    if ( VideoPortCompareMemory(XenVesaExt->Public.VbeExtInfo.Signature, "VESA", 4) != 4 ) {
        VideoPortDebugPrint(Error, "XenVesa: VBE extension signature incorrect\n");
        return STATUS_UNSUCCESSFUL;
    }

    return NO_ERROR;
}

//
// XenVesaGetPotentialModeCount
//
ULONG XenVesaGetPotentialModeCount(PXEN_VESA_DEVICE_EXTENSION_PRIVATE XenVesaExt)
{
    VP_STATUS Status;
    USHORT ModeNumber;
    ULONG PotentialModeCount = 0;

    while (TRUE) {
        Status = XenVesaExt->Int10Interface.Int10ReadMemory(
            XenVesaExt->Int10Interface.Context, XenVesaExt->Public.VbeExtInfo.VideoModeSeg, 
            XenVesaExt->Public.VbeExtInfo.VideoModeOffset + (USHORT)(PotentialModeCount << 1), 
            &ModeNumber, sizeof(ModeNumber));      
        if ( Status != NO_ERROR || ModeNumber == 0xffff ) {
            break;
        } else {
            PotentialModeCount++;
        }
    }
    return PotentialModeCount;
}

//
// XenVesaInitializeSuitableModeInfo
//
VP_STATUS XenVesaInitializeSuitableModeInfo(PXEN_VESA_DEVICE_EXTENSION_PRIVATE XenVesaExt, 
                                            ULONG PotentialModeCount)
{
    VP_STATUS Status;
    USHORT ModeNumber, Int10MemOffset;
    PVBE_MODE_INFO VbeModeInfo;
    ULONG Count, ModeCount = 0;
    INT10_BIOS_ARGUMENTS Int10BiosArg;

    Int10MemOffset = XenVesaExt->Int10MemOffset + 512;
    for ( Count=0; Count < PotentialModeCount; Count++ ) {
        Status = XenVesaExt->Int10Interface.Int10ReadMemory(
            XenVesaExt->Int10Interface.Context, 
            XenVesaExt->Public.VbeExtInfo.VideoModeSeg, 
            XenVesaExt->Public.VbeExtInfo.VideoModeOffset + (USHORT)(Count << 1), 
            &ModeNumber, sizeof(ModeNumber));
        if ( Status != NO_ERROR ) {
            VideoPortDebugPrint(Error, 
                "XenVesa: Int10ReadMemory failed - 0x%08x\n", Status);
            return Status;
        }

        VideoPortZeroMemory(&Int10BiosArg, sizeof(Int10BiosArg));
        Int10BiosArg.Eax = VBE_GET_MODE_INFORMATION;
        Int10BiosArg.Ecx = ModeNumber;
        Int10BiosArg.SegEs = XenVesaExt->Int10MemSeg;
        Int10BiosArg.Edi = Int10MemOffset;
        Status = XenVesaExt->Int10Interface.Int10CallBios(
                 XenVesaExt->Int10Interface.Context, &Int10BiosArg);
        if ( Status != NO_ERROR || (Int10BiosArg.Eax & 0xffff) != VBE_SUCCESS ) {
            VideoPortDebugPrint(Error, "XenVesa: In10CallBios failed\n");           
            return Status;
        }

        Status = XenVesaExt->Int10Interface.Int10ReadMemory(
                 XenVesaExt->Int10Interface.Context, XenVesaExt->Int10MemSeg, 
                 Int10MemOffset, XenVesaExt->Public.VbeModeInfo + ModeCount, 
                 sizeof(VBE_MODE_INFO));
        if ( Status != NO_ERROR ) {
            VideoPortDebugPrint(Error, "Int10ReadMemory failed - 0x%08x\n", Status);
            return Status;
        }

        VbeModeInfo = XenVesaExt->Public.VbeModeInfo + ModeCount;
        if ((Int10BiosArg.Eax & 0xffff) == VBE_SUCCESS && 
            VbeModeInfo->XResolution >= 640 &&
            VbeModeInfo->YResolution >= 480 &&
            (VbeModeInfo->MemoryModel == VBE_MEMORYMODEL_PACKEDPIXEL ||
            VbeModeInfo->MemoryModel == VBE_MEMORYMODEL_DIRECTCOLOR)) {
            
            if (VbeModeInfo->ModeAttributes & VBE_MODEATTR_LINEAR) {
                XenVesaExt->Public.VbeModeNumbers[ModeCount] = ModeNumber | 0x4000;
                ModeCount++;
            } else {
                XenVesaExt->Public.VbeModeNumbers[ModeCount] = ModeNumber;
                ModeCount++;
            }
        }
    }

    if ( ModeCount == 0 ) {
        VideoPortDebugPrint(Error, "No suitable modes available!\n");
        return STATUS_UNSUCCESSFUL;
    }

    XenVesaExt->Public.VbeModeCount = ModeCount;
    return NO_ERROR;
}

//
// XenVesaFreeResources
//
void XenVesaFreeResources(PXEN_VESA_DEVICE_EXTENSION_PRIVATE XenVesaExt)
{
    if ( XenVesaExt->Public.VbeModeInfo != NULL ) {
        VideoPortFreePool(XenVesaExt, XenVesaExt->Public.VbeModeInfo);
        XenVesaExt->Public.VbeModeInfo = NULL;
    }

    if ( XenVesaExt->Public.VbeModeNumbers != NULL ) {
        VideoPortFreePool(XenVesaExt, XenVesaExt->Public.VbeModeNumbers);
        XenVesaExt->Public.VbeModeNumbers = NULL;
    }

    XenVesaExt->Int10Interface.Int10FreeBuffer( XenVesaExt->Int10Interface.Context,
            XenVesaExt->Int10MemSeg, XenVesaExt->Int10MemOffset);
}


NTSTATUS
XenVideoPortSetRegistryParameters(PXEN_VESA_DEVICE_EXTENSION PublicExt, PWSTR DefaultSetting, 
                                  PVOID Value, ULONG Size)
{
	return VideoPortSetRegistryParameters(PublicExt->Private, DefaultSetting, Value, Size);
}
