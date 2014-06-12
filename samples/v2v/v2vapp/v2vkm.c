/*
 * Copyright (c) 2009 Citrix Systems, Inc.
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

#include <windows.h>
#pragma warning(push)
#pragma warning(disable: 4201)
#include <winioctl.h>
#pragma warning(pop)
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include <rpc.h>
#include "v2vapp.h"

void
V2vRunKernelMode(V2V_APP_CONFIG *vac)
{
    ULONG error, br;
	BOOL rc;
    HANDLE hcd;
    ULONG flags = 0;
    const wchar_t *v2vfile;

    /* TODO enhancements:
       - console input control
       - like local shutdown of connector/listner at any point
       - keep app running and start another round.
       - allow kernel mode v2v to run in work item detached from ioctl
    */    

    if (vac->role == RoleTypeConnector) {
        v2vfile = (vac->xfer == XferTypeInternal) ? \
            V2V_CONNECTOR_INTERNAL_NAME : V2V_CONNECTOR_FILE_NAME;
    }
    else {
        v2vfile = (vac->xfer == XferTypeInternal) ? \
            V2V_LISTENER_INTERNAL_NAME : V2V_LISTENER_FILE_NAME;
    }

    printf("V2VAPP-KM starting kernel for: %S\n", v2vfile);
  
    error = V2vDcOpenDeviceFile(v2vfile, &hcd);
    if (error != ERROR_SUCCESS) {
        printf("V2VAPP-KM failed to open v2v file %S; aborting - error: 0x%x\n", v2vfile, error);
        return;
    }

    if (vac->async)
        flags |= V2V_KERNEL_ASYNC;
    if (vac->fastrx)
        flags |= V2V_KERNEL_FASTRX;

    do {
        /* Initialize the connector for the given xfer type */
        if (vac->xfer == XferTypeInternal) {
            V2VK_IOCD_INIT_INTERNAL_XFER iixfer;
            strncpy(iixfer.localPrefix, vac->localPrefix, V2V_MAX_IOCTL_STRING - 1);
            iixfer.localPrefix[V2V_MAX_IOCTL_STRING - 1] = '\0';
            iixfer.flags = flags;
            iixfer.xferTimeout = vac->xferTimeout;
            iixfer.xferSize = vac->xferSize;
            iixfer.xferCount = vac->xferCount;
            iixfer.xferMaxFastRx = vac->xferMaxFastRx;
            rc = DeviceIoControl(hcd, V2VK_IOCTL_INIT_INTERNAL_XFER, &iixfer, sizeof(iixfer), NULL, 0, &br, NULL);
        }
        else {
            V2VK_IOCD_INIT_FILE_XFER ifxfer;
            strncpy(ifxfer.localPrefix, vac->localPrefix, V2V_MAX_IOCTL_STRING - 1);
            ifxfer.localPrefix[V2V_MAX_IOCTL_STRING - 1] = '\0';
            strncpy(ifxfer.filePath, vac->xferFilePath, V2V_MAX_IOCTL_STRING - 1);
            ifxfer.filePath[V2V_MAX_IOCTL_STRING - 1] = '\0';
            ifxfer.flags = flags;
            ifxfer.xferTimeout = vac->xferTimeout;
            ifxfer.xferSize = vac->xferSize;
            ifxfer.xferMaxFastRx = vac->xferMaxFastRx;
            rc = DeviceIoControl(hcd, V2VK_IOCTL_INIT_FILE_XFER, &ifxfer, sizeof(ifxfer), NULL, 0, &br, NULL);
        }
        if (!rc) {
			error = GetLastError();
            printf("V2VAPP-KM failed to initialize v2v device %S; aborting - error: 0x%x\n", v2vfile, error);
            break;
        }
        
        /* At this point, the v2v device is initialized and ready to run. This IOCTL will not return until the
           message processing is done and the v2v device is disconnected */
        if (vac->role == RoleTypeConnector)
            rc = DeviceIoControl(hcd, V2VK_IOCTL_RUN_CONNECTOR, NULL, 0, NULL, 0, &br, NULL);
        else
            rc = DeviceIoControl(hcd, V2VK_IOCTL_RUN_LISTENER, NULL, 0, NULL, 0, &br, NULL);

		if (!rc)		
            printf("V2VAPP-KM failure during process messages for v2v device %S; aborting - error: 0x%x\n",
				   v2vfile, GetLastError());
            
    } while (FALSE);

    
    CloseHandle(hcd);
}
