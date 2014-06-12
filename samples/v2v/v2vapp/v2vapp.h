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

#if !defined(_V2VAPP_H_)
#define _V2VAPP_H_

#include "v2v_common.h"
#include "v2v_ioctl.h"

/* V2V App */
typedef struct _V2V_APP_CONFIG {
    V2V_MODE_TYPE mode;
    V2V_ROLE_TYPE role;
    BOOL async;
    BOOL fastrx;
    char *localPrefix;  /* XenStore local path prefix */

    V2V_XFER_TYPE xfer;
    ULONG xferSize;
    char *xferFilePath;
    ULONG xferCount;
    ULONG xferTimeout;
    ULONG xferMaxFastRx;
} V2V_APP_CONFIG, *PV2V_APP_CONFIG;

void V2vRunUserMode(V2V_APP_CONFIG *vac);

void V2vRunKernelMode(V2V_APP_CONFIG *vac);

/* Driver/Device Control */
ULONG V2vDcInstallDriver(const wchar_t *driverName, const wchar_t *serviceExe, BOOL systemStart);
ULONG V2vDcStartDriver(const wchar_t *driverName);
ULONG V2vDcOpenDeviceFile(const wchar_t *fileName, HANDLE *deviceOut);
ULONG V2vDcStopDriver(const wchar_t *driverName);
ULONG V2vDcRemoveDriver(const wchar_t *driverName);

/* User Mode Utilities */
extern OSVERSIONINFOEXW g_osvi;

BOOL V2vAppGetOsVersionInfo();

#endif /*_V2VAPP_H_*/
