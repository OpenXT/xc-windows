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
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include <rpc.h>
#include "v2vapp.h"
#include "xs2.h"

#define V2V_CONFIG_BUFFER_SIZE 1024

static void
V2vFreeConfigSettings(V2V_APP_CONFIG *vac)
{
    if (vac->localPrefix != NULL)
        free(vac->localPrefix);
    if (vac->xferFilePath != NULL)
        free(vac->xferFilePath);
    free(vac);
}

static ULONG
V2vLoadConfigSettings(const char *configFile, V2V_APP_CONFIG *vac)
{
    ULONG error = 0;
    DWORD count;
    char *buf;

    buf = (char*)malloc(V2V_CONFIG_BUFFER_SIZE);
    if (buf == NULL) {
        printf("V2VAPP out of memory\n");
        return ERROR_OUTOFMEMORY;
    }
    
    do {
        count =        
            GetPrivateProfileStringA("V2V_Base", "Mode", "User", buf, V2V_CONFIG_BUFFER_SIZE, configFile);
        if ((count == 6)&&(_strnicmp(buf, "Kernel", 6) == 0))
            vac->mode = ModeTypeKernel;
        else
            vac->mode = ModeTypeUser;

        count =        
            GetPrivateProfileStringA("V2V_Base", "Role", "Listener", buf, V2V_CONFIG_BUFFER_SIZE, configFile);
        if ((count == 9)&&(_strnicmp(buf, "Connector", 9) == 0))
            vac->role = RoleTypeConnector;
        else
            vac->role = RoleTypeListener;

        count =        
            GetPrivateProfileStringA("V2V_Base", "Async", "False", buf, V2V_CONFIG_BUFFER_SIZE, configFile);
        if ((count == 4)&&(_strnicmp(buf, "True", 4) == 0))
            vac->async = TRUE;
        else
            vac->async = FALSE;
        if ((vac->async)&&(vac->mode != ModeTypeKernel)) {
            printf("V2VAPP No aynchronous transfer available for user mode V2V.\n");
            error = ERROR_GEN_FAILURE;
            break;
        }

        count =        
            GetPrivateProfileStringA("V2V_Base", "FastRx", "False", buf, V2V_CONFIG_BUFFER_SIZE, configFile);
        if ((count == 4)&&(_strnicmp(buf, "True", 4) == 0))
            vac->fastrx = TRUE;
        else
            vac->fastrx = FALSE;       

        count =        
            GetPrivateProfileStringA("V2V_Base", "LocalPrefix", NULL, buf, V2V_CONFIG_BUFFER_SIZE, configFile);
        if (count == 0) {
            printf("V2VAPP No LocalPrefix specified in the configuration.\n");
            error = ERROR_NO_DATA;
            break;
        }
        vac->localPrefix = (char*)malloc(count + 1);
        if (vac->localPrefix == NULL) {
            printf("V2VAPP out of memory\n");
            error = ERROR_OUTOFMEMORY;
            break;
        }
        strncpy(vac->localPrefix, buf, count);
        vac->localPrefix[count] = '\0';

        count =        
            GetPrivateProfileStringA("V2V_Data", "Transfer", "Internal", buf, V2V_CONFIG_BUFFER_SIZE, configFile);
        if ((count == 4)||(_strnicmp(buf, "File", 4) == 0))
            vac->xfer = XferTypeFile;
        else
            vac->xfer = XferTypeInternal;

        count =        
            GetPrivateProfileStringA("V2V_Data", "TransferSize", NULL, buf, V2V_CONFIG_BUFFER_SIZE, configFile);
        vac->xferSize = strtol(buf, NULL, 10);

        if ((count == 0)||(vac->xferSize == 0)) {
            printf("V2VAPP No transer size specified; idle test - no data will be sent.\n");
            vac->xferSize = 0;           
        }

        count =        
            GetPrivateProfileStringA("V2V_Data", "TransferMaxFastRx", "1024", buf, V2V_CONFIG_BUFFER_SIZE, configFile);
        vac->xferMaxFastRx = strtol(buf, NULL, 10);

        count =
            GetPrivateProfileStringA("V2V_Data", "TransferTimeout", "2000", buf, V2V_CONFIG_BUFFER_SIZE, configFile);
        vac->xferTimeout = strtol(buf, NULL, 10);
        if ((count == 0)||(vac->xferTimeout == 0)) {
            printf("V2VAPP No transer timeout set; using default %d ms.\n", V2V_RESPONSE_WAIT_TIMEOUT);
            vac->xferTimeout = V2V_RESPONSE_WAIT_TIMEOUT;
        }

        if (vac->xfer == XferTypeFile) {
             count =
                GetPrivateProfileStringA("V2V_Data", "TransferFile", NULL, buf, V2V_CONFIG_BUFFER_SIZE, configFile);
            if (count == 0) {
                printf("V2VAPP No file entry for file transfer specified in the configuration.\n");
                error = ERROR_NO_DATA;
                break;
            }
            vac->xferFilePath = (char*)malloc(count + 1);
            if (vac->xferFilePath == NULL) {
                printf("V2VAPP out of memory\n");
                error = ERROR_OUTOFMEMORY;
                break;
            }
            strncpy(vac->xferFilePath, buf, count);
            vac->xferFilePath[count] = '\0';            
        }
        else if (vac->role == RoleTypeConnector) { /* and xfer is internal */
            count =
                GetPrivateProfileStringA("V2V_Data", "TransferCount", NULL, buf, V2V_CONFIG_BUFFER_SIZE, configFile);
            vac->xferCount = strtol(buf, NULL, 10);
            if ((count == 0)||(vac->xferCount == 0)) {
                printf("V2VAPP No transer count internal transfer specified; connect test - no data will be sent.\n");
                vac->xferCount = 0;           
            }
        }

    } while (FALSE);

    free(buf);

    return error;
}

static ULONG
V2vXenstoreCheck(V2V_APP_CONFIG *vac)
{
#define V2V_EXTRA_BUF 128
    ULONG error = ERROR_SUCCESS;
    struct xs2_handle *xs2 = NULL;
    char *path = NULL;
    char *remote = NULL;
    char *peer = NULL;

    do {
        xs2 = xs2_open();
        if (!xs2) {
            printf("V2VAPP failed to open xenstore - error: 0x%x\n", GetLastError());
            error = ERROR_GEN_FAILURE;
            break;
        }

        path = (char*)malloc(strlen(vac->localPrefix) + V2V_EXTRA_BUF);
        if (!path) {
            printf("V2VAPP out of memory\n");
            error = ERROR_OUTOFMEMORY;
            break;
        }
        strcpy(path, vac->localPrefix);
        strcat(path, "/backend");
        remote = (char*)xs2_read(xs2, path, NULL);
        if ((!remote)||(strlen(remote) == 0)) {
            printf("V2VAPP could not find backend prefix in xenstore - error: 0x%x\n", GetLastError());
            error = ERROR_GEN_FAILURE;
            break;
        }

        strcpy(path, vac->localPrefix);
        strcat(path, "/peer-domid");
        peer = (char*)xs2_read(xs2, path, NULL);
        if ((!peer)||(strlen(peer) == 0)) {
            printf("V2VAPP could not find peer domain id in xenstore - error: 0x%x\n", GetLastError());
            error = ERROR_GEN_FAILURE;
            break;
        }
        printf("V2VAPP xenstore values - backend: %s  peer-domid: %s\n", remote, peer);
    } while (0);
    
    if (peer)
        xs2_free(peer);
    if (remote)
        xs2_free(remote);
    if (path)
        free(path);
    if (xs2)
        xs2_close(xs2);

    return error;
}

static void
V2vRun(const char *configFile)
{
    ULONG error;
    V2V_APP_CONFIG *vac = NULL;

    do {
        vac = (V2V_APP_CONFIG*)malloc(sizeof(V2V_APP_CONFIG));
        if (vac == NULL) {
            printf("V2VAPP out of memory\n");
            break;
        }
        memset(vac, 0, sizeof(V2V_APP_CONFIG));

        error = V2vLoadConfigSettings(configFile, vac);
        if (error != ERROR_SUCCESS) {
            printf("V2VAPP failed to load the configuration, file: %s error: 0x%x\n", configFile, error);
            break;
        }

        printf("V2VAPP Configuration:\n");
        printf("       Mode: %s\n", (vac->mode == ModeTypeUser) ? "User" : "Kernel");
        printf("       Role: %s\n", (vac->role == RoleTypeConnector) ? "Connector" : "Listener");
        printf("       LocalPrefix: %s\n", vac->localPrefix);        
        printf("       Transfer: %s\n", (vac->xfer == XferTypeInternal) ? "Internal" : "File");
        printf("       TransferSize: 0x%x\n", vac->xferSize);
        if (vac->xfer == XferTypeInternal)
            printf("       TransferCount: 0x%x\n", vac->xferCount);
        else
            printf("       TransferFile: %s\n", vac->xferFilePath);

        error = V2vXenstoreCheck(vac);
        if (error != ERROR_SUCCESS) {
            printf("V2VAPP xenstore check failed - xenstore must be setup first - exiting\n");
            break;
        }

        if (vac->mode == ModeTypeUser)
            V2vRunUserMode(vac);
        else
            V2vRunKernelMode(vac);
    } while (FALSE);

    if (vac != NULL)
        V2vFreeConfigSettings(vac);
}

static void
V2vAppUsage()
{
    printf("\nUSAGE: V2VAPP...\n");
    printf(" -install     Installs the driver\n");
    printf(" -remove      Uninstalls the driver\n");
    printf(" -start       Starts the driver service\n");
    printf(" -stop        Stops the driver service\n");
    printf(" -run <file>  Run the V2V sample app with the given config file\n");
}

int __cdecl
main(int argc, char* argv[])
{
	ULONG error;
	
	V2vAppGetOsVersionInfo();
	printf("V2VAPP Running on Windows Version %d.%d\n", g_osvi.dwMajorVersion, g_osvi.dwMinorVersion);

	if ((argc == 2)&&((_stricmp(argv[1], "-install") == 0)||
		              (_stricmp(argv[1], "/install") == 0))) {
        error = V2vDcInstallDriver(V2V_DRIVER_NAME, V2V_SYS_FILENAME, FALSE);
		if (error != ERROR_SUCCESS) {
			printf("V2VAPP: Failed to install driver! - Error: %x\n", error);
			return -1;
		}
		printf("V2VAPP: Installed driver.\n");
	}
	else if ((argc == 2)&&((_stricmp(argv[1], "-remove") == 0)||
		                   (_stricmp(argv[1], "/remove") == 0))) {
        error = V2vDcRemoveDriver(V2V_DRIVER_NAME);
		if (error != ERROR_SUCCESS) {
			printf("V2VAPP: Failed to remove driver! - Error: %x\n", error);
			return -1;
		}
		printf("V2VAPP: Removed driver.\n");
	}
	else if ((argc == 2)&&((_stricmp(argv[1], "-start") == 0)||
		                   (_stricmp(argv[1], "/start") == 0))) {
        error = V2vDcStartDriver(V2V_DRIVER_NAME);
		if (error != ERROR_SUCCESS) {
			printf("V2VAPP: Failed to start driver! - Error: %x\n", error);
			return -1;
		}
		printf("V2VAPP: Stared driver.\n");	
	}
	else if ((argc == 2)&&((_stricmp(argv[1], "-stop") == 0)||
		                   (_stricmp(argv[1], "/stop") == 0))) {
		error = V2vDcStopDriver(V2V_DRIVER_NAME);
		if (error != ERROR_SUCCESS) {
			printf("V2VAPP: Failed to stop driver! - Error: %x\n", error);
			return -1;
		}
		printf("V2VAPP: Stopped driver.\n");
	}
    else if ((argc == 3)&&((_stricmp(argv[1], "-run") == 0)||
		                   (_stricmp(argv[1], "/run") == 0))) {
		V2vRun(argv[2]);
	}
	else {
		V2vAppUsage();
	}
	
	return 0;
}
