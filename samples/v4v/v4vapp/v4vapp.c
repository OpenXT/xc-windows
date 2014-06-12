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

#include <windows.h>
#pragma warning(push)
#pragma warning(disable: 4201)
#include <winioctl.h>
#pragma warning(pop)
#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include <sys/stat.h>
#include "v4v_common.h"
#include "v4v_ioctl.h"
#include "v4vapi.h"
#include "v4vapp.h"

static OSVERSIONINFOEXW g_osvi = {0};

static ULONG
V4vLoadConfigSettings(const char *configFile, V4V_CONFIG *cfg)
{
#define V4V_CONFIG_BUFFER_SIZE 1024
    ULONG error = 0;
    DWORD count;
    char *buf;

    buf = (char*)malloc(V4V_CONFIG_BUFFER_SIZE);
    if (buf == NULL) {
        printf("V4VAPP out of memory\n");
        return ERROR_OUTOFMEMORY;
    }
    
    do {
        count =
            GetPrivateProfileStringA("V4V_Base", "Role", "NONE", buf, V4V_CONFIG_BUFFER_SIZE, configFile);
        if ((count == 9)&&(_strnicmp(buf, "Connector", 9) == 0))
            cfg->role = RoleTypeConnector;
        else if ((count == 8)&&(_strnicmp(buf, "Listener", 8) == 0))
            cfg->role = RoleTypeListener;
        else if ((count == 6)&&(_strnicmp(buf, "Sender", 6) == 0))
            cfg->role = RoleTypeSender;
        else if ((count == 8)&&(_strnicmp(buf, "Receiver", 8) == 0))
            cfg->role = RoleTypeReceiver;
        else
            cfg->role = RoleTypeNone;

        count =
            GetPrivateProfileStringA("V4V_Base", "Protocol", "Datagram", buf, V4V_CONFIG_BUFFER_SIZE, configFile);
        if ((count == 6)&&(_strnicmp(buf, "Stream", 6) == 0))
            cfg->protocol = V4V_PROTO_STREAM;
        else
            cfg->protocol = V4V_PROTO_DGRAM;

        if ((cfg->protocol == V4V_PROTO_STREAM)&&(cfg->role == RoleTypeNone)) {
            printf("V4VAPP Stream protocol must have a role of Connector or Listener.\n");
            error = ERROR_NO_DATA;
            break;
        }

        count =        
            GetPrivateProfileStringA("V4V_Base", "Async", "False", buf, V4V_CONFIG_BUFFER_SIZE, configFile);
        if ((count == 4)&&(_strnicmp(buf, "True", 4) == 0))
            cfg->async = TRUE;
        else
            cfg->async = FALSE;

        count =        
            GetPrivateProfileStringA("V4V_Base", "ConnectOnly", "False", buf, V4V_CONFIG_BUFFER_SIZE, configFile);
        if ((count == 4)&&(_strnicmp(buf, "True", 4) == 0))
            cfg->connectOnly = TRUE;
        else
            cfg->connectOnly = FALSE;

        count =
            GetPrivateProfileStringA("V4V_Base", "PeerId", "NONE", buf, V4V_CONFIG_BUFFER_SIZE, configFile);
        if ((count == 4)&&(_strnicmp(buf, "NONE", 4) == 0))
            cfg->dst.domain = V4V_DOMID_NONE;
        else
            cfg->dst.domain = (domid_t)strtol(buf, NULL, 10);

        count =
            GetPrivateProfileStringA("V4V_Base", "RemotePort", "NONE", buf, V4V_CONFIG_BUFFER_SIZE, configFile);
        if ((count == 4)&&(_strnicmp(buf, "NONE", 4) == 0))
            cfg->dst.port = V4V_PORT_NONE;
        else
            cfg->dst.port = (ULONG)strtol(buf, NULL, 10);

        cfg->src.domain = V4V_DOMID_NONE;
        count =
            GetPrivateProfileStringA("V4V_Base", "LocalPort", "NONE", buf, V4V_CONFIG_BUFFER_SIZE, configFile);
        if ((count == 4)&&(_strnicmp(buf, "NONE", 4) == 0))
            cfg->src.port = V4V_PORT_NONE;
        else
            cfg->src.port = (ULONG)strtol(buf, NULL, 10);

        count =        
            GetPrivateProfileStringA("V4V_Base", "RingSize", NULL, buf, V4V_CONFIG_BUFFER_SIZE, configFile);
        cfg->ringSize = strtol(buf, NULL, 10);

        if ((count == 0)||(cfg->ringSize == 0)) {
            printf("V4VAPP No ring size specified; defaulting to %d bytes.\n", V4V_DEFAULT_RING_SIZE);
            cfg->ringSize = V4V_DEFAULT_RING_SIZE;     
        }

        count =        
            GetPrivateProfileStringA("V4V_Data", "Transfer", "Internal", buf, V4V_CONFIG_BUFFER_SIZE, configFile);
        if ((count == 4)||(_strnicmp(buf, "File", 4) == 0))
            cfg->xfer = XferTypeFile;
        else
            cfg->xfer = XferTypeInternal;

        count =
            GetPrivateProfileStringA("V4V_Data", "TransferTimeout", "2000", buf, V4V_CONFIG_BUFFER_SIZE, configFile);
        cfg->xferTimeout = strtol(buf, NULL, 10);
        if ((count == 0)||(cfg->xferTimeout == 0)) {
            printf("V4VAPP No transer timeout set; using default %d ms.\n", V4V_TRANSFER_TIMEOUT);
            cfg->xferTimeout = V4V_TRANSFER_TIMEOUT;
        }

        count =
            GetPrivateProfileStringA("V4V_Data", "TransmitSize", "512", buf, V4V_CONFIG_BUFFER_SIZE, configFile);
        cfg->txSize = strtol(buf, NULL, 10);
        if ((count == 0)||(cfg->txSize == 0)) {
            printf("V4VAPP No transmit buffer size set, using 512b default.\n");
            cfg->txSize = V4V_DEFAULT_BUFFER_SIZE;
        }

        count =
            GetPrivateProfileStringA("V4V_Data", "ReceiveSize", "512", buf, V4V_CONFIG_BUFFER_SIZE, configFile);
        cfg->rxSize = strtol(buf, NULL, 10);
        if ((count == 0)||(cfg->rxSize == 0)) {
            printf("V4VAPP No receive buffer size set or too small, using 512b default.\n");
            cfg->rxSize = V4V_DEFAULT_BUFFER_SIZE;
        }

        if (cfg->xfer == XferTypeFile) {
             count =
                GetPrivateProfileStringA("V4V_Data", "TransferFile", NULL, cfg->xferFilePath, _MAX_PATH, configFile);
            if (count == 0) {
                printf("V4VAPP No file entry for file transfer specified in the configuration.\n");
                error = ERROR_NO_DATA;
                break;
            }
            cfg->xferFilePath[_MAX_PATH] = '\0';       
        }
    } while (FALSE);

    free(buf);

    return error;
}

void
V4vRunTest(const char *configFile)
{
    ULONG error;
    V4V_CONFIG *cfg = NULL;

    do {
        cfg = (V4V_CONFIG*)malloc(sizeof(V4V_CONFIG));
        if (cfg == NULL) {
            printf("V4VAPP out of memory\n");
            break;
        }
        memset(cfg, 0, sizeof(V4V_CONFIG));

        error = V4vLoadConfigSettings(configFile, cfg);
        if (error != ERROR_SUCCESS) {
            printf("V4VAPP failed to load the configuration, file: %s error: %d\n", configFile, error);
            break;
        }

        cfg->heap = HeapCreate(0, cfg->txSize + cfg->rxSize, 2*(cfg->txSize + cfg->rxSize));
        if (cfg->heap == NULL) {
            printf("V4VAPP HeapCreate() - error: %d\n", GetLastError());
            break;
        }

        cfg->txBuf = (UCHAR*)HeapAlloc(cfg->heap, HEAP_ZERO_MEMORY, cfg->txSize);
        if (cfg->txBuf == NULL) {
            printf("V4VAPP VirtualAlloc() - error: %d\n", GetLastError());
            break;
        }

        cfg->rxBuf = (UCHAR*)HeapAlloc(cfg->heap, HEAP_ZERO_MEMORY, cfg->rxSize);
        if (cfg->rxBuf == NULL) {
            printf("V4VAPP VirtualAlloc() - error: %d\n", GetLastError());
            break;
        }

        cfg->shutdownEvent1 = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (cfg->shutdownEvent1 == NULL) {
            printf("V4VAPP failed to create shutdown event error: %d\n", GetLastError());
            break;
        }

        cfg->shutdownEvent2 = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (cfg->shutdownEvent2 == NULL) {
            printf("V4VAPP failed to create shutdown event error: %d\n", GetLastError());
            break;
        }

        cfg->k32 = LoadLibraryA("kernel32.dll");
        if (cfg->k32 != NULL) {
            cfg->CancelSynchronousIoFn = (CancelSynchronousIo_t)GetProcAddress(cfg->k32, "CancelSynchronousIo");
            if (cfg->CancelSynchronousIoFn == NULL) {
                printf("V4VAPP could not locate CancelSynchronousIo, error: %d\n", GetLastError());
            }
            cfg->CancelIoExFn = (CancelIoEx_t)GetProcAddress(cfg->k32, "CancelIoEx");
            if (cfg->CancelIoExFn == NULL) {
                printf("V4VAPP could not locate CancelIoEx, error: %d\n", GetLastError());
            }
        }
        else {
            printf("V4VAPP could not load kernel32.dll???? error: %d\n", GetLastError());       
        }

        printf("V4VAPP Configuration:\n");
        printf("       Role: %d\n", cfg->role);
        printf("       Protocol: %d\n", cfg->protocol);
        printf("       PeerId: %d\n", cfg->dst.domain);
        printf("       RemotePort: %d\n", cfg->dst.port);
        printf("       LocalPort: %d\n", cfg->src.port);
        printf("       RingSize: %d\n", cfg->ringSize);
        printf("       Transfer: %d\n", cfg->xfer);
        printf("       TransmitBuffer Address: %p Size: 0x%x\n", cfg->txBuf, cfg->txSize);
        printf("       ReceiveBuffer  Address: %p Size: 0x%x\n", cfg->rxBuf, cfg->rxSize);      
        if (cfg->xfer == XferTypeFile)            
            printf("       TransferFile: %s\n", cfg->xferFilePath);
        printf("       CancelSynchronousIo: %p\n", cfg->CancelSynchronousIoFn);
        printf("       CancelIoEx: %p\n", cfg->CancelIoExFn);

        if (cfg->protocol == V4V_PROTO_DGRAM) {
            if (cfg->xfer == XferTypeFile)
                V4vStartDatagramFile(cfg);
            else
                V4vStartDatagram(cfg);
        }
        else {
            if (cfg->role == RoleTypeConnector)
                V4vStartConnector(cfg);
            else if (cfg->role == RoleTypeListener)
                V4vStartListener(cfg);
        }
       
    } while (FALSE);

    if (cfg != NULL) {
        if (cfg->k32 != NULL)
            FreeLibrary(cfg->k32);
        if (cfg->rxBuf != NULL)
            HeapFree(cfg->heap, 0, cfg->rxBuf);
        if (cfg->txBuf != NULL)
            HeapFree(cfg->heap, 0, cfg->txBuf);
        if (cfg->heap != NULL)
            HeapDestroy(cfg->heap);
        if (cfg->shutdownEvent2 != NULL)
            CloseHandle(cfg->shutdownEvent2);
        if (cfg->shutdownEvent1 != NULL)
            CloseHandle(cfg->shutdownEvent1);
        free(cfg);
    }
}

static ULONG
V4vAppStartDriverTest(USHORT partner)
{
    ULONG error, br;
    BOOL rc;
    HANDLE hdev = NULL;
    char buf[256];
    V4VD_IOCD_START_DRIVER_TEST iocd;

    iocd.partnerDomain = partner;

    error = V4vDcOpenDeviceFile(V4VD_FILE_NAME, &hdev);
    if (error != ERROR_SUCCESS) {
        printf("V4VAPP failed to open v4v file %S; aborting - error: %d\n", V4VD_SYS_FILENAME, error);
        return error;
    }

    rc = DeviceIoControl(hdev, V4VD_IOCTL_START_DRIVER_TEST, &iocd, sizeof(V4VD_IOCD_START_DRIVER_TEST), NULL, 0, &br, NULL);
    if (!rc) {
		error = GetLastError();
        printf("V4VAPP failed to start v4v driver test; aborting - error: %d\n", error);
        CloseHandle(hdev);
        return error;
    }

    printf("V4VAPP started driver test...\n");
    printf("type \"q\" to quit.\n");

    while (TRUE) {
        scanf("%s", buf);
        if (_stricmp(buf, "q") == 0)
            break;
    }

    rc = DeviceIoControl(hdev, V4VD_IOCTL_STOP_DRIVER_TEST, NULL, 0, NULL, 0, &br, NULL);
    if (!rc) {
		error = GetLastError();
        printf("V4VAPP failed to stop v4v simple test - error: %d\n", error);
    }
    else {
        printf("V4VAPP stopped simple test...\n");
    }

    CloseHandle(hdev);

    return error;
}

static BOOL
V4vAppGetOsVersionInfo(void)
{
	BOOL success;

	g_osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	success = GetVersionEx((OSVERSIONINFO*)&g_osvi);
	if (!success) {
		return FALSE;
	}
	return TRUE;
}

static void
V4vAppUsage()
{
    printf("\nUSAGE: V4VAPP...\n");
    printf(" -in  Installs the driver\n");
    printf(" -rm  Uninstalls the driver\n");
    printf(" -ld  Starts the driver service\n");
    printf(" -ud  Stops the driver service\n");
    printf(" -dt <partner>  Start the V4V driver test with the partner domain\n");
    printf(" -ct <domain>  Do the simple cancel IO test in the current domain\n");
    printf(" -la <partner> <port> Do the simple listen with immediate accept test\n");
    printf(" -dg <partner> <sport> <dport>  Run the simple V4V datagram test with the partner\n");
    printf(" -ml <partner> <sport> <dport>  Run the mock V4V listener test\n");
    printf(" -cm <partner> <sport> <dport>  Run the simple V4V char input connector test\n");
    printf(" -rx <partner> <sport>  Run the char receiver datagram V4V test\n");
    printf(" -tx <partner> <dport>  Run the char sender datagram V4V test\n");
    printf(" -cc <partner> <port> <conn=1|0>  Run the connector-connector char sender test\n");
    printf(" -ca <partner> <port> <conn=1|0>  Run the connector-accepter char sender test\n");
    printf(" -rt <file>  Run the V4V sample app with the given config file\n");
}

int __cdecl
main(int argc, char* argv[])
{
    ULONG error;
	
    V4vAppGetOsVersionInfo();
    printf("V4VAPP Running on Windows Version %d.%d\n", g_osvi.dwMajorVersion, g_osvi.dwMinorVersion);

    if ((argc == 2)&&((_stricmp(argv[1], "-in") == 0)||
                      (_stricmp(argv[1], "/i") == 0))) {
        error = V4vDcInstallDriver(V4VD_DRIVER_NAME, V4V_SYS_FILENAME, FALSE);
        if (error != ERROR_SUCCESS) {
            printf("V4VAPP: Failed to install driver! - Error: %x\n", error);
            return -1;
        }
        printf("V4VAPP: Installed driver.\n");
	}
    else if ((argc == 2)&&((_stricmp(argv[1], "-rm") == 0)||
                           (_stricmp(argv[1], "/rm") == 0))) {
        error = V4vDcRemoveDriver(V4VD_DRIVER_NAME);
        if (error != ERROR_SUCCESS) {
            printf("V4VAPP: Failed to remove driver! - Error: %x\n", error);
            return -1;
        }
        printf("V4VAPP: Removed driver.\n");
    }
    else if ((argc == 2)&&((_stricmp(argv[1], "-ld") == 0)||
                           (_stricmp(argv[1], "/ld") == 0))) {
        error = V4vDcStartDriver(V4VD_DRIVER_NAME);
        if (error != ERROR_SUCCESS) {
            printf("V4VAPP: Failed to start driver! - Error: %x\n", error);
            return -1;
        }
        printf("V4VAPP: Stared driver.\n");	
    }
    else if ((argc == 2)&&((_stricmp(argv[1], "-ud") == 0)||
                           (_stricmp(argv[1], "/ud") == 0))) {
        error = V4vDcStopDriver(V4VD_DRIVER_NAME);
        if (error != ERROR_SUCCESS) {
            printf("V4VAPP: Failed to stop driver! - Error: %x\n", error);
            return -1;
        }
        printf("V4VAPP: Stopped driver.\n");
    }
    else if ((argc == 3)&&((_stricmp(argv[1], "-dt") == 0)||
                           (_stricmp(argv[1], "/dt") == 0))) {
        error = V4vAppStartDriverTest((USHORT)strtol(argv[2], NULL, 10));
        if (error != ERROR_SUCCESS) {
            printf("V4VAPP: Failed to start driver test! - Error: %x\n", error);
            return -1;
        }
        printf("V4VAPP: Stared driver test.\n");	
    }
    else if ((argc == 3)&&((_stricmp(argv[1], "-ct") == 0)||
                           (_stricmp(argv[1], "/ct") == 0))) {
        V4vCancelTest((USHORT)strtol(argv[2], NULL, 10));
    }
    else if ((argc == 4)&&((_stricmp(argv[1], "-la") == 0)||
                           (_stricmp(argv[1], "/la") == 0))) {
        V4vRunListenAcceptImmediate((USHORT)strtol(argv[2], NULL, 10),
                                    (ULONG32)strtol(argv[3], NULL, 10));
    }
    else if ((argc == 5)&&((_stricmp(argv[1], "-dg") == 0)||
                           (_stricmp(argv[1], "/dg") == 0))) {
        V4vRunDatagramTest((USHORT)strtol(argv[2], NULL, 10),
                           (ULONG32)strtol(argv[3], NULL, 10),
                           (ULONG32)strtol(argv[4], NULL, 10));		
    }
    else if ((argc == 5)&&((_stricmp(argv[1], "-ml") == 0)||
                           (_stricmp(argv[1], "/ml") == 0))) {
        V4vRunMockListerTest((USHORT)strtol(argv[2], NULL, 10),
                             (ULONG32)strtol(argv[3], NULL, 10),
                             (ULONG32)strtol(argv[4], NULL, 10));		
    }
    else if ((argc == 5)&&((_stricmp(argv[1], "-cm") == 0)||
                           (_stricmp(argv[1], "/cm") == 0))) {
        V4vRunConnectorMockTest((USHORT)strtol(argv[2], NULL, 10),
                                 (ULONG32)strtol(argv[3], NULL, 10),
                                 (ULONG32)strtol(argv[4], NULL, 10));
    }
    else if ((argc == 4)&&((_stricmp(argv[1], "-rx") == 0)||
                           (_stricmp(argv[1], "/rx") == 0))) {
         V4vRunCharReceiverTest((USHORT)strtol(argv[2], NULL, 10),
                                (ULONG32)strtol(argv[3], NULL, 10));
    }
    else if ((argc == 4)&&((_stricmp(argv[1], "-tx") == 0)||
                           (_stricmp(argv[1], "/tx") == 0))) {
         V4vRunCharSenderTest((USHORT)strtol(argv[2], NULL, 10),
                              (ULONG32)strtol(argv[3], NULL, 10));
    }
    else if ((argc == 5)&&((_stricmp(argv[1], "-cc") == 0)||
                           (_stricmp(argv[1], "/cc") == 0))) {
         V4vRunConnectorConnectorTest((USHORT)strtol(argv[2], NULL, 10),
                                      (ULONG32)strtol(argv[3], NULL, 10),
                                      ((ULONG32)strtol(argv[4], NULL, 10) == 1 ? TRUE : FALSE));
    }
    else if ((argc == 5)&&((_stricmp(argv[1], "-ca") == 0)||
                           (_stricmp(argv[1], "/ca") == 0))) {
         V4vRunConnectorAccepterTest((USHORT)strtol(argv[2], NULL, 10),
                                     (ULONG32)strtol(argv[3], NULL, 10),
                                     ((ULONG32)strtol(argv[4], NULL, 10) == 1 ? TRUE : FALSE));
    }
    else if ((argc == 3)&&((_stricmp(argv[1], "-rt") == 0)||
                           (_stricmp(argv[1], "/rt") == 0))) {
        V4vRunTest(argv[2]);
    }
    else {
        V4vAppUsage();
    }

    return 0;
}
