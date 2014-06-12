/*
 * Copyright (c) 2010 Citrix Systems, Inc.
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
#include <assert.h>
#include <rpc.h>
#include "v4v_common.h"
#include "v4vapi.h"
#include "v4vapp.h"

VOID
V4vStartConnector(V4V_CONFIG *cfg)
{
    BOOL rc;
    v4v_ring_id_t id;
    v4v_addr_t addr;
    char buf[256];
    HANDLE ev = NULL;
    OVERLAPPED ov;
    DWORD status, bytes;

    if (cfg->async) {
        cfg->v4vctx.flags = V4V_FLAG_OVERLAPPED;
        ev = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (ev == NULL) {
            printf("V4VC failed to create overlapped open event - error: %d\n", GetLastError());       
            return;
        }
        V4V_RESET_OVERLAPPED(&ov, ev);
    }
    else {
        cfg->v4vctx.flags = V4V_FLAG_NONE;
    }

    printf("V4VC starting stream connnector test - using async: %s\n", ((cfg->async) ?  "TRUE" : "FALSE"));
    
    do {
        rc = V4vOpen(&cfg->v4vctx, cfg->ringSize, ((cfg->async) ? &ov : NULL));
        if (!rc) {
            printf("V4VC V4vOpen() failed error: %d\n", GetLastError());
            break;
        }

        if (cfg->async) {
            status = WaitForSingleObject(ev, INFINITE);
            if (status != WAIT_OBJECT_0) {
                printf("V4VC V4vOpen() wait warning, unexpected status: %d\n", status);
            }

            if (!GetOverlappedResult(cfg->v4vctx.v4vHandle, &ov, &bytes, FALSE)) {
                printf("V4VC GetOverlappedResult() for open failed with error: %d\n", GetLastError());
                break;
            }
            V4V_RESET_OVERLAPPED(&ov, ev);
        }

        assert(cfg->v4vctx.v4vHandle != NULL);
        assert(cfg->v4vctx.v4vHandle != INVALID_HANDLE_VALUE);
        assert(cfg->v4vctx.recvEvent != NULL);

        id.partner = cfg->dst.domain;
        id.addr.domain = V4V_DOMID_NONE;
        id.addr.port = cfg->src.port;

        addr.domain = cfg->dst.domain;
        addr.port = cfg->dst.port;

        rc = V4vBind(&cfg->v4vctx, &id, ((cfg->async) ? &ov : NULL));
        if (!rc) {
            printf("V4VC V4vBind() failed error: %d\n", GetLastError());
            break;
        }

        if (cfg->async) {
            status = WaitForSingleObject(ev, INFINITE);
            if (status != WAIT_OBJECT_0) {
                printf("V4VC V4vBind() wait warning, unexpected status: %d\n", status);
            }

            if (!GetOverlappedResult(cfg->v4vctx.v4vHandle, &ov, &bytes, FALSE)) {
                printf("V4VC GetOverlappedResult() for bind failed with error: %d\n", GetLastError());
                break;
            }
            V4V_RESET_OVERLAPPED(&ov, ev);
        }

        // TODO for now just try connecting only
        cfg->connectOnly = TRUE;
        rc = V4vConnect(&cfg->v4vctx, &addr, ((cfg->async) ? &ov : NULL));
        if (!rc) {
            printf("V4VC V4vConnect() failed error: %d\n", GetLastError());
            break;
        }
        
        if (cfg->async) {
            status = WaitForSingleObject(ev, INFINITE);
            if (status != WAIT_OBJECT_0) {
                printf("V4VC V4vConnect() wait warning, unexpected status: %d\n", status);
            }

            if (!GetOverlappedResult(cfg->v4vctx.v4vHandle, &ov, &bytes, FALSE)) {
                printf("V4VC GetOverlappedResult() for connect failed with error: %d\n", GetLastError());
                break;
            }
            CloseHandle(ev);
            ev = NULL;
        }

        if (cfg->connectOnly) {
            printf("Connect only test...\n");
            printf("Type \'q\' to quit.\n");

            while (TRUE) {
                scanf("%s", buf);
                if (_stricmp(buf, "q") == 0) {
                    printf("Stopping connect test.\n");
                    break;
                }
            }
            break;
        }

    } while (FALSE);

    if (ev != NULL)
        CloseHandle(ev);

    rc = V4vClose(&cfg->v4vctx);
    if (!rc)
        printf("V4VC V4vClose() failed error: %d\n", GetLastError());
}

VOID
V4vStartListener(V4V_CONFIG *cfg)
{
    UNREFERENCED_PARAMETER(cfg);
    printf("V4VL V4V listen/accept functionality currently unsupported\n");
}
