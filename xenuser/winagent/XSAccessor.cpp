/*
 * Copyright (c) 2006 XenSource, Inc. All use and distribution of this 
 * copyrighted material is governed by and subject to terms and 
 * conditions as licensed by XenSource, Inc. All other rights reserved. 
 */

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
#include "stdafx.h"
#include "XSAccessor.h"
#include "xs2.h"
#include "xs_private.h"

static __declspec(thread) struct xs2_handle *XenstoreHandle;

static int64_t update_cnt;

void GetXenTime(FILETIME *now)
{
    xs2_get_xen_time(XenstoreHandle, now);
}

int ListenSuspend(HANDLE event)
{
    if (!xs2_listen_suspend(XenstoreHandle, event))
        return -1;
    else
        return 0;
}

void XsLog(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    xs2_vlog(XenstoreHandle, fmt, args);
    va_end(args);
}

void InitXSAccessor(void)
{
	XenstoreHandle = xs2_open();
    if (!XenstoreHandle) {
        DBGPRINT (("Failed to connect to xenstore."));
        exit(1);
    }
    xs2_make_precious(XenstoreHandle);
}

void ShutdownXSAccessor(void)
{
    if (XenstoreHandle) {
        xs2_unmake_precious(XenstoreHandle);
        xs2_close(XenstoreHandle);
    }
}

int XenstorePrintf(const char *path, const char *fmt, ...)
{
    va_list l;
    char buf[4096];
    int ret;
    int cnt;

    va_start(l, fmt);
    cnt = _vsnprintf(buf, sizeof(buf), fmt, l);
    va_end(l);
    if (cnt < 0) {
        DBGPRINT (("Cannot format data for XenstorePrintf!"));
        return -1;
    }

    /* Now have the thing we're trying to write. */
    return xs2_write( XenstoreHandle, path, buf);
}

int XenstoreWrite(const char *path, const void *data, size_t len)
{
    return xs2_write_bin( XenstoreHandle, path, data, len );
}

void XenstoreKickXapi()
{
    /* Old protocol */
    xs2_write (XenstoreHandle, "data/updated", "1");
    /* New protocol */
    XenstorePrintf("data/update_cnt", "%I64d", update_cnt);

    update_cnt++;
}

void XenstoreDoDump(VMData *data)
{
    XenstorePrintf("data/meminfo_free", "%I64d", data->meminfo_free);
    XenstorePrintf("data/meminfo_total", "%I64d", data->meminfo_total);
}

int XenstoreDoNicDump(
    uint32_t num_vif,
    VIFData *vif
    )
{
    DWORD hStatus;
    unsigned int i;
    int ret = 0;
    char path[MAX_CHAR_LEN] = "";
    const char* domainVifPath = "data/vif";
    unsigned int entry;     
    unsigned int numEntries;
    char** vifEntries = NULL;
    char vifNode[MAX_XENBUS_PATH];

    //
    // Do any cleanup first outside of a transaction since failures are allowed
    // and in some cases expected.
    //
    // Remove all of the old vif entries in case the nics have been
    // disabled.  Otherwise they will have old stale data in xenstore.
    //
    if (XenstoreList(domainVifPath, &vifEntries, &numEntries) >= 0) {
        for (entry = 0; entry < numEntries; entry++) {
            _snprintf(path, MAX_CHAR_LEN, "data/vif/%s", vifEntries[entry]);
            xs2_remove(XenstoreHandle, path);
            _snprintf(path, MAX_CHAR_LEN, "attr/eth%s", vifEntries[entry]);
            xs2_remove(XenstoreHandle, path);
            xs2_free(vifEntries[entry]);
        }
        xs2_free(vifEntries);
    }

    do 
    {
        hStatus = ERROR_SUCCESS;

        xs2_transaction_start( XenstoreHandle );

        ret |= XenstorePrintf("data/num_vif", "%d", num_vif);

        for( i = 0; i < num_vif; i++ ){
            if (vif[i].ethnum != -1) {

                _snprintf(path, MAX_CHAR_LEN, "data/vif/%d/name" , vif[i].ethnum);
                path[MAX_CHAR_LEN-1] = 0;
                ret |= XenstorePrintf(path, "%s", vif[i].name);


                //
                // IP address is dumped to /attr/eth[x]/ip
                //
                _snprintf (path, MAX_CHAR_LEN, "attr/eth%d/ip", vif[i].ethnum);
                path[MAX_CHAR_LEN-1] = 0;
                ret |= XenstorePrintf (path, "%s", vif[i].ip);

            }
        }

        if(!xs2_transaction_commit(XenstoreHandle))
        {
            hStatus = GetLastError ();
            if (hStatus != ERROR_RETRY)
            {
                DBGPRINT (("XenSvc: unable to commit %x, ret %d", hStatus,
                           ret));
                return -1;
            }
        }

    } while (hStatus == ERROR_RETRY);

	return ret;
}

int
XenstoreList(const char *path, char ***entries, unsigned *numEntries)
{
    *entries = xs2_directory(XenstoreHandle, path, numEntries);
    if (*entries)
        return 0;
    else
        return -1;
}

int
XenstoreRemove(const char *path)
{
    if (xs2_remove(XenstoreHandle, path))
        return 0;
    else
        return -1;
}

ssize_t
XenstoreRead(const char* path, char** value)
{
    size_t len;
    *value = (char *)xs2_read(XenstoreHandle, path, &len);
    if (*value)
        return len;
    else
        return -1;
}

struct xs2_watch *
XenstoreWatch(const char *path, HANDLE event)
{
    return xs2_watch(XenstoreHandle, path, event);
}

void
XenstoreUnwatch(struct xs2_watch *watch)
{
    return xs2_unwatch(watch);
}

