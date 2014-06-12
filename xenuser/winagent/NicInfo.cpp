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
#include "NicInfo.h"
#include "XSAccessor.h"
#include <winsock2.h>
#include <Iphlpapi.h>
#include <xs2.h>

NicInfo::NicInfo() : netif_data(NULL), nr_netifs_found(0)
{
    NicChangeEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!NicChangeEvent) {
        XsLog("Failed to create NicChangeEvent");
        exit(1);
    }

    ResetEvent(NicChangeEvent);

    memset(&Overlap, 0, sizeof (Overlap));
    Overlap.hEvent = NicChangeEvent;
}

NicInfo::~NicInfo()
{
    //CancelIPChangeNotify(&Overlap); <--- Function does not exist in 2k
}

void NicInfo::Prime()
{
    DWORD dwRet;

    dwRet = NotifyAddrChange(&hAddrChange, &Overlap);
    if (dwRet != ERROR_IO_PENDING)
    {
        XsLog("NotifyAddrChange failed:  %d", dwRet);
    }
}

void NicInfo::Refresh()
{
    GetNicInfo();
    XenstoreDoNicDump(nr_netifs_found, netif_data);
}

void NicInfo::GetNicInfo()
{
    const char* domainVifPath = "device/vif";
    unsigned int entry;     
    int i;
    unsigned int numEntries;
    char** vifEntries = NULL;
    char vifNode[MAX_XENBUS_PATH];
    PIP_ADAPTER_INFO IpAdapterInfo = NULL;
    PIP_ADAPTER_INFO currAdapterInfo;
    ULONG cbIpAdapterInfo;
    ULONG numIpAdapterInfo;
    char AdapterMac[MAX_CHAR_LEN];

    //
    // Get the list of vif #'s from xenstore
    //
	if (XenstoreList(domainVifPath, &vifEntries, &numEntries) < 0) {
		goto clean;
	}
    nr_netifs_found = 0;
    if (netif_data) {
        free(netif_data);
        netif_data = NULL;
    }
	netif_data = (VIFData *)calloc(sizeof(VIFData), numEntries);
    if (!netif_data) {
        goto clean;
    }

    //
    // Loop through xenstore and collect the vif number and the mac address
    //
    for (entry = 0; entry < numEntries; entry++) {
        netif_data[entry].ethnum = atoi(vifEntries[entry]); 
        char* macAddress;
        sprintf(vifNode, "device/vif/%s/mac", vifEntries[entry]);
        if (XenstoreRead(vifNode, &macAddress) != -1) {
            lstrcpyn(netif_data[entry].mac, macAddress, sizeof(netif_data[entry].mac));
            xs2_free(macAddress);
        }
    }

    //
    // Call GetAdaptersInfo to get a list of network device information.
    // Use this to cooralate a mac address to an IP address and the nics name.
    //
    cbIpAdapterInfo = 0;
    if (GetAdaptersInfo(NULL, &cbIpAdapterInfo) != ERROR_BUFFER_OVERFLOW) {
        goto clean;
    }
    IpAdapterInfo = (PIP_ADAPTER_INFO)malloc(cbIpAdapterInfo);
    if (!IpAdapterInfo) {
        goto clean;
    }
    if (GetAdaptersInfo(IpAdapterInfo, &cbIpAdapterInfo) != NO_ERROR) {
        goto clean;
    }

    currAdapterInfo = IpAdapterInfo;
    while (currAdapterInfo) {
        sprintf(AdapterMac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
            currAdapterInfo->Address[0], currAdapterInfo->Address[1], currAdapterInfo->Address[2],
            currAdapterInfo->Address[3], currAdapterInfo->Address[4], currAdapterInfo->Address[5]);

        for (entry = 0; entry < numEntries; entry++) {
            if (!lstrcmpi(AdapterMac, netif_data[entry].mac)) {
                //
                // Found the matching netif_data entry, so fill in the other values from
                // the IP_ADAPTER_INFO values.
                //
                lstrcpyn(netif_data[entry].name, currAdapterInfo->Description, sizeof(netif_data[entry].name));
                lstrcpyn(netif_data[entry].ip, currAdapterInfo->IpAddressList.IpAddress.String, sizeof(netif_data[entry].ip));
                break;
            }
        }

        currAdapterInfo = currAdapterInfo->Next;
    }

    nr_netifs_found = numEntries;
clean:
    if (vifEntries) {
        for (entry = 0; entry < numEntries; entry++)
            xs2_free(vifEntries[entry]);
        xs2_free(vifEntries);
    }
    if (IpAdapterInfo) {
        free(IpAdapterInfo);
    }
}
