/*
 * Copyright (c) 2007 Citrix Systems, Inc.
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
#pragma warning (push, 3)
#include <winioctl.h>
#pragma warning (pop)
#include <ntddscsi.h>
#include <stdio.h>
#include <stdlib.h>

static void
dump_bytes(const char *buf, unsigned bytes)
{
    unsigned x;
    unsigned y;

    for (x = 0; x < bytes; x++) {
        printf("%02x ", (UCHAR)buf[x]);
        if (x % 16 == 15) {
            printf("  ");
            for (y = x - 15; y <= x; y++) {
                if (isprint(buf[y]))
                    printf("%c", buf[y]);
                else
                    printf(".");
            }
            printf("\n");
        }
    }
}

int
main(int argc, char *argv[])
{
    int devid = atoi(argv[1]);
    int c;
    int inq_page;
    SCSI_PASS_THROUGH *pt;
    HANDLE h;
    char buf[4096];
    DWORD bytes;

    sprintf(buf, "\\\\.\\PhysicalDrive%d", devid);
    h = CreateFile(buf,
                   GENERIC_READ|GENERIC_WRITE,
                   FILE_SHARE_READ|FILE_SHARE_WRITE,
                   NULL,
                   OPEN_EXISTING,
                   0,
                   NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("Couldn't open %s\n", buf);
        return 1;
    }

    for (c = 2; c < argc; c++) {
        switch (argv[c][0]) {
        case 'i':
            inq_page = atoi(argv[c+1]);
            printf("Inquiry page %d.\n", inq_page);
            memset(buf, 0, sizeof(buf));
            pt = (SCSI_PASS_THROUGH *)buf;
            pt->Length = sizeof(*pt);
            pt->CdbLength = 6;
            pt->SenseInfoLength = 0;
            pt->DataIn = SCSI_IOCTL_DATA_IN;
            pt->DataTransferLength = sizeof(buf) - sizeof(*pt);
            pt->TimeOutValue = 10;
            pt->DataBufferOffset = sizeof(*pt);
            pt->Cdb[0] = 0x12;
            pt->Cdb[1] = 1;
            pt->Cdb[2] = (UCHAR)inq_page;
            pt->Cdb[3] = (UCHAR)(pt->DataTransferLength >> 8);
            pt->Cdb[4] = (UCHAR)pt->DataTransferLength;
            if (!DeviceIoControl(h,
                                 IOCTL_SCSI_PASS_THROUGH,
                                 pt,
                                 sizeof(buf),
                                 buf,
                                 sizeof(buf),
                                 &bytes,
                                 NULL)) {
                printf("IOCTL failed %d\n", GetLastError());
            } else {
                printf("%d bytes back.\n", bytes);
                dump_bytes(buf + pt->DataBufferOffset,
                           bytes - pt->DataBufferOffset);
            }
            c++;
            break;
        case 'I':
            printf("Default inquiry.\n");
            memset(buf, 0, sizeof(buf));
            pt = (SCSI_PASS_THROUGH *)buf;
            pt->Length = sizeof(*pt);
            pt->CdbLength = 6;
            pt->SenseInfoLength = 0;
            pt->DataIn = SCSI_IOCTL_DATA_IN;
            pt->DataTransferLength = sizeof(buf) - sizeof(*pt);
            pt->TimeOutValue = 10;
            pt->DataBufferOffset = sizeof(*pt);
            pt->Cdb[0] = 0x12;
            pt->Cdb[1] = 0;
            pt->Cdb[2] = 0;
            pt->Cdb[3] = (UCHAR)(pt->DataTransferLength >> 8);
            pt->Cdb[4] = (UCHAR)pt->DataTransferLength;
            if (!DeviceIoControl(h,
                                 IOCTL_SCSI_PASS_THROUGH,
                                 pt,
                                 sizeof(buf),
                                 buf,
                                 sizeof(buf),
                                 &bytes,
                                 NULL)) {
                printf("IOCTL failed %d\n", GetLastError());
            } else {
                printf("%d bytes back.\n", bytes);
                dump_bytes(buf + pt->DataBufferOffset,
                           bytes - pt->DataBufferOffset);
            }
            break;
        default:
            printf("Bad arg %s\n", argv[c]);
            return 1;
        }
    }
    return 0;
}
