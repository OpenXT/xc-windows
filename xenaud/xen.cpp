/*
The MIT License (MIT)

Copyright (c) 2015 Assured Information Security

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE. */

#ifdef XEN

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include "xsapi.h"

#ifdef __cplusplus
} // extern "C"
#endif

#define XENAUD_VER "Alpha 1.0"

USHORT io_space[512];


VOID xWRITE_PORT_UCHAR (PUCHAR port, UCHAR value)
{
    *((PUCHAR)(&io_space[(int)port])) = value;
}

VOID xWRITE_PORT_USHORT (PUSHORT port, USHORT value)
{
    if ((int)port == 0x26) value = 0x0f;    // AC97REG_POWERDOWN
    *((PUSHORT)(&io_space[(int)port])) = value;
}

VOID xWRITE_PORT_ULONG (PULONG port, ULONG value)
{
    *((PULONG)(&io_space[(int)port])) = value;
}

UCHAR xREAD_PORT_UCHAR (PUCHAR port)
{
    UCHAR val;
    val = *((PUCHAR)(&io_space[(int)port]));
    return val;
}

USHORT xREAD_PORT_USHORT (PUSHORT port)
{
    USHORT val;
    val = *((PUSHORT)(&io_space[(int)port]));
    return val;
}

ULONG xREAD_PORT_ULONG (PULONG port)
{
    ULONG val;
    val = *((PULONG)(&io_space[(int)port]));
    return val;
}


void InitArray()
{
    xWRITE_PORT_USHORT((PUSHORT)0x00, 0);
    xWRITE_PORT_USHORT((PUSHORT)0x01, 0x8000);
    xWRITE_PORT_USHORT((PUSHORT)0x02, 0x8000);
    xWRITE_PORT_USHORT((PUSHORT)0x03, 0x8000);
    xWRITE_PORT_USHORT((PUSHORT)0x04, 0x0f0f);
    xWRITE_PORT_USHORT((PUSHORT)0x05, 0);
    xWRITE_PORT_USHORT((PUSHORT)0x06, 0x8008);
    xWRITE_PORT_USHORT((PUSHORT)0x07, 0x8008);
    xWRITE_PORT_USHORT((PUSHORT)0x08, 0x8808);
    xWRITE_PORT_USHORT((PUSHORT)0x09, 0x8808);
    xWRITE_PORT_USHORT((PUSHORT)0x0a, 0x8808);
    xWRITE_PORT_USHORT((PUSHORT)0x0b, 0x8808);
    xWRITE_PORT_USHORT((PUSHORT)0x0c, 0x8808);
    xWRITE_PORT_USHORT((PUSHORT)0x0d, 0x0404);
    xWRITE_PORT_USHORT((PUSHORT)0x0e, 0x8000);
    xWRITE_PORT_USHORT((PUSHORT)0x0f, 0x8000);
    xWRITE_PORT_USHORT((PUSHORT)0x10, 0);
    xWRITE_PORT_USHORT((PUSHORT)0x11, 0);
    xWRITE_PORT_USHORT((PUSHORT)0x12, 0);
    xWRITE_PORT_USHORT((PUSHORT)0x13, 0x000f);
    xWRITE_PORT_USHORT((PUSHORT)0x14, 0x4001);
    xWRITE_PORT_USHORT((PUSHORT)0x15, 0);
    xWRITE_PORT_USHORT((PUSHORT)0x16, 0);
    xWRITE_PORT_USHORT((PUSHORT)0x17, 0);
    xWRITE_PORT_USHORT((PUSHORT)0x18, 0);
    xWRITE_PORT_USHORT((PUSHORT)0x19, 0);
    xWRITE_PORT_USHORT((PUSHORT)0x1a, 0);
    xWRITE_PORT_USHORT((PUSHORT)0x1b, 0);
    xWRITE_PORT_USHORT((PUSHORT)0x1c, 0);
    xWRITE_PORT_USHORT((PUSHORT)0x1d, 0);
    xWRITE_PORT_USHORT((PUSHORT)0x26, 0x000f);
    xWRITE_PORT_USHORT((PUSHORT)0x3e, 0x1234);
    xWRITE_PORT_USHORT((PUSHORT)0x3f, 0xabcd);

    xWRITE_PORT_ULONG((PULONG)0x6c, 0);         // Global Control
    xWRITE_PORT_ULONG((PULONG)0x70, 0x0100);    // Global Status
    xWRITE_PORT_ULONG((PULONG)0x74, 0);         // Codec Access Semiphore
}

NTSTATUS XenInitialize(PDEVICE_OBJECT pdo)
{
//    PADAPTER adapter = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
//    PCHAR xenbusPath = NULL;

    UNREFERENCED_PARAMETER (pdo);

    memset (io_space, -1, sizeof(io_space));
    InitArray();

    TraceVerbose(("====> '%s'.\n", __FUNCTION__));

    xenbus_write(XBT_NIL, "drivers/xenaud", XENAUD_VER);

    //xenbusPath = xenbus_find_frontend(pdo);
    //if (!xenbusPath) {
    //    Status = STATUS_NOT_FOUND;
    //    goto exit;
    //}

    //TraceNotice(("Found '%s' frontend.\n", xenbusPath));
    //adapter = XmAllocateZeroedMemory(sizeof(ADAPTER));
    //if (adapter == NULL) {
    //    Status = STATUS_INSUFFICIENT_RESOURCES;
    //    goto exit;
    //}

//exit:
    TraceVerbose(("<==== '%s'.\n", __FUNCTION__));
    return Status;
}

#endif  // #ifdef XEN
