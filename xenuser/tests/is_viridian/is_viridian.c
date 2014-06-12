/*
 * Copyright (c) 2008 Citrix Systems, Inc.
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
#include <stdio.h>

void
cpuid(ULONG leaf, ULONG *peax, ULONG *pebx, ULONG *pecx,
       ULONG *pedx)
{
    ULONG reax, rebx, recx, redx;
    _asm {
        mov eax, leaf;
        cpuid;
        mov reax, eax;
        mov rebx, ebx;
        mov recx, ecx;
        mov redx, edx;
    };
    *peax = reax;
    *pebx = rebx;
    *pecx = recx;
    *pedx = redx;
}

void
stringy(ULONG n, char *p)
{
    int i;
    char c;

    for (i = 0; i < 4; i++)
    {
        c = (char)n & 0xff;
        p[i] = (c >= 0x20) && (c < 127) ? c : '.';
        n >>= 8;
    }
}

void
report(ULONG n, ULONG eax, ULONG ebx, ULONG ecx, ULONG edx)
{
    char pretty[13];
    pretty[12] = 0;

    stringy(ebx, pretty  );
    if (n == 0)
    {
        stringy(edx, pretty+4);
        stringy(ecx, pretty+8);
    }
    else
    {
        stringy(ecx, pretty+4);
        stringy(edx, pretty+8);
    }

    printf("CPUID(%08x) eax=%08x, ebx=%08x, ecx=%08x, edx=%08x (%s)\n",
            n, eax, ebx, ecx, edx, pretty);
}

int
main(int argc, char *argv[])
{
    ULONG eax, ebx, ecx, edx;
    int rc;

    UNREFERENCED_PARAMETER(argv);

    cpuid(0x40000000, &eax, &ebx, &ecx, &edx);

    rc = (ebx == 0x7263694d) && (ecx == 0x666f736f) && (edx == 0x76482074);

    if (argc != 1)
    {
        printf("CPUID reports viridian is %s.\n", rc ? "TRUE" : "FALSE");

        if (*argv[1] == 'V')
        {
            cpuid(0x00000000, &eax, &ebx, &ecx, &edx);
            report(0x00000000, eax, ebx, ecx, edx);
            cpuid(0x40000000, &eax, &ebx, &ecx, &edx);
            report(0x40000000, eax, ebx, ecx, edx);
            if (rc)
            {
                cpuid(0x40000100, &eax, &ebx, &ecx, &edx);
                report(0x40000100, eax, ebx, ecx, edx);
            }
        }
    }
    return rc == 0;
}
