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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "winsock2.h"

int __cdecl
main(int argc, char *argv[])
{
    WSADATA wsaData;
    int i, j;
    SOCKET sock;
    struct sockaddr_in saddr;
    char buffer[10000];
    WSABUF bufs[10000];
    DWORD count;
    WSAEVENT evt;
    WSAOVERLAPPED overlapped;

    UNREFERENCED_PARAMETER(argc);

    i = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (i != NO_ERROR) {
        printf("Failed to start winsock (%d)\n", i);
        return 1;
    }

top:
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("Failed to create socket\n");
        return 1;
    }
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr(argv[1]);
    saddr.sin_port = htons((u_short)atoi(argv[2]));

    if (connect(sock, (SOCKADDR*)&saddr, sizeof(saddr)) == SOCKET_ERROR) {
        printf("Failed to connect to %s:%s\n", argv[1], argv[2]);
        Sleep(100);
        closesocket(sock);
        goto top;
    }

    memset(buffer, 0x73, sizeof(buffer));
    for (i = 0; i < sizeof(buffer) - 5; i++) {
        bufs[sizeof(buffer) - i - 1].len = 1;
        bufs[sizeof(buffer) - i - 1].buf = buffer + sizeof(buffer) - i;
    }

    evt = WSACreateEvent();
    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = evt;

    while (1) {
        j = WSASend(sock, bufs, 100, &count, 0, &overlapped,
                    NULL);
        WSACloseEvent(evt);
        if (j != 0) {
            printf("WSASend returns %d (%d)\n", j, WSAGetLastError());
            closesocket(sock);
            goto top;
        }
        evt = WSACreateEvent();
        if (evt == WSA_INVALID_EVENT)
            printf("WSA_INVALID_EVENT?\n");
        memset(&overlapped, 0, sizeof(overlapped));
        overlapped.hEvent = evt;
    }
}
