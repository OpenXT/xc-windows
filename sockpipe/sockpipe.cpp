/*
 * Copyright (c) 2014 Citrix Systems, Inc.
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

#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>

// plj specials

#include "plj_utils.h"
#include "spinlock.h"
#include "threadcontrol.h"
#include "circle.h"
#include "logger.h"
#include "connectoid.h"
#include "pipereader.h"
#include "sockreader.h"

//
// Globals.
//

bool g_shutdown = false;
class Logger * g_log = NULL;
_TCHAR g_progname[MAX_PATH];

//
// Define TWO_PIPE if you want to go pipe to pipe instead of pipe to
// socket.  This is useful for debugging (this proxy) against a known
// working debuggee (eg a virtual machine under VPC).
//
//#define TWO_PIPE

//
// Generic (C style) support routines.
//

void my_exit(int code)
{
    if (g_log)
    {
        g_log->Flush();
    }
    exit(code);
}

void die(char * message,...)
{
    char    buf[1024];
    va_list args;

    va_start(args, message);
#if defined(SAFESTR)
    vsnprintf_s(buf, sizeof(buf), sizeof(buf) - 1, message, args);
#else
    _vsnprintf(buf, sizeof(buf), message, args);
#endif
    fprintf(stderr, "%s\n", buf);
    if (g_log)
    {
        g_log->Log(0, "die", buf);
    }
    my_exit(1);
}

void usage()
{
    _TCHAR * progname = g_progname;
    _TCHAR * endName = _tcsrchr(g_progname, TCHAR('\\'));

    if (endName)
    {
        progname = endName + 1;
    }

#if !defined(TWO_PIPE)
    fprintf(stderr, "usage: %s [-l] pipe [address] port\n\n", progname);
    fprintf(stderr, "where -  pipe is the name of the local pipe which the\n"
                    "         Microsoft Windows Debugger will try to connect to.\n"
                    "         address [optional] is the address of the target\n"
                    "         to connect to if Xen is listening.\n"
                    "         port is the (decimal) number of the TCP port Xen\n"
                    "         is configured to listen on or to connect to on\n"
                    "         this machine.\n\n"
                    "         Note: If sockpipe is listening then the port must\n"
                    "               be open through this machine's firewall.\n\n"
                    "         -l [optional] if specified, enable logging.  N.B.\n"
                    "         the log file can become quite large very quickly.\n"
                    "example: %s my_pipe 7001\n",
                    progname);
#else
    fprintf(stderr, "usage:   %s [-l] pipe1 pipe2\n\n", progname);
    fprintf(stderr, "where -  pipe1 is the name of the local pipe which the\n"
                    "         Microsoft Windows Debugger will try to connect to.\n"
                    "         pipe2 is the full path pipe name to the pipe being\n"
                    "         offered by a machine to be debugged.\n\n"
                    "         -l [optional] if specified, enable logging.  N.B.\n"
                    "         the log file can become quite large very quickly.\n"
                    "example: %s my_pipe \\remotemachine\pipe\debugee_name\n",
                    progname);
#endif
    fprintf(stderr, "\n"
                    "This program (%s) needs to be started BEFORE either the\n"
                    "kernel debugger or the system to be debugged.\n"
                    "To configure the serial ports of a Xen guest to connect,\n"
                    "add a line to the guest configuration file of the form-\n\n"
                    "serial='tcp:proxy-machine:port_number'\n\n"
                    "where proxy-machine is the IP address or name of the machine where\n"
                    "this program is running and port_number is the TCP port number it\n"
                    "is listening on.\n\n"
                    "To configure the serial ports of a Xen guest to listen,\n"
                    "add a line to the guest configuration file of the form-\n\n"
                    "serial='tcp::port_number,server,nodelay'\n\n"
                    "where port_number is the TCP port number the program should\n"
                    "connect to.\n",
                    progname);
    my_exit(1);
}

int __cdecl _tmain(int argc, _TCHAR* argv[])
{

#if defined(TWO_PIPE)
    //
    // Experiment with pipe to pipe so we can debug using VPC and capture
    // a log of a working debug session.
    //

    PipeReader  sock;

#else

    SockReader  sock;

#endif

    PipeReader  pipe;
    Logger      log;

    //
    // Save the name of the current running program. This is not presented
    // in argv[0] as you might expect... but hey, this is Windows.
    //

    GetModuleFileName(NULL, g_progname, sizeof (g_progname));
    g_progname[sizeof(g_progname) - 1] = _T('\0');
    *argv++;
    --argc;

    if (argc == 0)
        usage();

    //
    // Three arguments if you count the program name, the pipe name and
    // the port (or 2nd pipe).
    //

    if (_tcsncmp(*argv, _T("-l"), 2) == 0)
    {
        if (!log.Initialize())
        {
            die("couldn't initialize logger");
        }
        argv++;
        --argc;

        if (argc == 0)
            usage();
    }


    bool passive;

    if (argc == 2)
    {
        passive = true;
    }
    else if (argc == 3)
    {
        passive = false;
    }
    else
    {
        usage();
    }

    g_log = &log;

    //
    // Note: sock.Initialize will fire up the socket pump thread,
    // pipe initialization needs to be completed before that.
    //

    _TCHAR * lpipename = *argv;

#define whack_pipe _T("\\\\.\\pipe\\")

    size_t whackPipeLen =  (sizeof(whack_pipe) / sizeof(_TCHAR)) - 1;
    if (_tcsnccmp(lpipename, whack_pipe, whackPipeLen) != 0)
    {
        size_t originalNameLen = _tcslen(lpipename);
        size_t nameLen = whackPipeLen + originalNameLen + 1;
        if (nameLen > 1024) // arbitary
        {
            die("pipe name is too long.");
        }
        lpipename = (_TCHAR *)malloc(nameLen * sizeof(_TCHAR));
        if (lpipename == NULL)
        {
            die("failed to malloc space for local pipe name.");
        }
        memcpy(&lpipename[0], whack_pipe, whackPipeLen * sizeof(_TCHAR));
        memcpy(&lpipename[whackPipeLen],
               *argv,
               originalNameLen * sizeof(_TCHAR));
        lpipename[nameLen - 1] = 0;
    }
    argv++;

    printf("gonna try pipe '%s'\n", lpipename);
    if (!pipe.Initialize(lpipename, &log, &sock, false, false, "pip"))
    {
        die("couldn't open local named pipe, err %d", GetLastError());
    }

#if !defined(TWO_PIPE)
    _TCHAR * address;
    _TCHAR * portnumber;

    if (passive) {
        address = NULL;
        portnumber = *argv;
    } else {
        address = *argv++;
        portnumber = *argv;
    }

    if (!sock.Initialize(address, portnumber, &log, &pipe, true, "win"))
    {
        die("couldn't open socket.");
    }
#else
    _TCHAR * rpipename = *argv;

    if (!sock.Initialize(rpipename, &log, &pipe, true, true, "sok"))
    {
        die("couldn't open remote pipe.");
    }
#endif

    // 
    // We run the pipe reader directly on this thread.
    //

    pipe.ThreadEntry(&pipe);

    return 0;
}

