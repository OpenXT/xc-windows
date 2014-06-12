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
#include <stdio.h>
#include <stdlib.h>
#include <xs_private.h>

static char *
read_reg_string(HKEY key, const char *subkey, const char *value)
{
    HKEY reg;
    LONG r;
    DWORD type;
    unsigned char *res;
    DWORD sz;

    r = RegOpenKeyEx(key, subkey, 0, KEY_QUERY_VALUE, &reg);
    if (r != ERROR_SUCCESS) {
        SetLastError(r);
        return NULL;
    }
    sz = 0;
    r = RegQueryValueEx(reg, value, NULL, &type, NULL, &sz);
    if (r != ERROR_SUCCESS) {
        RegCloseKey(reg);
        SetLastError(r);
        return NULL;
    }
    if (type != REG_SZ) {
        RegCloseKey(reg);
        SetLastError(ERROR_INVALID_DATA);
        return NULL;
    }
    res = malloc(sz + 1);
    if (!res) {
        RegCloseKey(reg);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    r = RegQueryValueEx(reg, value, NULL, &type, res, &sz);
    if (r != ERROR_SUCCESS) {
        RegCloseKey(reg);
        free(res);
        SetLastError(r);
        return NULL;
    }
    res[sz] = 0;
    RegCloseKey(reg);

    return (char *)res;
}

int __cdecl
main()
{
    HMODULE module;
    HANDLE h;
    HANDLE (__stdcall *xs_open)(void);
    void *(__stdcall *xs_read_f)(HANDLE, const char *, size_t *);
    char *r;
    char *path;
    char *dll;

#ifdef AMD64
    path = read_reg_string(HKEY_LOCAL_MACHINE,
                           "SOFTWARE\\Wow6432node\\Citrix\\XenTools",
                           "Install_Dir");
#else
    path = read_reg_string(HKEY_LOCAL_MACHINE,
                           "SOFTWARE\\Citrix\\XenTools",
                           "Install_Dir");
#endif
    if (!path) 
        xs_win_err(1, &xs_render_error_stderr, "getting install dir");

    dll = xs_assemble_strings("\\", path, "xs.dll", NULL);
    if (!dll)
        xs_win_err(1, &xs_render_error_stderr, "assembling path");

    module = LoadLibrary(dll);
    if (!module)
        xs_win_err(1, &xs_render_error_stderr, "loading xs.dll");
    printf("Loaded module.\n");
    xs_open = (HANDLE (__stdcall *)(void))GetProcAddress(module, "xs_domain_open");
    if (!xs_open)
        xs_win_err(1, &xs_render_error_stderr, "getting xs_domain_open");
    h = xs_open();
    if (!h)
        xs_win_err(1, &xs_render_error_stderr, "opening interface");
    printf("interface %p\n", h);

    xs_read_f = (void *(__stdcall *)(HANDLE, const char *, size_t *))GetProcAddress(module, "xs_read");
    if (!xs_read_f)
        xs_win_err(1, &xs_render_error_stderr, "getting xs_read");
    r = xs_read_f(h, "vm", NULL);
    printf("r %p\n", r);
    printf("vm -> %s\n", r);

    return 0;
}
