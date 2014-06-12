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

#include <stdio.h>

#define NO_XS_ACCESSOR
#include "..\..\volumes.cpp"

static void
create_volume_stdout(const struct volume *v)
{
    UNREFERENCED_PARAMETER(v);
}

static void
destroy_volume_stdout(const struct volume *v)
{
    printf("destroy volume %s\n", v->xenstore_name);
}

static void
set_volume_field_stdout(const struct volume *v,
                        const char *field,
                        const char *value)
{
    printf("%s::%s -> %s\n", v->xenstore_name, field, value);
}

int __cdecl
main()
{
    while (1) {
        update_xenstore_volume_data(create_volume_stdout,
                                    destroy_volume_stdout,
                                    set_volume_field_stdout);
        Sleep(1000);
    }
}
