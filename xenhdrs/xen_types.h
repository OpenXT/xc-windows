/*
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/* Various typedefs and so forth to make it a bit easier to use the
   Xen headers in a Windows environment. */
#ifndef WIN_XEN_TYPES_H__
#define WIN_XEN_TYPES_H__

#define XEN_GUEST_HANDLE(name)  __guest_handle_ ## name

#define DEFINE_XEN_GUEST_HANDLE(name) \
        typedef struct { name *v; } XEN_GUEST_HANDLE(name)

#define SET_XEN_GUEST_HANDLE(_handle, _v)   \
        do {                                \
            (_handle).v = (_v);             \
        } while (FALSE)

typedef ULONG_PTR   xen_ulong_t;
typedef xen_ulong_t xen_pfn_t;

DEFINE_XEN_GUEST_HANDLE(xen_pfn_t);

#endif /* !WIN_XEN_TYPES_H__ */
