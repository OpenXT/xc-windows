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

#ifndef WRAPPER_TYPES_H__
#define WRAPPER_TYPES_H__

/* Various bits of stuff so that we can define wrapper types for
   e.g. event channel ports and make sure that you don't try to use
   them as ordinary integers or e.g. grant table references.  These
   are almost enforced by the compiler, and they're handy for
   documentation anyway. */

/* Create a wrapper type.  These wrap up something (usually an int
   or a pointer) in a nice type-safe way.  There are two main macros:

   MAKE_WRAPPER_PUB(name) -> create a wrapper type called name.  The
   nature of the thing wrapper is not exposed, *except* that the
   all-zeroes value is null (this makes initialisation a bit easier).
   Creates inline functions null_${name}(), which creates a null
   instance of the wrapper, and is_null_${name}(x), which tests
   whether x is a null instance.

   MAKE_WRAPPER_PRIV(name, type) -> make the contents of ${name} be of
   type ${type}, and create functions wrap_${name} and unwrap_${name}
   to access it.

   There's also a variant of MAKE_WRAPPER_PRIV called
   __MAKE_WRAPPER_PRIV, which creates __wrap_${name} and
   __unwrap_${name} instead.  The intent here is to make it easier to
   apply transformations to the thing which was wrapped.
*/

#define __MAKE_WRAPPER_PUB(name)                           \
static __inline name null_ ## name ()                      \
{                                                          \
    name ret = {{0}};                                      \
    return ret;                                            \
}
#ifdef AMD64
#define MAKE_WRAPPER_PUB(name)                             \
typedef struct {                                           \
    unsigned char __wrapped_data[8];                       \
} name;                                                    \
__MAKE_WRAPPER_PUB(name)                                   \
static __inline BOOLEAN is_null_ ## name (name x)          \
{                                                          \
    if (*(unsigned long long *)x.__wrapped_data == 0)      \
        return TRUE;                                       \
    else                                                   \
        return FALSE;                                      \
}
#else
#define MAKE_WRAPPER_PUB(name)                             \
typedef struct {                                           \
    unsigned char __wrapped_data[4];                       \
} name;                                                    \
__MAKE_WRAPPER_PUB(name)                                   \
static __inline BOOLEAN is_null_ ## name (name x)          \
{                                                          \
    if (*(unsigned *)x.__wrapped_data == 0)                \
        return TRUE;                                       \
    else                                                   \
        return FALSE;                                      \
}
#endif /* !AMD64 */

#define __MAKE_WRAPPER_PRIV(name, type)                    \
static __inline name __wrap_ ## name (type val)            \
{                                                          \
    name ret;                                              \
    *(type *)ret.__wrapped_data = val;                     \
    return ret;                                            \
}                                                          \
static __inline type __unwrap_ ## name (name x)            \
{                                                          \
    return *(type*)x.__wrapped_data;                       \
}

#define MAKE_WRAPPER_PRIV(name, type)                      \
static __inline name wrap_ ## name (type val)              \
{                                                          \
    name ret;                                              \
    *(type *)ret.__wrapped_data = val;                     \
    return ret;                                            \
}                                                          \
static __inline type unwrap_ ## name (name x)              \
{                                                          \
    return *(type*)x.__wrapped_data;                       \
}


#endif /* !WRAPPER_TYPES_H__ */
