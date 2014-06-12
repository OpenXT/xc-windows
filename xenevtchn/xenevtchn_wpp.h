//
// xenevtchn_wpp.h
//
// Copyright (c) 2009 XenSource, Inc. - All rights reserved.
//

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


#ifndef _XENEVTCHN_WPP_H_
#define _XENEVTCHN_WPP_H_

#define WPP_CONTROL_GUIDS \
  WPP_DEFINE_CONTROL_GUID( \
            XenevtchnWppGuid, \
			(01793C2A, 3CD0, 4C29, 95D3, DBA5FFD48332), \
			WPP_DEFINE_BIT(FLAG_DEBUG) \
			WPP_DEFINE_BIT(FLAG_VERBOSE) \
			WPP_DEFINE_BIT(FLAG_INFO) \
			WPP_DEFINE_BIT(FLAG_NOTICE) \
			WPP_DEFINE_BIT(FLAG_WARNING) \
			WPP_DEFINE_BIT(FLAG_ERROR) \
			WPP_DEFINE_BIT(FLAG_CRITICAL) \
			WPP_DEFINE_BIT(FLAG_PROFILE) \
            )

#endif // _XENEVTCHN_WPP_H_
