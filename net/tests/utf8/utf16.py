#! /usr/bin/env python
#
# Copyright (c) 2009 Citrix Systems, Inc.
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

import codecs
import random
import subprocess
import sys
import random

def validate(s):
    correct_utf16 = codecs.utf_16_encode(s)[0][2:]
    utf8 = codecs.utf_8_encode(s)
    p = subprocess.Popen("./utf16", stdin = subprocess.PIPE, stdout = subprocess.PIPE)
    maybe_utf16 = p.communicate(utf8[0])[0]
    if correct_utf16 != maybe_utf16:
        print u"tried to do %r, got back %r, expected %r" % (utf8[0], maybe_utf16, correct_utf16)
        raise "failed"

def valid_unicode_char(c):
    if (c >= 0xd800 and c < 0xe000) or c == 0xfffe or c == 0xffff:
        return False;
    return True

def random_unicode_char():
    while True:
        c = random.randint(0, 0x10ffff)
        if valid_unicode_char(c):
            return unichr(c)
        
def random_unicode_string():
    l = random.randint(0, 10)
    s = u"".join(map(lambda x: random_unicode_char(), range(0,l)))
    return s

# Validate a bunch of randomly generated strings.
for x in xrange(1, 10000):
    s = random_unicode_string()
    validate(s)
    if x % 1000 == 0:
        print x
    
# Validate every unicode character which can be represented in both
# UTF-8 and UTF-16.  That excludes the UTF-16 surrogates at
# 0xd800-0xe000 and the invalid characters at 0xfffe and 0xffff.
for x in xrange(1, 0x110000):
    if x % 0x100 == 0:
        print "%x" % x
    if valid_unicode_char(x):
        validate( unichr(x) )
