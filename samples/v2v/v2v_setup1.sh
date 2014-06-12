#! /bin/sh
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

# Setup the paths for v2v connector/listener to interact. This would normally be
# done by a toolstack broker.
LDOM="$1"
CDOM="$2"

xenstore-write "/v2v/test/connector" ""
xenstore-chmod "/v2v/test/connector" b0
# These are the core values for the v2v internal state
xenstore-write "/v2v/test/connector/backend" "/v2v/test/listener"
xenstore-write "/v2v/test/connector/peer-domid" "$LDOM"
xenstore-write "/v2v/test/connector/state" "unready"
# These values are used for the test
xenstore-write "/v2v/test/connector/cancel" "0"

xenstore-write "/v2v/test/listener" ""
xenstore-chmod "/v2v/test/listener" b0
# These are the core values for the v2v internal state
xenstore-write "/v2v/test/listener/backend" "/v2v/test/connector"
xenstore-write "/v2v/test/listener/peer-domid" "$CDOM"
xenstore-write "/v2v/test/listener/state" "unready"
# These values are used for the test
xenstore-write "/v2v/test/listener/cancel" "0"
