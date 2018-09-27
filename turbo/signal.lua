--- Turbo.lua Signal Module
--
-- Copyright John Abrahamsen 2011, 2012, 2013 < JhnAbrhmsn@gmail.com >
--
-- "Permission is hereby granted, free of charge, to any person obtaining a copy of
-- this software and associated documentation files (the "Software"), to deal in
-- the Software without restriction, including without limitation the rights to
-- use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
-- of the Software, and to permit persons to whom the Software is furnished to do
-- so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE."

local ffi = require "ffi"
require "turbo.cdef"
local platform = require "turbo.platform"

local util = require "turbo.util"
local libtffi = util.load_libtffi()

local function add_c_def(t, sym)
	t[sym] = libtffi.get_c_def(sym)
end

local SIGNAL = {}
SIGNAL.signal = ffi.C.signal
add_c_def(SIGNAL, "SIG_BLOCK")
add_c_def(SIGNAL, "SIG_UNBLOCK")
add_c_def(SIGNAL, "SIG_SETMASK")
add_c_def(SIGNAL, "SIGHUP")
add_c_def(SIGNAL, "SIGINT")
add_c_def(SIGNAL, "SIGQUIT")
add_c_def(SIGNAL, "SIGILL")
add_c_def(SIGNAL, "SIGTRAP")
add_c_def(SIGNAL, "SIGIOT")
add_c_def(SIGNAL, "SIGABRT")
add_c_def(SIGNAL, "SIGBUS")
add_c_def(SIGNAL, "SIGFPE")
add_c_def(SIGNAL, "SIGKILL")
add_c_def(SIGNAL, "SIGUSR1")
add_c_def(SIGNAL, "SIGSEGV")
add_c_def(SIGNAL, "SIGUSR2")
add_c_def(SIGNAL, "SIGPIPE")
add_c_def(SIGNAL, "SIGALRM")
add_c_def(SIGNAL, "SIGTERM")
add_c_def(SIGNAL, "SIGSTKFLT")
--add_c_def(SIGNAL, "SIGCLD")
add_c_def(SIGNAL, "SIGCHLD")
add_c_def(SIGNAL, "SIGCONT")
add_c_def(SIGNAL, "SIGSTOP")
add_c_def(SIGNAL, "SIGTSTP")
add_c_def(SIGNAL, "SIGTTIN")
add_c_def(SIGNAL, "SIGTTOU")
add_c_def(SIGNAL, "SIGURG")
add_c_def(SIGNAL, "SIGXCPU")
add_c_def(SIGNAL, "SIGXFSZ")
add_c_def(SIGNAL, "SIGVTALRM")
add_c_def(SIGNAL, "SIGPROF")
add_c_def(SIGNAL, "SIGWINCH")
add_c_def(SIGNAL, "SIGPOLL")
add_c_def(SIGNAL, "SIGIO")
add_c_def(SIGNAL, "SIGPWR")
add_c_def(SIGNAL, "SIGSYS")
add_c_def(SIGNAL, "_NSIG")
-- Fake signal functions.
SIGNAL.SIG_ERR = ffi.cast("sighandler_t", -1)    --[[ Error return.  ]]
SIGNAL.SIG_DFL = ffi.cast("sighandler_t", 0) --[[ Default action.  ]]
SIGNAL.SIG_IGN = ffi.cast("sighandler_t", 1) --[[ Ignore signal.  ]]

return SIGNAL
