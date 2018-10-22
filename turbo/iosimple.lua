--- Turbo.lua IO Stream module.
-- Very High-level wrappers for asynchronous socket communication.
--
-- Copyright 2015 John Abrahamsen
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
-- http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
--
-- A interface for turbo.iostream without the callback spaghetti, but still
-- the async backend (the yield is done internally):
-- turbo.ioloop.instance():add_callback(function()
--     local stream = turbo.iosimple.dial("tcp://turbolua.org:80")
--     stream:write("GET / HTTP/1.0\r\n\r\n")
--
--     local data = stream:read_until_close()
--     print(data)
--
--     turbo.ioloop.instance():close()
-- end):start()
--
--

local log =         require "turbo.log"
local ioloop =      require "turbo.ioloop"
local coctx =       require "turbo.coctx"
local socket =      require "turbo.socket_ffi"
local sockutils =   require "turbo.sockutil"
local util =        require "turbo.util"
local iostream =    require "turbo.iostream"
local crypto =      require "turbo.crypto"

local iosimple = {} -- iosimple namespace

--- Connect to a host using a simple URI pattern.
-- @param address (String) E.g tcp://turbolua.org:8887
-- @param io (IOLoop object) IOLoop class instance to use for event
-- processing. If none is set then the global instance is used, see the
-- ioloop.instance() function.
-- @return (IOSimple class instance) or raise error.
local function _connect_callback_success(coctx)
    coctx:finalize_context(true)
end

local function _connect_callback_error(coctx, errdesc)
    coctx:finalize_context(false, errdesc)
end

local function _connect_callback_timedout(ctx)
    local stream, coctx, ref = ctx[1], ctx[2], ctx[3]
    if ref then
        ctx[3] = nil
        stream:close()
        coctx:finalize_context(false, 'connection request timed out')
    end
end

function iosimple.dial(address, ssl, io, timeout)
    assert(type(address) == "string", "No address in call to dial.")
    local protocol, host, port = address:match("^(%a+)://(.+):(%d+)")
    port = tonumber(port)
    assert(
        protocol and host,
        "Invalid address. Use e.g \"tcp://turbolua.org:8080\".")

    io = io or ioloop.instance()
    local sock_t
    local address_family
    if protocol == "tcp" then
        sock_t = socket.SOCK_STREAM
        address_family = socket.AF_INET
    elseif protocol == "udp" then
        sock_t = socket.SOCK_DGRAM
        address_family = socket.AF_INET
    elseif protocol == "unix" then
        sock_t = socket.SOCK_STREAM
        address_family = socket.AF_UNIX
    else
        error("Unknown schema: " .. protocol)
    end

    local err, ssl_context
    if ssl then
        if ssl == true then
            ssl = {verify=true}
        end
        err, res = crypto.ssl_create_client_context(
            ssl.cert_file,
            ssl.key_file,
            ssl.ca_cert_file,
            ssl.verify)
        if err ~= 0 then
            error(res)
        end
        ssl_context = res
    end

    local sock, msg = socket.new_nonblock_socket(
         address_family,
         sock_t,
         0)
    if sock == -1 then
        error("Could not create socket.")
    end

    local ctx = coctx.CoroutineContext(io)
    local stream
    if ssl and ssl_context then
        stream = iostream.SSLIOStream(sock, {_ssl_ctx=ssl_context,
                                             _type=1})
        stream:connect(host, port, address_family, ssl.verify or false,
            _connect_callback_success,
            _connect_callback_error,
            ctx
        )
    else
        stream = iostream.IOStream(sock)
        stream:connect(host, port, address_family,
            _connect_callback_success,
            _connect_callback_error,
            ctx
        )
    end
    local timeoutctx
    if type(timeout) == 'number' then
        timeoutctx = { stream, ctx, nil }
        timeoutctx[3] = io:add_timeout(util.gettimemonotonic() + timeout, _connect_callback_timedout, timeoutctx)
    end
    local rc, errdesc = coroutine.yield(ctx)
    if timeoutctx and timeoutctx[3] then
        io:remove_timeout(timeoutctx[3])
        timeoutctx[3] = nil
    end
    if rc ~= true then
        error(errdesc)
    end
    return iosimple.IOSimple(stream, io)
end

iosimple.IOSimple = class("IOSimple")

--- Wrap a IOStream class instance with a simpler IO.
-- @param stream IOStream class instance, already connected. If not consider 
-- using iosimple.dial.
function iosimple.IOSimple:initialize(stream)
    self.stream = stream
    self.io = self.stream.io_loop
    self.stream:set_close_callback(self._wake_yield_close, self)
end

--- Close this stream and clean up.
function iosimple.IOSimple:close()
    self.stream:close()
end

--- Returns the IOStream instance backed by the current IOSimple instance.
-- @return (IOStream class instance)
function iosimple.IOSimple:get_iostream()
    return self.stream
end

local function _stream_method_timedout(ctx)
    local self, ref = ctx[1], ctx[2]
    if ref then
        ctx[2] = nil
        self.stream:cancel_read_write()
        self:_wake_yield(false, 'timeout')
    end
end

local function _stream_method(self, method, arg, timeout)
    local timeoutctx
    assert(not self.coctx, "IOSimple is already working.")
    self.coctx = coctx.CoroutineContext(self.io)
    if arg ~= nil then
        self.stream[method](self.stream, arg, self._wake_yield, self)
    else
        self.stream[method](self.stream, self._wake_yield, self)
    end
    if type(timeout) == 'number' then
        timeoutctx = { self, nil }
        timeoutctx[2] = self.io:add_timeout(util.gettimemonotonic() + timeout, _stream_method_timedout, timeoutctx)
    end
    local res, err = coroutine.yield(self.coctx)
    if timeoutctx and timeoutctx[2] then
        self.io:remove_timeout(timeoutctx[2])
        timeoutctx[2] = nil
    end
    if not res and err and err ~= 'timeout' then
        error(err)
    end
    return res, err
end


--- Write the given data to the stream. Return when data has been written.
-- @param data (String) Data to write to stream.
function iosimple.IOSimple:write(data, timeout)
    return _stream_method(self, 'write', data, timeout)
end

--- Read until delimiter.
-- Delimiter is plain text, and does not support Lua patterns. 
-- See read_until_pattern for Lua patterns.
-- read_until should be used instead of read_until_pattern wherever possible
-- because of the overhead of doing pattern matching.
-- @param delimiter (String) Delimiter sequence, text or binary.
-- @return (String) Data receive until delimiter.
function iosimple.IOSimple:read_until(delimiter, timeout)
    return _stream_method(self, 'read_until', delimiter, timeout)
end

--- Read given amount of bytes from connection.
-- @param bytes (Number) The amount of bytes to read.
-- @return (String) Data receive.
function iosimple.IOSimple:read_bytes(bytes, timeout)
    return _stream_method(self, 'read_bytes', bytes, timeout)
end

--- Read until pattern is matched, then returns receive data.
-- If you only are doing plain text matching then using read_until
-- is recommended for less overhead.
-- @param pattern (String) The pattern to match.
-- @return (String) Data receive.
function iosimple.IOSimple:read_until_pattern(pattern, timeout)
    return _stream_method(self, 'read_until_pattern', pattern, timeout)
end

--- Reads all data from the socket until it is closed.
-- @return (String) Data receive.
function iosimple.IOSimple:read_until_close(timeout)
    return _stream_method(self, 'read_until_close', nil, timeout)
end

function iosimple.IOSimple:_wake_yield_close(...)
    if self.coctx then
        self.coctx:finalize_context(nil, "disconnected")
        self.coctx = nil
    end
end

function iosimple.IOSimple:_wake_yield(...)
    local ctx = self.coctx
    self.coctx = nil
    ctx:finalize_context(...)
end

return iosimple
