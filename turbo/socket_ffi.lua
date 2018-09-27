--- Turbo.lua Socket Module
--
-- Copyright 2013 John Abrahamsen
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

local log = require "turbo.log"
local util = require "turbo.util"
local libtffi = util.load_libtffi()
local bit = jit and require "bit" or require "bit32"
local ffi = require "ffi"
local platform = require "turbo.platform"
require "turbo.cdef"

local function add_c_def(t, sym)
	t[sym] = libtffi.get_c_def(sym)
end

local F = {}
add_c_def(F, "F_DUPFD")
add_c_def(F, "F_GETFD")
add_c_def(F, "F_SETFD")
add_c_def(F, "F_GETFL")
add_c_def(F, "F_SETFL")

local O = {}
add_c_def(O, "O_ACCMODE")
add_c_def(O, "O_RDONLY")
add_c_def(O, "O_WRONLY")
add_c_def(O, "O_RDWR")
add_c_def(O, "O_CREAT")
add_c_def(O, "O_EXCL")
add_c_def(O, "O_NOCTTY")
add_c_def(O, "O_TRUNC")
add_c_def(O, "O_APPEND")
add_c_def(O, "O_NONBLOCK")
add_c_def(O, "O_NDELAY")
add_c_def(O, "O_SYNC")
--add_c_def(O, "O_FSYNC")
add_c_def(O, "O_ASYNC")

local SOCK = {}
add_c_def(SOCK, "SOCK_STREAM")
add_c_def(SOCK, "SOCK_DGRAM")
add_c_def(SOCK, "SOCK_RAW")
add_c_def(SOCK, "SOCK_RDM")
add_c_def(SOCK, "SOCK_SEQPACKET")
add_c_def(SOCK, "SOCK_DCCP")
add_c_def(SOCK, "SOCK_PACKET")
add_c_def(SOCK, "SOCK_CLOEXEC")
add_c_def(SOCK, "SOCK_NONBLOCK")

--[[ Protocol families.  ]]
local PF = {}
add_c_def(PF, "PF_UNSPEC")
add_c_def(PF, "PF_LOCAL")
add_c_def(PF, "PF_UNIX")
add_c_def(PF, "PF_FILE")
add_c_def(PF, "PF_INET")
add_c_def(PF, "PF_IPX")
add_c_def(PF, "PF_APPLETALK")
add_c_def(PF, "PF_NETROM")
add_c_def(PF, "PF_BRIDGE")
add_c_def(PF, "PF_ATMPVC")
add_c_def(PF, "PF_X25")
add_c_def(PF, "PF_INET6")
add_c_def(PF, "PF_PACKET")
add_c_def(PF, "PF_PPPOX")
add_c_def(PF, "PF_ROUTE")
add_c_def(PF, "PF_NETLINK")
add_c_def(PF, "PF_LLC")
add_c_def(PF, "PF_BLUETOOTH")
-- add more in case of need

--[[ Address families.  ]]
local AF = {}
AF.AF_UNSPEC =          PF.PF_UNSPEC
AF.AF_LOCAL =           PF.PF_LOCAL
AF.AF_UNIX =            PF.PF_UNIX
AF.AF_FILE =            PF.PF_FILE
AF.AF_INET =            PF.PF_INET
AF.AF_AX25 =            PF.PF_AX25
AF.AF_IPX =             PF.PF_IPX
AF.AF_APPLETALK =       PF.PF_APPLETALK
AF.AF_NETROM =          PF.PF_NETROM
AF.AF_BRIDGE =          PF.PF_BRIDGE
AF.AF_ATMPVC =          PF.PF_ATMPVC
AF.AF_X25 =             PF.PF_X25
AF.AF_INET6 =           PF.PF_INET6
AF.AF_ROSE =            PF.PF_ROSE
AF.AF_DECnet =          PF.PF_DECnet
AF.AF_NETBEUI =         PF.PF_NETBEUI
AF.AF_SECURITY =        PF.PF_SECURITY
AF.AF_KEY =             PF.PF_KEY
AF.AF_NETLINK =         PF.PF_NETLINK
AF.AF_ROUTE =           PF.PF_ROUTE
AF.AF_PACKET =          PF.PF_PACKET
AF.AF_ASH =             PF.PF_ASH
AF.AF_ECONET =          PF.PF_ECONET
AF.AF_ATMSVC =          PF.PF_ATMSVC
AF.AF_RDS =             PF.PF_RDS
AF.AF_SNA =             PF.PF_SNA
AF.AF_IRDA =            PF.PF_IRDA
AF.AF_PPPOX =           PF.PF_PPPOX
AF.AF_WANPIPE =         PF.PF_WANPIPE
AF.AF_LLC =             PF.PF_LLC
AF.AF_CAN =             PF.PF_CAN
AF.AF_TIPC =            PF.PF_TIPC
AF.AF_BLUETOOTH =       PF.PF_BLUETOOTH
AF.AF_IUCV =            PF.PF_IUCV
AF.AF_RXRPC =           PF.PF_RXRPC
AF.AF_ISDN =            PF.PF_ISDN
AF.AF_PHONET =          PF.PF_PHONET
AF.AF_IEEE802154 =      PF.PF_IEEE802154
AF.AF_CAIF =            PF.PF_CAIF
AF.AF_ALG =             PF.PF_ALG
AF.AF_NFC =             PF.PF_NFC
AF.AF_MAX =             PF.PF_MAX

local SOL = {}
add_c_def(SOL, "SOL_SOCKET")

local SO = {}
add_c_def(SO, "SO_DEBUG")
add_c_def(SO, "SO_REUSEADDR")
add_c_def(SO, "SO_TYPE")
add_c_def(SO, "SO_ERROR")
add_c_def(SO, "SO_DONTROUTE")
add_c_def(SO, "SO_BROADCAST")
add_c_def(SO, "SO_SNDBUF")
add_c_def(SO, "SO_RCVBUF")
add_c_def(SO, "SO_SNDBUFFORCE")
add_c_def(SO, "SO_RCVBUFFORCE")
add_c_def(SO, "SO_KEEPALIVE")
add_c_def(SO, "SO_OOBINLINE")
add_c_def(SO, "SO_NO_CHECK")
add_c_def(SO, "SO_PRIORITY")
add_c_def(SO, "SO_LINGER")
add_c_def(SO, "SO_BSDCOMPAT")
add_c_def(SO, "SO_PASSCRED")
add_c_def(SO, "SO_PEERCRED")
add_c_def(SO, "SO_RCVLOWAT")
add_c_def(SO, "SO_SNDLOWAT")
add_c_def(SO, "SO_RCVTIMEO")
add_c_def(SO, "SO_SNDTIMEO")
add_c_def(SO, "SO_SECURITY_AUTHENTICATION")
add_c_def(SO, "SO_SECURITY_ENCRYPTION_TRANSPORT")
add_c_def(SO, "SO_SECURITY_ENCRYPTION_NETWORK")
add_c_def(SO, "SO_BINDTODEVICE")
add_c_def(SO, "SO_ATTACH_FILTER")
add_c_def(SO, "SO_DETACH_FILTER")
add_c_def(SO, "SO_PEERNAME")
add_c_def(SO, "SO_TIMESTAMP")
add_c_def(SO, "SCM_TIMESTAMP")
add_c_def(SO, "SO_ACCEPTCONN")
add_c_def(SO, "SO_PEERSEC")
add_c_def(SO, "SO_PASSSEC")
add_c_def(SO, "SO_TIMESTAMPNS")
add_c_def(SO, "SCM_TIMESTAMPNS")
add_c_def(SO, "SO_MARK")
add_c_def(SO, "SO_TIMESTAMPING")
add_c_def(SO, "SCM_TIMESTAMPING")
add_c_def(SO, "SO_PROTOCOL")
add_c_def(SO, "SO_DOMAIN")
add_c_def(SO, "SO_RXQ_OVFL")
add_c_def(SO, "SO_WIFI_STATUS")
add_c_def(SO, "SCM_WIFI_STATUS")
add_c_def(SO, "SO_PEEK_OFF")
add_c_def(SO, "SO_NOFCS")

local E = {}
add_c_def(E, "EAGAIN")
add_c_def(E, "EWOULDBLOCK")
add_c_def(E, "EINPROGRESS")
add_c_def(E, "ECONNRESET")
add_c_def(E, "EPIPE")
add_c_def(E, "EAI_AGAIN")


if platform.__LINUX__ and not _G.__TURBO_USE_LUASOCKET__ then
    -- Linux FFI functions.

    local function strerror(errno)
        local cstr = ffi.C.strerror(errno);
        return ffi.string(cstr);
    end

    local function resolv_hostname(str)
        local in_addr_arr = {}
        local hostent = ffi.C.gethostbyname(str)
        if hostent == nil then
           return -1
        end
        local inaddr = ffi.cast("struct in_addr **", hostent.h_addr_list)
        local i = 0
        while inaddr[i] ~= nil do
           in_addr_arr[#in_addr_arr + 1] = inaddr[i][0]
           i = i + 1
        end
        return {
            in_addr = in_addr_arr,
            addrtype = tonumber(hostent.h_addrtype),
            name = ffi.string(hostent.h_name)
        }

    end

    local function set_nonblock_flag(fd)
        local flags = ffi.C.fcntl(fd, F.F_GETFL, 0);
        if flags == -1 then
           return -1, "fcntl GETFL failed."
        end
        if (bit.band(flags, O.O_NONBLOCK) ~= 0) then
           return 0
        end
        flags = bit.bor(flags, O.O_NONBLOCK)
        local rc = ffi.C.fcntl(fd, F.F_SETFL, flags)
        if rc == -1 then
           return -1, "fcntl set O_NONBLOCK failed."
        end
        return 0
    end

    local setopt = ffi.new("int32_t[1]")
    local function set_reuseaddr_opt(fd)
        setopt[0] = 1
        local rc = ffi.C.setsockopt(fd,
            SOL.SOL_SOCKET,
            SO.SO_REUSEADDR,
            setopt,
            ffi.sizeof("int32_t"))
        if rc ~= 0 then
           errno = ffi.errno()
           return -1, string.format("setsockopt SO_REUSEADDR failed. %s",
                                    strerror(errno))
        end
        return 0
    end

    --- Create new non blocking socket for use in IOStream.
    -- If family or stream type is not set AF_INET and SOCK_STREAM is used.
    local function new_nonblock_socket(family, stype, protocol)
        local fd = ffi.C.socket(family or AF.AF_INET,
                                stype or SOCK.SOCK_STREAM,
                                protocol or 0)

        if fd == -1 then
           errno = ffi.errno()
           return -1, string.format("Could not create socket. %s", strerror(errno))
        end
        local rc, msg = set_nonblock_flag(fd)
        if (rc ~= 0) then
           return rc, msg
        end
        return fd
    end

    local value = ffi.new("int32_t[1]")
    local socklen = ffi.new("socklen_t[1]", ffi.sizeof("int32_t"))
    local function get_socket_error(fd)
        local rc = ffi.C.getsockopt(fd,
            SOL.SOL_SOCKET,
            SO.SO_ERROR,
            ffi.cast("void *", value),
            socklen)
        if rc ~= 0 then
           return -1
        else
           return 0, tonumber(value[0])
        end
    end

    local export = util.tablemerge(SOCK,
        util.tablemerge(F,
        util.tablemerge(O,
        util.tablemerge(AF,
        util.tablemerge(PF,
        util.tablemerge(SOL,
        util.tablemerge(SO, E)))))))

    return util.tablemerge({
        strerror = strerror,
        resolv_hostname = resolv_hostname,
        getaddrinfo = ffi.C.getaddrinfo,
        set_nonblock_flag = set_nonblock_flag,
        set_reuseaddr_opt = set_reuseaddr_opt,
        new_nonblock_socket = new_nonblock_socket,
        get_socket_error = get_socket_error,
        INADDR_ANY = 0x00000000,
        INADDR_BROADCAST = 0xffffffff,
        INADDR_NONE =   0xffffffff,
    }, export)

else
    -- LuaSocket version.

    local luasocket = require "socket"

    --- Create new non blocking socket for use in IOStream.
    -- If family or stream type is not set AF_INET and SOCK_STREAM is used.
    local function new_nonblock_socket(family, stype, protocol)
        family = family or AF.AF_INET
        stype = stype or SOCK.SOCK_STREAM
        assert(family == AF.AF_INET or AF.AF_INET6,
            "LuaSocket only support AF_INET or AF_INET6")
        assert(stype == SOCK.SOCK_DGRAM or SOCK.SOCK_STREAM,
            "LuaSocket only support SOCK_DGRAM and SOCK_STREAM.")
        local sock
        if stype == SOCK.SOCK_DGRAM then
            sock = socket.udp()
        elseif stype == SOCK.SOCK_STREAM then
            sock = socket.tcp()
        end
        sock:settimeout(0)
        sock:setoption("keepalive", true)
        return sock
    end

    local export = util.tablemerge(SOCK,
        util.tablemerge(F,
        util.tablemerge(O,
        util.tablemerge(AF,
        util.tablemerge(PF,
        util.tablemerge(SOL,
        util.tablemerge(SO, E)))))))
    return util.tablemerge({
        new_nonblock_socket = new_nonblock_socket,
        INADDR_ANY = 0x00000000,
        INADDR_BROADCAST = 0xffffffff,
        INADDR_NONE = 0xffffffff,
    }, export)
end