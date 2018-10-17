
local turbo = require('turbo')
require "turbo.3rdparty.middleclass"


local Socket = class('Nginx Socket')

function Socket:initialize()
end

function Socket:settimeout(timeout)
	self._connect_timeout = timeout
	self._send_timeout = timeout
	self._read_timeout = timeout
end

function Socket:settimeouts(connect_timeout, send_timeout, read_timeout)
	self._connect_timeout = connect_timeout
	self._send_timeout = send_timeout
	self._read_timeout = read_timeout
end

function Socket:getreusedtimes()
	return 0
end

function Socket:close()
	if self._sock then
		self._sock:close()
		self._sock = nil
		return 1
	else
		return nil, 'socket is not connected'
	end
end

function Socket:setkeepalive()
	return self:close()
end

function Socket:connect(host, port)
	local dialurl
	if host:sub(1, 7) == 'unix://' then
		dialurl = host
	else
		dialurl = string.format('tcp://%s:%d', host, port)
	end
	local success, res, err = pcall(turbo.iosimple.dial, dialurl, nil, nil, self._connect_timeout)
	if not success then
		return false, 'iosimple dial failed in pcall: ' .. tostring(res)
	end
	if not res then
		return false, 'iosimple dial failed: ' .. tostring(err)
	end
	self._sock = res
	return true
end

function Socket:sslhandshake()
	error('sslhandshake is not implemented yet')
end

local function __flatten(data)
	local typ = type(data)
	if typ == 'string' then
		return data
	elseif typ == 'number' then
		return tostring(data)
	elseif typ == 'table' then
		for i = 1, #data do
			data[i] = __flatten(data[i])
		end
		return table.concat(data)
	else
		error('invalid param')
	end
end

function Socket:send(data)
	if not self._sock then
		return nil, 'socket is not open'
	end
	data = __flatten(data)
	local ok, res, err = pcall(self._sock.write, self._sock, data, self._send_timeout)
	if not ok then
		return nil, 'pcall: ' .. res
	end
	if not res and err then
		return nil, err
	end
	return #data
end

local function read_bytes(self, n)
	local ok, res, err = pcall(self._sock.read_bytes, self._sock, n, self._read_timeout)
	if not ok then
		return nil, 'pcall: ' .. res
	end
	return res, err
end

local function read_line(self)
	local ok, res, err = pcall(self._sock.read_until, self._sock, '\n', self._read_timeout)
	if not ok then
		return nil, 'pcall: ' .. res
	end
	if not res then
		return nil, err
	end
	local n = #res
	while true do
		local b = res:byte(n)
		if b ~= 10 and b ~= 13 then
			break
		end
		n = n - 1
	end
	return res:sub(1, n)
end

local function read_all(self)
	local ok, res, err = pcall(self._sock.read_until_close, self._sock, self._read_timeout)
	if not ok then
		return nil, 'pcall: ' .. res
	end
	return res, err
end

function Socket:receive(what)
	if not self._sock then
		return nil, 'socket is not open'
	end
	what = what or '*l'
	local typ = type(what)
	if typ == 'number' then
		return read_bytes(self, what)
	elseif typ == 'string' then
		local n = tonumber(what)
		if n then
			return read_bytes(self, n)
		elseif what == '*l' then
			return read_line(self)
		elseif what == '*a' then
			return read_all(self)
		else
			error('invalid arg: ' .. tostring(what))
		end
	else
		error('invalid arg: ' .. tostring(what))
	end
end

function Socket:receiveany()
	error('receiveany is not implemented yet')
end

function Socket:receiveuntil()
	error('receiveany is not implemented yet')
end

function Socket:setoption()
	error('setoption is not implemented yet')
end

local nginx = {}

nginx.socket = {}

function nginx.socket.tcp()
	return Socket()
end

return nginx