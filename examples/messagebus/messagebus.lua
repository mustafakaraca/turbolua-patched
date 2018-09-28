
_G.TURBO_SSL = true
local turbo = require('turbo')
local escape = require('turbo.escape')
local util = require('turbo.util')
local log = require('turbo.log')

local CONN_LISTENER = 1
local CONN_PUBLISHER = 2
local CONN_PEER = 3

local function msgpack(parsed)
	local strmsg = escape.json_encode(parsed)
	local n = #strmsg
	local t = n % 256
	n = (n - t) / 256
	local l4 = string.char(t)
	t = n % 256
	n = (n - t) / 256
	local l3 = string.char(t)
	t = n % 256
	n = (n - t) / 256
	local l2 = string.char(t)
	local l1 = string.char(n % 256)
	return l1 .. l2 .. l3 .. l4 .. strmsg
end

local function msglen(data)
	if #data < 4 then
		return nil, 'invalid msg format'
	end
	local size = 0
	for i = 1, 4 do
		size = size * 256
		size = size + data:byte(i)
	end
	return size
end

local function msgparse(data)
	local size, err = msglen(data)
	if not size then
		return nil, err
	end
	if size + 4 > #data then
		return nil, 'invalid msg format'
	end
	return escape.json_decode(data:sub(5, 4 + size))
end

local messagebus = {
	subscriptions = {},
	peers = {},
	peersubscriptions = {},
	pong_message = msgpack({ type = 'pong' }),
	ping_message = msgpack({ type = 'ping' }),
}

local Queue = {}
do
	Queue.__index = Queue

	function Queue.new()
		return setmetatable({ head = 0, tail = 0, nodump = true }, Queue)
	end

	function Queue:elemcount()
		return self.tail - self.head
	end

	function Queue:popleft()
		local head = self.head + 1
		local e = self[head]
		if not e then
		  return nil
		end
		self[head] = nil
		self.head = head
		return e
	end

	function Queue:pushleft(e)
		assert(e ~= nil)
		local head = self.head
		self[head] = e
		self.head = head - 1
	end

	function Queue:popright()
		local tail = self.tail
		local e = self[tail]
		if not e then
		  return nil
		end
		self[tail] = nil
		self.tail = tail - 1
		return e
	end

	function Queue:pushright(e)
		assert(e ~= nil)
		local tail = self.tail + 1
		self[tail] = e
		self.tail = tail
	end
end

local function stream_attach_receive_callback(stream, cb)
	local header_received
	local read_expected
	local read_expected_header

	local function body_received(stream, data)
		if #data ~= read_expected then
			log.error('logic error')
			stream:close()
			return
		end
		local msg, err = escape.json_decode(data)
		if not msg then
			log.error('invalid msg: ' .. tostring(err))
			stream:close()
			return
		end
		cb(read_expected_header .. data, msg)
		read_expected = 4
		stream:read_bytes(read_expected, header_received, stream)
	end

	header_received = function(stream, data)
		if #data ~= read_expected then
			log.error('logic error')
			stream:close()
			return
		end
		local size, err = msglen(data)
		if not size then
			log.error('msg header read failed with: ' .. tostring(err))
			stream:close()
		elseif size <= 0 or size > 65535 then
			log.error('invalid msg header size')
			stream:close()
		else
			read_expected = size
			read_expected_header = data
			stream:read_bytes(read_expected, body_received, stream)
		end
	end

	read_expected = 4
	stream:read_bytes(read_expected, header_received, stream)
end


local WriteQueueBase = {}
do
	WriteQueueBase.__index = WriteQueueBase
	setmetatable(WriteQueueBase, WriteQueueBase)

	function WriteQueueBase:__call(handle)
		return setmetatable({
			handle = handle,
			outgoing = Queue.new(),
			write_scheduled = false,
		}, self)
	end

	function WriteQueueBase:write(data, cb)
		error('WriteQueueBase write handler is not implemented')
	end

	function WriteQueueBase:close()
		error('WriteQueueBase close handler is not implemented')
	end

	local function write_completed(self)
		self.write_scheduled = false
		self:write_schedule()
	end

	function WriteQueueBase:write_schedule()
		if not self.write_scheduled then
			local msg = self.outgoing:popright()
			if msg then
				self.write_scheduled = true
				self:write(msg, write_completed)
			end
		end
	end

	function WriteQueueBase:enqueue_ping()
		self.write_scheduled = true
		self:write(messagebus.ping_message, write_completed)
	end

	function WriteQueueBase:enqueue_pong()
		self.write_scheduled = true
		self:write(messagebus.pong_message, write_completed)
	end

	function WriteQueueBase:enqueue_tail(msg)
		self.outgoing:pushleft(msg)
		local discarded = 0
		while self.outgoing:elemcount() > 1000 do
			self.outgoing:popright()
			discarded = discarded + 1
		end
		if discarded > 0 then
			log.warning(string.format('writequeue: discarded %d messages', discarded))
		end
		self:write_schedule()
	end
end

local WebSocketWriteQueue = setmetatable({}, WriteQueueBase)
do
	WebSocketWriteQueue.__index = WebSocketWriteQueue

	function WebSocketWriteQueue:write(data, cb)
		self.handle:write_message(data, true, cb, self)
	end

	function WebSocketWriteQueue:close()
		self.handle:close()
	end
end

local StreamWriteQueue = setmetatable({}, WriteQueueBase)
do
	StreamWriteQueue.__index = StreamWriteQueue

	function StreamWriteQueue:write(data, cb)
		self.handle:write(data, cb, self)
	end

	function StreamWriteQueue:close()
		self.handle:close()
	end
end

local function enqueue_message(from, data, msg)
	if type(msg.topic) ~= 'string' or #msg.topic == 0 then
		return
	end
	if type(msg.payload) ~= 'table' then
		return
	end

	local subscribers = {}

	local function get_topic_subscribers(topic)
		local list = messagebus.subscriptions[topic]
		if not list then
			return
		end
		for subscriber, _ in pairs(list.conns) do
			if from then
				if from ~= subscriber then
					subscribers[subscriber] = true
				end
			elseif subscriber.type ~= CONN_PEER then
				subscribers[subscriber] = true
			end
		end
	end

	get_topic_subscribers(msg.topic)
	get_topic_subscribers('*')

	for subscriber, _ in pairs(subscribers) do
		subscriber.outqueue:enqueue_tail(data)
	end
end

local Peers = {}
do
	Peers.__index = Peers

	function Peers.subscribe(topic)
		messagebus.peersubscriptions[topic] = true
		local msg = msgpack({ type = 'subscribe', topic = topic })
		for peer, _ in pairs(messagebus.peers) do
			if peer.outqueue then
				peer.outqueue:enqueue_tail(msg)
			end
		end
	end

	function Peers.unsubscribe(topic)
		messagebus.peersubscriptions[topic] = nil
		local msg = msgpack({ type = 'unsubscribe', topic = topic })
		for peer, _ in pairs(messagebus.peers) do
			if peer.outqueue then
				peer.outqueue:enqueue_tail(msg)
			end
		end
	end

	local function peer_on_connect(peer, outqueue)
		peer.outqueue = outqueue
		for topic, _ in pairs(messagebus.peersubscriptions) do
			outqueue:enqueue_tail(msgpack({ type = 'subscribe', topic = topic }))
		end
		peer.last_ping_replied = util.gettimemonotonic()
	end

	local function peer_on_message(peer, data, msg)
		if msg.type == 'ping' then
			peer.outqueue:enqueue_pong()
			peer.last_ping_replied = util.gettimemonotonic()
		elseif msg.type == 'publish' then
			enqueue_message(nil, data, msg)
		end
	end

	local function peer_on_close(peer, reason)
		log.warning('peer connection closed with: ' .. tostring(reason))
		peer.outqueue = nil
		turbo.ioloop.instance():add_timeout(util.gettimemonotonic() + 10000, Peers.start, peer)
	end

	local function websocket_peer_connect(peer)
		turbo.websocket.WebSocketClient(string.format('ws://%s:%d/messagebus', peer.cfg.host, peer.cfg.port), {
			on_connect = function(self)
				log.success('peer connection to WebSocket established')
				peer_on_connect(peer, WebSocketWriteQueue(self))
			end,
			on_message = function(self, data)
				local msg, err = msgparse(data)
				if not msg then
					log.error(err)
					peer.outqueue:close()
					peer.outqueue = nil
					return
				end
				peer_on_message(peer, data, msg)
			end,
			on_close = function(self)
				peer_on_close(peer, 'Closed')
			end,
			on_error = function(self, code, reason)
				peer_on_close(peer, string.format('%s:%d', reason, code))
			end,
		})
	end

	local function tcp_peer_connect(peer)
		local success, res, err = pcall(turbo.iosimple.dial, string.format('tcp://%s:%d', peer.cfg.host, peer.cfg.port), nil, nil, 5000)
		if not success then
			peer_on_close(peer, 'TCP dial failed in pcall with: ' .. tostring(res))
			return
		end
		if not res then
			peer_on_close(peer, 'TCP dial failed with: ' .. tostring(err))
			return
		end
		log.success('tcp dial succedded')

		local stream = res:get_iostream()
		peer_on_connect(peer, StreamWriteQueue(stream))
		stream_attach_receive_callback(stream, function(data, msg)
			peer_on_message(peer, data, msg)
		end)
		stream:set_close_callback(function()
			peer_on_close(peer, 'Tcp connection terminated')
		end)
	end

	function Peers:start()
		if self.cfg.protocol == 'ws' then
			websocket_peer_connect(self)
		elseif self.cfg.protocol == 'tcp' then
			tcp_peer_connect(self)
		end
	end

	turbo.ioloop.instance():set_interval(1000, function()
		local now = util.gettimemonotonic()
		for peer, _ in pairs(messagebus.peers) do
			if peer.outqueue and now > (peer.last_ping_replied + 30000) then
				log.warning('Peer connection timed out')
				peer.outqueue:close()
				peer.outqueue = nil
			end
		end
	end)

	local function new_peer(cfg)
		local peer = {
			outqueue = nil,
			last_ping_replied = util.gettimemonotonic(),
			connected = false,
			cfg = cfg,
		}
		return setmetatable(peer, Peers)
	end

	local peer_protocols = {
		ws = true,
		tcp = true,
	}
	for _, peercfg in ipairs(messagebusconfig.peers) do
		if type(peercfg.host) ~= 'string' or type(peercfg.port) ~= 'number' or not peer_protocols[peercfg.protocol] then
			error("peer config is invalid")
		end
		turbo.ioloop.instance():add_callback(function()
			local peer = new_peer(peercfg)
			messagebus.peers[peer] = true
			peer:start()
		end)
	end
end


local ClientConnection = {}
do
	ClientConnection.__index = ClientConnection
	setmetatable(ClientConnection, ClientConnection)

	local function ping_timer(self)
		local lost_pings = self.lost_pings
		log.debug(string.format('ping timer called with lost count: %s', lost_pings))
		self.lost_pings = lost_pings + 1
		if lost_pings < 6 then
			self.outqueue:enqueue_ping()
		else
			self.outqueue:close()
		end
	end

	function ClientConnection:__call(type, outqueue)
		local conn = setmetatable({
			type = type,
			outqueue = outqueue,
			lost_pings = 0,
			subscriptions = {},
			ping_interval = nil,
		}, self)
		conn.ping_interval = turbo.ioloop.instance():set_interval(5000, ping_timer, conn)
		return conn
	end

	local function conn_subscribe(self, topic)
		self.subscriptions[topic] = true
		local list = messagebus.subscriptions[topic]
		if not list then
			list = {
				nconns = 0,
				conns = {},
			}
			messagebus.subscriptions[topic] = list
		end
		if not list.conns[self] then
			list.conns[self] = true
			if self.type ~= CONN_PEER then
				if list.nconns == 0 then
					Peers.subscribe(topic)
				end
				list.nconns = list.nconns + 1
			end
		end
	end

	local function conn_unsubscribe(self, topic)
		self.subscriptions[topic] = nil
		local list = messagebus.subscriptions[topic]
		if list and list.conns[self] then
			list.conns[self] = nil
			if self.type ~= CONN_PEER then
				list.nconns = list.nconns - 1
				if list.nconns == 0 then
					Peers.unsubscribe(topic)
				end
			end
			if not next(list.conns) then
				messagebus.subscriptions[topic] = nil
			end
		end
	end

	function ClientConnection:msg_received(data, msg)
		if msg.type == 'pong' then
			self.lost_pings = 0
		elseif msg.type == 'subscribe' then
			if type(msg.topic) ~= 'string' or #msg.topic == 0 then
				return
			end
			log.debug(string.format('client subscribed to: %s', msg.topic))
			conn_subscribe(self, msg.topic)
		elseif msg.type == 'unsubscribe' then
			if type(msg.topic) ~= 'string' or #msg.topic == 0 then
				return
			end
			log.debug(string.format('client unsubscribed from: %s', msg.topic))
			conn_unsubscribe(self, msg.topic)
		elseif msg.type == 'publish' then
			if self.type == CONN_PUBLISHER then
				enqueue_message(self, data, msg)
			end
		end
	end

	function ClientConnection:destroy()
		turbo.ioloop.instance():clear_interval(self.ping_interval)
		for topic, _ in pairs(self.subscriptions) do
			conn_unsubscribe(self, topic)
		end
	end
end

local wsports = messagebusconfig.wsports
if wsports then
	local WebSocketBase = class("WebSocketBase", turbo.websocket.WebSocketHandler)
	function WebSocketBase:open()
		local conn = ClientConnection(self.__client_type, WebSocketWriteQueue(self))
		self.__mbus_conn = conn
		conn.outqueue:enqueue_ping()
	end
	function WebSocketBase:on_message(data)
		local msg, err = msgparse(data)
		if not msg then
			log.error('msgparse failed: ' .. tostring(err))
			self:close()
			return
		end
		self.__mbus_conn:msg_received(data, msg)
	end
	function WebSocketBase:on_close(msg)
		self.__mbus_conn:destroy()
	end

	local WebSocketListenerHandler = class("WebSocketListenerHandler", WebSocketBase)
	function WebSocketListenerHandler:prepare()
		self.__client_type = CONN_LISTENER
	end

	local WebSocketPublisherHandler = class("WebSocketPublisherHandler", WebSocketBase)
	function WebSocketPublisherHandler:prepare()
		self.__client_type = CONN_PUBLISHER
	end

	local WebSocketPeerHandler = class("WebSocketPeerHandler", WebSocketBase)
	function WebSocketPeerHandler:prepare()
		self.__client_type = CONN_PEER
	end

	if wsports.listener then
		turbo.web.Application({{"^/messagebus$", WebSocketListenerHandler}}):listen(wsports.listener)
	end
	if wsports.publisher then
		turbo.web.Application({{"^/messagebus$", WebSocketPublisherHandler}}):listen(wsports.publisher)
	end
	if wsports.peer then
		turbo.web.Application({{"^/messagebus$", WebSocketPeerHandler}}):listen(wsports.peer)
	end
end

local tcpports = messagebusconfig.tcpports
if tcpports then
	local function add_tcp_client(type, stream)
		local conn = ClientConnection(type, StreamWriteQueue(stream))
		stream:set_close_callback(function()
			log.warning('Tcp connection terminated')
			conn:destroy()
		end)
		conn.outqueue:enqueue_ping()
		stream_attach_receive_callback(stream, function(data, msg)
			conn:msg_received(data, msg)
		end)
	end

	if tcpports.listener then
		local server = turbo.tcpserver.TCPServer()
		function server:handle_stream(stream, addr)
			log.success('tcp client connected to listener port')
			add_tcp_client(CONN_LISTENER, stream)
		end
		server:listen(tcpports.listener)
	end
	if tcpports.publisher then
		local server = turbo.tcpserver.TCPServer()
		function server:handle_stream(stream, addr)
			log.success('tcp client connected to publisher port')
			add_tcp_client(CONN_PUBLISHER, stream)
		end
		server:listen(tcpports.publisher)
	end
	if tcpports.peer then
		local server = turbo.tcpserver.TCPServer()
		function server:handle_stream(stream, addr)
			log.success('tcp client connected to peer port')
			add_tcp_client(CONN_PEER, stream)
		end
		server:listen(tcpports.peer)
	end
end

for category, value in pairs(messagebusconfig.logs or {}) do
	turbo.log.categories[category] = value
end

turbo.ioloop.instance():start()
