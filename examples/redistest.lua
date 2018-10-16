_G.TURBO_SSL = true
local turbo = require('turbo')
local escape = require('turbo.escape')
local util = require('turbo.util')
local log = require('turbo.log')
local redis = require('turbo.redis')
local coctx = require "turbo.coctx"

local io_loop = turbo.ioloop.instance()

local redis_exec = nil
do
	local queue = {}
	local redis_conn
	local scheduled = false

	local function process_queue()
		while #queue > 0 do
			local q = queue
			queue = {}
			for _, req in ipairs(q) do
				req.ctx:set_arguments({ redis_conn[req.cmd](redis_conn, unpack(req.args)) })
				req.ctx:finalize_context()
			end
		end
		scheduled = false
	end

	redis_exec = function()
		error('redis connection is not established yet')
	end

	io_loop:add_callback(function()
		redis_conn = redis.new("127.0.0.1", 6379, 1000)

		redis_exec = function(cmd, ...)
			local ctx = coctx.CoroutineContext(io_loop)
			table.insert(queue, {
				ctx = ctx,
				cmd = cmd,
				args = {...},
			})
			if not scheduled then
				scheduled = true
				io_loop:add_callback(process_queue)
			end
			return coroutine.yield(ctx)
		end
	end)
end

local RedisHandler = class("RedisHandler", turbo.web.RequestHandler)

function RedisHandler:get()
	local key = self:get_argument('key', nil, true)
	if key then
		local res, err = redis_exec('get', key)
		self:write(string.format('result: %s\nerr: %s\n', res, err))
	end
end

turbo.web.Application({{"^/redis$", RedisHandler}}):listen(8090)

io_loop:start()
