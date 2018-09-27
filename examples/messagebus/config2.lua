messagebusconfig = {
	peers = {
		--{  protocol = 'ws', host = "127.0.0.1", port = 50012 },
		{  protocol = 'tcp', host = "127.0.0.1", port = 51012 },
	},
	wsports = {
		listener = 50110,
		publisher = 50111,
		peer = 50112,
	},
	tcpports = {
		listener = 51110,
		publisher = 51111,
		peer = 51112,
	},
	__logs = { -- rename to logs
		debug = false,
		notice = false,
	},
}

require('messagebus')
