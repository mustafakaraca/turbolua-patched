messagebusconfig = {
	peers = {
		--{  protocol = 'ws', host = "127.0.0.1", port = 50112 },
		{  protocol = 'tcp', host = "127.0.0.1", port = 51112 },
	},
	wsports = {
		listener = 50010,
		publisher = 50011,
		peer = 50012,
	},
	tcpports = {
		listener = 51010,
		publisher = 51011,
		peer = 51012,
	},
	__logs = { -- rename to logs
		debug = false,
		notice = false,
	},
}

require('messagebus')
