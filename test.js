const net = require('net');
const socks_server = require('./socks_server.js');
const server_generic = require('./server_generic.js');
const transparent_server = require('./transparent_server.js');

let c = server_generic.make_server(transparent_server.transparent_server, (e, s) => null, socks_server.make_socks_client({path: "/home/sebastian/gitprojects/universal-relay/urelay.sock"}));
for (let i = 1; i < 4; i++) {
	let s = net.createServer({pauseOnConnect: true, allowHalfOpen: true}, c);
	s.listen({fd: +process.env["CTRTOOL_NS_OPEN_FILE_FD_" + i]});
}
