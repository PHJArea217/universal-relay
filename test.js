const net = require('net');
const socks_server = require('./socks_server.js');
const server_generic = require('./server_generic.js');
const transparent_server = require('./transparent_server.js');
const fake_dns = require('./fake_dns.js');
const express = require('express');
var pdns_app = express();

var s_obj = fake_dns.make_urelay_ip_domain_map(0xfedb120045007800n);
s_obj.make_pdns_express_app(pdns_app);
pdns_app.listen({fd: +process.env.CTRTOOL_NS_OPEN_FILE_FD_4});

let c = server_generic.make_server(transparent_server.transparent_server, (e, s) => {
	console.log(e);
	switch (s_obj.rewrite_CRA_req(e.req)) {
		case -1n: /* not within prefix */
		case -4n: /* successfully rewritten to original domain */
			return null;
		default:
			throw new Error();
	}
}, socks_server.make_socks_client({path: "/home/sebastian/gitprojects/universal-relay/urelay.sock"}));
for (let i = 1; i < 4; i++) {
	let s = net.createServer({pauseOnConnect: true, allowHalfOpen: true}, c);
	s.listen({fd: +process.env["CTRTOOL_NS_OPEN_FILE_FD_" + i]});
}
