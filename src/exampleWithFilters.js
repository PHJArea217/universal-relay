'use strict';
const ip = require('ip');
const simpleIPRewrite = require('./filters/simpleIPRewrite.js');
const rewriteMap = new Map();
rewriteMap.set('192.168.100.1', '2602:806:a003:40e::3000:2621'); /* evan.aliases.peterjin.org */
rewriteMap.set('192.168.100.2', '2602:806:a003:40e::5c50:2521'); /* scp-2521.scp.rdns.peterjin.org */
rewriteMap.set('192.168.100.3', '2602:806:a003:40e::5c50:426'); /* scp-426.scp.rdns.peterjin.org */
rewriteMap.set('192.168.100.4', '2602:806:a003:40e::5c50:173'); /* scp-173.scp.rdns.peterjin.org */
rewriteMap.set('192.168.100.5', '2602:806:a003:40e::5c50:294'); /* scp-294.scp.rdns.peterjin.org */
rewriteMap.set('fd00::1000', '2602:806:a003:40e::5c50:f002'); /* euclid.scp.rdns.peterjin.org */
rewriteMap.set('fd00::1001', '2602:806:a003:40e::1'); /* ipv6-things.srv.peterjin.org */
const filters = [
	{
		ipv4: false,
		ipv6: true,
		cidrPrefix: {contains: (x) => {
			return ip.toBuffer(x).slice(0, 12).equals(new Buffer([0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]));
		}},
		filter: simpleIPRewrite.makeNAT64(false, null)
	},
	{
		ipv4: true,
		ipv6: false,
		cidrPrefix: {contains: (x) => (ip.toBuffer(x)[0] === 127)},
		filter: simpleIPRewrite.makeBlock()
	},
	{
		ipv4: true,
		ipv6: false,
		cidrPrefix: {contains: (x) => (x === '169.254.169.254')},
		filter: simpleIPRewrite.makeBlock()
	},
	{
		ipv4: false,
		ipv6: true,
		cidrPrefix: {contains: (x) => (x === '::1')},
		filter: simpleIPRewrite.makeBlock()
	},
	{
		ipv4: true, ipv6: false,
		cidrPrefix: {contains: (x) => (x === '172.21.21.22')},
		filter: (data, socket) => {
			data.host = "2602:806:a003:40e::3000:2961"; /* joshua.aliases.peterjin.org */
			data.hostBuf = null;
		}
	},
	{
		all: true,
		cidrPrefix: {contains: (x) => true},
		filter: (data, socket) => {
			let result = rewriteMap.get(data.host);
			if (result) {
				data.host = result;
				data.hostBuf = null;
			}
		}
	}
];

const net = require('net');
const socks_server = require('./socks_server.js');
const server_generic = require('./server_generic.js');
const transparent_server = require('./transparent_server.js');

let c = server_generic.make_server(transparent_server.transparent_server, simpleIPRewrite.makeSimpleIPRewrite(filters), socks_server.make_socks_client({path: "/home/sebastian/gitprojects/universal-relay/urelay.sock"}));
for (let i = 1; i < 4; i++) {
	let s = net.createServer({pauseOnConnect: true, allowHalfOpen: true}, c);
	s.listen({fd: +process.env["CTRTOOL_NS_OPEN_FILE_FD_" + i]});
}
