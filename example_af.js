'use strict';
/* To encourage modification of this file by end users, this file is public
 * domain and may be used and distributed without restriction. The LICENSE file
 * is not required to distribute, use, or modify this file. */
const app_func = require('./app_func.js');
const dns_he = require('./dns_he.js');
const endpoint = require('./endpoint.js');
const example_sm = require('./example-static-map.json');
const server_generic = require('./server_generic.js');
const transparent_server = require('./transparent_server.js');
const socks_server = require('./socks_server.js');
const app = new app_func.TransparentHandler({static_maps: example_sm, prefix: 0xfedb120045007800n});
const dns = require('dns');
const net = require('net');
var my_dns = new dns.Resolver();
my_dns.setServers(['8.8.8.8']);
var my_dns_resolver = dns_he.make_endpoint_resolver(my_dns, '6_weak', null);
async function common_at_domain(ep) {
	let sd_domain = ep.getSubdomainsOf(['arpa', 'home', 'u-relay'], 1);
	if (sd_domain && sd_domain[0]) {
		let new_ep2 = app.special_domain_resolve(sd_domain[0], ep);
		if (!new_ep2) throw new Error();
		ep = new_ep2;
	}
	let i = await ep.resolveDynamic(my_dns_resolver, {ipOnly: true});
	let result = [];
	for (let e of i) {
		result.push(e.toCRAreq());
	}
	return result;
}
var ts = server_generic.make_server(transparent_server.transparent_server, async (e, s) => {
	let ep = endpoint.fromCRAreq(e.req);
	let ep_iid = ep.getHostNR(0xfedb120045007800n << 64n, 64);
	if (ep_iid >= 0n) {
		let new_ep = app.transparent_to_domain(ep_iid, ep.getPort());
		if (new_ep) {
			e.req = await common_at_domain(new_ep);
			return null;
		}
	}
	throw new Error();
}, dns_he.simple_connect_HE);
var ss = server_generic.make_server(socks_server.socks_server, async (e, s) => {
	let ep = endpoint.fromCRAreq(e.req);
	e.req = await common_at_domain(ep);
	return null;
}, dns_he.simple_connect_HE);
app.expressApp.listen({fd: +process.env.CTRTOOL_NS_OPEN_FILE_FD_10});
let ts_obj = net.createServer({allowHalfOpen: true, pauseOnConnect: true}, ts);
let ss_obj = net.createServer({allowHalfOpen: true, pauseOnConnect: true}, ss);
ts_obj.listen({fd: +process.env.CTRTOOL_NS_OPEN_FILE_FD_11});
ss_obj.listen({fd: +process.env.CTRTOOL_NS_OPEN_FILE_FD_12});
