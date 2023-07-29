'use strict';
/* To encourage modification of this file by end users, this file is public
 * domain and may be used and distributed without restriction. The LICENSE file
 * is not required to distribute, use, or modify this file. */
/* This example file is intended to illustrate how a "field" of Unix domain
 * sockets can be used in conjunction with SKBOX_ENABLE_CONNECT=1 and
 * SKBOX_DIRECTORY_ROOT2 set to a temporary runtime directory. This allows
 * applications in a completely isolated network namespace to be able to
 * connect to the Internet through the Unix domain sockets. Using the provided
 * hosts file in tools/skbox_ec_hosts, certain domains can be redirected such
 * that they land on Universal Relay. The hosts file sets the IP address of the
 * domains to a virtual, otherwise-invalid IPv6 address. Then,
 * socketbox-preload intercepts the connect() system call, and if it sees that
 * the IP address falls within a certain range, then it will replace the TCP
 * socket with a Unix domain socket. The lower 32 bits of the IPv6 address
 * determine which Unix domain socket to connect to, such that certain Unix
 * domain socket paths correspond to certain IPv6 addresses and TCP ports.
 * An instance of transparent_server listens on the Unix domain socket and is
 * configured to relay to the actual domain name on the Internet. Thus, the
 * application appears to still be able to connect to the domain name, even
 * though the connection is through the Unix domain socket. The application
 * likely does not even know that it's through a Unix domain socket -- from the
 * sequence of system calls and library functions it attempted, the application
 * looks like it was able to connect to the server directly.
 *
 * This has been demostrated with wget and it was able to query the Let's
 * Encrypt ACME server without issue. Hopefully, it should also work with
 * actual ACME clients such as Certbot. However, Firefox did not seem to work
 * well with the Unix domain sockets in transparent mode, but it did work well
 * with a SOCKS server on a Unix domain socket once you configure the proxy
 * settings; you must select "Proxy DNS when using SOCKS v5", or otherwise it
 * might not work.
 */
const app_func = require('./app_func.js');
const dns_he = require('./dns_he.js');
const endpoint = require('./endpoint.js');
const example_sm = require('./example-static-map.json');
const server_generic = require('./server_generic.js');
const transparent_server = require('./transparent_server.js');
const socks_server = require('./socks_server.js');
const skbox_ec = require('./skbox_ec.js');
const mdns = require('./mdns.js');
const app = new app_func.TransparentHandler({static_maps: example_sm, prefix: 0xfedb120045007800n});
const dns = require('dns');
const net = require('net');
var my_dns = new dns.Resolver();
my_dns.setServers(['8.8.8.8']);
var my_dns_resolver = (d, h, ep) => mdns.systemd_resolve(h, null, true, ep); // mdns.make_libc_endpoint_resolver({all: true}); // dns_he.make_endpoint_resolver(my_dns, '6_weak', null);
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
let ts_obj = net.createServer({allowHalfOpen: true, pauseOnConnect: true}, ts);
let ss_obj = net.createServer({allowHalfOpen: true, pauseOnConnect: true}, ss);
let ss_obj2 = net.createServer({allowHalfOpen: true, pauseOnConnect: true}, ss);
if (Object.hasOwn(process.env, 'CTRTOOL_NS_OPEN_FILE_FD_10')) {
	app.expressApp.listen({fd: +process.env.CTRTOOL_NS_OPEN_FILE_FD_10});
	ts_obj.listen({fd: +process.env.CTRTOOL_NS_OPEN_FILE_FD_11});
	ss_obj.listen({fd: +process.env.CTRTOOL_NS_OPEN_FILE_FD_12});
}
let my_socket_root = process.env.URELAY_SKBOX_EC_ROOT || '/run/socketbox/00016';
function skbox_ec_make_server(ep) {
	let cb = server_generic.make_server(transparent_server.transparent_server, async (e, s) => {
		e.req = await common_at_domain(ep);
		return null;
	}, dns_he.simple_connect_HE);
	return net.createServer({allowHalfOpen: true, pauseOnConnect: true}, cb);
}
skbox_ec.make_skbox_ec_server(my_socket_root + '/00000_01080', ss_obj2);
let servers = [];
servers.unshift(skbox_ec_make_server(new endpoint.Endpoint().setDomain('acme-v02.api.letsencrypt.org').setPort(443)));
skbox_ec.make_skbox_ec_server(my_socket_root + '/00001_00443', servers[0]);
servers.unshift(skbox_ec_make_server(new endpoint.Endpoint().setDomain('r3.o.lencr.org').setPort(80)));
skbox_ec.make_skbox_ec_server(my_socket_root + '/00002_00080', servers[0]);
servers.unshift(skbox_ec_make_server(new endpoint.Endpoint().setDomain('e1.o.lencr.org').setPort(80)));
skbox_ec.make_skbox_ec_server(my_socket_root + '/00003_00080', servers[0]);
servers.unshift(skbox_ec_make_server(new endpoint.Endpoint().setDomain('website.peterjin.org').setPort(443)));
skbox_ec.make_skbox_ec_server(my_socket_root + '/00004_00443', servers[0]);
servers.unshift(skbox_ec_make_server(new endpoint.Endpoint().setDomain('github.com').setPort(443)));
skbox_ec.make_skbox_ec_server(my_socket_root + '/00005_00443', servers[0]);
servers.unshift(skbox_ec_make_server(new endpoint.Endpoint().setDomain('api.github.com').setPort(443)));
skbox_ec.make_skbox_ec_server(my_socket_root + '/00006_00443', servers[0]);
servers.unshift(skbox_ec_make_server(new endpoint.Endpoint().setDomain('acme-staging-v02.api.letsencrypt.org').setPort(443)));
skbox_ec.make_skbox_ec_server(my_socket_root + '/00007_00443', servers[0]);
servers.unshift(skbox_ec_make_server(new endpoint.Endpoint().setDomain('matrix-b.srv.peterjin.org').setPort(443)));
skbox_ec.make_skbox_ec_server(my_socket_root + '/00008_00443', servers[0]);
servers.unshift(skbox_ec_make_server(new endpoint.Endpoint().setDomain('registry.npmjs.org').setPort(443)));
skbox_ec.make_skbox_ec_server(my_socket_root + '/00009_00443', servers[0]);
