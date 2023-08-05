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
const mdns = require('./mdns.js');
const app = new app_func.TransparentHandler({static_maps: example_sm, prefix: 0xfedb120045007800n});
const dns = require('dns');
const net = require('net');
const misc_utils = require('./misc_utils.js');
const domain_level_filter = new misc_utils.EndpointMap();
domain_level_filter.addAll(example_sm.do_map || []);
const ip_level_filter = new misc_utils.EndpointMap();
ip_level_filter.addAll(example_sm.ip_map || []);
var my_dns = new dns.Resolver();
my_dns.setServers(['8.8.8.8']);
var my_dns_resolver = dns_he.make_endpoint_resolver(my_dns, 'all', null);
// Uses Node.js dns.lookup(), which calls libc getaddrinfo()
// var my_dns_resolver = mdns.make_libc_endpoint_resolver({all: true, flags: 0});
// Uses the systemd-resolved socket interface
// var my_dns_resolver = (d, ds, ep) => mdns.systemd_resolve(ds, null, true, ep);
// General mode of operation:
// Stage 1 -- The programmatic DNS server returns a randomly-generated "cookie" IPv6 address for the queried domain name.
// Stage 2 -- the "cookie" IPv6 address is transformed into the original domain name.
// Stage 3 -- The domain name is resolved into IP addresses and the Happy Eyeballs algorithm is used to connect to the domain name.
// Stage 4 -- The server and client sockets are piped in both directions, relaying information between each other.
// common_at_domain:
// 1. Check that the domain ends in u-relay.home.arpa. If so, then things like group substitution and ip4-/ip6- are parsed.
// 2. Check the domain name against the domain_level_filter (do_map in example-static-map.json), and if things are found,
// then they are applied. The DNS server may change due to this, or the default DNS server is used.
// 3. The domain name is resolved into IP addresses which are wrapped in IP address endpoints.
// 4. The IP addresses are individually checked against the ip_level_filter (ip_map in example-static-map.json)
// 5. The dns_sort function is called, reducing the number of IP addresses to check to 3 per IPv4/IPv6 and 5 in total.
// 6. The final remaining endpoints are converted into connReadAttributes to pass to Happy Eyeballs (it's a long story that has to do with compatibility reasons)
async function common_at_domain(ep) {
	let sd_domain = ep.getSubdomainsOf(['arpa', 'home', 'u-relay'], 1);
	if (sd_domain && sd_domain[0]) {
		let new_ep2 = app.special_domain_resolve(sd_domain[0], ep);
		if (!new_ep2) throw new Error();
		ep = new_ep2;
	}
	let epm_result = misc_utils.epm_apply(domain_level_filter, ep);
	let dns_resolver = my_dns_resolver;
	if (epm_result.action === 'delete') throw new Error();
	if (epm_result.dns_servers) {
		dns_resolver = dns_he.make_endpoint_resolver(misc_utils.make_epm_dns_resolver(epm_result), 'all', null);
	}
	let i = await ep.resolveDynamic(dns_resolver, {ipOnly: true});
	// i = i.flatMap(/* a function to filter, modify, or multiply IPs returned by DNS */);
	let filtered = [];
	for (let e of i) {
		let epm_result2 = misc_utils.epm_apply(ip_level_filter, e);
		if (epm_result2.action === 'delete') continue;
		// switch (e.options_map_.get("!user_category", "")) {}
		filtered.push(e);
	}
	i = dns_he.dns_sort(filtered, {mode: epm_result.dns_mode || '6_weak'});
	// return i.map(e => e.toCRAreq());
	let result = [];
	for (let e of i) {
		/* add info such as bind address, link local scope, or NAT64 prefix */
		result.push(e.toCRAreq());
	}
	return result;
}
var ts = server_generic.make_server(transparent_server.transparent_server, async (e, s) => {
	let ep = endpoint.fromCRAreq(e.req);
	let ep_iid = ep.getHostNR(0xfedb120045007800n << 64n, 64);
	// let ep_iid2 = ep.getHostNR(/* ipv4 prefix */);
	// if (ep_iid2 >= 0n) ep_iid = 0x5ff700101000000n /* offset */ + ep_iid2;
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
