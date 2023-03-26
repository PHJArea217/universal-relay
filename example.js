'use strict';
const net = require('net');
const endpoint = require('./endpoint.js');
const server_generic = require('./server_generic.js');
const socks_server = require('./socks_server.js');
const dns_he = require('./dns_he.js');
const domain_parser = require('./domain_parser.js');
const transparent_server = require('./transparent_server.js');
const fake_dns = require('./fake_dns.js');
const dns_helpers = require('./dns_helpers.js');
const express = require('express');
const dns = require('dns');
const my_dns_resolver = new dns.Resolver();
const domain_to_ip_static_map = new Map();
const ip_to_domain_static_map = new Map();
const domain_ip_special = require('./example-static-map.json');
const config = JSON.parse(process.argv[2] || '{}');
const user_hooks = require('./user_hooks.js');
(user_hooks.pre_init || (()=>0))(config, domain_ip_special);
for (let e of domain_ip_special.relay_map) {
	domain_to_ip_static_map.set(e[0], [false, e[1]]);
	ip_to_domain_static_map.set(e[1], e[0]);
}
for (let e of domain_ip_special.dns_map) {
	domain_to_ip_static_map.set(e[0], [true, e[1]]);
}
const hosts_map = new Map(domain_ip_special.hosts_map || []);
const resolve_map = new Map(domain_ip_special.resolve_map || []);
const gs_map = new Map(domain_ip_special.groupsub_map || []);
/* Set IP addresses of custom DNS servers. Universal Relay's fake_dns does not have a DNS cache, so it should be one that already has a cache, preferably a local server. */
my_dns_resolver.setServers(config.dns || ['8.8.8.8']);

/* Fake DNS server (PowerDNS backend)
 * Prefix argument corresponds to fedb:1200:4500:7800::/64
 */
const ipv6_prefix = BigInt(config.prefix || "0xfedb120045007800");
// const nat64_a = (new endpoint.Endpoint()).setIPBigInt((ipv6_prefix << 64n) | 0x5ff6464c00000aan).getIPString();
// const nat64_b = (new endpoint.Endpoint()).setIPBigInt((ipv6_prefix << 64n) | 0x5ff6464c00000abn).getIPString();
domain_to_ip_static_map.set("ipv4only.arpa", [true, [
	{qtype: "A", content: "192.0.0.170"},
	{qtype: "A", content: "192.0.0.171"},
	{qtype: "URELAY-A6-SYNTH", content: null, a6_synth: "0x5ff6464c00000aa"},
	{qtype: "URELAY-A6-SYNTH", content: null, a6_synth: "0x5ff6464c00000ab"}
]]);
async function domain_canonicalizer(ep) {
	if (await user_hooks.domain_canonicalizer(config, ep)) return;
	ep.getSubdomainsOfThen(['arpa', 'home', 'u-relay'], 1, (res, t) => {
		if (res[0]) t.setDomain(['arpa', 'home', 'u-relay', res[0]]);
	});
}
var ip_domain_map = fake_dns.make_urelay_ip_domain_map(ipv6_prefix, async (domain_unused, endpoint_object) => {
	await domain_canonicalizer(endpoint_object);
	let user_hook_result = await user_hooks.dns_map(config, endpoint_object, ipv6_prefix);
	if (user_hook_result) return user_hook_result;
	let override_ip = domain_to_ip_static_map.get(endpoint_object.getDomainString());
	let r_domain = [];
	let fallthrough = true;
	if (override_ip) {
		if (override_ip[0]) return override_ip[1];
		endpoint_object.setIPBigInt((ipv6_prefix << 64n) | (0x5ff700100000000n) | (BigInt(override_ip[1]) & 0xffffffffn));
		return undefined;
	}
	endpoint_object.getSubdomainsOfThen(['arpa', 'ip6'], 32, (res, t) => {
		fallthrough = false;
		let ip6_address = dns_helpers.handle_ip6_arpa(res);
		if (ip6_address < 0n) return;
		let ip6_ep = new endpoint.Endpoint().setIPBigInt(ip6_address);
		ip6_ep.getHostNRThen(ipv6_prefix << 64n, 64, (res2, t2) => {
			let result_array = [false];
			let r = ip_domain_map.query_ip(res2, result_array, 2);
			if (result_array[0]) {
				r_domain.push({qtype: 'PTR', content: (r === '.') ? '.' : (r + '.')});
			}
		});
	});
	if (fallthrough) {
		let udo_result = domain_parser.urelay_dns_override(endpoint_object.getDomain());
		if (udo_result) {
			r_domain.push(...udo_result);
		} else {
			r_domain.push(null);
		}
	}
	return r_domain;
});
var pdns_backend_app = express();
ip_domain_map.make_pdns_express_app(pdns_backend_app);

// ctrtool ns_open_file [...] -n -d inet -t stream -4 127.0.0.10,81,a [-N /path/to/private-side/network-namespace] [-U] [...] node example.js
// Can't do listen(3000) or similar due to the network namespace and IP_TRANSPARENT requirement!
if (config.pdns_fd !== false) pdns_backend_app.listen(config.pdns_fd || {fd: +process.env.CTRTOOL_NS_OPEN_FILE_FD_10});

async function common_ip_rewrite(my_cra, my_socket, is_transparent) {
	/* Recover the domain if the transparent server was used */
	let rewrite_CRA_req_retval = -1n;
	let user_hook_state = {};
	let ep_pre_lookup = endpoint.fromCRAreq(my_cra.req);
	await user_hooks.pre_lookup(config, user_hook_state, ep_pre_lookup, my_socket, ipv6_prefix, is_transparent);
	let ep_host = ep_pre_lookup.getHostNR(ipv6_prefix << 64n, 64);
	if (ep_host >= 0n) {
		if (is_transparent) {
			rewrite_CRA_req_retval = ip_domain_map.rewrite_CRA_req(my_cra.req, 2, ep_host);
		} else if (ep_host < 0x600000000000000n) {
			rewrite_CRA_req_retval = ep_host;
		}
	}
	let my_endpoint = null;
	switch (rewrite_CRA_req_retval) {
		case -4n:
			/* Only allow the domain to be used if the transparent server (instead of the SOCKS server) is used */
			if (!is_transparent) throw new Error();
			/* my_cra.req changed after call to rewrite_CRA_req */
			my_endpoint = endpoint.fromCRAreq(my_cra.req);
			break;
		case -1n: /* not within the ipv6_prefix */
			my_endpoint = ep_pre_lookup;
			break;
		default:
			if (rewrite_CRA_req_retval >= 0n) {
				let major = (rewrite_CRA_req_retval >> 32n) & 0x7ffffffn;
				let minor = rewrite_CRA_req_retval & 0xffffffffn;
				switch (major) {
					case 0x5ff6464n:
						my_endpoint = (new endpoint.Endpoint()).setIPBigInt(0xffff00000000n | minor).setPort(my_cra.req.port);
						break;
					case 0x5ff7001n:
						let lookup_result = ip_to_domain_static_map.get(Number(minor));
						if (lookup_result) {
							my_endpoint = (new endpoint.Endpoint()).setDomain(lookup_result).setPort(my_cra.req.port);
						}
						break;
					case 0x5ff7002n:
						my_endpoint = (new endpoint.Endpoint()).setDomain(`i-host-${minor.toString(16)}.u-relay.home.arpa`).setPort(my_cra.req.port);
						break;
					case 0x5ff7003n:
						my_endpoint = (new endpoint.Endpoint()).setDomain(`i-hx-s${minor >> 16n}-${minor & 0xffffn}.u-relay.home.arpa`).setPort(my_cra.req.port);
						break;
					default:
						switch (major >> 16n) {
							case 0x5fen:
								my_endpoint = (new endpoint.Endpoint()).setDomain(`i-hx-${major & 0xffffn}-${minor}.u-relay.home.arpa`).setPort(my_cra.req.port);
								break;
							default:
								my_endpoint = await user_hooks.handle_static_region(config, user_hook_state, {major: major, minor: minor}, ep_pre_lookup);
								break;
						}
						break;
				}
			}
			break;
	}
	if (!my_endpoint) throw new Error();
	/* Resolve the domain name in the my_endpoint object, if it is a "domain" type */
	await domain_canonicalizer(my_endpoint);
	let no_resolve_dns = false;
	let pre_resolve_result = null;
	let special_result = my_endpoint.getSubdomainsOf(['arpa', 'home', 'u-relay'], 1);
	if (special_result) {
		no_resolve_dns = true;
		let res_str = String(special_result[0] || '');
		let res_ip = (await user_hooks.hosts_map(config, user_hook_state, res_str, my_endpoint)) || hosts_map.get(res_str) || domain_parser.urelay_handle_special_domain_part(res_str, true);
		if (res_ip) {
			if (!Array.isArray(res_ip)) res_ip = [res_ip];
			if (res_ip[0]) {
				my_endpoint.setIPStringWithScope(String(res_ip[0]));
			} else {
				throw new Error();
			}
		} else {
			pre_resolve_result = domain_parser.apply_groupsub_map(gs_map, res_str, my_endpoint);
		}
	}
	if (user_hooks.pre_resolve) {
		let pre_resolve_result2 = await user_hooks.pre_resolve(config, user_hook_state, my_endpoint);
		if (pre_resolve_result2 || (pre_resolve_result2 === false)) {
			pre_resolve_result = pre_resolve_result2;
		}
	}
	if (pre_resolve_result) {
		my_cra.req = pre_resolve_result.craReq || my_endpoint.toCRAreq();
		return pre_resolve_result.connFunc;
	}
	let resolvedIPEndpoints = await my_endpoint.resolveDynamic(async (domain_parts, domain_name, ep) => {
		let resolve_map_override = await user_hooks.resolve_map(config, user_hook_state, domain_name, ep) || resolve_map.get(domain_name);
		if (resolve_map_override) {
			return resolve_map_override;
		}
		if (no_resolve_dns) {
			return [];
		}
		return await dns_he.resolve_dns_dualstack(domain_name, my_dns_resolver, '6_weak', /*domain_parser.urelay_handle_special_domain*/ null);
	}, {ipOnly: true});
	let transform_all_result = (await user_hooks.transform_all_resolved_endpoints(config, user_hook_state, resolvedIPEndpoints, my_endpoint)) || {};
	let resultIPs = null;
	let override_client = null;
	if (transform_all_result.hasOwnProperty('override_ip_list')) {
		resolvedIPEndpoints = transform_all_result.override_ip_list;
	}
	if (transform_all_result.hasOwnProperty('override_result')) {
		resultIPs = transform_all_result.override_result;
	}
	if (transform_all_result.hasOwnProperty('override_client')) {
		override_client = transform_all_result.override_client;
	}
	if (!resultIPs) {
		resultIPs = [];
		for (let r of resolvedIPEndpoints) {
			/* NAT64 CLAT with well-known prefix 64:ff9b::/96 */
			// r.getHostNRThen(0xffff00000000n, 96, (res, t) => t.setIPBigInt(res | (0x64ff9bn << 96n)));
			await user_hooks.transform_resolved_endpoint(config, user_hook_state, r, my_endpoint);
			if (!r.domain_) resultIPs.push(r.toCRAreq());
		}
	}
	my_cra.req = resultIPs;
	return override_client;
}
var my_transparent_server = server_generic.make_server(transparent_server.transparent_server, (e, s) => common_ip_rewrite(e, s, true), dns_he.simple_connect_HE);
var my_socks_server = server_generic.make_server(socks_server.socks_server, (e, s) => common_ip_rewrite(e, s, false), dns_he.simple_connect_HE);
var transparent_server_obj = net.createServer({allowHalfOpen: true, pauseOnConnect: true}, my_transparent_server);
var socks_server_obj = net.createServer({allowHalfOpen: true, pauseOnConnect: true}, my_socks_server);
if (config.transparent_fd !== false) transparent_server_obj.listen(config.transparent_fd || {fd: +process.env.CTRTOOL_NS_OPEN_FILE_FD_11});
if (config.socks_fd !== false) socks_server_obj.listen(config.socks_fd || {fd: +process.env.CTRTOOL_NS_OPEN_FILE_FD_12});
(user_hooks.post_init || (()=>0))(config);
