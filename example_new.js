'use strict';
/* To encourage modification of this file by end users, this file is public
 * domain and may be used and distributed without restriction. The LICENSE file
 * is not required to distribute, use, or modify this file. */
const my_app = require('./src'); // require('/usr/local/lib/u-relay')
const dns = require('dns');
const fs = require('fs');
const domain_override = new my_app.misc_utils.EndpointMap();
const domain_handler = my_app.sys_utils.make_domain_handler();
const trans_ip_override = new my_app.misc_utils.EndpointMap();
/* CONFIG START */
const ipv6_prefix = BigInt(process.env["NETBUILDER_IPV6_PREFIX_BASE"] || 0) || 0xfedb120045007800n;
const app = new my_app.app_func.TransparentHandler({
	prefix: ipv6_prefix, // change as above
	static_maps: {} // load from JSON file
});
const default_options = {app: app, special_domain: new my_app.endpoint.Endpoint().setDomain('u-relay.home.arpa')};
async function common_at_domain(ep, options) {
	let ep_value = domain_override.getValue(ep);
	let override_options = {};
	if (ep_value) {
		override_options = await ep_value(ep, options);
	}
	return domain_handler(ep, Object.assign({}, default_options, override_options || {}));
}
function common_at_trans_ip(ep, s, options) {
	let ep_value = trans_ip_override.getValue(ep);
	if (ep_value) {
		return ep_value(ep, s, options);
	}
	return ep.getHostNRThen(ipv6_prefix << 64n, 64, (v, e) => app.transparent_to_domain(v, e.getPort()));
}
async function common_transparent_handler(ep_, cra, s, options, cad_override) {
	let ep = ep_.clone();
	if (options.read_pp2) {
		let pp2 = await my_app.sys_utils.read_pp2(s);
		if (pp2 && ('localEndpoint' in pp2)) {
			ep = pp2.localEndpoint;
		} else {
			return [];
		}
	}
	if (options.translate) {
		ep.setIPBigInt(options.translate[0] | (ep.getIPBigInt() & options.translate[1]));
	}
	let domain_ep = await common_at_trans_ip(ep, s, options);
	if (domain_ep) {
		if (cad_override) {
			return await cad_override(domain_ep, options);
		}
		return await common_at_domain(domain_ep, options);
	}
	return [];
}
async function common_socks_handler(ep_, cra, s, options) {
	let ep = ep_.clone();
	return await common_at_domain(ep, options);
}
// USER CONFIG STARTS HERE
// const my_dns = new dns.Resolver();
// my_dns.setServers(['127.0.0.53']);
// const my_dns_func = my_app.dns_he.make_endpoint_resolver(my_dns, 'all', null);
const my_dns_func = (d, ds, ep) => my_app.mdns.systemd_resolve(ds, null, true, ep);
const dns_cache = my_app.dns_he.make_resolver_with_cache(my_dns_func, 100);
/*
setInterval(() => {
	for (let [k, v] of dns_cache.cache.map.entries()) {
		console.log(k, v.future.ch)
	}}, 10000);
	*/
default_options.dns = dns_cache.resolve.bind(dns_cache);
default_options.dns_sort = {mode: "6_weak"};
let socks_server_reinject = my_app.sys_utils.make_server_simple(common_socks_handler, {socks: true}, null, [{}]);
let i_app = make_internal_express_app({ipv6_prefix: ipv6_prefix});
let i_app_http = http.createServer(i_app);
// let ssl_options = {cert: fs.readFileSync('i-app_cert.pem'), key: fs.readFileSync('i-app_key.pem')};
// let i_app_https = https.createServer(ssl_options, i_app);
let i_app_https = null;

function cad_override_enable_socks(ep, options) {
	if (ep.options_map_.has('reinject')) {
		switch (ep.options_map_.get('reinject')) {
			case 'socks':
				return {[my_app.dns_he.internal_function]: (s) => socks_server_reinject.emit('connection', s)};
			case 'i-http':
				return {[my_app.dns_he.internal_function]: (s) => i_app_http.emit('connection', s)};
			case 'i-https':
				if (i_app_https) {
					return {[my_app.dns_he.internal_function]: (s) => i_app_https.emit('connection', s)};
				}
				break;
		}
		throw new Error('unrecognized reinject value');
	}
	return common_at_domain(ep, options);
}
setImmediate(() => {
	app.expressApp.listen({fd:+process.env.CTRTOOL_NS_OPEN_FILE_FD_100});
	my_app.sys_utils.make_server_simple(common_transparent_handler, null, {fd:+process.env.CTRTOOL_NS_OPEN_FILE_FD_101}, [{}, cad_override_enable_socks]);
	let new_unix = (nr, nr_port, unix_path, opt) => my_app.sys_utils.make_server_simple(common_transparent_handler, {
		forced_endpoint: new my_app.endpoint.Endpoint().setIPBigInt((ipv6_prefix << 64n) | 0x5ff700000000000n | nr).setPort(nr_port),
		unix_path: unix_path
	}, null, [opt, cad_override_enable_socks]);
	let new_alt = (alt_listen) => my_app.sys_utils.make_server_simple(common_transparent_handler, null, alt_listen, [{translate: [(ipv6_prefix << 64n) | 0x5ff700000000000n, 0xffffn]}, cad_override_enable_socks]);
	// new_unix(0n, 1080, '/run/user/1000/skbox_ec/00001/00000_01080', {});
	// new_unix(1n, 443, '/run/user/1000/skbox_ec/00001/00001_00443', {});
	// new_unix(0n, 0, '/run/user/1000/skbox_ec/00001/generic.sock', {read_pp2: true});
	// new_alt({fd:+process.env.CTRTOOL_NS_OPEN_FILE_FD_102});
});
trans_ip_override.ip_map.setValueInGroup([(ipv6_prefix << 64n) | 0x5ff700000000000n, 96], async function(ep, s, options) {
	let ep_lower = ep.getIPBigInt() & 0xffffffffn;
	if (ep_lower === 0n) {
		switch (ep.getPort()) {
		case 1080:
			let ep_clone = ep.clone();
			ep_clone.options_map_.set('reinject', 'socks');
			return ep_clone.setIPBigInt(0n).setPort(0);
		case 80:
			let ep_clone = ep.clone();
			ep_clone.options_map_.set('reinject', 'i-http');
			return ep_clone.setIPBigInt(0n).setPort(0);
		case 443:
			let ep_clone = ep.clone();
			ep_clone.options_map_.set('reinject', 'i-https');
			return ep_clone.setIPBigInt(0n).setPort(0);
		}
	}
	else if (ep_lower === 1n) {
		switch (ep.getPort()) {
			case 80:
			case 8080:
				let ep_clone = ep.clone();
				ep_clone.options_map_.set('!unix_path', '/run/user/1000/nginx-http-helper.sock');
				return ep_clone.setIPBigInt(0n).setPort(0);
		}
		let sni = await my_app.sys_utils.read_sni(s);
		if (sni && sni.hostname) {
			return ep.clone().setDomain(sni.hostname);
		}
	}
	return app.transparent_to_domain(0x5ff700100000000n | ep_lower, ep.getPort());
});


