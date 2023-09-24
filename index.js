'use strict';
/* This file is public domain. */
const A = require('./src');
function start_app(env, env2) {
	const ipv6_prefix = BigInt(env.ipv6_prefix || "0xfedb120045007800");
	const static_maps = env.static_maps;
	if (!static_maps) {
		if (env.static_maps_file) {
			static_maps = JSON.parse(fs.readFileSync(env.static_maps_file));
		} else {
			static_maps = {};
		}
	}
	const ipv4_handler_default = A.app_func.make_ipv4_handler_bindable.bind({
		new_iid_offset: BigInt(env.ipv4_iid_offset || "0x5ff700100010000"),
		mask: BigInt(env.ipv4_mask || "0xffffffff"),
		net: BigInt(env.ipv4_net || "0x0"),
		socks_iidl: BigInt(env.socks_iidl || "0"),
		sni_iidl: BigInt(env.sni_iidl || "1")
	});
	const dns_raw = (d, ds, ep) => A.mdns.systemd_resolve(ds, null, true, ep);
	const dns_cache = A.dns_he.make_resolver_with_cache(dns_raw, 100);
	const dns_cache_resolve = (...a) => dns_cache.resolve(...a);
	const app = new A.app_func.TransparentHandler({prefix: ipv6_prefix, static_maps: static_maps, ipv4_handler: ipv4_handler_default});
	const default_cad_options = {
		dns_filter: function (dns_array) {
			/* to be filled out by user */
			return dns_array;
		},
		app: app,
		special_domain: new A.endpoint.Endpoint().setDomain("u-relay.home.arpa"),
		dns: dns_cache_resolve
	};
	const domain_handler = A.sys_utils.make_domain_handler();
	async function common_at_domain(ep) {
		return domain_handler(ep, default_cad_options);
	}
	const socks_server = A.sys_utils.make_server_simple((ep, cra, s) => common_at_domain(ep), {socks: true}, null, []);
	const ttd_config = {
		socks_server: socks_server
	};
	async function trans_server(forced_iid_port, ep, cra, s) {
		let iid_info = forced_iid_port;
		if (!iid_info) {
			let ep_cra = A.endpoint.fromCRAreq(cra.req);
			let match_ipv6_prefix = ep_cra.getHostNR(ipv6_prefix << 64n, 64);
			let match_ipv4 = ep_cra.getHostNR(0xffff00000000n, 96);
			if (match_ipv4 >= 0n) {
				match_ipv6_prefix = match_ipv4 | 0x5ff700700000000n;
			}
			if (match_ipv6_prefix < 0n) throw new Error();
			iid_info = [match_ipv6_prefix, ep_cra.getPort()];
		}
		const ttd_result = await A.app_func.handle_reinject_loop(app, ttd_config, s, iid_info[0], iid_info[1]);
		if (!ttd_result) throw new Error();
		return await common_at_domain(ttd_result);
	}
	// const main_server = A.sys_utils.make_server_simple(trans_server.bind(null, null), {forced_endpoint: null}, env2.listen_main, []);
	return function(forced_iid, extra_opts) {
		return A.sys_utils.make_server_simple(trans_server.bind(null, forced_iid), {forced_endpoint: null, ...extra_opts}, null, []);
	}
}
