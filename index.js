'use strict';
/* This file is public domain. */
const A = require('./src');
const fs = require('fs');
const util = require('util');
function start_app(env, env2) {
	const ipv6_prefix = BigInt(env.ipv6_prefix || "0xfedb120045007800");
	let static_maps = env.static_maps;
	if (!static_maps) {
		if (env.static_maps_file) {
			static_maps = JSON.parse(fs.readFileSync(env.static_maps_file));
		} else {
			static_maps = {};
		}
	}
	const ipv4_handlers = [];
	if (Array.isArray(env.ipv4_handlers)) {
		for (let h of env.ipv4_handlers) {
			ipv4_handlers.unshift(A.app_func.make_ipv4_handler_bindable.bind({
				new_iid_offset: BigInt(h.ipv4_iid_offset || "0x5ff700100010000"),
				mask: BigInt(h.ipv4_mask || "0xffffffff"),
				net: BigInt(h.ipv4_net || "0x0"),
				socks_iidl: BigInt(h.socks_iidl || "0"),
				sni_iidl: BigInt(h.sni_iidl || "1"),
				tag: h.tag || null
				/* tag visible in ttd_result.options_map_.get('!intfunc_tag') */
			}));
		}
	}
	const dns_raw = (d, ds, ep) => A.mdns.systemd_resolve(ds, null, true, ep);
	const dns_cache = A.dns_he.make_resolver_with_cache(dns_raw, 100);
	const dns_cache_resolve = (...a) => dns_cache.resolve(...a);
	const app = new A.app_func.TransparentHandler({
		prefix: ipv6_prefix,
		static_maps: static_maps,
		ipv4_handler: function (...args) {
			for (let v4h of ipv4_handlers) {
				let r = v4h(...args);
				if (r) return r;
			}
			return null;
		}
	});
	const default_cad_options = {
		dns_filter: function (dns_array) {
			/* to be filled out by user */
			return dns_array;
		},
		app: app,
		special_domain: new A.endpoint.Endpoint().setDomain("u-relay.home.arpa"),
		dns: dns_cache_resolve,
		dns_sort: env.dns_sort || {"mode": "6_weak"}
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
	let result = function(forced_iid, extra_opts) {
		return A.sys_utils.make_server_simple(trans_server.bind(null, forced_iid), {forced_endpoint: null, ...extra_opts}, null, []);
	}
	result.app = app;
	return result;
}
function main(ctx) {
	let args = util.parseArgs({args: ctx.argv.slice(2), options: {
		'opt': {'type': 'string', 'multiple': true, 'short': 'o'},
		'optjson': {'type': 'string', 'multiple': true, 'short': 'O'},
		'append': {'type': 'string', 'multiple': true, 'short': 'a'},
		'env': {'type': 'string', 'short': 'e', 'default': ""},
		'envenv': {'type': 'string', 'short': 'E', 'default': ""},
		'envfile': {'type': 'string', 'short': 'f', 'default': ""}
	}});
	let envobj = Object.create(null);
	let ienv = {};
	if (args.values.envfile) {
		ienv = JSON.parse(fs.readFileSync(args.values.envfile));
	} else if (args.values.envenv) {
		ienv = JSON.parse(String(ctx.env[args.values.envenv]));
	} else if (args.values.env) {
		ienv = JSON.parse(args.values.env);
	}
	for (let k of Object.keys(ienv)) {
		envobj[k] = ienv[k];
	}
	for (let oj of args.values.optjson) {
		let key = String(oj);
		let eq = key.indexOf('=');
		if (eq >= 0) {
			envobj[key.substring(0, eq)] = JSON.parse(key.substring(eq+1));
		}
	}
	for (let o of args.values.opt) {
		let key = String(o);
		let eq = key.indexOf('=');
		if (eq >= 0) {
			envobj[key.substring(0, eq)] = key.substring(eq+1);
		}
	}
	for (let o of args.values.append) {
		let key = String(o);
		let eq = key.indexOf('=');
		if (eq >= 0) {
			let a = envobj[key.substring(0, eq)];
			if (Array.isArray(a)) {
				a.push(JSON.parse(key.substring(eq+1)));
			}
		}
	}
	const app = start_app(envobj);
	if ('dns_listen_fdenv' in envobj) {
		app.app.expressApp.listen({fd: +ctx.env[envobj.dns_listen_fdenv]});
	} else if ('dns_listen' in envobj) {
		app.app.expressApp.listen(envobj.dns_listen);
	}
	for (let e of envobj.listeners || []) {
		let listener = app(e.forced_iid ? [BigInt(e.forced_iid[0]), Number(e.forced_iid[1])] : null, e.listener_opts || {});
		if ('fdenv' in e) listener.listen({fd: +ctx.env[e.fdenv]});
		else if ('l' in e) listener.listen(e.l);
	}
	for (let e of envobj.ntp_listeners || []) {
		if ('fdenv' in e) {
			A.sys_utils.make_ntp_server({fd: +ctx.env[e.fdenv]}, e.v);
		} else {
			A.sys_utils.make_ntp_server(e.l, e.v);
		}
	}
}
exports.main = main;
exports.start_app = start_app;
if (require.main === module) {
	main(process);
}
