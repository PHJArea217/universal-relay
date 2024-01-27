const endpoint = require('./endpoint.js');
const sock_info = require('./sock_info.js');
function get_map_func(init_entry, init_val) {
	while (Array.isArray(init_entry)) {
		let new_entry = init_entry[1].get(init_entry[0](init_val));
		if (new_entry === undefined) new_entry = init_entry[1].get(undefined); // default value
		init_entry = new_entry;
	}
	return init_entry;
}

async function get_endpoint(init_entry, init_val, orig_socket) {
	while (true) {
		let mf = get_map_func(init_entry, init_val);
		if (typeof mf === 'function') {
			let mf_res = await mf(init_val, orig_socket);
			if (mf_res) {
				switch (mf_res.t) {
					case 1:
						return mf_res.v;
					case 2:
						init_val = mf_res.v;
						continue;
				}
			}
		}
		return null;
	}
}
function ip_smo(s, m, o, v) {
	return ((v[0] >> s) & m) + o;
}
function ep_of(domain_or_ip, port, tag) {
	if ((typeof domain_or_ip === 'object') && (domain_or_ip instanceof endpoint.Endpoint)) {
		let e = domain_or_ip.clone();
		if (tag !== undefined) e.options_map_.set('!intfunc_tag', tag);
		return {t: 1, v: e};
	}
	let e = new endpoint.Endpoint();
	if (typeof domain_or_ip === 'bigint') e.setIPBigInt(domain_or_ip);
	else if (typeof domain_or_ip === 'string') e.setDomain(domain_or_ip);
	else throw new Error(String(domain_or_ip) + ' is not a domain name or IP');
	e.setPort(port);
	if (tag !== undefined) e.options_map_.set('!intfunc_tag', tag);
	return {t: 1, v: e};
}
function ep_rij(f, fthis, tag) {
	let e = new endpoint.Endpoint();
	e.options_map_.set('!intfunc_tag', tag);
	e.options_map_.set('!reinject_func', function(sock) { sock_info.get_sock_info(sock, true).tag = tag; f.call(fthis, sock);});
	return {t: 1, v: e};
}
function handle_relay_map(s, m, o, i2d, v) {
	let idx = ip_smo(s, m, o, v);
	let rm_result = i2d.get(idx) || (Number.isSafeInteger(idx) ? i2d.get(Number(idx)) : null);
	if (rm_result) return ep_of(rm_result, v[1], v[2]);
	return null;
}
function handle_trans(s, m, o, v) {
	return ep_of(ip_smo(s, m, o, v), v[1], v[2]);
}
function handle_gs32(v) {
	return ep_of(`i-hx-${ip_smo(32n, 0xffffn, 0n, v)}-${ip_smo(0n, 0xffffffffn, 0n, v)}.u-relay.home.arpa`, v[1], v[2]);
}
function handle_gs16(v) {
	return ep_of(`i-hx-s${ip_smo(16n, 0xffffn, 0n, v)}-${ip_smo(0n, 0xffffn, 0n, v)}.u-relay.home.arpa`, v[1], v[2]);
}
function handle_transhe(s, m, o, idm, v) {
	let idx = ip_smo(s, m, o, v);
	if (idx < 0n) return null;
	let map_result = idm.get(idx);
	if (map_result) return ep_of(map_result, v[1], v[2]);
	return null;
}
function handle_i4w_sni(options, v, s) {
	switch (v[1]) {
		case 80: // would include 8080, but speedtest needs HTTPS on port 8080
			return options.nginx_ep ? ep_of(options.nginx_ep, null, v[2]) : null;
		default:
			let sni_result = await sys_utils.read_sni(s);
			if (sni_result) {
				if (sni_result.hostname) {
					return ep_of(sni_result.hostname, v[1], v[2]);
				}
			}
			return null;
	}
}
function handle_i4w_socks(options, v, s) {
	function do_server(server, need_resume, sock) {
		if (server) {
			return ep_rij(function(sock) {
				if (need_resume) sock.resume();
				server.emit('connection', sock);
			}, {}, v[2]);
		}
		return null;
	}
	switch (v[1]) {
		case 53:
			return do_server(options.app.dns_tcp_server, false, s);
			break;
		case 80:
			return do_server(options.app.web_app_http, true, s);
			break;
		case 443:
			return do_server(options.app.web_app_https, true, s);
			break;
		case 853:
			return do_server(options.app.dns_tls_server, false, s);
			break;
		case 1080:
			return do_server(options.app.socks_server, false, s);
			break;
		case 1081:
			return do_server(options.app.socks_server_ssl, false, s);
			break;
		case 8081:
			if (si.already_tproxy) return null;
			else {
				let pp2_result = await sys_utils.read_pp2(s);
				if (pp2_result) {
					if (pp2_result.localEndpoint) {
						let lep = pp2_result.localEndpoint;
						si.already_tproxy = true;
						si.vi = lep.getIPBigInt();
						return {t:2,v:[lep.getIPBigInt() & 0xffffffffffffffffn, lep.getPort(), v[2]]};
					}
				}
			}
			break;
		case 8082:
			let pp2_result2 = await sys_utils.read_pp2(s);
			if (pp2_result2) {
				if (pp2_result2.localEndpoint) {
					if (typeof pp2_result2.authority === 'string') {
						try {
							let ne = pp2_result2.localEndpoint.clone().setDomain(pp2_result2.authority);
							return ep_of(ne.getDomainString() || ne.getIPBigInt(), ne.getPort(), v[2]);
						} catch (e) {
							return null;
						}
					}
					return ((a) => ep_of(a.getDomainString() || a.getIPBigInt(), a.getPort(), v[2]))(pp2_result2.localEndpoint);
				}
			}
			return null;
			break;
	}
	return null;
}
function handle_i4w(options, windows, smo, v, s) {
	let i = ip_smo(...smo, v);
	let mask = w.mask || -1n;
	let net = w.net || 0n;
	for (let w of windows) {
		if ((i & mask) === net) {
			let lower = i & ~mask;
			if (!w.extended) lower &= 0xffffffffn;
			let si = sock_info.get_sock_info(s, true);
			si.tag = w.tag || v[2];
			if (lower === w.socks_iidl) return handle_i4w_socks(options, [v[0], v[1], si.tag], s);
			else if (lower === w.sni_iidl) return handle_i4w_sni(options, [v[0], v[1], si.tag], s);
			else return {t:2,v:[w.new_iid_offset + lower, v[1], w.tag || v[2]]};
		}
	}
	return null;
}
function make_static_region_map(options) {
	const l2_map = new Map([
		[0x6464n, handle_trans.bind({}, 0n, 0xffffffffn, 0xffff00000000n)],
		[0x7001n, handle_relay_map.bind({}, 0n, 0xffffffffn, 0n, options.relay_map_i2d)],
		[0x7003n, handle_gs16],
		[0x7007n, handle_i4w.bind({}, options, options.ipv4_windows, [0n, 0xffffffffn, 0n])]
	]);
	const l1_map = new Map([
		[undefined, handle_transhe.bind({}, 0n, 0xffffffffffffffffn, -0x600_0000_0000_0000n, options.transhe_idm)],
		[0x5fen, handle_gs32],
		[0x5ffn, [ip_smo.bind({}, 32n, 0xffffn, 0n), l2_map]]
	]);
	return [ip_smo.bind({}, 48n, 0xffffn, 0n), l1_map];
}
