const endpoint = require('./endpoint.js');

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
	let e = new endpoint.Endpoint();
	if (typeof domain_or_ip === 'bigint') e.setIPBigInt(domain_or_ip);
	else if (typeof domain_or_ip === 'string') e.setDomain(domain_or_ip);
	else throw new Error(String(domain_or_ip) + ' is not a domain name or IP');
	e.setPort(port);
	if (tag !== undefined) e.options_map_.set('!intfunc_tag', tag);
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
function make_static_region_map(options) {
	const l2_map = new Map([
		[0x6464n, handle_trans.bind({}, 0n, 0xffffffffn, 0xffff00000000n)],
		[0x7001n, handle_relay_map.bind({}, 0n, 0xffffffffn, 0n)],
		[0x7003n, handle_gs16],
		[0x7007n, /* handle_i4w */]
	]);
	const l1_map = new Map([
		[undefined, handle_transhe.bind({}, 0n, 0xffffffffffffffffn, -0x600_0000_0000_0000n)],
		[0x5fen, handle_gs32],
		[0x5ffn, [ip_smo.bind({}, 32n, 0xffffn, 0n), l2_map]]
	]);
	return [ip_smo.bind({}, 48n, 0xffffn, 0n), l1_map];
}
