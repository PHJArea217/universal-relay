'use strict';
const fake_dns = require('./fake_dns.js');
const endpoint = require('./endpoint.js');
const dns_helpers = require('./dns_helpers.js');
const dns_he = require('./dns_he.js');
const domain_parser = require('./domain_parser.js');
const express = require('express');
const sys_utils = require('./sys_utils.js');
class TransparentHandler {
	constructor(config) {
		if (config.static_maps) {
			this.relay_bidir_map = config.static_maps.relay_bidir_map || dns_helpers.make_bidir_map(config.static_maps.relay_map || [], {entry1_transform: x => BigInt(x)});
			this.dns_map = new Map(config.static_maps.dns_map || []);
			this.groupsub_map = new Map(config.static_maps.groupsub_map || []);
		} else {
			this.relay_bidir_map = null;
			this.dns_map = new Map();
			this.groupsub_map = new Map();
		}
		this.config = config;
		this.dns_overrideFunc = async (domain_array, ep, x_args) => {
			return this.dns_resolve(ep);
		}
		this.prefix = config.prefix || 0x100000000000000n;
		this.ip_domain_map = fake_dns.make_urelay_ip_domain_map(this.prefix, async (d, e, x) => {
			return await this['dns_overrideFunc'](d, e, x);
		}, config.idm_config);
		let app = express();
		this.ip_domain_map.make_pdns_express_app(app, this, false);
		this.expressApp = app;
	}
	dns_resolve(ep) {
		let result = [];
		let dns_map_result = this.dns_map.get(ep.getDomainString());
		if (dns_map_result) {
			let c = true;
			for (let e of dns_map_result) {
				if (!e) c = false;
				result.push(e);
			}
			if (c) return result;
		}
		if (this.relay_bidir_map) {
			let rm_result = this.relay_bidir_map.translate_forward(ep.getDomainString());
			if (rm_result) {
				result.push({qtype: "URELAY-A6-SYNTH", content: null, a6_synth: 0x5ff700100000000n | rm_result[0]});
			}
		}
		if (!this.config.disable_rdns) {
			let ip6_arpa_result = ep.getSubdomainsOf(['arpa', 'ip6'], 33);
			if (ip6_arpa_result) {
				let ip_parsed = dns_helpers.handle_ip6_arpa(ip6_arpa_result);
				if (ip_parsed >= 0n) {
					if (this.config.rdns_parser) {
						result.push(...this.config.rdns_parser(ip_parsed));
					} else {
						let s = [false];
						let d_result = this.ip_domain_map.query_ip(ip_parsed, s, 1);
						if (s[0]) {
							if (!d_result.endsWith('.')) d_result = d_result + '.';
							result.push({qtype: 'PTR', content: d_result});
						}
					}
				}
			}
		}
		let final1 = domain_parser.urelay_dns_override(ep.getDomain());
		/*
		 * If we found anything by one or more of the methods above, then dynamic
		 * domain mapping results are disabled, unless null was set as one of the
		 * elements of the array.
		 */
		if (result.length === 0) {
			return final1 || [null];
		} else {
			result.push(...(final1 || []));
		}
		return result;
	}
	transparent_to_domain(iid, port, special_domain_) {
		let special_domain = special_domain_ || 'u-relay.home.arpa';
		let tag = {};
		/* The IPv4 window could rewrite iid to reference another region, so check that first */
		if ((iid >> 32n) === 0x5ff7007n) {
			if (this.config.ipv4_handler) {
				let ipv4_result = this.config.ipv4_handler(iid & 0xffffffffn, port, special_domain);
				// can be one of null, Endpoint, or [iid, port]
				if (Array.isArray(ipv4_result)) {
					iid = ipv4_result[0];
					port = ipv4_result[1] || port;
					if ('2' in ipv4_result) {
						tag.tag = ipv4_result[2];
					}
				} else if (typeof ipv4_result === 'object') { // includes null
					return ipv4_result;
				} else {
					return null;
				}
			}
		}
		let e = new endpoint.Endpoint().setPort(port);
		if ('tag' in tag) e.options_map_.set('!intfunc_tag', tag.tag);
		let c = endpoint.addressChomper(iid, 64n);
		switch (c.chomp(16n)) {
			case 0x5fen:
				let h = c.chomp(16n);
				let l = c.chomp(32n);
				return e.setDomain2(`i-hx-{h}-{l}.{special_domain}`, false);
			case 0x5ffn:
				switch (c.chomp(16n)) {
					case 0x7001n:
						if (this.relay_bidir_map) {
							let rm_result = this.relay_bidir_map.translate_reverse(c.chomp(32n));
							return rm_result ? e.setDomain2(rm_result[0], true) : null;
						}
						break;
					case 0x7003n:
						let h = c.chomp(16n);
						let l = c.chomp(16n);
						return e.setDomain2(`i-hx-s{h}-{l}.{special_domain}`, false);
					case 0x6464n:
						return e.setIPBigInt(0xffff00000000n | c.chomp(32n));
				}
				break;
		}
		let s = [false];
		let d = this.ip_domain_map.query_ip(iid, s, 2);
		if (s[0]) return e.setDomain2(d, true);
		return null;
	}
	special_domain_resolve(sd_part, ep) {
		let sdp = domain_parser.urelay_handle_special_domain_part(sd_part, ('allow_linklocal' in this.config) ? this.config.allow_linklocal : true);
		if (sdp && sdp[0]) return (ep ? ep.clone() : new endpoint.Endpoint()).setIPStringWithScope(sdp[0]);
		let ep2 = ep.clone();
		let a = domain_parser.apply_groupsub_map(this.groupsub_map, sd_part, ep2);
		if (a) return ep2;
		return null;
	}
}
function make_ipv4_handler_bindable(iid, port) {
	let obj = this || {};
	let mask = obj.mask || -1n;
	let match_net = obj.net || 0n;
	if ((iid & mask) === obj.net) {
		let iid_lower = iid & 0xffffffffn & (~mask);
		if (iid_lower === obj.socks_iidl) {
			let reinject_endpoint = new endpoint.Endpoint();
			let service = 'other';
			switch (port) {
				case 1080:
					service = 'socks';
					break;
				case 8081:
					service = 'tproxy';
					break;
				case 8082:
					service = 'tproxy-real';
					break;
			}
			reinject_endpoint.options_map_.set('!intfunc', Object.freeze(['reinject', 0, service, port]));
			reinject_endpoint.options_map_.set('!intfunc_tag', obj.tag);
			return reinject_endpoint;
		}
		else if (iid_lower === obj.sni_iidl) {
			let reinject_endpoint = new endpoint.Endpoint();
			reinject_endpoint.options_map_.set('!intfunc', Object.freeze(['reinject', 1, [80, 8080].includes(port) ? 'http-host' : 'tls-sni', port]));
			reinject_endpoint.options_map_.set('!intfunc_tag', obj.tag);
			return reinject_endpoint;
		} else {
			return [obj.new_iid_offset + iid_lower, port, obj.tag];
		}
	}
	return null;
}
async function handle_reinject_endpoint_bindable(last, ep, s, tag) {
	let a = ep.options_map_.get('!intfunc');
	let effective_tag = tag || ep.options_map_.get('!intfunc_tag');
	function set_tag(_ep) {
		if (effective_tag) _ep.options_map_.set('!intfunc_tag', effective_tag);
		return _ep;
	}
	if (a) {
		if (a[0] === 'reinject') {
			switch (a[2]) {
				case 'http-host':
					return this.nginx_ep ? set_tag(this.nginx_ep.clone()) : null;
				case 'socks':
					let ss = this.socks_server;
					if (this.socks_server_by_tag) {
						ss = ((typeof effective_tag === 'string') && Object.prototype.hasOwnProperty.call(this.socks_server_by_tag, effective_tag)) ? this.socks_server_by_tag[effective_tag] : this.socks_server;
					}
					if (ss) {
						ep.options_map_.set('!reinject_func', (function(sock) {
							this.emit('connection', sock);
						}).bind(this.socks_server));
						return set_tag(ep);
					}
					return null;
				case 'tls-sni':
					let sni_result = await sys_utils.read_sni(s);
					if (sni_result) {
						if (sni_result.hostname) {
							return set_tag(new endpoint.Endpoint().setPort(a[3]).setDomain(sni_result.hostname));
						}
					}
					return null;
				case 'tproxy-real':
					let pp2_result2 = await sys_utils.read_pp2(s);
					if (pp2_result2) {
						if (pp2_result2.localEndpoint) {
							return set_tag(pp2_result2.localEndpoint);
						}
					}
					return null;
				case 'tproxy':
					if (last === 'tproxy') return null;
					let pp2_result = await sys_utils.read_pp2(s);
					if (pp2_result) {
						if (pp2_result.localEndpoint) {
							let lep = pp2_result.localEndpoint;
							return [lep.getIPBigInt() & 0xffffffffffffffffn, lep.getPort(), 'tproxy', effective_tag];
						}
					}
					return null;
			}
			return null;
		}
	}
	return set_tag(ep.clone());
}
// Order of priority for the resultant endpoint's tag:
// tag argument to this function (if truthy)
// curr[3] (set by tproxy intfunc)
// tag set by handle_reinject_endpoint_bindable (for other internal functions) or transparent_to_domain (for relay_map)
async function handle_reinject_loop(app, c, s, iid, port, special_domain, tag) {
	let curr = [iid, port, null, tag];
	while (true) {
		let ttd_result = app.transparent_to_domain(curr[0], curr[1], special_domain); // endpoint tag (om !intfunc_tag) not overridden. can return either a normal or reinjective endpoint.
		if (!(ttd_result instanceof endpoint.Endpoint)) return ttd_result;
		let reinject_result = await handle_reinject_endpoint_bindable.call(c, curr[2], ttd_result, s, curr[3]); // endpoint tag is overridden (forced) if curr[3] is truthy. otherwise, original tag from ttd_result is used.
		if (Array.isArray(reinject_result)) {
			curr = reinject_result;
			continue;
		}
		return reinject_result;
	}
}
exports.TransparentHandler = TransparentHandler;
exports.make_ipv4_handler_bindable = make_ipv4_handler_bindable;
exports.handle_reinject_loop = handle_reinject_loop;
exports.handle_reinject_endpoint_bindable = handle_reinject_endpoint_bindable;
