'use strict';
const fake_dns = require('./fake_dns.js');
const endpoint = require('./endpoint.js');
const dns_helpers = require('./dns_helpers.js');
const dns_he = require('./dns_he.js');
const domain_parser = require('./domain_parser.js');
const express = require('express');
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
		let e = new endpoint.Endpoint().setPort(port);
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
		let sdp = domain_parser.urelay_handle_special_domain_part(sd_part, Object.hasOwn(this.config, 'allow_linklocal') ? this.config.allow_linklocal : true);
		if (sdp && sdp[0]) return (ep ? ep.clone() : new endpoint.Endpoint()).setIPStringWithScope(sdp[0]);
		let ep2 = ep.clone();
		let a = domain_parser.apply_groupsub_map(this.groupsub_map, sd_part, ep2);
		if (a) return ep2;
		return null;
	}
}
exports.TransparentHandler = TransparentHandler;
