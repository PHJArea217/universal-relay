const dns_server = require('./dns/dns_server.js');
const dns_compat = require('./dns/dns_compat.js');
const dns_types = require('./dns/dns_types.js');
const sock_info = require('./sock_info.js');
const endpoint = require('./endpoint.js');
exports.make_f_pdns_compat = async function(dns_overrideFunc, options, dn, qtype_str, qclass, flags, socket) {
	if (qclass !== 1) {
		if (qclass === 3) {
			if (['ANY', 'TXT'].includes(qtype_str)) {
				switch(dn) {
					case 'version.bind':
						return [{
							qtype_class: dns_types.dns_types.TXT,
							rrdata: [['Universal Relay DNS server']]
						}];
				}
			}
		}
		return [];
	}
	let domain_ep = null;
	try {
		domain_ep = new endpoint.Endpoint().setDomain2(dn, false);
	} catch (e) {
		domain_ep = new endpoint.Endpoint().setDomain('invalid');
	}
	let ipv6_prefix = options.ipv6_prefix;
	if (options.auto_ipv6_prefix) {
		try {
			let si = sock_info.get_sock_info(socket, false);
			if (si && si.vi) /* exists and > 0n */{
				ipv6_prefix = si.vi >> 64n;
			} else {
				let sl = endpoint.ofLocal(socket);
				let v = sl.getIPBigInt() >> 64n;
				if (v > 0n) ipv6_prefix = v;
			}
		} catch (e) {
		}
	}
	let dof_result = await dns_overrideFunc(domain_ep.getDomain(), domain_ep, [options.dof_arg, null, null, 1, {orig_qname: dn, orig_qtype: qtype_str}]);
	if (domain_ep.ip_) {
		let ipv4 = domain_ep.getHostNR(0xffff00000000n, 96);
		if (ipv4 >= 0n) return (['ANY', 'A'].includes(qtype_str)) ? [{qtype_class: dns_types.dns_types.A, rrdata: [ipv4]}] : [];
		return (['ANY', 'AAAA'].includes(qtype_str)) ? [{qtype_class: dns_types.dns_types.AAAA, rrdata: [domain_ep.getIPBigInt()]}] : [];
	}
	let r = [];
	if (Array.isArray(dof_result)) {
		let do_aaaa = false;
		for (let v of dof_result) {
			if (v === null) {
				do_aaaa = true;
			} else if (v) {
				if (typeof v === 'string') {
					v = {qtype: 'AAAA', content: v};
				}
				if (['ANY', (v.qtype === 'URELAY-A6-SYNTH') ? 'AAAA' : v.qtype].includes(qtype_str)) {
					let vr = dns_compat.convert_pdns({ipv6_prefix: ipv6_prefix}, v);
					if (vr) r.push(vr);
				}
			}
		}
		if (!do_aaaa) return r;
	}
	if ((!options.staticOnly) && (!domain_ep.getSubdomainsOf(['invalid'], 1))) {
		if (['AAAA', 'ANY'].includes(qtype_str)) {
			let transhe_result = options.ip_domain_map.query_domain(domain_ep.getDomain());
			if (transhe_result) {
				let a = {qtype_class: dns_types.dns_types.AAAA,
					rrdata: [(ipv6_prefix << 64n)|(transhe_result.readBigUInt64BE(8))]
				};
				r.push(a);
			}
		}
	}
	return r;
}
			




