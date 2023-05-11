'use strict';
// const fake_dns = require('./fake_dns.js');
const net = require('net');
const socks_server = require('./socks_server.js');
const endpoint = require('./endpoint.js');
function extractSubdomains(domain, suffix) {
	if (domain.length < suffix.length) return null;
	for (let i = 0; i < suffix.length; i++) {
		if (!(domain[i] === suffix[i])) {
			return null;
		}
	}
	return domain.slice(suffix.length);
}
function urelay_handle_special_domain_part(special_part, allow_linklocal) {
	if (special_part.startsWith('ip4-')) {
		let result = '';
		let linklocal_part = '';
		for (let i = 4; i < special_part.length; i++) {
			let cc = special_part.charCodeAt(i);
			if ((cc >= 0x30) && (cc <= 0x39)) {
				result += '' + (cc - 0x30);
			} else if (cc === 0x2d) /* '-' */ {
				result += '.';
			} else if ((allow_linklocal === 2) && (cc === 0x73)) /* 's' */ {
				linklocal_part = '%' + special_part.substring(i + 1);
				break;
			} else {
				return [];
			}
		}
		if (net.isIPv4(result)) {
			return [result + linklocal_part]; /* FIXME: canonicalization? */
		}
		return [];
	} else if (special_part.startsWith('ip6-')) {
		let result = '';
		let linklocal_part = '';
		for (let i = 4; i < special_part.length; i++) {
			let cc = special_part.charCodeAt(i);
			if ((cc >= 0x30) && (cc <= 0x39)) {
				result += '' + (cc - 0x30);
			} else if ((cc >= 0x61) && (cc <= 0x66)) {
				result += 'abcdef'.charAt(cc - 0x61);
			} else if (cc === 0x2d) /* '-' */ {
				result += ':';
			} else if (allow_linklocal && (cc === 0x73)) /* 's' */ {
				linklocal_part = '%' + special_part.substring(i + 1);
				break;
			} else {
				return [];
			}
		}
		if (net.isIPv6(result)) {
			return [result + linklocal_part];
		}
		return [];
	}
	return null;
}
function urelay_handle_special_domain(domain_parts, domainName_unused) {
	let subdomain_parts = extractSubdomains(domain_parts, ['arpa', 'home', 'u-relay']); /* u-relay.home.arpa */
	if (subdomain_parts === null) return null;
	if (subdomain_parts.length === 0 /* [] */) return [];
	let special_part = String(subdomain_parts[0]);
	return urelay_handle_special_domain_part(special_part, false) || [];
}
function urelay_dns_override(domain_parts) {
	if (extractSubdomains(domain_parts, ['local'])) return []; /* *.local (mDNS) */
	if (extractSubdomains(domain_parts, ['arpa', 'ipv4only'])) return []; /* ipv4only.arpa */
	if (extractSubdomains(domain_parts, ['arpa', 'in-addr'])) return []; /* in-addr.arpa */
	if (extractSubdomains(domain_parts, ['arpa', 'ip6'])) return []; /* ip6.arpa TODO: generate PTR records for primary ip->domain map */
	if (extractSubdomains(domain_parts, ['net', 'use-application-dns'])) return []; /* use-application-dns.net */
	if (extractSubdomains(domain_parts, ['localhost'])) return ['::1', {'qtype': 'A', 'content': '127.0.0.1'}];
	return null;
}
function extract_groupsub_strings(domain_part) {
	return String(domain_part).match(/^i-hx-([^-]+)-(.*)$/);
}
function apply_groupsub(groupsub_data, string2, ep) {
	if (groupsub_data.ip_subst) {
		let groupsub_prefix = groupsub_data.__cache__prefix || endpoint.ofPrefix(groupsub_data.ip_subst);
		groupsub_data.__cache__prefix = groupsub_prefix;
		let groupsub_prefix_limit = 1n << (128n - groupsub_prefix[1]);
		let ip_val = -1n;
		try {
			let string2_bigint = BigInt(string2);
			if ((string2_bigint >= 0n) && (string2_bigint < groupsub_prefix_limit)) {
				ip_val = groupsub_prefix[0] | string2_bigint;
			}
		} catch (e) {
			return null;
		}
		if (ip_val >= 0n) ep.setIPBigInt(ip_val);
	}
	if (groupsub_data.domain_subst)
		ep.setDomain(groupsub_data.domain_subst.replaceAll('#', string2));
	for (let m of ['', '4', '4m', '6']) {
		if (groupsub_data.hasOwnProperty('bind_addr' + m)) {
			ep.options_map_.set('!bind_addr' + m, groupsub_data['bind_addr' + m]);
		}
	}
	if (groupsub_data.ipv6_scope)
		ep.options_map_.set('!ipv6_scope', groupsub_data.ipv6_scope);
	if (groupsub_data.__cache__socks) {
		return {client: groupsub_data.__cache_socks};
	}
	if (groupsub_data.socks_server) {
		let cached_socks_server = socks_server.make_socks_client(groupsub_data.socks_server);
		groupsub_data.__cache__socks = cached_socks_server;
		return {client: cached_socks_server};
	}
	return {client: null}; /* change IP address or domain, but not upstream interface */
}
function apply_groupsub_map(gs_map, domain_part, ep) {
	let groupsub_strings = extract_groupsub_strings(domain_part);
	if (groupsub_strings) {
		let gs_map_result = gs_map.get(groupsub_strings[1]);
		if (gs_map_result) {
			let groupsub_result = apply_groupsub(gs_map_result, groupsub_strings[2], ep);
			if (groupsub_result) return {connFunc: groupsub_result.client};
		}
	}
	return null;
}
exports.extractSubdomains = extractSubdomains;
exports.urelay_handle_special_domain = urelay_handle_special_domain;
exports.urelay_handle_special_domain_part = urelay_handle_special_domain_part;
exports.urelay_dns_override = urelay_dns_override;
exports.extract_groupsub_strings = extract_groupsub_strings;
exports.apply_groupsub = apply_groupsub;
exports.apply_groupsub_map = apply_groupsub_map;
