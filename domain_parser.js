'use strict';
// const fake_dns = require('./fake_dns.js');
const net = require('net');
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
		for (let i = 4; i < special_part.length; i++) {
			let cc = special_part.charCodeAt(i);
			if ((cc >= 0x30) && (cc <= 0x39)) {
				result += '' + (cc - 0x30);
			} else if (cc === 0x2d) /* '-' */ {
				result += '.';
			} else {
				return [];
			}
		}
		if (net.isIPv4(result)) {
			return [result]; /* FIXME: canonicalization? */
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
exports.extractSubdomains = extractSubdomains;
exports.urelay_handle_special_domain = urelay_handle_special_domain;
exports.urelay_handle_special_domain_part = urelay_handle_special_domain_part;
exports.urelay_dns_override = urelay_dns_override;
