'use strict';
/* To encourage modification of this file by end users, this file is public
 * domain and may be used and distributed without restriction. The LICENSE file
 * is not required to distribute, use, or modify this file. */
const misc_utils = require('./../misc_utils.js');
const epm_data = require('./domain_category_data.json');
const epm = new misc_utils.EndpointMap();
epm.addAll(epm_data);
exports.epm = epm;
exports.getCategory = (ep) => String(epm.getValue(ep, ""));
function dns_map_override(ep_cat) {
	switch (ep_cat) {
		case 'ntp':
			return [{'qtype': 'A', 'content': "192.0.2.1"}, {'qtype': 'AAAA', 'content': "2001:db8::1"}];
	}
}
function is_captive(ep_cat) {
	return ep_cat === 'captive'; // may trigger not using a VPN
}
exports.dns_map_override = dns_map_override;
// app.dns_overrideFunc = (domain_unused, ep, x) => (dns_map_override(ep) || app.dns_resolve(ep));
exports.is_captive = is_captive;
