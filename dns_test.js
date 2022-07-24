const fake_dns = require('./fake_dns.js');
const endpoint = require('./endpoint.js');
const dns_helpers = require('./dns_helpers.js');
const express = require('express');
var domain_manager = dns_helpers.make_soa_ns_handler('ns1.test.example. test.test.example. 1 10000 10000 10000 120', ['ns1.test.example.', 'ns2.test.example.']);
domain_manager.addDomain('example.com');
domain_manager.addDomain('example.org');
domain_manager.addDomain('example.net');
domain_manager.addDomain('8.b.d.0.1.0.0.2.ip6.arpa');
domain_manager.addDomain('2.0.192.in-addr.arpa');
var acme_manager = dns_helpers.make_acme_challenge_handler();
var pdns_app = express();
var acme_app = express();
acme_app.use(express.urlencoded());
acme_manager.make_express_app(acme_app);
var example_com_records_map = new Map();
acme_manager.addKey('example.com');
acme_manager.addKey('*.example.com');
example_com_records_map.set('_acme-challenge', acme_manager.getAcmeChallengeTXTFunc(['example.com', '*.example.com']));
example_com_records_map.set('_domainkey|selector', [{qtype: "TXT", content: "v=DKIM1; k=rsa; p="}]);
example_com_records_map.set('_dmarc', [{qtype: "TXT", content: "v=DMARC1; p=reject;"}]);
example_com_records_map.set('', [null, {qtype: 'A', content: '192.0.2.1'}, {qtype: 'AAAA', content: '2001:db8::1'}, {qtype: "MX", content: "0 mail.example.com."}, {qtype: "TXT", content: "v=spf1 ip4:192.0.2.0/24 -all"}]);
var mapping = dns_helpers.make_lookup_mapping(example_com_records_map, null);
var m = fake_dns.make_urelay_ip_domain_map(0x100000000000000n, function(domain_parts, ep, extra_args) {
	if (extra_args[3] === 2) {
		if (domain_manager.getSOANS(ep).length > 0) return {"PRESIGNED": ['0']};
		return {};
	}
	let result = [];
	result.push(...(domain_manager.getSOANS(ep)));
	ep.getSubdomainsOfThen(['com', 'example'], Infinity, function (res, t) {
		let r = mapping.lookup(res.join('|'));
		if (r) {
			result.push(...r.rrset);
		}
	});
	return result;
}, {domainList: domain_manager.domainList});
m.make_pdns_express_app(pdns_app, null, true);
pdns_app.listen({host: '127.0.0.10', port: 8181});
acme_app.listen('/home/henrie/gitprojects/universal-relay/test/acme.sock');
