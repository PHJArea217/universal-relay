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
var m = fake_dns.make_urelay_ip_domain_map(0x100000000000000n, function(domain_parts, ep, extra_args) {
	if (extra_args[3] === 2) {
		if (domain_manager.getSOANS(ep).length > 0) return {"PRESIGNED": ['0']};
		return {};
	}
	let result = [];
	result.push(...(domain_manager.getSOANS(ep)));
	return result;
}, {domainList: domain_manager.domainList});
m.make_pdns_express_app(pdns_app, null, true);
pdns_app.listen({host: '127.0.0.10', port: 8181});
