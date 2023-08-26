const endpoint = require('./endpoint.js');
const fake_dns = require('./fake_dns.js');
const express = require('express');
var app = express();
var isEmptyArray = (x) => (x && (x.length === 0));
var dns_server = fake_dns.make_urelay_ip_domain_map(0x100000000000000n, function (domain_labels, ep, xargs) {
	if (xargs[3] === 2) {
		switch (ep.getDomainString()) {
			case "example.com":
			case "example.org":
			case "sub1.example.net":
			case "sub2.example.net":
			case "sub3.example.net":
			case "sub4.example.net":
				return {PRESIGNED: ['0']};
		}
		return {};
	}
	return ep.getSubdomainsOfThen(['com', 'example'], Infinity, function (result, ep2) {
		if (result.length === 0) {
			return [
				{qtype: 'SOA', content: 'ns1.example.com. dns-admin.example.com. 1 10000 10000 10000 60'},
				{qtype: 'NS', content: 'ns1.example.com.'},
				{qtype: 'NS', content: 'ns2.example.com.'},
				{qtype: 'MX', content: '0 mailrelay.example.com.'},
				{qtype: 'A', content: '192.0.2.1'},
				{qtype: 'AAAA', content: '2001:db8::1'}
			];
		}
		switch (result[0]) {
			case 'ns1':
				if (result[1] === undefined) return [{qtype: 'A', content: '192.168.1.1'}, {qtype: 'AAAA', content: '2001:db8::10'}];
				if (result.length === 2) {
					switch (result[1]) {
						case '_acme-challenge':
							return [{qtype: 'TXT', content: '"Lets Encrypt DNS verification challenge string"'}];
					}
				}
				break;
			case 'ns2':
				if (result[1] === undefined) return [{qtype: 'A', content: '192.168.1.2'}, {qtype: 'AAAA', content: '2001:db8::11'}];
				if (result.length === 2) {
					switch (result[1]) {
						case '_acme-challenge':
							return [{qtype: 'TXT', content: '"Lets Encrypt DNS verification challenge string 2"'}];
					}
				}
				break;
			case 'mailserver':
				if (result[1] === undefined) return [{qtype: 'A', content: '192.168.1.3'}, {qtype: 'AAAA', content: '2001:db8::12'}];
				if (result.length === 2) {
					switch (result[1]) {
						case '_acme-challenge':
							return [{qtype: 'TXT', content: '"Lets Encrypt DNS verification challenge string 3"'}];
					}
				}
				break;
		}
		return [];
	}) || [];
}, {domainList: [
	{id: 1, zone: "example.com.", kind: "native"},
	{id: 2, zone: "example.org.", kind: "native"},
	{id: 3, zone: "sub1.example.net.", kind: "native"},
	{id: 4, zone: "sub2.example.net.", kind: "native"},
	{id: 5, zone: "sub3.example.net.", kind: "native"},
	{id: 6, zone: "sub4.example.net.", kind: "native"}
]});
dns_server.make_pdns_express_app(app, null, true);
app.listen({host: '127.0.0.10', port: 8181});
