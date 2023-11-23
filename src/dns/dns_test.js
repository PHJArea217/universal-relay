const dns_packet = require('./dns_packet.js');
const dns_types = require('./dns_types.js');
const dns_server = require('./dns_server.js');
const domain_name = require('./domain_name.js');
const dgram = require('dgram');
let server = dgram.createSocket('udp4');
server.bind({address: '127.0.0.60', 'port': 5350});
let records = new Map();
records.set('1 2 ', [new dns_types.dns_types.NS(domain_name.from_text('.'), 1, 60, domain_name.from_text('ns1.test.example'))]);
records.set('1 28 www.example.com', [new dns_types.dns_types.AAAA(domain_name.from_text('www.example.com'), 1, 60, 0x26020806a003040e00000000abcd1234n)]);
records.set('1 15 www.example.com', [new dns_types.dns_types.MX(domain_name.from_text('www.example.com'), 1, 6, 123, domain_name.from_text('mx1.srv.peterjin.org'))]);
records.set('1 6 ', [new dns_types.dns_types.SOA(domain_name.from_text('.'), 1, 60, domain_name.from_text('ns1.test.example'), domain_name.from_text('hostmaster.test.example'), 1, 2, 3, 4, 5555)]);
records.set('3 16 version.bind', [new dns_types.dns_types.TXT(domain_name.from_text('version.bind'), 1, 65, ['Universal Relay experimental DNS server'])]);
server.on('message', async function(data, rinfo) {
	try {
		let rbuf = await dns_server.query_dns(data, async (qname, qtype, qclass) => {
			let d = qname.to_text();
			// console.log(d, qclass, qtype);
			let res = records.get(qclass + ' ' + qtype + ' ' + d);
			if (res) return {an: res, au: []};
			return {an: [], au: records.get('1 6 ')};
		});
		if (rbuf) server.send(rbuf, rinfo.port, rinfo.address);
	} catch (e) {
		console.log(e); // e.printStackTrace();
	}
});

