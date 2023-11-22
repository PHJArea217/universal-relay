const dns_packet = require('./dns_packet.js');
const dns_types = require('./dns_types.js');
const domain_name = require('./domain_name.js');
exports.query_dns = async function(data, ifunc) {
	let decoded = dns_packet.read_dns_packet(data);
	if ((decoded.flags & 0xfb00) === 0x100) {
		if (decoded.q.length === 1) {
			let qname = dns_packet.get_domain(decoded.q[0].domain_buf, data);
			if (qname) {
				let qtype = decoded.q[0].type;
				let qclass = decoded.q[0].class;
				let req_q = new dns_types.DNSRecord(qname, qclass, qtype, 0);
				let result = await ifunc(qname, qtype, qclass);
				let res = {
					id: decoded.id,
					flags: 0x8580,
					q: [req_q],
					an: result.an,
					au: result.au,
					ad: []
				};
				return dns_packet.write_dns_packet(res);
			}
		}
		return dns_packet.write_dns_packet({id: decoded.id, flags: 0x8582, q: [], an: [], au: [], ad: []});
	}
	return null;
}

