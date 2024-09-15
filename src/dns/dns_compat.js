const ip = require('ip');
const domain_name = require('./domain_name.js');
const dns_types = require('./dns_types.js');
exports.convert_pdns = function(options, qtype_content) {
	if (typeof qtype_content === 'string') {
		qtype_content = {qtype: 'AAAA', content: qtype_content};
	}
	let v = {class: 1 /* IN */, ttl: ('ttl' in qtype_content) ? qtype_content.ttl : 60};
	switch (qtype_content.qtype) {
		case 'A':
			v.qtype_class = dns_types.dns_types.A;
			let ip_buf0 = ip.toBuffer(qtype_content.content);
			if (ip_buf0.length !== 4) break;
			v.rrdata = [ip_buf0.readUInt32BE(0)];
			return v;
		case 'URELAY-A6-SYNTH':
			if (options.ipv6_prefix) {
				v.qtype_class = dns_types.dns_types.AAAA;
				v.rrdata = [(options.ipv6_prefix << 64n) | (BigInt(qtype_content.a6_synth) & 0xffff_ffff_ffff_ffffn)];
				return v;
			}
			break;
		case 'AAAA':
			v.qtype_class = dns_types.dns_types.AAAA;
			let ip_buf = ip.toBuffer(qtype_content.content);
			if (ip_buf.length !== 16) break;
			v.rrdata = [(ip_buf.readBigUInt64BE(0) << 64n) | ip_buf.readBigUInt64BE(8)];
			return v;
		case 'CNAME':
			v.qtype_class = dns_types.dns_types.CNAME;
			v.rrdata = [domain_name.from_text(qtype_content.content)];
			return v;
		case 'NS':
			v.qtype_class = dns_types.dns_types.NS;
			v.rrdata = [domain_name.from_text(qtype_content.content)];
			return v;
		case 'PTR':
			v.qtype_class = dns_types.dns_types.PTR;
			v.rrdata = [domain_name.from_text(qtype_content.content)];
			return v;
		case 'TXT':
			v.qtype_class = dns_types.dns_types.TXT;
			v.rrdata = [qtype_content.text_list || []];
			return v;
	}
	return null;
}

