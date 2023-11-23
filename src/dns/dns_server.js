const dns_packet = require('./dns_packet.js');
const dns_types = require('./dns_types.js');
const domain_name = require('./domain_name.js');
exports.query_dns = async function(data, ifunc, socket) {
	let decoded = dns_packet.read_dns_packet(data);
	if ((decoded.flags & 0xf800) === 0) {
		if (decoded.q.length === 1) {
			let qname = dns_packet.get_domain(decoded.q[0].domain_buf, data);
			if (qname) {
				let qtype = decoded.q[0].type;
				let qclass = decoded.q[0].class;
				let req_q = new dns_types.DNSRecord(qname, qclass, qtype, 0);
				let result = await ifunc(qname, qtype, qclass, decoded.flags, socket);
				let res = {
					id: decoded.id,
					flags: 0x8480 | (decoded.flags & 0x100) | (result.rcode || 0),
					q: [req_q],
					an: result.an || [],
					au: result.au || [],
					ad: result.ad || []
				};
				return dns_packet.write_dns_packet(res);
			}
		}
		return dns_packet.write_dns_packet({id: decoded.id, flags: 0x8582, q: [], an: [], au: [], ad: []});
	}
	return null;
}
// app.use(express.raw({type: 'application/dns-message'}));
exports.make_doh_middleware = function (ifunc) {
	return async (req, res) => {
		let dns_query = req.query.dns;
		if (typeof dns_query === 'string') {
			let i = Buffer.from(dns_query, 'base64url');
			let o = await exports.query_dns(i, ifunc);
			if (o) {
				res.header('content-type', 'application/dns-message');
				res.status(200).send(o);
			}
		} else if (req.method === 'POST') {
			let i = req.body;
			if (Buffer.isBuffer(i)) {
				let o = await exports.query_dns(i, ifunc, req.socket);
				if (o) {
					res.header('content-type', 'application/dns-message');
					res.status(200).send(o);
				}
			}
		}
		res.status(400).send('bad request');
	};
}
exports.make_tcp_server = function (ifunc, s) {
	let state = {s: 0, n: 0, b: Buffer.from([])};
	s.on('readable', function () {
		let b = s.read();
		if (!Buffer.isBuffer(b)) return;
		state.b = Buffer.concat([state.b, b]);
		while (true) {
			if (state.s === 0) {
				if (state.b.length >= 2) {
					state.n = state.b.readUInt16BE(0);
					state.b = state.b.slice(2);
					state.s = 1;
					continue;
				}
			} else if (state.s === 1) {
				if (state.b.length >= state.n) {
					let dns_buffer = state.b.slice(0, state.n);
					state.s = 0;
					state.b = state.b.slice(state.n);
					state.n = 0;
					exports.query_dns(dns_buffer, ifunc, s).then(res_buf => {
						if (Buffer.isBuffer(res_buf) && (res_buf.length <= 65535)) {
							let lb = Buffer.alloc(2);
							lb.writeUInt16BE(res_buf.length);
							let rb = Buffer.concat([lb, res_buf]);
							s.write(rb);
						}
					}).catch((e) => {console.log(e); s.destroy()});
					continue;
				}
			}
			break;
		}
	});
	s.on('end',() => s.end());
}
const qtype_inv_map = Object.freeze(Object.assign(Object.create(null), {
	"!1": "A",
	"!28": "AAAA",
	"!255": "ANY",
	"!12": "PTR",
	"!6": "SOA",
	"!16": "TXT",
	"!5": "CNAME",
	"!2": "NS"
}));
exports.make_simple_ifunc = async function (f, default_soa, qname, qtype, qclass, flags, socket) {
	let dn = qname.to_text();
	let qtype_str = qtype_inv_map['!' + String(qtype)];
	if (typeof qtype_str !== 'string') qtype_str = 'TYPE' + String(qtype);
	let f_res = await f(dn, qtype_str, qclass, flags, socket);
	if ((!Array.isArray(f_res)) || (f_res.length === 0)) {
		return {au: [default_soa]};
	}
	let result = f_res.map(rec => {
		let name = rec.qname || qname;
		let cl = rec.class || qclass;
		let ttl = ('ttl' in rec) ? rec.ttl : 60;
		return new (rec.qtype_class)(name, cl, ttl, ...rec.rrdata);
	});
	return {an: result};
}
