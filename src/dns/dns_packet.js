const domain_name = require('./domain_name.js');
class DNSPacketBuilder {
	constructor() {
		this.result_buf = Buffer.from([]);
		this.compression_cache = new Map();
	}
	append_buffer(...b) {
		this.result_buf = Buffer.concat([this.result_buf, ...b]);
	}
	append_string(str) {
		let str_buf = Buffer.from(str);
		if (str_buf.length > 255) throw new Error('string too long');
		this.append_buffer(Buffer.from([str_buf.length]), str_buf);
	}
	append_domain(d) {
		let labels = d.d.slice();
		let curPos = this.result_buf.length;
		while(labels.length) {
			let cc_key = labels.map(b => b.toString('hex')).join(' ');
			if (this.compression_cache.has(cc_key)) {
				let offset = this.compression_cache.get(cc_key);
				let b_compressed = Buffer.from([0, 0]);
				b_compressed.writeUInt16BE(0xc000 | offset, 0);
				this.append_buffer(b_compressed);
				return this.result_buf.length - curPos;
			}
			this.compression_cache.set(cc_key, this.result_buf.length);
			let currLabel = labels.shift();
			let currLabelLength = currLabel.length;
			if ((currLabelLength > 0) && (currLabelLength <= 63)) {
				this.append_buffer(Buffer.from([currLabelLength]), currLabel);
			}
			else throw new Error('length === 0 or > 63');
		}
		this.append_buffer(Buffer.from([0]));
		return this.result_buf.length - curPos;
	}
}
exports.measure_domain = function(buf, start) {
	let r = 0;
	while (true) {
		if (start >= buf.length) return -1;
		let v = buf[start];
		if (v === 0) return r + 1;
		if (v >= 192) return r + 2;
		if (v <= 63) {
			r += 1 + v;
			start += 1 + v;
		}
		else return -1;
	}
}
exports.get_domain = function(buf, orig_packet) {
	let result = [];
	for (let i = 0; i < 128; i++) {
		if (buf.length === 0) return null;
		let a = buf[0];
		if ((a & 0xc0) === 0xc0) {
			if (buf.length < 2) return null;
			let offset = ((a & 0x3f) << 8) | buf[1];
			buf = orig_packet.slice(offset);
			continue;
		}
		if (a === 0) {
			return new domain_name.DomainName(result);
		}
		if (a <= 63) {
			if (buf.length < (a + 1)) return null;
			result.push(buf.slice(1, a+1));
			buf = buf.slice(a+1);
		} else {
			return null;
		}
	}
	return null;
}
exports.get_next_rr = function(buf, include_data) {
	let length = exports.measure_domain(buf, 0);
	if (length > (buf.length - 4)) return null;
	if (length === -1) return null;
	let result = {domain_buf: buf.slice(0, length), type: buf.readUInt16BE(length), class: buf.readUInt16BE(length+2)};
	if (include_data) {
		let data_buf = buf.slice(length + 4);
		if (data_buf.length < 6) return null;
		let dlength = data_buf.readUInt16BE(4);
		if ((dlength + 6) > data_buf.length) return null;
		result.data = data_buf.slice(6, 6+dlength);
		result.ttl = data_buf.readUInt32BE(0);
		result.advance = data_buf.slice(6+dlength);
	} else {
		result.advance = buf.slice(length + 4);
	}
	return result;
}
exports.read_dns_packet = function(buf) {
	if (buf.length < 12) return null;
	let res = {id: buf.readUInt16BE(0), flags: buf.readUInt16BE(2), q: [], an: [], au: [], ad: []};
	let nr_q = buf.readUInt16BE(4);
	let nr_an = buf.readUInt16BE(6);
	let nr_au = buf.readUInt16BE(8);
	let nr_ad = buf.readUInt16BE(10);
	let buf_n = buf.slice(12);
	while (nr_q) {
		let next_rr = exports.get_next_rr(buf_n, false);
		if (!next_rr) return null;
		nr_q--;
		res.q.push(next_rr);
		buf_n = next_rr.advance;
		delete next_rr.advance;
	}
	while (nr_an) {
		let next_rr = exports.get_next_rr(buf_n, true);
		if (!next_rr) return null;
		nr_an--;
		res.an.push(next_rr);
		buf_n = next_rr.advance;
		delete next_rr.advance;
	}
	while (nr_au) {
		let next_rr = exports.get_next_rr(buf_n, true);
		if (!next_rr) return null;
		nr_au--;
		res.au.push(next_rr);
		buf_n = next_rr.advance;
		delete next_rr.advance;
	}
	while (nr_ad) {
		let next_rr = exports.get_next_rr(buf_n, true);
		if (!next_rr) return null;
		nr_ad--;
		res.ad.push(next_rr);
		buf_n = next_rr.advance;
		delete next_rr.advance;
	}
	return res;
}
exports.write_dns_packet = function (contents) {
	let b = new DNSPacketBuilder();
	let header = Buffer.alloc(12);
	header.writeUInt16BE(contents.id, 0);
	header.writeUInt16BE(contents.flags, 2);
	header.writeUInt16BE(contents.q.length, 4);
	header.writeUInt16BE(contents.an.length, 6);
	header.writeUInt16BE(contents.au.length, 8);
	header.writeUInt16BE(contents.ad.length, 10);
	b.append_buffer(header);
	for (let q of contents.q) {
		let type_class = Buffer.alloc(4);
		b.append_domain(q.name);
		type_class.writeUInt16BE(q.type, 0);
		type_class.writeUInt16BE(q.class, 2);
		b.append_buffer(type_class);
	}
	for (let q of {[Symbol.iterator]: function*() {yield* contents.an; yield* contents.au; yield* contents.ad}}) {
		let type_class = Buffer.alloc(10);
		b.append_domain(q.name);
		type_class.writeUInt16BE(q.type, 0);
		type_class.writeUInt16BE(q.class, 2);
		type_class.writeUInt32BE(q.ttl, 4);
		type_class.writeUInt16BE(0, 8); // length (0 for now, computed later)
		b.append_buffer(type_class);
		let c = b.result_buf.length;
		q.write_serial_dns_data(b);
		let d_len = b.result_buf.length - c;
		b.result_buf.writeUInt16BE(d_len, c-2);
	}
	return b.result_buf;
}
exports.DNSPacketBuilder = DNSPacketBuilder;
