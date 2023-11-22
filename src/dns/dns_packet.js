class DNSPacketBuilder {
	constructor() {
		this.result_buf = Buffer.from([]);
		this.compression_cache = new Map();
	}
	append_buffer(...b) {
		this.result_buf = Buffer.concat([this.result_buf, ...b]);
	}
	append_domain(d) {
		let labels = d.d.slice();
		let curPos = this.result_buf.length;
		while(labels.length) {
			let cc_key = labels.map(b => b.toString('hex')).join(' ');
			if (this.compression_cache.has(cc_key)) {
				let offset = this.compression_cache.get(cc_key);
				let b_compressed = Buffer.from([0, 0]);
				b_compressed.writeUInt16BE(0, 0xc000 | offset);
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
