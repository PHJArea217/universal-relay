const common_promises = require('./common_promises.js');
const endpoint = require('./endpoint.js');
const _reader = require('./reader.js');
async function get_pp2_header_x(s) {
	let targetLength = 0;
	let b = Buffer.from([]);
	while (true) {
		let nb = await common_promises.readFromSocket(s);
		if (!nb) break;
		b = Buffer.concat([b, nb]);
		if (targetLength === 0) {
			if (b.length >= 14) {
				if (b.readUint16BE(0) !== 0xd0a) break;
				if (b.readUint32BE(2) !== 0xd0a51) break;
				if (b.readUint32BE(6) !== 0x5549540a) break;
				targetLength = 14+b.readUint16BE(12);
			}
		}
		if (targetLength > 0) {
			if (b.length >= targetLength) {
				s.unshift(b.slice(targetLength));
				return {buffer: Buffer.concat([Buffer.from([13, 10]), b.slice(0, targetLength)])};
			}
		}
	}
	s.unshift(b);
	return null;
	// throw new Error();
}
async function read_until_empty(s) {
	let reader = new _reader.Reader(4);
	reader.mode = 2;
	reader.charToFind = 0x0a /* (newline) */
	while (true) {
		let nb = await common_promises.readFromSocket(s);
		let result = reader.addBuf(nb);
		if (result) {
			s.unshift(result.excessBuf);
			if (result.buf.length === 0) return;
			if ((result.buf.length === 1) && result.buf[0] === 0x0a) {
				return;
			} else if ((result.buf.length === 2) && (result.buf.readUInt16BE(0) === 0x0d0a)) {
				return;
			}
		}
	}
}
async function get_proxy_header(s) {
	let reader = new _reader.Reader(400);
	reader.mode = 2;
	reader.charToFind = 0x0a /* (newline) */
	while (true) {
		let nb = await common_promises.readFromSocket(s);
		let result = reader.addBuf(nb);
		if (result) {
			s.unshift(result.excessBuf);
			if ((result.buf.length === 2) && (result.buf.readUInt16BE(0) === 0x0d0a)) {
				return get_pp2_header_x(s);
			}
			let text = result.buf.toString('latin1');
			if (typeof text === 'string') {
				let x = text.substring(0, 8).toLowerCase();
				if (x.startsWith('connect ')) {
					/* HTTP proxy */
					await read_until_empty(s);
					/* Dummy success response */
					s.write('HTTP/1.1 200 OK\r\nServer: Universal Relay\r\n\r\n');
					return {string: text};
				} else if (x.startsWith('proxy ')) {
					/* PROXY protocol v1 */
					/* Make sure the header is not truncated */
					if (result.buf.length >= 400) return null;
					return {string: text};
				}
			}
			return null;
		}
	}
}
function parse_tlv_sequence(buf) {
	if (buf.length < 3) return null;
	let length = buf.readUint16BE(1);
	if (length > (buf.length - 3)) return null;
	return {
		type: buf[0],
		length: length,
		value: buf.slice(3, 3+length),
		advance: length + 3
	};
}
function parse_tlv_generic(buf, typeLength, lengthLength) {
	let headerLength = typeLength + lengthLength;
	if (buf.length < headerLength) return null;
	let actualLength = lengthLength === 2 ? buf.readUint16BE(typeLength) : buf[typeLength];
	if ((actualLength + headerLength) > buf.length) return null;
	return {type: buf.slice(0, typeLength), value: buf.slice(headerLength, headerLength + actualLength), advance: buf.slice(headerLength + actualLength)};
}

function parse_tlv_multiple(tlv_buf) {
	let tlv_result ={};
	while (true) {
		let nextTLV = parse_tlv_sequence(tlv_buf);
		if (!nextTLV) break;
		if (typeof nextTLV.type !== 'number') continue;
		tlv_result[Number(nextTLV.type)] = nextTLV.value;
		tlv_buf = tlv_buf.slice(nextTLV.advance);
	}
	return tlv_result;
}

function parse_pp1_or_http_header(str) {
	let tokens = str.split(' ').flatMap(x => x ? [x.toLowerCase().trim()] : []);
	switch (tokens[0]) {
		case 'connect':
			let e = new endpoint.Endpoint();
			if (typeof tokens[1] === 'string') {
				let host = [];
				if (tokens[1][0] === '[') {
					host = tokens[1].substring(1).split(']:');
				} else {
					let host_colon = tokens[1].lastIndexOf(':');
					if (host_colon >= 0) {
						host.push(tokens[1].substring(0, host_colon));
						host.push(tokens[1].substring(host_colon+1));
					}
				}
				if (host.length !== 2) return null;
				e.setDomain(host[0]);
				e.setPort(Number(host[1]));
				switch (tokens[2]) {
					case 'http/1.0':
					case 'http/1.1':
						return {localEndpoint: e};
				}
			}
			break;
		case 'proxy':
			switch (tokens[1]) {
				case 'tcp':
				case 'tcp4':
				case 'tcp6':
					let rep = new endpoint.Endpoint();
					let lep = new endpoint.Endpoint();
					if (tokens.length < 6) return null;
					rep.setIPStringWithScope(tokens[2]);
					lep.setIPStringWithScope(tokens[3]);
					rep.setPort(Number(tokens[4]));
					lep.setPort(Number(tokens[5]));
					return {remoteEndpoint: rep, localEndpoint: lep};
			}
	}
	return null;
}
function parse_pp2_header(buf, options_) {
	if (buf.length < 16) return null;
	let options = options_ || {};
	let mode = buf[12];
	switch (mode) {
		case 0x20:
			return {mode: "local"};
		case 0x21:
			break;
		default:
			return null;
	}
	let result = {mode: "proxy", type: "other"};
	let type = buf[13];
	/* An earlier implementation of this protocol incorrectly assumed that
	 * the section which holds the IP addresses and ports was 216 bytes for
	 * all IP address and unix domain socket families. This was incorrect,
	 * however, the u-relay-tproxy implementation assumed this too. This
	 * should not break the u-relay-tproxy implementation because the zero
	 * bytes at the end can be regarded as empty TLV values, as long as the
	 * number of padding bytes is a multiple of three, which is the case
	 * here. */
	let limit = 232;
	switch (type) {
		case 0x11:
			limit = 28;
			if (buf.length < 28) return null;
			result.type = 'tcp4';
			result.remoteEndpoint = new endpoint.Endpoint();
			result.remoteEndpoint.setIPBuffer(buf.slice(16, 20)).setPort(buf.readUint16BE(24));
			result.localEndpoint = new endpoint.Endpoint();
			result.localEndpoint.setIPBuffer(buf.slice(20, 24)).setPort(buf.readUint16BE(26));
			break;
		case 0x21:
			limit = 52;
			if (buf.length < 52) return null;
			result.type = 'tcp6';
			result.remoteEndpoint = new endpoint.Endpoint();
			result.remoteEndpoint.setIPBuffer(buf.slice(16, 32)).setPort(buf.readUint16BE(48));
			result.localEndpoint = new endpoint.Endpoint();
			result.localEndpoint.setIPBuffer(buf.slice(32,48)).setPort(buf.readUint16BE(50));
			break;
		case 0x31:
			limit = 232;
			if (buf.length < 232) return null;
			result.type = 'unix_s';
			if (options.allow_unix) {
				result.remoteEndpoint = new endpoint.Endpoint();
				result.remoteEndpoint.options_map_.set('!unix_path', String(buf.slice(16, 16+108)));
				result.localEndpoint = new endpoint.Endpoint();
				result.localEndpoint.options_map_.set('!unix_path', String(buf.slice(16+108, 16+216)));
			}
			break;
	}
	let tlv_buf = buf.slice(limit);
	let tlv_obj = parse_tlv_multiple(tlv_buf);
	if (tlv_obj.hasOwnProperty("2")) {
		result.authority = String(tlv_obj[2]);
		if (options.set_sni) {
			try {
				result.localEndpoint = result.localEndpoint.clone().setDomain(result.authority);
			} catch (e) {
			}
		}
	}
	if (tlv_obj.hasOwnProperty("32")) {
		let ssl_buf = tlv_obj[32];
		result.ssl = {client: ssl_buf[0], verify: ssl_buf.readUint32BE(4)};
		result.ssl_data = parse_tlv_multiple(ssl_buf.slice(8));
	}
	result.tlv = tlv_obj;
	return result;
}
function parse_sni_header(buf) {
	let h = parse_tlv_generic(buf, 3, 2);
	if (!h) return null;
	let ch = parse_tlv_generic(h.value, 2, 2);
	if (!ch) return null;
	if (ch.type.readUint16BE(0) !== 0x100) return null;
	let ch_next = parse_tlv_generic(ch.value.slice(34), 0, 1); // skip past session id
	if (!ch_next) return null;
	ch_next = parse_tlv_generic(ch_next.advance, 0, 2); // cipher suites
	if (!ch_next) return null;
	ch_next = parse_tlv_generic(ch_next.advance, 0, 1); // compression methods
	if (!ch_next) return null;
	ch_next = parse_tlv_generic(ch_next.advance, 0, 2); // extensions
	if (!ch_next) return null;
	let ext_buf = ch_next.value;
	while (true) {
		let ext = parse_tlv_generic(ext_buf, 2, 2);
		if (!ext) break;
		if (ext.type.readUint16BE(0) === 0) {
			if (ext.value.length >= 2) {
				let sni_list_length = ext.value.readUint16BE(0);
				let sni_list = parse_tlv_multiple(ext.value.slice(2, 2+sni_list_length));
				if (sni_list.hasOwnProperty('0')) {
					return {"hostname": String(sni_list[0])};
				}
			}
		}
		ext_buf = ext.advance;
	}
	return null;
}
async function get_sni_header(s) {
	let targetLength = 0;
	let b = Buffer.from([]);
	while (true) {
		let nb = await common_promises.readFromSocket(s);
		if (!nb) break;
		b = Buffer.concat([b, nb]);
		if (targetLength === 0) {
			if (b.length >= 5) {
				if (b[0] !== 22) break;
				if (b.readUint16BE(1) !== 0x301) break;
				targetLength=5+b.readUint16BE(3);
				if (targetLength > 4096) break;
			}
		}
		if (targetLength > 0) {
			if (b.length >= targetLength) {
				s.unshift(b);
				return {buffer: b.slice(0, targetLength)};
			}
		}
	}
	s.unshift(b);
	return null;
	// throw new Error();
}
function make_pp2_header(rep, lep, tlv_buf) {
	let b = Buffer.alloc(216);
	let rep_buf = rep.getIPBuffer2(true);
	if (Buffer.isBuffer(rep_buf) && rep_buf.length === 16) {
		rep_buf.copy(b, 0);
	}
	let lep_buf = lep.getIPBuffer2(true);
	if (Buffer.isBuffer(lep_buf) && lep_buf.length === 16) {
		lep_buf.copy(b, 16);
	}
	b.writeUint16BE(32, rep.getPort());
	b.writeUint16BE(34, lep.getPort());
	let final_buf = Buffer.concat([b, tlv_buf || Buffer.from([])]);
	let i_buf = Buffer.from([13, 10, 13, 10, 0, 13, 10, 0x51, 0x55, 0x49, 0x54, 10, 0x21, 0x21, 0, 0]);
	i_buf.writeUint16BE(14, final_buf.length);
	return Buffer.concat([i_buf, final_buf]);
}


exports.get_proxy_header = get_proxy_header;
exports.get_sni_header = get_sni_header;
exports.parse_pp2_header = parse_pp2_header;
exports.parse_pp1_or_http_header = parse_pp1_or_http_header;
exports.parse_sni_header = parse_sni_header;
exports.parse_tlv_generic = parse_tlv_generic;
exports.parse_tlv_sequence = parse_tlv_sequence;
exports.parse_tlv_multiple = parse_tlv_multiple;
exports.make_pp2_header = make_pp2_header;
