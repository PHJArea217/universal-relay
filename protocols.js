const common_promises = require('./common_promises.js');
const endpoint = require('./endpoint.js');
async function get_pp2_header(s) {
	let targetLength = 0;
	let b = Buffer.from([]);
	while (true) {
		let nb = await common_promises.readFromSocket(s);
		if (!nb) break;
		b = Buffer.concat(b, nb);
		if (targetLength === 0) {
			if (b.length >= 16) {
				if (b.readUint32BE(0) !== 0xd0a0d0a) break;
				if (b.readUint32BE(4) !== 0xd0a51) break;
				if (b.readUint32BE(8) !== 0x5549540a) break;
				targetLength = 16+b.readUint16BE(14);
			}
		}
		if (targetLength > 0) {
			if (b.length >= targetLength) {
				s.unshift(b.slice(targetLength));
				return {buffer: b.slice(0, targetLength)};
			}
		}
	}
	throw new Error();
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


function parse_pp2_header(buf) {
	if (buf.length < 16) return null;
	let mode = buf[12];
	switch (mode) {
		case 0x20:
			return {mode: "local"};
		case 0x21:
			break;
		default:
			return null;
	}
	if (buf.length < 232) return null;
	let result = {mode: "proxy", type: "other"};
	let type = buf[13];
	switch (type) {
		case 0x11:
			result.type = 'tcp4';
			result.remoteEndpoint = new endpoint.Endpoint();
			result.remoteEndpoint.setIPBuffer(buf.slice(16, 20)).setPort(buf.readUint16BE(24));
			result.localEndpoint = new endpoint.Endpoint();
			result.localEndpoint.setIPBuffer(buf.slice(20, 24)).setPort(buf.readUint16BE(26));
			break;
		case 0x21:
			result.type = 'tcp6';
			result.remoteEndpoint = new endpoint.Endpoint();
			result.remoteEndpoint.setIPBuffer(buf.slice(16, 32)).setPort(buf.readUint16BE(48));
			result.localEndpoint = new endpoint.Endpoint();
			result.localEndpoint.setIPBuffer(buf.slice(32,48)).setPort(buf.readUint16BE(50));
			break;
		case 0x31:
			result.type = 'unix_s';
			break;
	}
	let tlv_buf = buf.slice(232);
	let tlv_obj = parse_tlv_multiple(tlv_buf);
	if (tlv_obj.hasOwnProperty("2")) {
		result.authority = String(tlv_obj[2]);
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
	let ch_next = parse_tlv_generic(ch_next.advance, 0, 2); // cipher suites
	if (!ch_next) return null;
	let ch_next = parse_tlv_generic(ch_next.advance, 0, 1); // compression methods
	if (!ch_next) return null;
	let ch_next = parse_tlv_generic(ch_next.advance, 0, 2); // extensions
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
		ext_buf = ext_buf.advance;
	}
	return null;
}
async function get_sni_header(s) {
	let targetLength = 0;
	let b = Buffer.from([]);
	while (true) {
		let nb = await common_promises.readFromSocket(s);
		if (!nb) break;
		b = Buffer.concat(b, nb);
		if (targetLength === 0) {
			if (b.length >= 5) {
				if (b[0] !== 22) break;
				if (b.readUint16BE(1) !== 0x301) break;
				targetLength=5+b.readUint16BE(3);
				if (targetLength > 1024) break;
			}
		}
		if (targetLength > 0) {
			if (b.length >= targetLength) {
				s.unshift(b);
				return {buffer: b.slice(0, targetLength)};
			}
		}
	}
	throw new Error();
}
exports.get_pp2_header = get_pp2_header;
exports.get_sni_header = get_sni_header;
