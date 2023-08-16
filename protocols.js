async function get_pp2_header(s) {
	let targetLength = 0;
	let b = Buffer.from([]);
	while (true) {
		let nb = common_promises.readFromSocket(s);
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
async function get_sni_header(s) {
	let targetLength = 0;
	let b = Buffer.from([]);
	while (true) {
		let nb = common_promises.readFromSocket(s);
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
