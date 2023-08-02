function checkIPClass(classes, ep) {
	let v = ep.getIPBigInt();
	for (let c of classes) {
		switch (c) {
		case 'loopback':
			if (v === 0n) return true; // ::
			if (v === 1n) return true; // ::1
			if (v === 0xffff00000000n) return true; // 0.0.0.0
			if ((v >> 24n) === 0xffff7fn) return true; // 127.0.0.0/8
			break;
		case 'privatenet':
			if ((v >> 121n) === 0x7en) return true; // fc00::/7
			if ((v >> 118n) === 1019n) return true; // fec0::/10
			if ((v >> 24n) === 0xffff00n) return true; // 0.0.0.0/8; supported in Linux since kernel 5.3
			if ((v >> 24n) === 0xffff0an) return true; // 10.0.0.0/8
			if ((v >> 20n) === 0xffffac1n) return true; // 172.16.0.0/12
			if ((v >> 16n) === 0xffffc0a8n) return true; // 192.168.0.0/16
			if (((v >> 20n) & -4n) === 0xffff644n) return true; // 100.64.0.0/10
			if (((v >> 16n) & -2n) === 0xffffc612n) return true; // 198.18.0.0/15
			break;
		case 'linklocal':
			if ((v >> 118n) === 1018n) return true; // fe80::/10
			if ((v >> 16n) === 0xffffa9fen) return true; // 169.254.0.0/16
			break;
		case 'special':
			if ((v >> 8n) === 0xffffc00000n) return true; // 192.0.0.0/24
			break;
		case 'doc':
			if ((v >> 8n) === 0xffffc00002n) return true; // 192.0.2.0/24
			if ((v >> 8n) === 0xffffc63364n) return true; // 198.51.100.0/24
			if ((v >> 8n) === 0xffffcb0071n) return true; // 203.0.113.0/24
			if ((v >> 96n) === 0x20010db8n) return true; // 2001:db8::/32
			break;
		}
	}
	return false;
}
exports.checkIPClass = checkIPClass;
exports.endpoint_is_private_ip = checkIPClass.bind(null, ['loopback', 'privatenet', 'linklocal', 'special', 'doc']);
