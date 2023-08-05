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
class WildcardMap {
	constructor(group_function, input_coalesce, key_func) {
		this.group_function = group_function;
		this.key_func = key_func || (a => a);
		this.input_coalesce = input_coalesce;
		this.maps = new Map();
		this.keys_list = [];
	}
	getMap(group) {
		if (!this.maps.has(group)) {
			let new_map = new Map();
			this.maps.set(group, new_map);
			this.keys_list = [...this.maps.keys()];
			this.keys_list.sort((a, b) => (a > b) ? -1 : ((a < b) ? 1 : 0));
			return new_map;
		}
		return this.maps.get(group);
	}
	getMapByInput(input_value) {
		return this.getMap(this.group_function(input_value));
	}
	setValue(group, key, value) {
		return this.getMap(group).set(this.key_func(key), value);
	}
	setValueInGroup(key, value) {
		return this.getMapByInput(key).set(this.key_func(key), value);
	}
	getAll(key, input_coalesce_func, default_value) {
		let cf = input_coalesce_func || this.input_coalesce;
		for (let k of this.keys_list) {
			let f = this.maps.get(k);
			let f_key = cf(k, key);
			if (f.has(f_key)) return f.get(f_key);
		}
		return default_value;
	}
}
// Check an IP address against CIDR prefixes, using a "longest prefix match" algorithm.
// group identifier is the CIDR prefix length.
// input to setValue is [prefix, length] array describing a CIDR prefix. Use
// endpoint.ofPrefix to generate such an array from a CIDR prefix string.
// input to getAll is the IP address to check as returned by Endpoint getIPBigInt()
function make_wcm_for_ips() {
	return new WildcardMap(s => BigInt(s[1]), function (group, key) {
		let bg = BigInt(group);
		if ((bg >= 0n) && (bg <= 128n)) {
			let m = (1n << (128n - bg)) - 1n;
			return key & ~m;
		}
		return undefined;
	}, s => BigInt(s[0]));
}
// Check a domain name to see if it is equal to any domain name in the map or a subdomain thereof.
// group identifier is the number of labels of the domain.
// input to setValue and getAll is the domain name label array, as returned by Endpoint getDomain()
function make_wcm_for_domains() {
	return new WildcardMap(d => d.length, (group, key) => (key.length < group ? undefined : key.slice(0, group).join('.')), k => k.join('.'));
}
exports.checkIPClass = checkIPClass;
// for A and AAAA records of domain names on public IANA/ICANN internet. For DN42, you may need to allow 172.16.0.0/12 and fd00::/8.
exports.endpoint_is_private_ip = checkIPClass.bind(null, ['loopback', 'privatenet', 'linklocal', 'special', 'doc']);
exports.endpoint_is_sensitive = checkIPClass.bind(null, ['loopback', 'linklocal']);
exports.endpoint_is_loopback = checkIPClass.bind(null, ['loopback']);
exports.WildcardMap = WildcardMap;
exports.make_wcm_for_ips = make_wcm_for_ips;
exports.make_wcm_for_domains = make_wcm_for_domains;
