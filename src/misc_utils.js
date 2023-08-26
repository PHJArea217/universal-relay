const endpoint = require('./endpoint.js');
const dns = require('dns');
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
class EndpointMap {
	constructor() {
		this.ip_map = make_wcm_for_ips();
		this.domain_map = make_wcm_for_domains();
	}
	addAll(entries) {
		for (const kv of entries) {
			if (!Array.isArray(kv)) continue;
			let k = kv[0];
			let v = (kv.length > 2) ? kv.slice(1) : kv[1];
			let s_k = String(k);
			let cidr = null;
			let domain_ = null;
			if (s_k.indexOf('/') >= 0) {
				cidr = endpoint.ofPrefix(s_k);
			} else {
				let ep = new endpoint.Endpoint().setDomain(s_k);
				if (ep.domain_) {
					domain_ = ep.getDomain();
				} else {
					cidr = [ep.getIPBigInt(), 128n];
				}
			}
			if (domain_) {
				this.domain_map.setValueInGroup(domain_, v);
			} else {
				this.ip_map.setValueInGroup(cidr, v);
			}
		}
	}
	getValue(ep, default_value) {
		if (ep.domain_) {
			return this.domain_map.getAll(ep.getDomain(), null, default_value);
		}
		return this.ip_map.getAll(ep.getIPBigInt(), null, default_value);
	}
}
function epm_setattr(ep, epm_value) {
	if (!epm_value) return {"action": "notfound"};
	let result = {};
	if (epm_value === 'delete') return {"action": "delete"};
	try {
	for (const kv of epm_value) {
		if (!Array.isArray(kv)) continue;
		let k = kv[0];
		let v = (kv.length > 2) ? kv.slice(1) : kv[1];
		let va = ((kv.length === 2) && Array.isArray(kv[1])) ? kv[1] : kv.slice(1);
		switch (k) {
			case 'bind_addr':
			case 'bind_addr4':
			case 'bind_addr6':
			case 'bind_addr4m':
			case 'connFuncType':
			case 'socks_server':
			case 'ip_type':
			case 'ipv6_scope':
			case 'tls_options':
			case 'user_options':
			case 'user_category':
				ep.options_map_.set("!" + k, v);
				break;
			case 'dns':
				result.dns_mode = String(va[0] || '6_weak');
				if (va.length > 1) {
					result.dns_servers = va.slice(1).map(a => String(a));
				}
				break;
			case 'ip_xlate':
				let cidr = endpoint.ofPrefix(String(v));
				let netmask = (1n << (128n - cidr[1])) - 1n;
				ep.setIPBigInt((cidr[0] & ~netmask) | (ep.getIPBigInt() & netmask));
				break;
			case 'domain_xlate':
				if (va.length >= 2) {
					let domain_ = endpoint.ofDomain(String(va[1]));
					ep.setDomain2([...domain_, ...((ep.getDomain() || []).slice(Number(va[0]) || 0))], false);
				}
				break;
		}
	}
	} catch (e) {
		return {"action": "delete", "exception": e};
	}
	result.action = "found";
	return result;
}
function epm_apply(epm, ep, oep) {
	let oep_ = oep || ep;
	return epm_setattr(oep, epm.getValue(ep, null));
}
function make_epm_dns_resolver(epm_apply_result) {
	if (!epm_apply_result) return null;
	if (!epm_apply_result.dns_servers) return null;
	let dns_resolver = new dns.Resolver();
	dns_resolver.setServers(epm_apply_result.dns_servers);
	return dns_resolver;
}
function json_map_reviver(key, value) {
	if (value === null) return null;
	if (Object.getPrototypeOf(value) === Object.prototype) {
		return new Map(Object.entries(value));
	}
	return value;
}
class Channel {
	constructor() {
		this.ch = [];
		this.wq = [];
	}
	wait() {
		return new Promise((resolve) => {
			if (this.ch.length) resolve();
			else this.wq.push(resolve);
		});
	}
	signal() {
		if (this.wq.length) {
			this.wq.shift()();
			return 1;
		}
		return 0;
	}
	broadcast() {
		let l = this.wq.length;
		if (l) {
			while (this.wq.length) this.wq.shift()();
		}
		return l;
	}
	queue(v) {
		this.ch.push(v);
		this.broadcast();
	}
	async dequeue() {
		while (this.ch.length === 0) {
			await this.wait();
		}
		return this.ch.shift();
	}
	queuem(v, max) {
		if (this.ch.length < max) this.queue(v);
	}
	async getValues() {
		while (this.ch.length === 0) {
			await this.wait();
		}
		return this.ch;
	}
}
exports.checkIPClass = checkIPClass;
// for A and AAAA records of domain names on public IANA/ICANN internet. For DN42, you may need to allow 172.16.0.0/12 and fd00::/8.
exports.endpoint_is_private_ip = checkIPClass.bind(null, ['loopback', 'privatenet', 'linklocal', 'special', 'doc']);
exports.endpoint_is_sensitive = checkIPClass.bind(null, ['loopback', 'linklocal']);
exports.endpoint_is_loopback = checkIPClass.bind(null, ['loopback']);
exports.WildcardMap = WildcardMap;
exports.make_wcm_for_ips = make_wcm_for_ips;
exports.make_wcm_for_domains = make_wcm_for_domains;
exports.EndpointMap = EndpointMap;
exports.epm_setattr = epm_setattr;
exports.epm_apply = epm_apply;
exports.make_epm_dns_resolver = make_epm_dns_resolver;
exports.json_map_reviver = json_map_reviver;
exports.Channel = Channel;
