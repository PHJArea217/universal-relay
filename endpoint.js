'use strict';
const ip = require('ip');
const net = require('net');
class Endpoint {
	constructor () {
		this.ip_ = 0n;
		this.domain_ = null;
		// this.options_map_ = new Map();
		this.port_ = 0;
	}
	get options_map_() {
		if (!this._options_map) this._options_map = new Map();
		return this._options_map;
	}
	setIPBigInt (newIP) {
		if ((newIP >= 0n) && (newIP < (1n<<128n))) {
			this.ip_ = newIP;
			this.domain_ = null;
			return this;
		} else {
			throw new Error("newIP must be between 0n and (1n<<128n)-1");
		}
	}
	setIPBuffer (newIP) {
		let result_bi = 0n;
		if (newIP.length === 4) {
			result_bi = BigInt(newIP.readUInt32BE(0)) | 0xffff00000000n;
		} else if (newIP.length === 16) {
			result_bi |= BigInt(newIP.readUInt32BE(0)) << 96n;
			result_bi |= BigInt(newIP.readUInt32BE(4)) << 64n;
			result_bi |= BigInt(newIP.readUInt32BE(8)) << 32n;
			result_bi |= BigInt(newIP.readUInt32BE(12)) << 0n;
		} else {
			throw new Error('newIP buffer must be of length 4 or 16');
		}
		return this.setIPBigInt(result_bi);
	}
	setIPString (newIP) {
		return this.setIPBuffer(ip.toBuffer(newIP));
	}
	setIPStringWithScope (newIP) {
		let newIPString = String(newIP);
		let percent_position = newIPString.indexOf('%');
		if (percent_position >= 0) {
			this.setIPString(newIPString.substring(0, percent_position));
			this.options_map_.set('!ipv6_scope', newIPString.substring(percent_position + 1));
			return this;
		} else {
			return this.setIPString(newIPString);
		}
	}
	getIPBigInt () {
		return this.ip_;
	}
	getIPBuffer2 (force_v4mapped) {
		/*
		 * IPv4 addresses are stored as IPv4-mapped-IPv6 addresses under the
		 * ::ffff:0:0/96 range. Retrieval of IPv4 addresses as a buffer or string
		 * will return the IPv4 address itself, not the IPv4-mapped-IPv6
		 * representation (unless forced with force_v4mapped = true)
		 */
		let v4_host_nr = force_v4mapped ? -1n : this.getHostNR(0xffff00000000n, 96);
		if (v4_host_nr >= 0n) {
			let newbuf = Buffer.allocUnsafe(4);
			newbuf.writeUInt32BE(Number(v4_host_nr), 0);
			return newbuf;
		} else {
			let newbuf = Buffer.allocUnsafe(16);
			newbuf.writeUInt32BE(Number((this.ip_ >> 96n) & 0xffffffffn), 0);
			newbuf.writeUInt32BE(Number((this.ip_ >> 64n) & 0xffffffffn), 4);
			newbuf.writeUInt32BE(Number((this.ip_ >> 32n) & 0xffffffffn), 8);
			newbuf.writeUInt32BE(Number((this.ip_ >> 0n) & 0xffffffffn), 12);
			return newbuf;
		}
	}
	getIPBuffer () {
		return this.getIPBuffer2(false);
	}
	getIPString2 (force_v4mapped) {
		return ip.toString(this.getIPBuffer2(force_v4mapped));
	}
	getIPString () {
		return this.getIPString2(false);
	}
	setDomain2 (domain__, convert_to_ip) {
		let d = domain__;
		if (!d) {
			throw new Error("Domain undefined or null");
		}
		if (!Array.isArray(d)) {
			d = String(domain__);
			/* Corner case for DNS root */
			if (d === '.') {
				this.domain_ = [];
				this.ip_ = 0n;
				return this;
			}
			if (convert_to_ip && net.isIP(d)) {
				return this.setIPString(d);
			}
			if (d.endsWith('.')) {
				d = d.substring(0, d.length - 1);
			}
			d = d.split('.');
			d.reverse();
		}
		let r = [];
		for (let domain_label of d) {
			let label_str = String(domain_label).toLowerCase();
			if (label_str.match(/^[0-9a-z_-]+$/)) {
				r.push(label_str);
			} else {
				throw new Error('Domain label contains invalid characters');
			}
		}
		Object.freeze(r);
		this.domain_ = r;
		this.ip_ = 0n;
		return this;
	}
	setDomain (domain__) {
		return this.setDomain2(domain__, true);
	}
	/*
	 * getHostNR and getSubdomainsOf take into account the general organization of IP
	 * addresses and domain names. They operate under the assumption that the lower
	 * components of a domain name or IP address are only meaningful if the upper
	 * components match; if we don't recognize the upper components, then there would
	 * not be any meaningful interpretation of the lower components.
	 *
	 * getHostNR and friends operate on an IP address endpoint. The prefix and length
	 * arguments represent an IPv6 CIDR prefix (IPv4 prefixes are represented under
	 * ::ffff:0:0/96). The prefix argument is an IPv6 address in numerical form,
	 * exactly as if returned by getIPBigInt(). The length argument is the CIDR prefix
	 * length. If the IP address of the endpoint is within the specified prefix,
	 * then the host bits of the endpoint's IP address is returned. For example, with
	 * the endpoint IP address as 2001:db8::1234:aaa0, and the prefix and length is
	 * 0x20010db8n<<96n and 64 (which corresponds to 2001:db8::/64), the return value is
	 * 0x1234aaa0n. If the endpoint IP address does not fall under the specified prefix,
	 * the return value is -1n for getHostNR. For getHostNRLex the return value is -1n
	 * if the endpoint is numerically greater than the prefix, and -2n if the endpoint
	 * is numerically less than the prefix.
	 */
	getHostNRLex (prefix, length) {
		let bitmask = 128n - BigInt(length);
		if ((bitmask < 0n) || (bitmask > 128n)) {
			throw new Error('Prefix length must be between 0 and 128 inclusive');
		}
		let host_mask = (1n << bitmask) - 1n;
		let network_mask = (1n << 128n) - (1n << bitmask);
		let a = this.ip_ & network_mask;
		let b = prefix & network_mask;
		if (a === b) {
			return this.ip_ & host_mask;
		} else if (a > b) {
			return -1n;
		} else if (a < b) {
			return -2n;
		}
		throw new Error();
	}
	getHostNR (prefix, length) {
		let result = this.getHostNRLex(prefix, length);
		if (result < 0n) return -1n;
		return result;
	}
	getPort () {
		return this.port_;
	}
	setPort (port) {
		let port_number = Number(port);
		if (port_number !== Math.floor(port_number)) {
			throw new Error("Port number must be an integer");
		}
		if (!(port_number >= 0)) {
			throw new Error("Port number must be greater than or equal to 0");
		}
		if (!(port_number <= 65535)) {
			throw new Error("Port number must be less than or equal to 65535");
		}
		this.port_ = port_number;
		return this;
	}
	getDomain () {
		return this.domain_;
	}
	getDomainString () {
		if (!this.domain_) return null;
		if (this.domain_.length === 0) return ".";
		let d = this.domain_.slice();
		d.reverse();
		return d.join('.');
	}
	/*
	 * getSubdomainsOf and friends operate on a domain endpoint. The base_domain
	 * argument represents a domain name, in backwards array form: an array of
	 * DNS labels from right to left order. For example, the domain www.example.com
	 * is represented as ['com', 'example', 'www']. This representation is roughly
	 * the same as the HTTP Host header domain represented in Express.js's
	 * req.subdomains property with the subdomain offset property set to 0. The
	 * endpoint's domain name is checked to see if it is a subdomain of the
	 * base_domain. If it is, then the return value is the subdomain portion of the
	 * endpoint's domain name, expressed as an array of DNS labels, where the first
	 * element is the first label directly below the matching base_domain. If the
	 * endpoint's domain is the same as the base_domain, the return value is []. If
	 * the endpoint's domain name is not a subdomain of the base_domain, then the
	 * return value is null. The nr_parts_to_keep argument specifies the maximum
	 * number of labels to return.
	 */
	getSubdomainsOfLex (base_domain, nr_parts_to_keep) {
		if (!this.domain_) {
			return null;
		}
		let domain_length = base_domain.length;
		for (let i = 0; i < domain_length; i++) {
			let a = this.domain_[i];
			let b = base_domain[i];
			if ((!a) || (a < b)) {
				return -2n;
			} else if (a > b) {
				return -1n;
			} else if (a === b) {
			} else {
				throw new Error();
			}
		}
		return this.domain_.slice(domain_length, domain_length + nr_parts_to_keep);
	}
	getSubdomainsOf (base_domain, nr_parts_to_keep) {
		let result = this.getSubdomainsOfLex(base_domain, nr_parts_to_keep);
		if (Array.isArray(result)) return result;
		return null;
	}
	async resolveDynamic (resolver, options_) {
		let cloned_this = this.clone();
		let options = options_ || {};
		if (!this.domain_) {
			return [cloned_this];
		}
		let resolverResult = await resolver(cloned_this.getDomain(), cloned_this.getDomainString(), cloned_this);
		if (!resolverResult) {
			return null; /* fall through */
		}
		if (resolverResult === true) {
			return [cloned_this]; /* the resolver called something like setIPString or setDomain on the third argument */
		}
		if (!Array.isArray(resolverResult)) {
			resolverResult = [resolverResult];
		}
		let result_array = [];
		for (let r of resolverResult) {
			if (r instanceof Endpoint) {
				result_array.push(r);
			} else {
				result_array.push(cloned_this.clone()[options.ipOnly ? "setIPStringWithScope" : "setDomain"](String(r)));
			}
		}
		return result_array;
	}
	clone () {
		let cloned_this = new Endpoint();
		cloned_this.ip_ = this.ip_;
		cloned_this.domain_ = this.domain_ ? this.domain_.slice() : null;
		cloned_this.port_ = this.port_;
		for (let e of this.options_map_.entries()) {
			cloned_this.options_map_.set(e[0], e[1]);
		}
		return cloned_this;
	}
	toCRAreq () {
		if (this.domain_) {
			return {
				type: 'domain',
				host: this.getDomainString(),
				port: this.getPort(),
				__orig_endpoint__: this
			};
		} else {
			return {
				type: (this.getHostNR(0xffff00000000n, 96) >= 0n) ? 'ipv4' : 'ipv6',
				host: this.getIPString(),
				port: this.getPort(),
				__orig_endpoint__: this
			};
		}
	}
	toNCCOptions2 (force_v4mapped) {
		let unix_path = this.options_map_.get('!unix_path');
		if (unix_path) {
			return {'path': unix_path};
		}
		let result_object = {};
		let bind_addr_key = null;
		if (this.domain_) {
			result_object.host = this.getDomainString();
		} else {
			if ((this.ip_ === 0n) || (this.ip_ === 0xffff00000000n)) {
				throw new Error('IP address is 0.0.0.0 or ::');
			} else {
				result_object.host = this.getIPString2(force_v4mapped);
				if (this.getHostNR(0xfe80n<<112n, 10) >= 0n) {
					let scope_id = this.options_map_.get('!ipv6_scope');
					if (scope_id) {
						scope_id = String(scope_id);
						if (!scope_id.startsWith('-')) {
							result_object.host += '%' + scope_id;
						}
					}
				}
				if (this.getHostNR(0xffff00000000n, 96) >= 0n) {
					if (force_v4mapped) {
						bind_addr_key = '!bind_addr4m';
					} else {
						bind_addr_key = '!bind_addr4';
					}
				} else {
					bind_addr_key = '!bind_addr6';
				}
			}
		}
		result_object.port = this.getPort();
		let localAddr = (bind_addr_key ? this.options_map_.get(bind_addr_key) : null) || this.options_map_.get('!bind_addr');
		if (localAddr) {
			result_object.localAddress = localAddr;
		}
		return result_object;
	}
	toNCCOptions () {
		return this.toNCCOptions2(false);
	}
	getHostNRThen (prefix, length, callback) {
		let result = this.getHostNR(prefix, length);
		if (result >= 0n) {
			return callback(result, this);
		}
		return undefined;
	}
	getSubdomainsOfThen (domain__, nr_parts, callback) {
		let result = this.getSubdomainsOf(domain__, nr_parts);
		if (result) {
			return callback(result, this);
		}
		return undefined;
	}
}
exports.Endpoint = Endpoint;
exports.fromCRAreq = function (req) {
	return (new Endpoint()).setDomain(req.host).setPort(req.port);
}
exports.ofLocal = function (s) {
	return (new Endpoint()).setIPStringWithScope(s.localAddress).setPort(s.localPort);
}
exports.ofRemote = function (s) {
	return (new Endpoint()).setIPStringWithScope(s.remoteAddress).setPort(s.remotePort);
}
exports.ofPrefix = function(prefix) {
	let ipAddr = prefix;
	let length = 128n;
	let i = prefix.indexOf('/');
	if (i >= 0) {
		ipAddr = prefix.substring(0, i);
		length = BigInt(prefix.substring(i+1)) + ((ipAddr.indexOf(':') >= 0) ? 0n : 96n);
	}
	return [new Endpoint().setIPString(ipAddr).getIPBigInt(), length];
}
exports.ofDomain = function(domain__) {
	return new Endpoint().setDomain2(domain__, false).getDomain();
}
exports.addressChomper = function(ipAddress, initialPosition) {
	let _result = {value: ipAddress, position: initialPosition};
	_result.setPosition = function(newPosition) {_result.position = newPosition;};
	_result.chomp = function(nr_bits) {
		if (nr_bits > _result.position) throw new Error("nr_bits beyond current position");
		_result.position -= nr_bits;
		return (_result.value >> _result.position) & ((1n << nr_bits) - 1n);
	};
	return _result;
}
