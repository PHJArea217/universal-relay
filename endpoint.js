'use strict';
const ip = require('ip');
const net = require('net');
class Endpoint {
	constructor () {
		this.ip_ = 0n;
		this.domain_ = null;
		this.options_map_ = new Map();
		this.port_ = 0;
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
	getIPBuffer () {
		let v4_host_nr = this.getHostNR(0xffff00000000n, 96);
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
	getIPString () {
		return ip.toString(this.getIPBuffer());
	}
	setDomain2 (domain, convert_to_ip) {
		let d = domain;
		if (!d) {
			throw new Error("Domain undefined or null");
		}
		if (!Array.isArray(d)) {
			d = String(domain);
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
	setDomain (domain) {
		return this.setDomain2(domain, true);
	}
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
	getSubdomainsOfLex (base_domain, nr_parts_to_keep) {
		if (!this.domain_) {
			return null;
		}
		let domain_length = base_domain.length;
		for (let i = 0; i < domain_length; i++) {
			let a = this.domain_[i];
			let b = base_domain[i];
			if (a > b) {
				return -1n;
			} else if (a < b) {
				return -2n;
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
	toNCCOptions () {
		let unix_path = this.options_map_.get('!unix_path');
		if (unix_path) {
			return {'path': unix_path};
		}
		let result_object = {};
		if (this.domain_) {
			result_object.host = this.getDomainString();
		} else {
			if ((this.ip_ === 0n) || (this.ip_ === 0xffff00000000n)) {
				throw new Error('IP address is 0.0.0.0 or ::');
			} else {
				result_object.host = this.getIPString();
				if (this.getHostNR(0xfe80n<<112n, 10) >= 0n) {
					let scope_id = this.options_map_.get('!ipv6_scope');
					if (scope_id) {
						scope_id = String(scope_id);
						if (!scope_id.startsWith('-')) {
							result_object.host += '%' + scope_id;
						}
					}
				}
			}
		}
		result_object.port = this.getPort();
		let localAddr = this.options_map_.get('!bind_addr');
		if (localAddr) {
			result_object.localAddress = localAddr;
		}
		return result_object;
	}
	getHostNRThen (prefix, length, callback) {
		let result = this.getHostNR(prefix, length);
		if (result >= 0n) {
			return callback(result, this);
		}
		return undefined;
	}
	getSubdomainsOfThen (domain, nr_parts, callback) {
		let result = this.getSubdomainsOf(domain, nr_parts);
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
exports.ofDomain = function(domain) {
	return new Endpoint().setDomain2(domain, false).getDomain();
}
