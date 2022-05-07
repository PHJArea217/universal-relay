const ip = require('ip');
const net = require('net');
function Endpoint() {
	this.ip_ = 0n;
	this.domain_ = null;
	this.options_map_ = new Map();
	this.port_ = 0;
	this.setIPBigInt = function (newIP) {
		if ((newIP >= 0n) && (newIP < (1n<<128n))) {
			this.ip_ = newIP;
			this.domain_ = null;
			return this;
		} else {
			throw new Error("newIP must be between 0n and (1n<<128n)-1");
		}
	};
	this.setIPBuffer = function (newIP) {
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
	};
	this.setIPString = function (newIP) {
		return this.setIPBuffer(ip.toBuffer(newIP));
	};
	this.setIPStringWithScope = function (newIP) {
		let newIPString = String(newIP);
		let percent_position = newIPString.indexOf('%');
		if (percent_position >= 0) {
			this.setIPString(newIPString.substring(0, percent_position));
			this.options_map_.set('!ipv6_scope', newIPString.substring(percent_position + 1));
			return this;
		} else {
			return this.setIPString(newIPString);
		}
	};
	this.getIPBigInt = function () {
		return this.ip_;
	};
	this.getIPBuffer = function () {
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
	};
	this.getIPString = function () {
		return ip.toString(this.getIPBuffer());
	};
	this.setDomain2 = function (domain, convert_to_ip) {
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
		this.domain_ = r;
		this.ip_ = 0n;
		return this;
	};
	this.setDomain = function (domain) {
		return this.setDomain2(domain, true);
	};
	this.getHostNR = function (prefix, length) {
		let bitmask = 128n - BigInt(length);
		if ((bitmask < 0n) || (bitmask > 128n)) {
			throw new Error('Prefix length must be between 0 and 128 inclusive');
		}
		let host_mask = (1n << bitmask) - 1n;
		let network_mask = (1n << 128n) - (1n << bitmask);
		if ((this.ip_ & network_mask) === (prefix & network_mask)) {
			return this.ip_ & host_mask;
		}
		return -1n;
	};
	this.getPort = function () {
		return this.port_;
	};
	this.setPort = function (port) {
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
	};
	this.getDomain = function () {
		return this.domain_;
	};
	this.getDomainString = function () {
		if (!this.domain_) return null;
		if (this.domain_.length === 0) return ".";
		let d = this.domain_.slice();
		d.reverse();
		return d.join('.');
	};
	this.getSubdomainsOf = function (base_domain, nr_parts_to_keep) {
		if (!this.domain_) {
			return null;
		}
		let domain_length = base_domain.length;
		for (let i = 0; i < domain_length; i++) {
			if (this.domain_[i] === base_domain[i]) {
			} else {
				return null;
			}
		}
		return this.domain_.slice(domain_length, domain_length + nr_parts_to_keep);
	};
	this.resolveDynamic = async function (resolver, options_) {
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
	};
	this.clone = function () {
		let cloned_this = new Endpoint();
		cloned_this.ip_ = this.ip_;
		cloned_this.domain_ = this.domain_ ? this.domain_.slice() : null;
		cloned_this.port_ = this.port_;
		for (let e of this.options_map_.entries()) {
			cloned_this.options_map_.set(e[0], e[1]);
		}
		return cloned_this;
	};
	this.toCRAreq = function () {
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
	};
	this.toNCCOptions = function () {
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
						result_object.host += '%' + scope_id;
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
	};
	this.getHostNRThen = function (prefix, length, callback) {
		let result = this.getHostNR(prefix, length);
		if (result >= 0n) {
			return callback(result, this);
		}
		return undefined;
	};
	this.getSubdomainsOfThen = function (domain, nr_parts, callback) {
		let result = this.getSubdomainsOf(domain, nr_parts);
		if (result) {
			return callback(result, this);
		}
		return undefined;
	};
}
exports.Endpoint = Endpoint;
exports.fromCRAreq = function (req) {
	return (new Endpoint()).setDomain(req.host).setPort(req.port);
}
