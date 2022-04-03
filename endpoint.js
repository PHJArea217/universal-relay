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
	this.setDomain = function (domain) {
		let d = domain;
		if (!Array.isArray(d)) {
			d = String(domain);
			if (net.isIP(d)) {
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
}
exports.Endpoint = Endpoint;
