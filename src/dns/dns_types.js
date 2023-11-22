'use strict';
const dns_packet = require('./dns_packet.js');
const domain_name = require('./domain_name.js');
class DNSRecord {
	constructor(name, class_, type, ttl) {
		this.name = name;
		this.class = class_;
		this.type = type;
		this.ttl = ttl;
	}
}
class AAAA extends DNSRecord {
	constructor(name, class_, ttl, ip_number) {
		super(name, class_, 28, ttl);
		this.ip_number = ip_number;
	}
	write_serial_dns_data(b) {
		let buf = Buffer.alloc(16);
		buf.writeBigUInt64BE(this.ip_number >> 64n, 0);
		buf.writeBigUInt64BE(this.ip_number & 0xffff_ffff_ffff_ffffn, 8);
		b.append_buffer(buf);
	}
}
class A extends DNSRecord {
	constructor(name, class_, ttl, ip_number) {
		super(name, class_, 1, ttl);
		this.ip_number = ip_number;
	}
	write_serial_dns_data(b) {
		let buf = Buffer.alloc(4);
		buf.writeUInt32BE(this.ip_number, 0);
		b.append_buffer(buf);
	}
}
class CAA extends DNSRecord {
	constructor(name, class_, ttl, flags, tag, value) {
		super(name, class_, 257, ttl);
		this.caa_flags = flags;
		this.caa_tag = tag;
		this.caa_value = value;
	}
	write_serial_dns_data(b) {
		let tag_bin = Buffer.from(this.caa_tag);
		let val_bin = Buffer.from(this.caa_value);
		b.append_buffer(Buffer.from([this.caa_flags, tag_bin.length]), tag_bin, val_bin);
	}
}
class CNAME extends DNSRecord {
	constructor(name, class_, ttl, target) {
		super(name, class_, 5, ttl);
		this.target = target;
	}
	write_serial_dns_data(b) {
		b.append_domain(this.target);
	}
}
class HINFO extends DNSRecord {
	constructor(name, class_, ttl, cpu, os) {
		super(name, class_, 13, ttl);
		this.cpu = cpu;
		this.os = os;
	}
	write_serial_dns_data(b) {
		b.append_string(this.cpu);
		b.append_string(this.os);
	}
}
class MX extends DNSRecord {
	constructor(name, class_, ttl, mxprio, target) {
		super(name, class_, 15, ttl);
		this.target = target;
		this.mxprio = mxprio;
	}
	write_serial_dns_data(b) {
		let buf = Buffer.alloc(2);
		buf.writeUInt16BE(this.mxprio, 0);
		b.append_buffer(buf);
		b.append_domain(this.target);
	}
}
class NS extends DNSRecord {
	constructor(name, class_, ttl, target) {
		super(name, class_, 2, ttl);
		this.target = target;
	}
	write_serial_dns_data(b) {
		b.append_domain(this.target);
	}
}
class PTR extends DNSRecord {
	constructor(name, class_, ttl, target) {
		super(name, class_, 12, ttl);
		this.target = target;
	}
	write_serial_dns_data(b) {
		b.append_domain(this.target);
	}
}
class SOA extends DNSRecord {
	constructor(name, class_, ttl, mname, rname, serial, refresh, retry, expire, minimum) {
		super(name, class_, 6, ttl);
		this.mname = mname;
		this.rname = rname;
		this.serial = serial;
		this.refresh = refresh;
		this.retry = retry;
		this.expire = expire;
		this.minimum = minimum;
	}
	write_serial_dns_data(b) {
		b.append_domain(this.mname);
		b.append_domain(this.rname);
		let buf = Buffer.alloc(20);
		buf.writeUInt32BE(this.serial, 0);
		buf.writeUInt32BE(this.refresh, 4);
		buf.writeUInt32BE(this.retry, 8);
		buf.writeUInt32BE(this.expire, 12);
		buf.writeUInt32BE(this.minimum, 16);
		b.append_buffer(buf);
	}
}
class TXT extends DNSRecord {
	constructor(name, class_, ttl, strings) {
		super(name, class_, 16, ttl);
		this.strings = strings;
	}
	write_serial_dns_data(b) {
		for (let s of this.strings) b.append_string(s);
	}
}
exports.DNSRecord = DNSRecord;
exports.dns_types = {
	A: A,
	AAAA: AAAA,
	CAA: CAA,
	CNAME: CNAME,
	HINFO: HINFO,
	MX: MX,
	NS: NS,
	PTR: PTR,
	SOA: SOA,
	TXT: TXT
};
