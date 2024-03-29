'use strict';
const ip = require('ip');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const endpoint = require('./endpoint.js');
function make_fake_DNS_state(ip_generator) {
	let result = {};
	result.byDomain = new Map();
	result.byIP = new Map();
	result.ip_generator = ip_generator;
	return result;
}
function updateEntry(state, entry, ttl) {
	let newTime = BigInt(new Date().getTime()) + ttl;
	entry[2] = newTime;
	state.byDomain.delete(entry[0]);
	state.byDomain.set(entry[0], entry);
	state.byIP.delete(entry[1]);
	state.byIP.set(entry[1], entry);
}
function deleteEntry(state, entry) {
	state.byDomain.delete(entry[0]);
	state.byIP.delete(entry[1]);
}
function pruneOldEntry(state) {
	let firstEntryDescriptor = state.byDomain[Symbol.iterator]().next();
	if (!firstEntryDescriptor.done) {
		let v = firstEntryDescriptor.value;
		deleteEntry(state, v);
	}
}
function findEntryByDomain(state, domain) {
	let existingEntry = state.byDomain.get(domain);
	/* Is there already an existing entry for this domain in cache? If so, update it and return the entry. */
	if (existingEntry) {
		updateEntry(state, existingEntry, 600000n);
		return existingEntry;
	}
	/* Otherwise, generate a random IP address for this entry (if there are not too many entries), and add it to the cache */
	if (state.byDomain.size > 10000) {
		pruneOldEntry(state);
	}
	let newEntry = [domain, state.ip_generator(domain), 0n];
	let existingEntryForIP = state.byIP.get(newEntry[1]);
	if (existingEntryForIP && (existingEntryForIP[0] !== domain)) {
		throw new Error('IP generator returned duplicate IPs!');
	}
	updateEntry(state, newEntry, 600000n);
	return newEntry;
}
function findEntryByIP(state, ip_address) {
	let existingEntry = state.byIP.get(ip_address);
	if (existingEntry) {
		updateEntry(state, existingEntry, 600000n);
		return existingEntry;
	}
	return null;
}
function canonicalizeDomain(domain) {
	let d = String(domain).toLowerCase();
	if (d.endsWith(".")) {
		d = d.substring(0, d.length - 1);
	}
	if (d.match(/^[0-9a-z._-]*$/)) {
		return d;
	} else {
		return null;
	}
}

function ipToBigInt(ip_address) {
	let result = 0n;
	for (let i = 0n; i < 16n; i++) {
		result |= BigInt(ip_address[Number(i)]) << (8n * (15n - i));
	}
	return result;
}

function parse_domain(domain) {
	let domain_c = canonicalizeDomain(domain);
	if (domain_c === null) return null;
	let domain_labels = domain_c.split('.');
	for (let label of domain_labels) {
		if (label === '') return null;
	}
	domain_labels.reverse();
	return domain_labels;
}
function unparse_domain(domain_labels) {
	let result = '';
	let first = true;
	for (let label of domain_labels) {
		result = label + (first ? '' : '.') + result;
		first = false;
	}
	return result;
}
function parse_ip(ip_address) {
	return ipToBigInt(ip.toBuffer(ip_address));
}
function unparse_ip(ip_int) {
	let result = Buffer.alloc(16);
	for (let i = 0n; i < 16n; i++) {
		result[15 - Number(i)] = Number((ip_int >> (8n * i)) & 0xffn);
	}
	return result;
}
const iid_cutoff = 0x600n << 48n;
function find_urelay_iid(prefix, ip_address) {
	let mask = ((1n<<128n)-(1n<<64n)); /* 0xfffffff...f0...0000000 */
	let ip_prefix = ip_address & mask;
	if (ip_prefix === (prefix << 64n)) {
		let iid_part = ip_address & ((1n<<64n)-1n);
		if (iid_part >= iid_cutoff) {
			return iid_part - iid_cutoff;
		} else {
			return -2n;
		}
	}
	return -1n;
}
function unfind_urelay_iid(prefix, ip_number) {
	if (ip_number < 0n) throw new Error();
	if (ip_number >= 0xfa00000000000000n) throw new Error();
	return (prefix << 64n) | (iid_cutoff + ip_number);
}
function make_urelay_ip_gen() {
	let urandom_fd = -1;
	let randomBuf = Buffer.alloc(5);
	try {
		urandom_fd = fs.openSync('/dev/urandom', 'r');
		if (fs.readSync(urandom_fd, randomBuf, 0, 5, 0) != 5) {
			throw new Error();
		}
	} catch (e) {
		crypto.getRandomValues(randomBuf);
	} finally {
		if (urandom_fd !== -1) fs.closeSync(urandom_fd);
	}
	let currentTime = new Date().getTime();
	let p1 = Math.floor(currentTime / 1000) % 65536;
	let p2 = Math.floor((currentTime % 1000) / 4);
	let initialCounterValue = (BigInt(p2) << 56n) |
		(BigInt(randomBuf[0]) << 48n) |
		(BigInt(randomBuf[1]) << 40n) |
		(BigInt(randomBuf[2]) << 32n) |
		(BigInt(p1) << 16n) |
		(BigInt(randomBuf[3]) << 8n) |
		(BigInt(randomBuf[4]) << 0n);
	let state = {counter: initialCounterValue};
	return function() {
		state.counter += 1n;
		if (state.counter >= 0xfa00000000000000n) {
			state.counter = 0n;
		}
		return state.counter;
	};
}
function make_urelay_ip_domain_map(prefix, dns_overrideFunc, options_arg) {
	let _result = {};
	_result.options = options_arg || {};
	_result.map_state = make_fake_DNS_state(_result.options.ip_generator || make_urelay_ip_gen());
	_result.prefix = prefix;
	_result.query_domain = function (domain_parts) {
		if (!Array.isArray(domain_parts)) return null;
		let domain_string = unparse_domain(domain_parts);
		let entry_result = findEntryByDomain(_result.map_state, domain_string);
		if (entry_result) {
			let result_ip = entry_result[1];
			return unparse_ip(unfind_urelay_iid(_result.prefix, result_ip));
		}
		return null;
	};
	_result.make_pdns_express_app = function(app, dof_arg_1, static_only) {
		let dof_arg = dof_arg_1;
		let staticOnly = static_only;
		app.use(express.urlencoded());
		app.post('/__pdns__/lookup', async function (req, res) {
			let input = JSON.parse(req.body.parameters);
			let qname = String(input.qname).toLowerCase();
			let qtype = String(input.qtype).toUpperCase();
			let result = [];
			if ((qname === '.') && !_result.options.rootIsNotSpecial) {
				if ((qtype === 'SOA') || (qtype === 'ANY')) {
					result.push({qname: '.', qtype: 'SOA', ttl: 120, content: 'dns-root.u-relay.home.arpa. u-relay.peterjin.org. 1 1000 1000 1000 120'});
				}
				if ((qtype === 'NS') || (qtype === 'ANY')) {
					result.push({qname: '.', qtype: 'NS', ttl: 120, content: 'dns-root.u-relay.home.arpa.'});
				}
			} else {
				let domain_labels = new endpoint.Endpoint();
				let do_aaaa = true;
				let do_dummy_hinfo = true;
				try {
					if (qname.length > 255) throw new Error();
					domain_labels.setDomain2(qname, false);
				} catch (e) {
					res.send(200, {result: []});
					return;
				}
				let overrideResult = dns_overrideFunc ? (await dns_overrideFunc(domain_labels.getDomain(), domain_labels, [dof_arg, req, res, 1])) : null;
				if (domain_labels.ip_) {
					let ipString = domain_labels.getIPString();
					let ipType = (ipString.indexOf(':') >= 0) ? 'AAAA' : 'A';
					overrideResult = [{qtype: ipType, content: ipString}];
				}
				if (Array.isArray(overrideResult)) {
					do_aaaa = false;
					for (let e of overrideResult) {
						if (e === null) {
							do_aaaa = true;
							continue;
						}
						if (e === 0) {
							do_dummy_hinfo = false;
							continue;
						}
						let fullEntry = ('qtype' in e) ? {
							qname: ('qname' in e) ? e.qname : qname,
							qtype: e.qtype,
							ttl: ('ttl' in e) ? e.ttl : 60,
							content: e.content} : {qname: qname, qtype: 'AAAA',
								ttl: 60, content: e};
						let a6_synth = false;
						if (fullEntry.qtype === 'URELAY-A6-SYNTH') {
							fullEntry.qtype = 'AAAA';
							a6_synth = true;
						}
						if ((qtype === 'ANY') || (qtype === fullEntry.qtype)) {
							if (a6_synth && ('a6_synth' in e)) {
								let a6_synth_val = BigInt(e.a6_synth);
								fullEntry.content = [
									((prefix >> 48n) & 0xffffn).toString(16),
									((prefix >> 32n) & 0xffffn).toString(16),
									((prefix >> 16n) & 0xffffn).toString(16),
									((prefix >> 0n) & 0xffffn).toString(16),
									((a6_synth_val >> 48n) & 0xffffn).toString(16),
									((a6_synth_val >> 32n) & 0xffffn).toString(16),
									((a6_synth_val >> 16n) & 0xffffn).toString(16),
									((a6_synth_val >> 0n) & 0xffffn).toString(16)
								].join(':');
							}
							result.push(fullEntry);
						}
					}
				}
				if (do_aaaa && domain_labels.domain_ && !staticOnly) {
					if ((qtype === 'ANY') || (qtype === 'AAAA')) {
						/* dns_overrideFunc could have called setDomain on the Endpoint
						 * to set a "lookup alias" for the original domain in qname */
						let result_ip = _result.query_domain(domain_labels.getDomain());
						if (result_ip) {
							let ipString = ip.toString(result_ip);
							result.push({qname: qname, qtype: 'AAAA', ttl: 60, content: ipString});
						} else {
							res.send(500);
							return;
						}
					}
				}
				if (do_dummy_hinfo && (result.length === 0)) {
					/* Without this dummy record, PowerDNS would return NXDOMAIN for blocked domains. Not what we want. */
					if ((qtype === 'ANY') || (qtype === 'HINFO')) {
						result = [{qname: qname, qtype: 'HINFO', ttl: 60, content: '"RFC8482" ""'}];
					}
				}
			}
//			if (result.length === 0) {
//				result = [{qname: req_path_parts[1], qtype: "0", ttl: 0, content: ""}];
//			}
			res.send(200, {result: result});
		});
		let common_function = async function (req, res, num) {
			let input = JSON.parse(req.body.parameters);
			let qname = String(input.name).toLowerCase();
			let result = [];
			if ((qname === '.') && !_result.options.rootIsNotSpecial) {
				res.send(200, {result: {"PRESIGNED": ["0"]}});
			} else {
				let domain_labels = new endpoint.Endpoint();
				try {
					if (qname.length > 255) throw new Error();
					domain_labels.setDomain2(qname, false);
				} catch (e) {
					res.send(200, {result: {}});
					return;
				}
				let overrideResult = (dns_overrideFunc && _result.options.haveDomainMetadata) ? (await dns_overrideFunc(domain_labels.getDomain(), domain_labels, [dof_arg, req, res, num])) : {};
				res.send(200, {result: overrideResult});
			}
		};
		app.post('/__pdns__/getalldomainmetadata', (req, res) => common_function(req, res, 2));
		app.post('/__pdns__/getAllDomainMetadata', (req, res) => common_function(req, res, 2));
		let get_all_domains_func = (req, res) => res.send(200, {result: _result.options.domainList || [{id: 1, zone: ".", kind: "native"}]});
		app.post('/__pdns__/getAllDomains', get_all_domains_func);
		app.post('/__pdns__/getalldomains', get_all_domains_func);
		app.use('/dump_data', function (req, res) {
			let result = [];
			for (let entry of _result.map_state.byIP) {
				result.push(entry[1][0] + " " + String(entry[1][1]));
			}
			res.send(200, result);
		});
	};
	/* Returns -1n if IP not within prefix, -3n if IP is within prefix
	 * but not found in dynamic map, a number >= 0n if IP is within
	 * static region, and the actual domain name as a string if IP is
	 * found within dynamic map.
	 * raw = 0 -> ip_buf is buffer containing full ipv6 address.
	 * raw = 1 -> ip_buf is bigint containing full ipv6 address.
	 * raw = 2 -> ip_buf is bigint containing bottom 64 bits of ipv6 address.
	 */
	_result.query_ip = function (ip_buf, success_array, raw) {
		let full_ip_num = ip_buf;
		if (!raw) {
			if (ip_buf.byteLength !== 16) return -1n;
			full_ip_num = ipToBigInt(ip_buf);
		}
		let iid = find_urelay_iid((raw === 2) ? 0n : _result.prefix, full_ip_num);
		if (iid === -2n) {
			return full_ip_num & ((1n<<64n)-1n); /* 0xffffffffffffffffn */
		}
		if (iid < 0n) return iid;
		let entry_result = findEntryByIP(_result.map_state, iid);
		if (entry_result) {
			if (success_array) success_array[0] = true;
			return String(entry_result[0]);
		}
		return -3n;
	};
	/* If the request type is ipv6 and the IP address of the req object
	 * is associated with a domain, then the req object is rewritten to be
	 * of type 'domain' and the host is set to that domain, and -4n is
	 * returned to indicate success. Otherwise, the return values are the
	 * same as those of query_ip.
	 * If raw is 1 or 2, then ip_bigint will be used as key for ip->domain
	 * lookups instead of the ipv6 address in the original req object.
	 */
	_result.rewrite_CRA_req = function (req, raw, ip_bigint) {
		if ((!raw) && (req.type !== 'ipv6')) return -1n;
		try {
			let success_array = [false];
			let result_domain = _result.query_ip(raw ? ip_bigint : ip.toBuffer(req.host), success_array, raw);
			if (success_array[0]) {
//				console.log(result_domain);
				req.type = 'domain';
				req.host = result_domain;
				return -4n;
			}
			return result_domain;
		} catch (e) {
//			console.log(e);
			return -3n;
		}
		return -3n;
	};
	return _result;
}
exports.make_fake_DNS_state = make_fake_DNS_state;
exports.updateEntry = updateEntry;
exports.deleteEntry = deleteEntry;
exports.pruneOldEntry = pruneOldEntry;
exports.findEntryByDomain = findEntryByDomain;
exports.findEntryByIP = findEntryByIP;
// exports.canonicalizeDomain = canonicalizeDomain;
exports.ipToBigInt = ipToBigInt;
exports.parse_domain = parse_domain;
exports.unparse_domain = unparse_domain;
exports.parse_ip = parse_ip;
exports.unparse_ip = unparse_ip;
exports.find_urelay_iid = find_urelay_iid;
exports.unfind_urelay_iid = unfind_urelay_iid;
exports.make_urelay_ip_gen = make_urelay_ip_gen;
exports.make_urelay_ip_domain_map = make_urelay_ip_domain_map;
