const endpoint = require('./endpoint.js');
function handle_inaddr_arpa(lower_parts) {
	if (lower_parts.length !== 4) {
		return -1n;
	}
	let result = 0xffffn;
	try {
		for (let i = 0; i < 4; i++) {
			let val = BigInt(lower_parts[i]);
			if ((val >= 0n) && (val < 256n)) {
				result = (result << 8n) | val;
			} else {
				return -1n;
			}
		}
	} catch (e) {
		return -1n;
	}
	return result;
}
function handle_ip6_arpa(lower_parts) {
	if (lower_parts.length !== 32) {
		return -1n;
	}
	let result = 0n;
	for (let i = 0; i < 32; i++) {
		let val = '0123456789abcdef'.indexOf(lower_parts[i]);
		if (val < 0) return -1n;
		result = (result << 4n) | BigInt(val);
	}
	return result;
}
var identityMap = (x) => x;
function make_bidir_map(staticMap, options) {
	let result = {};
	let options_ = options || {};
	let staticMap_ = staticMap || [];
	result.options = options_;
	result.forward_map = new Map();
	result.reverse_map = new Map();
	result.translate_forward = function (key) {
		if (result.options.forward_override) {
			let override_result = result.options.forward_override(key);
			if (override_result !== null) {
				return override_result;
			}
		}
		return result.forward_map.get(key) || null;
	};
	result.translate_reverse = function (key) {
		if (result.options.reverse_override) {
			let override_result = result.options.reverse_override(key);
			if (override_result !== null) {
				return override_result;
			}
		}
		return result.reverse_map.get(key) || null;
	};
	for (let entry of staticMap_) {
		let entry0 = (result.options.entry0_transform || identityMap)(entry[0]);
		let entry1 = (result.options.entry1_transform || identityMap)(entry[1]);
		result.forward_map.set(entry0, [entry1, entry[2]]);
		result.reverse_map.set(entry1, [entry0, entry[2]]);
	}
	return result;
}
function make_lookup_mapping(staticMap, options) {
	let result = {};
	let options_ = options || {};
	result.options = options_;
	result.staticMap = staticMap;
	result.lookup = function (key) {
		let result_rrset = [];
		if (result.options.dynamicOverride) {
			let overrideResult = result.options.dynamicOverride(key);
			if (Array.isArray(overrideResult)) {
				if (Array.isArray(overrideResult[0])) {
					if (overrideResult[0][0] !== null) {
						return {"src": "do", "rrset": overrideResult[0], "user_obj": overrideResult[1]};
					} else {
						result_rrset.push(...(overrideResult[0].slice(1)));
					}
				}
			}
		}
		if (result.staticMap) {
			let overrideResult = result.staticMap.get(key);
			if (Array.isArray(overrideResult)) {
			} else if (overrideResult) /* is a function */ {
				overrideResult = overrideResult(key);
			}
			if (overrideResult) {
				if (Array.isArray(overrideResult[0])) {
					if (overrideResult[0][0] !== null) {
						result_rrset.push(...(overrideResult[0]));
						return {"src": "sm", "rrset": result_rrset, "user_obj": overrideResult[1]};
					} else {
						result_rrset.push(...(overrideResult[0].slice(1)));
					}
				}
			}
		}
		if (result.bidir_map) {
			let overrideResult = result.bidir_map[result.options.reverse ? 'translate_reverse'
				: 'translate_forward']((result.options.bidir_input_transform || identityMap)(key));
			if (overrideResult) {
				let overrideResult2 = (result.options.bidir_output_transform || identityMap)(overrideResult);
				if (Array.isArray(overrideResult2)) {
					result_rrset.push(...(overrideResult2[0]));
					return {"src": "bd", "rrset": result_rrset, "user_obj": overrideResult2[1]};
				}
			}
		}
		if (result_rrset.length === 0) {
			return null;
		}
		return {"src": "none", "rrset": result_rrset};
	};
	return result;
}
function make_soa_ns_handler(default_soa, default_ns, options) {
	function generate_rrset(soa, ns) {
		let result_rrset = [{qtype: 'SOA', content: soa}];
		for (let n of ns) {
			result_rrset.push({qtype: 'NS', content: n});
		}
		return result_rrset;
	}
	let result = {options: options || {}, domainList: [], default_soa: default_soa, default_ns: default_ns, map: new Map(), counter: 0};
	result.addDomain = function (domain, soa, ns) {
		result.map.set(domain, generate_rrset(soa || result.default_soa, ns || result.default_ns));
		result.domainList.push({id: ++result.counter, zone: (domain.endsWith('.') ? domain : (domain + '.')), kind: "native"});
	};
	result.getSOANS = function (ep) {
		let r = result.map.get(ep.getDomainString());
		return r || [];
	};
	return result;
}
function make_acme_challenge_handler(options) {
	let result = {options: options || {}, domain_map: new Map()};
	result.addKey = function (key) {
		result.domain_map.set(key, []);
	};
	result.getAcmeChallengeTXTFunc = function (keys) {
		return function () {
			let resultTXTRecords = [];
			for (let k of keys) {
				let v = result.domain_map.get(k);
				if (v) {
					for (let r of v) {
						resultTXTRecords.push({qtype: "TXT", content: '"' + r + '"'});
					}
				}
			}
			return resultTXTRecords;
		};
	};
	result.make_express_app = function (app) {
		app.post('/add', function (req, res) {
			let k = String(req.query.k);
			let c = String(req.query.c);
			if (c.match(/^[0-9A-Za-z_-]{20,60}$/) || (c === 'clear')) {
				let v = result.domain_map.get(k);
				if (v) {
					if (c === 'clear') {
						while (v.length > 0)
							v.pop();
					} else if (v.length < 2) {
						console.log(c + ' -> ' + k);
						v.push(c);
					} else {
						res.send(400, 'too many TXT records for key');
						return;
					}
					res.send(200, 'success');
				} else {
					res.send(400, 'invalid key');
				}
			} else {
				res.send(400, 'invalid challenge string');
			}
		});
		app.get('/list', function (req, res) {
			let result2 = [];
			for (let k of result.domain_map.entries()) {
				result2.push(k);
			}
			res.send(200, result2);
		});
		app.get('/', function (req, res) {
			res.header('content-type', 'text/html');
			res.send(200, '<form action="/add" method="post"><input id="k"></input><input id="c"></input><input type="submit"></input></form>');
		});
	};
	return result;
}
function make_output_transform_ip(numbers_only, ranges) {
	return function (input) {
		let result = [];
		let relative_ip = input[0];
		let user_obj = input[1];
		for (let r of ranges){
			let offset = r.offset || 0n;
			let base = r.base;
			let limit = r.limit;
			if (relative_ip >= offset) {
				let offset_ip = relative_ip - offset;
				if (offset_ip < limit){
					if (numbers_only) {
						result.push(offset_ip + base);
					} else {
						let ep = new endpoint.Endpoint();
						ep.setIPBigInt(offset_ip + base);
						let ip_string = ep.getIPString();
						if (ip_string.indexOf(':') >= 0) {
							result.push({qtype: 'AAAA', content: ip_string});
						} else {
							result.push({qtype: 'A', content: ip_string});
						}
					}
				}
			}
		}
		return [result, user_obj];
	};
}
exports.handle_inaddr_arpa = handle_inaddr_arpa;
exports.handle_ip6_arpa = handle_ip6_arpa;
exports.make_bidir_map = make_bidir_map;
exports.make_lookup_mapping = make_lookup_mapping;
exports.make_soa_ns_handler = make_soa_ns_handler;
exports.make_acme_challenge_handler = make_acme_challenge_handler;
