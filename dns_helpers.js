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
			let overrideResult = result.bidir_map[result.options.reverse ? 'translate_reverse' \
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
		result.domainList.push({id: ++counter, zone: (domain.endsWith('.') ? domain : (domain + '.')), kind: "native"});
	};
	result.getSOANS = function (ep) {
		let r = result.map.get(ep.getDomainString());
		return r || [];
	};
	return result;
}
exports.handle_inaddr_arpa = handle_inaddr_arpa;
exports.handle_ip6_arpa = handle_ip6_arpa;
exports.make_bidir_map = make_bidir_map;
exports.make_lookup_mapping = make_lookup_mapping;
