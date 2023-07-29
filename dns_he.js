'use strict';
const net = require('net');
const fake_dns = require('./fake_dns.js');
const socks_server = require('./socks_server.js');
function resolve_dns_dualstack(_domainName, dnsResolver, mode, overrideFunc) {
	return new Promise((resolve, reject) => {
		let domainNameX = String(_domainName);
		if (net.isIP(domainNameX)) {
			resolve([domainNameX]);
			return;
		}
		let domain_parts = fake_dns.parse_domain(domainNameX);
		if (domain_parts === null) {
			resolve([]);
			return;
		}
		let domainName = fake_dns.unparse_domain(domain_parts);
		if (overrideFunc) {
			let overrideFuncResult = overrideFunc(domain_parts, domainName);
			if (Array.isArray(overrideFuncResult)) {
				resolve(overrideFuncResult);
				return;
			}
		}
		let state = {ipv4: null, ipv6: null, alreadyReturned: false};
		let nextStepAll = () => {
			if (state.alreadyReturned) return;
			state.alreadyReturned = true;
			let u_ipv4 = state.ipv4 || [];
			let u_ipv6 = state.ipv6 || [];
			let result = [];
			switch (mode) {
				case "4_strong": /* strongly prefer ipv4 */
					for (let i of u_ipv4) {result.push(i); if (result.length > 3) break;}
					for (let i of u_ipv6) {result.push(i); if (result.length > 3) break;}
					break;
				case "6_strong": /* strongly prefer ipv6 */
					for (let i of u_ipv6) {result.push(i); if (result.length > 3) break;}
					for (let i of u_ipv4) {result.push(i); if (result.length > 3) break;}
					break;
				case "4_weak":
					while ((u_ipv4.length > 0) || (u_ipv6.length > 0)) {
						if (u_ipv4.length > 0) result.push(u_ipv4.shift());
						if (u_ipv6.length > 0) result.push(u_ipv6.shift());
						/* Technically this is an off by one error but the limit is not a "hard" limit */
						if (result.length > 5) break;
					}
					break;
				case "6_weak":
					while ((u_ipv4.length > 0) || (u_ipv6.length > 0)) {
						if (u_ipv6.length > 0) result.push(u_ipv6.shift());
						if (u_ipv4.length > 0) result.push(u_ipv4.shift());
						if (result.length > 5) break;
					}
					break;
			}
			resolve(result);
		};
		dnsResolver.resolve4(domainName, (err, addresses) => {
			if (err) {
				state.ipv4 = [];
			} else {
				state.ipv4 = addresses;
			}
			if (state.ipv6 !== null) {
				nextStepAll();
			} else {
				setTimeout(nextStepAll, 2000);
			}
		});
		dnsResolver.resolve6(domainName, (err, addresses) => {
			if (err) {
				state.ipv6 = [];
			} else {
				state.ipv6 = addresses;
			}
			if (state.ipv4 !== null) {
				nextStepAll();
			} else {
				setTimeout(nextStepAll, 2000);
			}
		});
		setTimeout(nextStepAll, 10000);
	});
}
function make_endpoint_resolver(dnsResolver, mode, overrideFunc) {
	return async function (domain_labels, domain_name, ep) {
		return await resolve_dns_dualstack(domain_name, dnsResolver, mode, overrideFunc);
	};
}
function connect_HE(req_array, connFunc, addOnAbort, origCRA) {
	return new Promise((resolve, reject) => {
		if (req_array.length === 0) reject();
		let state = {connectionsLeft: req_array.length, done: false};
		let pendingConnections = [];
		addOnAbort(() => {
			state.done = true;
			for (let c of pendingConnections) {
				if (c.abort !== null) {
					c.abort();
				}
			}
			reject();
		});
		let tryNewConnection = () => {
			if (state.done) return;
			if (req_array.length === 0) return;
			let current_req = req_array[0];
			let conn = ((current_req.hasOwnProperty("__orig_endpoint__") ? current_req.__orig_endpoint__.options_map_.get("!connFunc") : null) || connFunc)(current_req);
			req_array.shift();
			pendingConnections.push(conn);
			let onFailureCalled = false;
			conn.onSuccess(() => {
				if (onFailureCalled) return;
				onFailureCalled = true;
				state.done = true;
				for (let c of pendingConnections) {
					if ((c !== conn) && (c.abort !== null)) c.abort();
				}
				if (current_req.sendOnAccept2 && origCRA) origCRA.sendOnAccept2 = current_req.sendOnAccept2;
				conn.result.pause();
				resolve(conn.result);
			});
			let onFailure = () => {
				if (onFailureCalled) return;
				onFailureCalled = true;
				state.connectionsLeft--;
				if (state.connectionsLeft <= 0) {
					state.done = true;
					reject();
					return;
				}
				conn.abort = null;
				setTimeout(tryNewConnection, 200);
			};
			conn.onFailure(onFailure);
			setTimeout(onFailure, 10000);
		};
		process.nextTick(tryNewConnection);
		setTimeout(tryNewConnection, 500);
	});
}
function makeIPRewriteDNS(dnsResolver, mode, postIPRewrite, overrideFunc) {
	return async function(connReadAttributes, socket) {
		let ips = await resolve_dns_dualstack(connReadAttributes.req.host, dnsResolver, mode, overrideFunc);
		let resultReqs = [];
		for (let i of ips) {
			let j = String(i);
			let fakeCRA = {
				req: {
					type: (j.indexOf(':') >= 0) ? 'ipv6' : 'ipv4',
					host: j,
					port: connReadAttributes.req.port
				},
				originalDomain: connReadAttributes.req.host
			};
			try {
				if ((await postIPRewrite(fakeCRA, socket)) === null) {
					resultReqs.push(fakeCRA.req);
				}
			} catch (e) {
			}
		}
		if (resultReqs.length > 0) {
			connReadAttributes.req = resultReqs;
			return null;
		} else {
			throw new Error();
		}
	};
}

function connFuncDirect(reqAttr) {
	let s = net.createConnection(reqAttr.__orig_endpoint__ ? reqAttr.__orig_endpoint__.toNCCOptions() : reqAttr);
	return {
		result: s,
		onSuccess: (func) => s.once('connect', func),
		onFailure: (func) => s.once('error', func),
		abort: () => {
			s.destroy();
		}
	};
}
function connFuncDirectTLS(reqAttr) {
	if (reqAttr.__orig_endpoint__) {
		let o = reqAttr.__orig_endpoint__.options_map_.get('!tls_options');
		if (o) {
			if (!Object.hasOwn(o, "port")) {
				o = {...o};
				Object.assign(o, reqAttr.__orig_endpoint__.toNCCOptions());
			}
			let s = tls.connect(o);
			return {
				result: s,
				onSuccess: (func) => s.once('secureConnect', func),
				onFailure: (func) => s.once('error', func),
				abort: () => {
					s.destroy();
				}
			};
		}
	}
	throw new Error("!tls_options not found in reqAttr.__orig_endpoint__");
}
function connFuncSocks(reqAttr) {
	let socksPromise = socks_server.make_socks_client(reqAttr.__orig_endpoint__.options_map_.get("!socks_server"));
	let state = {success: null, failure: null};
	let result = {
		result: null,
		onSuccess: ((func) => state.success = func),
		onFailure: ((func) => state.failure = func),
		abort: () => {
			if (reqAttr.hasOwnProperty("_conn")) {
				reqAttr._conn.destroy();
			}
		}
	};
	process.nextTick(() => {
		reqAttr.req = reqAttr; /* hacky but we need the reqAttr to be under .req AND we need to collect .sendOnAccept2 */
		socksPromise(null, reqAttr).then((result_) => {
			result.result = result_;
			state.success();
		}).catch(() => {
			state.failure();
		});
	});
	return result;
}

async function simple_connect_HE(socket, connReadAttributes) {
	let addOnAbort = (f) => socket.on('close', f);
	let req_array = Array.isArray(connReadAttributes.req) ? connReadAttributes.req : [connReadAttributes.req];
	return await connect_HE(req_array, connFuncDirect, addOnAbort, connReadAttributes);
}
function dns_sort(endpoints, options) {
	options = options || {};
	let max_ipv4 = Object.hasOwn(options, 'max_ipv4') ? options.max_ipv4 : 3;
	let max_ipv6 = Object.hasOwn(options, 'max_ipv6') ? options.max_ipv6 : 3;
	let max_all = Object.hasOwn(options, 'max_all') ? options.max_all : 5;
	let mode = Object.hasOwn(options, 'mode') ? options.mode : '6_weak';
	let available_ipv4 = [];
	let available_ipv6 = [];
	for (const e of endpoints) {
		let ip_type = e.options_map_.get('!ip_type');
		let which_array = null;
		switch (ip_type) {
			case 4:
				which_array = available_ipv4;
				break;
			case 6:
				which_array = available_ipv6;
				break;
			default:
				which_array = ((e.getIPBigInt() >> 32n) == 0xffffn) ? available_ipv4 : available_ipv6;
				break;
		}
		which_array.push(e);
	}
	let result = [];
	let limit4 = {cur: 0, max: max_ipv4};
	let limit6 = {cur: 0, max: max_ipv6};
	let limit_all = {cur: 0, max: max_all};
	function add_from(which_array, limit) {
		if (which_array.length < 1) return false;
		let idx = Math.floor(Math.random() * which_array.length);
		let em = which_array[idx];
		if (!em) throw new Error();
		if (limit.cur >= limit.max) return false;
		if (limit_all.cur >= limit_all.max) return false;
		limit.cur++;
		limit_all.cur++;
		result.push(em);
		let removed_element = which_array.pop();
		if (idx < which_array.length) {
			which_array[idx] = removed_element;
		}
		return true;
	}
	switch (mode) {
		case '4_weak':
			while(add_from(available_ipv4, limit4) | add_from(available_ipv6, limit6)) {}
			break;
		case '6_weak':
			while(add_from(available_ipv6, limit6) | add_from(available_ipv4, limit4)) {}
			break;
		case '4_strong':
			while (add_from(available_ipv4, limit4)) {}
			while (add_from(available_ipv6, limit6)) {}
			break;
		case '6_strong':
			while (add_from(available_ipv6, limit6)) {}
			while (add_from(available_ipv4, limit4)) {}
			break;
		case '4_only':
			while (add_from(available_ipv4, limit4)) {}
			break;
		case '6_only':
			while (add_from(available_ipv6, limit6)) {}
			break;
	}
	return result;
}
exports.resolve_dns_dualstack = resolve_dns_dualstack;
exports.make_endpoint_resolver = make_endpoint_resolver;
exports.connect_HE = connect_HE;
exports.makeIPRewriteDNS = makeIPRewriteDNS;
exports.connFuncDirect = connFuncDirect;
exports.connFuncSocks = connFuncSocks;
exports.simple_connect_HE = simple_connect_HE;
exports.dns_sort = dns_sort;
