const net = require('net');
function resolve_dns_dualstack(domainName, dnsResolver, mode) {
	return new Promise((resolve, reject) => {
		if ((domainName.indexOf(':') >= 0) || (/^[0-9.]*$/.matches(domainName))) {
			resolve([domainName]);
			return;
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
					for (let i of u_ipv4) {result.push(i); if (result.length > 25) break;}
					for (let i of u_ipv6) {result.push(i); if (result.length > 25) break;}
					break;
				case "6_strong": /* strongly prefer ipv6 */
					for (let i of u_ipv6) {result.push(i); if (result.length > 25) break;}
					for (let i of u_ipv4) {result.push(i); if (result.length > 25) break;}
					break;
				case "4_weak":
					while ((u_ipv4.length > 0) || (u_ipv6.length > 0)) {
						if (u_ipv4.length > 0) result.push(u_ipv4.shift());
						if (u_ipv6.length > 0) result.push(u_ipv6.shift());
						/* Technically this is an off by one error but the limit is not a "hard" limit */
						if (result.length > 25) break;
					}
					break;
				case "6_weak":
					while ((u_ipv4.length > 0) || (u_ipv6.length > 0)) {
						if (u_ipv6.length > 0) result.push(u_ipv6.shift());
						if (u_ipv4.length > 0) result.push(u_ipv4.shift());
						if (result.length > 25) break;
					}
					break;
			}
			resolve(result);
		};
		dnsResolver.lookup4(domainName, (err, addresses) => {
			if (err) {
				state.ipv4 = [];
			} else {
				state.ipv4 = addresses;
			}
			if (state.ipv6 !== null) {
				nextStepAll();
			} else {
				setTimeout(nextStepAll, 1000);
			}
		});
		dnsResolver.lookup6(domainName, (err, addresses) => {
			if (err) {
				state.ipv6 = [];
			} else {
				state.ipv6 = addresses;
			}
			if (state.ipv4 !== null) {
				nextStepAll();
			} else {
				setTimeout(nextStepAll, 1000);
			}
		});
		setTimeout(nextStepAll, 10000);
	});
}
function connect_HE(req_array, connFunc, addOnAbort) {
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
			let conn = connFunc(req_array.shift());
			pendingConnections.push(conn);
			let onFailureCalled = false;
			conn.onSuccess(() => {
				if (onFailureCalled) return;
				onFailureCalled = true;
				state.done = true;
				for (let c of pendingConnections) {
					if ((c !== conn) && (c.abort !== null)) c.abort();
				}
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
function makeIPRewriteDNS(dnsResolver, mode, postIPRewrite) {
	return async function(connReadAttributes, socket) {
		let ips = await resolve_dns_dualstack(connReadAttributes.req.host, dnsResolver, mode);
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
					resultReqs.add(fakeCRA);
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
	let s = net.createConnection(reqAttr.req);
	return {
		result: s,
		onSuccess: (func) => s.once('connect', func),
		onFailure: (func) => s.once('error', func),
		abort: () => {
			s.destroy();
		}
	};
}

async function simple_connect_HE(socket, connReadAttributes) {
	let addOnAbort = (f) => socket.on('close', f);
	let req_array = Array.isArray(connReadAttributes) ? connReadAttributes : [connReadAttributes];
	return await connect_HE(req_array, connFuncDirect, addOnAbort);
}
exports.resolve_dns_dualstack = resolve_dns_dualstack;
exports.connect_HE = connect_HE;
exports.makeIPRewriteDNS = makeIPRewriteDNS;
exports.connFuncDirect = connFuncDirect;
exports.simple_connect_HE = simple_connect_HE;
