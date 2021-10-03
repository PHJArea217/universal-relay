const promises_lib = require("./common_promises.js");
async function transparent_server(conn) {
	let host = String(conn.localAddress);
	/* Since the meaning of IPv6 scope IDs for link locals could be different in other network namespaces, trim it off. It's mostly useless here. */
	let percent_brk = host.indexOf('%');
	if (percent_brk >= 0) {
		host = host.substring(0, percent_brk);
	}
	let type = 'ipv4';
	if (host.indexOf(':') >= 0) {
		type = 'ipv6';
	}
	return {req: {host: host, port: Number(conn.localPort), type: type}, excessBuf: null};
}
async function transparent_connect(origSocket, dest) {
	let reqArray = Array.isArray(dest.req) ? dest.req : [dest.req];
	let success = false;
	let eError = null;
	let newConn = null;
	for (let req_i of reqArray) {
		if (origSocket.destroyed) break;
		try {
			newConn = await promises_lib.socketConnect({host: req_i.host, port: req_i.port}, origSocket);
			success = true;
			break;
		} catch (e) {
			eError = e;
		}
	}
	if (success) {
		return newConn;
	}
	throw eError;
}
exports.transparent_server = transparent_server;
exports.transparent_connect = transparent_connect;
