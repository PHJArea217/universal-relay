const promises_lib = require("./common_promises.js");
async function transparent_server(conn) {
	let host = String(conn.localAddress);
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
	for (let req_i of reqArray) {
		if (origSocket.destroyed) break;
		try {
			let newConn = await promises_lib.socketConnect({host: reqArray.host, port: reqArray.port}, origSocket);
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
