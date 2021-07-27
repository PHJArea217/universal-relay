async function transparent_server(conn) {
	let host = String(conn.localAddress);
	let type = 'ipv4';
	if (host.indexOf(':') >= 0) {
		type = 'ipv6';
	}
	return {host: host, port: Number(conn.localPort), excessBuf: null, type: type};
}
async function transparent_connect(origSocket, dest) {
	try {
		let newConn = await promises_lib.socketConnect({host: dest.host, port: dest.port}, origSocket);
		if (origSocket.excessBuf) {
			newConn.write(origSocket.excessBuf);
		}
		if (origSocket.sendOnAccept) {
			origSocket.write(origSocket.sendOnAccept);
		}
		return newConn;
	} catch (e) {
		if (origSocket.sendOnReject) {
			origSocket.write(origSocket.sendOnReject);
		}
		throw e;
	}
}
exports.transparent_server = transparent_server;
exports.transparent_connect = transparent_connect;
