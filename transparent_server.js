async function transparent_server(conn) {
	let host = String(conn.localAddress);
	let type = 'ipv4';
	if (host.indexOf(':') >= 0) {
		type = 'ipv6';
	}
	return {host: host, port: Number(conn.localPort), excessBuf: null, type: type};
}
exports.transparent_server = transparent_server;
