async function transparent_server(conn) {
	return {host: conn.localAddress, port: conn.localPort, excessBuf: null};
}
exports.transparent_server = transparent_server;
