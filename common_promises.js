const net = require('net');
function readFromSocket(socket) {
	return new Promise((resolve, reject) => {
		let handlers = {
			data: function(buf) {
				socket.pause();
				socket.removeListener('data', handlers.data);
				socket.removeListener('error', handlers.error);
				socket.removeListener('end', handlers.end);
				resolve(buf);
			},
			error: function() {
				socket.removeListener('data', handlers.data);
				socket.removeListener('error', handlers.error);
				socket.removeListener('end', handlers.end);
				reject();
			},
			end: function() {
				socket.removeListener('data', handlers.data);
				socket.removeListener('error', handlers.error);
				socket.removeListener('end', handlers.end);
				resolve(null);
			}
		};
		socket.on('data', handlers.data);
		socket.on('error', handlers.error);
		socket.on('end', handlers.end);
		socket.unpause();
	});
}
function socketConnect(options) {
	return new Promise((resolve, reject) => {
		let conn = net.createConnection(options);
		conn.once('connect', () => resolve(conn));
		conn.once('error', () => reject());
	});
}
exports.readFromSocket = readFromSocket;
exports.socketConnect = socketConnect;
