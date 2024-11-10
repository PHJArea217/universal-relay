'use strict';
const net = require('net');
exports.readFromSocket = async function (s) {
	for await (const b of s.iterator({destroyOnReturn: false})) {
		return b;
	}
	return null;
}
function socketConnect(options, destroyOnClose) {
	return new Promise((resolve, reject) => {
		let conn = net.createConnection(options);
		let done = false;
		conn.once('connect', () => {
			if (done) return;
			done = true;
			conn.pause();
			resolve(conn);
		});
		conn.once('error', () => {
			if (done) return;
			done = true;
			conn.destroy();
			reject();
		});
		setTimeout(() => {
			if (done) return;
			done = true;
			conn.destroy();
			reject();
		}, 10000);
		if (destroyOnClose) {
			destroyOnClose.on('close', () => {
				if (done) return;
				done = true;
				conn.destroy();
				reject();
			});
		}
	});
}
exports.socketConnect = socketConnect;
