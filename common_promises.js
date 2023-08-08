'use strict';
const net = require('net');
function readFromSocket(socket) {
	return new Promise((resolve, reject) => {
		let state = {done: false};
		if (!socket.readable) {
			resolve(null);
			return;
		}
		let b = socket.read();
		if (b) {
			resolve(b);
			return;
		}
		if (!socket.readable) {
			resolve(null);
			return;
		}
		socket.once('readable', () => {
			if (state.done) return;
			state.done = true;
			resolve(socket.read() || Buffer.from([]));
		});
		socket.once('error', () => {
			if (state.done) return;
			state.done = true;
			resolve(null);
		});
		socket.once('close', () => {
			if (state.done) return;
			state.done = true;
			resolve(null);
		});
		socket.once('end', () => {
			if (state.done) return;
			state.done = true;
			resolve(null);
		});
		setTimeout(() => {
			if (state.done) return;
			state.done = true;
			resolve(null);
		}, 10000);
	});
}

/*
function readFromSocket(socket) {
	return new Promise((resolve, reject) => {
		let done = false;
		let handlers = {
			data: function(buf) {
				if (done) return;
				done = true;
				socket.pause();
				socket.removeListener('data', handlers.data);
				socket.removeListener('close', handlers.error);
				socket.removeListener('end', handlers.end);
				resolve(buf);
			},
			error: function() {
				if (done) return;
				done = true;
				socket.removeListener('data', handlers.data);
				socket.removeListener('close', handlers.error);
				socket.removeListener('end', handlers.end);
				socket.destroy();
				reject();
			},
			end: function() {
				if (done) return;
				done = true;
				socket.removeListener('data', handlers.data);
				socket.removeListener('close', handlers.error);
				socket.removeListener('end', handlers.end);
				resolve(null);
			}
		};
		if (socket.destroyed) {reject(); return;}
		socket.on('data', handlers.data);
		socket.on('close', handlers.error);
		socket.on('end', handlers.end);
		setTimeout(handlers.error, 10000);
		socket.resume();
	});
}
*/
function socketConnect(options, destroyOnClose) {
	return new Promise((resolve, reject) => {
		let conn = net.createConnection(options);
		if (Object.hasOwn(options, "port") || Object.hasOwn(options, "path")) {
			options._conn = conn;
		}
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
exports.readFromSocket = readFromSocket;
exports.socketConnect = socketConnect;
