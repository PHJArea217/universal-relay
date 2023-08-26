'use strict';
const net = require('net');
function wait_for_events_g(events, bailout, timeout) {
	return new Promise((resolve, reject) => {
		if (bailout && bailout()) {
			resolve({obj: null, event: null, args: []});
			return;
		}
		let state = [];
		let state2 = {};
		function common_end(obj, event_name, ...args) {
			if (state.length === 0) return;
			while (state.length) state.pop()();
			if (state2.hasOwnProperty('ct')) {
				clearTimeout(state2.ct);
			}
			resolve({obj: obj, event: event_name, args: args});
		}
		for (let [obj, e] of events) {
			let listen_func = common_end.bind(null, obj, e);
			obj.on(e, listen_func);
			state.push(() => obj.removeListener(e, listen_func));
		}
		if (timeout) {
			state2.ct = setTimeout(common_end.bind(null, null, 'timeout'), timeout);
		}
	});
}
async function wait_for_events(obj, events, abortsignal, timeout) {
	if (abortsignal) {
		if (abortsignal.aborted) return {obj: abortsignal, event: 'abort', args: []};
	}
	let e = Array.prototype.map.call(events, a => [obj, a]);
	if (abortsignal) {
		e.push([abortsignal, 'abort']);
	} else {
		abortsignal = {aborted: false, on: ()=>0, removeListener: ()=>0};
	}
	return await wait_for_events_g(e, () => abortsignal.aborted, timeout);
}
async function readFromSocket(socket) {
	//return new Promise((resolve, reject) => {
	if (true) {
		if (!socket.readable) {
			return null;
		}
		let b = socket.read();
		if (b) {
			return b;
		}
		if (!socket.readable) {
			return null;
		}
		let result = await wait_for_events(socket, ['readable', 'error', 'close', 'end'], null, 10000);
		if (result.event === 'readable') {
			return socket.read() || Buffer.from([]);
		} else {
			return null;
		}
	}
	/*
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
	*/
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
		if (("port" in options) || ("path" in options)) {
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
