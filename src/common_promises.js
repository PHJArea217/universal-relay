'use strict';
const net = require('net');
exports.readFromSocket = async function (s) {
	for await (const b of s.iterator({destroyOnReturn: false})) {
		return b;
	}
	return null;
}
exports.socketConnect = socketConnect;
