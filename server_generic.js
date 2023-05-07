'use strict';
/*
 * connReadPromise: attempt to perform I/O on the socket to extract the client's requested destination, should produce the exact numbers.
 *                  Return an opaque object.
 * ipRewrite: transform the socket address into something else (e.g. to implement access control, Socketbox-like subnet routing, and NAT64).
 *            Return an opaque object.
 * connPromise: attempt to connect to the ultimate destination, performing any callbacks or confirmations to the original client as necessary.
 *              Return a socket object, to which data will be relayed to and from the client socket.
 */
function make_server(connReadPromise, ipRewrite, connPromise) {
	return async function(socket) {
		socket.once('error', () => {
			try {
				socket.end();
				socket.destroy();
			} catch (e) {
			}
		});
		let connReadAttributes = null;
		let connOutSuccess = false;
		try {
			socket.pause();
			try {
				socket.setKeepAlive(true);
			} catch (e) {
			}
			connReadAttributes = await connReadPromise(socket);
			console.log(`[${socket.remoteAddress}]:${socket.remotePort} -> [${socket.localAddress}]:${socket.localPort} ` +
				`${connReadAttributes.req.type} ${connReadAttributes.req.host} ${connReadAttributes.req.port}`);
			// console.log(connReadAttributes);
			let connFunc = await ipRewrite(connReadAttributes, socket); /* Change connReadAttributes.req in some way, return null for default action, or throw exception to indicate error/access denied. */
			if (connFunc === null) connFunc = connPromise;
			let connOut = await connFunc(socket, connReadAttributes);
			connOutSuccess = true;
			/*
			if (connReadAttributes.excessBuf) {
				socket.unshift(connReadAttributes.excessBuf);
			}
			*/
			if (connReadAttributes.sendOnAccept) {
				socket.write(connReadAttributes.sendOnAccept);
			}
			if (connReadAttributes.sendOnAccept2) {
				socket.write(connReadAttributes.sendOnAccept2);
			}
			if (connReadAttributes.socketAcceptor) {
				/* Intended use case is to connect the incoming connection to some internal function such as an Express app, rather than an external host. connOut might be null. */
				socket.resume();
				connReadAttributes.socketAcceptor(socket);
				return;
			}
			try {
				connOut.setKeepAlive(true);
			} catch (e) {
			}
			socket.resume();
			connOut.resume();
			socket.on('close', () => {
				socket.destroy();
				connOut.destroy();
			});
			connOut.on('close', () => {
				socket.destroy();
				connOut.destroy();
			});
			socket.on('error', () => {});
			connOut.on('error', () => {});
			socket.pipe(connOut);
			connOut.pipe(socket);
		} catch (e) {
			try {
				if ((!connOutSuccess) && connReadAttributes && connReadAttributes.sendOnReject) {
					socket.write(connReadAttributes.sendOnReject);
				}
			} catch (e2) {
			}
			socket.end();
			socket.destroy();
			// console.log(e);
		}
	};
}
exports.make_server = make_server;
