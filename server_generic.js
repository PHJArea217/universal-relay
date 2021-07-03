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
		try {
			let connReadAttributes = await connReadPromise(socket);
			let newDestination = ipRewrite(connReadAttributes);
			let connOut = await connPromise(socket, newDestination);
			socket.pipe(connOut);
			connOut.pipe(socket);
		} catch (e) {
			socket.end();
		}
	};
}
exports.make_server = make_server;
