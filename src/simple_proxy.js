'use strict';
/* Relay connections from local port 3443 to the specified IP addresses (the IP addresses for website.peterjin.org as of July 15, 2023) on port 443 */
const dns_he = require('./dns_he.js');
const endpoint = require('./endpoint.js');
const server_generic = require('./server_generic.js');
const transparent_server = require('./transparent_server.js');
const net = require('net');
let c = server_generic.make_server(transparent_server.transparent_server, (e, s) => {
	e.req = [
		new endpoint.Endpoint().setIPString('2602:806:a000:2a88:0:100:0:1').setPort(443).toCRAreq(),
		new endpoint.Endpoint().setIPString('23.161.208.254').setPort(443).toCRAreq()
	];
	return null;
}, dns_he.simple_connect_HE);
let s = net.createServer({pauseOnConnect: true, allowHalfOpen: true}, c);
s.listen(3443);
