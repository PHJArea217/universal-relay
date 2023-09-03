const express = require('express');
const endpoint = require('./endpoint.js');
function make_internal_express_app(features) {
	const app = express();
	if (features.wpad) {
		switch (typeof features.wpad) {
			case 'string':
				app.get('/wpad.dat', (req, res) => {
					res.set('content-type', 'application/x-ns-proxy-autoconfig');
					res.status(200).send(features.wpad);
				});
				break;
			case 'function':
				app.get('/wpad.dat', (req, res) => features.wpad(req, res));
				break;
		}
	}
	app.get('/time', (req, res) => {
		res.set('access-control-allow-origin', '*');
		res.status(200).send({time: Date.now() / 1000, remoteIP: req.ip, remotePort: req.socket.remotePort});
	});
	const intfunc = [];
	if (typeof features.ipv6_prefix === 'bigint') {
		intfunc.push(new endpoint.Endpoint().setIPBigInt((features.ipv6_prefix << 64n) | 0x5ff700000000000n).getIPString());
		intfunc.push(new endpoint.Endpoint().setIPBigInt((features.ipv6_prefix << 64n) | 0x5ff700000000001n).getIPString());
	} else {
		intfunc.push("ipv6_prefix + :5ff:7000:0:0");
		intfunc.push("ipv6_prefix + :5ff:7000:0:1");
	}
	app.get('/', (req, res) => {
		res.status(200).send(`<!DOCTYPE HTML>
<html>
<head>
<title>Universal Relay</title>
</head>
<body>
<p>Universal Relay is an open source transparent proxy server designed for the needs of the modern Internet. More information about Universal Relay can be found <a href="https://website.peterjin.org/wiki/Universal_Relay">here</a>.</p>
<p>This web server provides the following internal functions:</p>
<ul>
<li><a href="/time">/time</a> (time of day service, also shows your IP address)</li>
<li><a href="/wpad.dat">wpad.dat</a> (intended to allow autoconfiguration of the SOCKS proxy)</li>
</ul>
<p>Other internal functions include:</p>
<ul>
<li>${intfunc[0]} port 1080 -- internal SOCKS server</li>
<li>${intfunc[1]} port 443 (other ports can also be used) -- SNI proxy</li>
</ul>
Source can be found on <a href="https://github.com/PHJArea217/universal-relay">GitHub</a>.
</body>
</html>
`);
	});
	return app;
}
exports.make_internal_express_app = make_internal_express_app;
