const internal_webserver = require('./internal-webserver.js');
const app = internal_webserver.make_internal_express_app({
	ipv6_prefix: 0xfedb120045007800n,
	wpad: `function FindProxyForURL(url, host) { return "SOCKS [fedb:1200:4500:7800:5ff:7000::]:1080" }`
});
app.listen(8080, '127.0.0.1');
