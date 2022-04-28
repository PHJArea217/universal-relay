const net = require('net');
const endpoint = require('./endpoint.js');
const server_generic = require('./server_generic.js');
const socks_server = require('./socks_server.js');
const dns_he = require('./dns_he.js');
const domain_parser = require('./domain_parser.js');
const transparent_server = require('./transparent_server.js');
const fake_dns = require('./fake_dns.js');
const express = require('express');
const dns = require('dns');
const my_dns_resolver = new dns.Resolver();
/* Set IP addresses of custom DNS servers. Universal Relay's fake_dns does not have a DNS cache, so it should be one that already has a cache, preferably a local server. */
my_dns_resolver.setServers(['8.8.8.8']);

/* Fake DNS server (PowerDNS backend)
 * Prefix argument corresponds to fedb:1200:4500:7800::/64
 */
var ip_domain_map = fake_dns.make_urelay_ip_domain_map(0xfedb120045007800n, (domain_unused, endpoint_object) => {
});
var pdns_backend_app = express();
ip_domain_map.make_pdns_express_app(pdns_backend_app);

// ctrtool ns_open_file [...] -n -d inet -t stream -4 127.0.0.10,81,a [-N /path/to/private-side/network-namespace] [-U] [...] node example.js
// Can't do listen(3000) or similar due to the network namespace and IP_TRANSPARENT requirement!
pdns_backend_app.listen({fd: +process.env.CTRTOOL_NS_OPEN_FILE_FD_0});

async function common_ip_rewrite(my_endpoint, my_socket) {
	/* Resolve the domain name in the my_endpoint object, if it is a "domain" type */
	let resolvedIPEndpoints = await my_endpoint.resolveDynamic(async (domain_parts, domain_name, ep) => {
		return await dns_he.resolve_dns_dualstack(domain_name, my_dns_resolver, '6_weak', domain_parser.urelay_handle_special_domain);
	});
	let resultIPs = [];
	for (let r of resolvedIPEndpoints) {
		/* NAT64 CLAT with well-known prefix 64:ff9b::/96 */
		// r.getHostNRThen(0xffff00000000n, 96, (res, t) => t.setIPBigInt(res | (0x64ff9bn << 96n)));
		resultIPs.push(r);
	}
}
var my_transparent_server = server_generic.make_server(transparent_server.transparent_server, (e, s) => {
}, dns_he.simple_connect_HE);
