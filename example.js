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
const domain_to_ip_static_map = new Map();
const ip_to_domain_static_map = new Map();
const domain_ip_special = require('./example-static-map.json');
for (let e of domain_ip_special.relay_map) {
	domain_to_ip_static_map.set(e[0], [false, e[1]]);
	ip_to_domain_static_map.set(e[1], e[0]);
}
for (let e of domain_ip_special.dns_map) {
	domain_to_ip_static_map.set(e[0], [true, e[1]]);
}
/* Set IP addresses of custom DNS servers. Universal Relay's fake_dns does not have a DNS cache, so it should be one that already has a cache, preferably a local server. */
my_dns_resolver.setServers(['8.8.8.8']);

/* Fake DNS server (PowerDNS backend)
 * Prefix argument corresponds to fedb:1200:4500:7800::/64
 */
const ipv6_prefix = 0xfedb120045007800n;
var ip_domain_map = fake_dns.make_urelay_ip_domain_map(ipv6_prefix, (domain_unused, endpoint_object) => {
	let override_ip = domain_to_ip_static_map.get(endpoint_object.getDomainString());
	if (override_ip) {
		if (override_ip[0]) return override_ip[1];
		endpoint_object.setIPBigInt((ipv6_prefix << 64n) | (0x200000000n) | (BigInt(override_ip[1]) & 0xffffffffn));
		return undefined;
	}
	endpoint_object.getSubdomainsOfThen(['arpa', 'home', 'u-relay'], 1, (res, t) => {
		if (res[0]) t.setDomain(['arpa', 'home', 'u-relay', res[0]]);
	});
	return domain_parser.urelay_dns_override(endpoint_object.getDomain());
});
var pdns_backend_app = express();
ip_domain_map.make_pdns_express_app(pdns_backend_app);

// ctrtool ns_open_file [...] -n -d inet -t stream -4 127.0.0.10,81,a [-N /path/to/private-side/network-namespace] [-U] [...] node example.js
// Can't do listen(3000) or similar due to the network namespace and IP_TRANSPARENT requirement!
pdns_backend_app.listen({fd: +process.env.CTRTOOL_NS_OPEN_FILE_FD_10});

async function common_ip_rewrite(my_cra, my_socket, is_transparent) {
	/* Recover the domain if the transparent server was used */
	let rewrite_CRA_req_retval = ip_domain_map.rewrite_CRA_req(my_cra.req);
	let my_endpoint = null;
	switch (rewrite_CRA_req_retval) {
		case -4n:
			/* Only allow the domain to be used if the transparent server (instead of the SOCKS server) is used */
			if (!is_transparent) throw new Error();
			my_endpoint = endpoint.fromCRAreq(my_cra.req);
			break;
		case -1n: /* not within the ipv6_prefix */
			my_endpoint = endpoint.fromCRAreq(my_cra.req);
			break;
		default:
			if (rewrite_CRA_req_retval >= 0n) {
				let major = (rewrite_CRA_req_retval >> 32n) & 0x7ffffffn;
				let minor = rewrite_CRA_req_retval & 0xffffffffn;
				switch (major) {
					case 0x5ff6464n:
						my_endpoint = (new endpoint.Endpoint()).setIPBigInt(0xffff00000000n | minor).setPort(my_cra.req.port);
						break;
					case 2n:
						let lookup_result = ip_to_domain_static_map.get(Number(minor));
						if (lookup_result) {
							my_endpoint = (new endpoint.Endpoint()).setDomain(lookup_result).setPort(my_cra.req.port);
						}
						break;
				}
			}
			break;
	}
	if (!my_endpoint) throw new Error();
	/* Resolve the domain name in the my_endpoint object, if it is a "domain" type */
	let resolvedIPEndpoints = await my_endpoint.resolveDynamic(async (domain_parts, domain_name, ep) => {
		return await dns_he.resolve_dns_dualstack(domain_name, my_dns_resolver, '6_weak', domain_parser.urelay_handle_special_domain);
	});
	let resultIPs = [];
	for (let r of resolvedIPEndpoints) {
		/* NAT64 CLAT with well-known prefix 64:ff9b::/96 */
		// r.getHostNRThen(0xffff00000000n, 96, (res, t) => t.setIPBigInt(res | (0x64ff9bn << 96n)));
		resultIPs.push(r.toCRAreq());
	}
	my_cra.req = resultIPs;
	return null;
}
var my_transparent_server = server_generic.make_server(transparent_server.transparent_server, (e, s) => common_ip_rewrite(e, s, true), dns_he.simple_connect_HE);
var my_socks_server = server_generic.make_server(socks_server.socks_server, (e, s) => common_ip_rewrite(e, s, false), dns_he.simple_connect_HE);
var transparent_server_obj = net.createServer({allowHalfOpen: true, pauseOnConnect: true}, my_transparent_server);
var socks_server_obj = net.createServer({allowHalfOpen: true, pauseOnConnect: true}, my_socks_server);
transparent_server_obj.listen({fd: +process.env.CTRTOOL_NS_OPEN_FILE_FD_11});
socks_server_obj.listen({fd: +process.env.CTRTOOL_NS_OPEN_FILE_FD_12});
