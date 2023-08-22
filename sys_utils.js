const socks_server = require('./socks_server.js');
const transparent_server = require('./transparent_server.js');
const dns_he = require('./dns_he.js');
const endpoint = require('./endpoint.js');
const protocols = require('./protocols.js');
const net = require('net');
const fs = require('fs');
function make_server_simple(f, options_, listen_parameters, extra_args) {
	let options = options_ || {};
	let unix_path = null;
	if (options.unix_path) {
		unix_path = options.unix_path;
		try {
			if (fs.lstatSync(unix_path).isSocket()) fs.unlinkSync(unix_path);
		} catch (e) {
		}
	}
	let server = server_generic.make_server(options.socks ? socks_server.socks_server : transparent_server.transparent_server, async (cra, s) => {
		let ep = Object.prototype.hasOwnProperty.call(options, "forced_endpoint") ? options.forced_endpoint : endpoint.fromCRAreq(cra.req);
		cra.req = await f(ep, cra, s, ...extra_args);
		return null;
	}, dns_he.simple_connect_HE);
	let server_obj = net.createServer({allowHalfOpen: true, pauseOnConnect: true}, server);
	if (unix_path) {
		server_obj.listen({path: unix_path}, () => fs.chmodSync(unix_path, 438));
	} else if (listen_parameters) {
		server_obj.listen(listen_parameters);
	}
	return server_obj;
}
async function read_sni(s) {
	let sni_header = await protocols.get_sni_header(s);
	if (!sni_header) return null;
	if (!Buffer.isBuffer(sni_header.buffer)) return {};
	let sni_header_data = protocols.parse_sni_header(sni_header.buffer);
	if (!sni_header_data) return {};
	return sni_header_data;
}
async function read_pp2(s) {
	let pp2_header = await protocols.get_pp2_header(s);
	if (!pp2_header) return null;
	if (!Buffer.isBuffer(pp2_header.buffer)) return {};
	let pp2_header_data = protocols.parse_pp2_header(pp2_header.buffer);
	if (!pp2_header_data) return {};
	return pp2_header_data;
}
async function resolve_endpoint(ep, dns_server) {
	if (!dns_server) return [ep.clone()];
	return await ep.resolveDynamic(dns_server, {ipOnly: true});
}
// TODO WildcardMap like getHostNRThen, getSubdomainsOfThen
