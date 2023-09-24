const socks_server = require('./socks_server.js');
const transparent_server = require('./transparent_server.js');
const dns_he = require('./dns_he.js');
const endpoint = require('./endpoint.js');
const protocols = require('./protocols.js');
const server_generic = require('./server_generic.js');
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
		let ep = ("forced_endpoint" in options) ? options.forced_endpoint : endpoint.fromCRAreq(cra.req);
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
function make_domain_handler() {
	/* don't use hasOwnProperty on options, we might inherit from a prototype. */
	return async function (ep, options) {
		let bypass = ep.options_map_.get('!reinject_func');
		if (typeof bypass === 'function') {
			return {[dns_he.internal_function]: bypass};
		}
		if (options.special_domain) {
			let sd_domain = ep.getSubdomainsOf(options.special_domain.getDomain(), 1);
			if (sd_domain) {
				let new_ep2 = options.app.special_domain_resolve(sd_domain[0] || 'www', ep);
				if (!new_ep2) return [];
				ep = new_ep2;
			}
		}
		let dns_result = [ep.clone()];
		if (options.dns) {
			dns_result = await ep.resolveDynamic(options.dns, {ipOnly: true});
		}
		let dns_result_filtered = options.dns_filter ? options.dns_filter(dns_result) : dns_result;
		if (options.dns_sort) {
			dns_result_filtered = dns_he.dns_sort(dns_result_filtered, options.dns_sort);
		}
		return Array.prototype.map.call(dns_result_filtered, (e) => e.toCRAreq());
	};
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
exports.make_server_simple = make_server_simple;
exports.make_domain_handler = make_domain_handler;
exports.read_sni = read_sni;
exports.read_pp2 = read_pp2;
exports.resolve_endpoint = resolve_endpoint;
// TODO WildcardMap like getHostNRThen, getSubdomainsOfThen
