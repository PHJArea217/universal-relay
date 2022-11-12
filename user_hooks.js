const endpoint = require('./endpoint.js');
function domain_canonicalizer(config, ep) {
	return null;
}
function dns_map(config, ep, ipv6_prefix) {
	return null;
}
function pre_lookup(config, state, ep, socket, ipv6_prefix, is_transparent) {
}
function handle_static_region(config, state, majorminor, ep) {
	return null;
}
function hosts_map(config, state, res, ep) {
	return null;
}
function resolve_map(config, state, domain_name, ep) {
	return null;
}
function transform_all_resolved_endpoints(config, state, endpoints, orig_ep) {
	return null;
}
function transform_resolved_endpoint(config, state, ep, orig_ep) {
}
exports.domain_canonicalizer = domain_canonicalizer;
exports.dns_map = dns_map;
exports.pre_lookup = pre_lookup;
exports.handle_static_region = handle_static_region;
exports.hosts_map = hosts_map;
exports.resolve_map = resolve_map;
exports.transform_all_resolved_endpoints = transform_all_resolved_endpoints;
exports.transform_resolved_endpoint = transform_resolved_endpoint;
