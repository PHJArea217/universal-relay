const si_symbol = Symbol('u-relay-sockinfo');
function get_sock_info(sock, create_if_not_exist) {
	if (sock._parent) sock = sock._parent;
	if (!(si_symbol in sock)) {
		if (create_if_not_exist) sock[si_symbol] = {};
	}
	return sock[si_symbol];
}
// Properties:
// vi: set to the destination IP (bigint) in the PP2 header if "prefixed" with Proxy Protocol v2. This is subsequently used to determine the top 64 bits of AAAA records to return if the DNS server is selected.
// tag (like !intfunc_tag. Needed, so that it is preserved after reinjection.)
module.exports = {si_symbol: si_symbol, get_sock_info: get_sock_info};
