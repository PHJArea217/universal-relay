const si_symbol = Symbol('u-relay-sockinfo');
function get_sock_info(sock, create_if_not_exist) {
	if (sock._parent) sock = sock._parent;
	if (!(si_symbol in sock)) {
		if (create_if_not_exist) sock[si_symbol] = {};
	}
	return sock[si_symbol];
}
