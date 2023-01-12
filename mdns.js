const common_promises = require('./common_promises.js');
async function mdns_resolve(hostname, simplePath, allow_linklocal_scope, orig_endpoint) {
	let simpleConn = await common_promises.socketConnect(simplePath, null);
	simpleConn.write(`RESOLVE-HOSTNAME ${hostname}\n`);
	let response = [];
	while (true) {
		let response_buffer = await common_promises.readFromSocket(simpleConn);
		if (!response_buffer) break;
		response.push(response_buffer);
	}
	let result_buffer = Buffer.concat(response).toString();
	let match_result = result_buffer.match(/^\+ ([0-9]+) ([0-9]+) ([^ ]+) ([^ ]+)\n/);
	if (match_result) {
		let ifindex = BigInt(match_result[1]);
		let ip_address = orig_endpoint.clone().setIPString(match_result[4]);
		let linklocal_host = ip_address.getHostNR(0xfe80n<<112n, 64);
		if ((ifindex > 0n) && (ifindex <= 0xffffffffn) && (linklocal_host >= 0n)) {
			ip_address.setIPBigInt((0xfe90n << 112n) | (ifindex << 64n) | linklocal_host);
		}
		return ip_address;
	}
	throw new Error(`mdns_resolve: failed to resolve ${hostname}`);
}
exports.mdns_resolve = mdns_resolve;
