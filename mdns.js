const common_promises = require('./common_promises.js');
/* The implementations here were reverse engineered by strace-ing :) */
async function mdns_resolve(hostname, simplePath, allow_linklocal_scope, orig_endpoint) {
	let simpleConn = await common_promises.socketConnect(simplePath || '/run/avahi-daemon/socket', null);
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
async function systemd_resolve(hostname, simplePath, allow_linklocal_scope, orig_endpoint) {
	let simpleConn = await common_promises.socketConnect(simplePath || '/run/systemd/resolve/io.systemd.Resolve', null);
	let requestJSON = {method: "io.systemd.Resolve.ResolveHostname",parameters: {name: hostname, flags: 0}};
	simpleConn.write(JSON.stringify(requestJSON));
	simpleConn.write(new Buffer([0]));
	let response = [];
	let continueLoop = true;
	while (continueLoop) {
		let response_buffer = await common_promises.readFromSocket(simpleConn);
		if (!response_buffer) break;
		for (let c of response_buffer) {
			if (c === 0) {
				continueLoop = false;
				break;
			}
			response.push(c);
		}
	}
	simpleConn.destroy();
	let result_buffer = Buffer.from(response).toString();
	let match_result = JSON.parse(result_buffer);
	// console.log(result_buffer);
	if (match_result && match_result.parameters && Array.isArray(match_result.parameters.addresses)) {
		let result = [];
		for (let a of match_result.parameters.addresses) {
			if ((a.family === 2) || (a.family === 10)) {
				let ip_address = orig_endpoint.clone().setIPBuffer(Buffer.from(a.address));
				result.push(ip_address);
			}
		}
		return result;
	}
	throw new Error(`systemd_resolve: failed to resolve ${hostname}`);
}
exports.mdns_resolve = mdns_resolve;
exports.systemd_resolve = systemd_resolve;
