const dgram = require('dgram');
function udp_relay(options) {
	let a = dgram.createSocket(options.a_type || 'udp6');
	let b = dgram.createSocket(options.b_type || 'udp6');
	a.bind(options.a_bind);
	b.bind(options.b_bind);
	a.connect(options.a_connect);
	b.connect(options.b_connect);
	function relay_data(other, data) {
		try { other.send(data); } catch (e) {}
	}
	let errorFunc = () => 0;
	let a_data = relay_data.bind(a, b);
	let b_data = relay_data.bind(b, a);
	a.on('data', a_data);
	b.on('data', b_data);
	a.on('error', errorFunc);
	b.on('error', errorFunc);
	return {a: a, b: b, errorFunc: errorFunc, a_data: a_data, b_data: b_data};
}
exports.udp_relay = udp_relay;
