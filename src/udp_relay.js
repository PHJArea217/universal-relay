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
	a.on('message', a_data);
	b.on('message', b_data);
	a.on('error', errorFunc);
	b.on('error', errorFunc);
	return {a: a, b: b, errorFunc: errorFunc, a_data: a_data, b_data: b_data};
}
function clockTimeToNTP(clockTime_ns) {
	return ((2208988800000000000n + clockTime_ns) << 32n) / 1000000000n;
}
/* XXX: no leap seconds right now */
let ntp_obuf = Buffer.from([0x24, 1, 6, 0xec /* 2^-20 s */, 0, 0, 0, 0, 0, 0, 0, 1, 0x58, 0x55, 0x2d, 0x52]);
function ntp_server(ibuf) {
	if (ibuf.length < 48) return;
	let obuf2 = Buffer.allocUnsafe(32);
	let curTime = clockTimeToNTP(BigInt(Date.now() * 1000) * 1000n);
	obuf2.writeBigUInt64BE(curTime - 1n, 0);
	obuf2.writeBigUInt64BE(ibuf.readBigUInt64BE(40), 8);
	obuf2.writeBigUInt64BE(curTime, 16);
	obuf2.writeBigUInt64BE(curTime, 24);
	return Buffer.concat([ntp_obuf, obuf2]);
}
function make_ntp_server_message_bindable(data, rinfo) {
	try {
		let o = ntp_server(data);
		if (o) this.send(o, 0, 48, rinfo.port, rinfo.address);
	} catch (e) {
	}
}

exports.udp_relay = udp_relay;
exports.ntp_server = ntp_server;
exports.make_ntp_server_message_bindable = make_ntp_server_message_bindable;
