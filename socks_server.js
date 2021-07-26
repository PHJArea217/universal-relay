const promises_lib = require('./common_promises.js');
const ip = require('ip');
async function socks_server(conn) {
	let state = 'i';
	let charCounter = 0;
	let charList = null;
	let info = {};
	let hostString = "";
	let hostStringLen = 0;
	let sendError4 = function() {
		conn.write(new Buffer([0, 0x5b, 0, 0, 0, 0, 0, 0]));
		conn.end();
	};
	let sendError5auth = function() {
		conn.write(new Buffer([5, 255]));
		conn.end();
	};
	let sendError5fail = function() {
		conn.write(new Buffer([5, 1, 0, 1, 0, 0, 0, 0, 0, 0]));
		conn.end();
	};
	let sendSuccess5auth = function() {
		conn.write(new Buffer([5, 0]));
	};
	let excessBuf = [];
	let phase = 0;
	while (true) {
		let nextBuf = await promises_lib.readFromSocket(conn);
		for (let c of nextBuf) {
			if (phase === 1) {
				excessBuf.push(c);
				continue;
			}
			if (charCounter > 0) {
				charList.push(c);
				charCounter--;
			}
			if (charCounter > 0) continue;
			switch (state) {
				case 'i':
					if (c === 5) {
						state = '5';
					} else if (c === 4) {
						state = '4';
					} else {
						conn.end();
						throw new Error("Invalid version");
					}
					break;
				case '4':
					if (c === 1) {
						state = '4i';
						charCounter = 6;
						charList = [];
					} else {
						sendError4();
						throw new Error();
					}
					break;
				case '4i':
					info.host = +charList[2] + "." + +charList[3] + "." + +charList[4] + "." + +charList[5];
					info.port = (+charList[0] << 8) + +charList[1];
					if ((charList[2] === 0) && (charList[3] === 0) && (charList[4] === 0) && (charList[5] > 0)) {
						state = '4ud';
					} else {
						state = '4ui';
					}
					break;
				case '4ud':
					if (c === 0) {
						state = '4udd';
					}
					break;
				case '4udd':
					if (c === 0) {
						state = '4uc';
						phase = 1;
						info.host = hostString;
						info.version = 4;
					} else if ((c === 0x2d) || (c === 0x2e) || (c === 0x5f) || ((c >= 0x41) && (c <= 0x5a)) || ((c >= 0x61) && (c <= 0x7a)) || ((c >= 0x30) && (c <= 0x39))) {
						hostString += String.fromCharCode(c);
						hostStringLen++;
						if (hostStringLen > 255) {
							sendError4();
							throw new Error();
						}
					}
					break;
				case '4ui':
					if (c === 0) {
						state = '4uc';
						phase = 1;
						info.version = 4;
					}
					break;
				case '5':
					if (c === 0) {
						sendError5auth();
						throw new Error();
					}
					state = '5a';
					charList = [];
					charCounter = c;
					break;
				case '5a':
					let found = false;
					for (let i of c) {
						if (i === 0) {
							found = true;
							break;
						}
					}
					if (found) {
						sendSuccess5auth();
						state = '5r';
						charList = [];
						charCounter = 4;
					} else {
						sendError5auth();
						throw new Error();
					}
					break;
				case '5r':
					if ((charList[0] === 5) && (charList[1] === 1) && (charList[2] === 0)) {
						switch (charList[3]) {
							case 1:
								state = '5r4';
								charList = [];
								charCounter = 4;
								break;
							case 3:
								state = '5rd';
								break;
							case 4:
								state = '5r6';
								charList = [];
								charCounter = 16;
								break;
							default:
								sendError5fail();
								throw new Error();
								break;
						}
					} else {
						sendError5fail();
						throw new Error();
					}
					break;
				case '5rd':
					if (c > 0) {
						state = '5rdr';
						charList = [];
						charCounter = c;
					} else {
						sendError5fail();
						throw new Error();
					}
					break;
				case '5r4':
				case '5r6':
					info.host = ip.toString(new Buffer(charList));
					state = '5rp';
					charList = [];
					charCounter = 2;
					break;
				case '5rdr':
					let domainString = "";
					for (let bc of charList) {
						if ((bc === 0x2d) || (bc === 0x2e) || (bc === 0x5f) || ((bc >= 0x41) && (bc <= 0x5a)) || ((bc >= 0x61) && (bc <= 0x7a)) || ((bc >= 0x30) && (bc <= 0x39))) {
							domainString += String.fromCharCode(bc);
						} else {
							sendError5fail();
							throw new Error();
						}
					}
					info.host = domainString;
					state = '5rp';
					charList = [];
					charCounter = 2;
					break;
				case '5rp':
					state = '5c';
					phase = 1;
					info.port = charList[0] << 8 + charList[1];
					info.version = 5;
					break;
				default:
					conn.end();
					throw new Error();
					break;
			}
		}
		if (phase === 1) {
			info.excessBuf = new Buffer(excessBuf);
			return info;
		}
	}
}
exports.socks_server = socks_server;
