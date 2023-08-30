'use strict';
const promises_lib = require('./common_promises.js');
const ip = require('ip');
async function socks_server(conn) {
	let state = 'i';
	let charCounter = 0;
	let charList = null;
	let info = {req: {}};
	let hostString = "";
	let hostStringLen = 0;
	let sendError4 = function() {
		conn.write(Buffer.from([0, 0x5b, 0, 0, 0, 0, 0, 0]));
		conn.destroy();
	};
	let sendError5auth = function() {
		conn.write(Buffer.from([5, 255]));
		conn.destroy();
	};
	let sendError5fail = function() {
		conn.write(Buffer.from([5, 1, 0, 1, 0, 0, 0, 0, 0, 0]));
		conn.destroy();
	};
	let sendSuccess5auth = function() {
		conn.write(Buffer.from([5, 0]));
	};
	let phase = 0;
	while (true) {
		let nextBuf = await promises_lib.readFromSocket(conn);
		let charsReadE = 0;
		for (let c of nextBuf) {
			if (phase === 1) {
				break;
			}
			charsReadE++;
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
						conn.destroy();
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
					info.req.host = +charList[2] + "." + +charList[3] + "." + +charList[4] + "." + +charList[5];
					info.req.port = (+charList[0] << 8) + +charList[1];
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
						info.req.host = hostString;
						info.__socks_version = 4;
						info.req.type = 'domain';
						/* Colon character allowed due to IPv6 literals, but there
						 * could be circumstances where it could be confused with
						 * a port number. Maybe it's up to the filter to do that;
						 * the included ipRewrite filter (simpleIPRewrite) already
						 * blocks "domain" requests. */
					} else if ((c === 0x2d) || (c === 0x2e) || (c === 0x5f) || ((c >= 0x41) && (c <= 0x5a)) || ((c >= 0x61) && (c <= 0x7a)) || ((c >= 0x30) && (c <= 0x3a))) {
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
						info.__socks_version = 4;
						info.req.type = 'ipv4';
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
					for (let i of charList) {
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
					info.req.host = ip.toString(Buffer.from(charList));
					info.req.type = charList.length > 4 ? 'ipv6' : 'ipv4';
					state = '5rp';
					charList = [];
					charCounter = 2;
					break;
				case '5rdr':
					let domainString = "";
					for (let bc of charList) {
						if ((bc === 0x2d) || (bc === 0x2e) || (bc === 0x5f) || ((bc >= 0x41) && (bc <= 0x5a)) || ((bc >= 0x61) && (bc <= 0x7a)) || ((bc >= 0x30) && (bc <= 0x3a))) {
							domainString += String.fromCharCode(bc);
						} else {
							sendError5fail();
							throw new Error();
						}
					}
					info.req.type = 'domain';
					info.req.host = domainString;
					state = '5rp';
					charList = [];
					charCounter = 2;
					break;
				case '5rp':
					state = '5c';
					phase = 1;
					info.req.port = (charList[0] << 8) + charList[1];
					info.__socks_version = 5;
					break;
				default:
					conn.destroy();
					throw new Error();
					break;
			}
		}
		if (phase === 1) {
			conn.unshift(nextBuf.slice(charsReadE));
			if (state === '4uc') {
				info.sendOnAccept = Buffer.from([0, 0x5a, 0, 0, 0, 0, 0, 0]);
				info.sendOnReject = Buffer.from([0, 0x5b, 0, 0, 0, 0, 0, 0]);
			} else {
				info.sendOnAccept = Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
				info.sendOnReject = Buffer.from([5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
			}
			// info.req = {host: info.host, port: info.port, type: info.type};
			return info;
		}
	}
}
/* TODO: multiple destination options */
function make_socks_client(options) {
	return async function(origSocket, dest) {
		let socksClient = await promises_lib.socketConnect(options, origSocket);
		socksClient.write(Buffer.from([5, 1, 0]));
		let state = 'i';
		let charsLeft = 2;
		let aBuf = [];
		let phase = 0;
		while (true) {
			let nextBuf = await promises_lib.readFromSocket(socksClient);
			if ((!nextBuf) || (nextBuf.length === 0)) {
				/*
				if (dest.sendOnReject) {
					origSocket.write(dest.sendOnReject);
				}*/
				origSocket.destroy();
				socksClient.destroy();
				throw new Error();
			}
			let i = -1;
			for (let c of nextBuf) {
				i++;
				if (charsLeft > 0) {
					aBuf.push(c);
					charsLeft--;
				}
				if (charsLeft > 0) continue;
				switch (state) {
					case 'i':
						if ((aBuf[0] === 5) && (aBuf[1] === 0)) {
							state = 'x';
							aBuf = [];
							charsLeft = 5;
							socksClient.write(Buffer.from([5, 1, 0]));
							switch (dest.req.type) {
								case 'ipv4':
								case 'ipv6':
									let ipBuffer = ip.toBuffer(dest.req.host);
									switch (ipBuffer.length) {
										case 4:
											socksClient.write(Buffer.from([1]));
											break;
										case 16:
											socksClient.write(Buffer.from([4]));
											break;
										default:
											throw new Error();
											break;
									}
									socksClient.write(ipBuffer);
									break;
								case 'domain':
									let sl = dest.req.host.length;
									if (sl > 255) throw new Error();
									socksClient.write(Buffer.from([3, sl]));
									socksClient.write(dest.req.host);
									break;
								default:
									throw new Error();
									break;
							}
							socksClient.write(Buffer.from([dest.req.port >> 8, dest.req.port & 0xff]));
						} else {
							throw new Error();
						}
						break;
					case 'x':
						// console.log(aBuf);
						if ((aBuf[0] === 5) && (aBuf[1] === 0) && (aBuf[2] === 0)) {
							state = 'done';
							switch (aBuf[3]) {
								case 1:
									aBuf = [];
									charsLeft = 5;
									break;
								case 3:
									charsLeft = aBuf[4] + 2;
									aBuf = [];
									break;
								case 4:
									aBuf = [];
									charsLeft = 17;
									break;
								default:
									throw new Error();
							}
						} else {
							throw new Error();
						}
						break;
					case 'done':
						state = 'v';
						phase = 1;
						break;
					case 'v':
						if (phase === 1) {
							phase = 2;
							dest.sendOnAccept2 = nextBuf.slice(i);
						}
						break;
				}
				if (phase === 2) break;
			}
			if (phase >= 1) {
				return socksClient;
			}
		}
	};
}
exports.socks_server = socks_server;
exports.make_socks_client = make_socks_client;
