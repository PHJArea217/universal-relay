'use strict';
const ip = require('ip');
function makeSimpleIPRewrite(filters) {
	return async function(attr, socket) {
		let ipBuf = null;
		let ipType = 0;
		switch (attr.req.type) {
			case 'ipv4':
				ipBuf = ip.toBuffer(attr.req.host);
				if (ipBuf.length !== 4) throw new Error();
				ipType = 4;
				break;
			case 'ipv6':
				ipBuf = ip.toBuffer(attr.req.host);
				if (ipBuf.length !== 16) throw new Error();
				ipType = 6;
				break;
			default:
				throw new Error("attr.req.type is not ipv4 or ipv6");
				break;
		}
		if (ipType === 6) {
			let n = 0;
			for (let i = 0; i < 10; i++) {
				if (ipBuf[i] === 0) n++;
			}
			if ((n === 10) && (ipBuf[10] === 255) && (ipBuf[11] === 255)) {
				/* It's a v4-mapped-v6 address */
				ipBuf = new Buffer([ipBuf[12], ipBuf[13], ipBuf[14], ipBuf[15]]);
				ipType = 4;
			}
		}
		let ipString = ip.toString(ipBuf);
		let currentData = {
			host: ipString,
			hostBuf: ipBuf,
			port: attr.req.port,
			connectFunc: null,
			attrReqOverride: null,
			originalCRA: attr
		};
		for (let f of filters) {
			if ((ipType === 4) && (f.ipv4 || f.all)) {
			} else if ((ipType === 6) && (f.ipv6 || f.all)) {
			} else {
				continue;
			}
			if (f.cidrPrefix.contains(currentData.host)) { /* cidrPrefix can simply be {contains: (x) => true} */
				await f.filter(currentData, socket);
				if ((currentData.host === null) || (currentData.hostBuf !== null)) { /* Both host and hostBuf are present, or host is missing. */
					if (currentData.hostBuf === null) {
						throw new Error(`Connection to ${attr.req} blocked by filter`);
					}
					currentData.host = ip.toString(currentData.hostBuf);
				} else { /* Only in the case where the hostBuf is missing. */
					currentData.hostBuf = ip.toBuffer(currentData.host);
				}
				if (currentData.hostBuf.length === 16) {
					ipType = 6;
				} else if (currentData.hostBuf.length === 4) {
					ipType = 4;
				} else {
					throw new Error("currentData.hostBuf must be IPv4 (4 bytes) or IPv6 (16 bytes)");
				}
			}
			if (currentData.attrReqOverride) {
				attr.req = currentData.attrReqOverride;
				return currentData.connectFunc;
			}
		}
		let ipResult = ip.toString(currentData.hostBuf);
		let attrReqResult = {host: ipResult, port: currentData.port};
		if (ipResult.indexOf(':') >= 0) {
			attrReqResult.type = 'ipv6';
		} else {
			attrReqResult.type = 'ipv4';
		}
		attr.req = attrReqResult;
		return currentData.connectFunc;
	};
}
async function blockPrefix(data, socket) {
	throw new Error(String(data) + " is blocked");
}
function makeNAT64(prefix, isCLAT) {
	if (isCLAT) {
		let prefixBuffer = ip.toBuffer(prefix);
		if (prefixBuffer.length !== 16) throw new Error("NAT64 prefix must be IPv6 address");
		return async function (data, socket) {
			let newAddress = Buffer.from(prefixBuffer);
			if (data.hostBuf.length !== 4) {
				throw new Error("NAT64 CLAT function called on non-IPv4 destination");
			}
			data.hostBuf.copy(newAddress, 12, 0, 4);
			data.hostBuf = newAddress;
			data.host = null;
		};
	} else {
		return async function(data, socket) {
			if (data.hostBuf.length !== 16) {
				throw new Error("NAT64 PLAT function called on non-IPv6 destination");
			}
			data.hostBuf = data.hostBuf.slice(12);
			data.host = null;
		};
	}
}
exports.makeSimpleIPRewrite = makeSimpleIPRewrite;
exports.makeBlock = function() {
	return blockPrefix;
};
exports.makeNAT64 = makeNAT64;
