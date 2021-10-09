const ip = require('ip');
function makeSimpleIPRewrite(filters) {
	return async function(attr, socket) {
		let ipBuf = null;
		switch (attr.req.type) {
			case 'ipv4':
				ipBuf = ip.toBuffer(attr.req.host);
				if (ipBuf.length !== 4) throw new Error();
				break;
			case 'ipv6':
				ipBuf = ip.toBuffer(attr.req.host);
				if (ipBuf.length !== 16) throw new Error();
				break;
			default:
				throw new Error("attr.req.type is not ipv4 or ipv6");
				break;
		}
		if (ipBuf.length === 16) {
			let n = 0;
			for (let i = 0; i < 10; i++) {
				if (ipBuf[i] === 0) n++;
			}
			if ((n === 10) && (ipBuf[10] === 255) && (ipBuf[11] === 255)) {
				/* It's a v4-mapped-v6 address */
				ipBuf = new Buffer([ipBuf[12], ipBuf[13], ipBuf[14], ipBuf[15]]);
			}
		}
		let ipString = ip.toString(ipBuf);
		let currentData = {
			host: ipString,
			hostBuf: ipBuf,
			port: attr.req.port,
			connectFunc: null,
			attrReqOverride: null
		};
		for (let f of filters) {
			if (f.cidrSubnet.contains(currentData.host)) { /* cidrSubnet can simply be {contains: (x) => true} */
				await f.filter(currentData, socket);
				if ((currentData.host === null) || (currentData.hostBuf !== null)) { /* Both host and hostBuf are present, or host is missing. */
					if (currentData.hostBuf === null) {
						throw new Error(`Connection to ${attr.req} blocked by filter`);
					}
					currentData.host = ip.toString(currentData.hostBuf);
				} else { /* Only in the case where the hostBuf is missing. */
					currentData.hostBuf = ip.toBuffer(currentData.host);
				}
			}
		}
		if (currentData.attrReqOverride) {
			attr.req = currentData.attrReqOverride;
			return currentData.connectFunc;
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
	}
}
exports.makeSimpleIPRewrite = makeSimpleIPRewrite;
