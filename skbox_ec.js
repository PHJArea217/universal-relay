const fs = require('fs');
exports.make_skbox_ec_server = function(socketPath, ncsObj) {
	try {
		if (fs.lstatSync(socketPath).isSocket()) fs.unlinkSync(socketPath);
	} catch (e) {
	}
	ncsObj.listen({path: socketPath}, () => fs.chmodSync(socketPath,438 /*0666*/));
}

