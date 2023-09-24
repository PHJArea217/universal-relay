try {
	var napi_helpers = require('./build/Release/napi_helpers.node');
	exports.make_socket = napi_helpers.make_socket;
} catch (e) {
	console.error('napi-helpers not available, need to use node-gyp to compile');
}
