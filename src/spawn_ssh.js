const crypto = require('crypto');
const fs = require('fs');
const child_process = require('child_process');
var socketsToDelete = [];
function spawn_ssh(command, args, options, tempDir) {
	let randomBuf = crypto.randomBytes(8);
	let a = randomBuf.readUInt32BE(0);
	let b = randomBuf.readUInt32BE(4);
	let tempDir_ = tempDir || '/run/u-relay';
	let socketPath = tempDir_ + `/u-relay-ssh-${a}-${b}`;
	let args_d = ['-D', socketPath];
	args_d.push(...args);
	try {
		fs.mkdirSync(tempDir_, {recursive: true});
	} catch (e) {
	}
	let myProcess = child_process.spawn(command || 'ssh', args_d, options);
	myProcess.on('exit', () => {
		try {
			fs.unlinkSync(socketPath);
		} catch (e) {
		}
	});
	return {server: {"path": socketPath}, c_process: myProcess};
}
process.on('exit', () => {
	for (const s of socketsToDelete) {
		try {
			fs.unlinkSync(s);
		} catch (e) {
		}
	}
});
exports.spawn_ssh = spawn_ssh;
