'use strict';
class DomainName {
	constructor(labels) {
		let totlen = 0;
		let l = Object.freeze(labels.slice());
		for (let v in l) {
			if ((v.length === 0) || (v.length > 63)) {
				throw new Error('label length === 0 or > 63');
			}
			totlen += v.length + 1;
			if (totlen > 253) {
				throw new Error('domain name length > 253');
			}
		}
		this.d = l;
		Object.freeze(this);
	}
	get_compression_keys() {
		let _result = {d: this.d.map(b => b.toString('hex')).slice()};
		_result.next = function() {
			if (!_result.d) return {done: true};
			let rv = {done: false, value: _result.d.join(' ')};
			if (_result.d.length === 0) {
				_result.d = null;
			} else {
				_result.d.shift();
			}
			return rv;
		}
		return _result;
	}
	get_iterable_compression_keys() {
		return {[Symbol.iterator]: () => this.get_compression_keys()};
	}
	to_text() {
		let result = [];
		for (let l of this.d) {
			let s = '';
			for (let c of l) {
				if ((c <= 32) || (c >= 127)) {
					s += '\\' + ((512 + c).toString(8).substring(1,4));
				} else if (c === 0x2e) {
					s += '\\.';
				} else if (c === 0x5c) {
					s += '\\\\';
				} else {
					s += String.fromCharCode(c);
				}
			}
			result.push(s);
		}
		return result.join('.');
	}
}
exports.domain_from_text = function(text) {
	let state = 0;
	let cbuf = '';
	let result = [];
	let lresult = [];
	if (text === '.') return new DomainName([]);
	for (let c of String(text)) {
		if (state === 2) {
			if ('01234567'.indexOf(c) >= 0) {
				cbuf += c;
				if (cbuf.length >= 3) {
					lresult.push(parseInt(cbuf, 8));
					cbuf = '';
					state = 0;
					continue;
				}
			} else {
				lresult.push(parseInt(cbuf, 8));
				cbuf = '';
				state = 0;
			}
		}
		if (state === 1) {
			if ('01234567'.indexOf(c) >= 0) {
				cbuf = c;
				state = 2;
			} else {
				lresult.push(c.charCodeAt(0));
				state = 0;
				continue;
			}
		}
		if (state === 0) {
			if (c === '.') {
				if (lresult.length === 0) {
					throw new Error('empty label');
				}
				result.push(Buffer.from(lresult));
				lresult = [];
			}
			else if (c === '\\') {
				state = 1;
			}
			else {
				lresult.push(c.charCodeAt(0));
			}
		}
	}
	if (state === 2) {
		lresult.push(parseInt(cbuf, 8));
	}
	if (lresult.length > 0) {
		result.push(Buffer.from(lresult));
	}
	return new DomainName(result);
}
exports.from_text = exports.domain_from_text;
exports.DomainName = DomainName;
