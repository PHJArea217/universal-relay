class Reader {
	constructor(size) {
		this.mode = 0; // 0 = no criteria, 1 = fixed length, 2 = delimiter
		this.bytesLeft = 0;
		this.charToFind = 0;
		this.tmpBuf = Buffer.alloc(size);
		this.tmpBufPos = 0;
	}
	appendBuf(buf) {
		let maxLen = this.tmpBuf.length - this.tmpBufPos;
		if (maxLen > buf.length) maxLen = buf.length;
		if (maxLen <= 0) return 0;
		let a = buf.copy(this.tmpBuf, this.tmpBufPos, 0, maxLen);
		this.tmpBufPos += a;
		return a;
	}
	addBuf(buf) {
		switch (this.mode) {
			case 1:
				if (this.bytesLeft <= buf.length) {
					this.appendBuf(buf.slice(0, this.bytesLeft));
					this.mode = 0;
					let retval = {found: true, buf: this.tmpBuf.slice(0, this.tmpBufPos), excessBuf: buf.slice(this.bytesLeft)}
					this.bytesLeft = 0;
					// this.tmpBuf.fill(0);
					this.tmpBufPos = 0;
					return retval;
				}
				this.appendBuf(buf);
				this.bytesLeft -= buf.length;
				return null;
				break;
			case 2:
				let indexOfDelim = buf.indexOf(this.charToFind);
				if (indexOfDelim >= 0) {
					indexOfDelim++;
					this.appendBuf(buf.slice(0, indexOfDelim));
					let retval = {found: true, buf: this.tmpBuf.slice(0, this.tmpBufPos), excessBuf: buf.slice(indexOfDelim)};
					this.tmpBufPos = 0;
					return retval;
				}
				this.appendBuf(buf);
				break;
		}
		return null;
	}
}
exports.Reader = Reader;
