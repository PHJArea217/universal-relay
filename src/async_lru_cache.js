const misc_utils = require('./misc_utils.js');
class AsyncLRUCache {
	constructor(maximum) {
		this.map = new Map();
		this.maximum = maximum;
	}
	async compute(k, f) {
		if (!this.map.has(k)) {
			if (this.map.size > this.maximum) {
				let first = this.map[Symbol.iterator].next();
				if (!first.done) {
					first.value[1].future.queue(null);
					first.value[1].state = 2;
					this.map.delete(first.value[0]);
				}
			}
			this.map.set(k, {future: new misc_utils.Channel(), state: 0, expires: 0});
		}
		let this_obj = this.map.get(k);
		if (this_obj.state === 2) {
			if (this_obj.expires > (new Date().getTime())) {
				this_obj = {future: new misc_utils.Channel(), state: 0, expires: 0};
			}
		}
		this.map.delete(k);
		this.map.set(k, this_obj);
		if (!this_obj.future.ch.length) {
			if (this_obj.state === 0) {
				this_obj.state = 1;
				f(k).then((result) => {
					this_obj.state = 2;
					this_obj.expires = new Date().getTime() + result[1];
					this_obj.future.queue(result[0]);
				});
			}
		}
		return await this_obj.future.getValue()[0];
	}
}
exports.AsyncLRUCache = AsyncLRUCache;
