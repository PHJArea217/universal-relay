function make_fake_DNS_state(ip_generator) {
	let result = {};
	result.byDomain = new Map();
	result.byIP = new Map();
	result.ip_generator = ip_generator;
	return result;
}
function updateEntry(state, entry, ttl) {
	let newTime = BigInt(new Date().getTime()) + ttl;
	entry[2] = newTime;
	state.byDomain.delete(entry[0]);
	state.byDomain.set(entry[0], entry);
	state.byIP.delete(entry[1]);
	state.byIP.set(entry[1], entry);
}
function deleteEntry(state, entry) {
	state.byDomain.delete(entry[0]);
	state.byIP.delete(entry[1]);
}
function pruneOldEntry(state) {
	let firstEntryDescriptor = state.byDomain[Symbol.iterator].next();
	if (!firstEntryDescriptor.done) {
		let v = firstEntryDescriptor.value;
		deleteEntry(state, v);
	}
}
function findEntryByDomain(state, domain) {
	let existingEntry = state.byDomain.get(domain);
	/* Is there already an existing entry for this domain in cache? If so, update it and return the entry. */
	if (existingEntry) {
		updateEntry(state, existingEntry, 600000n);
		return existingEntry;
	}
	/* Otherwise, generate a random IP address for this entry (if there are not too many entries), and add it to the cache */
	if (state.byDomain.size > 10000) {
		pruneOldEntry(state);
	}
	let newEntry = [domain, state.ip_generator(domain), 0n];
	let existingEntryForIP = state.byIP.get(newEntry[1]);
	if (existingEntryForIP && (existingEntryForIP[0] !== domain)) {
		throw new Error('IP generator returned duplicate IPs!');
	}
	updateEntry(state, newEntry, 600000n);
	return newEntry;
}
function findEntryByIP(state, ip_address) {
	let existingEntry = state.byIP.get(ip_address);
	if (existingEntry) {
		updateEntry(state, existingEntry, 600000n);
		return existingEntry;
	}
	return null;
}
function canonicalizeDomain(domain) {
	let d = String(domain).toLowerCase();
	if (d.endsWith(".")) {
		d = d.substring(0, d.length - 1);
	}
	if (d.match(/^[0-9a-z._-]/)) {
		return d;
	} else {
		return null;
	}
}

function ipToBigInt(ip_address) {
	let result = 0n;
	for (let i = 0n; i < 16n; i++) {
		result |= BigInt(ip_address[Number(i)]) << (8n * (15n - i));
	}
	return result;
}
