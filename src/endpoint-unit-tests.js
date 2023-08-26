let { Endpoint, ofPrefix } = require('./endpoint.js');

function test(val) {
	if (!val) throw new Error('Test failed!');
}
test(new Endpoint().setDomain('a.b.c.d.example.com').getSubdomainsOf(['com', 'example'], Infinity).join('|') === 'd|c|b|a');
test(new Endpoint().setDomain('a.b.c.d.example.com').getSubdomainsOf(['com', 'example', 'd', 'c'], Infinity).join('|') === 'b|a');
test(new Endpoint().setDomain('a.b.c.d.example.com').getSubdomainsOfLex(['com', 'example', 'd', 'e'], Infinity) === -2n);
test(new Endpoint().setDomain('a.b.c.d.example.com').getSubdomainsOfLex(['com', 'example', 'd', 'a'], Infinity) === -1n);
test(new Endpoint().setIPString('2001:db8::1:64').getHostNR(...ofPrefix('2001:db8::/64')) === 0x10064n);
test(new Endpoint().setIPString('2001:db8::2:64').getHostNR(...ofPrefix('2001:db8::/64')) === 0x20064n);
test(new Endpoint().setIPString('2001:db8::2:64').getHostNR(...ofPrefix('2001:db8::1:0/112')) === -1n);
console.log('Success');
