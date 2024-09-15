Universal Relay is a transparent and SOCKS proxy server designed to meet the
needs of the modern Internet.

** socks_iidl port 8083 **
socks_iidl port 8083 can only be used with socks_iidl port 8081. It cannot
be used directly, either as the transparent server or forced_iid.

To be able to set the destination, it is required to provide a Proxy Protocol
v2 TLV of type 0xe0, of the form:
struct u_relay_tlv_0xe0 {
uint8_t version;
uint16_t port;
uint8_t ip[16];
uint32_t reserved[2];
} __attribute__((packed));
This mode was added because connecting to a domain name on the port 8082 server with only the port 8081 "reinjection" socket would have required two Proxy Protocol v2 headers, and was therefore difficult to support in u-relay-tproxy.

TODO:

* Use mysql tables to store relay_map, dns_map, etc. as well as dynamic ip->domain map.

CREATE TABLE urelay_relay_map (id INTEGER PRIMARY KEY AUTO_INCREMENT, domain VARCHAR(255), idx UNSIGNED INT, UNIQUE KEY (domain), UNIQUE KEY (idx));
CREATE TABLE urelay_dyn_relay_map (id_ip UNSIGNED INTEGER PRIMARY KEY AUTO_INCREMENT, domain VARCHAR(255), UNIQUE KEY (domain));
urelay_dyn_relay_map range is :5f0:0000:0000:0000 -> :5f7:ffff:ffff:ffff

A smaller range here is fine, because unlike with the old dynamic map, we don't really have much of the concerns about key collisions every time Universal Relay is restarted.
Upper 19 bits: configurable "generation" or "group" value.
Lower 32 bits = numeric value of id_ip;

* replace ip module with napi inet_aton/inet_pton/inet_ntop/[0,1,2,3,4,5,6,7].map(i=>dataview.readUint16(2*i).toString(16)).join(':')
