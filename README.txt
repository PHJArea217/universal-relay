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
