class Endpoint:
    def __init__(self):
        self.ip_ = 0
        self.port_ = 0
        self.options_dict_ = {}
        self.domain_ = None
    def get_ip_int(self):
        return self.ip_
    def get_ip(self):
        host_nr = self.get_host_nr(0xffff00000000, 96)
        if host_nr >= 0:
            return ipaddress.IPv4Address(host_nr)
        return ipaddress.IPv6Address(self.ip_)
    def set_ip_int(self, new_ip):
        if type(new_ip) != int:
            raise ValueError('new_ip is not an int')
        if new_ip >= 0 and new_ip < (2**128):
            self.ip_ = new_ip
            return self
        raise ValueError('new_ip must be >= 0 and < 2**128')
    def set_ip(self, new_ip):
        if type(new_ip) == ipaddress.IPv4Address:
            self.set_ip_int(int(new_ip) | 0xffff00000000)
            return self
        elif type(new_ip) == ipaddress.IPv6Address:
            self.set_ip_int(int(new_ip))
            return self
        raise ValueError('new_ip must be instanceof IPv4Address or IPv6Address')
    def get_host_nr(self, prefix, length):
        host_mask = (1 << (128 - length)) - 1
        network_mask = ~host_mask
        if (prefix & network_mask) == (self.ip_ & network_mask):
            return self.ip_ & host_mask
        return -1


