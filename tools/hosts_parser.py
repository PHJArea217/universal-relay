#!/usr/bin/python3

# Convert a /etc/hosts file to dc_map format
# Need ["hosts", {"ip_subst": "::/0"}] in groupsub_map
import argparse, shlex, json, ipaddress
parser = argparse.ArgumentParser();
parser.add_argument('filename');
parser.add_argument('-s', '--string1', default='hosts')
parser.add_argument('-x', '--suffix', default='')
result = parser.parse_args();
result_list = []
with open(result.filename, 'r') as hosts_file:
    for hosts_line_raw in hosts_file.readlines():
        hosts_line = shlex.split(hosts_line_raw, comments=True)
        if len(hosts_line) >= 2:
            # print(hosts_line)
            host_ip = ipaddress.ip_address(hosts_line[0])
            if isinstance(host_ip, ipaddress.IPv4Address):
                host_ip_groupsub = f'i-hx-{result.string1}-{hex(int(host_ip) | 0xffff00000000)}.u-relay.home.arpa'
            else:
                host_ip_groupsub = f'i-hx-{result.string1}-{hex(int(host_ip))}.u-relay.home.arpa'
            for host in hosts_line[1:]:
                if host.endswith(result.suffix):
                    result_list.append([host, host_ip_groupsub])
print(json.dumps(result_list))
