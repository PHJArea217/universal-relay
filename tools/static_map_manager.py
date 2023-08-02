#!/usr/bin/python3
import argparse, json, ipaddress, sys, shlex, re
parser = argparse.ArgumentParser()
parser.add_argument('filename', nargs='*');
parser.add_argument('-l', '--list-file', nargs='*', default=[]);
parser.add_argument('-H', '--hosts-file', nargs='*', default=[]);
parser.add_argument('-r', '--build-relay-map', action='store_true');
parser.add_argument('-c', '--combine', action='store_true');
parser.add_argument('-L', '--make-list', action='store_true');
parser.add_argument('-o', '--offset', default='0');
parser.add_argument('-O', '--offset-limit', default='4294967296');
parser.add_argument('-t', '--relay-map-to-hosts', action='store_true')
parser.add_argument('-p', '--ipv6-prefix', default='0xfedb120045007800')
parser.add_argument('-4', '--ipv4-start', default='198.18.0.0')
parser.add_argument('-f', '--format', default='hosts')
args = parser.parse_args()
filter_ = re.compile(r'^[a-z0-9_.-]*$')
if args.build_relay_map:
    domains = []
    for map_file in args.filename:
        map_json = json.load(open(map_file, 'r'))
        if 'relay_map' in map_json:
            for e in map_json['relay_map']:
                domains.append(str(e[0]))
    for host_file in args.hosts_file:
        with open(host_file, 'r') as h_file:
            for l in h_file.readlines():
                hosts_file_line = shlex.split(l, comments=True)
                if len(hosts_file_line) >= 2:
                    host_ip = ipaddress.ip_address(hosts_file_line[0])
                    for d in hosts_file_line[1:]:
                        domains.append(d)
    for list_file in args.list_file:
        with open(list_file, 'r') as h_file:
            for l in h_file.readlines():
                hosts_file_line = shlex.split(l, comments=True)
                for d in hosts_file_line:
                    domains.append(d)
                    break
    domain_dict = {}
    offset = int(args.offset)
    offset_limit = int(args.offset_limit)
    offset_relative = 0
    for d_ in domains:
        d = d_.lower()
        if filter_.match(d) == None:
            continue
        elif d in domain_dict:
            pass
        else:
            domain_dict[d] = (offset + offset_relative) & 0xffffffff
            offset_relative = offset_relative + 1
            if offset_relative >= offset_limit:
                sys.stderr.write("Offset limit exceeded\n")
                break
    new_domains = []
    for a in domain_dict:
        new_domains.append([a, domain_dict[a]])
    print(json.dumps({'relay_map': new_domains}))
    sys.exit(0)
if args.combine:
    result = {'relay_map': {}, 'dns_map': {}, 'resolve_map': {}, 'groupsub_map': {}, 'dc_map': {}}
    for f in args.filename:
        input_file_json = json.load(open(f, 'r'))
        for m in result:
            if m in input_file_json:
                for m_entry in input_file_json[m]:
                    result[m][m_entry[0]] = m_entry[1]
    for f in args.list_file:
        input_file_json = json.load(open(f, 'r'))
        for m in result:
            if m == 'relay_map':
                continue
            if m in input_file_json:
                for m_entry in input_file_json[m]:
                    result[m][m_entry[0]] = m_entry[1]
    result_map = {}
    for m in result:
        result_map[m] = [[a,result[m][a]] for a in result[m]]
    print(json.dumps(result_map))
    sys.exit(0)
if args.make_list:
    for f in args.filename:
        file_json = json.load(open(f, 'r'))
        for e in file_json:
            print(str(e))
    sys.exit(0)
if args.relay_map_to_hosts:
    ipv6_prefix = int(args.ipv6_prefix, base=0) << 64
    ipv4_start = int(ipaddress.IPv4Address(args.ipv4_start))
    ipv4_offset = int(args.offset)
    ipv4_offset_limit = int(args.offset_limit)
    file_json = json.load(open(args.filename[0], 'r'))
    for e in file_json['relay_map']:
        if filter_.match(e[0]) != None:
            my_ip = ipaddress.IPv6Address(ipv6_prefix | 0x5ff700100000000 | (e[1] & 0xffffffff))
            my_ipv4 = None
            if ipv4_offset_limit < 4294967296:
                normal_ipv4 = (e[1] & 0xffffffff) - ipv4_offset
                if normal_ipv4 >= 0 and normal_ipv4 < ipv4_offset_limit:
                    my_ipv4 = ipaddress.IPv4Address(ipv4_start + normal_ipv4)
            if args.format == 'bind':
                print(e[0] + '. IN AAAA ' + str(my_ip))
                if my_ipv4 != None:
                    print(e[0] + '. IN A ' + str(my_ipv4))
            elif args.format == 'dnsmasq':
                if my_ipv4 != None:
                    print(f"""address=/{e[0]}/{my_ipv4}""")
                print(f"""address=/{e[0]}/{my_ip}""")
            else: # --format hosts is the default
                if my_ipv4 != None:
                    print(str(my_ipv4) + ' ' + e[0])
                print(str(my_ip) + ' ' + e[0])
    sys.exit(0)
# domain
