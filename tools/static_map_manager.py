#!/usr/bin/python3
import argparse, json, ipaddress, sys
parser = argparse.ArgumentParser()
parser.add_argument('filename', nargs='*');
parser.add_argument('-l', '--list-file', nargs='*', default=[]);
parser.add_argument('-H', '--hosts-file', nargs='*', default=[]);
parser.add_argument('-r', '--build-relay-map', action='store_true');
parser.add_argument('-c', '--combine', action='store_true');
parser.add_argument('-L', '--make-list', action='store_true');
parser.add_argument('-o', '--offset', default='0');
parser.add_argument('-O', '--offset-limit', default='4294967296');
args = parser.parse_args()
if args.build_relay_map:
    domains = []
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
    for map_file in args.filename:
        map_json = json.load(open(map_file, 'r'))
        if 'relay_map' in map_json:
            for e in map_json['relay_map']:
                domains.append(str(e[0]))
    domain_dict = {}
    offset = int(args.offset)
    offset_limit = int(args.offset_limit)
    offset_relative = 0
    for d in domains:
        if d in domain_dict:
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
