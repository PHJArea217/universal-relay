#!/usr/bin/python3
# To encourage modification of this file by end users, this file is public
# domain and may be used and distributed without restriction. The LICENSE file
# is not required to distribute, use, or modify this file.
# DONT USE
import ctypes, socket, os, subprocess
libc = ctypes.CDLL(None)
def set_netns(fd):
    if libc.setns(fd, 0x40000000) != 0:
        raise OSError('setns failed')
def ctrtool_nsof_add_listener(is_ipv6, bind, port, options='a', listen_backlog=4096, netns=None, netns_enter_userns=False):
    res = ['-6' if is_ipv6 else '-4']
    res = res + ['%s,%d,%s' % (bind, port, options)]
    if netns is not None:
        res = res + ['-N', netns]
    if netns_enter_userns:
        res = res + ['-U']
    res = res + ['-l', str(listen_backlog)]
    return res
def get_cmdline(listeners, options):
    res = [os.environ.get('CTRTOOL', 'ctrtool'), 'ns_open_file', '-o100']
    for l in listeners:
        res = res + l
    res = res + ['node', '-e', '''const my_app = require("./src");
const config = JSON.parse(process.argv[2]);
const app = my_app.app_func.TransparentHandler(config.app_options)
