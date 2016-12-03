#!/usr/bin/python

import socket
import dpkt
import struct
import sys

import pcap

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0x0300)
s.bind(("enp1s0f1", 0))
iface = "enp1s0f1"


def get_wscale(opts):
    i = 0
    while i < len(opts):
        opt_type, = struct.unpack('!B', opts[i:i+1])
        if opt_type == dpkt.tcp.TCP_OPT_NOP:
            i += 1
            continue
        elif opt_type == 0:
            return 0
        opt_len, = struct.unpack('!B', opts[i+1:i+2])
        if opt_type == dpkt.tcp.TCP_OPT_WSCALE:
            wscale, = struct.unpack('!B', opts[i+2:i+3])
            return wscale
        i += opt_len
    return 0

window_scales = {}

while True:
#for ts, pkt in pcap.pcap('443.pcap'):
    #print str(pkt).encode('hex')
    #sys.exit(1)
    pkt = s.recv(0xffff)
    eth = dpkt.ethernet.Ethernet(str(pkt))
    #print eth.__repr__()

    if isinstance(eth.data, dpkt.ip.IP):
        if isinstance(eth.data.data, dpkt.tcp.TCP):
            ip = eth.data
            tcp = ip.data
            #print tcp.__repr__()
            if tcp.sport == 443:

                conn_id = (ip.src, tcp.dport)
                if tcp.flags == (dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK):
                    wscale = get_wscale(tcp.opts)
                    #print '%s %d %d' % (conn_id, tcp.win, wscale)
                    window_scales[conn_id] = (tcp.win, wscale)

                elif tcp.data.startswith('\x17\x03') and conn_id in window_scales:
                    synack_win, wscale, = window_scales[conn_id]
                    print '%s,%d %d %d %d' % (socket.inet_ntoa(ip.src), tcp.dport, synack_win, wscale,
                            tcp.win << wscale)

