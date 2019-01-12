from scapy.all import *

def pkt_callback(pkt):
    pkt.show() # debug statement

sniff(iface="<My Interface>", prn=pkt_callback, filter="tcp", store=0)