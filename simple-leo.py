from scapy.all import *

def pkt_callback(pkt):
    pkt.show() # debug statement

sniff(iface="wlan1", prn=pkt_callback, store=0)