from scapy.all import *

def pkt_callback(pkt):
    pkt.command() # debug statement

sniff(iface="wlan1mon", prn=pkt_callback, store=0)