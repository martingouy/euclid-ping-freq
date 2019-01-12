from scapy.all import *

def pkt_callback(pkt):
    print str(pkt).encode('HEX') # debug statement

sniff(iface="wlan1mon", prn=pkt_callback, store=0)