from scapy.all import *

def pkt_callback(pkt):
    print str(pkt).encode('HEX') # debug statement

sniff(prn=pkt_callback, store=0)