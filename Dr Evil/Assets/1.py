import binascii
from scapy.all import *

p = rdpcap('1.pcap')

a = ""
b = ""

for i in p:
    if i[IP].src == '52.15.194.28':
        if i[IP].flags == 'evil':
            a += '1'
        else:
            a += '0'
        
        if len(a)%8 == 0:
            b += chr(int(a, 2))
            a = ""

print(b)