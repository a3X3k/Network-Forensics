# Dr Evil

- By analysing the PCAP, we shall figure out that the **Reserved Bits** (or) **Evil Bits** which are the unused bit in the **IPv4** packet header, which can be used to indicate whether a **packet** had been sent with **malicious intent**. 
- Using this idea, the data has been sent in evil bits of the IPv4 headers. 
- Extracting the bits gives the transmitted data in the **Binary** format since the reserved bit can either be **Set (1)** or **Unset (0)**.

### Python Script

```py
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
```

### Output

```
Ladies and gentlemen, welcome to my underground lair. I have gathered here before me the world's deadliest assassins. 
And yet, each of you has failed to kill Austin Powers and submit the flag "midnight{1_Milli0n_evil_b1tz!}". That makes me angry. 
And when Dr. Evil gets angry, Mr. Bigglesworth gets upset. And when Mr. Bigglesworth gets upset, people DIE!!
```

### Flag

```c
midnight{1_Milli0n_evil_b1tz!}
```
