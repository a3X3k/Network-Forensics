# Fresh From the Oven

- While analysing each packets, In one of the `TCP` packets you can find the `Message` which is being transmitted.
- So now we got an idea that all the messages are transmitted through `TCP` protocol.
- Now apply the TCP filter as `tcp` in wireshark and analyze the TCP packets.

## Message

```js
Hello, Rohith!

Hii, Shyam!

How much do you know about data security?

I don't know much about it. Can you explain it to me?

It means protecting our private data from unauthorized users.

Oh I see!

It also means encoding the data also. So we shall chat by encoding our messages so that others cannot intercept them! Our secret code: Remember remember the FIFTH of november :slight_smile:

Okay, sure.:)

Ymnx nx f xfruqj ns ymfy jshtiji bfd.

Tm, Ny'x ltti fsi ny yttp f qty tk ynrj yt zsijwxyfsi ktw rj.

Xjsinsl dtz xtrj nsyjwjxynsl knqjx, ywd yt knsi ymj xjhwjy gjmnsi ymjr fsi pjju ny htsknijsynfq

Tpfd, xzwj:)

Transferring files....
```

- The message which is being transmitted is `encrypted`. 
- We got a hint in the packet `61` as `November 5`.
- Now `5` is our hint and we shall try shifting 5 positions which we call as `ROT Cypher` and in this case its `ROT 5` substitution.
- After `ROT 5` we shall get the decrypted text.

## Decrypted Message

```js
Ymnx nx f xfruqj ns ymfy jshtiji bfd
This is a sample in that encoded way

Tm, Ny'x ltti fsi ny yttp f qty tk ynrj yt zsijwxyfsi ktw rj.
Oh, It's good and it took a lot of time to understand for me.

Xjsinsl dtz xtrj nsyjwjxynsl knqjx, ywd yt knsi ymj xjhwjy gjmnsi ymjr fsi pjju ny htsknijsynfq
Sending you some interesting files, try to find the secret behind them and keep it confidential

Tpfd, xzwj:)
Okay, sure:)
```

- Further Analysing we shall see that the port 81 and 444 are transmitting some large amount of information.
- Analysing port `81` gives the text `UP` and on applying `ROT 5` decryption, it gives the hint as `PK`.
- Analysing port `444` gives the text `*UIK263` and on applying `ROT 5` decryption, it gives the hint as `PDF`.
- Now we shall understand that the payloads which we are trying to extract contains a ZIP file and PDF file

```py
from scapy.all import *

f=rdpcap('1.pcap')

a=""
b=""
c=""
temp=""

for i in f[TCP]:

    if i.dport==81 or i.dport==444:
    
        temp = str(i[TCP].payload)
        
        for j in temp:
        
            b = chr((ord(j)-5)%256) # Shift by 5
            
            if i.dport==81: # Extract ZIP file
              a += b 
              
            if i.dport==444: # Extract PDF file
              c += b 
    
with open("1.zip", "w") as g:
    g.write(a)
    g.close()

with open("1.pdf", "w") as g:
    g.write(c)
    g.close()
```

- PDF file contains only some `Lorem ipsum` text.
- Trying `peepdf` doesn't give anything.
- ZIP file is password protected.
- Use `fcrackzip` to crack the password.

![image](https://user-images.githubusercontent.com/52845731/147371606-101c6846-02d1-4855-bd5f-a1c8c1a0265f.png)

- We have got a PNG on unzipping it. 
- Analysing it with `zsteg -a` shows some `1MLorem ipsum text` in the LSB.
- On extracting the entire LSB payload from the image, gives some unprintable characters.

```py
zsteg -E b1,bgr,lsb,xy flag.png
```

![image](https://user-images.githubusercontent.com/52845731/147371704-3f1603e2-92b9-4b07-b980-b0588deff7ea.png)

- Grepping with `strings` gives the flag.

```py
zsteg -E b1,bgr,lsb,xy flag.png | strings | grep -i inctf 
```

### Flag

```py
inctf{3ach_4nd_3v3ry_s3cre7_inf0rm4t10n_w1ll_b3_kn0wn_by_wir3shark!!!!!_:)}
```
