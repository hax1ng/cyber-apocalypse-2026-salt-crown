#!/usr/bin/env python3
from scapy.all import rdpcap,IP,TCP,Raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib,struct
segments={}
for p in rdpcap('decrypted_wg.pcap'):
 if IP in p and TCP in p and Raw in p and p[IP].src=='10.0.0.2' and p[TCP].dport==9999:
  segments[p[TCP].seq]=bytes(p[Raw].load)
base=min(segments)
stream=bytearray()
for seq,data in sorted(segments.items()):
 assert seq==base+len(stream),(seq,base+len(stream))
 stream+=data
n=struct.unpack('!I',stream[:4])[0]
payload=bytes(stream[4:4+n])
assert len(payload)==n,(len(payload),n)
open('wg_stream_correct.bin','wb').write(stream)
key=hashlib.sha256(b'https://www.youtube.com/watch?v=oHafFDkFgeg').digest()
plain=AESGCM(key).decrypt(payload[:12],payload[12:],None)
open('exfil_plain.bin','wb').write(plain)
print('segments',len(segments),'framed',len(stream),'payload',n,'plaintext',len(plain),'sha256',hashlib.sha256(plain).hexdigest())
