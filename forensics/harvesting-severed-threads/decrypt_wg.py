#!/usr/bin/env python3
from scapy.all import rdpcap,IP,IPv6,wrpcap
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import struct
send=bytes.fromhex('2d3d193f3889d53e9d1788e2fb42589d2b5390a2160c061baa6529e6da1da21c') # .101 -> .1
recv=bytes.fromhex('953c534a5e6402ff3ed260cc23383beba5dccb31adb4119429bd9c54f3e8a42e') # .1 -> .101
out=[]
for pkt in rdpcap('capture.pcapng'):
 if not pkt.haslayer('UDP'): continue
 raw=bytes(pkt['UDP'].payload)
 if len(raw)<32 or struct.unpack_from('<I',raw)[0]!=4: continue
 typ,idx,counter=struct.unpack_from('<IIQ',raw)
 key=send if pkt[IP].src=='192.168.56.101' else recv
 nonce=b'\0'*4+struct.pack('<Q',counter)
 try: plain=ChaCha20Poly1305(key).decrypt(nonce,raw[16:],None)
 except Exception as e:
  print('FAIL',pkt.time,pkt[IP].src,idx,counter,e); continue
 print('OK',pkt.time,pkt[IP].src,'->',pkt[IP].dst,'idx=%08x'%idx,'ctr',counter,'plain',len(plain),plain[:24].hex())
 if not plain: continue
 inner=IP(plain) if plain[0]>>4==4 else IPv6(plain)
 inner.time=pkt.time
 out.append(inner)
wrpcap('decrypted_wg.pcap',out)
print('wrote',len(out),'packets')
