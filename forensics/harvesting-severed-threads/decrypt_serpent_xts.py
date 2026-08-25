#!/usr/bin/env python3
import socket, struct, sys
from pathlib import Path
SOL_ALG=279; ALG_SET_KEY=1; ALG_SET_IV=2; ALG_SET_OP=3; ALG_OP_DECRYPT=0
key=Path('master.key').read_bytes()
def setup():
 s=socket.socket(socket.AF_ALG,socket.SOCK_SEQPACKET,0)
 s.bind(('skcipher','xts(serpent)'))
 s.setsockopt(SOL_ALG,ALG_SET_KEY,key)
 return s.accept()[0]
def dec(op, data, ivn):
 iv=struct.pack('<Q',ivn)+b'\0'*8
 cmsgs=[(SOL_ALG,ALG_SET_OP,struct.pack('I',ALG_OP_DECRYPT)),(SOL_ALG,ALG_SET_IV,struct.pack('I',len(iv))+iv)]
 op.sendmsg([data],cmsgs)
 out=b''
 while len(out)<len(data): out+=op.recv(len(data)-len(out))
 return out
if __name__=='__main__':
 op=setup()
 with open('dev_disk.img','rb') as f:
  f.seek(8192*512)
  for unit in (512,1024,2048,4096):
   f.seek(8192*512)
   out=b''.join(dec(op,f.read(unit),i) for i in range(2 if unit<=2048 else 1))
   print(unit,out[:64].hex(), 'ext4',out[1080:1082].hex() if len(out)>1082 else '-')
