#!/usr/bin/env python3
import socket, struct, os, stat, sys
from pathlib import Path
from functools import lru_cache
SOL_ALG=279; ALG_SET_KEY=1; ALG_SET_IV=2; ALG_SET_OP=3; ALG_OP_DECRYPT=0
class CryptReader:
 def __init__(self,path,key,base=4*1024*1024,unit=2048):
  self.f=open(path,'rb'); self.base=base; self.unit=unit
  s=socket.socket(socket.AF_ALG,socket.SOCK_SEQPACKET,0);s.bind(('skcipher','xts(serpent)'));s.setsockopt(SOL_ALG,ALG_SET_KEY,key);self.op=s.accept()[0]
 @lru_cache(maxsize=8192)
 def sector(self,n):
  self.f.seek(self.base+n*self.unit); data=self.f.read(self.unit)
  if len(data)<self.unit:data+=b'\0'*(self.unit-len(data))
  # dm-crypt uses 512-byte sector numbers for plain64 unless the optional
  # iv_large_sectors flag is set.  Here each crypto data unit is 2048 bytes.
  iv=struct.pack('<Q',n*(self.unit//512))+b'\0'*8
  self.op.sendmsg([data],[(SOL_ALG,ALG_SET_OP,struct.pack('I',ALG_OP_DECRYPT)),(SOL_ALG,ALG_SET_IV,struct.pack('I',16)+iv)])
  out=b''
  while len(out)<len(data):out+=self.op.recv(len(data)-len(out))
  return out
 def read(self,off,n):
  if n<=0:return b''
  a=off//self.unit;b=(off+n-1)//self.unit
  d=b''.join(self.sector(i) for i in range(a,b+1))
  return d[off-a*self.unit:off-a*self.unit+n]
class Ext4:
 def __init__(self,r):
  self.r=r; s=r.read(1024,1024)
  assert s[56:58]==b'\x53\xef',s[56:58].hex()
  self.s=s; self.bs=1024<<u32(s,0x18); self.ipg=u32(s,0x28);self.bpg=u32(s,0x20);self.isz=u16(s,0x58);self.first=u32(s,0x14)
  self.desc_size=max(32,u16(s,0xfe));self.gdt=(2 if self.bs==1024 else 1)*self.bs
  self.blocks=u32(s,4)|(u32(s,0x150)<<32)
  print(f'ext4: block_size={self.bs} blocks={self.blocks} inode_size={self.isz} inodes/group={self.ipg} desc={self.desc_size}')
 def inode(self,ino):
  g=(ino-1)//self.ipg;idx=(ino-1)%self.ipg
  gd=self.r.read(self.gdt+g*self.desc_size,self.desc_size)
  table=u32(gd,8)|((u32(gd,40)<<32) if self.desc_size>=64 else 0)
  d=self.r.read(table*self.bs+idx*self.isz,self.isz)
  return d
 def extents(self,node):
  if u16(node,0)!=0xf30a: raise ValueError('non-extent inode/block')
  entries=u16(node,2);depth=u16(node,6); out=[]
  if depth==0:
   for i in range(entries):
    e=node[12+i*12:24+i*12];logical=u32(e,0);ln=u16(e,4)&0x7fff;phys=u32(e,8)|(u16(e,6)<<32)
    if ln:out.append((logical,phys,ln))
  else:
   for i in range(entries):
    e=node[12+i*12:24+i*12];leaf=u32(e,4)|(u16(e,8)<<32);out+=self.extents(self.r.read(leaf*self.bs,self.bs))
  return out
 def file(self,ino):
  d=self.inode(ino);sz=u32(d,4)|(u32(d,108)<<32); flags=u32(d,32); root=d[40:100]
  if sz==0:return b''
  if not flags&0x80000: raise ValueError(f'inode {ino}: no extents flags={flags:x}')
  ex=self.extents(root); out=bytearray(sz)
  for logical,phys,ln in ex:
   off=logical*self.bs;amount=min(ln*self.bs,max(0,sz-off))
   if amount:out[off:off+amount]=self.r.read(phys*self.bs,amount)
  return bytes(out)
 def directory(self,ino):
  d=self.file(ino); p=0
  while p+8<=len(d):
   ent=u32(d,p);rec=u16(d,p+4);nl=d[p+6];typ=d[p+7]
   if rec<8 or p+rec>len(d):break
   if ent and nl:yield ent,d[p+8:p+8+nl].decode('utf-8','replace'),typ
   p+=rec
 def walk(self,ino=2,path=''):
  yield ino,path or '/',2
  for child,name,typ in self.directory(ino):
   if name in ('.','..'):continue
   cp=(path+'/'+name) if path else '/'+name
   yield child,cp,typ
   if typ==2:yield from self.walk(child,cp)
def u16(b,o):return struct.unpack_from('<H',b,o)[0]
def u32(b,o):return struct.unpack_from('<I',b,o)[0]
def main():
 key=Path('master.key').read_bytes();fs=Ext4(CryptReader('dev_disk.img',key))
 entries=list(fs.walk())
 for ino,p,t in entries:print(f'{ino:8d} {t} {p}')
 if len(sys.argv)>1:
  out=Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
  for ino,p,t in entries:
   q=out/p.lstrip('/')
   if t==2:q.mkdir(parents=True,exist_ok=True)
   elif t==1:
    q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(fs.file(ino))
if __name__=='__main__':main()
