#!/usr/bin/env python3
import socket,struct,time,json,urllib.request,sys
HOST=sys.argv[1] if len(sys.argv)>1 else '154.57.164.72'
MODBUS=int(sys.argv[2]) if len(sys.argv)>2 else 31558
HMI=int(sys.argv[3]) if len(sys.argv)>3 else 30797
TID=0

def req(pdu, unit=1):
 global TID
 TID=(TID+1)&0xffff
 frame=struct.pack('>HHHB',TID,0,len(pdu)+1,unit)+pdu
 with socket.create_connection((HOST,MODBUS),3) as s:
  s.settimeout(3); s.sendall(frame); hdr=b''
  while len(hdr)<7:
   x=s.recv(7-len(hdr))
   if not x: raise EOFError('short MBAP')
   hdr+=x
  tid,pid,n,uid=struct.unpack('>HHHB',hdr)
  body=b''
  while len(body)<n-1:
   x=s.recv(n-1-len(body))
   if not x: raise EOFError('short PDU')
   body+=x
  if body and body[0]&0x80: raise RuntimeError(f'Modbus exception {body.hex()}')
  return body

def write_mask(mask):
 # FC15, coils 0..7, one packed byte
 r=req(struct.pack('>BHHB',15,0,8,1)+bytes([mask]))
 print(f'WRITE coils=0x{mask:02x} response={r.hex()}')

def read_coils():
 r=req(struct.pack('>BHH',1,0,8))
 return r[2] if len(r)>=3 else None

def status():
 with urllib.request.urlopen(f'http://{HOST}:{HMI}/status.json',timeout=3) as r:
  return json.load(r)

def show(s):
 print(f"scan={s['t'][2]:4} mode={s['m']:<6} L={s['p'][0]:5.1f}% P={s['p'][1]:5.1f}kPa coils=0x{read_coils():02x} out={s['o']} int={s['s']} trip={s['t'][1]} stable={s['t'][0]} alarms={s['a']}")

# C1 MANUAL_ARM + C5 PUMP, all other commands off.
SAFE=0x22
write_mask(SAFE)
time.sleep(1.2)

# Hold safe alignment until RESET_PERMISSIVE (s[2]) is true.
for _ in range(90):
 s=status(); show(s)
 if s['s'][2]: break
 # If level is high, drain; if pressure is high, vent. Otherwise all closed/pump on.
 level,pressure=s['p'][0],s['p'][1]
 desired=SAFE
 if level>60: desired |= 1<<3
 if pressure>42: desired |= 1<<4
 write_mask(desired)
 time.sleep(1)
else: raise SystemExit('reset permissive not reached')

# Close valves, preserve manual+pump and pulse reset C6 for one scan.
write_mask(SAFE)
time.sleep(1.1)
s=status(); show(s)
if not s['s'][2]:
 raise SystemExit('lost reset permissive before reset pulse')
write_mask(SAFE | (1<<6))
time.sleep(1.2)
write_mask(SAFE)
time.sleep(1.2)

# Wait for cleared latches and seal pressure/level band with seal off.
for _ in range(90):
 s=status(); show(s)
 level,pressure=s['p'][0],s['p'][1]
 if (not s['s'][1]) and (not s['s'][6]) and 38<=level<=54 and 28<=pressure<=36:
  break
 # maintain pump/all valves closed; trim only if needed
 desired=SAFE
 if level>54: desired |= 1<<3
 if pressure>36: desired |= 1<<4
 write_mask(desired)
 time.sleep(1)
else: raise SystemExit('seal-ready process band not reached')

# Command seal while retaining manual, pump, and closed valves.
SEAL=SAFE | (1<<7)
write_mask(SEAL)
for _ in range(30):
 time.sleep(1)
 s=status(); show(s)
 if s['s'][5]:
  print('\nTOKEN ALARM:')
  for a in s['a']: print(a)
  break
else: raise SystemExit('seal alarm did not latch')
