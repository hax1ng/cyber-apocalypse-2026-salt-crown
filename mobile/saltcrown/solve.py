from pathlib import Path
MASK=0xffffffff

def rol32(x,n):
    return ((x<<n)|(x>>(32-n)))&MASK

data=Path('analysis_extract/assets/rubbings/ashvault.dat').read_bytes()
assert len(data)==256
state=[]
for seat_i in range(64):
    h=0x811c9dc5
    # Translation of x86-64 AshVault::admit_bucket initialization loop.
    even_len=len(data)&~1
    for k in range(0,even_len,2):
        h=((h^(data[k]+seat_i))*0x1000193)&MASK
        t=(data[k+1]+seat_i)^h^(h>>11)
        q=(t*0x1000193)&MASK
        h=q^(q>>11)
    if len(data)&1:
        q=(((data[-1]+seat_i)^h)*0x1000193)&MASK
        h=q^(q>>11)
    state.append(h&MASK)

round_constant=0
for rnd in range(0x1000):
    new=[]
    for j in range(64):
        s=rol32(state[(j-1)&63],7)^rol32(state[(j+1)&63],27)^state[j]
        d=(s*0x85ebca77+round_constant+j)&MASK
        s2=d^(d>>15)
        d2=(s2*0xc2b2ae3d)&MASK
        v=rol32(state[j],13)^d2
        new.append((v^(v>>16))&MASK)
    state=new
    round_constant=(round_constant+0x9e3779b9)&MASK

def admit_bucket(choke):
    a=(7*choke+3)&63
    b=(23*choke+41)&63
    x=rol32(state[b],11)^state[a]
    return ((x>>5)^(x>>13))&0xff

buckets=[admit_bucket(i) for i in range(8)]
print('buckets:',buckets)

def mix(h,v):
    h=(h^v)&MASK
    h=(h*16777619)&MASK
    h=(h^(h>>15))&MASK
    h=(h*2246822519)&MASK
    h=(h^(h>>13))&MASK
    return h

measured=2166136261
for choke in range(3,8):
    measured=mix(measured,choke)
    measured=mix(measured,buckets[choke])
print(f'measured: 0x{measured:08x}')
sealed=bytes.fromhex('75c9ab6b9a53cfbf1fe97e4a939425e029cf87a9c280dedc')
out=[]
num=measured
for i,c in enumerate(sealed):
    num=mix(num,i)
    out.append(c^(num>>24))
print('flag:', 'HTB{'+bytes(out).decode('ascii')+'}')
for i in range(3,8):
    print(f'choke {i}: z={14-6*i:3d}, bucket={buckets[i]:3d}, phase={buckets[i]/256:.6f}')
