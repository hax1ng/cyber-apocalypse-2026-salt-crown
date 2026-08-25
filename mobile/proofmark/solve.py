#!/usr/bin/env python3
from struct import pack

MASK=0xffffffff
C=0xc2b2ae35
M1=0x85ebca6b
M2=0xc2b2ae35
TARGET=(83,67,55,462)
CIPHERTEXT=bytes.fromhex('2a53db7ba35d34f55f59745e0043881ca1136fb7f8d73f79c1b0af1a')

def mix(x):
    x=((x>>16)^x)*M1&MASK
    x=((x>>13)^x)*M2&MASK
    return ((x>>16)^x)&MASK

def raw_reseal(words):
    x = 0x53437277
    for b in pack("<4I", *words):
        x ^= b
        x = ((x << 5) | (x >> 27)) & MASK
        x = (x + 0x9e3779b9) & MASK
        x = mix(x)
    return mix(x ^ 0xd1b54a33)

hallmark=raw_reseal(TARGET)
x=hallmark
for _ in range(1_200_000):
    x=mix((x+C)&MASK)
x=mix(x^M1)
out=bytearray()
for c in CIPHERTEXT:
    x=mix((x+C)&MASK)
    out.append(c^(x>>24))
print('target:',TARGET)
print(f'hallmark: 0x{hallmark:08x}')
print('certificate:',out.decode())
