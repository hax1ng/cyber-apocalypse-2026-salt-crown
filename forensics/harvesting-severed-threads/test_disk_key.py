from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
key=bytes.fromhex('6d092b4dcb45c0141e5306b7e8ee39ceecb8cb4b4b75f6f4e1b1f8f2d74773a0d4ce7acf39d2197edc70fb453728b1713ed52e396c50217e99299a6797d350df')
with open('dev_disk.img','rb') as f:
 f.seek(8192*512); enc=f.read(4096)
for keyname,k in [('normal',key),('halves-swapped',key[32:]+key[:32])]:
 out=b''
 for sec in range(8):
  tweak=sec.to_bytes(16,'little')
  out+=Cipher(algorithms.AES(k),modes.XTS(tweak)).decryptor().update(enc[sec*512:(sec+1)*512])
 open('disk_head_'+keyname+'.bin','wb').write(out)
 print(keyname,out[:64].hex(),'ext4 magic',out[1024+56:1024+58].hex(),'label?',out[1024+120:1024+136])
