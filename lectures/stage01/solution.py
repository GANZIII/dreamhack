from pwn import *

p = process("./a.out")
p.recvline()
quiz = [116, 66, 85, 81, 93, 120, 81, 83, 91]
for i in range(len(quiz)):
    quiz[i] ^= 0x30
quiz = ''.join([chr(_) for _ in quiz])
p.sendline(quiz)
p.interactive()