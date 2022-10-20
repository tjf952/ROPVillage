# ROP Chain Exploitation

### What is ROP Chaining
> Return-oriented programming (ROP) is a computer security exploit technique that allows an attacker to execute code in the presence of security defenses such as executable space protection and code signing. Here, it will be used as leverage to bypass exploit mitigation schemes such as NX/DEP. In this technique, an attacker gains control of the call stack to hijack program control flow and then executes carefully chosen machine instruction sequences that are already in the machine's memory. These sequences are known as *gadgets* and typically exist in a subroutine within the program or the shared library code. Chained together, these gadgets allow an attacker to perform arbitrary operations on a machine even in the face of simple defenses. 
>
> Please refer to the wikipedia page for more information: [Return-oriented programming](https://en.wikipedia.org/wiki/Return-oriented_programming).

### Hunting

**Needles in callstacks**
Two hings to look for are:
1. what useful functions are present - disammebly, rabin, nm
2. what selection of gadgets are available - ropper, ROPGadget

**Confirming protections**
It's good practice to check if protections are enable on a binary. There are two worthwhile commands to run:
- `$ rabin2 -I <binary>` A standalone binary in the radare2 suite
- `$ checksec <binary>` A standalone functionality that is also integrated into the pwntools framework

**Function names**
Listing functions from shared libraries and the binary:
- `$ rabin2 -i <binary>` Prints a list of functions with their virtual address and bind type
- `$ nm -u <binary>` Prints a list of functions with their libraries and bind type
- `$ rabin2 -qs <binary> | grep -ve imp -e ' 0 '` Lists programmer written symbols

**Strings**
Don't use `strings` command because it will yield many lines of irrelevant output, use `rabin2` instead:
- `rabin2 -z <binary>` Pritns list of strings with their adresses and type


### GDB Commands and Plugins: 

> Check out this repo if you need gdb plugins: [PluginsGDB](https://github.com/tjf952/PluginsGDB)
>
> Favorite command to run: `gdb-gef`

***Essential Commands***
- **gdb** *program* [*core*] 
	- debug program [using coredump core]
- **b** [*file*:]*function* 
	- set breakpoint at function [in file]
- **run** [*arglist*] 
	- start your program [with arglist]
- **bt** 
	- backtrace: display program stack
- **p** *expr*
	- display the value of an expression
- **c**
	- continue running your program
- **n**
	- next line, stepping over function calls
- **s**
	- next line, stepping into function calls
- **disassem** [*addr*]
	- display memory as machine instructions
