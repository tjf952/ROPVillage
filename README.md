# ROP Chain Exploitation

### What is ROP Chaining
> Return-oriented programming (ROP) is a computer security exploit technique that allows an attacker to execute code in the presence of security defenses such as executable space protection and code signing. Here, it will be used as leverage to bypass exploit mitigation schemes such as NX/DEP. In this technique, an attacker gains control of the call stack to hijack program control flow and then executes carefully chosen machine instruction sequences that are already in the machine's memory. These sequences are known as *gadgets* and typically exist in a subroutine within the program or the shared library code. Chained together, these gadgets allow an attacker to perform arbitrary operations on a machine even in the face of simple defenses. 
>
> Please refer to the wikipedia page for more information: [Return-oriented programming](https://en.wikipedia.org/wiki/Return-oriented_programming).

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
