# ROP Chain Exploitation

What is ROP Chaining
> Definition

## My First ROP Chain

[vuln.c](first_rop/vuln.c)

This script was written with the intention of being vulnerable to a buffer overflow and ROP chain. It has a vulnerable read() function that will allow for overwriting the EIP and a valid system() call that can be used to get RCE by making a call to the location in memory.

Cmd to build: `gcc vuln.c -o vuln -fno-stack-protector -no-pie`

[exploit.py](first_rop/expoit.py)

This script intends to take advantage of the vulnerable binary through the following steps:

1. First make sure the binary is vulnerable with the following command: `checksec vuln`
	- Check to make NX is on. NX stands for non-execute or non-executable segment. It means that the application, when loaded in memory, does not allow any of its segments to be both writable and executable. ROPs are used to get around this.
	- Check to make sure there is no PIE (position independent executable). A "No PIE" executable tells the loader which virtual address it should use. Combined with ASLR, PIE makes applications have a more divergent memory organization, making attacks that rely on the memory structure more diffiult.
	- Check to make sure the stack portion says "No canary found". A canary is a certain value put on a stack to be validated when leaving a function. If the canary value is not correct during validation, then the application is stopped due to the stack being overwritten or corrupted.
	- 
2. Find possible gadgets that exist within the binary with the following command: `ropper -f vuln`
	- Looking for chains to pass variables to have program execute NEC
3. Python Stuff

Simple **GDB** CMDs (Using GEF): 

> Check out this repo if you need gdb: https://github.com/tjf952/PluginsGDB

- `b main` # Put a breakpoint at the start of main
- `disass main` # Disassemble the main function of the program
- `c` # Continue; Go until the next breakpoint of return of program
- `ni` # Next Instruction; Go to the next line of code in main
