## My First ROP Chain

### [vuln.c](vuln.c)

This script was written with the intention of being vulnerable to a buffer overflow and ROP chain. It has a vulnerable read() function that will allow for overwriting the EIP and a valid system() call that can be used to get RCE by making a call to the location in memory.

Cmd to build: `gcc -w -fno-stack-protector -no-pie vuln.c -o vuln`

### [exploit.py](expoit.py)

This script intends to take advantage of the vulnerable binary. I used the following steps to develop it and exploit the application:

1. First make sure the binary is vulnerable with the following command: `checksec vuln`
	- Check to make NX is on. NX stands for non-execute or non-executable segment. It means that the application, when loaded in memory, does not allow any of its segments to be both writable and executable. ROPs are used to get around this.
	- Check to make sure there is no PIE (position independent executable). A "No PIE" executable tells the loader which virtual address it should use. Combined with ASLR, PIE makes applications have a more divergent memory organization, making attacks that rely on the memory structure more diffiult.
	- Check to make sure the stack portion says "No canary found". A canary is a certain value put on a stack to be validated when leaving a function. If the canary value is not correct during validation, then the application is stopped due to the stack being overwritten or corrupted.
2. Find possible gadgets that exist within the binary with the following command: `ropper -f vuln`
	- Looking for chains to pass variables to have program execute NEC
	- For this program, there will always be a `pop rdi; ret;` gadget that we can use.
	- Taking the `ret;` gadget as well can be useful for alignment.
3. Get the memory location of global variables and function calls if necessary from gdb: `disassemble main`
	- Global variable name is found at 0x404060
	- System call is at 0x401040
4. Find the buffer overflow offset in gdb
	- Create a pattern to input: `pattern create N`
	- Run the program: `run`
	- Search the pattern for the offset: `pattern search EXPR`
5. Create the ROP chain by carefully ordering the stack

	| Top             |
	| :-------------: |
	| buffer overflow |
	| pop rdi         |
	| name            |
	| ret             |
	| system call     |

6. Send payload and analyze the need to shift bytes or align using gdb