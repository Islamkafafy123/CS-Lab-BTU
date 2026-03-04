
# NOTES For TASK 1
- `md5_fastcoll` بيستخدم طريقة Marc Stevens المعروفة باسم **Differential Path Collision**.
	- الأداة بتعدل في آخر **128 بايت** (2 blocks × 64) بطريقة **بتخدع دالة الـ MD5 compression** علشان تطلع نفس الـ hash في الآخر.
# Task 1

## Initial Prep
- First We make the prefix file 
```
echo "Hello From islam" >> prefix.txt
```
- now we need to generate the binary files using the hashclash tools
```
./md5fastcoll -p prefix.txt -o msg1.bin msg2.bin
```

- using the diff command 
![[Pasted image 20250421164016.png]]
- we can see that the binary files of both files are different
![[Pasted image 20250421164158.png]]
- this shows us the binary files 
##  Experiments
### Experiment1
```
echo -n "1234567890abcdefghij1234567890ABCDEFGH1234567890ijklmnop12345678" > prefix64.txt
```
- show length
```
stat -c %s prefix64.txt

ans --> 64

```
- lets make collinsion
```
./md5fastcoll -p prefix64.txt -o msg111.bin msg222.bin
```
- and show the binary files 
![[Pasted image 20250421212503.png]]
- and both have the same hash
![[Pasted image 20250421212541.png]]
### Experiment2
- create a prefix of 65 byte
```
echo -n "1234567890abcdefghij1234567890ABCDEFGH1234567890ijklmnop123456789" > prefix65.txt
```
- check length
![[Pasted image 20250421212833.png]]
- generate collision
```
./md5fastcoll -p prefix65.txt -o msg1111.bin msg2222.bin
```
- reviewing the binary files
![[Pasted image 20250421221841.png]]
- we see a padding of zero why ?
- Because the prefix is ​​not a multiple of 64, padding occurs, and the collision is postponed for an entire block.
- and they have the same hash
![[Pasted image 20250421222012.png]]
#### What  actually happend ?
- First 64 bytes of the prefix ---> Block 1 (64 B)
- The remaining 1 byte + padding until it completes 64 --> Block 2 (64 B)
- Here the collision began (P and Q) ---> Block 3
### Experiment3
- first Putting the values into files
![[Pasted image 20250422125345.png]]

- Now to differentiate 
![[Pasted image 20250422125626.png]]
-we can see the difference in this lines
-  And to know which bytes excatly 
![[Pasted image 20250422130514.png]]


## Q1 : 
[See Experiment 2](#Experiment2)
- Ans : 
     - we see a padding of zero
     - Because the prefix is ​​not a multiple of 64, padding occurs, and the collision is postponed for an entire block.
     - If the byte length of your prefix file is **not a multiple of 64**, `md5fastcoll` adds **padding** to align it, so the collision block (`P` and `Q`) starts at the **beginning of a new 64-byte block**.
## Q2 : 
- [See Experiment 1](#Experiment1)
- Ans: 
     - No padding of zero
     - The **collision block starts immediately after the prefix** at byte **65**.
## Q3: 
- The two files are **mostly identical**, except for a **few carefully placed byte differences** within the 128-byte collision block
- [See Experiment 3](#Experiment3)


# NOTES For Task 2
# Task 2
- First **Create two different files (`M` and `N`)**: 
     - I used the `msg1.bin` and `msg2.bin`

- Generate a common suffix file (`T` )
  ![[Pasted image 20250422205205.png]]
- msg1 and msg2 have the same md5 hash
- ![[Pasted image 20250422205222.png]]
- after adding the suffix we check the md5 of the 
![[Pasted image 20250422205401.png]]
- they have the same hash
- so adding the same suffix T to them will result in two outputs that have the same hash value as well.
# NOTES For Task 3
- Unicoll is a tool for generating chosen-prefix collisions for MD5
- it was developed by Marc Stevens, who also built **HashClash**
##### what is the difference between UniColl and md5_fastcoll?

- md5_fastcoll: Generates an MD5 collision where you have the same prefix (i.e., both messages start the same).
- UniColl: Much more powerful — allows you to generate a collision where the two files can have different prefixes that you choose yourself **-> and this is exactly what we want in our case**
- ##### Internals of UniColl (basic idea)
1. we pick two prefixes, P1 and P2
2. UniColl extends these prefixes carefully (adding special padding blocks)
3. It uses differential cryptanalysis on MD5's compression function
##### UniColl in more details:
- 1. it was mentioned that we can control a few bytes in the collision blocks, and in our case of png, we just need to modify the pointer which points to which chunk to be shown, and everything else will be exactly the same.
# Task 3
## Q1
- In **Scenario 1**, this means breaking **second preimage resistance**, where the attacker must find a different input that matches the hash of a known file.
```
Given a file A, find file B such that `MD5(A) = MD5(B)`  
But **A is fixed**, and you’re trying to **hit the same hash** with a different B.
```
- In **Scenario 2**, this requires breaking **collision resistance**, where the attacker freely creates two different inputs with the same hash.
```
You create two files, A and B, such that: `MD5(A) = MD5(B)`  
You are free to choose **both** files.
```
## Q2
- **Scenario 1**
     - **Not completely**. While MD5 is **weak**, second preimage attacks are **much harder** than regular collisions.
     - As of now, there is **no public method** to perform a practical second preimage attack on MD5.
     - It would require **huge computational resources**.
     - The MD5 algorithm is vulnerable to preimage attacks that allow an attacker to find a preimage for a given hash.
- **Scenario 2**
     - **Yes, 100% broken.**
     - Researchers have found and published practical methods to generate MD5 collisions.
     - The **collision resistance** of MD5 is **completely broken**.  
     - Practical collision attacks are **well-known, easy to reproduce**, and widely used in demonstrations and attacks.
## Q3
### Overview
- I chose Scenario 2 
- First an Overview About PNG

![[Pasted image 20250429112155.png]]
- so PNG is a signature then a sequence of chunks.

- What is a Chunk 

![[Pasted image 20250429112300.png]]
### Exploit Strategy 
- lower-case chunk are ignored. aLIG/cOLL
- 3 chunks to add:
     1. alignment 
     2. collision:aligned with UniColl’s 10th character to jump over collision blocks with variable length. 
     3. skip: one to land successfully, and jump over the first image
- At last we copy the whole images’ contents after their signature as they’re made of sequence of chunks,
![[Pasted image 20250429132620.png]]
### After Collison form unicoll script
#### In **File 1**:
- The length of the `cOLL` chunk is:
```
00 00 00 75 → 0x75 = 117 bytes
```
- The parser reads 117 bytes of data
- Collision block is only 113 bytes long
- Parser reaches the skip chunk 
- and the skip chunk jumps to chunk b with is the rest of image1
#### In **File 2**:
- The length of the `cOLL` chunk is:
```
00 00 01 75 → 0x175 = 373 bytes
```
So:
- Parser reads 373 bytes of data for `cOLL`
- That swallows up all of the skip chunk 
-  lands on **Chunk A**
### Attack Sequance 
1. Extract Common Signature and Write The prefix in alignment
```
with open("prefix", "wb") as f:
    f.write(b"".join([
    d1[:0x21],
    b"\x00\x00\x00\x1a", b"zPAD", b"\x00" *26 , b"\x00\x00\x00\x00",
    b"\0\0\0\x75", b"cOLL", b"X",
  ]))
```
- this is just for making the the alignment 

2. Generate collision
```
~/hashclash/scripts/generic_ipc.sh prefix
```
3. Build the Suffix
    - Filler bytes to align the chunk
    - `jUMP` chunk
        - Swallow a large part of the file inside one chunk's data field.
    - padding
    - The actual image payloads (`d2`, `d1`), and fake CRCs
```
suffix = b"".join([
   
    b"\x00" * 0x08, struct.pack(">I", 0x100 - 4*2 + len(d2[0x21:])), b"jUMP", b"\x00" * 0xF4,b"\xDE\xAD\xBE\xEF", 

    d2[0x21:],
    b"\x5E\xAF\x00\x0D", 
    d1[0x21:],
  ])
```

#### The Whole Script
```
#!/usr/bin/env python3


import sys
import struct
import hashlib
import glob
import os
import shutil

def get_data(args):
  fn1, fn2 = args

  with open(fn1, "rb") as f:
    d1 = f.read()
  with open(fn2, "rb") as f:
    d2 = f.read()
  return d1, d2

d1, d2 = get_data(sys.argv[1:3])
hash = hashlib.sha256(d1[:0x21]).hexdigest()[:8]

print("Header hash: %s" % hash)

with open("prefix", "wb") as f:
    f.write(b"".join([
    d1[:0x21],
    b"\x00\x00\x00\x1a", b"zPAD", b"\x00" *26 , b"\x00\x00\x00\x00",
    b"\0\0\0\x75", b"cOLL", b"X",
  ]))

  
os.system("~/hashclash/scripts/generic_ipc.sh  prefix")

shutil.copyfile("collision1.bin", "png1.bin")
shutil.copyfile("collision2.bin", "png2.bin")

with open("png1.bin", "rb") as f:
  block1 = f.read()
with open("png2.bin", "rb") as f:
  block2 = f.read()

suffix = b"".join([
   
    b"\x00" * 0x08, struct.pack(">I", 0x100 - 4*2 + len(d2[0x21:])), b"jUMP", b"\x00" * 0xF4,b"\xDE\xAD\xBE\xEF", 

    d2[0x21:],
    b"\x5E\xAF\x00\x0D", 
    d1[0x21:],
  ])

with open("%s-1.png" % hash, "wb") as f:
  f.write(b"".join([
    block1,
    suffix
    ]))

with open("%s-2.png" % hash, "wb") as f:
  f.write(b"".join([
    block2,
    suffix
    ]))

```
