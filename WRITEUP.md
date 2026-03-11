# Exposed -- CTF Reverse Engineering Writeup

**Binary:** `exposed` (ELF 64-bit, x86-64, non-PIE, stripped, Rust)  
**Difficulty:** Easy / Intermediate / Hard  
**Author:** Vianpyro  
**Flags:** 3

## Setup

The archive contains three files:

```
exposed                     # the main binary
libstd-267b04dbd87607fb.so  # Rust standard library
run.sh                      # wrapper that sets LD_LIBRARY_PATH
```

Run the binary using the provided script, or manually:

```bash
LD_LIBRARY_PATH=. ./exposed
```

The program greets you, explains there are three flags of increasing difficulty, then prompts for each one sequentially. Wrong answers loop until you get it right.

## Reconnaissance

Before touching a disassembler, always start with the basics.

```bash
file exposed
# ELF 64-bit LSB executable, x86-64, dynamically linked, stripped

strings exposed | less
```

`strings` already leaks a lot: you can see references to `base64-0.22.1` (a Rust crate), the three difficulty labels (`Easy`, `Intermediate`, `Hard`), and, **crucially**: a suspicious base64 string sitting in plaintext.

```bash
checksec --file=exposed
# No PIE, no stack canary (for the flag logic itself)
```

Non-PIE means all code and data addresses are fixed at load time, which makes static analysis straightforward.

## Flag 1 -- Easy

### Finding it

```bash
strings exposed | grep -E '^[A-Za-z0-9+/]{20,}={0,2}$'
# RkxBR3tiNHMzXzFzX24wdF8zbmNyeXB0MTBufQ==
```

That's a base64 string sitting directly in `.rodata`. Decode it:

```bash
echo "RkxBR3tiNHMzXzFzX24wdF8zbmNyeXB0MTBufQ==" | base64 -d
```

**Flag 1: `FLAG{b4s3_1s_n0t_3ncrypt10n}`**

### What's happening

The program calls the `base64` crate to decode this string at runtime, then compares it character by character against your input. The "encoded" value is stored verbatim in the binary -- there's no obfuscation at all. The flag name says it all.

### Tools

- `strings` -- good enough here
- `xxd` / `hexdump` -- for a raw dump if needed
- Any base64 decoder (`base64 -d`, CyberChef, Python)

## Flag 2 -- Intermediate

### Static analysis approach

`strings` gives nothing readable for flag 2. Time to look at the binary structure more carefully.

```bash
objdump -s -j .rodata ./exposed | less
```

Around offset `0x2011b0` you'll find a block of seemingly random bytes:

```
2011b0: 1f 19 1e 20 24 25 6d 2b  08 30 6e 31 35 08 2b 6d
2011c0: 31 71 31 6e 6d 37 08 6e  2c 08 3b 6c 31 31 6c 2b  2a
```

Now look at the disassembly of the flag 2 checker:

```bash
objdump -d -M intel ./exposed | less
```

The relevant logic sits around `0x202f42`. Two instructions give it away immediately:

```asm
80 f2 5a    xor   dl, 0x5a
80 c2 03    add   dl, 0x3
3a 90 ...   cmp   dl, BYTE PTR [rax+0x2011b8]
```

The check is: `(input_byte XOR 0x5a) + 0x3 == stored_byte`

Inverting: `input_byte = (stored_byte - 0x3) XOR 0x5a`

The loop also checks that the input is exactly 33 characters (the `cmp rax, 0x21` guard) and skips over whitespace characters (`\r`, `\n`) at the end.

### Decoding

```python
data = bytes([
    0x1f, 0x19, 0x1e, 0x20, 0x24, 0x25, 0x6d, 0x2b, 0x08,
    0x30, 0x6e, 0x31, 0x35, 0x08, 0x2b, 0x6d, 0x31,
    0x71, 0x31, 0x6e, 0x6d, 0x37, 0x08, 0x6e, 0x2c,
    0x08, 0x3b, 0x6c, 0x31, 0x31, 0x6c, 0x2b, 0x2a
])

flag = ''.join(chr((b - 3) ^ 0x5a) for b in data)
print(flag)
```

**Flag 2: `FLAG{x0r_w1th_r0t4t10n_1s_b3tt3r}`**

### What's happening

A simple XOR cipher combined with a byte rotation (add 3). Neither operation is cryptographically meaningful on its own -- together they're just mild obfuscation, enough to survive `strings` but trivial to reverse once you spot the two-instruction pattern in the disassembly.

### Tools

- `objdump -d -M intel` -- for disassembly
- `Ghidra` / `IDA Free` / `Binary Ninja` -- any of these will decompile the checker into readable pseudocode, making the XOR+add pattern obvious immediately
- Python -- to invert the transform

## Flag 3 -- Hard

This one requires understanding how Rust compiles trait objects (vtables) and how the binary uses them to split the validation across multiple closures.

### First look

The flag 3 checker starts around `0x202f87`. Unlike the previous two, it doesn't have a single comparison loop -- it builds a small array of four objects on the stack and iterates over them:

```asm
mov QWORD PTR [rsp+0x8],  0x2011e0   ; struct A
mov QWORD PTR [rsp+0x18], 0x201210   ; struct B
mov QWORD PTR [rsp+0x28], 0x201240   ; struct C
mov QWORD PTR [rsp+0x38], 0x201270   ; struct D

; loop: r15 = 8, step 0x10, until r15 = 0x48
mov rdx, QWORD PTR [rsp+r15]
call QWORD PTR [rdx+0x28]            ; virtual dispatch
```

This is Rust's trait object mechanism: each "struct" is actually a vtable, and `[vtable+0x28]` is the slot for the validation method. The four vtables live in `.rodata` and each points to a different sub-checker function.

### The key derivation function

Before comparing anything, each sub-checker calls the function at `0x202d82`:

```asm
202d82: mov QWORD PTR [rsp-0x8], rdi   ; save the argument on the stack
202d87: xor ecx, ecx
202d89: xor eax, eax
202d8b: xor al, BYTE PTR [rsp+rcx-0x8] ; XOR the 8 bytes of the pointer value
202d8f: inc rcx
202d92: cmp rcx, 0x8
202d96: jne 202d8b
202d98: ret
```

This XORs together all 8 bytes of its argument **as a little-endian 64-bit integer** -- that is, the bytes of the pointer value itself, not the memory it points to. Then each sub-checker adds a fixed offset to that result to produce the XOR key used for comparison.

The four structs are at fixed addresses (non-PIE binary):

| Struct address | Bytes (LE)                 | XOR  | Offset | Key  |
|---------------|-----------------------------|------|--------|------|
| `0x2011e0`    | `e0 11 20 00 00 00 00 00`   | 0xd1 | +0xa3  | 0x74 |
| `0x201210`    | `10 12 20 00 00 00 00 00`   | 0x22 | +0x5c  | 0x7e |
| `0x201240`    | `40 12 20 00 00 00 00 00`   | 0x72 | +0x71  | 0xe3 |
| `0x201270`    | `70 12 20 00 00 00 00 00`   | 0x42 | +0x2f  | 0x71 |

> **Gotcha:** The XOR of `e0 11 20` is `0xd1`, not `0xf1`. It's easy to miscalculate `0xe0 ^ 0x11 = 0xf1`, then forget to XOR `0x20` again. Catching this with GDB saved the analysis:
> ```
> break *0x202d82
> commands
>   x/8bx $rsp-8
>   continue
> end
> ```

### The comparison loops

Each sub-checker compares input bytes against reference data from `.rodata` at `0x200c20`:

```
200c20: 38 33 03 47  32 35 0f 1c  21 4e 13 4d  10 0c 21 4d
200c30: 90 95 97 97  bc ce 13 42  0c 10 1d 02
```

The loop processes two bytes per iteration, pulling from two alternating reference pointers (`rsi` and `r8`). For each byte:

```
(input[i] XOR key) == reference[i]
-> input[i] = reference[i] XOR key
```

The four sub-checkers cover 8 + 8 + 6 + 6 = 28 bytes of input total (including the trailing `}`), split across the reference data as follows:

| Sub-checker    | Key  | ptr_a (even positions)  | ptr_b (odd positions)   | Count |
|----------------|------|-------------------------|-------------------------|-------|
| SC2 (0x203217) | 0x74 | `0x200c24` (ref[4..7])  | `0x200c20` (ref[0..3])  |   4   |
| SC1 (0x203191) | 0x7e | `0x200c2c` (ref[12..15])| `0x200c28` (ref[8..11]) |   4   |
| SC3 (0x20329d) | 0xe3 | `0x200c33` (ref[19..21])| `0x200c30` (ref[16..18])|   3   |
| SC4 (0x203323) | 0x71 | `0x200c39` (ref[25..27])| `0x200c36` (ref[22..24])|   3   |

### Decoding

```python
ref = bytes([
    0x38, 0x33, 0x03, 0x47,  0x32, 0x35, 0x0f, 0x1c,
    0x21, 0x4e, 0x13, 0x4d,  0x10, 0x0c, 0x21, 0x4d,
    0x90, 0x95, 0x97, 0x97,  0xbc, 0xce, 0x13, 0x42,
    0x0c, 0x10, 0x1d, 0x02
])

def decode_chunk(key, a_start, b_start, count):
    out = []
    for i in range(count):
        out.append(ref[a_start + i] ^ key)
        out.append(ref[b_start + i] ^ key)
    return out

sc2 = decode_chunk(0x74, 4,  0,  4)
sc1 = decode_chunk(0x7e, 12, 8,  4)
sc3 = decode_chunk(0xe3, 19, 16, 3)
sc4 = decode_chunk(0x71, 25, 22, 3)

print(''.join(chr(b) for b in sc2 + sc1 + sc3 + sc4))
```

**Flag 3: `FLAG{wh3n_r0_m33ts_v-tabl3s}`**

### What's happening

The flag name is the explanation: the checker is structured around Rust vtables (the `-tabl3s` part) and ROT-style XOR obfuscation (`r0` = rot/xor). The key is derived from the vtable pointer address itself -- a self-referential trick that ties the validation logic to the binary's load address. Since the binary is non-PIE, those addresses are deterministic, so the keys are constant. A PIE binary would have made this considerably harder.

### Tools

- `objdump -d -M intel` -- mandatory, Ghidra/IDA make the vtable dispatch much more obvious
- **Ghidra** (recommended) -- its Rust support has improved; it will recognize the vtable layout and label the closures
- **GDB** -- essential for catching the subtle XOR arithmetic and verifying key values at runtime:
  ```bash
  gdb ./exposed
  set env LD_LIBRARY_PATH=.
  break *0x203252
  commands
    printf "key=0x%02x ref=", $rcx&0xff
    x/1bx $rsi
    continue
  end
  run
  ```
- **pwndbg** or **GEF** -- nicer GDB frontends, useful for inspecting memory around the vtables
- Python -- for the decoding script above

## Summary

| Flag | Value                               | Technique                                      |
|------|-------------------------------------|------------------------------------------------|
|  1   | `FLAG{b4s3_1s_n0t_3ncrypt10n}`      | Plaintext base64 in `.rodata`                  |
|  2   | `FLAG{x0r_w1th_r0t4t10n_1s_b3tt3r}` | XOR 0x5a + rotate 3, static key                |
|  3   | `FLAG{wh3n_r0_m33ts_v-tabl3s}`      | Rust vtable dispatch, address-derived XOR keys |

Each flag builds on the previous one: `strings` -> static disassembly -> dynamic analysis. 
The binary is a clean progression that covers the main techniques you'll encounter in beginner-to-intermediate reversing challenges.