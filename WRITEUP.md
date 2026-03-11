# Exposed - Full Writeup

## Overview

A small Rust ELF binary with three flags buried inside, each harder than the last.
Run it with `./exposed` and it'll prompt you for each one in order.

## Flag 1 - Easy: `FLAG{b4s3_1s_n0t_3ncrypt10n}`

Classic "strings" challenge. The flag is base64-encoded and sitting right there in the binary.

### How to solve it

```bash
strings ./exposed | grep "=="
# RkxBR3tiNHMzXzFzX24wdF8zbmNyeXB0MTBufQ==

echo "RkxBR3tiNHMzXzFzX24wdF8zbmNyeXB0MTBufQ==" | base64 -d
# FLAG{b4s3_1s_n0t_3ncrypt10n}
```

That's it. The static `FLAG1` variable holds the base64 string and survives into the
binary since it's a `static`, not a `const`. Anyone who has done a CTF before will spot
the `==` padding and try decoding it.

## Flag 2 - Intermediate: `FLAG{x0r_w1th_r0t4t10n_1s_b3tt3r}`

A byte-level transformation applied to each character of the flag. The transformed
array is stored in the binary as `FLAG2_TRANSFORMED`.

### The transform

```
stored[i] = ((plaintext[i] ^ 0x5A) + 3) % 256
```

### Reversing it (Python)

```python
stored = [
    0x1f, 0x19, 0x1e, 0x20, 0x24, 0x25, 0x6d, 0x2b,
    0x08, 0x30, 0x6e, 0x31, 0x35, 0x08, 0x2b, 0x6d,
    0x31, 0x71, 0x31, 0x6e, 0x6d, 0x37, 0x08, 0x6e,
    0x2c, 0x08, 0x3b, 0x6c, 0x31, 0x31, 0x6c, 0x2b, 0x2a
]
flag = bytes(((b - 3) & 0xFF) ^ 0x5A for b in stored)
print(flag)  # FLAG{x0r_w1th_r0t4t10n_1s_b3tt3r}
```

### With a decompiler

In Ghidra or IDA, `check_flag2` shows up as a comparison loop over a byte array with
two arithmetic operations. Once you spot the constants `0x5A` and `3`, it's straightforward
to reverse.

## Flag 3 - Hard: `FLAG{wh3n_r0_m33ts_v-tabl3s}`

This is where it gets interesting. The XOR key doesn't exist anywhere in the binary -
it's derived at runtime from the memory address of Rust trait vtables.

### Why a C decompiler won't help much

A traditional decompiler (Ghidra without plugins, older IDA) sees:
- Indirect calls through vtable pointers - no function names
- Rust-mangled symbols like `_ZN12exposed6PieceA6halves17h...`
- No XOR key constant anywhere - it's computed from the vtable pointer address,
  which changes with every build or ASLR slide
- Ciphertext bytes scattered across custom ELF sections (`.rodata.p0lo`, `.rodata.p0hi`, ...)
  that are never contiguous on disk

### What Rust-aware tools reveal

Demangling symbols with `rustfilt` gives you the full picture:
```bash
nm ./exposed | rustfilt | grep -i piece
# exposed::PieceA::halves
# exposed::PieceB::halves
# exposed::vtable_mix
# ...
```

From there (or with Binary Ninja's Rust plugin), you can identify four structs
(`PieceA` through `PieceD`) implementing a `Piece` trait. Each one provides:
- `halves()` - returns two byte slices (lo and hi), interleaved at runtime
- `rotation_seed()` - a per-type constant

The actual key is `vtable_mix(dyn_self).wrapping_add(rotation_seed)`, where `vtable_mix`
XORs together all the bytes of the vtable pointer address.


### Static approach (PIE is off)

This binary is compiled with `-C relocation-model=static`, so there's no ASLR
and vtable addresses are fixed. You can read them straight from the disassembly:

```
mov  QWORD PTR [rsp+0x8],  0x2011e0   ; PieceA vtable
mov  QWORD PTR [rsp+0x18], 0x201210   ; PieceB vtable
mov  QWORD PTR [rsp+0x28], 0x201240   ; PieceC vtable
mov  QWORD PTR [rsp+0x38], 0x201270   ; PieceD vtable
```

Then compute the key for each piece:
```python
import struct

def vtable_mix(addr):
    bs = struct.pack("<Q", addr)
    r = 0
    for b in bs:
        r ^= b
    return r

vtables = [0x2011e0, 0x201210, 0x201240, 0x201270]
seeds   = [0xA3, 0x5C, 0x71, 0x2F]

for vt, seed in zip(vtables, seeds):
    k = (vtable_mix(vt) + seed) & 0xFF
    print(f"vtable {vt:#x} -> key {k:#04x}")
```

XOR each lo/hi pair with the corresponding key, interleave them, and you get the flag.

### Why this works as a hard challenge

In C, polymorphism uses function pointer structs or `void*` - patterns that decompilers
handle well. Rust's `&dyn Trait` fat pointers are two words (data + vtable), and using
`transmute` to extract the vtable address as a key derivation input is something no
standard decompiler is going to flag for you. There's no key in the binary, the ciphertext
is split across sections, and the dispatch is all indirect. You need to understand
Rust's trait object layout — a plain C decompiler won't get you there.

## Summary

| # | Difficulty    | Flag                                 | Technique                               |
|---|---------------|--------------------------------------|-----------------------------------------|
| 1 | Easy          | `FLAG{b4s3_1s_n0t_3ncrypt10n}`       | Base64 in strings                       |
| 2 | Intermediate  | `FLAG{x0r_w1th_r0t4t10n_1s_b3tt3r}`  | XOR + add (reverse with Python)         |
| 3 | Hard          | `FLAG{wh3n_r0_m33ts_v-tabl3s}`       | Vtable-derived key + split ELF sections |
