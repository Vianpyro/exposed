# Exposed

A reverse engineering CTF challenge written in Rust. Three flags, three difficulty levels.

Runs on **Linux x86_64**. On macOS or Windows, use Docker or WSL.

## Quick start

Grab the latest release from the [Releases](../../releases) page, extract it, and run:

```bash
tar xzf exposed-linux-x86_64.tar.gz
./run.sh
```

## Building from source

You'll need Rust installed. The build is a two-pass process because flag 3's ciphertext
depends on vtable addresses that only exist after linking:

```bash
./build.sh
```

This zeros the arrays, builds once to get addresses, computes the real values, then
builds again with the final binary. It also verifies all three flags at the end.

## Dev Container

If you'd rather not install anything locally:

1. Open this folder in VS Code
2. `Ctrl+Shift+P` -> **Dev Containers: Reopen in Container**
3. The container handles the Rust toolchain for you

## Useful tools

| Tool      | What for                  |
|-----------|---------------------------|
| `strings` | Find readable strings     |
| `xxd`     | Hex dump                  |
| `file`    | Identify binary type      |
| `nm`      | List symbols              |
| `objdump` | Disassemble               |
| `gdb`     | Debug at runtime          |

## Flags

There are three. Good luck.
