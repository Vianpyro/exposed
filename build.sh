#!/usr/bin/env bash
set -euo pipefail

SRC="src/main.rs"
CARGO="Cargo.toml"
FLAG3="FLAG{wh3n_r0_m33ts_v-tabl3s}"
SEEDS=(0xA3 0x5C 0x71 0x2F)
SIZES=(4 4 3 3)
NAMES=(A B C D)

zero_arrays() {
    for name in "${NAMES[@]}"; do
        local idx=$(($(printf '%d' "'$name") - $(printf '%d' "'A")))
        local sz=${SIZES[$idx]}
        local zeros
        zeros=$(printf '0x00, %.0s' $(seq 1 "$sz") | sed 's/, $//')
        sed -i "s/static RAW_${name}_LO: \[u8; ${sz}\] = \[.*\]/static RAW_${name}_LO: [u8; ${sz}] = [${zeros}]/" "$SRC"
        sed -i "s/static RAW_${name}_HI: \[u8; ${sz}\] = \[.*\]/static RAW_${name}_HI: [u8; ${sz}] = [${zeros}]/" "$SRC"
    done
}

set_strip() {
    sed -i "s/^strip.*=.*/strip        = $1/" "$CARGO"
}

# Pass 1: zero arrays, no strip
echo "[1/5] zeroing arrays and disabling strip..."
zero_arrays
set_strip "false"

echo "[2/5] building pass 1 (unstripped, zeroed arrays)..."
cargo build --release 2>&1

# Grab vtable addresses
echo "[3/5] extracting vtable addresses from disassembly..."
BINARY="target/release/exposed"
VTABLES=()
while IFS= read -r line; do
    addr=$(echo "$line" | grep -oP '0x20[0-9a-f]{4}')
    VTABLES+=("$addr")
done < <(objdump -d -M intel "$BINARY" \
    | grep -A 60 '<.*check_flag3' \
    | grep 'mov.*QWORD PTR \[rsp+0x[0-9a-f]*\],0x20' \
    | head -4)

if [ "${#VTABLES[@]}" -ne 4 ]; then
    echo "error: expected 4 vtable addresses, got ${#VTABLES[@]}" >&2
    exit 1
fi

echo "   A=${VTABLES[0]}  B=${VTABLES[1]}  C=${VTABLES[2]}  D=${VTABLES[3]}"

# Compute the real ciphertext arrays
echo "[4/5] computing ciphertext arrays..."

PATCH_CMDS=$(perl -e '
    use strict; use warnings;
    my $flag = $ARGV[0];
    my @chars = split //, $flag;
    my @vt    = map { hex($_) } @ARGV[1..4];
    my @seeds = (0xA3, 0x5C, 0x71, 0x2F);
    my @sizes = (4, 4, 3, 3);
    my @names = qw(A B C D);

    sub vtable_mix {
        my $addr = shift;
        my $r = 0;
        for my $i (0..7) { $r ^= (($addr >> ($i*8)) & 0xFF); }
        return $r;
    }

    my $off = 0;
    for my $p (0..3) {
        my $k = (vtable_mix($vt[$p]) + $seeds[$p]) & 0xFF;
        my (@lo, @hi);
        for my $i (0..$sizes[$p]-1) {
            push @lo, ord($chars[$off + $i*2])     ^ $k;
            push @hi, ord($chars[$off + $i*2 + 1]) ^ $k;
        }
        my $lo_str = join(", ", map { sprintf "0x%02x", $_ } @lo);
        my $hi_str = join(", ", map { sprintf "0x%02x", $_ } @hi);
        my $n  = $names[$p];
        my $sz = $sizes[$p];
        print "s/static RAW_${n}_LO: \\[u8; ${sz}\\] = \\[.*\\]/static RAW_${n}_LO: [u8; ${sz}] = [${lo_str}]/\n";
        print "s/static RAW_${n}_HI: \\[u8; ${sz}\\] = \\[.*\\]/static RAW_${n}_HI: [u8; ${sz}] = [${hi_str}]/\n";
        $off += $sizes[$p] * 2;
    }
' "$FLAG3" "${VTABLES[@]}")

echo "$PATCH_CMDS" | sed -i -f - "$SRC"
set_strip "true"

# Pass 2: final stripped build
echo "[5/5] building pass 2 (stripped, real arrays)..."
cargo build --release 2>&1

# Sanity check
echo ""
echo "=== verification ==="
RUSTLIB=$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/lib
RESULT=$(printf 'FLAG{b4s3_1s_n0t_3ncrypt10n}\nFLAG{x0r_w1th_r0t4t10n_1s_b3tt3r}\nFLAG{wh3n_r0_m33ts_v-tabl3s}\n' \
    | LD_LIBRARY_PATH="$RUSTLIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$BINARY" 2>&1)

if echo "$RESULT" | grep -q "You found all three"; then
    echo "all three flags validated."
    ls -lh "$BINARY"
    file "$BINARY"
else
    echo "error: flag verification failed!" >&2
    echo "$RESULT"
    exit 1
fi
