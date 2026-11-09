#!/usr/bin/env bash
#
# mayhem/build.sh — build OpenSC's in-tree libFuzzer harnesses (src/tests/fuzzing) and its cmocka unit suite.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# OpenSC is autotools. Both builds are OUT-OF-TREE under mayhem/build-* (gitignored by mayhem/.gitignore,
# so `git clean -ffdX` removes them); the generated configure/Makefile.in are gitignored upstream and are
# regenerated here from committed content, so a cleaned tree rebuilds.
./bootstrap

OBJ="$SRC/mayhem/build-fuzz"
TST="$SRC/mayhem/build-test"
mkdir -p "$OBJ" "$TST"

# 1) The PROJECT, sanitized + DWARF-3, with the fuzz coverage instrumentation compiled in (no libFuzzer link
#    yet). Mirrors upstream's documented fuzz configure (src/tests/fuzzing/README.md).
# Four benign-UB UBSan checks are relaxed (ASan and every other UBSan check keep halting). Without this, upstream's own seeds
# abort 10 of 13 harnesses on the first input, before any coverage: `alignment` (fuzzer_tool.c reads a uint16_t through a
# misaligned pointer), `function` (asn1.c calls sc_pkcs15_pubkey_from_spki_fields through a generic callback type),
# `nonnull-attribute` (memcpy(dst, NULL, 0) in pkcs15.c and the fuzz_card/fuzz_asn1_sig_value paths) and `pointer-overflow`
# (NULL + 0 in pkcs11-object.c). None is memory corruption; OSS-Fuzz's own UBSan set also omits alignment/nonnull/pointer-overflow.
FUZZ_UBSAN_RELAX="-fno-sanitize=alignment,function,nonnull-attribute,pointer-overflow"
# Old code (mining BASE) trips -Werror under the current clang (e.g. -Wdeprecated-non-prototype in card-openpgp.c); warnings must not fail the build.
FUZZ_UBSAN_RELAX="$FUZZ_UBSAN_RELAX -Wno-error"
cd "$OBJ"
# configure's own probe programs run under ASan; leak reports there would fail feature checks (build-time only).
ASAN_OPTIONS=detect_leaks=0 "$SRC/configure" \
    --disable-optimization --disable-shared --enable-static --disable-pcsc --enable-ctapi \
    --enable-fuzzing --enable-openssl --disable-man --disable-doc --disable-notify \
    CC="$CC" CFLAGS="$SANITIZER_FLAGS $FUZZ_UBSAN_RELAX $DEBUG_FLAGS -fsanitize=fuzzer-no-link" \
    LDFLAGS="$SANITIZER_FLAGS"
# fuzz_pkcs15init upstream links -static, which the ASan runtime cannot do; link it dynamically against libc.
LINK_OVERRIDES=(fuzz_pkcs15init_LDFLAGS=)
make -j"$MAYHEM_JOBS" "${LINK_OVERRIDES[@]}" FUZZING_LIBS="-fsanitize=fuzzer $SANITIZER_FLAGS" all

# 2) Link every harness twice: against libFuzzer, and against the LLVM run-once driver (-standalone).
#    lsan_off.o disables leak detection at build time (ASan + UBSan stay on).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$OBJ/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"

FZ="$OBJ/src/tests/fuzzing"
# fuzz_asn1_sig_value: upstream's harness memcpy()s into a NULL buffer on an empty input (UB, and UBSan halts), so it is
# linked from the corrected copy in mayhem/harnesses/ (same libraries, same API under test). The rest use upstream's sources.
FIXED=fuzz_asn1_sig_value
HARNESSES=$(cd "$SRC/src/tests/fuzzing" && ls fuzz_*.c | sed 's/\.c$//' | grep -vx "$FIXED")
$CC -DHAVE_CONFIG_H -I"$OBJ" -I"$SRC/src" -O0 $SANITIZER_FLAGS $FUZZ_UBSAN_RELAX $DEBUG_FLAGS -fsanitize=fuzzer-no-link \
    -c "$SRC/mayhem/harnesses/$FIXED.c" -o "$OBJ/$FIXED.o"

link_all() {   # $1 = suffix, $2... = FUZZING_LIBS
    local suffix="$1"; shift
    for h in $HARNESSES; do rm -f "$FZ/$h"; done
    make -C "$FZ" "${LINK_OVERRIDES[@]}" FUZZING_LIBS="$*" $HARNESSES
    for h in $HARNESSES; do cp "$FZ/$h" "/mayhem/$h$suffix"; done
    "$OBJ/libtool" --tag=CC --mode=link $CC $SANITIZER_FLAGS $DEBUG_FLAGS -O0 -o "/mayhem/$FIXED$suffix" "$OBJ/$FIXED.o" $* \
        "$OBJ/src/libopensc/libopensc.la" "$OBJ/src/common/libscdl.la" \
        "$OBJ/src/pkcs15init/libpkcs15init.la" "$OBJ/src/common/libcompat.la"
}
link_all ""            -fsanitize=fuzzer "$SANITIZER_FLAGS" "$OBJ/lsan_off.o"
link_all "-standalone" "$OBJ/standalone_main.o" "$SANITIZER_FLAGS" "$OBJ/lsan_off.o"

# 3) The unit suite (cmocka), built from a separate configure with the project's NORMAL flags.
cd "$TST"
(env -u CFLAGS -u LDFLAGS -u CPPFLAGS "$SRC/configure" \
    --enable-cmocka --enable-openssl --disable-pcsc --enable-ctapi --disable-man --disable-doc --disable-notify \
    CC="$CC" CFLAGS="-g -O1 -Wno-error $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS")
(env -u CFLAGS -u LDFLAGS -u CPPFLAGS make -j"$MAYHEM_JOBS" -C . all)
