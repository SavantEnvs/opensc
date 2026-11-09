#!/usr/bin/env bash
#
# mayhem/test.sh — RUN OpenSC's cmocka unit suite (built by mayhem/build.sh) plus opensc-asn1 known-answer probes.
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

TST="$SRC/mayhem/build-test"
UT="$TST/src/tests/unittests"
TOOLS="$TST/src/tools"

passed=0; failed=0; skipped=0

# cmocka suites: every case asserts decoded/encoded values. A suite that prints no summary (e.g. a
# neutered binary that exits before running) counts as a failure, never a skip.
for t in asn1 simpletlv cachedir pkcs15filter openpgp-tool decode_ecdsa_signature \
         check_macro_reference_loop strip_pkcs1_2_padding base64 parse_pkcs11_uri compression sm; do
  bin="$UT/$t"
  # Suites added upstream after this BASE: their sources do not exist here, so they count as skipped, by name.
  case "$t" in decode_ecdsa_signature|check_macro_reference_loop|strip_pkcs1_2_padding|base64|parse_pkcs11_uri)
    if [ ! -e "$SRC/src/tests/unittests/$t.c" ]; then echo "SKIP (not in this BASE): $t"; skipped=$((skipped+1)); continue; fi;; esac
  if [ ! -x "$bin" ]; then echo "MISSING unit test binary: $bin" >&2; failed=$((failed+1)); continue; fi
  out=$("$bin" 2>&1); rc=$?
  echo "$out" | tail -3
  p=$(echo "$out" | sed -n 's/^\[  PASSED  \] \([0-9]*\) test(s)\./\1/p' | tail -1)
  f=$(echo "$out" | sed -n 's/^\[  FAILED  \] \([0-9]*\) test(s).*/\1/p' | tail -1)
  if [ "$rc" -eq 0 ] && [ -n "$p" ] && [ "$p" -gt 0 ] && [ -z "$f" ]; then
    passed=$((passed+p))
  else
    echo "FAIL: $t (rc=$rc passed='${p}' failed='${f}')" >&2
    failed=$((failed+${f:-1}))
  fi
done

# hextobin has no cmocka output; it returns non-zero on the first wrong sc_hex_to_bin() result.
if [ ! -x "$UT/hextobin" ]; then echo "MISSING hextobin" >&2; failed=$((failed+1))
elif "$UT/hextobin"; then passed=$((passed+1)); else echo "FAIL: hextobin" >&2; failed=$((failed+1)); fi

# Known-answer probes through the real (dynamically linked) opensc-asn1 tool: fixed DER in, exact decode out.
kat() {   # kat <name> <expected> <printf-bytes>
  local name="$1" want="$2" der got
  der=$(mktemp); printf "$3" > "$der"
  got=$("$TOOLS/opensc-asn1" "$der" 2>&1 | tail -n +2)
  rm -f "$der"
  if [ "$got" = "$want" ]; then passed=$((passed+1)); else
    echo "FAIL KAT $name: got:" >&2; echo "$got" >&2; failed=$((failed+1)); fi
}
[ -x "$TOOLS/opensc-asn1" ] || { echo "MISSING opensc-asn1" >&2; emit_ctrf cmocka+kat "$passed" $((failed+1)) 0; exit 1; }
kat seq-int-octet $'30 SEQUENCE (6 bytes)\n   02 INTEGER (1 byte): 5\n   04 OCTET STRING (1 byte): 41 A' \
    '\x30\x06\x02\x01\x05\x04\x01\x41'
kat int-300 $'02 INTEGER (2 bytes): 300' '\x02\x02\x01\x2c'

emit_ctrf "cmocka+kat" "$passed" "$failed" "$skipped"
