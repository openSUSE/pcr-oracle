#!/bin/bash
#
# Adversarial / negative test cases for pcr-oracle.
# Verifies that malformed input, missing files, and invalid arguments are
# rejected with a non-zero exit code and do NOT produce output files.
#
# This script needs to be run with root privilege (same as the other tests).
#

pcr_oracle=pcr-oracle
if [ -x "$(dirname "$0")/../pcr-oracle" ]; then
	pcr_oracle=$(cd "$(dirname "$0")/.." && pwd)/pcr-oracle
elif [ -x pcr-oracle ]; then
	pcr_oracle=$PWD/pcr-oracle
fi

if [ -z "$TESTDIR" ]; then
	tmpdir=$(mktemp -d /tmp/pcrtestXXXXXX)
	trap "cd / && rm -rf \"$tmpdir\"" 0 1 2 10 11 15
	TESTDIR=$tmpdir
fi

set -e
cd "$TESTDIR"

pass=0
fail=0

# Run pcr-oracle and expect it to EXIT NON-ZERO.
# Usage: expect_failure DESCRIPTION [pcr-oracle args...]
expect_failure() {
	local desc="$1"
	shift
	echo "****************"
	echo "EXPECT FAILURE: $desc"
	echo "pcr-oracle $*"
	if "$pcr_oracle" "$@" 2>/dev/null; then
		echo "FAIL: command succeeded but should have failed -- $desc"
		fail=$((fail + 1))
	else
		echo "PASS: $desc"
		pass=$((pass + 1))
	fi
}

# Run pcr-oracle, expect non-zero exit AND verify that the output file was
# not created (or left empty).
# Usage: expect_failure_no_output DESCRIPTION OUTPUT_FILE [pcr-oracle args...]
expect_failure_no_output() {
	local desc="$1"
	local outfile="$2"
	shift 2
	rm -f "$outfile"
	echo "****************"
	echo "EXPECT FAILURE (no output): $desc"
	echo "pcr-oracle $*"
	if "$pcr_oracle" "$@" 2>/dev/null; then
		echo "FAIL: command succeeded but should have failed -- $desc"
		fail=$((fail + 1))
	elif [ -s "$outfile" ]; then
		echo "FAIL: output file '$outfile' was written despite failure -- $desc"
		fail=$((fail + 1))
	else
		echo "PASS: $desc"
		pass=$((pass + 1))
	fi
	rm -f "$outfile"
}

echo "This is super secret" > secret

# ---------------------------------------------------------------------------
# 1. Invalid PCR masks
# ---------------------------------------------------------------------------

expect_failure \
	"PCR index out of range (99)" \
	--from zero seal-secret 99

expect_failure \
	"Non-numeric PCR mask" \
	--from zero seal-secret abc

expect_failure \
	"Empty PCR mask" \
	--from zero --input secret --output sealed seal-secret ""

expect_failure \
	"Negative PCR index" \
	--from zero seal-secret -- -1

# ---------------------------------------------------------------------------
# 2. Missing / unreadable input files
# ---------------------------------------------------------------------------

expect_failure_no_output \
	"seal-secret with missing --input file" \
	sealed \
	--from current \
	--input /nonexistent/secret \
	--output sealed \
	seal-secret 0,2,4

expect_failure_no_output \
	"unseal-secret with missing sealed file" \
	recovered \
	--input /nonexistent/sealed \
	--output recovered \
	unseal-secret

expect_failure_no_output \
	"sign with missing private key" \
	signed.policy \
	--private-key /nonexistent/key.pem \
	--from current \
	--output signed.policy \
	sign 0,2,4

expect_failure_no_output \
	"store-public-key with missing private key" \
	pubkey.out \
	--private-key /nonexistent/key.pem \
	--public-key pubkey.out \
	store-public-key

expect_failure_no_output \
	"unseal-secret with missing public key file" \
	recovered \
	--input secret \
	--output recovered \
	--public-key /nonexistent/pubkey \
	unseal-secret 0,2,4

# ---------------------------------------------------------------------------
# 3. Corrupted / malformed sealed data
# ---------------------------------------------------------------------------

# 3a. Empty sealed file
touch empty-sealed
expect_failure_no_output \
	"unseal-secret with empty sealed file" \
	recovered \
	--input empty-sealed \
	--output recovered \
	unseal-secret
rm -f empty-sealed

# 3b. Random bytes (not a valid TPM2 key structure)
dd if=/dev/urandom of=garbage-sealed bs=256 count=1 2>/dev/null
expect_failure_no_output \
	"unseal-secret with garbage sealed file" \
	recovered \
	--input garbage-sealed \
	--output recovered \
	unseal-secret
rm -f garbage-sealed

# 3c. Truncated sealed file (first 16 bytes of a real sealed object)
echo "This is super secret" > secret
"$pcr_oracle" --target-platform tpm2.0 \
	--from current \
	--input secret \
	--output sealed-good \
	seal-secret 0,2,4 2>/dev/null || true

if [ -s sealed-good ]; then
	dd if=sealed-good of=truncated-sealed bs=16 count=1 2>/dev/null
	expect_failure_no_output \
		"unseal-secret with truncated sealed file" \
		recovered \
		--input truncated-sealed \
		--output recovered \
		unseal-secret
	rm -f truncated-sealed

	# 3d. Bit-flip in the middle of the sealed object
	cp sealed-good bitflip-sealed
	# Flip a byte near the middle of the file
	filesize=$(wc -c < bitflip-sealed)
	midpoint=$((filesize / 2))
	printf '\xff' | dd of=bitflip-sealed bs=1 seek="$midpoint" conv=notrunc 2>/dev/null
	expect_failure_no_output \
		"unseal-secret with bit-flipped sealed file" \
		recovered \
		--input bitflip-sealed \
		--output recovered \
		unseal-secret
	rm -f bitflip-sealed
fi
rm -f sealed-good

# ---------------------------------------------------------------------------
# 4. Malformed TPM event log
# ---------------------------------------------------------------------------

# 4a. Empty event log file
touch empty-eventlog
expect_failure \
	"predict with empty event log" \
	--from eventlog \
	--tpm-eventlog empty-eventlog \
	0,2,4
rm -f empty-eventlog

# 4b. Random garbage as event log
dd if=/dev/urandom of=garbage-eventlog bs=512 count=1 2>/dev/null
expect_failure \
	"predict with garbage event log" \
	--from eventlog \
	--tpm-eventlog garbage-eventlog \
	0,2,4
rm -f garbage-eventlog

# 4c. Truncated event log (just the spec ID header, no events)
# The EFI TCG2 spec ID event starts with the 4-byte PCR index + 4-byte event
# type + 20-byte SHA1 digest + 4-byte event size.  Write just those 32 bytes.
printf '\x00\x00\x00\x00' > truncated-eventlog   # PCR index 0
printf '\x03\x00\x00\x00' >> truncated-eventlog  # EV_NO_ACTION
dd if=/dev/zero bs=20 count=1 2>/dev/null >> truncated-eventlog  # digest
printf '\x00\x00\x00\x00' >> truncated-eventlog  # event size = 0
expect_failure \
	"predict with truncated event log (header only)" \
	--from eventlog \
	--tpm-eventlog truncated-eventlog \
	0,2,4
rm -f truncated-eventlog

# ---------------------------------------------------------------------------
# 5. Invalid --stop-event arguments
# ---------------------------------------------------------------------------

expect_failure \
	"stop-event with no '=' separator" \
	--from zero \
	--stop-event grub-command \
	0,2,4

expect_failure \
	"stop-event with unknown event type" \
	--from zero \
	--stop-event unknown-type=foo \
	0,2,4

expect_failure \
	"stop-event with empty name" \
	--from zero \
	--stop-event "=foo" \
	0,2,4

# ---------------------------------------------------------------------------
# 6. Unsupported / conflicting options
# ---------------------------------------------------------------------------

expect_failure \
	"unknown --from source" \
	--from bogussource \
	0,2,4

expect_failure \
	"unseal-secret with no --input" \
	--output recovered \
	unseal-secret

expect_failure \
	"seal-secret with no --input" \
	--from current \
	--output sealed \
	seal-secret 0,2,4

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "========================================"
echo "Results: $pass passed, $fail failed"
echo "========================================"

if [ "$fail" -gt 0 ]; then
	exit 1
fi
