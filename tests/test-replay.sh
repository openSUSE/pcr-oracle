#!/bin/bash
#
# Replay test script for pcr-oracle
# Unpacks testcase eventlog tarballs and verifies predicted PCR values
#

pcr_oracle=pcr-oracle
if [ -x "$(dirname "$0")/../pcr-oracle" ]; then
	pcr_oracle=$(cd "$(dirname "$0")/.." && pwd)/pcr-oracle
elif [ -x pcr-oracle ]; then
	pcr_oracle=$PWD/pcr-oracle
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
TESTCASES_DIR="$SCRIPT_DIR/testcases"
TMP_DIR=$(mktemp -d /tmp/pcr-replayXXXXXX)

# List of test case basenames
TEST_CASES=(
	"normal-x86-64"
	"update-shim-x86-64"
	"sbat-latest-x86-64"
)

# Clean up function for temporary files and unpacked folders
cleanup() {
	rm -rf "$TMP_DIR"
	for tc in "${TEST_CASES[@]}"; do
		rm -rf "$SCRIPT_DIR/$tc"
	done
}
trap cleanup EXIT

# Change directory to REPO_ROOT so that paths like "tests/update-shim-x86-64" match exactly
cd "$REPO_ROOT"

passed_count=0
failed_count=0

# Disable exit on error so we can run all test cases
set +e

for tc in "${TEST_CASES[@]}"; do
	echo "----------------------------------------"
	echo "Running replay test for: $tc"

	# Unpack tarball (normal-x86-64 is the base; others are diffs built on top of normal-x86-64)
	if [ "$tc" = "normal-x86-64" ]; then
		echo "Unpacking $tc.tar.xz..."
		if ! tar -C "$SCRIPT_DIR" -xf "$TESTCASES_DIR/$tc.tar.xz"; then
			echo "FAIL: $tc unpack failed!"
			failed_count=$((failed_count + 1))
			continue
		fi
	else
		echo "Unpacking base normal-x86-64.tar.xz for $tc..."
		if ! tar -C "$SCRIPT_DIR" -xf "$TESTCASES_DIR/normal-x86-64.tar.xz"; then
			echo "FAIL: $tc base unpack failed!"
			failed_count=$((failed_count + 1))
			continue
		fi
		mv "$SCRIPT_DIR/normal-x86-64" "$SCRIPT_DIR/$tc"

		echo "Unpacking diff $tc.tar.xz..."
		if ! tar -C "$SCRIPT_DIR" -xf "$TESTCASES_DIR/$tc.tar.xz"; then
			echo "FAIL: $tc diff unpack failed!"
			failed_count=$((failed_count + 1))
			continue
		fi

		if [ "$tc" = "sbat-latest-x86-64" ]; then
			rm -f "$SCRIPT_DIR/$tc/current-pcrs"
		fi
	fi

	# Run prediction
	echo "Executing pcr-oracle..."
	if ! $pcr_oracle --from eventlog --replay-testcase "tests/$tc" --stop-event grub-file=grub.cfg --after 0,2,4,7,9 > "$TMP_DIR/$tc-actual.txt"; then
		echo "FAIL: $tc pcr-oracle execution failed!"
		failed_count=$((failed_count + 1))
		continue
	fi

	# Compare with expected result
	echo "Comparing output with expected result..."
	if ! diff -u "$TESTCASES_DIR/$tc-result.txt" "$TMP_DIR/$tc-actual.txt"; then
		echo "FAIL: $tc replay test output did not match expected result!"
		failed_count=$((failed_count + 1))
	else
		echo "PASS: $tc replay test output matches expected result."
		passed_count=$((passed_count + 1))
	fi
done

echo "----------------------------------------"
echo "Replay test results:"
echo "  Passed: $passed_count"
echo "  Failed: $failed_count"

if [ "$failed_count" -gt 0 ]; then
	exit 1
fi
