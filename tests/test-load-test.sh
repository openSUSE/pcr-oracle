#!/bin/bash
#
# This script needs to be run with root privilege
#

# TESTDIR=policy.test
PCR_MASK=0,2,4,12

pcr_oracle=pcr-oracle
if [ -x "$(dirname "$0")/../pcr-oracle" ]; then
	pcr_oracle=$(cd "$(dirname "$0")/.." && pwd)/pcr-oracle
elif [ -x pcr-oracle ]; then
	pcr_oracle=$PWD/pcr-oracle
fi

function call_oracle {

	echo "****************"
	echo "pcr-oracle $*"
	$pcr_oracle -d "$@"
}

# Run load-test and check the SRK it reports. The expected algorithm is
# given as the first argument, the remaining ones are passed to pcr-oracle.
function expect_srk {

	local expected="$1"
	local reported

	shift

	echo "****************"
	echo "pcr-oracle $* load-test (expecting $expected)"
	reported=$($pcr_oracle "$@" load-test)

	if [ "$reported" != "$expected" ]; then
		echo "BAD: load-test reported \"$reported\" instead of \"$expected\""
		exit 1
	fi

	echo "NICE: load-test reported $reported"
}

# Run load-test with a candidate we know to be wrong; it has to fail.
function expect_no_srk {

	echo "****************"
	echo "pcr-oracle $* load-test (expecting a failure)"
	if $pcr_oracle "$@" load-test; then
		echo "BAD: load-test accepted an SRK the key was not sealed with"
		exit 1
	fi

	echo "GOOD: load-test rejected the wrong SRK"
}

if [ -z "$TESTDIR" ]; then
	tmpdir=$(mktemp -d /tmp/pcrtestXXXXXX)
	trap "cd / && rm -rf $tmpdir" 0 1 2 10 11 15

	TESTDIR=$tmpdir
fi

trap "echo 'FAIL: command exited with error'; exit 1" ERR

echo "This is super secret" >$TESTDIR/secret

set -e
cd $TESTDIR

echo "=== A key sealed with an ECC SRK is reported as ECC"
call_oracle \
	--target-platform tpm2.0 \
	--from current \
	--input secret \
	--output sealed-ecc \
	--ecc-srk \
	seal-secret $PCR_MASK

expect_srk ECC --input sealed-ecc

echo "=== A key sealed with an RSA SRK is reported with its key size"
call_oracle \
	--target-platform tpm2.0 \
	--from current \
	--input secret \
	--output sealed-rsa \
	seal-secret $PCR_MASK

expect_srk RSA2048 --input sealed-rsa

echo "=== The oldgrub format has no rsaParent, the SRK is found anyway"
call_oracle \
	--target-platform oldgrub \
	--from current \
	--input secret \
	--output sealed-oldgrub \
	seal-secret $PCR_MASK

expect_srk RSA2048 --input sealed-oldgrub

echo "=== Restricting the test to the wrong candidate fails"
expect_no_srk --input sealed-rsa --ecc-srk
expect_no_srk --input sealed-ecc --rsa-bits 2048

echo "=== Restricting the test to the right candidate succeeds"
expect_srk ECC --input sealed-ecc --ecc-srk
expect_srk RSA2048 --input sealed-rsa --rsa-bits 2048

echo "=== Signing a policy does not change the SRK of the key"
call_oracle \
	--rsa-generate-key \
	--private-key policy-key.pem \
	--auth authorized.policy \
	create-authorized-policy $PCR_MASK

call_oracle \
	--target-platform tpm2.0 \
	--auth authorized.policy \
	--input secret \
	--output sealed-auth \
	--ecc-srk \
	seal-secret

call_oracle \
	--target-platform tpm2.0 \
	--policy-name "authorized-policy-test" \
	--private-key policy-key.pem \
	--from current \
	--input sealed-auth \
	--output sealed-auth-signed \
	sign $PCR_MASK

expect_srk ECC --input sealed-auth-signed

echo "=== A key sealed with a larger RSA SRK is reported with its key size"
if $pcr_oracle --rsa-bits 3072 rsa-test; then
	call_oracle \
		--target-platform tpm2.0 \
		--from current \
		--input secret \
		--output sealed-rsa3072 \
		--rsa-bits 3072 \
		seal-secret $PCR_MASK

	expect_srk RSA3072 --input sealed-rsa3072
else
	echo "SKIP: this TPM does not support RSA 3072"
fi

echo "=== A key stored in an NV index is handled too"
nvindex=0x01800002
tpm2_nvundefine -C o $nvindex 2>/dev/null || true
call_oracle \
	--target-platform tpm2.0 \
	--from current \
	--input secret \
	--nvindex $nvindex \
	--ecc-srk \
	seal-secret $PCR_MASK

expect_srk ECC --nvindex $nvindex

tpm2_nvundefine -C o $nvindex 2>/dev/null || true

echo "NICE: all load-test checks passed"
