#!/bin/bash
#
# Test for TPM NV Index seal and unseal
#

PCR_MASK=0,2,4,12
NV_INDEX=0x01800001

pcr_oracle=pcr-oracle
if [ -x "$(dirname "$0")/../pcr-oracle" ]; then
	pcr_oracle=$(cd "$(dirname "$0")/.." && pwd)/pcr-oracle
elif [ -x pcr-oracle ]; then
	pcr_oracle=$PWD/pcr-oracle
fi

function call_oracle {
	echo "****************"
	echo "pcr-oracle $*"
	$pcr_oracle "$@"
}

if [ -z "$TESTDIR" ]; then
	tmpdir=$(mktemp -d /tmp/pcrtestXXXXXX)
	trap "cd / && rm -rf ${tmpdir}" 0 1 2 10 11 15

	TESTDIR=${tmpdir}
fi

trap "echo 'FAIL: command exited with error'; exit 1" ERR

echo "This is super secret for NVindex test" >$TESTDIR/secret

set -e
cd $TESTDIR

# Cleanup any existing NV index to ensure a clean state
echo "Pre-test cleanup of NV index $NV_INDEX if defined"
tpm2_nvundefine -C o $NV_INDEX 2>/dev/null || true

# Test: TPM2.0 key format to NV index
echo "=== Test: Sealing & Unsealing with tpm2.0 target platform ==="
call_oracle \
	--target-platform tpm2.0 \
	--nvindex $NV_INDEX \
	--from current \
	--input secret \
	seal-secret $PCR_MASK

echo "Unsealing directly from NV index $NV_INDEX using --nvindex..."
call_oracle \
	--target-platform tpm2.0 \
	--nvindex $NV_INDEX \
	--output unsealed_tpm2key \
	unseal-secret

echo "Comparing unsealed content with original secret..."
if ! cmp secret unsealed_tpm2key; then
	echo "BAD: Unsealed secret did not match original input secret under tpm2.0 platform"
	exit 1
else
	echo "NICE: Unsealed secret matched original exactly under tpm2.0 platform!"
fi

# Cleanup NV Index for the next test
tpm2_nvundefine -C o $NV_INDEX 2>/dev/null || true

# Test: Sealing & Unsealing with Authorized Policy & --nvindex
echo "=== Test: Sealing & Unsealing with Authorized Policy & --nvindex ==="
echo "Generating authorized policy..."
call_oracle \
	--target-platform tpm2.0 \
	--rsa-generate-key \
	--private-key policy-key.pem \
	--auth authorized.policy \
	create-authorized-policy $PCR_MASK

call_oracle \
	--target-platform tpm2.0 \
	--private-key policy-key.pem \
	--public-key policy-pubkey \
	store-public-key

echo "Sealing secret with authorized policy to disk..."
call_oracle \
	--target-platform tpm2.0 \
	--auth authorized.policy \
	--input secret \
	--output sealed-auth.tpm \
	seal-secret

echo "Signing the policy and writing directly to NV index $NV_INDEX..."
call_oracle \
	--target-platform tpm2.0 \
	--policy-name "authorized-policy-nvindex-test" \
	--private-key policy-key.pem \
	--from current \
	--input sealed-auth.tpm \
	--nvindex $NV_INDEX \
	sign $PCR_MASK

echo "Unsealing directly from NV index $NV_INDEX using --nvindex..."
call_oracle \
	--target-platform tpm2.0 \
	--nvindex $NV_INDEX \
	--output unsealed_auth \
	unseal-secret

echo "Comparing unsealed content with original secret..."
if ! cmp secret unsealed_auth; then
	echo "BAD: Unsealed secret did not match original input secret under authorized policy with NV index"
	exit 1
else
	echo "NICE: Unsealed secret matched original exactly under authorized policy with NV index!"
fi

# Post-test cleanup of NV index and files
echo "Post-test cleanup of NV index and files"
rm -f policy-key.pem policy-pubkey authorized.policy sealed-auth.tpm unsealed_auth unsealed_tpm2key secret
tpm2_nvundefine -C o $NV_INDEX 2>/dev/null || true

echo "ALL TESTS PASSED SUCCESSFULLY!"
exit 0
