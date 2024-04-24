#!/bin/bash
#
# This script needs to be run with root privilege
#

# TESTDIR=policy.test
PCR_MASK=0,2,4,12

pcr_oracle=pcr-oracle
if [ -x pcr-oracle ]; then
	pcr_oracle=$PWD/pcr-oracle
fi

function call_oracle {

	echo "****************"
	echo "pcr-oracle $*"
	$pcr_oracle --target-platform tpm2.0 -d "$@"
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

echo "Seal the secret with PCR policy"
call_oracle \
	--from current \
	--input secret \
	--output sealed \
	--ecc-srk \
	seal-secret $PCR_MASK

echo "Unseal the sealed with PCR policy"
call_oracle \
	--input sealed \
	--output recovered \
	unseal-secret

if ! cmp secret recovered; then
	echo "BAD: Unable to recover original secret"
	echo "Secret:"
	od -tx1c secret
	echo "Recovered:"
	od -tx1c recovered
	exit 1
else
	echo "NICE: we were able to recover the original secret"
fi

rm -f sealed recovered

call_oracle \
	--rsa-generate-key \
	--private-key policy-key.pem \
	--auth authorized.policy \
	create-authorized-policy $PCR_MASK

call_oracle \
	--private-key policy-key.pem \
	--public-key policy-pubkey \
	store-public-key

call_oracle \
	--auth authorized.policy \
	--input secret \
	--output sealed \
	--ecc-srk \
	seal-secret

for attempt in first second; do
	echo "Sign the set of PCRs we want to authorize"
	call_oracle \
		--policy-name "authorized-policy-test" \
		--private-key policy-key.pem \
		--from current \
		--input sealed \
		--output sealed-signed \
		sign $PCR_MASK

	echo "$attempt attempt to unseal the secret"
	call_oracle \
		--input sealed-signed \
		--output recovered \
		unseal-secret

	if ! cmp secret recovered; then
		echo "BAD: Unable to recover original secret"
		echo "Secret:"
		od -tx1c secret
		echo "Recovered:"
		od -tx1c recovered
		exit 1
	else
		echo "NICE: we were able to recover the original secret"
	fi

	if [ "$attempt" = "second" ]; then
		break
	fi

	echo "Extend PCR 12. Unsealing should fail afterwards"
	tpm2_pcrextend 12:sha256=21d2013e3081f1e455fdd5ba6230a8620c3cfc9a9c31981d857fe3891f79449e
	rm -f recovered
	call_oracle \
		--input sealed-signed \
		--output recovered \
		unseal-secret || true

	if [ -s recovered ] && ! cmp secret recovered; then
		echo "BAD: We were still able to recover the original secret. Something stinks"
		exit 1
	else
		echo "GOOD: After changing a PCR, the secret can no longer be unsealed"
	fi

	echo "Now recreate the signed PCR policy"
done
