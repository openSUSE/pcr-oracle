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
	$pcr_oracle --target-platform oldgrub -d "$@"
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

call_oracle \
	--input secret \
	--output sealed \
	--from current \
	seal-secret $PCR_MASK

echo "attempt to unseal the secret"
call_oracle \
	--input sealed \
	--output recovered \
	unseal-secret $PCR_MASK

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

echo "Extend PCR 12. Unsealing should fail afterwards"
tpm2_pcrextend 12:sha256=21d2013e3081f1e455fdd5ba6230a8620c3cfc9a9c31981d857fe3891f79449e
rm -f recovered
call_oracle \
	--input sealed \
	--output recovered \
	unseal-secret $PCR_MASK || true

if [ -s recovered ] && ! cmp secret recovered; then
	echo "BAD: We were still able to recover the original secret. Something stinks"
	exit 1
else
	echo "GOOD: After changing a PCR, the secret can no longer be unsealed"
fi
