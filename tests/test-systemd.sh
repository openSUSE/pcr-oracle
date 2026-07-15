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
	$pcr_oracle --target-platform systemd -d "$@"
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

POLICY_FILE=authorized.policy
SIGNED_POLICY_FILE=systemd-policy.json
rm -f sealed recovered

call_oracle \
	--rsa-generate-key \
	--private-key policy-key.pem \
	--auth $POLICY_FILE \
	create-authorized-policy $PCR_MASK

call_oracle \
	--private-key policy-key.pem \
	--public-key policy-pubkey \
	store-public-key

call_oracle \
	--auth $POLICY_FILE \
	--input secret \
	--output sealed \
	seal-secret

for attempt in first second; do
	echo "Sign the set of PCRs we want to authorize"
	call_oracle \
		--policy-name "authorized-policy-test" \
		--private-key policy-key.pem \
		--from current \
		--output $SIGNED_POLICY_FILE \
		sign $PCR_MASK

	echo "*** Contents of $SIGNED_POLICY_FILE"
	cat $SIGNED_POLICY_FILE
	echo

	echo "*** Terminating test early; the systemd code does not support unsealing yet" >&2
	break;
done
