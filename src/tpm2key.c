/*
 *   Copyright (C) 2023 SUSE LLC
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <tss2_mu.h>

#include "bufparser.h"
#include "tpm2key-asn.h"
#include "util.h"

bool
tpm2key_basekey(TSSPRIVKEY **tpm2key, const TPM2_HANDLE parent,
		const TPM2B_PUBLIC *sealed_pub,
		const TPM2B_PRIVATE *sealed_priv)
{
	TSSPRIVKEY *key;
	buffer_t *bp_pub;
	buffer_t *bp_priv;
	TPM2_RC rc;

	bp_pub = buffer_alloc_write(sizeof(*sealed_pub));
	bp_priv = buffer_alloc_write(sizeof(*sealed_priv));

	rc = Tss2_MU_TPM2B_PUBLIC_Marshal(sealed_pub, bp_pub->data, bp_pub->size,
					  &bp_pub->wpos);
	if (rc != TSS2_RC_SUCCESS)
		return false;

	rc = Tss2_MU_TPM2B_PRIVATE_Marshal(sealed_priv, bp_priv->data, bp_priv->size,
					   &bp_priv->wpos);
	if (rc != TSS2_RC_SUCCESS)
		return false;

	key = TSSPRIVKEY_new();
	if (key == NULL)
		return false;

	key->type = OBJ_txt2obj(OID_sealedData, 1);
	key->emptyAuth = 1;
	key->parent = ASN1_INTEGER_new();
	ASN1_INTEGER_set(key->parent, parent);

	key->pubkey = ASN1_OCTET_STRING_new();
	ASN1_STRING_set(key->pubkey, bp_pub->data, buffer_available(bp_pub));
	key->privkey = ASN1_OCTET_STRING_new();
	ASN1_STRING_set(key->privkey, bp_priv->data, buffer_available(bp_priv));

	*tpm2key = key;

	return true;
}

static bool
__policy_add_policypcr(STACK_OF(TSSOPTPOLICY) *policy_seq, const TPML_PCR_SELECTION *pcr_sel)
{
	TSSOPTPOLICY *policy;
	TPM2B_DIGEST pcr_digest = {.size = 0};
	buffer_t *bp;
	TPM2_RC rc;

	policy = TSSOPTPOLICY_new();
	if (policy == NULL)
		return false;

	bp = buffer_alloc_write(sizeof(pcr_digest) + sizeof(*pcr_sel));
	if (bp == NULL)
		return false;

	rc = Tss2_MU_TPM2B_DIGEST_Marshal(&pcr_digest, bp->data, sizeof(pcr_digest), &bp->wpos);
	if (rc != TSS2_RC_SUCCESS)
		return false;

	rc = Tss2_MU_TPML_PCR_SELECTION_Marshal(pcr_sel, bp->data, sizeof(*pcr_sel), &bp->wpos);
	if (rc != TSS2_RC_SUCCESS)
		return false;

	ASN1_INTEGER_set(policy->CommandCode, TPM2_CC_PolicyPCR);
	ASN1_STRING_set(policy->CommandPolicy, bp->data, buffer_available(bp));

	sk_TSSOPTPOLICY_push(policy_seq, policy);

	return true;
}

static bool
__policy_add_policyauthorize(STACK_OF(TSSOPTPOLICY) *policy_seq,
			     const TPM2B_PUBLIC *pub_key,
			     const TPMT_SIGNATURE *signature)
{
	TSSOPTPOLICY *policy;
	TPM2B_DIGEST policy_ref = {.size = 0};
	buffer_t *bp;
	TPM2_RC rc;

	policy = TSSOPTPOLICY_new();
	if (policy == NULL)
		return false;

	bp = buffer_alloc_write(sizeof(*pub_key) + sizeof(policy_ref) +
				sizeof(*signature));
	if (bp == NULL)
		return false;

	rc = Tss2_MU_TPM2B_PUBLIC_Marshal(pub_key, bp->data, bp->size, &bp->wpos);
	if (rc != TSS2_RC_SUCCESS)
		return false;

	rc = Tss2_MU_TPM2B_DIGEST_Marshal(&policy_ref, bp->data, bp->size, &bp->wpos);
	if (rc != TSS2_RC_SUCCESS)
		return false;

	rc = Tss2_MU_TPMT_SIGNATURE_Marshal(signature, bp->data, bp->size, &bp->wpos);
	if (rc != TSS2_RC_SUCCESS)
		return false;

	ASN1_INTEGER_set(policy->CommandCode, TPM2_CC_PolicyAuthorize);
	ASN1_STRING_set(policy->CommandPolicy, bp->data, buffer_available(bp));

	sk_TSSOPTPOLICY_push(policy_seq, policy);

	return true;
}

bool
tpm2key_add_policy_policypcr(TSSPRIVKEY *tpm2key, const TPML_PCR_SELECTION *pcr_sel)
{
	if (tpm2key->policy == NULL)
		tpm2key->policy = sk_TSSOPTPOLICY_new_null();
	return __policy_add_policypcr(tpm2key->policy, pcr_sel);
}

bool
tpm2key_add_authpolicy_policyauthorize(TSSPRIVKEY *tpm2key,
				       const char *name,
				       const TPML_PCR_SELECTION *pcr_sel,
				       const TPM2B_PUBLIC *pub_key,
				       const TPMT_SIGNATURE *signature,
				       bool append)
{
	TSSAUTHPOLICY *ap = NULL;

	ap = TSSAUTHPOLICY_new();
	if (ap == NULL)
		return false;

	ap->name = ASN1_UTF8STRING_new();
	ap->policy = sk_TSSOPTPOLICY_new_null();

	ASN1_STRING_set(ap->name, name, strlen (name));

	if (!__policy_add_policypcr(ap->policy, pcr_sel))
		goto cleanup;

	if (!__policy_add_policyauthorize(ap->policy, pub_key, signature))
		goto cleanup;

	if (tpm2key->authPolicy == NULL)
		tpm2key->authPolicy = sk_TSSAUTHPOLICY_new_null();

	/* Append the new authPolicy */
	if (append)
		sk_TSSAUTHPOLICY_push(tpm2key->authPolicy, ap);
	else
		sk_TSSAUTHPOLICY_unshift(tpm2key->authPolicy, ap);

	return true;

cleanup:
	if (ap)
		TSSAUTHPOLICY_free(ap);

	return false;
}

bool
tpm2key_read_file(const char *path, TSSPRIVKEY **tpm2key)
{
	TSSPRIVKEY *key = NULL;
	buffer_t *bp;
	const uint8_t *ptr;
	char oid[128];

	if (!(bp = buffer_read_file(path, 0)))
		return false;

	ptr = bp->data;
	d2i_TSSPRIVKEY(&key, &ptr, bp->size);
	if (key == NULL) {
		error("%s does not seem to contain a valid TPM 2.0 Key\n", path);
		return false;
	}

	buffer_free(bp);

	/* check the content of the key */
	if (OBJ_obj2txt(oid, sizeof(oid), key->type, 1) == 0) {
		error("failed to parse object type\n");
		goto error;
	}

	if (strcmp(OID_sealedData, oid) != 0) {
		error("%s is not a sealed key in TPM 2.0 Key Format\n");
		goto error;
	}

	if (key->emptyAuth != 1) {
		error("emptyAuth is not TRUE\n");
		goto error;
	}

	*tpm2key = key;

	return true;
error:
	TSSPRIVKEY_free(key);

	return false;
}

bool
tpm2key_write_file(const char *path, TSSPRIVKEY *tpm2key)
{
	buffer_t write_buf;
	unsigned char *der_buf = NULL;
	int der_size;
	bool ok = false;

	der_size = i2d_TSSPRIVKEY(tpm2key, &der_buf);
	if (der_size < 0) {
		error("Failed to encode the key\n");
		return false;
	}

	buffer_init_write(&write_buf, der_buf, der_size);
	write_buf.wpos = der_size;
	ok = buffer_write_file(path, &write_buf);

	free(der_buf);

	return ok;
}

/* Implement the TPM 2.0 Key File structures */
IMPLEMENT_ASN1_FUNCTIONS(TSSOPTPOLICY)
IMPLEMENT_ASN1_FUNCTIONS(TSSAUTHPOLICY)
IMPLEMENT_ASN1_FUNCTIONS(TSSPRIVKEY)
IMPLEMENT_PEM_write_bio(TSSPRIVKEY, TSSPRIVKEY, TSSPRIVKEY_PEM_STRING, TSSPRIVKEY)
IMPLEMENT_PEM_read_bio(TSSPRIVKEY, TSSPRIVKEY, TSSPRIVKEY_PEM_STRING, TSSPRIVKEY)

ASN1_SEQUENCE(TSSOPTPOLICY) = {
	ASN1_EXP(TSSOPTPOLICY, CommandCode, ASN1_INTEGER, 0),
	ASN1_EXP(TSSOPTPOLICY, CommandPolicy, ASN1_OCTET_STRING, 1)
} ASN1_SEQUENCE_END(TSSOPTPOLICY)

ASN1_SEQUENCE(TSSAUTHPOLICY) = {
	ASN1_EXP_OPT(TSSAUTHPOLICY, name, ASN1_UTF8STRING, 0),
	ASN1_EXP_SEQUENCE_OF(TSSAUTHPOLICY, policy, TSSOPTPOLICY, 1)
} ASN1_SEQUENCE_END(TSSAUTHPOLICY)

ASN1_SEQUENCE(TSSPRIVKEY) = {
	ASN1_SIMPLE(TSSPRIVKEY, type, ASN1_OBJECT),
	ASN1_EXP_OPT(TSSPRIVKEY, emptyAuth, ASN1_BOOLEAN, 0),
	ASN1_EXP_SEQUENCE_OF_OPT(TSSPRIVKEY, policy, TSSOPTPOLICY, 1),
	ASN1_EXP_OPT(TSSPRIVKEY, secret, ASN1_OCTET_STRING, 2),
	ASN1_EXP_SEQUENCE_OF_OPT(TSSPRIVKEY, authPolicy, TSSAUTHPOLICY, 3),
	ASN1_EXP_OPT(TSSPRIVKEY, description, ASN1_UTF8STRING, 4),
	ASN1_EXP_OPT(TSSPRIVKEY, rsaParent, ASN1_BOOLEAN, 5),
	ASN1_SIMPLE(TSSPRIVKEY, parent, ASN1_INTEGER),
	ASN1_SIMPLE(TSSPRIVKEY, pubkey, ASN1_OCTET_STRING),
	ASN1_SIMPLE(TSSPRIVKEY, privkey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(TSSPRIVKEY)
