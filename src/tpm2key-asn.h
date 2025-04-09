/*
 *Copyright (C) 2016 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Note: The ASN.1 defines constitute an interface specification for
 * the openssl key format which may be copied by other implementations
 * as fair use regardless of licence
 */
#ifndef _TPM2KEY_ASN_H
#define _TPM2KEY_ASN_H

#include <openssl/asn1t.h>
#include <openssl/pem.h>

/*
 * Define the format of policy commands required for TPM enhanced authorization.
 *
 * TPMPolicy ::= SEQUENCE {
 *	CommandCode		[0] EXPLICIT INTEGER
 *	CommandPolicy		[1] EXPLICIT OCTET STRING
 * }
 */
typedef struct {
	ASN1_INTEGER *CommandCode;
	ASN1_OCTET_STRING *CommandPolicy;
} TSSOPTPOLICY;

DEFINE_STACK_OF(TSSOPTPOLICY);

/*
 * Define the format of optional authorization policy.  The policy for
 * the key must begin with a TPM2_PolicyAuthorize statement with a
 * nonce and pub key but empty signature.  Each element of the
 * AuthPolicy->Policy array must end with TPM2_PolicyAuthorize with
 * empty nonce and pubkey but polulated signature which is a hash of
 * nonce || this policy
 *
 * TPMAuthPolicy ::= {
 *      Name                  [0] EXPLICIT UTF8STRING OPTIONAL
 *      Policy                [1] EXPLICIT SEQUENCE OF TPMPolicy
 * }
 */
typedef struct {
	ASN1_STRING *name;
	STACK_OF(TSSOPTPOLICY) *policy;
} TSSAUTHPOLICY;

DEFINE_STACK_OF(TSSAUTHPOLICY);

/*
 * Define the format of a TPM key file.
 *
 * TPMKey ::= SEQUENCE {
 *	type		OBJECT IDENTIFIER
 *	emptyAuth	[0] EXPLICIT BOOLEAN OPTIONAL
 *	policy		[1] EXPLICIT SEQUENCE OF TPMPolicy OPTIONAL
 *	secret		[2] EXPLICIT OCTET STRING OPTIONAL
 *	authPolicy	[3] EXPLICIT SEQUENCE OF TPMAuthPolicy OPTIONAL
 *	description     [4] EXPLICIT UTF8String OPTIONAL
 *	rsaParent       [5] EXPLICIT BOOLEAN OPTIONAL
 *	parent		INTEGER
 *	pubkey		OCTET STRING
 *	privkey		OCTET STRING
 * }
 */

typedef struct {
	ASN1_OBJECT *type;
	ASN1_BOOLEAN emptyAuth;
	STACK_OF(TSSOPTPOLICY) *policy;
	ASN1_OCTET_STRING *secret;
	STACK_OF(TSSAUTHPOLICY) *authPolicy;
	ASN1_UTF8STRING description;
	ASN1_BOOLEAN rsaParent;
	ASN1_INTEGER *parent;
	ASN1_OCTET_STRING *pubkey;
	ASN1_OCTET_STRING *privkey;
} TSSPRIVKEY;

#define OID_sealedData			"2.23.133.10.1.5"

/* This is the PEM guard tag */
#define TSSPRIVKEY_PEM_STRING "TSS2 PRIVATE KEY"

DECLARE_ASN1_FUNCTIONS(TSSOPTPOLICY);
DECLARE_ASN1_FUNCTIONS(TSSAUTHPOLICY);
DECLARE_ASN1_FUNCTIONS(TSSPRIVKEY);
DECLARE_PEM_write_bio(TSSPRIVKEY, TSSPRIVKEY);
DECLARE_PEM_read_bio(TSSPRIVKEY, TSSPRIVKEY);

#endif
