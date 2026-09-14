/*
 *   Copyright (C) 2026 SUSE LLC
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <strings.h>
#include <getopt.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <tss2_mu.h>
#include "tpm2key.h"
#include "tpm2key-asn.h"
#include "util.h"

unsigned int opt_debug = 0;

static void
usage(int exitval, const char *msg)
{
	if (msg)
		fputs(msg, stderr);

	fprintf(stderr,
		"\nUsage:\n"
		"tpm2key-tool [-d|--debug] parse <key-file>\n"
		"tpm2key-tool [-d|--debug] cmp <key-file-1> <key-file-2>\n"
		"\n"
		"The following options are recognized:\n"
		"  -d, --debug            Enable debug logging\n"
		"  -h, --help             Display this help message\n"
		"\n"
		"Exit status:\n"
		"  0  success, and for 'cmp' both keys share the same base key\n"
		"  1  'cmp' only: the keys are not derived from the same base key\n"
		"  2  trouble: invalid usage, or a key file cannot be read or parsed\n"
	       );
	exit(exitval);
}

/* Compute and print SHA-256 hash of a buffer */
static void
print_sha256(const uint8_t *data, size_t len)
{
	uint8_t md[32];
	uint32_t md_len = 0;
	uint32_t i;

	if (!data || len == 0) {
		printf("unknown (no data)\n");
		return;
	}

	if (EVP_Digest(data, len, md, &md_len, EVP_sha256(), NULL)) {
		for (i = 0; i < md_len; i++) {
			printf("%02x", md[i]);
		}
		printf("\n");
	} else {
		printf("unknown (hash failed)\n");
	}
}

/* Print wrapper for the library's native hexdump function */
static void
print_wrap(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

/* Helper to print a stack of TPM policy steps with custom prefix/indents */
static void
print_policy_steps(const STACK_OF(TSSOPTPOLICY) *policy, bool show_steps, const char *indent)
{
	int op_count = sk_TSSOPTPOLICY_num(policy);
	long code;
	int j;

	for (j = 0; j < op_count; j++) {
		TSSOPTPOLICY *op = sk_TSSOPTPOLICY_value(policy, j);
		code = ASN1_INTEGER_get(op->CommandCode);

		if (show_steps) {
			printf("%s - Step %d:\n", indent, j + 1);
			printf("%s   Command:      0x%08x\n", indent, (uint32_t)code);
		} else {
			printf("%s  * Command:  0x%08x\n", indent, (uint32_t)code);
		}

		if (op->CommandPolicy == NULL)
			continue;

		if (show_steps) {
			printf("%s   Policy Data Size: %d bytes\n",
			       indent, op->CommandPolicy->length);
		} else {
			printf("%s    Policy Data Size: %d bytes\n",
			       indent, op->CommandPolicy->length);
		}

		if (opt_debug) {
			hexdump(op->CommandPolicy->data, op->CommandPolicy->length,
				print_wrap, 4);
		}
	}
}

/* Print details of the Standard Policy attached to the key */
static void
print_policy(const TSSPRIVKEY *tpm2key)
{
	if (tpm2key->policy == NULL) {
		printf("Policy:           None\n");
		return;
	}

	printf("Policy:           %d steps found\n", sk_TSSOPTPOLICY_num(tpm2key->policy));
	print_policy_steps(tpm2key->policy, true, " ");
}

/* Print details of the Auth Policies attached to the key */
static void
print_auth_policies(const TSSPRIVKEY *tpm2key)
{
	int ap_count;
	int i;

	if (tpm2key->authPolicy == NULL) {
		printf("Auth Policies:    None\n");
		return;
	}

	ap_count = sk_TSSAUTHPOLICY_num(tpm2key->authPolicy);
	printf("Auth Policies:    %d found\n", ap_count);
	for (i = 0; i < ap_count; i++) {
		TSSAUTHPOLICY *ap = sk_TSSAUTHPOLICY_value(tpm2key->authPolicy, i);
		printf("  - Policy %d:\n", i + 1);

		if (ap->name && ap->name->length > 0)
			printf("    Name:         %.*s\n", ap->name->length, ap->name->data);

		if (ap->policy == NULL)
			continue;

		printf("    Steps (%d):\n", sk_TSSOPTPOLICY_num(ap->policy));
		print_policy_steps(ap->policy, false, "    ");
	}
}

static int
do_parse(const char *path)
{
	TSSPRIVKEY *tpm2key = NULL;
	char oid_str[128] = {0};
	long parent_val;

	/* tpm2key_read_file() already reported the reason */
	if (!tpm2key_read_file(path, &tpm2key))
		return 2;

	if (OBJ_obj2txt(oid_str, sizeof(oid_str), tpm2key->type, 1) > 0) {
		printf("Object Type OID:  %s\n", oid_str);
	}
	printf("EmptyAuth:        %s\n", tpm2key->emptyAuth == 1 ? "TRUE" : "FALSE");
	printf("RSAParent:        %s\n", tpm2key->rsaParent == 1 ? "TRUE" : "FALSE");

	parent_val = ASN1_INTEGER_get(tpm2key->parent);
	printf("Parent Handle:    0x%08x\n", (uint32_t)parent_val);

	if (tpm2key->description && tpm2key->description->length > 0) {
		printf("Description:      %.*s\n", tpm2key->description->length, tpm2key->description->data);
	}

	if (tpm2key->pubkey) {
		printf("Pubkey Size:      %d bytes\n", tpm2key->pubkey->length);
		printf("Pubkey SHA-256:   ");
		print_sha256(tpm2key->pubkey->data, tpm2key->pubkey->length);
		if (opt_debug) {
			printf("Pubkey Hex Dump:\n");
			hexdump(tpm2key->pubkey->data, tpm2key->pubkey->length, print_wrap, 2);
			printf("\n");
		}
	}
	if (tpm2key->privkey) {
		printf("Privkey Size:     %d bytes\n", tpm2key->privkey->length);
		printf("Privkey SHA-256:  ");
		print_sha256(tpm2key->privkey->data, tpm2key->privkey->length);
		if (opt_debug) {
			printf("Privkey Hex Dump:\n");
			hexdump(tpm2key->privkey->data, tpm2key->privkey->length, print_wrap, 2);
			printf("\n");
		}
	}

	print_policy(tpm2key);

	print_auth_policies(tpm2key);

	TSSPRIVKEY_free(tpm2key);
	return 0;
}

static int
do_cmp(const char *path1, const char *path2)
{
	TSSPRIVKEY *key1 = NULL;
	TSSPRIVKEY *key2 = NULL;
	bool matched = true;

	/* tpm2key_read_file() already reported the reason */
	if (!tpm2key_read_file(path1, &key1))
		return 2;

	if (!tpm2key_read_file(path2, &key2)) {
		TSSPRIVKEY_free(key1);
		return 2;
	}

	if (!key1->type || !key2->type) {
		printf("Difference: Object Type OID is missing in one or both keys.\n");
		matched = false;
	} else if (OBJ_cmp(key1->type, key2->type) != 0) {
		printf("Difference: Object Types do not match.\n");
		matched = false;
	}

	if (!key1->parent || !key2->parent) {
		printf("Difference: Parent handle is missing in one or both keys.\n");
		matched = false;
	} else if (ASN1_INTEGER_cmp(key1->parent, key2->parent) != 0) {
		printf("Difference: Parent handles do not match.\n");
		matched = false;
	}

	if (!key1->pubkey || !key2->pubkey) {
		printf("Difference: Public key components (pubkey) are missing in one or both keys.\n");
		matched = false;
	} else if (key1->pubkey->length != key2->pubkey->length ||
		memcmp(key1->pubkey->data, key2->pubkey->data, key1->pubkey->length) != 0) {
		printf("Difference: Public key components (pubkey) do not match.\n");
		printf(" - File 1 Pubkey SHA-256: ");
		print_sha256(key1->pubkey->data, key1->pubkey->length);
		printf(" - File 2 Pubkey SHA-256: ");
		print_sha256(key2->pubkey->data, key2->pubkey->length);
		matched = false;
	}

	if (!key1->privkey || !key2->privkey) {
		printf("Difference: Private key components (privkey) are missing in one or both keys.\n");
		matched = false;
	} else if (key1->privkey->length != key2->privkey->length ||
		memcmp(key1->privkey->data, key2->privkey->data, key1->privkey->length) != 0) {
		printf("Difference: Private key components (privkey) do not match.\n");
		printf(" - File 1 Privkey SHA-256: ");
		print_sha256(key1->privkey->data, key1->privkey->length);
		printf(" - File 2 Privkey SHA-256: ");
		print_sha256(key2->privkey->data, key2->privkey->length);
		matched = false;
	}

	TSSPRIVKEY_free(key1);
	TSSPRIVKEY_free(key2);

	if (matched) {
		printf("SUCCESS: Both files share the exact same underlying TPM 2.0 sealed secret.\n");
		return 0;
	} else {
		printf("FAIL: The TPM 2.0 keys are not derived from the same base key.\n");
		return 1;
	}
}

static const struct option long_options[] = {
	{"debug", no_argument, NULL, 'd'},
	{"help",  no_argument, NULL, 'h'},
	{NULL,    0,           NULL, 0}
};

int
main(int argc, char **argv)
{
	int args_count;
	const char *action;
	int c;

	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, "dh", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'd':
			opt_debug = 1;
			break;
		case 'h':
			usage(0, NULL);
			break;
		case '?':
			/* getopt_long already prints the error message */
			usage(2, NULL);
			break;
		default:
			usage(2, NULL);
		}
	}

	args_count = argc - optind;
	if (args_count == 0) {
		usage(2, NULL);
	}

	action = argv[optind];

	if (strcmp(action, "parse") == 0) {
		if (args_count < 2)
			usage(2, "Error: 'parse' requires a file path.\n");
		return do_parse(argv[optind + 1]);
	} else if (strcmp(action, "cmp") == 0) {
		if (args_count < 3)
			usage(2, "Error: 'cmp' requires two file paths.\n");
		return do_cmp(argv[optind + 1], argv[optind + 2]);
	} else {
		char err_msg[256];
		snprintf(err_msg, sizeof(err_msg), "Error: Unknown action '%s'\n", action);
		usage(2, err_msg);
	}

	return 0;
}
