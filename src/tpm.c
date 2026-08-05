/*
 *   Copyright (C) 2022, 2023 SUSE LLC
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
 *
 * Written by Olaf Kirch <okir@suse.com>
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <ctype.h>

#include <tss2_esys.h>
#include <tss2_sys.h>
#include <tss2_tctildr.h>
#include <tss2_rc.h>
#include <tss2_mu.h>

#include "oracle.h"
#include "tpm.h"
#include "bufparser.h"
#include "util.h"
#include "config.h"

uint32_t	esys_tr_rh_null = ~0;
uint32_t	esys_tr_rh_owner = ~0;

void
tss_print_error(int rc, const char *msg)
{
	const char *tss_msg;

	if (rc == TSS2_RC_SUCCESS)
		return;

	tss_msg = Tss2_RC_Decode(rc);
	if (tss_msg == NULL)
		tss_msg = "Unknown error code";

	if (msg)
		error("%s: %s\n", msg, tss_msg);
	else
		error("tss2 function returned an error: %s\n", tss_msg);
}


ESYS_CONTEXT *
tss_esys_context(void)
{
	static ESYS_CONTEXT  *esys_ctx;

	if (esys_ctx == NULL) {
		TSS2_RC rc;
		TSS2_RC rc_tcti;
		char *tcti_env = NULL;
		TSS2_TCTI_CONTEXT *tcti = NULL;

		tcti_env = getenv("PCRORACLE_TCTI");
		if (tcti_env != NULL) {
			infomsg("Using TCTI env: %s\n", tcti_env);
			rc_tcti = Tss2_TctiLdr_Initialize(tcti_env, &tcti);
			if (!tss_check_error(rc_tcti, "Failed to initialize TCTI context"))
				tcti = NULL;
		}

		rc = Esys_Initialize(&esys_ctx, tcti, NULL);
		if (!tss_check_error(rc, "Unable to initialize TSS2 ESAPI context"))
			fatal("Aborting.\n");

		/* There's no way to query the library version programmatically, so
		 * we need to check it in configure. */
		if (version_string_compare(LIBTSS2_VERSION, "3.1") > 0) {
			/* debug("Detected tss2-esys library version %s, using new ESYS_TR_RH_* constants\n", LIBTSS2_VERSION); */
			esys_tr_rh_null = ESYS_TR_RH_NULL;
			esys_tr_rh_owner = ESYS_TR_RH_OWNER;
		} else {
			debug("Detected tss2-esys library version %s, using old TPM2_RH_* constants\n", LIBTSS2_VERSION);
			esys_tr_rh_null = TPM2_RH_NULL;
			esys_tr_rh_owner = TPM2_RH_OWNER;
		}
	}
	return esys_ctx;
}

static bool
tpm_get_tpm_property(TPM2_PT property, uint32_t *value)
{
	ESYS_CONTEXT *esys_ctx = tss_esys_context();
	TPMS_CAPABILITY_DATA *cap_data = NULL;
	TPMI_YES_NO more_data;
	TPML_TAGGED_TPM_PROPERTY *props = NULL;
	TSS2_RC rc;
	bool okay = false;

	if (value == NULL)
		return false;

	rc = Esys_GetCapability(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
			ESYS_TR_NONE, TPM2_CAP_TPM_PROPERTIES, property,
			1, &more_data, &cap_data);
	if (rc != TSS2_RC_SUCCESS)
		return tss_check_error(rc, "Esys_GetCapability (TPM_PROPERTIES) failed");

	if (cap_data == NULL) {
		error("Empty CAP data (TPM_PROPERTIES)\n");
		return false;
	}

	if (cap_data->capability != TPM2_CAP_TPM_PROPERTIES) {
		error("Wrong CAP data (TPM_PROPERTIES)\n");
		goto out;
	}

	props = &cap_data->data.tpmProperties;
	if (props->count != 1) {
		error("Got more than 1 property\n");
		goto out;
	}

	if (props->tpmProperty[0].property != property) {
		error("Property not match\n");
		goto out;
	}

	*value = props->tpmProperty[0].value;

	okay = true;
out:
	if (cap_data)
		free(cap_data);

	return okay;
}

#ifdef TPM2_CAP_AUTH_POLICIES
static bool
tpm_get_auth_policies(TPM2_HANDLE hierarchy, TPMS_CAPABILITY_DATA **cap_data)
{
	ESYS_CONTEXT *esys_ctx = tss_esys_context();
	TPMI_YES_NO more_data;
	TSS2_RC rc;

	rc = Esys_GetCapability(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
			ESYS_TR_NONE, TPM2_CAP_AUTH_POLICIES, hierarchy,
			TPM2_MAX_TAGGED_POLICIES, &more_data, cap_data);
	if (rc != TSS2_RC_SUCCESS)
		return tss_check_error(rc, "Esys_GetCapability (AUTH_POLICIES) failed");

	if (*cap_data == NULL) {
		error("Empty CAP data (AUTH_POLICIES)\n");
		return false;
	}

	if ((*cap_data)->capability != TPM2_CAP_AUTH_POLICIES) {
		error("Wrong CAP data (AUTH_POLICIES)\n");
		return false;
	}

	return true;
}

static bool
tpm_check_auth_policies(TPM2_HANDLE hierarchy)
{
	TPMS_CAPABILITY_DATA *cap_data = NULL;
	TPML_TAGGED_POLICY *policies = NULL;
	uint32_t i;
	bool okay = false;

	if (!tpm_get_auth_policies(hierarchy, &cap_data))
		goto out;

	policies = &cap_data->data.authPolicies;
	for (i = 0; i < policies->count; i++) {
		if (policies->policies[i].policyHash.hashAlg != TPM2_ALG_NULL) {
			error("Tagged policy NON-NULL Hash Algorithm\n");
			goto out;
		}
	}

	okay = true;
out:
	if (cap_data)
		free(cap_data);

	return okay;
}
#endif

static bool
tpm_check_capabilities(void)
{
	uint32_t prop_startup, prop_permanent;

	/* Check PropertyStartupClear (TPM2_PT_STARTUP_CLEAR) */
	if (!tpm_get_tpm_property(TPM2_PT_STARTUP_CLEAR, &prop_startup)) {
		error("Failed to get PropertyStartupClear\n");
		return false;
	}

	if ((prop_startup & TPMA_STARTUP_CLEAR_SHENABLE) == 0) {
		error("Storage hierarchy not enabled\n");
		return false;
	}

	/* Check PropertyPermanent (TPM2_PT_PERMANENT) */
	if (!tpm_get_tpm_property(TPM2_PT_PERMANENT, &prop_permanent)) {
		error("Failed to get PropertyPermanent\n");
		return false;
	}

	if ((prop_permanent & TPMA_PERMANENT_OWNERAUTHSET) != 0) {
		error("TPM2 Owner Authorization set\n");
		return false;
	}

#ifdef TPM2_CAP_AUTH_POLICIES
	/*
	 * Ensure that there is no authorization policy associated with the
	 * TPM2_RH_OWNER hierarchy.
	 */
	if (!tpm_check_auth_policies(TPM2_RH_OWNER)) {
		error("Error from Owner handle\n");
		return false;
	}
#endif

	return true;
}

static bool
tpm_check_srk(void)
{
	ESYS_CONTEXT *esys_ctx = tss_esys_context();
	TPMT_PUBLIC_PARMS parms = {0};
	TSS2_RC rc;

	/* Test RSA SRK */
	parms.type = TPM2_ALG_RSA;
	memcpy(&parms.parameters, &RSA_SRK_template.publicArea.parameters,
	       sizeof(TPMU_PUBLIC_PARMS));

	rc = Esys_TestParms(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &parms);
	if (rc != TSS2_RC_SUCCESS)
		return tss_check_error(rc, "RSA SRK test failed");

	memset(&parms, 0, sizeof(TPMT_PUBLIC_PARMS));

	/* Test ECC SRK */
	parms.type = TPM2_ALG_ECC;
	memcpy(&parms.parameters, &ECC_SRK_template.publicArea.parameters,
	       sizeof(TPMU_PUBLIC_PARMS));

	rc = Esys_TestParms(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &parms);
	if (rc != TSS2_RC_SUCCESS)
		return tss_check_error(rc, "ECC SRK test failed");

	return true;
}

bool
tpm_selftest(bool fulltest)
{
	ESYS_CONTEXT *esys_ctx = tss_esys_context();
	TSS2_RC rc;

	/* TPM self test */
	rc = Esys_SelfTest(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, fulltest);
	if (rc != TSS2_RC_SUCCESS)
		return tss_check_error(rc, "TPM self test failed");

	/* Capability check */
	if(!tpm_check_capabilities())
		return false;

	/* SRK template test */
	if (!tpm_check_srk())
		return false;

	return true;
}

bool
tpm_rsa_bits_test(unsigned int rsa_bits)
{
	ESYS_CONTEXT *esys_ctx = tss_esys_context();
	TPMT_PUBLIC_PARMS rsa_parms = {
		.type = TPM2_ALG_RSA,
		.parameters = {
			.rsaDetail = {
				.symmetric = { TPM2_ALG_NULL },
				.scheme = { TPM2_ALG_NULL },
				.keyBits = rsa_bits
			}
		}
	};
	TSS2_RC rc;
	bool okay = false;

	/* Suppress the messages from tpm2-tss */
	setenv("TSS2_LOG", "all+NONE", 1);

	rc = Esys_TestParms(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
			ESYS_TR_NONE, &rsa_parms);
	if (rc == TSS2_RC_SUCCESS)
		okay = true;
	else if (rc != (TPM2_RC_VALUE | TPM2_RC_P | TPM2_RC_1))
		tss_check_error(rc, "Esys_TestParms failed");

	return okay;
}

bool
tpm_ecc_test(void)
{
	ESYS_CONTEXT *esys_ctx = tss_esys_context();
	TPMT_PUBLIC_PARMS parms = {0};
	TSS2_RC rc;
	bool okay = false;

	/* Suppress the messages from tpm2-tss */
	setenv("TSS2_LOG", "all+NONE", 1);

	parms.type = TPM2_ALG_ECC;
	memcpy(&parms.parameters, &ECC_SRK_template.publicArea.parameters,
	       sizeof(TPMU_PUBLIC_PARMS));

	rc = Esys_TestParms(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
			ESYS_TR_NONE, &parms);
	if (rc == TSS2_RC_SUCCESS)
		okay = true;
	else if (rc != (TPM2_RC_VALUE | TPM2_RC_P | TPM2_RC_1))
		tss_check_error(rc, "Esys_TestParms failed");

	return okay;
}

static bool
tpm_nvindex_exists(uint32_t nv_index)
{
	ESYS_CONTEXT *esys_ctx = tss_esys_context();
	TPMS_CAPABILITY_DATA *cap_data = NULL;
	TPMI_YES_NO more_data;
	TSS2_RC rc;
	bool exists = false;

	rc = Esys_GetCapability(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
	                        TPM2_CAP_HANDLES, nv_index, 1, &more_data, &cap_data);
	if (rc == TSS2_RC_SUCCESS && cap_data != NULL) {
		if (cap_data->capability == TPM2_CAP_HANDLES &&
		    cap_data->data.handles.count > 0 &&
		    cap_data->data.handles.handle[0] == nv_index) {
			exists = true;
		}
	}

	if (cap_data)
		free(cap_data);

	return exists;
}

bool
tpm_nvindex_write(uint32_t nv_index, const buffer_t *bp)
{
	ESYS_CONTEXT *esys_ctx = tss_esys_context();
	ESYS_TR nv_tr = ESYS_TR_NONE;
	TSS2_RC rc;
	TPM2B_AUTH auth_value = { .size = 0 };
	TPM2B_MAX_NV_BUFFER nv_buffer;
	const void *data;
	size_t size;
	bool ok = false;

	if (!bp) {
		error("tpm_nvindex_write: buffer is NULL\n");
		return false;
	}

	data = buffer_read_pointer(bp);
	size = buffer_available(bp);

	if (size > sizeof(nv_buffer.buffer)) {
		error("Data size %zu exceeds maximum NV buffer size %zu\n", size, sizeof(nv_buffer.buffer));
		return false;
	}

	/* Try to see if NV index is already defined */
	if (tpm_nvindex_exists(nv_index)) {
		rc = Esys_TR_FromTPMPublic(esys_ctx, nv_index,
		                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
		                           &nv_tr);
		if (rc == TSS2_RC_SUCCESS) {
			/* Space is already defined, let's undefine it first */
			debug("NV Index 0x%08x is already defined. Undefining it...\n", nv_index);
			rc = Esys_NV_UndefineSpace(esys_ctx, esys_tr_rh_owner, nv_tr,
			                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
			if (!tss_check_error(rc, "Esys_NV_UndefineSpace failed"))
				goto err;
			Esys_TR_Close(esys_ctx, &nv_tr);
			nv_tr = ESYS_TR_NONE;
		}
	}

	/* Define the NV space */
	TPM2B_NV_PUBLIC public_info = {
		.size = 0,
		.nvPublic = {
			.nvIndex = nv_index,
			.nameAlg = TPM2_ALG_SHA256,
			.attributes = TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD,
			.authPolicy = { .size = 0 },
			.dataSize = size,
		}
	};

	debug("Defining NV Index 0x%08x with size %zu...\n", nv_index, size);
	rc = Esys_NV_DefineSpace(esys_ctx, esys_tr_rh_owner,
	                         ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
	                         &auth_value, &public_info, &nv_tr);
	if (!tss_check_error(rc, "Esys_NV_DefineSpace failed"))
		goto err;

	/* Write to the NV space */
	nv_buffer.size = size;
	memcpy(nv_buffer.buffer, data, size);

	debug("Writing to NV Index 0x%08x...\n", nv_index);
	rc = Esys_NV_Write(esys_ctx, esys_tr_rh_owner, nv_tr,
	                   ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
	                   &nv_buffer, 0);
	if (!tss_check_error(rc, "Esys_NV_Write failed")) {
		Esys_NV_UndefineSpace(esys_ctx, esys_tr_rh_owner, nv_tr,
				      ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
		goto err;
	}

	infomsg("Successfully wrote %zu bytes to TPM NV Index 0x%08x\n", size, nv_index);
	ok = true;

err:
	if (nv_tr != ESYS_TR_NONE)
		Esys_TR_Close(esys_ctx, &nv_tr);

	return ok;
}
