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
#include <stdio.h>
#include <string.h>


#include "eventlog.h"
#include "bufparser.h"
#include "runtime.h"
#include "digest.h"
#include "authenticode.h"
#include "util.h"


/* Magic pointer returned by efi_variable_authority_get_record() when the boot service application
 * to be verified cannot be located. */
#define EFI_BSA_NOT_FOUND	((buffer_t *) 0x01)

/*
 * Process EFI_VARIABLE events
 */
static void
__tpm_event_efi_variable_destroy(tpm_parsed_event_t *parsed)
{
}

static void
__tpm_event_efi_variable_print(tpm_parsed_event_t *parsed, tpm_event_bit_printer *print_fn)
{
	print_fn("  --> EFI variable %s: %u bytes of data\n",
			tpm_efi_variable_event_extract_full_varname(parsed),
			parsed->efi_variable_event.len);
}

static bool
__tpm_event_marshal_efi_variable(buffer_t *bp, const tpm_parsed_event_t *parsed, const void *raw_data, unsigned int raw_data_len)
{
	unsigned int var_len, name_len;

	if (!buffer_put(bp, parsed->efi_variable_event.variable_guid, sizeof(parsed->efi_variable_event.variable_guid)))
		return false;

	var_len = strlen(parsed->efi_variable_event.variable_name);
	if (!buffer_put_u64le(bp, var_len)
	 || !buffer_put_u64le(bp, raw_data_len)
	 || !buffer_put_utf16le(bp, parsed->efi_variable_event.variable_name, &name_len)
	 || !buffer_put(bp, raw_data, raw_data_len))
		return false;

	if (name_len != 2 * var_len)
		return false;

	return true;
}

static buffer_t *
__tpm_event_efi_variable_build_event(const tpm_parsed_event_t *parsed, const void *raw_data, unsigned int raw_data_len)
{
	buffer_t *bp;

	/* The marshal buffer needs to hold
	 * GUID, 2 * UINT64, plus the UTF16 encoding of the variable name, plus the raw efivar value */
	bp = buffer_alloc_write(16 + 8 + 8 +
			+ 2 * strlen(parsed->efi_variable_event.variable_name)
			+ raw_data_len);

	if (!__tpm_event_marshal_efi_variable(bp, parsed, raw_data, raw_data_len)) {
		debug("Failed to marshal EFI variable %s\n", parsed->efi_variable_event.variable_name);
		buffer_free(bp);
		return NULL;
	}

	return bp;
}

#define SBATLEVELRT_VARNAME "SbatLevelRT-605dab50-e046-4300-abb6-3dd810dd8b23"
#define SBATPOLICY_VARNAME "SbatPolicy-605dab50-e046-4300-abb6-3dd810dd8b23"
#define SECUREBOOT_VARNAME "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

#define POLICY_LATEST		1
#define POLICY_AUTOMATIC	2
#define POLICY_RESET		3
#define POLICY_NOTREAD		255

#define SBAT_ORIGINAL "sbat,1,2021030218\n"

static bool
parse_sbatlevel_section(buffer_t *sec, char **sbat_automatic, char **sbat_latest)
{
	uint32_t fmt_ver;
	uint32_t offset_auto;
	uint32_t offset_latest;

	if (!buffer_get_u32le(sec, &fmt_ver)
	 || !buffer_get_u32le(sec, &offset_auto)
	 || !buffer_get_u32le(sec, &offset_latest))
		return false;

	if (offset_auto >= offset_latest)
		return false;

	if (!buffer_seek_read(sec, offset_auto + 4))
		return false;
	*sbat_automatic = (char *)buffer_read_pointer(sec);

	if (!buffer_seek_read(sec, offset_latest + 4))
		return false;
	*sbat_latest = (char *)(buffer_read_pointer(sec));

	return true;
}

static bool
fetch_sbat_datestamp(const char *sbat, size_t size, uint32_t *datestamp)
{
	uint32_t date = 0;
	size_t i;

	/* Expected string: "sbat,X,YYYYYYYYYY\n" */
	if (size < 17)
		return false;

	if (strncmp(sbat, "sbat,", 5) != 0)
		return false;

	for (i = 5; i < size && sbat[i] != ','; i++);
	i++;
	if (i >= size)
		return false;

	for (; i < size && sbat[i] != '\n'; i++) {
		if (sbat[i] < '0' || sbat[i] > '9')
			return false;
		date = date * 10 + sbat[i] - '0';
	}

	*datestamp = date;
	return true;
}

static buffer_t *
efi_sbatlevel_get_record(buffer_t *sbatlevel)
{
	char *sbat_automatic;
	char *sbat_latest;
	const char *sbat_candidate;
	const char *sbat_current;
	buffer_t *buffer = NULL;
	buffer_t *sbatlvlrt = NULL;
	buffer_t *result = NULL;
	uint8_t secureboot;
	uint8_t sbatpolicy;
	uint32_t auto_date;
	uint32_t current_date;
	uint32_t candidate_date;
	bool sbat_reset = false;

	if (!parse_sbatlevel_section(sbatlevel, &sbat_automatic, &sbat_latest)) {
		error("Unable to process SbatLevel\n");
		return NULL;
	}

	if (!fetch_sbat_datestamp(sbat_automatic, strlen(sbat_automatic), &auto_date)) {
		error("Unable to get datestamp of SBAT automatic\n");
		return NULL;
	}

	buffer = runtime_read_efi_variable(SECUREBOOT_VARNAME);
	if (buffer == NULL || !buffer_get_u8(buffer, &secureboot))
		secureboot = 0;
	buffer_free(buffer);

	buffer = runtime_read_efi_variable(SBATPOLICY_VARNAME);
	if (buffer == NULL || !buffer_get_u8(buffer, &sbatpolicy))
		sbatpolicy = POLICY_NOTREAD;
	buffer_free(buffer);

	switch (sbatpolicy) {
	case POLICY_LATEST:
		sbat_candidate = sbat_latest;
		break;
	case POLICY_AUTOMATIC:
		sbat_candidate = sbat_automatic;
		break;
	case POLICY_RESET:
		if (secureboot == 1) {
			infomsg("SBAT cannot be reset when Secure Boot is enabled.\n");
			sbat_candidate = sbat_automatic;
		} else {
			sbat_reset = true;
			sbat_candidate = SBAT_ORIGINAL;
		}
		break;
	case POLICY_NOTREAD:
		if (secureboot == 1) {
			sbat_candidate = sbat_automatic;
		} else {
			/* shim 15.8 always resets SbatLevel when Secure Boot is disabled.
			 * The automatic datestamp of shim 15.8 is 2023012900. */
			if (auto_date >= 2023012900) {
				sbat_reset = true;
				sbat_candidate = SBAT_ORIGINAL;
			} else {
				sbat_candidate = sbat_automatic;
			}
		}
		break;
	default:
		error("Invalid SBAT policy\n");
		return NULL;
	}

	if ((sbatlvlrt = runtime_read_efi_variable(SBATLEVELRT_VARNAME)) == NULL) {
		error("Unable to read SbatLevelRT\n");
		return NULL;
	}

	sbat_current = (const char *)buffer_read_pointer(sbatlvlrt);

	if (!fetch_sbat_datestamp(sbat_current, sbatlvlrt->size, &current_date)
	 || !fetch_sbat_datestamp(sbat_candidate, strlen(sbat_candidate), &candidate_date)) {
		error("Unable to get SBAT datestamp\n");
		goto fail;
	}

	debug("Current SBAT datestamp: %u\n", current_date);
	debug("Candidate SBAT datestamp: %u\n", candidate_date);

	if (current_date >= candidate_date && sbat_reset == false) {
		debug("Use current SbatLevel\n");
		result = sbatlvlrt;
	} else {
		debug("Use candidate SbatLevel\n");
		buffer_free(sbatlvlrt);

		/* Copy the candidate SbatLevel string without the terminating null */
		if ((result = buffer_alloc_write(strlen(sbat_candidate))) == NULL
		 || !buffer_put(result, sbat_candidate, strlen(sbat_candidate)))
			goto fail;
	}

	return result;

fail:
	buffer_free(sbatlvlrt);
	buffer_free(result);

	return NULL;
}

enum {
	HASH_STRATEGY_EVENT,
	HASH_STRATEGY_DATA,
};

static buffer_t *
efi_variable_authority_get_record(const tpm_parsed_event_t *parsed, const char *var_name, tpm_event_log_rehash_ctx_t *ctx)
{
	const char *var_short_name = parsed->efi_variable_event.variable_name;
	parsed_cert_t *signer;
	const char *db_name = NULL;
	buffer_t *result;

	if (!strcmp(var_short_name, "Shim")) {
		db_name = "shim-vendor-cert";
	} else
	if (!strcmp(var_short_name, "db")) {
		db_name = "db";
	} else
	if (!strcmp(var_short_name, "MokListRT")) {
		db_name = "MokList";
	} else
	if (!strcmp(var_short_name, "SbatLevel")) {
		if (ctx->sbatlevel == NULL)
			fatal("No reference .sbatlevel section. Please add PCR4 into the PCR index list\n");
		return efi_sbatlevel_get_record(ctx->sbatlevel);
	} else {
		/* Read as-is (this could be SbatLevel, or some other variable that's not
		 * a signature db). */
		return runtime_read_efi_variable(var_name);
	}

	if (ctx->next_stage_img == NULL) {
		infomsg("Unable to verify signature of a boot service; probably a driver residing in ROM.\n");
		return EFI_BSA_NOT_FOUND;
	}

	signer = authenticode_get_signer(ctx->next_stage_img);
	if (signer == NULL)
		return NULL;

	debug("Next stage application was signed by %s\n", parsed_cert_subject(signer));
	result = efi_application_locate_authority_record(db_name, signer);
	parsed_cert_free(signer);

	return result;
}

static int
__tpm_event_efi_variable_detect_hash_strategy(const tpm_event_t *ev, const tpm_parsed_event_t *parsed, const tpm_algo_info_t *algo)
{
	const tpm_evdigest_t *md, *old_md;

	old_md = tpm_event_get_digest(ev, algo);
	if (old_md == NULL) {
		debug("Event does not provide a digest for algorithm %s\n", algo->openssl_name);
		return -1;
	}

	/* UEFI implementations seem to differ in what they hash. Some Dell firmwares
	 * always seem to hash the entire event. The OVMF firmware, on the other hand,
	 * hashes the log for EFI_VARIABLE_DRIVER_CONFIG events, and just the data for
	 * other variable events. */
	md = digest_compute(algo, ev->event_data, ev->event_size);
	if (digest_equal(old_md, md)) {
		debug("  Firmware hashed entire event data\n");
		return HASH_STRATEGY_EVENT;
	}

	md = digest_compute(algo, parsed->efi_variable_event.data, parsed->efi_variable_event.len);
	if (digest_equal(old_md, md)) {
		debug("  Firmware hashed variable data\n");
		return HASH_STRATEGY_DATA;
	}

	debug("  I'm lost.\n");
	return HASH_STRATEGY_DATA; /* no idea what would be right */
}

static const unsigned char uefi_global_guid[16] =
	{0xcb, 0xb2, 0x19, 0xd7,
	 0x3a, 0x3d,
	 0x96, 0x45,
	 0xa3, 0xbc,
	 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f};
static const unsigned char shim_variable_guid[16] =
	{0x50, 0xab, 0x5d, 0x60,
	 0x46, 0xe0,
	 0x00, 0x43,
	 0xab, 0xb6,
	 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23};

static tpm_parsed_event_t *
efi_variable_get_parsed_alt (const tpm_parsed_event_t *parsed)
{
	tpm_parsed_event_t *parsed_alt = NULL;
	const char *var_short_name;

	if (parsed->event_type != TPM2_EFI_VARIABLE_AUTHORITY)
		return NULL;

	var_short_name = parsed->efi_variable_event.variable_name;

	if (strcmp(var_short_name, "db") != 0 && strcmp(var_short_name, "MokListRT") != 0)
		return NULL;

	parsed_alt = malloc(sizeof(tpm_parsed_event_t));
	if (parsed_alt == NULL)
		return NULL;

	memcpy(parsed_alt, parsed, sizeof(tpm_parsed_event_t));

	/* Set the alternative database: "MokListRT" <==> "db" */
	if (!strcmp(var_short_name, "db")) {
		memcpy(parsed_alt->efi_variable_event.variable_guid, shim_variable_guid, 16);
		parsed_alt->efi_variable_event.variable_name = "MokListRT";
	} else
	if (!strcmp(var_short_name, "MokListRT")) {
		memcpy(parsed_alt->efi_variable_event.variable_guid, uefi_global_guid, 16);
		parsed_alt->efi_variable_event.variable_name = "db";
	}

	/* No event data for this synthesized parsed event */
	parsed_alt->efi_variable_event.len = 0;
	parsed_alt->efi_variable_event.data = NULL;

	return parsed_alt;
}

static const tpm_evdigest_t *
__tpm_event_efi_variable_rehash(const tpm_event_t *ev, const tpm_parsed_event_t *parsed, tpm_event_log_rehash_ctx_t *ctx)
{
	const tpm_algo_info_t *algo = ctx->algo;
	const char *var_name;
	unsigned int num_buffers_to_free = 0;
	buffer_t *buffers_to_free[4];
	buffer_t *file_data = NULL, *event_data = NULL, *data_to_hash = NULL;
	const tpm_evdigest_t *md = NULL;
	int hash_strategy;
	char *var_name_alt = NULL;
	tpm_parsed_event_t *parsed_alt = NULL;

	if (!(var_name = tpm_efi_variable_event_extract_full_varname(parsed)))
		fatal("Unable to extract EFI variable name from EFI_VARIABLE event\n");

	hash_strategy = __tpm_event_efi_variable_detect_hash_strategy(ev, parsed, algo);
	if (hash_strategy < 0)
		return NULL;

	if (ev->event_type == TPM2_EFI_VARIABLE_AUTHORITY) {
		/* For certificate related variables, EFI_VARIABLE_AUTHORITY events don't return the
		 * entire DB, but only the record that was used in verifying the application's
		 * authenticode signature. */
		file_data = efi_variable_authority_get_record(parsed, var_name, ctx);
		if (file_data == EFI_BSA_NOT_FOUND) {
			/* The boot service we may be authenticating here might be an EFI
			 * application residing in device ROM.
			 * OVMF, for example, seems to do that, and the DevicePath it
			 * uses for this is PNP0A03/PCI(2.0)/PCI(0)/OffsetRange(....)
			 *
			 * For the time being, just pretend these cannot be changed from
			 * within the running system.
			 */
			md = tpm_event_get_digest(ev, algo);
			goto out;
		} else
		if (file_data == NULL && (parsed_alt = efi_variable_get_parsed_alt(parsed))) {
			/* If the signer of the next application is not available in the
			 * specified EFI variable of the EFI_VARIABLE_AUTHORITY event,
			 * we may need to look for the signer in another database.
			 *
			 * For example, a testing GRUB2 may be signed with a testing key
			 * enrolled in UEFI db while the original GRUB2 is verified by
			 * the certificate in MokListRT. After installing the testing GRUB2,
			 * the corresponding EFI_VARIABLE_AUTHORITY event will change
			 * in the next boot with signing authority from UEFI db instead of
			 * MokListRT. To predict the EFI_VARIABLE_AUTHORITY event,
			 * 'parsed_alt' is created to contain the path to the alternative
			 * database so we can look for signing authority in the alternative
			 * database. */
			var_name_alt = (char *)tpm_efi_variable_event_extract_full_varname(parsed_alt);
			if (var_name_alt == NULL)
				fatal("Unable to extract EFI variable name from EFI_VARIABLE event(alt)\n");
			debug("Looking for signing authority in alternative database\n");
			file_data = efi_variable_authority_get_record(parsed_alt, var_name_alt, ctx);
			if (file_data == NULL) {
				warning("Failed to find authority record\n");
				var_name_alt = NULL;
				free(parsed_alt);
				parsed_alt = NULL;
			} else {
				warning("Signing authority from different database!\n");
			}
		}
	} else {
		file_data = runtime_read_efi_variable(var_name);
	}

	/* The PCR 7 is always expanded, even if the data is empty */
	if (file_data == NULL
	    && ev->event_type != TPM2_EFI_VARIABLE_DRIVER_CONFIG
	    && ev->pcr_index != 7) {
		if (parsed->efi_variable_event.len == 0) {
			/* The content of the variable doesn't exist during the measurement
			 * and is also not available at runtime. Let's skip this event.
			 */
			md = tpm_event_get_digest(ev, algo);
		}
		goto out;
	}

	buffers_to_free[num_buffers_to_free++] = file_data;

	if (hash_strategy == HASH_STRATEGY_EVENT) {
		event_data = __tpm_event_efi_variable_build_event(
				parsed_alt ? parsed_alt : parsed,
				buffer_read_pointer(file_data),
				buffer_available(file_data));
		if (event_data == NULL)
			fatal("Unable to re-marshal EFI variable for hashing\n");

		if (opt_debug > 1) {
			debug("  Remarshaled event for EFI variable %s:\n",
				 var_name_alt ? var_name_alt : var_name);
			hexdump(buffer_read_pointer(event_data),
				buffer_available(event_data),
				debug, 8);
		 }

		buffers_to_free[num_buffers_to_free++] = event_data;
		data_to_hash = event_data;
	} else {
		data_to_hash = file_data;
	}

	md = digest_compute(algo,
			buffer_read_pointer(data_to_hash),
			buffer_available(data_to_hash));

out:
	while (num_buffers_to_free)
		buffer_free(buffers_to_free[--num_buffers_to_free]);
	if (parsed_alt)
		free(parsed_alt);
	return md;
}

bool
__tpm_event_parse_efi_variable(tpm_event_t *ev, tpm_parsed_event_t *parsed, buffer_t *bp)
{
	uint64_t name_len, data_len;

	parsed->destroy = __tpm_event_efi_variable_destroy;
	parsed->print = __tpm_event_efi_variable_print;
	parsed->rehash = __tpm_event_efi_variable_rehash;

	if (!buffer_get(bp, parsed->efi_variable_event.variable_guid, sizeof(parsed->efi_variable_event.variable_guid)))
		return false;

	if (!buffer_get_u64le(bp, &name_len) || !buffer_get_u64le(bp, &data_len))
		return false;

	if (!(parsed->efi_variable_event.variable_name = buffer_get_utf16le(bp, name_len)))
		return false;

	parsed->efi_variable_event.data = malloc(data_len);
	if (!buffer_get(bp, parsed->efi_variable_event.data, data_len))
		return false;
	parsed->efi_variable_event.len = data_len;

	return parsed;
}

const char *
tpm_efi_variable_event_extract_full_varname(const tpm_parsed_event_t *parsed)
{
	static char varname[256];
	const struct efi_variable_event *evspec = &parsed->efi_variable_event;
	const char *shim_rtname;

	/* First, check if this is one of the variables used by the shim loader.
	 * These are usually not accessible at runtime, but the shim loader
	 * does provide copies of them that are.
	 */
	shim_rtname = shim_variable_get_full_rtname(evspec->variable_name);
	if (shim_rtname != NULL)
		return shim_rtname;

	snprintf(varname, sizeof(varname), "%s-%s", 
			evspec->variable_name,
			tpm_event_decode_uuid(evspec->variable_guid));
	return varname;
}

