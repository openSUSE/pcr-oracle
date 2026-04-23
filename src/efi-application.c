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
#include <stdarg.h>
#include <limits.h>

#include "oracle.h"
#include "eventlog.h"
#include "bufparser.h"
#include "runtime.h"
#include "authenticode.h"
#include "digest.h"
#include "sd-boot.h"
#include "util.h"


/*
 * Process EFI Boot Service Application events
 */
static const tpm_evdigest_t *	__tpm_event_efi_bsa_rehash(const tpm_event_t *, const tpm_parsed_event_t *, tpm_event_log_rehash_ctx_t *);
static bool			__tpm_event_efi_bsa_extract_location(tpm_parsed_event_t *parsed);
static bool			__tpm_event_efi_bsa_inspect_image(struct efi_bsa_event *evspec);

static bool			__is_shim_issue(const tpm_event_t *ev, const struct efi_bsa_event *evspec);
static bool			__is_shim_extra_file(const tpm_event_t *ev, const struct efi_bsa_event *evspec, tpm_event_log_scan_ctx_t *ctx, bool is_fullpath);

static void
__tpm_event_efi_bsa_destroy(tpm_parsed_event_t *parsed)
{
	__tpm_event_efi_device_path_destroy(&parsed->efi_bsa_event.device_path);

	drop_string(&parsed->efi_bsa_event.efi_partition);
	drop_string(&parsed->efi_bsa_event.efi_application);
}

static void
__tpm_event_efi_bsa_print(tpm_parsed_event_t *parsed, tpm_event_bit_printer *print_fn)
{
#if 0
	print_fn("BSA image loc=%Lx", (unsigned long long) parsed->efi_bsa_event.image_location);
	print_fn(" len=%Lx", (unsigned long long) parsed->efi_bsa_event.image_length);
	print_fn(" lt-addr=%Lx", (unsigned long long) parsed->efi_bsa_event.image_lt_address);
	print_fn("\n");
#endif

	print_fn("Boot Service Application; device path:\n");
	__tpm_event_efi_device_path_print(&parsed->efi_bsa_event.device_path, print_fn);
}

static const char *
__tpm_event_efi_bsa_describe(const tpm_parsed_event_t *parsed)
{
	static char buffer[1024];
	char *result;

	if (parsed->efi_bsa_event.efi_application) {
		snprintf(buffer, sizeof(buffer), "EFI Boot Service Application %s", parsed->efi_bsa_event.efi_application);
		result = buffer;
	} else {
		result = "EFI Boot Service Application";
	}

	return result;
}

static bool
__is_data_already_measured(measured_blob_t **head, const buffer_t *data)
{
	measured_blob_t *cur = *head;
	unsigned int len;
	const void *ptr;
	measured_blob_t *node;

	if (!data)
		return false;

	len = buffer_available(data);
	ptr = buffer_read_pointer(data);

	while (cur != NULL) {
		if (buffer_available(cur->data) == len &&
		    memcmp(buffer_read_pointer(cur->data), ptr, len) == 0) {
			return true;
		}
		cur = cur->next;
	}

	node = calloc(1, sizeof(*node));
	if (node == NULL) {
		error("Failed to allocate memory for measured data link\n");
		return false;
	}
	node->data = buffer_alloc_write(len);
	buffer_put(node->data, ptr, len);
	node->next = *head;
	*head = node;

	return false;
}

static const tpm_evdigest_t *
__synthetic_pcr7_rehash(const tpm_event_t *ev, const tpm_parsed_event_t *parsed, tpm_event_log_rehash_ctx_t *ctx)
{
	return digest_compute(ctx->algo, parsed->efi_variable_event.data, parsed->efi_variable_event.len);
}

static const char *
__synthetic_pcr7_describe(const tpm_parsed_event_t *parsed)
{
	return "Synthesized Shim Authority Event";
}

static void
__synthetic_pcr7_destroy(tpm_parsed_event_t *parsed)
{
	free(parsed->efi_variable_event.data);
}

static const uint8_t uefi_db_guid[16] =
	{0xcb, 0xb2, 0x19, 0xd7,
	 0x3a, 0x3d,
	 0x96, 0x45,
	 0xa3, 0xbc,
	 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f};

static const uint8_t shim_variable_guid[16] =
	{0x50, 0xab, 0x5d, 0x60,
	 0x46, 0xe0,
	 0x00, 0x43,
	 0xab, 0xb6,
	 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23};

typedef struct {
	const char *search_name;
	const char *var_name;
	const uint8_t *var_guid;
} db_search_t;

static buffer_t *
build_shim_authority_payload(const parsed_cert_t *signer)
{
	buffer_t *var_data = NULL;
	const char *var_name = NULL;
	const uint8_t *var_guid = NULL;
	uint64_t name_len = 0;
	buffer_t *bp = NULL;
	uint64_t i;

	const db_search_t databases[] = {
		{ "db", "db", uefi_db_guid },
		{ "MokList", "MokList", shim_variable_guid },
		{ "shim-vendor-cert", "Shim", shim_variable_guid }
	};

	for (i = 0; i < sizeof(databases) / sizeof(databases[0]); i++) {
		var_data = efi_application_locate_authority_record(databases[i].search_name,
								   signer);
		if (var_data) {
			var_name = databases[i].var_name;
			name_len = strlen(var_name);
			var_guid = databases[i].var_guid;
			break;
		}
	}

	if (!var_data) {
		error("Failed to locate authority record for synthetic event\n");
		return NULL;
	}

	uint64_t data_len = buffer_available(var_data);
	bp = buffer_alloc_write(16 + 8 + 8 + name_len * 2 + data_len);

	buffer_put(bp, var_guid, 16);
	buffer_put_u64le(bp, name_len);
	buffer_put_u64le(bp, data_len);
	for (i = 0; i < name_len; i++)
		buffer_put_u16le(bp, var_name[i]);
	buffer_copy(var_data, data_len, bp);
	buffer_free(var_data);

	return bp;
}

static tpm_event_t *
synthesize_shim_authority_event(tpm_event_t *inject_after, const parsed_cert_t *signer)
{
	tpm_event_t *syn_7;
	buffer_t *payload = NULL;

	syn_7 = calloc(1, sizeof(*syn_7));
	if (syn_7 == NULL) {
		error("Failed to allocate memory for shim Authority event\n");
		goto err;
	}

	payload = build_shim_authority_payload(signer);
	if (!payload) {
		error("Failed to build shim Authority event payload\n");
		goto err;
	}

	syn_7->synthetic = true;
	syn_7->event_type = TPM2_EFI_VARIABLE_AUTHORITY;
	syn_7->pcr_index = 7;
	syn_7->rehash_strategy = EVENT_STRATEGY_PARSE_REHASH;

	syn_7->event_size = buffer_available(payload);
	syn_7->event_data = malloc(syn_7->event_size);
	if (syn_7->event_data == NULL) {
		error("Failed to allocate memory for shim Authority event data\n");
		goto err;
	}
	memcpy(syn_7->event_data, buffer_read_pointer(payload), syn_7->event_size);

	syn_7->__parsed = calloc(1, sizeof(tpm_parsed_event_t));
	if (syn_7->__parsed == NULL) {
		error("Failed to allocate memory for parsed shim Authority event\n");
		goto err;
	}
	syn_7->__parsed->describe = __synthetic_pcr7_describe;
	syn_7->__parsed->rehash = __synthetic_pcr7_rehash;
	syn_7->__parsed->destroy = __synthetic_pcr7_destroy;
	syn_7->__parsed->efi_variable_event.len = buffer_available(payload);
	syn_7->__parsed->efi_variable_event.data = malloc(buffer_available(payload));
	if (syn_7->__parsed->efi_variable_event.data == NULL) {
		error("Failed to allocate memory for efi variable event data\n");
		goto err;
	}
	memcpy(syn_7->__parsed->efi_variable_event.data,
	       buffer_read_pointer(payload),
	       buffer_available(payload));
	buffer_free(payload);

	syn_7->next = inject_after->next;
	syn_7->prev = inject_after;
	if (inject_after->next)
		inject_after->next->prev = syn_7;
	inject_after->next = syn_7;
	return syn_7;

err:
	buffer_free(payload);

	if (syn_7 != NULL) {
		if (syn_7->__parsed != NULL) {
			free(syn_7->__parsed->efi_variable_event.data);
			free(syn_7->__parsed);
		}
		free(syn_7->event_data);
		free(syn_7);
	}

	return inject_after;
}

static tpm_event_t *
synthesize_shim_bsa_event(tpm_event_t *inject_after, const char *filepath, tpm_event_log_scan_ctx_t *ctx)
{
	tpm_event_t *syn_4 = calloc(1, sizeof(*syn_4));

	if (syn_4 == NULL) {
		error("Failed to allocate memory for shim BSA event\n");
		goto err;
	}

	syn_4->synthetic = true;
	syn_4->event_type = TPM2_EFI_BOOT_SERVICES_APPLICATION;
	syn_4->pcr_index = 4;
	syn_4->rehash_strategy = EVENT_STRATEGY_PARSE_REHASH;
	if (ctx->shim_event_data_template) {
		syn_4->event_size = ctx->shim_event_data_size;
		syn_4->event_data = malloc(syn_4->event_size);
		if (syn_4->event_data == NULL) {
			error("Failed to allocate memory for shim BSA event data\n");
			goto err;
		}
		memcpy(syn_4->event_data, ctx->shim_event_data_template, syn_4->event_size);
	}
	syn_4->__parsed = calloc(1, sizeof(tpm_parsed_event_t));
	if (syn_4->__parsed == NULL) {
		error("Failed to allocate memory for parsed shim BSA event\n");
		goto err;
	}
	syn_4->__parsed->describe = __tpm_event_efi_bsa_describe;
	syn_4->__parsed->rehash = __tpm_event_efi_bsa_rehash;
	syn_4->__parsed->destroy = __tpm_event_efi_bsa_destroy;
	syn_4->__parsed->efi_bsa_event.efi_partition = strdup(ctx->efi_partition);
	if (syn_4->__parsed->efi_bsa_event.efi_partition == NULL) {
		error("Failed to duplicate efi_partition for shim BSA event\n");
		goto err;
	}
	syn_4->__parsed->efi_bsa_event.efi_application = strdup(filepath);
	if (syn_4->__parsed->efi_bsa_event.efi_application == NULL) {
		error("Failed to duplicate efi_application for shim BSA event\n");
		goto err;
	}
	__tpm_event_efi_bsa_inspect_image(&syn_4->__parsed->efi_bsa_event);

	syn_4->next = inject_after->next;
	syn_4->prev = inject_after;
	if (inject_after->next)
		inject_after->next->prev = syn_4;
	inject_after->next = syn_4;
	return syn_4;

err:
	if (syn_4 != NULL) {
		if (syn_4->__parsed != NULL) {
			free(syn_4->__parsed->efi_bsa_event.efi_partition);
			free(syn_4->__parsed);
		}
		free(syn_4->event_data);
		free(syn_4);
	}

	return inject_after;
}

static char *
__extract_efi_directory(const char *efi_application)
{
	char *efi_directory = NULL;
	char *last_slash;

	if (efi_application == NULL)
		return NULL;

	efi_directory = strdup(efi_application);
	if (efi_directory == NULL) {
		error("Failed to allocate memory for efi directory\n");
		return NULL;
	}

	last_slash = strrchr(efi_directory, '/');
	if (last_slash == NULL) {
		error("Invalid path\n");
		free(efi_directory);
		return NULL;
	}

	if (last_slash == efi_directory)
		*(last_slash + 1) = '\0';
	else
		*last_slash = '\0';

	return efi_directory;
}

static file_list_t *
__shim_extra_files_init(const struct efi_bsa_event *evspec)
{
	file_list_t *head = NULL, *tail, *node;
	buffer_t *raw_list = NULL;
	char *efi_directory;
	const char *str_ptr;
	char filename[PATH_MAX];
	char filepath[PATH_MAX];
	int offset = 0;
	int ret;

	if (evspec->efi_partition == NULL || evspec->efi_application == NULL)
		return NULL;

	efi_directory = __extract_efi_directory(evspec->efi_application);
	if (efi_directory == NULL) {
		error("unable to extract directory\n");
		return NULL;
	}

	raw_list = runtime_read_efi_directory(evspec->efi_partition, efi_directory);
	if (raw_list == NULL || raw_list->size <= 2) {
		debug("Empty directory (%s)\n", efi_directory);
		goto out;
	}
	str_ptr = buffer_read_pointer(raw_list);

	/* Pass 1: Shim explicitly searches for and measures revocations_sbat.efi
	 * first. If found, it stops the search and rewinds the directory.
	 */
	do {
		if (sscanf(str_ptr, "%[^\n]\n%n", filename, &offset) != 1)
			break;
		str_ptr += offset;

		if (strcasecmp(filename, "revocations_sbat.efi") != 0)
			continue;

		node = calloc(1, sizeof(file_list_t));
		if (node == NULL) {
			error("Failed to allocate a file_list_t node\n");
			goto out;
		}

		/* Construct the full file path */
		ret = snprintf(filepath, sizeof(filepath), "%s/%s", efi_directory, filename);
		if (ret >= sizeof(filepath)) {
			error("File path too long: (%s/%s)\n", efi_directory, filename);
			free(node);
			goto out;
		}
		node->filepath = strdup(filepath);
		if (node->filepath == NULL) {
			error("Failed to duplicate filepath(%s)\n", filepath);
			free(node);
			goto out;
		}

		/* revocations_sbat.efi is always the first node if exists */
		head = node;
		tail = node;
		break;
	} while (*str_ptr != '\0');

	/* Pass 2: Shim iterates the directory again from the beginning, ignoring
	 * the SBAT file, and measures certificates and SKU revocations in raw
	 * FAT directory order.
	 */
	str_ptr = buffer_read_pointer(raw_list);
	do {
		if (sscanf(str_ptr, "%[^\n]\n%n", filename, &offset) != 1)
			break;
		str_ptr += offset;

		if (strcasecmp(filename, "revocations_sku.efi") != 0 &&
		    !(strncasecmp(filename, "shim_certificate", 16) == 0 &&
		      path_has_file_extension(filename, ".efi"))) {
			continue;
		}

		node = calloc(1, sizeof(file_list_t));
		if (node == NULL) {
			error("Failed to allocate a file_list_t node\n");
			goto out;
		}

		/* Construct the full file path */
		ret = snprintf(filepath, sizeof(filepath), "%s/%s", efi_directory, filename);
		if (ret >= sizeof(filepath)) {
			error("File path too long: (%s/%s)\n", efi_directory, filename);
			free(node);
			goto out;
		}

		node->filepath = strdup(filepath);
		if (node->filepath == NULL) {
			error("Failed to duplicate filepath(%s)\n", filepath);
			free(node);
			goto out;
		}

		/* Append the filepath to the list */
		if (head) {
			tail->next = node;
			tail = node;
		} else {
			head = node;
			tail = node;
		}
	} while (*str_ptr != '\0');

out:
	if (efi_directory)
		free(efi_directory);

	if (raw_list)
		buffer_free(raw_list);

	return head;
}

static tpm_event_t *
get_previous_authority_event(tpm_event_t *ev)
{
	tpm_event_t *prev = ev->prev;

	while (prev) {
		if (prev->event_type == TPM2_EFI_VARIABLE_AUTHORITY)
			return prev;

		/* Stop searching if we hit another application or driver load */
		if (prev->event_type == TPM2_EFI_BOOT_SERVICES_APPLICATION ||
		    prev->event_type == TPM2_EFI_BOOT_SERVICES_DRIVER)
			break;

		prev = prev->prev;
	}
	return NULL;
}

static bool
synthesize_shim_extra_events(tpm_event_t *ev, struct efi_bsa_event *evspec, tpm_event_log_scan_ctx_t *ctx)
{
	file_list_t *list, *cur;
	tpm_event_t *inject_after = ev;
	tpm_event_t *auth_ev;

	auth_ev = get_previous_authority_event(ev);

	/* Retroactively skip the corresponding PCR 7 event */
	if (auth_ev)
		auth_ev->rehash_strategy = EVENT_STRATEGY_NO_ACTION;

	/* Save the original event data payload as a template for synthetic events */
	if (!ctx->shim_event_data_template && ev->event_data && ev->event_size > 0) {
		ctx->shim_event_data_template = malloc(ev->event_size);
		if (ctx->shim_event_data_template == NULL) {
			error("Failed to allocate memory for shim event template\n");
			return false;
		}

		memcpy(ctx->shim_event_data_template, ev->event_data, ev->event_size);
		ctx->shim_event_data_size = ev->event_size;
	}

	if (ctx->skip_original_shim_events)
		goto out;

	list = __shim_extra_files_init(evspec);
	if (list == NULL) {
		error("Failed to get shim extra file list\n");
		return false;
	}

	ctx->shim_extra.head = list;
	cur = list;

	while (cur != NULL) {
		buffer_t *img_data;
		pecoff_image_info_t *img_info;
		parsed_cert_t *signer;
		buffer_t *cert_der;

		img_data = runtime_read_efi_application(ctx->efi_partition, cur->filepath);
		if (!img_data) {
			cur = cur->next;
			continue;
		}

		img_info = pecoff_inspect(img_data, cur->filepath);
		if (!img_info) {
			buffer_free(img_data);
			cur = cur->next;
			continue;
		}

		signer = authenticode_get_signer(img_info);
		if (signer) {
			cert_der = parsed_cert_as_buffer(signer);
			if (!__is_data_already_measured(&ctx->measured_blobs, cert_der)) {
				inject_after = synthesize_shim_authority_event(inject_after, signer);
				debug("Synthesized PCR 7 event for signer of %s\n",
				      cur->filepath);
			}
			buffer_free(cert_der);
			parsed_cert_free(signer);
		}

		inject_after = synthesize_shim_bsa_event(inject_after, cur->filepath, ctx);
		debug("Synthesized PCR 4 event for %s\n", cur->filepath);

		pecoff_image_info_free(img_info);
		cur = cur->next;
	}

	/* All shim extra file events are synthesized. Skip the original events
	 * from shim. */
	ctx->skip_original_shim_events = true;

out:
	/* Mark the original PCR 4 event as NO ACTION to skip it */
	ev->rehash_strategy = EVENT_STRATEGY_NO_ACTION;
	return true;
}

static bool
deduplicate_main_authority_event(tpm_event_t *ev, struct efi_bsa_event *evspec, tpm_event_log_scan_ctx_t *ctx)
{
	parsed_cert_t *signer;
	buffer_t *cert_der;
	tpm_event_t *auth_ev;

	/* Skip deduplication if it is not necessary */
	if (!evspec->img_info || !secure_boot_enabled())
		return true;

	/* Skip deduplication if there is no signer */
	signer = authenticode_get_signer(evspec->img_info);
	if (signer == NULL)
		return true;

	cert_der = parsed_cert_as_buffer(signer);
	if (cert_der == NULL) {
		error("Failed to fetch signer buffer\n");
		return false;
	}

	/* Fetch the corresponding authority event for this application */
	auth_ev = get_previous_authority_event(ev);

	if (!__is_data_already_measured(&ctx->measured_blobs, cert_der)) {
		/* Not measured yet. If we don't have the PCR 7 event, synthesize one. */
		if (auth_ev == NULL && ev->prev != NULL)
			synthesize_shim_authority_event(ev->prev, signer);
	} else {
		/* Already measured. If we have a PCR 7 event for this signer,
		 * neutralize it. */
		if (auth_ev)
			auth_ev->rehash_strategy = EVENT_STRATEGY_NO_ACTION;
	}
	buffer_free(cert_der);
	parsed_cert_free(signer);

	return true;
}

bool
__tpm_event_parse_efi_bsa(tpm_event_t *ev, tpm_parsed_event_t *parsed, buffer_t *bp, tpm_event_log_scan_ctx_t *ctx)
{
	struct efi_bsa_event *evspec = &parsed->efi_bsa_event;
	size_t device_path_len;
	buffer_t path_buf;
	bool is_fullpath = false;

	parsed->destroy = __tpm_event_efi_bsa_destroy;
	parsed->print = __tpm_event_efi_bsa_print;
	parsed->describe = __tpm_event_efi_bsa_describe;
	parsed->rehash = __tpm_event_efi_bsa_rehash;

	if (!buffer_get_u64le(bp, &evspec->image_location)
	 || !buffer_get_size(bp, &evspec->image_length)
	 || !buffer_get_size(bp, &evspec->image_lt_address)
	 || !buffer_get_size(bp, &device_path_len)
	 || !buffer_get_buffer(bp, device_path_len, &path_buf))
		return false;

	if (!__tpm_event_parse_efi_device_path(&evspec->device_path, &path_buf))
		return false;

	if (__tpm_event_efi_bsa_extract_location(parsed)
	 && evspec->efi_application) {
		/* If a previous BSA event specified a device path with a partition,
		 * then the next event may omit it. */
		if (evspec->efi_partition != NULL) {
			assign_string(&ctx->efi_partition, evspec->efi_partition);
			is_fullpath = true;
		} else {
			assign_string(&evspec->efi_partition, ctx->efi_partition);
		}
	}

	/* When the shim issue is present the efi_application will be
	 * empty.  The binary path will be reconstructed with the
	 * --next-kernel parameter, but to generate the full path the
	 * `efi_partition` is needed.
	 */
	if (__is_shim_issue(ev, evspec))
		assign_string(&evspec->efi_partition, ctx->efi_partition);

	/* TPM events for shim extra files do not record the actual file paths
	 * in their device path payload. We synthesize the PCR 4 and PCR 7
	 * events directly from the directory contents to accurately predict
	 * changes in signer or file count across updates.
	 */
	if (__is_shim_extra_file(ev, evspec, ctx, is_fullpath))
		return synthesize_shim_extra_events(ev, evspec, ctx);

	if (!evspec->efi_application)
		return true;

	if (is_fullpath == true && ctx->first_application == NULL)
		assign_string(&ctx->first_application, evspec->efi_application);

	__tpm_event_efi_bsa_inspect_image(evspec);

	/* Deduplicate PCR 7 Authority event for the main bootloader, e.g. grub2 */
	return deduplicate_main_authority_event(ev, evspec, ctx);
}

bool
__tpm_event_efi_bsa_extract_location(tpm_parsed_event_t *parsed)
{
	struct efi_bsa_event *evspec = &parsed->efi_bsa_event;
	const struct efi_device_path *efi_path;
	const struct efi_device_path_item *item;
	unsigned int i;

	efi_path = &parsed->efi_bsa_event.device_path;
	for (i = 0, item = efi_path->entries; i < efi_path->count; ++i, ++item) {
		const char *uuid, *filepath;

		if ((uuid = __tpm_event_efi_device_path_item_harddisk_uuid(item)) != NULL) {
			char *dev_path;

			if ((dev_path = runtime_blockdev_by_partuuid(uuid)) == NULL) {
				error("Cannot find device for partition with uuid %s\n", uuid);
				return false;
			}

			drop_string(&evspec->efi_partition);
			evspec->efi_partition = dev_path;
		}

		if ((filepath = __tpm_event_efi_device_path_item_file_path(item)) != NULL) {
			assign_string(&evspec->efi_application, filepath);
		}
	}

	return true;
}

static bool
__tpm_event_efi_bsa_inspect_image(struct efi_bsa_event *evspec)
{
	char path[PATH_MAX];
	const char *display_name;
	buffer_t *img_data;

	if (!evspec->efi_application)
		return false;

	if (evspec->efi_partition) {
		snprintf(path, sizeof(path), "(%s)%s", evspec->efi_partition, evspec->efi_application);
		display_name = path;
	} else
		display_name = evspec->efi_application;

	img_data = runtime_read_efi_application(evspec->efi_partition, evspec->efi_application);
	if (img_data == NULL)
		fatal("Failed to locate EFI application %s\n", display_name);

	/* if successful, this takes ownership of img_data */
	if (!(evspec->img_info = pecoff_inspect(img_data, display_name))) {
		buffer_free(img_data);
		return false;
	}

	return true;
}

static const tpm_evdigest_t *
__pecoff_rehash_old(tpm_event_log_rehash_ctx_t *ctx, const char *filename)
{
	const char *algo_name = ctx->algo->openssl_name;
	char cmdbuf[8192], linebuf[1024];
	const tpm_evdigest_t *md = NULL;
	FILE *fp;
	int exitcode;

	snprintf(cmdbuf, sizeof(cmdbuf),
			"pesign --hash --in %s --digest_type %s",
			filename, algo_name);

	debug("Executing command: %s\n", cmdbuf);
	if ((fp = popen(cmdbuf, "r")) == NULL)
		fatal("Unable to run command: %s\n", cmdbuf);

	while (fgets(linebuf, sizeof(linebuf), fp) != NULL) {
		char *w;

		/* line must start with "hash:" */
		if (!(w = strtok(linebuf, " \t\n:")) || strcmp(w, "hash"))
			continue;

		if (!(w = strtok(NULL, " \t\n")))
			fatal("cannot parse pesign output\n");

		if (!(md = parse_digest(w, algo_name)))
			fatal("unable to parse %s digest printed by pesign: \"%s\"\n", algo_name, w);

		debug("  pesign digest: %s\n", digest_print(md));
		break;
	}

	exitcode = pclose(fp);
	if (exitcode == -1)
		fatal("pclose failed: %m\n");
	else if (!WIFEXITED(exitcode))
		fatal("pesign command failed\n");
	else if (WEXITSTATUS(exitcode) != 0)
		fatal("pesign command failed with %d\n", WEXITSTATUS(exitcode));

	return md;
}

static const tpm_evdigest_t *
__efi_application_rehash_direct(const struct efi_bsa_event *evspec, tpm_event_log_rehash_ctx_t *ctx)
{
	const tpm_evdigest_t *md;
	digest_ctx_t *digest;

	debug("Computing authenticode digest using built-in PECOFF parser\n");
	if (evspec->img_info == NULL)
		return NULL;

	digest = digest_ctx_new(ctx->algo);

	md = authenticode_get_digest(evspec->img_info, digest);

	digest_ctx_free(digest);

	return md;
}

static const tpm_evdigest_t *
__efi_application_rehash_pesign(tpm_event_log_rehash_ctx_t *ctx, const char *device_path, const char *file_path)
{
	const tpm_evdigest_t *md;
	file_locator_t *loc;
	const char *fullpath;

	loc = runtime_locate_file(device_path, file_path);
	if (!loc)
		fatal("Failed to locate EFI application (%s)%s", device_path, file_path);

	fullpath = file_locator_get_full_path(loc);
	md = __pecoff_rehash_old(ctx, fullpath);
	file_locator_free(loc);

	return md;
}

parsed_cert_t *
efi_application_extract_signer(const tpm_parsed_event_t *parsed)
{
	const struct efi_bsa_event *evspec = &parsed->efi_bsa_event;

	if (evspec->img_info == NULL) {
		debug("%s: cannot extract signer, no image info for this application\n", __func__);
		return NULL;
	}

	return authenticode_get_signer(evspec->img_info);
}

static bool __is_shim_issue(const tpm_event_t *ev, const struct efi_bsa_event *evspec)
{
	/* When secure boot is enabled and shim is installed,
	 * systemd-boot installs some security overrides that will
	 * delegate into shim (via shim_validate from systemd-boot)
	 * the validation of the kernel signature.
	 *
	 * The shim_validate function receives the device path from
	 * the firmware, and is used to load the kernel into memory.
	 * At the end call shim_verify from shim, but pass only the
	 * buffer with the loaded image.
	 *
	 * The net result is that the event log
	 * EV_EFI_BOOT_SERVICES_APPLICATION registered by shim_verify
	 * will not contain the device path that pcr-oracle requires
	 * to rehash the binary.
	 *
	 * So far only the kernel is presenting this issue (when
	 * systemd-boot is used, GRUB2 needs to be evaluated), so this
	 * can be detected if there is an event registered in PCR 4
	 * without path.
	 */
	return (secure_boot_enabled() && ev->pcr_index == 4 && !evspec->efi_application);
}

static bool
__is_shim_extra_file(const tpm_event_t *ev, const struct efi_bsa_event *evspec, tpm_event_log_scan_ctx_t *ctx, bool is_fullpath)
{
	/* When secure boot is enabled, shim calls verify_image() to measure
	 * the extra files (revocations_sbat.efi, revocations_sku.efi, and
	 * shim_certificate*.efi) into PCR 4.
	 *
	 * The device path in these TPM events contains only the file path node.
	 * Furthermore, this path always points to the shim image itself rather
	 * than the specific extra file being measured.
	 */
	if (is_fullpath || !secure_boot_enabled() || ev->pcr_index != 4
	 || ctx->first_application == NULL || evspec->efi_application == NULL)
		return false;

	if (strcmp(ctx->first_application, evspec->efi_application) != 0)
		return false;

	return true;
}

static const tpm_evdigest_t *
__tpm_event_efi_bsa_rehash(const tpm_event_t *ev, const tpm_parsed_event_t *parsed, tpm_event_log_rehash_ctx_t *ctx)
{
	const struct efi_bsa_event *evspec = &parsed->efi_bsa_event;
	const char *new_application;
	struct efi_bsa_event evspec_clone;
	buffer_t *sbatlevel;

	/* Some BSA events do not refer to files, but to some data blobs residing somewhere on a device.
	 * We're not yet prepared to handle these, so we hope the user doesn't mess with them, and
	 * return the original digest from the event log.
	 */
	if (!evspec->efi_application && !(__is_shim_issue(ev, evspec) && ctx->boot_entry)) {
		if (__is_shim_issue(ev, evspec) && !ctx->boot_entry)
			debug("Unable to locate boot service application - missing device path because shim issue");
		else
			debug("Unable to locate boot service application - probably not a file\n");
		return tpm_event_get_digest(ev, ctx->algo);
	}

	/* The next boot can have a different kernel */
	if ((sdb_is_kernel(evspec->efi_application) || __is_shim_issue(ev, evspec)) && ctx->boot_entry) {
		if (__is_shim_issue(ev, evspec))
			debug("Empty device path for the kernel - building one based on next kernel\n");

		/* TODO: the parsed data type did not change, so all
		 * the description correspond to the current event
		 * log, and not the asset that has been measured.  The
		 * debug output can then be missleading.
		 */
		debug("Measuring %s\n", ctx->boot_entry->image_path);
		new_application = ctx->boot_entry->image_path;
		if (new_application) {
			evspec_clone = *evspec;
			evspec_clone.efi_application = strdup(new_application);
			__tpm_event_efi_bsa_inspect_image(&evspec_clone);
			evspec = &evspec_clone;
		}
	}

	/* Set the sbatlevel section from shim.efi */
	if (ctx->sbatlevel == NULL
	 && (sbatlevel = pecoff_image_get_sbatlevel(evspec->img_info)) != NULL) {
		if ((ctx->sbatlevel = buffer_alloc_write(sbatlevel->size)) == NULL
		 || !buffer_copy(sbatlevel, sbatlevel->size, ctx->sbatlevel))
			return NULL;
	}

	if (ctx->use_pesign)
		return __efi_application_rehash_pesign(ctx, evspec->efi_partition, evspec->efi_application);

	return __efi_application_rehash_direct(evspec, ctx);
}

#define EFI_MAX_SIGNATURES	16

typedef struct efi_signature_data {
	unsigned char		owner[16];
	unsigned int		len;
	const unsigned char *	data;
	unsigned int		raw_len;
	const unsigned char *	raw_data;
} efi_signature_data_t;

typedef struct efi_signature_list {
	unsigned char		type[16];
	uint32_t		list_size;
	uint32_t		header_size;
	uint32_t		signature_size;
	const unsigned char *	header;

	unsigned int		num_signatures;
	efi_signature_data_t	signatures[EFI_MAX_SIGNATURES];
} efi_signature_list_t;

static bool
__efi_signature_data_parse(buffer_t *bp, unsigned int sig_size, efi_signature_data_t *result)
{
	memset(result, 0, sizeof(*result));
	result->raw_data = buffer_read_pointer(bp);
	result->raw_len = sig_size;
	if (!buffer_get(bp, result->owner, sizeof(result->owner)))
		return false;

	result->data = buffer_read_pointer(bp);
	result->len = sig_size - 16;
	if (!buffer_skip(bp, sig_size - 16))
		return false;

	return true;
}

static bool
__efi_signature_list_parse(buffer_t *db_data, unsigned int list_num, efi_signature_list_t *result)
{
	unsigned int payload_size, i;
	buffer_t list;

	memset(result, 0, sizeof(*result));

	debug2("Parsing list %u:\n");
	hexdump(buffer_read_pointer(db_data), 28, debug2, 8);

	if (!buffer_get(db_data, result->type, sizeof(result->type))
	 || !buffer_get_u32le(db_data, &result->list_size)
	 || !buffer_get_u32le(db_data, &result->header_size)
	 || !buffer_get_u32le(db_data, &result->signature_size))
		return false;

	if (result->header_size) {
		if (result->header_size >= result->list_size) {
			error("%s: list entry header too large (list_size=%u, header_size=%u)\n",
					__func__, result->list_size, result->header_size);
			return false;
		}
		result->header = buffer_read_pointer(db_data);
		if (!buffer_skip(db_data, result->header_size))
			return false;
	}

	if (result->signature_size == 0) {
		error("%s: signature list with signature_size 0\n", __func__);
		return false;
	}

	/* Compute the size of the signatures[] array */
	payload_size = result->list_size - 16 - 3 * 4 - result->header_size;

	if (!buffer_get_buffer(db_data, payload_size, &list)) {
		error("%s: list entry too large (list_size=%u)\n", __func__, result->list_size);
		return false;
	}

	result->num_signatures = payload_size / result->signature_size;
	if (result->num_signatures * result->signature_size != payload_size) {
		error("%s: entry with odd signatures[] array (%u is not a multiple of sig size %u)\n",
				__func__, payload_size, result->signature_size);
		return false;
	}

	for (i = 0; i < result->num_signatures; ++i) {
		if (!__efi_signature_data_parse(&list, result->signature_size, &result->signatures[i])) {
			error("%s: unable to parse signature %u of list %u\n", __func__, i, list_num);
			return false;
		}
	}

	return true;
}

static buffer_t *
efi_application_locate_and_check_shim_vendor_cert(const parsed_cert_t *signer)
{
	buffer_t *der_cert;
	parsed_cert_t *authority = NULL;

	if (!(der_cert = platform_read_shim_vendor_cert())) {
		error("Cannot locate authority record - please implement platform_read_shim_vendor_cert()\n");
		return NULL;
	}

	if (!(authority = cert_parse(der_cert))) {
		error("Unparseable X509 shim vendor certificate\n");
		goto failed;
	}

	if (!parsed_cert_issued_by(signer, authority)) {
		error("Next stage loader not signed by shim vendor.\n");
		parsed_cert_free(authority);
		goto failed;
	}

	debug("Returning CA certificate %s\n", parsed_cert_subject(authority));
	parsed_cert_free(authority);

	/* In many cases, VARIABLE_AUTHORITY will use the authority record from db or
	 * MokList (which includes the owner GUID). The shim loader does not do this when
	 * checking the signature against its built-in vendor certificiate.
	 * Yes, things would be much easier if the shim would actually export its vendor
	 * cert in a UEFI variable, but it does not do this yet.
	 */

	return der_cert;

failed:
	buffer_free(der_cert);
	return NULL;
}

buffer_t *
efi_application_locate_authority_record(const char *db_name, const parsed_cert_t *signer)
{
	const char *var_name = NULL;
	buffer_t *db_data;
	buffer_t *result = NULL;
	unsigned int list_num = 0;

	/* This is a special case. The shim does not consult any regular certificate lists
	 * but checks its built-in vendor cert. */
	if (!strcmp(db_name, "shim-vendor-cert"))
		return efi_application_locate_and_check_shim_vendor_cert(signer);

	if (!strcmp(db_name, "db"))
		var_name = "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f";
	else
	if (!strcmp(db_name, "MokList"))
		var_name = "MokListRT-605dab50-e046-4300-abb6-3dd810dd8b23";
	else {
		error("%s: unknown authority db %s\n", __func__, db_name);
		return NULL;
	}

	if (opt_debug > 1) {
		debug2("Looking for signing authority in %s\n", var_name);
		debug2("  subject %s\n", parsed_cert_subject(signer));
		debug2("  issuer  %s\n", parsed_cert_issuer(signer));
	}

	if (!(db_data = runtime_read_efi_variable(var_name)))
		return NULL;

	while (buffer_available(db_data) != 0) {
		static unsigned char efi_cert_x509_guid[] = {
			0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
			0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72 };
		efi_signature_list_t sig_list;
		unsigned int i;

		if (!__efi_signature_list_parse(db_data, list_num, &sig_list)) {
			error("%s: unable to parse signature list %u in %s\n", __func__, list_num, var_name);
			goto out;
		}

		if (memcmp(sig_list.type, efi_cert_x509_guid, 16)) {
			debug(" %u ignoring signature list with type %s\n", list_num, tpm_event_decode_uuid(sig_list.type));
			continue;
		}

		debug2(" %u inspecting X.509 signature list\n", list_num, tpm_event_decode_uuid(sig_list.type));
		for (i = 0; i < sig_list.num_signatures; ++i) {
			efi_signature_data_t *sig_data = &sig_list.signatures[i];
			parsed_cert_t *authority;
			buffer_t cert_buf;

			buffer_init_read(&cert_buf, (void *) sig_data->data, sig_data->len);

			if (!(authority = cert_parse(&cert_buf))) {
				error("Unparseable X509 certificate in %s\n", var_name);
				continue;
			}

			debug2(" %u.%u: owner %s\n", list_num, i, tpm_event_decode_uuid(sig_data->owner));
			debug2("    cert subject: %s\n", parsed_cert_subject(authority));

			if (parsed_cert_issued_by(signer, authority)) {
				debug("Found authority record for %s\n", parsed_cert_subject(authority));
				result = buffer_alloc_write(sig_data->raw_len);
				buffer_put(result, sig_data->raw_data, sig_data->raw_len);
				parsed_cert_free(authority);
				break;
			}

			parsed_cert_free(authority);
		}

		list_num++;
	}

out:
	buffer_free(db_data);
	return result;
}
