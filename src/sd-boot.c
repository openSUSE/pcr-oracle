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
 *
 */

#include <assert.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include <json_util.h>
#include <json_object.h>

#include "sd-boot.h"
#include "util.h"

static const char *
read_entry_token(void)
{
	static char id[SDB_LINE_MAX];

	return read_single_line_file("/etc/kernel/entry-token", id, sizeof(id));
}

static const char *
read_os_release(const char *key)
{
	static char id[128];
	char line[SDB_LINE_MAX];
	unsigned int n, k;
	FILE *fp;

	if (!(fp = fopen("/etc/os-release", "r"))) {
		error("Cannot open /etc/os-release: %m\n");
		goto fail;
	}

	while (fgets(line, SDB_LINE_MAX, fp)) {
		if (strncmp(line, key, strlen(key)))
			goto next_line;

		n = strlen(key);
		while (isspace(line[n]))
			++n;

		if (line[n++] != '=')
			goto next_line;

		while (isspace(line[n]))
			++n;

		if (line[n++] != '"')
			goto next_line;

		k = 0;
		while (line[n] != '"') {
			if (line[n] == '\0')
				goto next_line;
			if (k + 1 >= sizeof(id))
				goto next_line;
			id[k++] = line[n++];
		}
		id[k] = '\0';

		fclose(fp);
		return id;

next_line:
		continue;
	}

fail:
	return NULL;
}

static const char *
read_machine_id(void)
{
	static char id[SDB_LINE_MAX];

	return read_single_line_file("/etc/machine-id", id, sizeof(id));
}

/*
 * Kernels installed by kernel-install can use a variety of IDs as entry-token.
 * Try to cater to all of them.
 */
static const uapi_kernel_entry_tokens_t *
get_valid_kernel_entry_tokens(void)
{
	static uapi_kernel_entry_tokens_t valid_tokens;
	const char *token;

	if (valid_tokens.count != 0)
		return &valid_tokens; /* I've been here before */

	if ((token = read_entry_token()) != NULL)
		uapi_kernel_entry_tokens_add(&valid_tokens, token);

	if ((token = read_machine_id()) != NULL)
		uapi_kernel_entry_tokens_add(&valid_tokens, token);

	if ((token = read_os_release("ID")) != NULL)
		uapi_kernel_entry_tokens_add(&valid_tokens, token);

	if ((token = read_os_release("IMAGE_ID")) != NULL)
		uapi_kernel_entry_tokens_add(&valid_tokens, token);

	return &valid_tokens;
}

/*
 * This should probably use UAPI boot entry logic as well
 */
bool
sdb_is_kernel(const char *application)
{
	static const char prefix[] = "linux-";
	const uapi_kernel_entry_tokens_t *match;
	char *path_copy;
	int found = 0;

	if (!application)
		return false;

	match = get_valid_kernel_entry_tokens();
	path_copy = strdup(application);

	for (char *ptr = strtok(path_copy, "/"); ptr; ptr = strtok(NULL, "/")) {
		unsigned int i;
		for (i = 0; i < match->count; ++i) {
			const char *token = match->entry_token[i];

			if (!strcmp(ptr, token))
				found |= 1;
			else if (!strncmp(ptr, prefix, sizeof(prefix) - 1))
				found |= 2;
		}
	}

	free(path_copy);
	return (found == 3);
}

/*
 * Identify the next kernel and initrd given an ID
 */
uapi_boot_entry_t *
sdb_identify_boot_entry(const char *id)
{
	uapi_kernel_entry_tokens_t id_match = { 0 };
	const uapi_kernel_entry_tokens_t *match;
	const char *machine_id;
	uapi_boot_entry_t *result = NULL;

	if (id == NULL || !strcasecmp(id, "auto")) {
		match = get_valid_kernel_entry_tokens();
	} else {
		/* Try to load the entry referenced _exactly_ by the
		 * given id. */
		result = uapi_get_boot_entry(id);
		if (result != NULL)
			goto done;

		/* No cigar, revert to a prefix based search */
		uapi_kernel_entry_tokens_add(&id_match, id);
		match = &id_match;
	}

	machine_id = read_machine_id();

	if (machine_id != NULL)
		result = uapi_find_boot_entry(match, machine_id);

done:
	uapi_kernel_entry_tokens_destroy(&id_match);
	return result;
}

/*
 * Update the systemd json file
 */
static inline bool
sdb_policy_entry_get_pcr_mask(struct json_object *entry, unsigned int *mask_ret)
{
	struct json_object *pcrs = NULL;
	unsigned int i, count;

	*mask_ret = 0;

	if (!(pcrs = json_object_object_get(entry, "pcrs"))
	 || !json_object_is_type(pcrs, json_type_array))
		return false;

	count = json_object_array_length(pcrs);
	for (i = 0; i < count; ++i) {
		struct json_object *item = json_object_array_get_idx(pcrs, i);
		int32_t pcr_index;

		if (!json_object_is_type(item, json_type_int))
			return false;
		pcr_index = json_object_get_int(item);
		if (pcr_index < 0 || pcr_index >= 32)
			return false;

		*mask_ret |= (1 << pcr_index);
	}

	return true;
}

static inline void
sdb_policy_entry_set_pcr_mask(struct json_object *entry, unsigned int pcr_mask)
{
	struct json_object *pcrs;
	unsigned int pcr_index;

	pcrs = json_object_new_array();
	json_object_object_add(entry, "pcrs", pcrs);

	for (pcr_index = 0; pcr_mask; pcr_index++, pcr_mask >>= 1) {
		if (pcr_mask & 1)
			json_object_array_add(pcrs, json_object_new_int(pcr_index));
	}
}

static struct json_object *
sdb_policy_find_or_create_entry(struct json_object *bank_obj, const void *policy, unsigned int policy_len)
{
	char formatted_policy[2 * policy_len + 1];
	struct json_object *entry;
	unsigned int i, count;

	print_hex_string_buffer(policy, policy_len, formatted_policy, sizeof(formatted_policy));

	count = json_object_array_length(bank_obj);
	for (i = 0; i < count; ++i) {
		struct json_object *child;
		const char *entry_policy;

		entry = json_object_array_get_idx(bank_obj, i);
		if (entry == NULL
		 || (child = json_object_object_get(entry, "pol")) == NULL
		 || (entry_policy = json_object_get_string(child)) == NULL) {
			/* should we warn about entries that we cannot handle? should we error out? */
			continue;
		}

		if (!strcasecmp(entry_policy, formatted_policy))
			return entry;
	}

	entry = json_object_new_object();
	json_object_array_add(bank_obj, entry);

	json_object_object_add(entry, "pol", json_object_new_string(formatted_policy));
	return entry;
}

bool
sdb_policy_file_add_entry(const char *filename, const char *policy_name, const char *algo_name, unsigned int pcr_mask,
				const void *fingerprint, unsigned int fingerprint_len,
				const void *policy, unsigned int policy_len,
				const void *signature, unsigned int signature_len)
{
	struct json_object *doc = NULL;
	struct json_object *bank_obj = NULL;
	struct json_object *entry = NULL;
	bool ok = false;

	if (access(filename, R_OK) == 0) {
		doc = json_object_from_file(filename);
		if (doc == NULL) {
			error("%s: unable to read json file: %s\n", filename, json_util_get_last_err());
			goto out;
		}

		if (!json_object_is_type(doc, json_type_object)) {
			error("%s: not a valid json file\n", filename);
			goto out;
		}
	} else if (errno == ENOENT) {
		doc = json_object_new_object();
	} else {
		error("Cannot update %s: %m\n", filename);
		goto out;
	}

	bank_obj = json_object_object_get(doc, algo_name);
	if (bank_obj == NULL) {
		bank_obj = json_object_new_array();
		json_object_object_add(doc, algo_name, bank_obj);
	} else if (!json_object_is_type(bank_obj, json_type_array)) {
		error("%s: unexpected type for %s\n", filename, algo_name);
		goto out;
	}

	entry = sdb_policy_find_or_create_entry(bank_obj, policy, policy_len);
	if (entry == NULL)
		goto out;

	sdb_policy_entry_set_pcr_mask(entry, pcr_mask);
	json_object_object_add(entry, "pkfp",
			json_object_new_string(print_hex_string(fingerprint, fingerprint_len)));
	json_object_object_add(entry, "sig",
			json_object_new_string(print_base64_value(signature, signature_len)));

	if (json_object_to_file_ext(filename, doc, JSON_C_TO_STRING_PRETTY)) {
		error("%s: unable to write json file: %s\n", filename, json_util_get_last_err());
		goto out;
	}

	ok = true;

out:
	if (doc)
		json_object_put(doc);

	return ok;
}
