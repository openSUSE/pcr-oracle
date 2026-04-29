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
 * Written by Alberto Planas <aplanas@suse.com>, Olaf Kirch <okir@suse.com>
 */


#include <stdlib.h>
#include <sys/dir.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <limits.h>
#include <unistd.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>

#include "uapi.h"
#include "util.h"

#define UAPI_LINE_MAX		1024


static int	vercmp(const void *va, const void *vb);

static uapi_boot_entry_t *
uapi_boot_entry_new(void)
{
	uapi_boot_entry_t *ube;

	ube = calloc(1, sizeof(*ube));
	return ube;
}

static void
drop_boot_entry(uapi_boot_entry_t **entry_p)
{
	if (*entry_p) {
		uapi_boot_entry_free(*entry_p);
		*entry_p = NULL;
	}
}

static uapi_boot_entry_t *
uapi_boot_entry_load(const char *path)
{
	uapi_boot_entry_t *result = NULL;
	char line[UAPI_LINE_MAX];
	FILE *fp;

	if (!(fp = fopen(path, "r"))) {
		error("Unable to open %s: %m\n", path);
		return NULL;
	}

	result = uapi_boot_entry_new();
	while (fgets(line, sizeof(line), fp)) {
		char *key, *value;
		unsigned int i;

		if (!isalpha(line[0]))
			continue;

		/* strip white space off the end */
		i = strlen(line);
		while (i > 0 && isspace(line[i-1]))
			line[--i] = '\0';

		key = line;
		for (i = 0; line[i]; ++i) {
			if (isspace(line[i])) {
				line[i++] = '\0';
				break;
			}
		}

		while (isspace(line[i]))
			++i;
		value = line + i;
		if (*value == '\0')
			value = NULL;

                if (!strcmp("sort-key", key))
			assign_string(&result->sort_key, value);
                else
                if (!strcmp("machine-id", key))
			assign_string(&result->machine_id, value);
                else
                if (!strcmp("version", key))
			assign_string(&result->version, value);
                else
                if (!strcmp("options", key))
			assign_string(&result->options, value);
                else
                if (!strcmp("linux", key))
			assign_string(&result->image_path, value);
                else
                if (!strcmp("initrd", key))
			assign_string(&result->initrd_path, value);
        }

        fclose(fp);
	return result;
}

static bool
uapi_boot_entry_applies(const uapi_boot_entry_t *entry, const char *machine_id, const char *architecture)
{
	if (entry->machine_id && machine_id && strcmp(entry->machine_id, machine_id))
		return false;
	if (entry->architecture && architecture && strcmp(entry->architecture, architecture))
		return false;
	return true;
}

/*
 * Returns true iff entry_a is "more recent" or "better" than entry_b
 */
static bool
uapi_boot_entry_more_recent(const uapi_boot_entry_t *entry_a, const uapi_boot_entry_t *entry_b)
{
	int r = 0;

	/* having a sort key is better than not having one. */
	r = strcmp(entry_a->sort_key? : "", entry_b->sort_key? : "");

	if (r == 0)
		r = vercmp(entry_a->version? : "", entry_b->version? : "");

	return r > 0;
}

/*
 * We pass in a best_ret pointer in case we need to extend this
 * to search more than one directory
 */
uapi_boot_entry_t *
uapi_find_matching_boot_entry(const char *dir_path,
		const uapi_kernel_entry_tokens_t *match, const char *machine_id, const char *architecture,
		uapi_boot_entry_t **best_ret)
{
	uapi_boot_entry_t *best = *best_ret;
	struct dirent *d;
	DIR *dir;

	if (!(dir = opendir(dir_path))) {
		if (errno != ENOENT)
			error("Cannot open %s for reading: %m\n", dir_path);
		return NULL;
	}

	while ((d = readdir(dir)) != NULL) {
		char config_path[PATH_MAX];
		uapi_boot_entry_t *entry;

		if (d->d_type != DT_REG)
			continue;

		if (match && !uapi_kernel_entry_tokens_match_filename(match, d->d_name))
			continue;

		snprintf(config_path, sizeof(config_path), "%s/%s", dir_path, d->d_name);
		if (!(entry = uapi_boot_entry_load(config_path))) {
			warning("Unable to process UAPI boot entry file at \"%s\"\n", config_path);
			continue;
		}

		if (uapi_boot_entry_applies(entry, machine_id, architecture)) {
			if (best == NULL || uapi_boot_entry_more_recent(entry, best)) {
				/* swap best and entry */
				uapi_boot_entry_t *tmp = best;
				best = entry;
				entry = tmp;
			}
		}

		drop_boot_entry(&entry);
	}

	closedir(dir);

	*best_ret = best;
	return best;
}

/*
 * Get the exact boot entry identified by id.
 * This is mainly for iterating over entries like
 *   for name in "/boot/efi/loader/entries/"*.conf; do
 *	pcr-oracle --boot-entry $(basename $name .conf) ...
 *   done
 */
uapi_boot_entry_t *
uapi_get_boot_entry(const char *id)
{
	char path[PATH_MAX];

	if (path_has_file_extension(id, ".conf"))
		snprintf(path, sizeof(path), "%s/%s", UAPI_BOOT_DIRECTORY, id);
	else
		snprintf(path, sizeof(path), "%s/%s.conf", UAPI_BOOT_DIRECTORY, id);

	if (access(path, R_OK) < 0)
		return NULL;

	return uapi_boot_entry_load(path);
}

uapi_boot_entry_t *
uapi_find_boot_entry(const uapi_kernel_entry_tokens_t *match, const char *machine_id)
{
	uapi_boot_entry_t *best = NULL;
	struct utsname uts;
	const char *architecture = NULL;

	if (uname(&uts) >= 0)
		architecture = uts.machine;

	return uapi_find_matching_boot_entry(UAPI_BOOT_DIRECTORY,
			match, machine_id, architecture,
			&best);
}

void
uapi_boot_entry_free(uapi_boot_entry_t *ube)
{
	drop_string(&ube->title);
	drop_string(&ube->version);
	drop_string(&ube->machine_id);
	drop_string(&ube->image_path);
	drop_string(&ube->initrd_path);
	drop_string(&ube->options);
	free(ube);
}

/*
 * Manage list of valid entry-tokens
 */
void
uapi_kernel_entry_tokens_add(uapi_kernel_entry_tokens_t *match, const char *id)
{
	if (id == NULL)
		return;

	if (match->count >= UAPI_MAX_ENTRY_TOKENS)
		fatal("%s: too many tokens\n", __func__);

	match->entry_token[match->count++] = strdup(id);
}

void
uapi_kernel_entry_tokens_destroy(uapi_kernel_entry_tokens_t *match)
{
	while (match->count)
		drop_string(&match->entry_token[--(match->count)]);
}

bool
uapi_kernel_entry_tokens_match_filename(const uapi_kernel_entry_tokens_t *token_list, const char *filename)
{
	unsigned int i;

	for (i = 0; i < token_list->count; ++i) {
		const char *token = token_list->entry_token[i];
		int len = strlen(token);
		char cc;

		if (strncmp(filename, token, len))
			continue;

		cc = filename[len];
		if (cc == '\0' || cc == '-' || cc == '.')
			return true;
	}

	return false;
}

/*
 * Version comparison
 */
static int
cmp(int a, int b)
{
	return a - b;
}

static bool
isvalid(char a)
{
	return isalnum(a) || a == '~' || a == '-' || a == '^' || a == '.';
}

static int
natoi(const char *a, unsigned int n)
{
	char line[UAPI_LINE_MAX];

	strncpy(line, a, MIN(UAPI_LINE_MAX, n));
	return atoi(line);
}

static int
vercmp(const void *va, const void *vb)
{
	/* https://uapi-group.org/specifications/specs/version_format_specification/ */
	/* This code is based on strverscmp_improved from systemd */

	const char *a = va;
	const char *b = vb;
	const char *sep = "~-^.";

	assert(a != NULL);
	assert(b != NULL);

	for(;;) {
		const char *aa, *bb;
		int r;

		while (*a != '\0' && !isvalid(*a))
			a++;
		while (*b != '\0' && !isvalid(*b))
			b++;

		/* The longer string is considered new */
		if (*a == '\0' || *b == '\0')
			return cmp(*a, *b);

		for (int i = 0; i < strlen(sep); i++) {
			char s = sep[i];

			if (*a == s || *b == s) {
				r = cmp(*a != s, *b != s);
				if (r != 0)
					return r;

				a++;
				b++;
			}
		}

		if (isdigit(*a) || isdigit(*b)) {
			for (aa = a; isdigit(*aa); aa++);
			for (bb = b; isdigit(*bb); bb++);

			r = cmp(a != aa, b != bb);
			if (r != 0)
				return r;

			r = cmp(natoi(a, aa - a), natoi(b, bb - b));
			if (r != 0)
				return r;
		} else {
			for (aa = a; isalpha(*aa); aa++);
			for (bb = b; isalpha(*bb); bb++);

			r = cmp(strncmp(a, b, MIN(aa - a, bb - b)), 0);
			if (r != 0)
				return r;

			r = cmp(aa - a, bb - b);
			if (r != 0)
				return r;
		}

		a = aa;
		b = bb;
	}
}

