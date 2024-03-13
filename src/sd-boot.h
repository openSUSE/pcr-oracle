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

#ifndef SD_BOOT_H
#define SD_BOOT_H

#include <limits.h>
#include "uapi.h"
#include "types.h"

#define SDB_MAX_ENTRIES 16
#define SDB_LINE_MAX 512

typedef struct sdb_entry_data {
	char	path[PATH_MAX];
	char	sort_key[SDB_LINE_MAX];
	char	machine_id[SDB_LINE_MAX];
	char	version[SDB_LINE_MAX];
	char	options[SDB_LINE_MAX];
	char	image[SDB_LINE_MAX];
	char	initrd[SDB_LINE_MAX];
} sdb_entry_data_t;

typedef struct sdb_entry_list {
	unsigned int		num_entries;
	sdb_entry_data_t	entries[SDB_MAX_ENTRIES];
} sdb_entry_list_t;

extern uapi_boot_entry_t *	sdb_identify_boot_entry(const char *id);
extern bool			sdb_is_boot_entry(const char *application);
extern bool			sdb_is_kernel(const char *application);
extern bool			sdb_is_initrd(const char *application);

/* This will have to update the systemd json file, and add a new entry. */
extern bool			sdb_policy_file_add_entry(const char *filename,
						const char *policy_name,
						const char *algo_name,
						unsigned int pcr_mask,
						const void *fingerprint, unsigned int fingerprint_len,
						const void *policy, unsigned int policy_len,
						const void *signature, unsigned int signature_len);

#endif /* SD_BOOT_H */
