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

#ifndef UAPI_H
#define UAPI_H

#include "types.h"

struct uapi_boot_entry {
	char *		title;
	bool		efi;
	char *		sort_key;
	char *		version;
	char *		machine_id;
	char *		architecture;
	char *		image_path;
	char *		initrd_path;
	char *		options;
};

#define UAPI_MAX_ENTRY_TOKENS	8
typedef struct uapi_kernel_entry_tokens {
	unsigned int	count;
	char *		entry_token[UAPI_MAX_ENTRY_TOKENS];
} uapi_kernel_entry_tokens_t;

#define UAPI_BOOT_DIRECTORY_EFI	"/loader/entries"
#define UAPI_BOOT_DIRECTORY	"/boot/efi" UAPI_BOOT_DIRECTORY_EFI

extern uapi_boot_entry_t *	uapi_get_boot_entry(const char *id);
extern uapi_boot_entry_t *	uapi_find_boot_entry(const uapi_kernel_entry_tokens_t *match, const char *machine_id);
extern void			uapi_boot_entry_free(uapi_boot_entry_t *);
extern void			uapi_kernel_entry_tokens_add(uapi_kernel_entry_tokens_t *, const char *);
extern void			uapi_kernel_entry_tokens_destroy(uapi_kernel_entry_tokens_t *);
extern bool			uapi_kernel_entry_tokens_match_filename(const uapi_kernel_entry_tokens_t *, const char *filename);

#endif /* UAPI_H */
