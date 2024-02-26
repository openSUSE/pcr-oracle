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
 * Written by Alberto Planas <aplanas@suse.com>
 */

#include <stdio.h>
#include "bufparser.h"
#include "runtime.h"

#define SECURE_BOOT_EFIVAR_NAME	"SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"


bool
secure_boot_enabled()
{
	buffer_t *data;
	uint8_t enabled;

	data = runtime_read_efi_variable(SECURE_BOOT_EFIVAR_NAME);
	if (data == NULL) {
		return false;
	}

	if (!buffer_get_u8(data,  &enabled)) {
		 return false;
	}

	return enabled == 1;
}
