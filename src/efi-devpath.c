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

#include <string.h>
#include <limits.h>


#include "eventlog.h"
#include "bufparser.h"
#include "util.h"

extern const char *	tpm_event_decode_uuid(const unsigned char *data);

bool
__tpm_event_parse_efi_device_path(efi_device_path_t *path, buffer_t *bp)
{
	while (!buffer_eof(bp)) {
		struct efi_device_path_item *item;

		if (path->count >= EFI_DEVICE_PATH_MAX)
			fatal("Cannot parse EFI device path - too many entries");
		item = &path->entries[path->count++];

		if (!buffer_get_u8(bp, &item->type)
		 || !buffer_get_u8(bp, &item->subtype)
		 || !buffer_get_u16le(bp, &item->len))
			return false;

		if (item->len < 4)
			return false;

		/* encoded len includes the size of the header */
		item->len -= 4;

		item->data = malloc(item->len);
		if (!buffer_get(bp, item->data, item->len))
			return false;
	}

	return true;
}

/*
 * Handle EFI device path information in a rudimentary fashion.
 * Enought to locate the mentioned files in the file system.
 */
static const char *
__efi_device_path_type_to_string(unsigned int type, unsigned int subtype)
{
	static char retbuf[128];
	const char *type_string;

	switch (type) {
	case TPM2_EFI_DEVPATH_TYPE_HARDWARE_DEVICE:
		type_string = "hardware"; break;
	case TPM2_EFI_DEVPATH_TYPE_ACPI_DEVICE:
		if (subtype == TPM2_EFI_DEVPATH_ACPI_SUBTYPE_ACPI)
			return "ACPI";

		type_string = "acpi"; break;
	case TPM2_EFI_DEVPATH_TYPE_MESSAGING_DEVICE:
		if (subtype == TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_SATA)
			return "SATA";

		type_string = "messaging"; break;
	case TPM2_EFI_DEVPATH_TYPE_MEDIA_DEVICE:
		switch (subtype) {
		case TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_HARDDRIVE:
			return "harddrive";
		case TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_CDROM:
			return "cdrom";
		case TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_VENDOR:
			return "vendor";
		case TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_FILE_PATH:
			return "file-path";
		case TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_MEDIA_PROTOCOL:
			return "media-protocol";
		case TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_PIWG_FIRMWARE:
			return "piwg-firmware";
		case TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_PIWG_FIRMWARE_VOLUME :
			return "piwg-firmware-volume";
		case TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_RELATIVE_OFFSET_RANGE :
			return "relative-offset-range";
		case TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_RAMDISK:
			return "ramdisk";
		}
		type_string = "hardware";
		break;
	case TPM2_EFI_DEVPATH_TYPE_BIOS_BOOT_DEVICE:
		type_string = "BIOS bootdev"; break;
	case TPM2_EFI_DEVPATH_TYPE_END:
		return "end";
	default:
		snprintf(retbuf, sizeof(retbuf), "type%u/subtype%u", type, subtype);
		return retbuf;
	}

	snprintf(retbuf, sizeof(retbuf), "%s/subtype%u", type_string, subtype);
	return retbuf;
}

const char *
__tpm_event_efi_device_path_item_harddisk_uuid(const struct efi_device_path_item *item)
{
	if (item->type == TPM2_EFI_DEVPATH_TYPE_MEDIA_DEVICE
	 && item->subtype == TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_HARDDRIVE)
		return tpm_event_decode_uuid(item->data + 20);

	return NULL;
}

const char *
__tpm_event_efi_device_path_item_file_path(const struct efi_device_path_item *item)
{
	static char file_path[PATH_MAX];

	if (item->type == TPM2_EFI_DEVPATH_TYPE_MEDIA_DEVICE
	 && item->subtype == TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_FILE_PATH) {
		buffer_t file_path_buf;
		char *s;

		if (item->len / 2 >= sizeof(file_path))
			return NULL;

		buffer_init_read(&file_path_buf, item->data, item->len);
		s = buffer_get_utf16le(&file_path_buf, item->len / 2);
		if (s == NULL)
			return NULL;

		strncpy(file_path, s, sizeof(file_path) - 1);
		free(s);

		/* convert path\name into path/name */
		return path_dos2unix(file_path);
	}

	return NULL;
}

static const char *
__tpm_event_efi_device_path_item_pnp_name(const struct efi_device_path_item *item)
{
	static char name_path[32];

	if (item->type == TPM2_EFI_DEVPATH_TYPE_ACPI_DEVICE) {
		uint32_t pnp_hid, pnp_uid;
		buffer_t buf;

		buffer_init_read(&buf, item->data, item->len);

		/* The ACPI device path component encodes PNP0a03 as 0x0a0x41d0 */
		if (!buffer_get_u32le(&buf, &pnp_hid) || ((pnp_hid & 0xFFFF) != 0x41d0))
			return NULL;

		pnp_hid >>= 16;

		if (!buffer_get_u32le(&buf, &pnp_uid))
			return NULL;

		if (pnp_uid)
			snprintf(name_path, sizeof(name_path), "PNP%04X.%d", pnp_hid, pnp_uid);
		else
			snprintf(name_path, sizeof(name_path), "PNP%04X", pnp_hid);
		return name_path;
	}

	return NULL;
}

static void
__tpm_event_efi_device_path_item_print(const struct efi_device_path_item *item, tpm_event_bit_printer *print_fn)
{
	const char *string;

	if (item->type == TPM2_EFI_DEVPATH_TYPE_END) {
		print_fn("  end\n");
		return;
	}

	if ((string = __tpm_event_efi_device_path_item_harddisk_uuid(item)) != NULL) {
		print_fn("  harddisk   part-uuid=%s\n", string);
		return;
	}

	if ((string = __tpm_event_efi_device_path_item_file_path(item)) != NULL) {
		print_fn("  file-path  \"%s\"\n", string);
		return;
	}

	if ((string = __tpm_event_efi_device_path_item_pnp_name(item)) != NULL) {
		print_fn("  ACPI       %s\n", string);
		return;
	}

	if (item->type == TPM2_EFI_DEVPATH_TYPE_HARDWARE_DEVICE) {
		if (item->subtype == TPM2_EFI_DEVPATH_HARDWARE_SUBTYPE_PCI) {
			unsigned char pci_dev, pci_fn;

			pci_dev = ((unsigned char *) item->data)[1];
			pci_fn = ((unsigned char *) item->data)[0];
			print_fn("  PCI        %02x.%d\n", pci_dev, pci_fn);
			return;
		}
	}

	/* hard drive seems to have the UUID at offset 20 in item->data */

	print_fn("  %-10s len=%d data=%s\n",
			__efi_device_path_type_to_string(item->type, item->subtype),
			item->len,
			print_octet_string(item->data, item->len));
}

void
__tpm_event_efi_device_path_print(const efi_device_path_t *path, tpm_event_bit_printer *print_fn)
{
	const struct efi_device_path_item *item;
	unsigned int i;

	for (i = 0, item = path->entries; i < path->count; ++i, ++item) {
		__tpm_event_efi_device_path_item_print(item, print_fn);
	}
}

void
__tpm_event_efi_device_path_destroy(efi_device_path_t *path)
{
	unsigned int i;

	for (i = 0; i < path->count; ++i) {
		struct efi_device_path_item *item = &path->entries[i];

		free(item->data);
	}
	memset(path, 0, sizeof(*path));
}

