/*
 *   Copyright (C) 2025 SUSE LLC
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
 * Written by Gary Lin <glin@suse.com>
 */

#include <stdbool.h>

#include "bufparser.h"
#include "eventlog.h"
#include "runtime.h"

/* Process Compact Hash Events */

static void
__tpm_event_compact_hash_destroy(tpm_parsed_event_t *parsed)
{
	drop_string(&parsed->compact_hash_event.prep_partition);
}

static const char *
__tpm_event_compact_hash_describe(const tpm_parsed_event_t *parsed)
{
	return "Compact Hash";
}

static const tpm_evdigest_t *
__prep_bootloader_rehash (const struct compact_hash_event *evspec, tpm_event_log_rehash_ctx_t *ctx)
{
	const tpm_evdigest_t *md;

	debug("Computing digest of the bootloader in PReP partition\n");
	if (evspec->prep_partition == NULL)
		return NULL;

	md = runtime_digest_prep_booloader(ctx->algo, evspec->prep_partition);

	return md;
}

static const tpm_evdigest_t *
__tpm_event_compact_hash_rehash(const tpm_event_t *ev, const tpm_parsed_event_t *parsed, tpm_event_log_rehash_ctx_t *ctx)
{
	const struct compact_hash_event *evspec = &parsed->compact_hash_event;

	/* Copy the digest for the normal Compact Hash events */
	if (evspec->prep_partition == NULL)
		return tpm_event_get_digest(ev, ctx->algo);

	/* Rehash the bootloader in the PReP partition */
	return __prep_bootloader_rehash(evspec, ctx);
}

bool
__tpm_event_parse_compact_hash(tpm_event_t *ev, tpm_parsed_event_t *parsed, buffer_t *bp)
{
	struct compact_hash_event *evspec = &parsed->compact_hash_event;

	parsed->destroy = __tpm_event_compact_hash_destroy;
	parsed->describe = __tpm_event_compact_hash_describe;
	parsed->rehash = __tpm_event_compact_hash_rehash;

	/* Only handle the Compact Hash event with "BOOTLOADER" in the event data */
	if (bp->size != 10 || memcmp(bp->data, "BOOTLOADER", 10) != 0)
		return true;

	/* Locate the PReP partition */
	if (!(evspec->prep_partition = runtime_locate_prep_partition()))
		return false;

	return true;
}
