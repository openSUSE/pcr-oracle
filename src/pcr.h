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

#ifndef PCR_H
#define PCR_H

#include "types.h"
#include "digest.h"

#define PCR_BANK_REGISTER_MAX	24

typedef struct tpm_pcr_bank {
	uint32_t		pcr_mask;
	uint32_t		valid_mask;
	const char *		algo_name;
	const tpm_algo_info_t *	algo_info;
	tpm_evdigest_t		pcr[PCR_BANK_REGISTER_MAX];
} tpm_pcr_bank_t;

typedef struct tpm_pcr_selection {
	unsigned int		pcr_mask;
	const tpm_algo_info_t *	algo_info;
} tpm_pcr_selection_t;

extern void		set_srk_alg (const char *alg);
extern void		set_srk_rsa_bits (const unsigned int rsa_bits);
extern void		pcr_bank_initialize(tpm_pcr_bank_t *bank, unsigned int pcr_mask, const tpm_algo_info_t *algo);
extern bool		pcr_bank_wants_pcr(tpm_pcr_bank_t *bank, unsigned int index);
extern void		pcr_bank_mark_valid(tpm_pcr_bank_t *bank, unsigned int index);
extern bool		pcr_bank_register_is_valid(const tpm_pcr_bank_t *bank, unsigned int index);
extern tpm_evdigest_t *	pcr_bank_get_register(tpm_pcr_bank_t *bank, unsigned int index, const char *algo);
extern void		pcr_bank_set_locality(tpm_pcr_bank_t *bank, unsigned int index, uint8_t locality);
extern void		pcr_bank_init_from_zero(tpm_pcr_bank_t *bank);
extern void		pcr_bank_init_from_snapshot_fp(FILE *fp, tpm_pcr_bank_t *bank);
extern void		pcr_bank_init_from_snapshot(tpm_pcr_bank_t *bank, const char *efivar_path);
extern void		pcr_bank_init_from_current(tpm_pcr_bank_t *bank);

extern bool		pcr_selection_valid_string(const char *);
extern tpm_pcr_selection_t *pcr_selection_new(const char *algo_name, const char *pcr_spec);
extern void		pcr_selection_free(tpm_pcr_selection_t *);

extern bool		pcr_read_into_bank(tpm_pcr_bank_t *bank);
extern bool		pcr_authorized_policy_create(const tpm_pcr_selection_t *pcr_selection,
				const stored_key_t *private_key_file,
				const char *output_path);
extern bool		pcr_store_public_key(const stored_key_t *private_key_file,
				const stored_key_t *public_key_file);
extern bool		pcr_policy_sign(const target_platform_t *platform, const tpm_pcr_bank_t *bank,
				const stored_key_t *private_key_file,
				const char *input_path,
				const char *output_path, const char *policy_name);
extern bool		pcr_authorized_policy_seal_secret(const target_platform_t *platform,
				const char *opt_persistent_srk, const char *authorized_policy,
				const char *input_path, const char *output_path);
extern bool		pcr_seal_secret(const target_platform_t *, const tpm_pcr_bank_t *bank,
				const char *opt_persistent_srk, const char *input_path,
				const char *output_path);
extern bool		pcr_unseal_secret(const target_platform_t *,
				const tpm_pcr_selection_t *pcr_selection,
				const char *signed_policy_path,
				const stored_key_t *public_key_file,
				const char *input_path, const char *output_path);
extern bool		pcr_policy_unseal_tpm2key(const char *input_path,
				const char *output_path);

extern const target_platform_t *pcr_get_target_platform(const char *name);

/* Flags that indicate the set of arguments required for a specific operation */
#define PLATFORM_NEED_INPUT_FILE	0x0001
#define PLATFORM_NEED_OUTPUT_FILE	0x0002
#define PLATFORM_NEED_PCR_SELECTION	0x0004
#define PLATFORM_NEED_PUBLIC_KEY	0x0008
#define PLATFORM_NEED_SIGNED_POLICY	0x0010
#define PLATFORM_OPTIONAL_PCR_POLICY	0x0020

extern unsigned int	target_platform_unseal_flags(const target_platform_t *);

#endif /* PCR_H */
