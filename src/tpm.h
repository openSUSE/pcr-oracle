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


#ifndef TPM_H
#define TPM_H

#include <stdbool.h>
#include <tss2_esys.h>

extern uint32_t		esys_tr_rh_null;
extern uint32_t		esys_tr_rh_owner;

extern TPM2B_PUBLIC	RSA_SRK_template;
extern TPM2B_PUBLIC	ECC_SRK_template;

extern ESYS_CONTEXT *	tss_esys_context(void);
extern void		tss_print_error(int rc, const char *msg);

extern TPM2B_PUBLIC *	tss_read_public_key(const char *);
extern bool		tss_write_public_key(const char *, const TPM2B_PUBLIC *);

static inline bool
tss_check_error(int rc, const char *msg)
{
	if (rc == TSS2_RC_SUCCESS)
		return true;
	tss_print_error(rc, msg);
	return false;
}

#endif /* TPM_H */
