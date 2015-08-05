/* $FreeBSD$ */

/*-
 * Copyright (c) 2015 Bruce Simpson.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _XHCI_DBC_H_
#define	_XHCI_DBC_H_

/*
 * xHCI Debug Capability Context [Sec. 7.6.9.1]
 */

enum xhci_dbcic_desc {
	DBCIC_STR0_DESC	= 0,
	DBCIC_VENDOR_DESC,
	DBCIC_PRODUCT_DESC,
	DBCIC_SERIAL_DESC
};
#define DBCIC_MAX_DESCS		4

/*
 * Controller-visible structures.
 */

struct xhci_dbc_ic {
	uint64_t	 aqwDesc[DBCIC_MAX_DESCS];
	uint8_t		 abyStrlen[DBCIC_MAX_DESCS];
	uint32_t	 dwReserved[7];
} __packed;

struct xhci_dbc_ctx {
	struct xhci_dbc_ic	dbcic;
	struct xhci_endp_ctx	ctx_out; 	/* [Sec. 6.2.3] */
	struct xhci_endp_ctx	ctx_in;
} __packed;

/*
 * Host-side structures.
 */

/* XXX TODO */

#endif /* _XHCI_DBC_H_ */
