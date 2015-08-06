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
#define DBCIC_MAX_DESCS		4	/* number of descriptors in DbC IC */
#define DBCIC_DESC_SIZE_MAX	256	/* maximum size of each descriptor */

/*
 * Controller-visible structures.
 */

struct xhci_dbc_ic {
	uint64_t	 aqwDesc[DBCIC_MAX_DESCS];
	uint8_t	 abyStrlen[DBCIC_MAX_DESCS];
	uint32_t	 dwReserved[7];
} __packed;

struct xhci_dbc_ctx {
	struct xhci_dbc_ic		 dbcic;	/* Info context; 'personality' */
	struct xhci_endp_ctx	 ctx_out; 	/* [Sec. 6.2.3] */
	uint32_t			 reserved00[8];
	struct xhci_endp_ctx	 ctx_in;
	uint32_t			 reserved01[8];
} __packed;

/*
 * Kernel-visible structures.
 */

/* 'usb/' + 'xhci' + 'NNNNNN' + '-dbc' + '\0' + 2*pad := 80 bytes */
#define DBC_PROCNAMELEN (4 + SPECNAMELEN + 6 + 4 + 1 + 2)

/* XXX name */
/* XXX watch for cache line effects */
struct xhci_dbc {
	struct usb_page_cache	 dbc_pc;
	struct usb_page_cache	 dbc_pg;
	
	struct usb_process		 dbc_proc;
	struct mtx			 dbc_mtx;
	
	char				 dbc_procname[DBC_PROCNAMELEN];
};

/*
 * There are no user-visible structures.
 */

#endif /* _XHCI_DBC_H_ */
