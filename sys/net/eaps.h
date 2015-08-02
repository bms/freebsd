#ifndef _NET_EAPS_H_
#define _NET_EAPS_H_
/*-
 * Copyright (c) 2015 Bruce Simpson.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
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
 *
 * $FreeBSD$
 */

/*
 * Extreme Active Protection System (EAPS) definitions.
 * Normative reference: draft-shah-extreme-rfc3619bis-02 [Expired I-D]
 */

/*
 * Extreme Networks proprietary MAC addresses.
 */
#define	EXTREME_OUI_INIT	{ 0x00, 0xE0, 0x2B }
#define	EDP_ETHERADDR_INIT	{ 0x00, 0xE0, 0x2B, 0x00, 0x00, 0x00 }
#define	EAPS_ETHERADDR_INIT	{ 0x00, 0xE0, 0x2B, 0x00, 0x00, 0x04 }

/*
 * EDP/EAPS packets are SNAP encapsulated on Ethernet.
 * dsap/ssap are LLV_SNAP_LSAP, llc_control is LLC_UI,
 * oui is EXTREME_OUI, PID is EDP.
 * The outer edp_hdr encapsulates an EAPS payload as a set of TLVs.
 */
#define EDP_SNAP_PID 0x00BB

/*
 * Extreme Discovery Protocol (EDP) header.
 */
struct edp_hdr {
	uint8_t		edp_version;		/* EDP_VERSION_1 */
	uint8_t		edp_reserved00;		/* must be zero */
	uint16_t	edp_len;		/* Payload length including edp_hdr */
	uint16_t	edp_cksum;		/* RFC 1071-like */
	uint16_t	edp_seq;		/* simple monotonic */
	uint16_t	edp_devid;		/* 0 for MAC address */
	struct ether_addr edp_dev_mac;		/* 48 bits */
	/* followed by 0..N TLVs. */
} __packed;
#define EDP_VERSION_1	0x01

/*
 * EDP Tag-Length-Value (TLV) header.
 * Minimum length: 32 bits (length: 0x0004).
 */
struct edp_tlv_hdr {
	uint8_t		 etv_marker;	/* always set to EDP_MARKER 0x99 */
	uint8_t		 etv_tag;	/* Tag: see below. */
	uint16_t	 etv_len;	/* network-endian; includes this header */
	/* followed by [0..etv_len] octets */
} __packed;

#define	EDP_MARKER	0x99	/* etv_marker constant */
#define EDP_TAG_NULL	0x00	/* No-op, length must be 0x04. */
#define EDP_TAG_ESRP	0x08	/* Extreme Standby Router Protocol (undocumented) */
#define EDP_TAG_EAPS	0x0B	/* RFC 3619 Extreme Active Protection System */

/*
 * EAPS TLV payload.
 */
struct eaps_pdu {
	uint8_t		eaps_version;	/* Always EAPS_VERSION_1 (for now) */
	uint8_t		eaps_type;	/* PDU type */
	uint16_t	eaps_cvlan;	/* Control VLAN Tag ID */
	uint32_t	eaps_rsvd0;	/* Reserved; set to zero */
	struct ether_addr eaps_origin;	/* Originating MAC address */
	uint16_t	eaps_hello;	/* HELLO interval (hardcoded) */
	uint16_t	eaps_fail;	/* FAIL interval (set by master) */
	uint8_t		eaps_state;	/* EAPS_S_xxx; see below */
	uint8_t		eaps_rsvd1;	/* Reserved; set to zero */
	uint16_t	eaps_seq;	/* Health PDU sequence number */	
	uint16_t	eaps_rsvd1[38];	/* Reserved; set to zero */
} __packed;

#define EAPS_VERSION_1		0x01	/* EAPSv1; may support v2 in future */
#define EAPS_HELLO_INTERVAL	0x04	/* hardcoded value of eaps_hello */

/*
 * EAPS PDU Types
 */
#define	EAPS_P_HEALTH		0x05	/* Polling for ring health */
#define	EAPS_P_RING_UP		0x06	/* Master indicates link is up */
#define	EAPS_P_RING_DOWN	0x07	/* Master indicates link is down  */
#define	EAPS_P_LINK_DOWN	0x08	/* Peer indicates link is down */
#define	EAPS_P_FLUSH		0x0D	/* Topology change: flush FDB for domain */
#define	EAPS_P_LINK_QUERY	0x0F	/* Link status query from peer */
#define	EAPS_P_LINK_UP		0x10	/* Peer indicates link is up */

/*
 * EAPS ring node states
 */
#define	EAPS_S_IDLE		0x00	/* EAPS Domain (Master/Transit) not running */
#define	EAPS_S_COMPLETE		0x01	/* Master node in COMPLETE state */
#define	EAPS_S_FAILED		0x02	/* Master node in FAILED state */
#define	EAPS_S_LINKS_UP		0x03	/* Transit UP: Pri & Sec ring ports are up */
#define	EAPS_S_LINK_DOWN	0x04 	/* Transit DOWN: Pri and/or Sec ports down */
#define	EAPS_S_PREFORWARD	0x05	/* Transit in PREFORWARDING State */
#define	EAPS_S_INIT		0x06	/* Master node in INIT state */

#endif /* _NET_EAPS_H_ */
