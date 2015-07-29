/*-
 * Copyright (c) 2006 The FreeBSD Project
 * All rights reserved.
 *
 * Author: Victor Cruceru <soc-victor@freebsd.org>
 *
 * Redistribution of this software and documentation and use in source and
 * binary forms, with or without modification, are permitted provided that
 * the following conditions are met:
 *
 * 1. Redistributions of source code or documentation must retain the above
 *    copyright notice, this list of conditions and the following disclaimer.
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

#define BSMUX_MAX_PACKET_SIZE	1500
#define BSMUX_MAX_STR_LEN	1024

#define BSMUX_CLOSE_PDU		\
	((u_char)(ASN_CLASS_APPLICATION | 1))
	
#define BSMUX_OPEN_PDU		\
	((u_char)(ASN_CLASS_APPLICATION | ASN_TYPE_CONSTRUCTED | 0))
	
#define BSMUX_REG_REQ_PDU       \
	((u_char)(ASN_CLASS_APPLICATION | ASN_TYPE_CONSTRUCTED | 2))
	
#define BSMUX_REG_RSP_PDU       \
	((u_char)(ASN_CLASS_APPLICATION | 3))
	
#define BSMUX_SOUT_PDU	       	\
	((u_char)(ASN_CLASS_APPLICATION | 4))

#define BSMUX_GET_OP		\
	((u_char)(ASN_CLASS_CONTEXT | ASN_TYPE_CONSTRUCTED | SNMP_PDU_GET))
	
#define BSMUX_GETNEXT_OP	\
	((u_char)(ASN_CLASS_CONTEXT | ASN_TYPE_CONSTRUCTED | SNMP_PDU_GETNEXT))
	
#define BSMUX_GETRSP_OP		\
	((u_char)(ASN_CLASS_CONTEXT | ASN_TYPE_CONSTRUCTED | SNMP_PDU_RESPONSE))
	
#define BSMUX_SET_OP		\
	((u_char)(ASN_CLASS_CONTEXT | ASN_TYPE_CONSTRUCTED | SNMP_PDU_SET))
	
#define BSMUX_TRAP_OP		\
	((u_char)(ASN_CLASS_CONTEXT | ASN_TYPE_CONSTRUCTED | SNMP_PDU_TRAP))

#define BSMUX_DEL_REG		0	/* Delete a registration */
#define BSMUX_RO_REG		1	/* Register READ ONLY */
#define BSMUX_RW_REG		2	/* Register READ WRITE */

/*
 * SMUX Closing Reasons
 */
#define SCR_GOING_DOWN			((u_char)0)
#define SCR_UNSUPPORTED_VERSION		((u_char)1)
#define SCR_PACKET_FORMAT               ((u_char)2)
#define SCR_PROTOCOL_ERROR              ((u_char)3)
#define SCR_INTERNAL_ERROR		((u_char)4)
#define SCR_AUTHENTICATION_FAILURE	((u_char)5)

enum reg_status {
	S_REG_INACTIVE = 0,
	S_REG_ACTIVE = 1
};

/*
 * SMUX peer registration control block.
 *  Used to identify an ACTIVE or an INACTIVE SMUX peer
 *  A SMUX registration control block is identified by (r_oid, r_prio)
 */
struct smux_reg_cb {
	struct asn_oid		r_oid;	 	/* registered OID */					
	u_int32_t		r_prio;		/* registered priority */
	struct smux_peer_cb*	psmux;		/* pointer to smux peer */
	enum reg_status		status;
	struct snmp_node	ag_tree_node;
	u_char			reg_type;	/* set to BSMUX_RO_REG
							or BSMUX_RO_RW*/
	TAILQ_ENTRY(smux_reg_cb) link;
};

/* Peer status, according to SMUX-MIB */
enum snmp_peer_status {
	PS_VALID 	= 1,
	PS_INVALID 	= 2,
	PS_CONNECTING	= 3
};

/*
 * Structure used to represent a smux peer
 * Note that this is different from begemot_peer structure
 * which is used to store a configuration item
 */
struct smux_peer_cb {
	int32_t		index;		/* SNMP table index */
					/* ALSO socket descriptor for the peer */ 			
	struct asn_oid	identity;	/* for SNMP table */
	u_char *	description;	/* for SNMP table */
	int 		status;		/* for SNMP table */
	
	void *		sd_id;		/* as returned by fd_select() */
	struct sockaddr_in in_socket;	/* remote peer */
	
	TAILQ_ENTRY(smux_peer_cb) link;
};
TAILQ_HEAD(smux_peer_tbl, smux_peer_cb);

