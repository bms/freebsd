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
#include <sys/cdefs.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <assert.h>
#include <sys/limits.h>
#include <errno.h>

#include "snmpmod.h"
#include "snmppriv.h"		/* XXX SMUX must see bsnmpd internals. */
#include "smux_snmp.h"
#include "smux_oid.h"
#include "smux_proto.h"
#include "smux_tree.h"

/* Prototypes */
static int	op_smuxProto(struct snmp_context *, struct snmp_value *, 
			     u_int, u_int, enum snmp_op);

TAILQ_HEAD(registration_list, smux_reg_cb);
static struct registration_list registration_list =
    TAILQ_HEAD_INITIALIZER(registration_list);

/* SMUX protocol peers. [Sorted on smux_peer_cb.index] */
/* XXX Should be static TAILQ_INIT */
static struct smux_peer_tbl smux_peer_tbl =
	TAILQ_HEAD_INITIALIZER(smux_peer_tbl);

/*
 * Set the read timeout for the connection with a SMUX peer
 */
static void
smux_set_timeout(struct smux_peer_cb *pcb, uint32_t timeout)
{
	struct timeval rcvTimeout;
	
	rcvTimeout.tv_sec = timeout;
	rcvTimeout.tv_usec = 0;

	if(setsockopt(pcb->index, SOL_SOCKET, SO_RCVTIMEO, &rcvTimeout,
		sizeof(rcvTimeout) ) < 0) {
		syslog(LOG_WARNING,
		  "setsockopt / SO_RCVTIMEO / %d sec failed: %m", timeout);
		
	}
	SMUXDBG("Rcv timeout set to %d for peer %s", timeout,
		asn_oid2str(&pcb->identity));
	
}	

/*
 * Comparator. Used by INSERT_OBJECT_FUNC_LINK().
 */
static int
smux_reg_cmp(const struct smux_reg_cb *a, const struct smux_reg_cb *b)
{
	assert(a != NULL);
	assert(b != NULL);
	int result = 0;
	if ( (result = asn_compare_oid(&a->r_oid, &b->r_oid)) != 0)
		return result;
	
	if (a->r_prio < b->r_prio)
		return (-1);
	else
	if (a->r_prio > b->r_prio)
		return (+1);
	else
		return (0);			
}

/*
 * Comparator. Used by [NEXT|FIND]_OBJECT_FUNC_LINK().
 */
static int
smux_reg_idx_cmp(const struct asn_oid *oid, u_int sub,
    const struct smux_reg_cb *e)
{
	u_int i;
	
	for (i = 0; i < e->r_oid.len + 1 && i < oid->len - sub; i++) {
		if (i < e->r_oid.len) {
			if (oid->subs[sub + i] < e->r_oid.subs[i])
				return (-1);
			if (oid->subs[sub + i] > e->r_oid.subs[i])
				return (+1);
		} else {
			/* here i == e->r_oid.len  */
			if (oid->subs[sub + i] < e->r_prio)
				return (-1);
			if (oid->subs[sub + i] > e->r_prio)
				return (+1);
		}	
	}
	
	if (oid->len - sub < e->r_oid.len + 1)
		return (-1);
	if (oid->len - sub > e->r_oid.len + 1)
		return (+1);

	return (0);
}
	
/*
 * Next function iterates the list of registration to find
 * the maximum priority. The list of registrations is
 * kept sorted by (r_oid, r_prio)
 */
static uint32_t
find_max_prio(struct smux_reg_cb* const rcb)
{
	struct smux_reg_cb* entry;
	uint32_t max_prio;

	assert(rcb != NULL);

	/* rcb must be in list */
	entry = rcb;
	max_prio = rcb->r_prio;
	while (entry != NULL &&
		asn_compare_oid(&entry->r_oid, &rcb->r_oid) <= 0 ) {
  		max_prio = entry->r_prio;
  		entry = TAILQ_NEXT(entry, link);
  	}
	return (max_prio); 		
}

/*
 * Compare 2 oids up to the maximum common length
 */
static int
smux_oid_scoped_cmp(const struct asn_oid* o1, const struct asn_oid* o2)
{
	int 	 i;
	int	 min_len;
	
	assert(o1 != NULL);
	assert(o2 != NULL);

	min_len = (o1->len < o2->len ? o1->len: o2->len);
	for (i = 0; i < min_len; i++) {
		if (o1->subs[i] < o2->subs[i])
			return (-1);
		if (o1->subs[i] > o2->subs[i])
			return (+1);
	}
	return (0);    	

}

/*
 * Find an ACTIVE registration by its OID.
 * Returns NULL if nothing found
 */
static struct smux_reg_cb *
find_smux_reg(struct asn_oid *oid)
{
	struct smux_reg_cb* entry = NULL;
	
	assert(oid != NULL);
	
	TAILQ_FOREACH(entry, &registration_list, link) {
		if (entry->status == S_REG_INACTIVE)
			continue;
		if (asn_is_suboid(&entry->r_oid, oid))
			return (entry);
	}
	return (NULL);
	
}

/*
 * Find an alternative registration for the ACTIVE registration passed
 * as parameter. Returned registration will be an INACTIVE one
 * Used to find an alternative candidate to replace an active registration
 * Best matched oid are considered first - then priority
 *
 * Example: 1.2.3 will be replaced 1.2.3.1 and not with 1.2.3.1.7
 *	if an inactive reg for 1.2.3 does not exist
 *
 * Another example: 1.2.3 will be replaced with (1.2.3.7, 2) and not
 *	with (1.2.3.7, 5)
 */
static struct smux_reg_cb *
smux_find_alt_reg(struct smux_reg_cb* active)
{
	struct smux_reg_cb* entry;
	struct smux_reg_cb* candidate;
	int diff_length;
	int min_diff_length;
	
	assert(active != NULL);
	
	min_diff_length = INT_MAX;
	candidate = NULL;
	
	TAILQ_FOREACH(entry, &registration_list, link) {
		if (entry->status == S_REG_ACTIVE)
			continue;
		if (entry == active)
			continue;
		if (!asn_is_suboid(&active->r_oid, &entry->r_oid))
			continue;
		diff_length = entry->r_oid.len - active->r_oid.len; 	 	
		assert(diff_length >= 0);
		if (diff_length < min_diff_length) {
			min_diff_length = diff_length;
			candidate = entry;
		} else if (diff_length == min_diff_length) {
			if (entry->r_prio < candidate->r_prio)
				candidate = entry;
		}
	}
	assert(active != candidate);
	return (candidate);
}

/*
 * Fill in the snmp tree node for a given registration.
 * Then attach it to the list of nodes in SNMP agent.
 */
static void
agent_register(struct smux_reg_cb *r)
{
	r->ag_tree_node.oid = r->r_oid; 	
	r->ag_tree_node.name = "smux";
	r->ag_tree_node.type = SNMP_NODE_SMUX;
	r->ag_tree_node.syntax = SNMP_SYNTAX_NULL;
	r->ag_tree_node.op= op_smuxProto;
	tree_register_oid(&r->ag_tree_node, smux_module);
	SMUXDBG("OID %s registered with master agent",
		asn_oid2str(&r->ag_tree_node.oid));
}


static void
agent_unregister(struct smux_reg_cb *r)
{
	tree_unregister_oid(&r->ag_tree_node, smux_module);
	SMUXDBG("OID %s UNREGISTERED from master agent",
		asn_oid2str(&r->ag_tree_node.oid));
	
}

/*
 * Detach an existing registration from agent.
 *
 * If any candidate is found then this will be registered to the agent.
 * Note that the registration to be decoupled is removed from the list
 * and its memory it is freed.
 */
static void
smux_decouple_registration(struct smux_reg_cb *r)
{

	assert(r != NULL);
	TAILQ_REMOVE(&registration_list, r, link);
	if (r->status == S_REG_ACTIVE) {
		struct smux_reg_cb* candidate;
		/* unregister the entry's tree from agent */
		agent_unregister(r);
		candidate = smux_find_alt_reg(r);
		if (candidate != NULL) {
			candidate->status = S_REG_ACTIVE;
			SMUXDBG("Found candidate -> %s ",
				asn_oid2str(&candidate->ag_tree_node.oid));
			/* register the candidate's tree with agent*/
			agent_register(candidate);
		}
		
	}	
	free(r);	
}			

/*
 * Free a SMUX peer.
 * Registrations are freed also if del_registrations is non-zero.
 */
static void
destroy_peer_cb(struct smux_peer_cb *pcb, int del_registrations)
{

	assert(pcb != NULL);
	if (pcb->sd_id != NULL)
 		fd_deselect(pcb->sd_id);
           	 	
 	(void)close(pcb->index);
 	if (del_registrations) {
 		struct smux_reg_cb *e, *etmp;
		TAILQ_FOREACH_SAFE(e, &registration_list, link, etmp)
			if(e->psmux == pcb)
				smux_decouple_registration(e);	
        }   	 	

	free(pcb);
 	if (smux_peer_count > 0)
 		smux_peer_count--;
}


void
smux_shutdown_peer_by_id(const struct asn_oid* id)
{
	struct smux_peer_cb *entry = NULL;
	
	assert(id != NULL);
	
	TAILQ_FOREACH(entry, &smux_peer_tbl, link) {
		if (asn_compare_oid(&entry->identity, id) == 0)
		break;		
	}
	if (entry == NULL)
		return;
		
	TAILQ_REMOVE(&smux_peer_tbl, entry, link);
	destroy_peer_cb(entry, 1);
	
}

/*
 *  Send a CLOSE PDU SMUX message
 *  for the specified SMUX protocol contol block.
 *  close_reason parameter must be from SCR_* macros above
 *
 *  ClosePDU ::=
 *      [APPLICATION 1] IMPLICIT
 *          INTEGER {
 *              goingDown(0),
 *              unsupportedVersion(1),
 *              packetFormat(2),
 *              protocolError(3),
 *              internalError(4),
 *              authenticationFailure(5)
 *          }
 */
static void
smux_send_close_pdu(struct smux_peer_cb *pcb, u_char close_reason)
{
	u_char close_pdu[3];
	int	res;

	close_pdu[0] = BSMUX_CLOSE_PDU;
	close_pdu[1] = 1;
	close_pdu[2] = close_reason;
    	res = send(pcb->index, &close_pdu[0], sizeof(close_pdu), 0);
	if (res < 0) {
   		syslog( LOG_ERR,
   	  	 "Failed to send CLOSE PDU for peer %s:%d",
	   	 inet_ntoa(pcb->in_socket.sin_addr),
           	 ntohs(pcb->in_socket.sin_port));        	
    	}	
}

/*
 *  SOutPDU ::=
 *      [APPLICATION 4] IMPLICIT
 *          INTEGER {
 *              commit(0),
 *              rollback(1)
 *          }
 *
 *  END
 */
static void
smux_send_sout_pdu(struct smux_peer_cb *pcb, u_char sout_type)
{
	u_char	sout_pdu[3];
	int	res;

	sout_pdu[0] = BSMUX_SOUT_PDU;
	sout_pdu[1] = 1;
	sout_pdu[2] = sout_type;
        res = send(pcb->index, &sout_pdu[0],sizeof(sout_pdu),0);
        if (res != sizeof(sout_pdu))
              syslog(LOG_ERR, "%s: socket send failed: %m",__func__);
}

/*
 *  RRspPDU ::=
 *      [APPLICATION 3] IMPLICIT
 *          INTEGER {
 *              failure(-1)
 *
 *             -- on success the non-negative priority is returned
 *          }
 */
static void
smux_send_rrsp_pdu(struct smux_peer_cb *pcb, int32_t prio)
{
	struct asn_buf	 b;
	u_char		 buf[32];
	u_char		*xbuf;
	
	b.asn_ptr = buf;
        b.asn_len = sizeof(buf);

	if (asn_put_temp_header(&b, BSMUX_REG_RSP_PDU, &xbuf) != ASN_ERR_OK) {
		SMUXDBG("asn_put_temp_header failed");
		return;
	}
        if (asn_put_integer(&b, prio) != ASN_ERR_OK) {
		SMUXDBG("asn_put_integer(priority) failed");
		return;
        }

	if (asn_commit_header(&b, xbuf, NULL) != ASN_ERR_OK) {
		SMUXDBG("asn_commit_header failed");
		return;
	}
	assert(b.asn_ptr - &buf[0] > 0);
        if (send(pcb->index, &buf[0], b.asn_ptr - &buf[0], 0) !=
        	b.asn_ptr - &buf[0]) {
              syslog(LOG_ERR, "%s: socket send failed: %m",__func__);
	}
}

/*
 *  SimpleOpen ::=
 *      [APPLICATION 0] IMPLICIT
 *          SEQUENCE {
 *              version     -- of SMUX protocol
 *                  INTEGER {
 *                      version-1(0)
 *                  },
 *
 *              identity    -- of SMUX peer, authoritative
 *                  OBJECT IDENTIFIER,
 *
 *              description -- of SMUX peer, implementation-specific
 *                  DisplayString,
 *
 *              password    -- zero length indicates no authentication
 *                  OCTET STRING
 *          }
 *
 *
 */
static int
handle_smux_open_pdu(struct smux_peer_cb* pcb, struct asn_buf* abuf)
{
	static char password[BSMUX_MAX_STR_LEN + 1];
	uint32_t	 timeout;
	int32_t		 version;
	int		 str_len;
	asn_len_t	 len;
	u_char		 type;
	
	assert(pcb != NULL);
	assert(abuf != NULL);
	
	SMUXDBG("OPEN PDU/ read %d bytes",abuf->asn_len);
	if (asn_get_header(abuf, &type, &len) != ASN_ERR_OK) {
   		syslog( LOG_ERR, "Failed to asn_get_header/OPEN PDU for peer %s:%d",
	   	 inet_ntoa(pcb->in_socket.sin_addr),
           	 ntohs(pcb->in_socket.sin_port));
		smux_send_close_pdu(pcb, SCR_PACKET_FORMAT);
		return (-1);
	}
	
	if (type != BSMUX_OPEN_PDU) {
   		syslog( LOG_ERR,
   	  	 "Packet is not an OPEN PDU  as expected for peer %s:%d",
	   	 inet_ntoa(pcb->in_socket.sin_addr),
           	 ntohs(pcb->in_socket.sin_port));
		smux_send_close_pdu(pcb, SCR_PROTOCOL_ERROR);
		return (-1);
	}
	SMUXDBG("ASN HEADER received is BSMUX_OPEN_PDU/ length = %d", len);
	
	if (asn_get_integer(abuf, &version) != ASN_ERR_OK) {
		SMUXDBG("Cannot decode OPEN_PDU.version");
		smux_send_close_pdu(pcb, SCR_PACKET_FORMAT);
		return (-1);
	}
	if (version != 0) {
		SMUXDBG("Received OPEN_PDU.version = %d/ UNSUPPORTED",
			version);
		smux_send_close_pdu(pcb, SCR_UNSUPPORTED_VERSION);
		return (-1);
	}
	if (asn_get_objid(abuf, &pcb->identity) != ASN_ERR_OK) {
		SMUXDBG("Cannot decode OPEN_PDU.identity");
		smux_send_close_pdu(pcb, SCR_PACKET_FORMAT);
		return (-1);
	}
	SMUXDBG("Received OPEN_PDU.idenity = %s ",asn_oid2str(&pcb->identity));
	
	assert(pcb->description == NULL);
	pcb->description = reallocf( pcb->description, BSMUX_MAX_STR_LEN + 1);
	if (pcb->description == NULL) {
		syslog(LOG_WARNING,"reallocf failed %s:%d",__FILE__,__LINE__);
	} else {
		str_len = BSMUX_MAX_STR_LEN;
		if (asn_get_octetstring(abuf, (u_char *)pcb->description,
	    		&str_len) != ASN_ERR_OK) {
			SMUXDBG("Cannot decode OPEN_PDU.description");
			smux_send_close_pdu(pcb, SCR_PACKET_FORMAT);
			return (-1);
		}
		pcb->description[str_len] = '\0';
		SMUXDBG("Decoded OPEN_PDU.description = %s",
			pcb->description);
	}

	str_len = BSMUX_MAX_STR_LEN;
	if (asn_get_octetstring(abuf, (u_char *)&password[0],
	    &str_len) != ASN_ERR_OK) {
		SMUXDBG("Cannot decode OPEN_PDU.password");
		smux_send_close_pdu(pcb, SCR_PACKET_FORMAT);
		return (-1);
	}

	password[str_len] = '\0';
	SMUXDBG("Decoded decode OPEN_PDU.password = %s", password);
	SMUXDBG("asn buf len is = %d", 	abuf->asn_len);

	if (smux_authorize_peer(&pcb->identity, password, &timeout) != 1) {
		smux_send_close_pdu(pcb, SCR_AUTHENTICATION_FAILURE);
		SMUXDBG("SMUX Peer DENIED!!!");
		return (-1);
	}

	SMUXDBG("SMUX Peer AUTHORDIZED");
	smux_set_timeout(pcb, timeout);

	return (0);
}

/*
 * Unregister an existent registration
 * If out_prio is not NULL then *out_prio will be set to the priority value
 * used in the response (if any response is needed) taht will be sent to the
 * smux peer;
 */
static void
smux_do_unregister_req(struct smux_peer_cb *pcb, struct asn_oid *subtree,
		       int32_t prio, int32_t *out_prio)
{
	struct smux_reg_cb* entry;
	struct smux_reg_cb* with_min_prio = NULL;
	int cmp_result;
	
	TAILQ_FOREACH(entry, &registration_list, link) {
		if (entry->psmux != pcb)
			continue;
			
		cmp_result = asn_compare_oid(subtree, &entry->r_oid);
		if (cmp_result < 0)
			continue;
		if (cmp_result > 0) {
			entry = NULL;
			break;
		}
		
		if (entry->r_prio == (uint32_t)prio)
			break;		
		if (prio == -1) {
			if (with_min_prio == NULL)
				with_min_prio = entry;
			else if (with_min_prio->r_prio > entry->r_prio)
				with_min_prio = entry; 	
		}	
	}

	if (prio == -1)
		entry = with_min_prio;
	if (entry == NULL) {
		/* One way or another - nothing forund */
		/* This item was not registered with me - respond with error */
		if (out_prio != NULL)
			*out_prio = -1;
		return;
	}
	if (out_prio != NULL)
		*out_prio  = entry->r_prio;
	
	smux_decouple_registration(entry);
}

/*
 * Register a new registration
 */
static void
smux_do_register_req(struct smux_peer_cb *pcb, struct asn_oid *subtree,
		     int32_t prio, u_char reg_type)
{
	struct smux_reg_cb	*iter;
	struct smux_reg_cb	*entry;
	struct smux_reg_cb	*new_entry;
	
	assert(subtree != NULL);
	
	new_entry = malloc(sizeof(*new_entry));
	if (new_entry == NULL) {
		syslog(LOG_ERR, "malloc failed in %s: %m", __func__);
		smux_send_rrsp_pdu(pcb, -1);
		return;
	}
	new_entry->r_oid = *subtree;
	new_entry->psmux = pcb;
	new_entry->reg_type =  reg_type;
	
	SMUXDBG("Tree %s is registered %s", asn_oid2str(subtree),
		reg_type == BSMUX_RO_REG ? "RO" : "RW");

	/* check if new oid is a suboid for an already
	   registered oid or vice versa*/	
	TAILQ_FOREACH(entry, &registration_list, link) {
		if (entry->status != S_REG_ACTIVE)
			continue;
		if (smux_oid_scoped_cmp(&entry->r_oid, subtree) != 0)
			continue;
			
		if (subtree->len == entry->r_oid.len) {
			/* same oid already registered */
			if (prio  == -1) {
				/* the new one will be an active one
				   REPLACE current entry */
				new_entry->status = S_REG_ACTIVE;
				entry->status = S_REG_INACTIVE;
				
				new_entry->r_prio = entry->r_prio;
				
				/* increase priority for all the items
				   with the same OID*/
				for(iter = entry;
				  iter != NULL &&
				  asn_compare_oid(&iter->r_oid, subtree) == 0;
				  TAILQ_NEXT(iter, link))
				    iter->r_prio++;
				
				
				goto ready;
			} else if ((uint32_t)prio < entry->r_prio) {
				/* better priority - REPLACE current entry*/
				new_entry->status = S_REG_ACTIVE;
				entry->status = S_REG_INACTIVE;
				new_entry->r_prio = (uint32_t)prio;
				goto ready;
			} else {
				/* equal/ weaker  priority - INACTIVE */
				new_entry->status = S_REG_INACTIVE;
				new_entry->r_prio = find_max_prio(entry) + 1;
				goto ready;
			}	
		} else if (subtree->len < entry->r_oid.len) {
			/* the new one scopes an existent active tree:
			   REPLACE current entry */
			entry->status = S_REG_INACTIVE;
			/* unregister the entry's tree from agent*/
			agent_unregister(entry);
			new_entry->status = S_REG_ACTIVE;
			new_entry->r_prio = (uint32_t)prio;
			/* register new_entry's tree to agent*/
			agent_register(new_entry);
			goto ready;
		} else {
			/* the new is scoped by an existent active
			   tree: add as INACTIVE */
			new_entry->status = S_REG_INACTIVE;
			new_entry->r_prio = (uint32_t)prio;
			goto ready;
		}	
	}
	
	/* not found between active items: register as ACTIVE  */
	if (prio == -1)
		new_entry->r_prio = 0;
	else 	
		new_entry->r_prio = (uint32_t)prio;

	new_entry->status = S_REG_ACTIVE;
	INSERT_OBJECT_FUNC_LINK(new_entry, &registration_list, link,
		smux_reg_cmp);
		
	/* register new_entry's tree to agent */
	agent_register(new_entry);	
	
ready:	
	smux_send_rrsp_pdu(pcb, new_entry->r_prio);
}			

/*
 *  -- insert PDU
 *
 *  RReqPDU ::=
 *      [APPLICATION 2] IMPLICIT
 *          SEQUENCE {
 *              subtree
 *                  ObjectName,
 *
 *              priority    -- the lower the better, "-1" means default
 *                  INTEGER (-1..2147483647),
 *
 *              operation
 *                  INTEGER {
 *                      delete(0),    -- remove registration
 *                      readOnly(1),  -- add registration, objects are RO
 *                      readWrite(2)  --   .., objects are RW
 *                  }
 *          }
 */
static int
handle_smux_reg_req(struct smux_peer_cb *pcb, struct asn_buf *abuf)
{
	struct asn_oid	 subtree;
	int32_t		 priority;
	int32_t		 operation;
	
	if (asn_get_objid(abuf, &subtree) != ASN_ERR_OK) {
		SMUXDBG("Cannot decode RReqPDU.subtree");
		smux_send_rrsp_pdu(pcb, -1);
		return (-1);
	}
	SMUXDBG("Received RReqPDU.subtree = %s ", asn_oid2str(&subtree));
	
	if (asn_get_integer(abuf, &priority) != ASN_ERR_OK) {
		SMUXDBG("Cannot decode RReqPDU.priority");
		smux_send_rrsp_pdu(pcb, -1);
		return (-1);
	}	
	SMUXDBG("Received RReqPDU.priority = %d ", priority);

	if (asn_get_integer(abuf, &operation) != ASN_ERR_OK) {
		SMUXDBG("Cannot decode RReqPDU.operation");
		smux_send_rrsp_pdu(pcb, -1);
		return (-1);
	}	
	SMUXDBG("Received RReqPDU.operation = %d ", operation);
	if (operation != BSMUX_DEL_REG &&
		operation != BSMUX_RO_REG &&
		operation != BSMUX_RW_REG) {
		SMUXDBG("unknown RReqPDU.operation value");
		smux_send_rrsp_pdu(pcb, -1);
		return (-1);
		
	}
	
	switch (operation) {
		case BSMUX_DEL_REG: {
			int32_t resp_prio;
			smux_do_unregister_req(pcb, &subtree, priority, &resp_prio);
			smux_send_rrsp_pdu(pcb, resp_prio);
			return (0);
			break;
		}	
		case BSMUX_RO_REG:
		case BSMUX_RW_REG:
			smux_do_register_req(pcb, &subtree, priority,
				operation);
			return (0);
			break;
		default:
			SMUXDBG("unknown RReqPDU.operation value");
			smux_send_rrsp_pdu(pcb, -1);
			return (-1);
			break;
	}

	return (0);
}

static
int handle_smux_trap(struct smux_peer_cb* pcb, struct asn_buf* abuf)
{
	struct asn_oid	eoid;
	u_char	agent_addr[4];
	int 	 varbinds_len;
	int32_t	 generic_trap;
	int32_t	 specific_trap;
	uint32_t time_stamp;
	struct snmp_value v[SNMP_MAX_BINDINGS];
	int vi;
	asn_len_t trailer;
	
	if (asn_get_objid(abuf, &eoid) != ASN_ERR_OK) {
		SMUXDBG("%s: Cannot decode TRAP::enterprise oid", __func__);
		smux_send_close_pdu(pcb, SCR_PACKET_FORMAT);
		return (-1);
	}
	if (asn_get_ipaddress(abuf, &agent_addr[0]) != ASN_ERR_OK) {
		SMUXDBG("%s: Cannot decode TRAP::agent-addr", __func__);
		smux_send_close_pdu(pcb, SCR_PACKET_FORMAT);
		return (-1);
	}
	
	if (asn_get_integer(abuf, &generic_trap) != ASN_ERR_OK) {
		SMUXDBG("%s: Cannot decode TRAP::generic_trap", __func__);
		smux_send_rrsp_pdu(pcb, -1);
		return (-1);
	}	
	if (asn_get_integer(abuf, &specific_trap) != ASN_ERR_OK) {
		SMUXDBG("%s: Cannot decode TRAP::specific_trap", __func__);
		smux_send_close_pdu(pcb, SCR_PACKET_FORMAT);
		return (-1);
	}	
	if (asn_get_timeticks(abuf, &time_stamp) != ASN_ERR_OK) {
		SMUXDBG("%s: Cannot decode TRAP::time_stamp", __func__);
		smux_send_close_pdu(pcb, SCR_PACKET_FORMAT);
		return (-1);
	}	
	if (asn_get_sequence(abuf, &varbinds_len) != ASN_ERR_OK) {
		SMUXDBG("%s: cannot get TRAP::varlist header", __func__);
		smux_send_close_pdu(pcb, SCR_PACKET_FORMAT);
		return (-1);
	}

	trailer = abuf->asn_len - varbinds_len;
	abuf->asn_len = varbinds_len;
	vi = 0;
	while (abuf->asn_len > 0) {
		if (vi == SNMP_MAX_BINDINGS) {
			SMUXDBG("too many bindings (> %u) in PDU",
			    SNMP_MAX_BINDINGS);
			smux_send_close_pdu(pcb, SCR_INTERNAL_ERROR);
			return (-1);
		}
		if (snmp_get_var_binding(abuf, &v[vi]) != ASN_ERR_OK) {
			SMUXDBG("%s: cannot get TRAP::varbind", __func__);
			smux_send_close_pdu(pcb, SCR_PACKET_FORMAT);
			return (-1);
		}
		vi++;
	}

	abuf->asn_len = trailer;
	snmp_smux_send_trap(&eoid, agent_addr, generic_trap, specific_trap,
		time_stamp, v, vi);	

	return (0);
}

/*
 * Process any incomping PDU except SMUX OPEN PDU.
 * (This means that an OPEN PDU here is treated as an error)
 * SMUX CLOSE PDU is sent and the connection is cleared in case
 * of an error and the function returns (-1). If everything is OK
 * (0) is returned
 */
static int
handle_smux_any_pdu(struct smux_peer_cb *pcb, struct asn_buf *abuf)
{
	u_char type;
	asn_len_t len;
	int result = 0;
	int destroy_peer = 0;
	
	if (asn_get_header(abuf, &type, &len) != ASN_ERR_OK) {
   		syslog( LOG_ERR,
   	  	 "Failed to asn_get_header for peer %s:%d",
	   	 inet_ntoa(pcb->in_socket.sin_addr),
           	 ntohs(pcb->in_socket.sin_port));
           	
		smux_send_close_pdu(pcb, SCR_PACKET_FORMAT);
		destroy_peer = 1;
		result = -1;
		goto any_done;
	}
	switch (type) {
		case BSMUX_OPEN_PDU:
			smux_send_close_pdu(pcb, SCR_PROTOCOL_ERROR);
			SMUXDBG("Received again SMUX OPEN in OPEN STATE");
			destroy_peer = 1;
			result = -1;
			break;	
		case BSMUX_CLOSE_PDU:
			SMUXDBG("Received SMUX CLOSE - OK, peer cleaned up");
			destroy_peer = 1;
			result = 0;
			break;
		case BSMUX_REG_REQ_PDU:
			SMUXDBG("Received REGISTER REQUEST - OK ");
			handle_smux_reg_req(pcb, abuf);
			destroy_peer = 0;
			result = 0;
			break;
		case BSMUX_REG_RSP_PDU:
			SMUXDBG("Receveid REGISTER RESPONSE in OPEN STATE");
			smux_send_close_pdu(pcb, SCR_PROTOCOL_ERROR);
			destroy_peer = 1;
			result = -1;
			break;	
		case BSMUX_SOUT_PDU:
			SMUXDBG("Received SOUT REQUEST in OPEN STATE");
			smux_send_close_pdu(pcb, SCR_PROTOCOL_ERROR);
			destroy_peer = 1;
			result = -1;
			break;	
		case BSMUX_TRAP_OP:
			SMUXDBG("Received TRAP OP - OK ");
			if ((result = handle_smux_trap(pcb, abuf) != 0))
				destroy_peer = 1;
			else
				destroy_peer = 0;
			break;		
		default:
			SMUXDBG("Receveid UNKNOWN PDU in OPEN STATE");
			smux_send_close_pdu(pcb, SCR_PROTOCOL_ERROR);
			destroy_peer = 1;
			result = -1;
			break;
	}

any_done:
	if (destroy_peer == 1) {
		TAILQ_REMOVE(&smux_peer_tbl, pcb, link);
		destroy_peer_cb(pcb, 1);
	}	

	return (result);
}

static void
smux_socket_callback(int fd __unused, void *arg)
{
	u_char			 r_data[BSMUX_MAX_PACKET_SIZE];
	struct asn_buf		 abuf;
	struct smux_peer_cb	*pcb;
	ssize_t			 r_data_len;
	
	assert(arg != NULL);
	pcb = (struct smux_peer_cb*)arg;
	memset(&r_data[0], 0, sizeof(r_data));

	r_data_len = recv(pcb->index,(void *)&r_data[0],
		BSMUX_MAX_PACKET_SIZE, 0);
		
	if (r_data_len < 0) {
   		syslog( LOG_ERR,"Failed to recv for peer %s:%d - %m",
	   		inet_ntoa(pcb->in_socket.sin_addr),
           		ntohs(pcb->in_socket.sin_port));
           		
       	 	TAILQ_REMOVE(&smux_peer_tbl, pcb, link);
       	 	destroy_peer_cb(pcb, 1);
           	return;
	}
	
	if (r_data_len == 0) {
		/* The peer has closed the connection */
		SMUXDBG("received 0 bytes from sd %d ", pcb->index);
       	 	TAILQ_REMOVE(&smux_peer_tbl, pcb, link);
       	 	destroy_peer_cb(pcb, 1);
		return;
	}
	
	abuf.asn_ptr = r_data;
	abuf.asn_len = r_data_len;
	
	if (pcb->status == PS_CONNECTING) {
		if (handle_smux_open_pdu(pcb, &abuf) != 0) {
           	 	TAILQ_REMOVE(&smux_peer_tbl, pcb, link);
           	 	destroy_peer_cb(pcb, 0);
           	 	return;
		}
		pcb->status = PS_VALID;
	}
	/* we may be here for processing the same packet containing
	 * OPEN_PDU decoded above - this is why we check abuf.asn_len
	 */
	while (pcb->status == PS_VALID && abuf.asn_len > 0) {
		if (handle_smux_any_pdu(pcb, &abuf) != 0) {
			SMUXDBG("Wrong PDU from peer %s:%d - stop processing",
	   			inet_ntoa(pcb->in_socket.sin_addr),
           			ntohs(pcb->in_socket.sin_port));
			return;
		}
	}
}

/*
 * Add a new entry in the peer list.
 * After this call the we are waiting for the
 * SMUX OPEN message from the remote party
 */
void
smux_handle_new_peer(int fd, struct sockaddr_in* peer_socket)
{
	struct smux_peer_cb *pcb;

	pcb = (struct smux_peer_cb *)malloc(sizeof(*pcb));
	if (pcb == NULL) {
   		syslog( LOG_ERR,
   	  	"Failed to allocate the peer control block for peer %s:%d",
	   	inet_ntoa(peer_socket->sin_addr),
           	ntohs(peer_socket->sin_port));
   		close(fd);
   		return;
	}
	memset(pcb, 0, sizeof(*pcb));
	
	pcb->index = fd;
	pcb->in_socket = *peer_socket;
	pcb->status = PS_CONNECTING;
	pcb->sd_id = fd_select(pcb->index, smux_socket_callback,
			pcb, smux_module);
        if (pcb->sd_id == NULL) {
   		syslog( LOG_ERR,
   	  	"Failed to fd_select for the control block for peer %s:%d",
	   	inet_ntoa(peer_socket->sin_addr),
           	ntohs(peer_socket->sin_port));
   		close(fd);
   		free(pcb);
   		return;
        }

	INSERT_OBJECT_INT(pcb, &smux_peer_tbl);
	smux_peer_count++;
	SMUXDBG("Inserted SMUX peer with index = %d [peer count =%d]",
		 pcb->index, smux_peer_count);
}

void
smux_proto_cleanup(void)
{
	struct smux_reg_cb *e, *etmp;
	struct smux_peer_cb *p;
	struct smux_peer_cb *next_p;
	
	TAILQ_FOREACH_SAFE(e, &registration_list, link, etmp)
		smux_decouple_registration(e);
	assert(TAILQ_EMPTY(&registration_list));
	
	p = TAILQ_FIRST(&smux_peer_tbl);
     	while (p != NULL) {
             next_p = TAILQ_NEXT(p, link);
             smux_send_close_pdu(p, SCR_GOING_DOWN);
             destroy_peer_cb(p, 0);
             p = next_p;
     	}
	assert(TAILQ_EMPTY(&smux_peer_tbl));
}

static int
smux_encode_op(int32_t request_id, struct snmp_value *value, u_char op,
	       u_char *buf, size_t buf_len)
{
	struct asn_buf 	b;
	u_char*		xbuf;
	u_char*		varbind_buf;
	int32_t		error_status = 0;
	int32_t		error_index = 0;
	
        b.asn_ptr = buf;
        b.asn_len = buf_len;
	if (asn_put_temp_header(&b, op, &xbuf) != ASN_ERR_OK) {
		SMUXDBG("asn_put_temp_header failed");
		return (-1);
	}
        if (asn_put_integer(&b, request_id) != ASN_ERR_OK) {
		SMUXDBG("asn_put_integer(request_id) failed");
		return (-1);
        }

        if (asn_put_integer(&b, error_status) != ASN_ERR_OK) {
		SMUXDBG("asn_put_integer(error_status) failed");
		return (-1);
        }

        if (asn_put_integer(&b, error_index) != ASN_ERR_OK) {
		SMUXDBG("asn_put_integer(error_index) failed");
		return (-1);
        }
	
	/* -- start varbind zone -- */
	if (asn_put_temp_header(&b, (ASN_TYPE_SEQUENCE|ASN_TYPE_CONSTRUCTED),
	    &varbind_buf) != ASN_ERR_OK)
		return (-1);
    	if (op != BSMUX_SET_OP) {
        	value->syntax = SNMP_SYNTAX_NULL;
        	memset(&value->v, 0, sizeof(value->v));
    	}	
    	
    	/* only one varbind at a time */
    	if (snmp_binding_encode(&b, value) != 0) {
		SMUXDBG("snmp_binding_encode failed");
		return (-1);
    	}
	if (asn_commit_header(&b, varbind_buf, NULL) != ASN_ERR_OK) {
		SMUXDBG("asn_commit_header/ varbind failed");
		return (-1);
	
	}
	/* -- end varbind zone -- */
	
	if (asn_commit_header(&b, xbuf, NULL) != ASN_ERR_OK) {
		SMUXDBG("asn_commit_header/ smux packet failed");
		return (-1);
	}
	
	assert(b.asn_ptr - &buf[0] > 0);
	return (b.asn_ptr - &buf[0]);
}

/*
 * Used to parse an incomming SMUX message from remote
 * peer as a respone for a SMUX GET.
 * Returns 0 if the incomming message is OK or
 * -1 if parse failed (and a SMUX CLOSE was sent, hence we need to
 * clean up the socket after this function returns)
 * in snmp_err parameter the explicit SNMP error is filled in
 * to be returned to the SNMP client
 */
static int
smux_read_dialog_decode_op(struct snmp_value *value, u_char* buf, size_t buf_len,
			   struct smux_reg_cb* reg, int32_t exp_request_id,
			   int *snmp_err)
{
	struct asn_buf		 b;
	int32_t			 have_varbind;
	asn_len_t		 len;
	u_char			 type;

	have_varbind = 0;

        b.asn_ptr = buf;
        b.asn_len = buf_len;
	while (b.asn_len > 0) {	
		if (asn_get_header(&b, &type, &len) != ASN_ERR_OK) {
   			syslog( LOG_ERR,
   	  	 	"Failed to asn_get_header/  for peer %s:%d",
	   	 	inet_ntoa(reg->psmux->in_socket.sin_addr),
           	 	ntohs(reg->psmux->in_socket.sin_port));
           	
			smux_send_close_pdu(reg->psmux, SCR_PACKET_FORMAT);
			*snmp_err = SNMP_ERR_GENERR;
			return (-1);
		}
		if (type == BSMUX_TRAP_OP) {
			/*
			 * Traps are okay at any stage - so, process this
			 * one and keep searching
			 */
			if (handle_smux_trap(reg->psmux, &b) != 0) {
				*snmp_err = SNMP_ERR_GENERR;
				return (-1);			
			}
		} else if ( type != BSMUX_GETRSP_OP ) {
			/* Only BSMUX_GETRSP_OP or BSMUX_TRAP_OP is expected*/
			/* Everything else is junk, so close the conn. */
			smux_send_close_pdu(reg->psmux, SCR_PROTOCOL_ERROR);
			*snmp_err = SNMP_ERR_GENERR;
			return (-1);	
		} else {
			int32_t seq_no;
			int32_t	error_status;
			int32_t	error_index ;
			u_char v_type;
			asn_len_t v_len;
			
			if (asn_get_integer(&b, &seq_no) != ASN_ERR_OK) {
			  SMUXDBG("Cannot decode seqeunece number");
			  smux_send_close_pdu(reg->psmux, SCR_PACKET_FORMAT);
			  *snmp_err = SNMP_ERR_GENERR;
			  return (-1);
			}
			if (seq_no != exp_request_id) {
			  SMUXDBG("Sequnce number mismatch. Expected %d/ Recv %d",
			  exp_request_id, seq_no);
			  smux_send_close_pdu(reg->psmux, SCR_PROTOCOL_ERROR);
			  *snmp_err = SNMP_ERR_GENERR;
			  return (-1);
			}	
			
			if (asn_get_integer(&b, &error_status) != ASN_ERR_OK) {
			  SMUXDBG("Cannot decode error status");
			  smux_send_close_pdu(reg->psmux, SCR_PACKET_FORMAT);
			  *snmp_err = SNMP_ERR_GENERR;
			  return (-1);
			}
			
			if (error_status != 0) {
			  SMUXDBG("Received error status != 0 ");
			  *snmp_err = error_status;
			  return (0);
			}
			
			if (asn_get_integer(&b, &error_index) != ASN_ERR_OK) {
			  SMUXDBG("Cannot decode error index");
			  smux_send_close_pdu(reg->psmux, SCR_PACKET_FORMAT);
			  *snmp_err = SNMP_ERR_GENERR;
			  return (-1);
			}
			
			if (asn_get_header(&b, &v_type, &v_len) != ASN_ERR_OK) {
			  SMUXDBG("asn_get_header/ varbinds failed");
			  smux_send_close_pdu(reg->psmux, SCR_PACKET_FORMAT);
			  *snmp_err = SNMP_ERR_GENERR;
			  return (-1);

			} else if (v_type !=
				(ASN_TYPE_SEQUENCE|ASN_TYPE_CONSTRUCTED)) {
			  SMUXDBG("wrong asn header/varbinds ");
			  smux_send_close_pdu(reg->psmux, SCR_PACKET_FORMAT);
			  *snmp_err = SNMP_ERR_GENERR;
			  return (-1);
			}
			
			if (snmp_get_var_binding(&b, value) != 0) {
			  SMUXDBG("snmp_get_var_binding failed");
			  smux_send_close_pdu(reg->psmux, SCR_PACKET_FORMAT);
			  *snmp_err = SNMP_ERR_GENERR;
			  return (-1);
			}
			have_varbind = 1;

		}
	}
	
	/* we are expecting exactly one varbind in response for
	 * our request - or we are cleaning up the connection
	 */
	if (have_varbind == 1) {
		*snmp_err = SNMP_ERR_NOERROR;
		return (0);
	} else {
		smux_send_close_pdu(reg->psmux, SCR_PACKET_FORMAT);
		*snmp_err = SNMP_ERR_GENERR;
		return (-1);
	}
}


/*
 * Used to decode the response from peers for SMUX SET messages
 * Returns (0) if evrything is OK or (-1)  if we need to clean up
 * the connection to this SMUX peer.
 * In addition, we fill in snmp_err pointer with the SNMP value we
 * are going to send back to our SNMP client
 */
static int
smux_write_dialog_decode_op(u_char* buf, size_t buf_len,
	struct smux_reg_cb* reg, int32_t exp_request_id, int* snmp_err)
{
	struct asn_buf 	b;
	u_char type;
	asn_len_t len;
	int32_t have_response;

	have_response = 0;

        b.asn_ptr = buf;
        b.asn_len = buf_len;
	while (b.asn_len > 0) {	
		if (asn_get_header(&b, &type, &len) != ASN_ERR_OK) {
   			syslog( LOG_ERR,
   	  	 	"Failed to asn_get_header/  for peer %s:%d",
	   	 	inet_ntoa(reg->psmux->in_socket.sin_addr),
           	 	ntohs(reg->psmux->in_socket.sin_port));
           	
			smux_send_close_pdu(reg->psmux, SCR_PACKET_FORMAT);
			*snmp_err = SNMP_ERR_GENERR;
			return (-1);
		}
		
		SMUXDBG("Trying to decode SET RESPONSE - header type = %d",
			type);
			
		if (type == BSMUX_TRAP_OP) {
			/* Traps are okay at any stage, process them and
		 	keep searching*/
			if (handle_smux_trap(reg->psmux, &b) != 0) {
				*snmp_err = SNMP_ERR_GENERR;
				return (-1);
			}
		
		} else if ( type != BSMUX_GETRSP_OP ) {
			/* Only BSMUX_GETRSP_OP or BSMUX_TRAP_OP are expected*/
			/* Everything else is junk, so close the conn. */
			SMUXDBG("Unexpected header recevied = %d", type);
			*snmp_err = SNMP_ERR_GENERR;
			return (-1);
		} else {
			int32_t seq_no;
			int32_t	error_status;
			int32_t	error_index ;
			struct snmp_value value;
			u_char v_type;
			asn_len_t v_len;
			
			SMUXDBG("Have SET RESPONSE - header type = %d", type);
			if (asn_get_integer(&b, &seq_no) != ASN_ERR_OK) {
				SMUXDBG("Cannot decode seqeunece number");
				smux_send_close_pdu(reg->psmux, SCR_PACKET_FORMAT);
				*snmp_err = SNMP_ERR_GENERR;
				return (-1);
			}
			if (seq_no != exp_request_id) {
				SMUXDBG("Sequnce number mismatch. Expected %d/ Recv %d",
				exp_request_id, seq_no);
				smux_send_close_pdu(reg->psmux, SCR_PROTOCOL_ERROR);
				*snmp_err = SNMP_ERR_GENERR;
				return (-1);
			}	
			
			if (asn_get_integer(&b, &error_status) != ASN_ERR_OK) {
				SMUXDBG("Cannot decode error status");
				smux_send_close_pdu(reg->psmux, SCR_PACKET_FORMAT);
				*snmp_err = SNMP_ERR_GENERR;
				return (-1);
			}
			
			if (error_status != 0) {
				SMUXDBG("Received error status != 0 ");
				*snmp_err = error_status;
				return (0);
			}
			
			if (asn_get_integer(&b, &error_index) != ASN_ERR_OK) {
				SMUXDBG("Cannot decode error index");
				smux_send_close_pdu(reg->psmux, SCR_PACKET_FORMAT);
				*snmp_err = SNMP_ERR_GENERR;
				return (-1);

			}
			if (asn_get_header(&b, &v_type, &v_len) != ASN_ERR_OK) {
				SMUXDBG("asn_get_header/ varbinds failed");
				smux_send_close_pdu(reg->psmux, SCR_PACKET_FORMAT);
				*snmp_err = SNMP_ERR_GENERR;
				return (-1);
			} else if (v_type !=
				(ASN_TYPE_SEQUENCE|ASN_TYPE_CONSTRUCTED)) {
				SMUXDBG("wrong asn header/varbinds ");
				smux_send_close_pdu(reg->psmux, SCR_PACKET_FORMAT);
				*snmp_err = SNMP_ERR_GENERR;
				return (-1);
				
			}
			
			if (snmp_get_var_binding(&b, &value) != 0) {
				SMUXDBG("snmp_get_var_binding failed");
				smux_send_close_pdu(reg->psmux, SCR_PACKET_FORMAT);
				*snmp_err = SNMP_ERR_GENERR;
				return (-1);
			}
			snmp_value_free(&value);
			have_response = 1;

		}
	}

	/*
	 * Response for SMUX SET is mandatory at this stage.
	 * Not having it in this packet is an error, hence
	 * close the connection with this peer
	 */
	if (have_response == 1) {
		*snmp_err = SNMP_ERR_NOERROR;
		return (0);
		
	} else {
		smux_send_close_pdu(reg->psmux, SCR_PACKET_FORMAT);
		*snmp_err = SNMP_ERR_GENERR;
		return (-1);
	}
}

/*
 * Perform the SMUX GET dialog with SMUX peers:
 * encode the request, read and decode the response
 * returns (0) if everythig was OK, or (-1) if a fatal error
 * occured (like  decoding failed, socket failure)
 * in snmp_err paramer we fill in the SNMP error to be passed
 * back to the SNMP client
 */
static int
smux_peer_read_dialog(struct snmp_value *value, u_char op, struct smux_reg_cb *reg,
		      int *snmp_err)
{
        u_char buf[BSMUX_MAX_PACKET_SIZE];
        ssize_t ret;
        int pdu_len;
	int32_t req_id;
	int return_value = 0;
	
	assert(value != NULL);
	req_id = reqid_next(smux_reqid_type);
	if ((pdu_len = smux_encode_op(req_id, value, op, buf,
		 		      BSMUX_MAX_PACKET_SIZE)) <= 0) {
		 /*
		  * This is not a peer error - hence no need to clean
		  * up the peer structure or the conection.
		  * Just return error to our client.
		  */
		 *snmp_err = SNMP_ERR_GENERR;
		 return (0);
	}	 	
		
        assert(reg->psmux != NULL);
        assert(reg->psmux->sd_id != NULL);
	*snmp_err =  SNMP_ERR_NOERROR;
	
	fd_suspend(reg->psmux->sd_id);
        if ((ret = send(reg->psmux->index, buf, pdu_len, 0)) == -1) {
		SMUXDBG("Failed to send to peer %s because %s",
		  asn_oid2str(&reg->r_oid), strerror(errno));
		free(buf);
                return_value = -1;
                *snmp_err = SNMP_ERR_GENERR;
                goto done;
	}
	
	memset(&buf[0], 0, BSMUX_MAX_PACKET_SIZE);
	if ((ret = recv(reg->psmux->index, buf,
		BSMUX_MAX_PACKET_SIZE, 0)) < 0) {
		SMUXDBG("Failed to recv from peer %s because %s",
		  asn_oid2str(&reg->r_oid), strerror(errno));
                return_value = -1;
                *snmp_err = SNMP_ERR_GENERR;
                goto done;

		
	}
	return_value = smux_read_dialog_decode_op(value, &buf[0], ret, reg,
						  req_id, snmp_err);
done:	
	fd_resume(reg->psmux->sd_id);

	return (return_value);
}

/*
 * Perform the SMUX SET dialog with SMUX peers:
 * encode the request, read and decode the response
 * returns (0) if everythig was OK, or (-1) if a fatal error
 * occured (like  decoding failed, socket failure);
 * in snmp_err paramer we fill in the SNMP error to be passed
 * back to the SNMP client
 */
static int
smux_peer_write_dialog(struct snmp_value *value, struct smux_reg_cb *reg,
		       int *snmp_err)
{
        u_char		 buf[BSMUX_MAX_PACKET_SIZE];
        int		 pdu_len;
	int32_t		 req_id;
        ssize_t		 ret;
	int		 return_value = 0;
	
	assert(value != NULL);

	req_id = reqid_next(smux_reqid_type);
	if ((pdu_len = smux_encode_op(req_id, value, BSMUX_SET_OP, buf,
		 BSMUX_MAX_PACKET_SIZE)) <= 0 ) {
		 /*
		  * This is not a peer error - hence no need to clean
		  * up the peer structure or the conection.
		  * Just return error to our client.
		  */
		 *snmp_err = SNMP_ERR_GENERR;
		 return (0);
	}		 	
        assert(reg->psmux != NULL);
        assert(reg->psmux->sd_id != NULL);
	*snmp_err = SNMP_ERR_NOERROR;

	fd_suspend(reg->psmux->sd_id);
        if ((ret = send(reg->psmux->index, buf, pdu_len, 0)) == -1) {
		SMUXDBG("Failed to send a SET to peer %s because %s",
			asn_oid2str(&reg->r_oid), strerror(errno));
		free(buf);
		*snmp_err = SNMP_ERR_GENERR;
                return_value = -1;
                goto done;
	}
	
	memset(&buf[0], 0, BSMUX_MAX_PACKET_SIZE);
	if ((ret = recv(reg->psmux->index, buf, BSMUX_MAX_PACKET_SIZE, 0)) < 0){
		SMUXDBG("Failed to recv from peer %s because %s",
			asn_oid2str(&reg->r_oid), strerror(errno));
		*snmp_err = SNMP_ERR_GENERR;
                return_value = -1;
                goto done;
	}
	
	return_value = smux_write_dialog_decode_op(&buf[0], ret, reg,
		req_id,	snmp_err);	
done:	
	fd_resume(reg->psmux->sd_id);

	return (return_value);

}

/*
 * This is the function used for sustaining the dialog with
 * the registered SMUX peers. Note that this is just a BSNMP
 * function of type snmp_op_t - hence this op_smuxProto implementation
 * obeys the conventions used in any instrumentation for BSNMP
 */
int op_smuxProto(struct snmp_context *ctx __unused,
	struct snmp_value *value,  u_int sub __unused,
	u_int iidx __unused, enum snmp_op op)
{
	int dialog_result = 0;
	int snmp_status = SNMP_ERR_GENERR;
	struct smux_reg_cb* reg;
	
	reg = find_smux_reg(&value->var);
        if (reg == NULL) {
        	SMUXDBG("No registration found for %s ",
		  asn_oid2str(&value->var));
		return (SNMP_ERR_NOSUCHNAME);
        }
	assert(reg->psmux != NULL);
	
	if (reg->psmux->status != PS_VALID) {
        	SMUXDBG("No valid peer found for %s ",
		  asn_oid2str(&value->var));
		return (SNMP_ERR_NOSUCHNAME);
	}
		
	switch (op) {
		case SNMP_OP_GET:
		  dialog_result =
			smux_peer_read_dialog(value, BSMUX_GET_OP, reg,
			&snmp_status);
		break;
		
		case SNMP_OP_GETNEXT:
		  dialog_result =
			smux_peer_read_dialog(value, BSMUX_GETNEXT_OP, reg,
			&snmp_status);
			
		  /* check the received OID to be in the registered range */ 	
		  if (!asn_is_suboid( &reg->r_oid, &value->var)) {
		    SMUXDBG("received oid '%s' is outside the registered tree",
		  	asn_oid2str(&value->var));
		    /* make the agent to advance to the next tree root */	
		    snmp_status = SNMP_ERR_NOSUCHNAME;	
		  }	
		break;
		
		case SNMP_OP_SET:
		  if (reg->reg_type == BSMUX_RO_REG) {
		  	snmp_status = SNMP_ERR_NOT_WRITEABLE;
		  	dialog_result = 0;
		  	SMUXDBG("SNMP_OP_SET: reg '%s' is READ-ONLY",
		  	  asn_oid2str(&reg->r_oid));
		  } else {
		  	dialog_result =
			  smux_peer_write_dialog(value, reg,
			  &snmp_status);
		  }	
		break;
		
		case SNMP_OP_COMMIT:
			SMUXDBG("SNMP_OP_COMMIT, sending SOUT/ 0");
			smux_send_sout_pdu(reg->psmux, 0);
			dialog_result = 0;
		break;
		
		case SNMP_OP_ROLLBACK:
			SMUXDBG("SNMP_OP_ROLLBACK, sending SOUT/ 1");
			smux_send_sout_pdu(reg->psmux, 1);
			dialog_result = 0;
		break;

		default:
			abort();	/* XXX */
		break;	
		
	}
	
	if (dialog_result != 0) {
		TAILQ_REMOVE(&smux_peer_tbl, reg->psmux, link);
		destroy_peer_cb(reg->psmux, 1);
	}
	
	return (snmp_status);
}

int	
op_smuxPeerTable(struct snmp_context *ctx, struct snmp_value *value,
	         u_int sub, u_int iidx __unused, enum snmp_op op )
{
	struct smux_peer_cb *p;
		
	switch (op) {
	  case SNMP_OP_GETNEXT:
		if ((p = NEXT_OBJECT_INT(&smux_peer_tbl,
		 	&value->var, sub)) == NULL) {
		 	SMUXDBG("No NEXT SMUX peer");
			return (SNMP_ERR_NOSUCHNAME);
		}	
		value->var.len = sub + 1;
		value->var.subs[sub] = p->index;
		goto get;
		break;

	  case SNMP_OP_GET:
  		if ((p = FIND_OBJECT_INT(&smux_peer_tbl,
		    &value->var, sub)) == NULL)
			return (SNMP_ERR_NOSUCHNAME);
		goto get;
		break;

	  case SNMP_OP_SET:
  		if ((p = FIND_OBJECT_INT(&smux_peer_tbl,
		    &value->var, sub)) == NULL)
			return (SNMP_ERR_NOSUCHNAME);
			
		if (value->var.subs[sub - 1] != LEAF_smuxPstatus)
			return (SNMP_ERR_NOT_WRITEABLE);
		
		if (value->v.integer != PS_INVALID)
			return (SNMP_ERR_WRONG_VALUE);
		
		ctx->scratch->int1 = p->status;
		p->status = PS_INVALID;
		return (SNMP_ERR_NOERROR);
		break;
	  	
	  case SNMP_OP_ROLLBACK:
  		if ((p = FIND_OBJECT_INT(&smux_peer_tbl,
		    &value->var, sub)) == NULL) {
		    	assert(0);
			return (SNMP_ERR_NOERROR);
		}	
			
		assert(value->var.subs[sub - 1] == LEAF_smuxPstatus);

		p->status = ctx->scratch->int1;
		return (SNMP_ERR_NOERROR);
		break;
	  	
	  case SNMP_OP_COMMIT:
  		if ((p = FIND_OBJECT_INT(&smux_peer_tbl,
		    &value->var, sub)) == NULL) {
		    	assert(0);
			return (SNMP_ERR_NOERROR);
		}	
	  	
	  	assert(p->status == PS_INVALID);
	  	
	  	TAILQ_REMOVE(&smux_peer_tbl, p, link);
		destroy_peer_cb(p, 1);
		
	  	return (SNMP_ERR_NOERROR);
		break;
	  	
	  default:
	  	abort(); /* XXX*/
		break;
	}

	abort(); /* XXX */

get:	
	switch (value->var.subs[sub - 1]) {
	  case LEAF_smuxPindex:
	  	value->v.integer = p->index;
	  	return (SNMP_ERR_NOERROR);	
		break;
	  case LEAF_smuxPidentity:
	  	return (oid_get(value, &p->identity));
		break;
	  case LEAF_smuxPdescription:
	  	return (string_get(value, p->description, -1));
		break;
	  case LEAF_smuxPstatus:
	  	value->v.integer = p->status;
	  	return (SNMP_ERR_NOERROR);
		break;
	  default:
	  	SMUXDBG("wrong leaf: %d", value->var.subs[sub - 1]);
		abort();
		return (SNMP_ERR_NOSUCHNAME);
		break;
	}	

	abort();

	return (SNMP_ERR_NOSUCHNAME);
}


int	
op_smuxTreeTable(struct snmp_context *ctx, struct snmp_value *value,
    u_int sub, u_int iidx __unused, enum snmp_op op)
{
	struct smux_reg_cb *re;
	
	SMUXDBG("%s - entering", __func__);
	switch (op) {

	case SNMP_OP_GETNEXT:
		if ((re = NEXT_OBJECT_FUNC(&registration_list,
		    &value->var, sub, smux_reg_idx_cmp)) == NULL) {
		    	SMUXDBG("NO NEXT REGISTRATION");
			return (SNMP_ERR_NOSUCHNAME);
		}
		value->var.len = sub + re->r_oid.len + 1;
		if (value->var.len >= ASN_MAXOIDLEN)
			return (SNMP_ERR_GENERR);
			
		memcpy(&value->var.subs[sub], &re->r_oid.subs[0],
			re->r_oid.len * sizeof(re->r_oid.subs[0]));
			
		value->var.subs[sub + re->r_oid.len] = re->r_prio;
		goto get;
		break;

	case SNMP_OP_GET:
		if ((re = FIND_OBJECT_FUNC(&registration_list,
		    &value->var, sub, smux_reg_idx_cmp)) == NULL)
			return (SNMP_ERR_NOSUCHNAME);
		goto get;
		break;

	case SNMP_OP_SET:
		if ((re = FIND_OBJECT_FUNC(&registration_list,
		    &value->var, sub, smux_reg_idx_cmp)) == NULL)
			return (SNMP_ERR_NOSUCHNAME);
			
		if (value->var.subs[sub - 1] != LEAF_smuxTstatus)
			return (SNMP_ERR_NOT_WRITEABLE);
		
		if (value->v.integer != 2)
			return (SNMP_ERR_WRONG_VALUE);
		
		ctx->scratch->int1 = 2;		
		return (SNMP_ERR_NOERROR);
		break;
		
	case SNMP_OP_ROLLBACK:
		ctx->scratch->int1 = 0;
		return (SNMP_ERR_NOERROR);
	case SNMP_OP_COMMIT:
		if ((re = FIND_OBJECT_FUNC(&registration_list,
		    &value->var, sub, smux_reg_idx_cmp)) == NULL) {
		    	assert(0);
			return (SNMP_ERR_NOERROR);
		}	
		if (ctx->scratch->int1 == 2)
			/* No need to send a response, so the 4th paramemter
			 in the call below is NULL*/
			smux_do_unregister_req(re->psmux, &re->r_oid,
				re->r_prio, NULL);		
		
		return (SNMP_ERR_NOERROR);
		break;

	default:
		abort();	
		break;
	}
	abort();

get:
	switch (value->var.subs[sub - 1]) {
	case LEAF_smuxTsubtree:
		return (oid_get(value, &re->r_oid));
		break;

	case LEAF_smuxTpriority:
		value->v.integer = re->r_prio;
		return (SNMP_ERR_NOERROR);
		break;

	case LEAF_smuxTindex:
		value->v.integer = re->psmux->index;
		return (SNMP_ERR_NOERROR);
		break;

	case LEAF_smuxTstatus:
		value->v.integer = 1;
		return (SNMP_ERR_NOERROR);
		break;

	default:
		abort();	
		break;
	}
	abort();

	return (SNMP_ERR_NOSUCHNAME);
}

void
smux_set_peer_timeout(const struct asn_oid* id, uint32_t timeout)
{
	struct smux_peer_cb *entry = NULL;

	assert(id != NULL);
	
	TAILQ_FOREACH(entry, &smux_peer_tbl, link) {
		if (asn_compare_oid(&entry->identity, id) == 0)
		break;		
	}
	if (entry == NULL)
		return;
	
	smux_set_timeout(entry, timeout);
}
