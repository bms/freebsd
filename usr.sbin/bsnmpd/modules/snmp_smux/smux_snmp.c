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

#include "snmpmod.h"
#include "smux_snmp.h"
#include "smux_oid.h"
#include "smux_tree.h"

/*
 * FIXME: IPv6 and SNMPv3 support are missing.
 */

struct lmodule				*smux_module;
static const struct asn_oid		 oid_smux = OIDX_smux;

static u_int		 smux_registration_id = 0;
/*static*/ u_int	 smux_reqid_type = 0;

static int		 smux_listener_sd = -1;
static u_int32_t	 smux_listener_port = SMUX_LISTENER_PORT;
static void		*smux_listener_id = NULL;

/*
 * XXX Gnarly. This is the address of the SMUX endpoint, normally IPADDR_ANY.
 * Unfortunately this isn't IPv6 compatible at the moment.
 */
static u_char smux_listen_addr[4] = { 0, 0, 0, 0 };

/*
 * Maximum number of connected SMUX peers - configurable
 */
u_int32_t smux_max_peers = SMUX_DEF_MAX_PEERS;

/*
 * The number of currently connected smux peers
 * The number is incremented each time when an
 * incoming  SMUX OPEN was accepted
 */
u_int32_t smux_peer_count = 0;

//TAILQ_HEAD(begemot_peer_tbl, begemot_peer);
/* THE begemotSmuxPeerTable table. */
static struct begemot_peer_tbl begemot_peer_tbl =
    TAILQ_HEAD_INITIALIZER(begemot_peer_tbl);

/*
 * Creates the listener socket and returns it
 * Returns -1 in case of an error.
 */
static int
smux_create_listener(const u_char ip_addr[4])
{
	struct sockaddr_in	 listener_addr;
	u_int32_t		 ip;
	int			 on = 1;
	int			 smux_sd = -1;

	/* XXX v4 only */	
    	if ((smux_sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        	syslog(LOG_ERR,
        		"%s: socket(AF_INET, SOCK_STREAM, 0) failed: %m",
                        __func__);
        	return (-1);
    	}
	if (setsockopt(smux_sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0){
        	syslog(LOG_ERR, "%s: setsockopt( SO_REUSEADDR ) failed: %m",
                          __func__);
        	/* This is not so bad, so we don't return an error */

        }

	/* XXX Hack */
	ip = (ip_addr[0] << 24) | (ip_addr[1] << 16) | (ip_addr[2] << 8) |
	    ip_addr[3];	
	
	memset(&listener_addr, 0, sizeof(listener_addr));
    	listener_addr.sin_family = AF_INET;
	listener_addr.sin_addr.s_addr = htonl(ip);
	listener_addr.sin_port = htons(smux_listener_port);
	listener_addr.sin_len = sizeof(listener_addr);    	
	
        SMUXDBG("SMUX: trying to bind on %s:%d", inet_ntoa(listener_addr.sin_addr),
        	smux_listener_port );          	
        	
        if (bind(smux_sd, (struct sockaddr *) &listener_addr,
             sizeof(listener_addr)) < 0) {
        	syslog(LOG_ERR, "%s: bind( %s:%d ) failed: %m",
                          __func__,
                          inet_ntoa(listener_addr.sin_addr),
                          smux_listener_port);

        	(void)close(smux_sd);
		return (-1);	
        }

	if (setsockopt(smux_sd, SOL_SOCKET, SO_KEEPALIVE, &on,
                   sizeof(on)) < 0) {
        	syslog(LOG_ERR, "%s: setsockopt( SO_KEEPALIVE ) failed: %m",
                          __func__);
        	/* This is not so bad, so we don't return an error */

        }

        if (listen(smux_sd, SOMAXCONN) == -1) {
		syslog(LOG_ERR, "%s: setsockopt( SO_KEEPALIVE ) failed: %m",
                          __func__);
        	(void)close(smux_sd);
		return (-1);	
	}

	return (smux_sd);
}

static void
smux_listener_callback(int fd, void *arg __unused)
{
	struct sockaddr_in peer_socket;
	socklen_t s_len;
	int peer_sd;
	s_len = sizeof(struct sockaddr_in);
	
	SMUXDBG("listener callback called");
	
	peer_sd = accept(fd, (struct sockaddr *) &peer_socket, &s_len);
	
	if (peer_sd < 0) {
		syslog(LOG_ERR, "%s: accept() failed: %m", __func__);
		return;
	}
	syslog(LOG_INFO, "New incoming SMUX peer from %s:%d",
		inet_ntoa(peer_socket.sin_addr),
                ntohs(peer_socket.sin_port));

        if (smux_max_peers <= smux_peer_count + 1) {

        	close(peer_sd);
        	
		syslog(LOG_INFO,
			"Max no of peers (%d) reached - droping %s:%d",
			smux_max_peers,
			inet_ntoa(peer_socket.sin_addr),
                	ntohs(peer_socket.sin_port));

		return;
        }

	smux_handle_new_peer(peer_sd, &peer_socket);
}


/*
 * Find a SMUX peer by its OID
 */
static
struct begemot_peer*
bpeer_get(struct asn_oid *index_p)
{

	struct begemot_peer* p;
	
	assert(index_p != NULL);
	if (index_p == NULL)
		return (NULL);
		
	TAILQ_FOREACH(p, &begemot_peer_tbl, link)
		if (asn_compare_oid(&p->index, index_p) == 0)
			return (p);

	return (NULL);		
}

/*
 * Create a peer.
 * No check is performed if a SMUX peer with the same OID
 * is already configured
 */
static
struct begemot_peer*
bpeer_create(struct asn_oid *index_p, const u_char * const password)
{
	struct begemot_peer* p = NULL;
	
	assert(index_p != NULL);
	
	
	p = (struct begemot_peer*)malloc(sizeof(*p));
	assert (p != NULL);		
	if (p == NULL)
		return (NULL);
	
	memcpy(&p->index, index_p, sizeof(*index_p));
	
	if (password == NULL)
		p->password = NULL;
	else
		p->password = strdup(password);
	
	
	p->status = 1; /* 1 means valid */
	p->timeout = 3; /* default timeout in seconds*/
	INSERT_OBJECT_OID(p, &begemot_peer_tbl);
	return (p);
	
}

/*
 * Delete a peer by its OID
 */
static
void
bpeer_delete(struct asn_oid *index_p)
{
	struct begemot_peer* entry = NULL;
	assert(index_p != NULL);
	if ((entry = bpeer_get(index_p)) != NULL) {
		TAILQ_REMOVE(&begemot_peer_tbl, entry, link);
		
		/* delete SMUX protocol peer */
		smux_shutdown_peer_by_id(&entry->index);
		
		if (entry->password != NULL) {
			free(entry->password);
			entry->password = NULL;
		}
		free(entry);
		entry = NULL;
	}
	
}


/*
 * Delete the entire list of configured SMUX peers
 */
static void
bpeer_table_delete(void)
{
	struct begemot_peer *n1;

	while ((n1 = TAILQ_FIRST(&begemot_peer_tbl)) != NULL) {
		TAILQ_REMOVE(&begemot_peer_tbl, n1, link);
		if (n1->password != NULL) {
			free(n1->password);
			n1->password = NULL;
		}	
		free(n1);
	}
}

static int
smux_init(struct lmodule *mod, int argc __unused, char *argv[] __unused)
{

	SMUXDBG("SMUX init: %s", __func__ );	
	smux_module = mod;
	SMUXDBG("SMUX init DONE: %s", __func__ );	

	return (0);
	
}

static int
smux_fini(void)
{
	SMUXDBG("SMUX finalizying: %s", __func__ );
	if (smux_registration_id > 0)
		or_unregister(smux_registration_id);
		
	/*
	 * Disconnect all the SMUX peers
	 * Cleanup all the data structures associated
	 * with smux protocol peers
	 */	
	smux_proto_cleanup();

        /*
         * Close the listener
         */
	if (smux_listener_id != NULL)
		fd_deselect(smux_listener_id);
	
	if (smux_listener_sd > 0)
		(void)close(smux_listener_sd);
		
	smux_listener_id = NULL;
	smux_listener_sd = -1;

	bpeer_table_delete();	

	SMUXDBG("SMUX fini DONE: %s", __func__ );
	return (0);
}


static void
smux_start(void)
{
	
	SMUXDBG("SMUX starting: %s", __func__ );
	
	smux_registration_id = or_register(&oid_smux,
	    "SMUX Implementation (rfc 1227)",
	    smux_module);

	/*
	 * Allocate reqid space for communicating with sub-agents.
	 * This will be freed after module unload.
	 */
	smux_reqid_type = reqid_allocate(SMUX_DEF_MAX_REQID, smux_module);
	if (0 == smux_reqid_type) {
	       	syslog(LOG_ERR, "%s: Failed to allocate reqid range",
        		__func__);
        	return;	
	}
	
	smux_listener_sd = smux_create_listener(smux_listen_addr);
	if (smux_listener_sd < 0) {
	       	syslog(LOG_ERR,
        		"%s: Failed to create SMUX listener socket",
        		__func__);
        	return;	

	}
	smux_listener_id =
		fd_select(smux_listener_sd, smux_listener_callback,
			NULL, smux_module);
	if (smux_listener_id == NULL) {
		syslog(LOG_ERR, "%s: SMUX Fatal error: failed to fd_select",
			__func__);
		abort();	
	}	
	SMUXDBG("SMUX start DONE: %s", __func__ );

}

int	
smux_authorize_peer(struct asn_oid *identity, char* password,
	uint32_t* timeout)
{
	struct begemot_peer* p;
	
	assert(identity != NULL);
	assert(password != NULL);
	assert(timeout != NULL);
		
	TAILQ_FOREACH(p, &begemot_peer_tbl, link) {
		SMUXDBG("Checking %s with pass %s",
			asn_oid2str(&p->index), p->password);
		if (asn_compare_oid(&p->index, identity) == 0 &&
			strcmp(p->password, password) == 0) {
			*timeout = p->timeout;
			return (1);
		}
	}
	return (0);	
}

/*
 * Instrumentation handler for the 2 scalars used for provisioning
 * this SMUX module
 */
int	
op_begemotSmuxObjects(struct snmp_context *ctx, struct snmp_value *value,
    u_int sub, u_int iidx __unused, enum snmp_op op)
{
	switch (op) {
	
	  case SNMP_OP_GETNEXT:
		abort();

	  case SNMP_OP_GET:
		switch (value->var.subs[sub - 1]) {

		  case LEAF_begemotSmuxAddr:
		  	return (ip_get(value, (void *)smux_listen_addr));

		  case LEAF_begemotSmuxPort:
			value->v.uint32 = smux_listener_port;
			return (SNMP_ERR_NOERROR);

		}
		abort();


	  case SNMP_OP_SET:
	  	/* only at initialization */
		if (community != COMM_INITIALIZE)
			return (SNMP_ERR_NOT_WRITEABLE);
			
		switch (value->var.subs[sub - 1]) {
		  case LEAF_begemotSmuxAddr:
			return (ip_save(value, ctx, smux_listen_addr));

		  case LEAF_begemotSmuxPort:
			ctx->scratch->int1 = smux_listener_port;
			smux_listener_port = value->v.uint32;
			SMUXDBG("Configured SMUX port = %d",
				smux_listener_port);
			return (SNMP_ERR_NOERROR);			
		}
		abort();

	  case SNMP_OP_COMMIT:

		switch (value->var.subs[sub - 1]) {
		
		  case LEAF_begemotSmuxAddr:
			ip_commit(ctx);
			return (SNMP_ERR_NOERROR);

		  case LEAF_begemotSmuxPort:
			return (SNMP_ERR_NOERROR);

		}
		abort();

	  case SNMP_OP_ROLLBACK:
		switch (value->var.subs[sub - 1]) {
		  case LEAF_begemotSmuxAddr:
			ip_rollback(ctx, smux_listen_addr);
			return (SNMP_ERR_NOERROR);

		  case LEAF_begemotSmuxPort:
			smux_listener_port = ctx->scratch->int1;
			return (SNMP_ERR_NOERROR);

		}
		abort();
	}

	abort();

}

/*
 * Instrumentation handler for table SmuxPeerTable used for provisioning
 * this SMUX module
 */
int
op_begemotSmuxPeerTable(struct snmp_context *ctx, struct snmp_value *value,
    u_int sub, u_int iidx __unused, enum snmp_op op)
{
	asn_subid_t which = value->var.subs[sub-1];
	struct begemot_peer *p;
	struct asn_oid new_oid;

	switch (op) {

	  case SNMP_OP_GETNEXT:
		if ((p = NEXT_OBJECT_OID(&begemot_peer_tbl,
		 	&value->var, sub)) == NULL)
			return (SNMP_ERR_NOSUCHNAME);
		index_append(&value->var, sub, &p->index);
		break;

	  case SNMP_OP_GET:
  		if ((p = FIND_OBJECT_OID(&begemot_peer_tbl,
		    &value->var, sub)) == NULL)
			return (SNMP_ERR_NOSUCHNAME);
		break;

	  case SNMP_OP_SET:

		p = FIND_OBJECT_OID(&begemot_peer_tbl, &value->var, sub);
		ctx->scratch->int1 = (p != NULL);

		switch (which) {
		    case LEAF_begemotSmuxPeerPassword:
			if (p == NULL) {
			
				ctx->scratch->int2 &= ~1;
				
				asn_slice_oid(&new_oid, &value->var, sub,
					value->var.len);
				
				if ((p = bpeer_create(&new_oid, "")) == NULL)
					return (SNMP_ERR_GENERR);
			
			}
			
			if (string_save(value, ctx, -1, &p->password) != 0)
				return (SNMP_ERR_GENERR);
			else
				return (SNMP_ERR_NOERROR);
		
		    case LEAF_begemotSmuxPeerStatus:
			if (value->v.integer == 1) {
				ctx->scratch->int2 &= ~1;	
				/* add an entry */
				if (p != NULL)
					/* already in list - do nothing */
					return (SNMP_ERR_NOERROR);

				asn_slice_oid(&new_oid, &value->var, sub,
					value->var.len);
				
				if (bpeer_create(&new_oid, "") == NULL)
					return (SNMP_ERR_GENERR);
				else
					return (SNMP_ERR_NOERROR);
				  	
				  	
			} else if (value->v.integer == 2)
				ctx->scratch->int2 |= 1;
				/*  deletion is done in commit */
			else
				return (SNMP_ERR_WRONG_VALUE);
				
		   case LEAF_begemotSmuxPeerTimeout: 		
	        	if (value->v.integer < 0 || value->v.integer > 128)
	        		return (SNMP_ERR_WRONG_VALUE);
	        		
	        	ctx->scratch->int2 = (ctx->scratch->int2 & 1) |
	        		( p->timeout << 1);
	        	p->timeout = value->v.integer;
			return (SNMP_ERR_NOERROR);
		
		   default:
	        	SMUXDBG("SNMP_OP_SET/ UNKNOWN field...");
	               	abort();
		}	
		return (SNMP_ERR_NOERROR);

	  case SNMP_OP_ROLLBACK:
		p =  FIND_OBJECT_OID(&begemot_peer_tbl,	&value->var, sub);
		
		switch (which) {
	 	    case LEAF_begemotSmuxPeerPassword:
	        	if (p != NULL)
				string_rollback(ctx, &p->password);
			else
				string_free(ctx);
				
		    	return (SNMP_ERR_NOERROR);
		    				
		    case LEAF_begemotSmuxPeerStatus:
			if (ctx->scratch->int1 == 0) {
				/* did not exist */
				if ((ctx->scratch->int2 & 1) == 0) {
					/* created */
					if (p != NULL) {
						bpeer_delete(&p->index);
						p = NULL;
					}
				}
			}
	        	return (SNMP_ERR_NOERROR);
	        	
		    case LEAF_begemotSmuxPeerTimeout:
			if (p != NULL)
				p->timeout = ctx->scratch->int2 >> 1;
				
	        	ctx->scratch->int2 = ctx->scratch->int2 & 1;
			return (SNMP_ERR_NOERROR);
			
		    default:
			SMUXDBG("SNMP_OP_ROLLBACK/ UNKNOWN field...");
			abort();
		}
		return (SNMP_ERR_NOERROR);

	  case SNMP_OP_COMMIT:
		p = FIND_OBJECT_OID(&begemot_peer_tbl,	&value->var, sub);
	
		switch (which) {
	  	    case LEAF_begemotSmuxPeerPassword:
	        	string_commit(ctx);
			return (SNMP_ERR_NOERROR);
				
		    case LEAF_begemotSmuxPeerStatus:
	        	if (ctx->scratch->int1 == 1) {
				/* did exist */
				if ((ctx->scratch->int2 & 1) == 1) {
					/* delete */
					if (p != NULL) {
						bpeer_delete(&p->index);
						p = NULL;
					}	
				}
			}
			return (SNMP_ERR_NOERROR);
	        	
		    case LEAF_begemotSmuxPeerTimeout:
			smux_set_peer_timeout(&p->index, p->timeout);
			return (SNMP_ERR_NOERROR);
			
		    default:
			SMUXDBG("SNMP_OP_COMMIT/ UNKNOWN field...");
			abort();
		}
		return (SNMP_ERR_NOERROR);

	  default:
		abort();
	}

	/*
	 * Come here to fetch the value
	 */
	switch (which) {

	  case LEAF_begemotSmuxPeerPassword:
	  	return (string_get(value, p->password, -1));
	  case LEAF_begemotSmuxPeerStatus:
	  	value->v.integer = 1;
	  	break;
	  case LEAF_begemotSmuxPeerTimeout:
	  	value->v.integer = p->timeout;	
	  	break;
	  default:
		abort();
	}

	return (SNMP_ERR_NOERROR);
}

const char smux_comment[] = \
"SMUX Sub-agent passthrough for Begemot SNMPD (RFC 1227)";

const struct snmp_module config = {
        .comment =      smux_comment,
        .init =         smux_init,
        .fini =         smux_fini,
        .start =        smux_start,
        .tree =         smux_ctree,
        .tree_size =    smux_CTREE_SIZE,
};
