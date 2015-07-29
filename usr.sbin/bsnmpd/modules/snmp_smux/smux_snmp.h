#ifndef _SMUX_SNMP_H_
#define _SMUX_SNMP_H_
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

struct sockaddr_in;
struct asn_oid;
struct lmodule;

#ifndef NDEBUG
 #define	SMUXDBG(...) do {					\
	fprintf(stderr, "SMUX: %s: ", __func__);			\
	fprintf(stderr, __VA_ARGS__);					\
	fprintf(stderr, "\n");						\
   } while (0)
#else
 #define	SMUXDBG(...) do { } while (0)
#endif /*NDEBUG*/

/*
 * This structure represents one row in the begemotSmuxPeerTable
 * begemotSmuxPeerTable is used to configure this BSNMPd SMUX  module
 */
struct begemot_peer {
	struct asn_oid	index;		/* SNMP Index */
	u_char *	password;
	uint32_t 	timeout;
	int		status;
	TAILQ_ENTRY(begemot_peer) link;
};
TAILQ_HEAD(begemot_peer_tbl, begemot_peer);

int	smux_authorize_peer(struct asn_oid *, char *, uint32_t *);
void 	smux_handle_new_peer(int, struct sockaddr_in *);	/* XXX v4 */
void	smux_proto_cleanup(void);
void	smux_shutdown_peer_by_id(const struct asn_oid *);
void	smux_set_peer_timeout(const struct asn_oid *, uint32_t);

extern struct lmodule *smux_module;
extern uint32_t smux_peer_count;
extern u_int smux_reqid_type;

#define SMUX_LISTENER_PORT	199	/* TCP port 199 */
#define SMUX_DEF_MAX_PEERS      16      /* default: maximum number of sub-agents */
#define SMUX_DEF_MAX_REQID      1024    /* reqid space to allocate from master */

#endif  /* _SMUX_SNMP_H_ */
