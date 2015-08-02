/*
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Implementation of the ... protocol as defined in ...
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/kernel.h>
#include <sys/callout.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/taskqueue.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_llc.h>
#include <net/if_media.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
/*#include <net/bridgestp.h>*/
#include <net/eaps.h>

/* compare two OUI values for equality */
#define IEEE_OUI_ARE_EQUAL(a, b) \
	(((uint8_t *)(a))[0] == ((uint8_t *)(b))[0] && \
	 ((uint8_t *)(a))[1] == ((uint8_t *)(b))[1] && \
	 ((uint8_t *)(a))[2] == ((uint8_t *)(b)[2])

#ifdef	EAPS_DEBUG
#define	DPRINTF(fmt, arg...)	printf("eaps: " fmt, ##arg)
#else
#define	DPRINTF(fmt, arg...)	(void)0
#endif

#if 0
#define	PV2ADDR(pv, eaddr)	do {		\
	eaddr[0] = pv >> 40;			\
	eaddr[1] = pv >> 32;			\
	eaddr[2] = pv >> 24;			\
	eaddr[3] = pv >> 16;			\
	eaddr[4] = pv >> 8;			\
	eaddr[5] = pv >> 0;			\
} while (0)

#define	INFO_BETTER	1
#define	INFO_SAME	0
#define	INFO_WORSE	-1
#endif

const uint8_t extreme_oui[] = EXTREME_OUI_INIT;
const uint8_t eaps_etheraddr[] = EAPS_ETHERADDR_INIT;

#if 0
LIST_HEAD(, eaps_state) eaps_list;
static struct mtx	eaps_list_mtx;

static void	eaps_transmit(struct eaps_state *, struct eaps_port *);
static void	eaps_transmit_bpdu(struct eaps_state *, struct eaps_port *);
static void	eaps_transmit_tcn(struct eaps_state *, struct eaps_port *);
static void	eaps_decode_bpdu(struct eaps_port *, struct eaps_cbpdu *,
		    struct eaps_config_unit *);
static void	eaps_send_bpdu(struct eaps_state *, struct eaps_port *,
		    struct eaps_cbpdu *);
static int	eaps_pdu_flags(struct eaps_port *);
static void	eaps_received_stp(struct eaps_state *, struct eaps_port *,
		    struct mbuf **, struct eaps_tbpdu *);
static void	eaps_received_rstp(struct eaps_state *, struct eaps_port *,
		    struct mbuf **, struct eaps_tbpdu *);
static void	eaps_received_tcn(struct eaps_state *, struct eaps_port *,
		    struct eaps_tcn_unit *);
static void	eaps_received_bpdu(struct eaps_state *, struct eaps_port *,
		    struct eaps_config_unit *);
static int	eaps_pdu_rcvtype(struct eaps_port *, struct eaps_config_unit *);
static int	eaps_pdu_bettersame(struct eaps_port *, int);
static int	eaps_info_cmp(struct eaps_pri_vector *,
		    struct eaps_pri_vector *);
static int	eaps_info_superior(struct eaps_pri_vector *,
		    struct eaps_pri_vector *);
static void	eaps_assign_roles(struct eaps_state *);
static void	eaps_update_roles(struct eaps_state *, struct eaps_port *);
static void	eaps_update_state(struct eaps_state *, struct eaps_port *);
static void	eaps_update_tc(struct eaps_port *);
static void	eaps_update_info(struct eaps_port *);
static void	eaps_set_other_tcprop(struct eaps_port *);
static void	eaps_set_all_reroot(struct eaps_state *);
static void	eaps_set_all_sync(struct eaps_state *);
static void	eaps_set_port_state(struct eaps_port *, int);
static void	eaps_set_port_role(struct eaps_port *, int);
static void	eaps_set_port_proto(struct eaps_port *, int);
static void	eaps_set_port_tc(struct eaps_port *, int);
static void	eaps_set_timer_tc(struct eaps_port *);
static void	eaps_set_timer_msgage(struct eaps_port *);
static int	eaps_rerooted(struct eaps_state *, struct eaps_port *);
static uint32_t	eaps_calc_path_cost(struct eaps_port *);
static void	eaps_notify_state(void *, int);
static void	eaps_notify_rtage(void *, int);
static void	eaps_ifupdstatus(void *, int);
static void	eaps_enable_port(struct eaps_state *, struct eaps_port *);
static void	eaps_disable_port(struct eaps_state *, struct eaps_port *);
static void	eaps_tick(void *);
static void	eaps_timer_start(struct eaps_timer *, uint16_t);
static void	eaps_timer_stop(struct eaps_timer *);
static void	eaps_timer_latch(struct eaps_timer *);
static int	eaps_timer_dectest(struct eaps_timer *);
static void	eaps_hello_timer_expiry(struct eaps_state *,
		    struct eaps_port *);
static void	eaps_message_age_expiry(struct eaps_state *,
		    struct eaps_port *);
static void	eaps_migrate_delay_expiry(struct eaps_state *,
		    struct eaps_port *);
static void	eaps_edge_delay_expiry(struct eaps_state *,
		    struct eaps_port *);
static int	eaps_addr_cmp(const uint8_t *, const uint8_t *);
static int	eaps_same_bridgeid(uint64_t, uint64_t);
static void	eaps_reinit(struct eaps_state *);
#endif

#if 0
static void
eaps_transmit(struct eaps_state *bs, struct eaps_port *bp)
{
	if (bs->bs_running == 0)
		return;

	/*
	 * a PDU can only be sent if we have tx quota left and the
	 * hello timer is running.
	 */
	if (bp->bp_hello_timer.active == 0) {
		/* Test if it needs to be reset */
		eaps_hello_timer_expiry(bs, bp);
		return;
	}
	if (bp->bp_txcount > bs->bs_txholdcount)
		/* Ran out of karma */
		return;

	if (bp->bp_protover == EAPS_PROTO_RSTP) {
		eaps_transmit_bpdu(bs, bp);
		bp->bp_tc_ack = 0;
	} else { /* STP */
		switch (bp->bp_role) {
			case EAPS_ROLE_DESIGNATED:
				eaps_transmit_bpdu(bs, bp);
				bp->bp_tc_ack = 0;
				break;

			case EAPS_ROLE_ROOT:
				eaps_transmit_tcn(bs, bp);
				break;
		}
	}
	eaps_timer_start(&bp->bp_hello_timer, bp->bp_desg_htime);
	bp->bp_flags &= ~EAPS_PORT_NEWINFO;
}

static void
eaps_transmit_bpdu(struct eaps_state *bs, struct eaps_port *bp)
{
	struct eaps_cbpdu bpdu;

	EAPS_LOCK_ASSERT(bs);

	bpdu.cbu_rootpri = htons(bp->bp_desg_pv.pv_root_id >> 48);
	PV2ADDR(bp->bp_desg_pv.pv_root_id, bpdu.cbu_rootaddr);

	bpdu.cbu_rootpathcost = htonl(bp->bp_desg_pv.pv_cost);

	bpdu.cbu_bridgepri = htons(bp->bp_desg_pv.pv_dbridge_id >> 48);
	PV2ADDR(bp->bp_desg_pv.pv_dbridge_id, bpdu.cbu_bridgeaddr);

	bpdu.cbu_portid = htons(bp->bp_port_id);
	bpdu.cbu_messageage = htons(bp->bp_desg_msg_age);
	bpdu.cbu_maxage = htons(bp->bp_desg_max_age);
	bpdu.cbu_hellotime = htons(bp->bp_desg_htime);
	bpdu.cbu_forwarddelay = htons(bp->bp_desg_fdelay);

	bpdu.cbu_flags = eaps_pdu_flags(bp);

	switch (bp->bp_protover) {
		case EAPS_PROTO_STP:
			bpdu.cbu_bpdutype = EAPS_MSGTYPE_CFG;
			break;

		case EAPS_PROTO_RSTP:
			bpdu.cbu_bpdutype = EAPS_MSGTYPE_RSTP;
			break;
	}

	eaps_send_bpdu(bs, bp, &bpdu);
}

static void
eaps_transmit_tcn(struct eaps_state *bs, struct eaps_port *bp)
{
	struct eaps_tbpdu bpdu;
	struct ifnet *ifp = bp->bp_ifp;
	struct ether_header *eh;
	struct mbuf *m;

	KASSERT(bp == bs->bs_root_port, ("%s: bad root port\n", __func__));

	if ((ifp->if_drv_flags & IFF_DRV_RUNNING) == 0)
		return;

	m = m_gethdr(M_NOWAIT, MT_DATA);
	if (m == NULL)
		return;

	m->m_pkthdr.rcvif = ifp;
	m->m_pkthdr.len = sizeof(*eh) + sizeof(bpdu);
	m->m_len = m->m_pkthdr.len;

	eh = mtod(m, struct ether_header *);

	memcpy(eh->ether_shost, IF_LLADDR(ifp), ETHER_ADDR_LEN);
	memcpy(eh->ether_dhost, eaps_etheraddr, ETHER_ADDR_LEN);
	eh->ether_type = htons(sizeof(bpdu));

	bpdu.tbu_ssap = bpdu.tbu_dsap = LLC_8021D_LSAP;
	bpdu.tbu_ctl = LLC_UI;
	bpdu.tbu_protoid = 0;
	bpdu.tbu_protover = 0;
	bpdu.tbu_bpdutype = EAPS_MSGTYPE_TCN;

	memcpy(mtod(m, caddr_t) + sizeof(*eh), &bpdu, sizeof(bpdu));

	bp->bp_txcount++;
	ifp->if_transmit(ifp, m);
}
#endif

#if 0
static void
eaps_decode_bpdu(struct eaps_port *bp, struct eaps_cbpdu *cpdu,
    struct eaps_config_unit *cu)
{
	int flags;

	cu->cu_pv.pv_root_id =
	    (((uint64_t)ntohs(cpdu->cbu_rootpri)) << 48) |
	    (((uint64_t)cpdu->cbu_rootaddr[0]) << 40) |
	    (((uint64_t)cpdu->cbu_rootaddr[1]) << 32) |
	    (((uint64_t)cpdu->cbu_rootaddr[2]) << 24) |
	    (((uint64_t)cpdu->cbu_rootaddr[3]) << 16) |
	    (((uint64_t)cpdu->cbu_rootaddr[4]) << 8) |
	    (((uint64_t)cpdu->cbu_rootaddr[5]) << 0);

	cu->cu_pv.pv_dbridge_id =
	    (((uint64_t)ntohs(cpdu->cbu_bridgepri)) << 48) |
	    (((uint64_t)cpdu->cbu_bridgeaddr[0]) << 40) |
	    (((uint64_t)cpdu->cbu_bridgeaddr[1]) << 32) |
	    (((uint64_t)cpdu->cbu_bridgeaddr[2]) << 24) |
	    (((uint64_t)cpdu->cbu_bridgeaddr[3]) << 16) |
	    (((uint64_t)cpdu->cbu_bridgeaddr[4]) << 8) |
	    (((uint64_t)cpdu->cbu_bridgeaddr[5]) << 0);

	cu->cu_pv.pv_cost = ntohl(cpdu->cbu_rootpathcost);
	cu->cu_message_age = ntohs(cpdu->cbu_messageage);
	cu->cu_max_age = ntohs(cpdu->cbu_maxage);
	cu->cu_hello_time = ntohs(cpdu->cbu_hellotime);
	cu->cu_forward_delay = ntohs(cpdu->cbu_forwarddelay);
	cu->cu_pv.pv_dport_id = ntohs(cpdu->cbu_portid);
	cu->cu_pv.pv_port_id = bp->bp_port_id;
	cu->cu_message_type = cpdu->cbu_bpdutype;

	/* Strip off unused flags in STP mode */
	flags = cpdu->cbu_flags;
	switch (cpdu->cbu_protover) {
		case EAPS_PROTO_STP:
			flags &= EAPS_PDU_STPMASK;
			/* A STP BPDU explicitly conveys a Designated Port */
			cu->cu_role = EAPS_ROLE_DESIGNATED;
			break;

		case EAPS_PROTO_RSTP:
			flags &= EAPS_PDU_RSTPMASK;
			break;
	}

	cu->cu_topology_change_ack =
		(flags & EAPS_PDU_F_TCA) ? 1 : 0;
	cu->cu_proposal =
		(flags & EAPS_PDU_F_P) ? 1 : 0;
	cu->cu_agree =
		(flags & EAPS_PDU_F_A) ? 1 : 0;
	cu->cu_learning =
		(flags & EAPS_PDU_F_L) ? 1 : 0;
	cu->cu_forwarding =
		(flags & EAPS_PDU_F_F) ? 1 : 0;
	cu->cu_topology_change =
		(flags & EAPS_PDU_F_TC) ? 1 : 0;

	switch ((flags & EAPS_PDU_PRMASK) >> EAPS_PDU_PRSHIFT) {
		case EAPS_PDU_F_ROOT:
			cu->cu_role = EAPS_ROLE_ROOT;
			break;
		case EAPS_PDU_F_ALT:
			cu->cu_role = EAPS_ROLE_ALTERNATE;
			break;
		case EAPS_PDU_F_DESG:
			cu->cu_role = EAPS_ROLE_DESIGNATED;
			break;
	}
}
#endif

#if 0
static void
eaps_send_bpdu(struct eaps_state *bs, struct eaps_port *bp,
    struct eaps_cbpdu *bpdu)
{
	struct ifnet *ifp;
	struct mbuf *m;
	struct ether_header *eh;

	EAPS_LOCK_ASSERT(bs);

	ifp = bp->bp_ifp;

	if ((ifp->if_drv_flags & IFF_DRV_RUNNING) == 0)
		return;

	m = m_gethdr(M_NOWAIT, MT_DATA);
	if (m == NULL)
		return;

	eh = mtod(m, struct ether_header *);

	bpdu->cbu_ssap = bpdu->cbu_dsap = LLC_8021D_LSAP;
	bpdu->cbu_ctl = LLC_UI;
	bpdu->cbu_protoid = htons(EAPS_PROTO_ID);

	memcpy(eh->ether_shost, IF_LLADDR(ifp), ETHER_ADDR_LEN);
	memcpy(eh->ether_dhost, eaps_etheraddr, ETHER_ADDR_LEN);

	switch (bpdu->cbu_bpdutype) {
		case EAPS_MSGTYPE_CFG:
			bpdu->cbu_protover = EAPS_PROTO_STP;
			m->m_pkthdr.len = sizeof(*eh) + EAPS_BPDU_STP_LEN;
			eh->ether_type = htons(EAPS_BPDU_STP_LEN);
			memcpy(mtod(m, caddr_t) + sizeof(*eh), bpdu,
			    EAPS_BPDU_STP_LEN);
			break;

		case EAPS_MSGTYPE_RSTP:
			bpdu->cbu_protover = EAPS_PROTO_RSTP;
			bpdu->cbu_versionlen = htons(0);
			m->m_pkthdr.len = sizeof(*eh) + EAPS_BPDU_RSTP_LEN;
			eh->ether_type = htons(EAPS_BPDU_RSTP_LEN);
			memcpy(mtod(m, caddr_t) + sizeof(*eh), bpdu,
			    EAPS_BPDU_RSTP_LEN);
			break;

		default:
			panic("not implemented");
	}
	m->m_pkthdr.rcvif = ifp;
	m->m_len = m->m_pkthdr.len;

	bp->bp_txcount++;
	ifp->if_transmit(ifp, m);
}
#endif

static int
eaps_pdu_flags(struct eaps_port *bp)
{
	int flags = 0;

	if (bp->bp_proposing && bp->bp_state != EAPS_IFSTATE_FORWARDING)
		flags |= EAPS_PDU_F_P;

	if (bp->bp_agree)
		flags |= EAPS_PDU_F_A;

	if (bp->bp_tc_timer.active)
		flags |= EAPS_PDU_F_TC;

	if (bp->bp_tc_ack)
		flags |= EAPS_PDU_F_TCA;

	switch (bp->bp_state) {
		case EAPS_IFSTATE_LEARNING:
			flags |= EAPS_PDU_F_L;
			break;

		case EAPS_IFSTATE_FORWARDING:
			flags |= (EAPS_PDU_F_L | EAPS_PDU_F_F);
			break;
	}

	switch (bp->bp_role) {
		case EAPS_ROLE_ROOT:
			flags |=
				(EAPS_PDU_F_ROOT << EAPS_PDU_PRSHIFT);
			break;

		case EAPS_ROLE_ALTERNATE:
		case EAPS_ROLE_BACKUP:	/* fall through */
			flags |=
				(EAPS_PDU_F_ALT << EAPS_PDU_PRSHIFT);
			break;

		case EAPS_ROLE_DESIGNATED:
			flags |=
				(EAPS_PDU_F_DESG << EAPS_PDU_PRSHIFT);
			break;
	}

	/* Strip off unused flags in either mode */
	switch (bp->bp_protover) {
		case EAPS_PROTO_STP:
			flags &= EAPS_PDU_STPMASK;
			break;
		case EAPS_PROTO_RSTP:
			flags &= EAPS_PDU_RSTPMASK;
			break;
	}
	return (flags);
}

void
eaps_input(struct eaps_port *bp, struct ifnet *ifp, struct mbuf *m)
{
	struct eaps_state *bs = bp->bp_bs;
	struct ether_header *eh;
	//struct eaps_tbpdu tpdu;
	uint16_t len;
	struct llc *l;

#if 0
	if (bp->bp_active == 0) {
		m_freem(m);
		return;
	}
#endif

#if 0
	EAPS_LOCK(bs);
#endif

	eh = mtod(m, struct ether_header *);

	len = ntohs(eh->ether_type);
	//if (len < sizeof(tpdu))
	//	goto out;

	/* XXX Would additionally check ether dst here with eaps_etheraddr. */

	m_adj(m, ETHER_HDR_LEN);

	/* XXX Pull up to minimum size eth + llc-snap + edp */
	if (m->m_pkthdr.len > len)
		m_adj(m, len - m->m_pkthdr.len);
	if (m->m_len < sizeof(tpdu) &&
	    (m = m_pullup(m, sizeof(tpdu))) == NULL)
		goto out;

	/* basic packet checks */
	if (l->llc_dsap != LLC_SNAP_LSAP ||
	    l->llc_ssap != LLC_SNAP_LSAP)
		goto out;

	if (l->llc_snap.control != LLC_UI ||
	    !IEEE_OUI_ARE_EQUAL(&l->llc_snap.org_code[0], extreme_oui) ||
	    l->llc_snap.ether_type != EDP_SNAP_PID)
		goto out;

	/* ...now parse EDP header and checksum, index into it, don't pullup.  */
	/* ... while we have TLVs... */
		/* ...now parse EAPS fields */
		/* ...now parse or discard additional TLVs fields */
	/* done */

#if 0
	/*
	 * We can treat later versions of the PDU as the same as the maximum
	 * version we implement. All additional parameters/flags are ignored.
	 */
	if (tpdu.tbu_protover > EAPS_PROTO_MAX)
		tpdu.tbu_protover = EAPS_PROTO_MAX;

	if (tpdu.tbu_protover != bp->bp_protover) {
		/*
		 * Wait for the migration delay timer to expire before changing
		 * protocol version to avoid flip-flops.
		 */
		if (bp->bp_flags & EAPS_PORT_CANMIGRATE)
			eaps_set_port_proto(bp, tpdu.tbu_protover);
		else
			goto out;
	}
#endif

#if 0
	/* Clear operedge upon receiving a PDU on the port */
	bp->bp_operedge = 0;
	eaps_timer_start(&bp->bp_edge_delay_timer,
	    EAPS_DEFAULT_MIGRATE_DELAY);

	switch (tpdu.tbu_protover) {
		case EAPS_PROTO_STP:
			eaps_received_stp(bs, bp, &m, &tpdu);
			break;

		case EAPS_PROTO_RSTP:
			eaps_received_rstp(bs, bp, &m, &tpdu);
			break;
	}
#endif

out:
#if 0
	EAPS_UNLOCK(bs);
#endif
	if (m)
		m_freem(m);
}

#if 0
static void
eaps_received_stp(struct eaps_state *bs, struct eaps_port *bp,
    struct mbuf **mp, struct eaps_tbpdu *tpdu)
{
	struct eaps_cbpdu cpdu;
	struct eaps_config_unit *cu = &bp->bp_msg_cu;
	struct eaps_tcn_unit tu;

	switch (tpdu->tbu_bpdutype) {
	case EAPS_MSGTYPE_TCN:
		tu.tu_message_type = tpdu->tbu_bpdutype;
		eaps_received_tcn(bs, bp, &tu);
		break;
	case EAPS_MSGTYPE_CFG:
		if ((*mp)->m_len < EAPS_BPDU_STP_LEN &&
		    (*mp = m_pullup(*mp, EAPS_BPDU_STP_LEN)) == NULL)
			return;
		memcpy(&cpdu, mtod(*mp, caddr_t), EAPS_BPDU_STP_LEN);

		eaps_decode_bpdu(bp, &cpdu, cu);
		eaps_received_bpdu(bs, bp, cu);
		break;
	}
}
#endif

static void
eaps_received_rstp(struct eaps_state *bs, struct eaps_port *bp,
    struct mbuf **mp, struct eaps_tbpdu *tpdu)
{
	struct eaps_cbpdu cpdu;
	struct eaps_config_unit *cu = &bp->bp_msg_cu;

	if (tpdu->tbu_bpdutype != EAPS_MSGTYPE_RSTP)
		return;

	if ((*mp)->m_len < EAPS_BPDU_RSTP_LEN &&
	    (*mp = m_pullup(*mp, EAPS_BPDU_RSTP_LEN)) == NULL)
		return;
	memcpy(&cpdu, mtod(*mp, caddr_t), EAPS_BPDU_RSTP_LEN);

	eaps_decode_bpdu(bp, &cpdu, cu);
	eaps_received_bpdu(bs, bp, cu);
}

static void
eaps_received_tcn(struct eaps_state *bs, struct eaps_port *bp,
    struct eaps_tcn_unit *tcn)
{
	bp->bp_rcvdtcn = 1;
	eaps_update_tc(bp);
}

static void
eaps_received_bpdu(struct eaps_state *bs, struct eaps_port *bp,
    struct eaps_config_unit *cu)
{
	int type;

	EAPS_LOCK_ASSERT(bs);

	/* We need to have transitioned to INFO_MINE before proceeding */
	switch (bp->bp_infois) {
		case EAPS_INFO_DISABLED:
		case EAPS_INFO_AGED:
			return;
	}

	type = eaps_pdu_rcvtype(bp, cu);

	switch (type) {
		case EAPS_PDU_SUPERIOR:
			bs->bs_allsynced = 0;
			bp->bp_agreed = 0;
			bp->bp_proposing = 0;

			if (cu->cu_proposal && cu->cu_forwarding == 0)
				bp->bp_proposed = 1;
			if (cu->cu_topology_change)
				bp->bp_rcvdtc = 1;
			if (cu->cu_topology_change_ack)
				bp->bp_rcvdtca = 1;

			if (bp->bp_agree &&
			    !eaps_pdu_bettersame(bp, EAPS_INFO_RECEIVED))
				bp->bp_agree = 0;

			/* copy the received priority and timers to the port */
			bp->bp_port_pv = cu->cu_pv;
			bp->bp_port_msg_age = cu->cu_message_age;
			bp->bp_port_max_age = cu->cu_max_age;
			bp->bp_port_fdelay = cu->cu_forward_delay;
			bp->bp_port_htime =
				(cu->cu_hello_time > EAPS_MIN_HELLO_TIME ?
				 cu->cu_hello_time : EAPS_MIN_HELLO_TIME);

			/* set expiry for the new info */
			eaps_set_timer_msgage(bp);

			bp->bp_infois = EAPS_INFO_RECEIVED;
			eaps_assign_roles(bs);
			break;

		case EAPS_PDU_REPEATED:
			if (cu->cu_proposal && cu->cu_forwarding == 0)
				bp->bp_proposed = 1;
			if (cu->cu_topology_change)
				bp->bp_rcvdtc = 1;
			if (cu->cu_topology_change_ack)
				bp->bp_rcvdtca = 1;

			/* rearm the age timer */
			eaps_set_timer_msgage(bp);
			break;

		case EAPS_PDU_INFERIOR:
			if (cu->cu_learning) {
				bp->bp_agreed = 1;
				bp->bp_proposing = 0;
			}
			break;

		case EAPS_PDU_INFERIORALT:
			/*
			 * only point to point links are allowed fast
			 * transitions to forwarding.
			 */
			if (cu->cu_agree && bp->bp_ptp_link) {
				bp->bp_agreed = 1;
				bp->bp_proposing = 0;
			} else
				bp->bp_agreed = 0;

			if (cu->cu_topology_change)
				bp->bp_rcvdtc = 1;
			if (cu->cu_topology_change_ack)
				bp->bp_rcvdtca = 1;
			break;

		case EAPS_PDU_OTHER:
			return;	/* do nothing */
	}
	/* update the state machines with the new data */
	eaps_update_state(bs, bp);
}

static int
eaps_pdu_rcvtype(struct eaps_port *bp, struct eaps_config_unit *cu)
{
	int type;

	/* default return type */
	type = EAPS_PDU_OTHER;

	switch (cu->cu_role) {
	case EAPS_ROLE_DESIGNATED:
		if (eaps_info_superior(&bp->bp_port_pv, &cu->cu_pv))
			/* bpdu priority is superior */
			type = EAPS_PDU_SUPERIOR;
		else if (eaps_info_cmp(&bp->bp_port_pv, &cu->cu_pv) ==
		    INFO_SAME) {
			if (bp->bp_port_msg_age != cu->cu_message_age ||
			    bp->bp_port_max_age != cu->cu_max_age ||
			    bp->bp_port_fdelay != cu->cu_forward_delay ||
			    bp->bp_port_htime != cu->cu_hello_time)
				/* bpdu priority is equal and timers differ */
				type = EAPS_PDU_SUPERIOR;
			else
				/* bpdu is equal */
				type = EAPS_PDU_REPEATED;
		} else
			/* bpdu priority is worse */
			type = EAPS_PDU_INFERIOR;

		break;

	case EAPS_ROLE_ROOT:
	case EAPS_ROLE_ALTERNATE:
	case EAPS_ROLE_BACKUP:
		if (eaps_info_cmp(&bp->bp_port_pv, &cu->cu_pv) <= INFO_SAME)
			/*
			 * not a designated port and priority is the same or
			 * worse
			 */
			type = EAPS_PDU_INFERIORALT;
		break;
	}

	return (type);
}

static int
eaps_pdu_bettersame(struct eaps_port *bp, int newinfo)
{
	if (newinfo == EAPS_INFO_RECEIVED &&
	    bp->bp_infois == EAPS_INFO_RECEIVED &&
	    eaps_info_cmp(&bp->bp_port_pv, &bp->bp_msg_cu.cu_pv) >= INFO_SAME)
		return (1);

	if (newinfo == EAPS_INFO_MINE &&
	    bp->bp_infois == EAPS_INFO_MINE &&
	    eaps_info_cmp(&bp->bp_port_pv, &bp->bp_desg_pv) >= INFO_SAME)
		return (1);

	return (0);
}

static int
eaps_info_cmp(struct eaps_pri_vector *pv,
    struct eaps_pri_vector *cpv)
{
	if (cpv->pv_root_id < pv->pv_root_id)
		return (INFO_BETTER);
	if (cpv->pv_root_id > pv->pv_root_id)
		return (INFO_WORSE);

	if (cpv->pv_cost < pv->pv_cost)
		return (INFO_BETTER);
	if (cpv->pv_cost > pv->pv_cost)
		return (INFO_WORSE);

	if (cpv->pv_dbridge_id < pv->pv_dbridge_id)
		return (INFO_BETTER);
	if (cpv->pv_dbridge_id > pv->pv_dbridge_id)
		return (INFO_WORSE);

	if (cpv->pv_dport_id < pv->pv_dport_id)
		return (INFO_BETTER);
	if (cpv->pv_dport_id > pv->pv_dport_id)
		return (INFO_WORSE);

	return (INFO_SAME);
}

/*
 * This message priority vector is superior to the port priority vector and
 * will replace it if, and only if, the message priority vector is better than
 * the port priority vector, or the message has been transmitted from the same
 * designated bridge and designated port as the port priority vector.
 */
static int
eaps_info_superior(struct eaps_pri_vector *pv,
    struct eaps_pri_vector *cpv)
{
	if (eaps_info_cmp(pv, cpv) == INFO_BETTER ||
	    (eaps_same_bridgeid(pv->pv_dbridge_id, cpv->pv_dbridge_id) &&
	    (cpv->pv_dport_id & 0xfff) == (pv->pv_dport_id & 0xfff)))
		return (1);
	return (0);
}

static void
eaps_assign_roles(struct eaps_state *bs)
{
	struct eaps_port *bp, *rbp = NULL;
	struct eaps_pri_vector pv;

	/* default to our priority vector */
	bs->bs_root_pv = bs->bs_bridge_pv;
	bs->bs_root_msg_age = 0;
	bs->bs_root_max_age = bs->bs_bridge_max_age;
	bs->bs_root_fdelay = bs->bs_bridge_fdelay;
	bs->bs_root_htime = bs->bs_bridge_htime;
	bs->bs_root_port = NULL;

	/* check if any recieved info supersedes us */
	LIST_FOREACH(bp, &bs->bs_bplist, bp_next) {
		if (bp->bp_infois != EAPS_INFO_RECEIVED)
			continue;

		pv = bp->bp_port_pv;
		pv.pv_cost += bp->bp_path_cost;

		/*
		 * The root priority vector is the best of the set comprising
		 * the bridge priority vector plus all root path priority
		 * vectors whose bridge address is not equal to us.
		 */
		if (eaps_same_bridgeid(pv.pv_dbridge_id,
		    bs->bs_bridge_pv.pv_dbridge_id) == 0 &&
		    eaps_info_cmp(&bs->bs_root_pv, &pv) == INFO_BETTER) {
			/* the port vector replaces the root */
			bs->bs_root_pv = pv;
			bs->bs_root_msg_age = bp->bp_port_msg_age +
			    EAPS_MESSAGE_AGE_INCR;
			bs->bs_root_max_age = bp->bp_port_max_age;
			bs->bs_root_fdelay = bp->bp_port_fdelay;
			bs->bs_root_htime = bp->bp_port_htime;
			rbp = bp;
		}
	}

	LIST_FOREACH(bp, &bs->bs_bplist, bp_next) {
		/* calculate the port designated vector */
		bp->bp_desg_pv.pv_root_id = bs->bs_root_pv.pv_root_id;
		bp->bp_desg_pv.pv_cost = bs->bs_root_pv.pv_cost;
		bp->bp_desg_pv.pv_dbridge_id = bs->bs_bridge_pv.pv_dbridge_id;
		bp->bp_desg_pv.pv_dport_id = bp->bp_port_id;
		bp->bp_desg_pv.pv_port_id = bp->bp_port_id;

		/* calculate designated times */
		bp->bp_desg_msg_age = bs->bs_root_msg_age;
		bp->bp_desg_max_age = bs->bs_root_max_age;
		bp->bp_desg_fdelay = bs->bs_root_fdelay;
		bp->bp_desg_htime = bs->bs_bridge_htime;


		switch (bp->bp_infois) {
		case EAPS_INFO_DISABLED:
			eaps_set_port_role(bp, EAPS_ROLE_DISABLED);
			break;

		case EAPS_INFO_AGED:
			eaps_set_port_role(bp, EAPS_ROLE_DESIGNATED);
			eaps_update_info(bp);
			break;

		case EAPS_INFO_MINE:
			eaps_set_port_role(bp, EAPS_ROLE_DESIGNATED);
			/* update the port info if stale */
			if (eaps_info_cmp(&bp->bp_port_pv,
			    &bp->bp_desg_pv) != INFO_SAME ||
			    (rbp != NULL &&
			    (bp->bp_port_msg_age != rbp->bp_port_msg_age ||
			    bp->bp_port_max_age != rbp->bp_port_max_age ||
			    bp->bp_port_fdelay != rbp->bp_port_fdelay ||
			    bp->bp_port_htime != rbp->bp_port_htime)))
				eaps_update_info(bp);
			break;

		case EAPS_INFO_RECEIVED:
			if (bp == rbp) {
				/*
				 * root priority is derived from this
				 * port, make it the root port.
				 */
				eaps_set_port_role(bp, EAPS_ROLE_ROOT);
				bs->bs_root_port = bp;
			} else if (eaps_info_cmp(&bp->bp_port_pv,
				    &bp->bp_desg_pv) == INFO_BETTER) {
				/*
				 * the port priority is lower than the root
				 * port.
				 */
				eaps_set_port_role(bp, EAPS_ROLE_DESIGNATED);
				eaps_update_info(bp);
			} else {
				if (eaps_same_bridgeid(
				    bp->bp_port_pv.pv_dbridge_id,
				    bs->bs_bridge_pv.pv_dbridge_id)) {
					/*
					 * the designated bridge refers to
					 * another port on this bridge.
					 */
					eaps_set_port_role(bp,
					    EAPS_ROLE_BACKUP);
				} else {
					/*
					 * the port is an inferior path to the
					 * root bridge.
					 */
					eaps_set_port_role(bp,
					    EAPS_ROLE_ALTERNATE);
				}
			}
			break;
		}
	}
}

static void
eaps_update_state(struct eaps_state *bs, struct eaps_port *bp)
{
	struct eaps_port *bp2;
	int synced;

	EAPS_LOCK_ASSERT(bs);

	/* check if all the ports have syncronised again */
	if (!bs->bs_allsynced) {
		synced = 1;
		LIST_FOREACH(bp2, &bs->bs_bplist, bp_next) {
			if (!(bp2->bp_synced ||
			     bp2->bp_role == EAPS_ROLE_ROOT)) {
				synced = 0;
				break;
			}
		}
		bs->bs_allsynced = synced;
	}

	eaps_update_roles(bs, bp);
	eaps_update_tc(bp);
}

static void
eaps_update_roles(struct eaps_state *bs, struct eaps_port *bp)
{
	switch (bp->bp_role) {
	case EAPS_ROLE_DISABLED:
		/* Clear any flags if set */
		if (bp->bp_sync || !bp->bp_synced || bp->bp_reroot) {
			bp->bp_sync = 0;
			bp->bp_synced = 1;
			bp->bp_reroot = 0;
		}
		break;

	case EAPS_ROLE_ALTERNATE:
	case EAPS_ROLE_BACKUP:
		if ((bs->bs_allsynced && !bp->bp_agree) ||
		    (bp->bp_proposed && bp->bp_agree)) {
			bp->bp_proposed = 0;
			bp->bp_agree = 1;
			bp->bp_flags |= EAPS_PORT_NEWINFO;
			DPRINTF("%s -> ALTERNATE_AGREED\n",
			    bp->bp_ifp->if_xname);
		}

		if (bp->bp_proposed && !bp->bp_agree) {
			eaps_set_all_sync(bs);
			bp->bp_proposed = 0;
			DPRINTF("%s -> ALTERNATE_PROPOSED\n",
			    bp->bp_ifp->if_xname);
		}

		/* Clear any flags if set */
		if (bp->bp_sync || !bp->bp_synced || bp->bp_reroot) {
			bp->bp_sync = 0;
			bp->bp_synced = 1;
			bp->bp_reroot = 0;
			DPRINTF("%s -> ALTERNATE_PORT\n", bp->bp_ifp->if_xname);
		}
		break;

	case EAPS_ROLE_ROOT:
		if (bp->bp_state != EAPS_IFSTATE_FORWARDING && !bp->bp_reroot) {
			eaps_set_all_reroot(bs);
			DPRINTF("%s -> ROOT_REROOT\n", bp->bp_ifp->if_xname);
		}

		if ((bs->bs_allsynced && !bp->bp_agree) ||
		    (bp->bp_proposed && bp->bp_agree)) {
			bp->bp_proposed = 0;
			bp->bp_sync = 0;
			bp->bp_agree = 1;
			bp->bp_flags |= EAPS_PORT_NEWINFO;
			DPRINTF("%s -> ROOT_AGREED\n", bp->bp_ifp->if_xname);
		}

		if (bp->bp_proposed && !bp->bp_agree) {
			eaps_set_all_sync(bs);
			bp->bp_proposed = 0;
			DPRINTF("%s -> ROOT_PROPOSED\n", bp->bp_ifp->if_xname);
		}

		if (bp->bp_state != EAPS_IFSTATE_FORWARDING &&
		    (bp->bp_forward_delay_timer.active == 0 ||
		    (eaps_rerooted(bs, bp) &&
		    bp->bp_recent_backup_timer.active == 0 &&
		    bp->bp_protover == EAPS_PROTO_RSTP))) {
			switch (bp->bp_state) {
			case EAPS_IFSTATE_DISCARDING:
				eaps_set_port_state(bp, EAPS_IFSTATE_LEARNING);
				break;
			case EAPS_IFSTATE_LEARNING:
				eaps_set_port_state(bp,
				    EAPS_IFSTATE_FORWARDING);
				break;
			}
		}

		if (bp->bp_state == EAPS_IFSTATE_FORWARDING && bp->bp_reroot) {
			bp->bp_reroot = 0;
			DPRINTF("%s -> ROOT_REROOTED\n", bp->bp_ifp->if_xname);
		}
		break;

	case EAPS_ROLE_DESIGNATED:
		if (bp->bp_recent_root_timer.active == 0 && bp->bp_reroot) {
			bp->bp_reroot = 0;
			DPRINTF("%s -> DESIGNATED_RETIRED\n",
			    bp->bp_ifp->if_xname);
		}

		if ((bp->bp_state == EAPS_IFSTATE_DISCARDING &&
		    !bp->bp_synced) || (bp->bp_agreed && !bp->bp_synced) ||
		    (bp->bp_operedge && !bp->bp_synced) ||
		    (bp->bp_sync && bp->bp_synced)) {
			eaps_timer_stop(&bp->bp_recent_root_timer);
			bp->bp_synced = 1;
			bp->bp_sync = 0;
			DPRINTF("%s -> DESIGNATED_SYNCED\n",
			    bp->bp_ifp->if_xname);
		}

		if (bp->bp_state != EAPS_IFSTATE_FORWARDING &&
		    !bp->bp_agreed && !bp->bp_proposing &&
		    !bp->bp_operedge) {
			bp->bp_proposing = 1;
			bp->bp_flags |= EAPS_PORT_NEWINFO;
			eaps_timer_start(&bp->bp_edge_delay_timer,
			    (bp->bp_ptp_link ? EAPS_DEFAULT_MIGRATE_DELAY :
			     bp->bp_desg_max_age));
			DPRINTF("%s -> DESIGNATED_PROPOSE\n",
			    bp->bp_ifp->if_xname);
		}

		if (bp->bp_state != EAPS_IFSTATE_FORWARDING &&
		    (bp->bp_forward_delay_timer.active == 0 || bp->bp_agreed ||
		    bp->bp_operedge) &&
		    (bp->bp_recent_root_timer.active == 0 || !bp->bp_reroot) &&
		    !bp->bp_sync) {
			if (bp->bp_agreed)
				DPRINTF("%s -> AGREED\n", bp->bp_ifp->if_xname);
			/*
			 * If agreed|operedge then go straight to forwarding,
			 * otherwise follow discard -> learn -> forward.
			 */
			if (bp->bp_agreed || bp->bp_operedge ||
			    bp->bp_state == EAPS_IFSTATE_LEARNING) {
				eaps_set_port_state(bp,
				    EAPS_IFSTATE_FORWARDING);
				bp->bp_agreed = bp->bp_protover;
			} else if (bp->bp_state == EAPS_IFSTATE_DISCARDING)
				eaps_set_port_state(bp, EAPS_IFSTATE_LEARNING);
		}

		if (((bp->bp_sync && !bp->bp_synced) ||
		    (bp->bp_reroot && bp->bp_recent_root_timer.active) ||
		    (bp->bp_flags & EAPS_PORT_DISPUTED)) && !bp->bp_operedge &&
		    bp->bp_state != EAPS_IFSTATE_DISCARDING) {
			eaps_set_port_state(bp, EAPS_IFSTATE_DISCARDING);
			bp->bp_flags &= ~EAPS_PORT_DISPUTED;
			eaps_timer_start(&bp->bp_forward_delay_timer,
			    bp->bp_protover == EAPS_PROTO_RSTP ?
			    bp->bp_desg_htime : bp->bp_desg_fdelay);
			DPRINTF("%s -> DESIGNATED_DISCARD\n",
			    bp->bp_ifp->if_xname);
		}
		break;
	}

	if (bp->bp_flags & EAPS_PORT_NEWINFO)
		eaps_transmit(bs, bp);
}

static void
eaps_update_tc(struct eaps_port *bp)
{
	switch (bp->bp_tcstate) {
		case EAPS_TCSTATE_ACTIVE:
			if ((bp->bp_role != EAPS_ROLE_DESIGNATED &&
			    bp->bp_role != EAPS_ROLE_ROOT) || bp->bp_operedge)
				eaps_set_port_tc(bp, EAPS_TCSTATE_LEARNING);

			if (bp->bp_rcvdtcn)
				eaps_set_port_tc(bp, EAPS_TCSTATE_TCN);
			if (bp->bp_rcvdtc)
				eaps_set_port_tc(bp, EAPS_TCSTATE_TC);

			if (bp->bp_tc_prop && !bp->bp_operedge)
				eaps_set_port_tc(bp, EAPS_TCSTATE_PROPAG);

			if (bp->bp_rcvdtca)
				eaps_set_port_tc(bp, EAPS_TCSTATE_ACK);
			break;

		case EAPS_TCSTATE_INACTIVE:
			if ((bp->bp_state == EAPS_IFSTATE_LEARNING ||
			    bp->bp_state == EAPS_IFSTATE_FORWARDING) &&
			    bp->bp_fdbflush == 0)
				eaps_set_port_tc(bp, EAPS_TCSTATE_LEARNING);
			break;

		case EAPS_TCSTATE_LEARNING:
			if (bp->bp_rcvdtc || bp->bp_rcvdtcn || bp->bp_rcvdtca ||
			    bp->bp_tc_prop)
				eaps_set_port_tc(bp, EAPS_TCSTATE_LEARNING);
			else if (bp->bp_role != EAPS_ROLE_DESIGNATED &&
				 bp->bp_role != EAPS_ROLE_ROOT &&
				 bp->bp_state == EAPS_IFSTATE_DISCARDING)
				eaps_set_port_tc(bp, EAPS_TCSTATE_INACTIVE);

			if ((bp->bp_role == EAPS_ROLE_DESIGNATED ||
			    bp->bp_role == EAPS_ROLE_ROOT) &&
			    bp->bp_state == EAPS_IFSTATE_FORWARDING &&
			    !bp->bp_operedge)
				eaps_set_port_tc(bp, EAPS_TCSTATE_DETECTED);
			break;

		/* these are transient states and go straight back to ACTIVE */
		case EAPS_TCSTATE_DETECTED:
		case EAPS_TCSTATE_TCN:
		case EAPS_TCSTATE_TC:
		case EAPS_TCSTATE_PROPAG:
		case EAPS_TCSTATE_ACK:
			DPRINTF("Invalid TC state for %s\n",
			    bp->bp_ifp->if_xname);
			break;
	}

}

static void
eaps_update_info(struct eaps_port *bp)
{
	struct eaps_state *bs = bp->bp_bs;

	bp->bp_proposing = 0;
	bp->bp_proposed = 0;

	if (bp->bp_agreed && !eaps_pdu_bettersame(bp, EAPS_INFO_MINE))
		bp->bp_agreed = 0;

	if (bp->bp_synced && !bp->bp_agreed) {
		bp->bp_synced = 0;
		bs->bs_allsynced = 0;
	}

	/* copy the designated pv to the port */
	bp->bp_port_pv = bp->bp_desg_pv;
	bp->bp_port_msg_age = bp->bp_desg_msg_age;
	bp->bp_port_max_age = bp->bp_desg_max_age;
	bp->bp_port_fdelay = bp->bp_desg_fdelay;
	bp->bp_port_htime = bp->bp_desg_htime;
	bp->bp_infois = EAPS_INFO_MINE;

	/* Set transmit flag but do not immediately send */
	bp->bp_flags |= EAPS_PORT_NEWINFO;
}

/* set tcprop on every port other than the caller */
static void
eaps_set_other_tcprop(struct eaps_port *bp)
{
	struct eaps_state *bs = bp->bp_bs;
	struct eaps_port *bp2;

	EAPS_LOCK_ASSERT(bs);

	LIST_FOREACH(bp2, &bs->bs_bplist, bp_next) {
		if (bp2 == bp)
			continue;
		bp2->bp_tc_prop = 1;
	}
}

static void
eaps_set_all_reroot(struct eaps_state *bs)
{
	struct eaps_port *bp;

	EAPS_LOCK_ASSERT(bs);

	LIST_FOREACH(bp, &bs->bs_bplist, bp_next)
		bp->bp_reroot = 1;
}

static void
eaps_set_all_sync(struct eaps_state *bs)
{
	struct eaps_port *bp;

	EAPS_LOCK_ASSERT(bs);

	LIST_FOREACH(bp, &bs->bs_bplist, bp_next) {
		bp->bp_sync = 1;
		bp->bp_synced = 0;	/* Not explicit in spec */
	}

	bs->bs_allsynced = 0;
}

static void
eaps_set_port_state(struct eaps_port *bp, int state)
{
	if (bp->bp_state == state)
		return;

	bp->bp_state = state;

	switch (bp->bp_state) {
		case EAPS_IFSTATE_DISCARDING:
			DPRINTF("state changed to DISCARDING on %s\n",
			    bp->bp_ifp->if_xname);
			break;

		case EAPS_IFSTATE_LEARNING:
			DPRINTF("state changed to LEARNING on %s\n",
			    bp->bp_ifp->if_xname);

			eaps_timer_start(&bp->bp_forward_delay_timer,
			    bp->bp_protover == EAPS_PROTO_RSTP ?
			    bp->bp_desg_htime : bp->bp_desg_fdelay);
			break;

		case EAPS_IFSTATE_FORWARDING:
			DPRINTF("state changed to FORWARDING on %s\n",
			    bp->bp_ifp->if_xname);

			eaps_timer_stop(&bp->bp_forward_delay_timer);
			/* Record that we enabled forwarding */
			bp->bp_forward_transitions++;
			break;
	}

	/* notify the parent bridge */
	taskqueue_enqueue(taskqueue_swi, &bp->bp_statetask);
}

static void
eaps_set_port_role(struct eaps_port *bp, int role)
{
	struct eaps_state *bs = bp->bp_bs;

	if (bp->bp_role == role)
		return;

	/* perform pre-change tasks */
	switch (bp->bp_role) {
		case EAPS_ROLE_DISABLED:
			eaps_timer_start(&bp->bp_forward_delay_timer,
			    bp->bp_desg_max_age);
			break;

		case EAPS_ROLE_BACKUP:
			eaps_timer_start(&bp->bp_recent_backup_timer,
			    bp->bp_desg_htime * 2);
			/* fall through */
		case EAPS_ROLE_ALTERNATE:
			eaps_timer_start(&bp->bp_forward_delay_timer,
			    bp->bp_desg_fdelay);
			bp->bp_sync = 0;
			bp->bp_synced = 1;
			bp->bp_reroot = 0;
			break;

		case EAPS_ROLE_ROOT:
			eaps_timer_start(&bp->bp_recent_root_timer,
			    EAPS_DEFAULT_FORWARD_DELAY);
			break;
	}

	bp->bp_role = role;
	/* clear values not carried between roles */
	bp->bp_proposing = 0;
	bs->bs_allsynced = 0;

	/* initialise the new role */
	switch (bp->bp_role) {
		case EAPS_ROLE_DISABLED:
		case EAPS_ROLE_ALTERNATE:
		case EAPS_ROLE_BACKUP:
			DPRINTF("%s role -> ALT/BACK/DISABLED\n",
			    bp->bp_ifp->if_xname);
			eaps_set_port_state(bp, EAPS_IFSTATE_DISCARDING);
			eaps_timer_stop(&bp->bp_recent_root_timer);
			eaps_timer_latch(&bp->bp_forward_delay_timer);
			bp->bp_sync = 0;
			bp->bp_synced = 1;
			bp->bp_reroot = 0;
			break;

		case EAPS_ROLE_ROOT:
			DPRINTF("%s role -> ROOT\n",
			    bp->bp_ifp->if_xname);
			eaps_set_port_state(bp, EAPS_IFSTATE_DISCARDING);
			eaps_timer_latch(&bp->bp_recent_root_timer);
			bp->bp_proposing = 0;
			break;

		case EAPS_ROLE_DESIGNATED:
			DPRINTF("%s role -> DESIGNATED\n",
			    bp->bp_ifp->if_xname);
			eaps_timer_start(&bp->bp_hello_timer,
			    bp->bp_desg_htime);
			bp->bp_agree = 0;
			break;
	}

	/* let the TC state know that the role changed */
	eaps_update_tc(bp);
}

static void
eaps_set_port_proto(struct eaps_port *bp, int proto)
{
	struct eaps_state *bs = bp->bp_bs;

	/* supported protocol versions */
	switch (proto) {
		case EAPS_PROTO_STP:
			/* we can downgrade protocols only */
			eaps_timer_stop(&bp->bp_migrate_delay_timer);
			/* clear unsupported features */
			bp->bp_operedge = 0;
			/* STP compat mode only uses 16 bits of the 32 */
			if (bp->bp_path_cost > 65535)
				bp->bp_path_cost = 65535;
			break;

		case EAPS_PROTO_RSTP:
			eaps_timer_start(&bp->bp_migrate_delay_timer,
			    bs->bs_migration_delay);
			break;

		default:
			DPRINTF("Unsupported STP version %d\n", proto);
			return;
	}

	bp->bp_protover = proto;
	bp->bp_flags &= ~EAPS_PORT_CANMIGRATE;
}

static void
eaps_set_port_tc(struct eaps_port *bp, int state)
{
	struct eaps_state *bs = bp->bp_bs;

	bp->bp_tcstate = state;

	/* initialise the new state */
	switch (bp->bp_tcstate) {
		case EAPS_TCSTATE_ACTIVE:
			DPRINTF("%s -> TC_ACTIVE\n", bp->bp_ifp->if_xname);
			/* nothing to do */
			break;

		case EAPS_TCSTATE_INACTIVE:
			eaps_timer_stop(&bp->bp_tc_timer);
			/* flush routes on the parent bridge */
			bp->bp_fdbflush = 1;
			taskqueue_enqueue(taskqueue_swi, &bp->bp_rtagetask);
			bp->bp_tc_ack = 0;
			DPRINTF("%s -> TC_INACTIVE\n", bp->bp_ifp->if_xname);
			break;

		case EAPS_TCSTATE_LEARNING:
			bp->bp_rcvdtc = 0;
			bp->bp_rcvdtcn = 0;
			bp->bp_rcvdtca = 0;
			bp->bp_tc_prop = 0;
			DPRINTF("%s -> TC_LEARNING\n", bp->bp_ifp->if_xname);
			break;

		case EAPS_TCSTATE_DETECTED:
			eaps_set_timer_tc(bp);
			eaps_set_other_tcprop(bp);
			/* send out notification */
			bp->bp_flags |= EAPS_PORT_NEWINFO;
			eaps_transmit(bs, bp);
			getmicrotime(&bs->bs_last_tc_time);
			DPRINTF("%s -> TC_DETECTED\n", bp->bp_ifp->if_xname);
			bp->bp_tcstate = EAPS_TCSTATE_ACTIVE; /* UCT */
			break;

		case EAPS_TCSTATE_TCN:
			eaps_set_timer_tc(bp);
			DPRINTF("%s -> TC_TCN\n", bp->bp_ifp->if_xname);
			/* fall through */
		case EAPS_TCSTATE_TC:
			bp->bp_rcvdtc = 0;
			bp->bp_rcvdtcn = 0;
			if (bp->bp_role == EAPS_ROLE_DESIGNATED)
				bp->bp_tc_ack = 1;

			eaps_set_other_tcprop(bp);
			DPRINTF("%s -> TC_TC\n", bp->bp_ifp->if_xname);
			bp->bp_tcstate = EAPS_TCSTATE_ACTIVE; /* UCT */
			break;

		case EAPS_TCSTATE_PROPAG:
			/* flush routes on the parent bridge */
			bp->bp_fdbflush = 1;
			taskqueue_enqueue(taskqueue_swi, &bp->bp_rtagetask);
			bp->bp_tc_prop = 0;
			eaps_set_timer_tc(bp);
			DPRINTF("%s -> TC_PROPAG\n", bp->bp_ifp->if_xname);
			bp->bp_tcstate = EAPS_TCSTATE_ACTIVE; /* UCT */
			break;

		case EAPS_TCSTATE_ACK:
			eaps_timer_stop(&bp->bp_tc_timer);
			bp->bp_rcvdtca = 0;
			DPRINTF("%s -> TC_ACK\n", bp->bp_ifp->if_xname);
			bp->bp_tcstate = EAPS_TCSTATE_ACTIVE; /* UCT */
			break;
	}
}

static void
eaps_set_timer_tc(struct eaps_port *bp)
{
	struct eaps_state *bs = bp->bp_bs;

	if (bp->bp_tc_timer.active)
		return;

	switch (bp->bp_protover) {
		case EAPS_PROTO_RSTP:
			eaps_timer_start(&bp->bp_tc_timer,
			    bp->bp_desg_htime + EAPS_TICK_VAL);
			bp->bp_flags |= EAPS_PORT_NEWINFO;
			break;

		case EAPS_PROTO_STP:
			eaps_timer_start(&bp->bp_tc_timer,
			    bs->bs_root_max_age + bs->bs_root_fdelay);
			break;
	}
}

static void
eaps_set_timer_msgage(struct eaps_port *bp)
{
	if (bp->bp_port_msg_age + EAPS_MESSAGE_AGE_INCR <=
	    bp->bp_port_max_age) {
		eaps_timer_start(&bp->bp_message_age_timer,
		    bp->bp_port_htime * 3);
	} else
		/* expires immediately */
		eaps_timer_start(&bp->bp_message_age_timer, 0);
}

static int
eaps_rerooted(struct eaps_state *bs, struct eaps_port *bp)
{
	struct eaps_port *bp2;
	int rr_set = 0;

	LIST_FOREACH(bp2, &bs->bs_bplist, bp_next) {
		if (bp2 == bp)
			continue;
		if (bp2->bp_recent_root_timer.active) {
			rr_set = 1;
			break;
		}
	}
	return (!rr_set);
}

int
eaps_set_htime(struct eaps_state *bs, int t)
{
	/* convert seconds to ticks */
	t *=  EAPS_TICK_VAL;

	/* value can only be changed in leagacy stp mode */
	if (bs->bs_protover != EAPS_PROTO_STP)
		return (EPERM);

	if (t < EAPS_MIN_HELLO_TIME || t > EAPS_MAX_HELLO_TIME)
		return (EINVAL);

	EAPS_LOCK(bs);
	bs->bs_bridge_htime = t;
	eaps_reinit(bs);
	EAPS_UNLOCK(bs);
	return (0);
}

int
eaps_set_fdelay(struct eaps_state *bs, int t)
{
	/* convert seconds to ticks */
	t *= EAPS_TICK_VAL;

	if (t < EAPS_MIN_FORWARD_DELAY || t > EAPS_MAX_FORWARD_DELAY)
		return (EINVAL);

	EAPS_LOCK(bs);
	bs->bs_bridge_fdelay = t;
	eaps_reinit(bs);
	EAPS_UNLOCK(bs);
	return (0);
}

int
eaps_set_maxage(struct eaps_state *bs, int t)
{
	/* convert seconds to ticks */
	t *= EAPS_TICK_VAL;

	if (t < EAPS_MIN_MAX_AGE || t > EAPS_MAX_MAX_AGE)
		return (EINVAL);

	EAPS_LOCK(bs);
	bs->bs_bridge_max_age = t;
	eaps_reinit(bs);
	EAPS_UNLOCK(bs);
	return (0);
}

int
eaps_set_holdcount(struct eaps_state *bs, int count)
{
	struct eaps_port *bp;

	if (count < EAPS_MIN_HOLD_COUNT ||
	    count > EAPS_MAX_HOLD_COUNT)
		return (EINVAL);

	EAPS_LOCK(bs);
	bs->bs_txholdcount = count;
	LIST_FOREACH(bp, &bs->bs_bplist, bp_next)
		bp->bp_txcount = 0;
	EAPS_UNLOCK(bs);
	return (0);
}

int
eaps_set_protocol(struct eaps_state *bs, int proto)
{
	struct eaps_port *bp;

	switch (proto) {
		/* Supported protocol versions */
		case EAPS_PROTO_STP:
		case EAPS_PROTO_RSTP:
			break;

		default:
			return (EINVAL);
	}

	EAPS_LOCK(bs);
	bs->bs_protover = proto;
	bs->bs_bridge_htime = EAPS_DEFAULT_HELLO_TIME;
	LIST_FOREACH(bp, &bs->bs_bplist, bp_next) {
		/* reinit state */
		bp->bp_infois = EAPS_INFO_DISABLED;
		bp->bp_txcount = 0;
		eaps_set_port_proto(bp, bs->bs_protover);
		eaps_set_port_role(bp, EAPS_ROLE_DISABLED);
		eaps_set_port_tc(bp, EAPS_TCSTATE_INACTIVE);
		eaps_timer_stop(&bp->bp_recent_backup_timer);
	}
	eaps_reinit(bs);
	EAPS_UNLOCK(bs);
	return (0);
}

int
eaps_set_priority(struct eaps_state *bs, int pri)
{
	if (pri < 0 || pri > EAPS_MAX_PRIORITY)
		return (EINVAL);

	/* Limit to steps of 4096 */
	pri -= pri % 4096;

	EAPS_LOCK(bs);
	bs->bs_bridge_priority = pri;
	eaps_reinit(bs);
	EAPS_UNLOCK(bs);
	return (0);
}

int
eaps_set_port_priority(struct eaps_port *bp, int pri)
{
	struct eaps_state *bs = bp->bp_bs;

	if (pri < 0 || pri > EAPS_MAX_PORT_PRIORITY)
		return (EINVAL);

	/* Limit to steps of 16 */
	pri -= pri % 16;

	EAPS_LOCK(bs);
	bp->bp_priority = pri;
	eaps_reinit(bs);
	EAPS_UNLOCK(bs);
	return (0);
}

int
eaps_set_path_cost(struct eaps_port *bp, uint32_t path_cost)
{
	struct eaps_state *bs = bp->bp_bs;

	if (path_cost > EAPS_MAX_PATH_COST)
		return (EINVAL);

	/* STP compat mode only uses 16 bits of the 32 */
	if (bp->bp_protover == EAPS_PROTO_STP && path_cost > 65535)
		path_cost = 65535;

	EAPS_LOCK(bs);

	if (path_cost == 0) {	/* use auto */
		bp->bp_flags &= ~EAPS_PORT_ADMCOST;
		bp->bp_path_cost = eaps_calc_path_cost(bp);
	} else {
		bp->bp_path_cost = path_cost;
		bp->bp_flags |= EAPS_PORT_ADMCOST;
	}
	eaps_reinit(bs);
	EAPS_UNLOCK(bs);
	return (0);
}

int
eaps_set_edge(struct eaps_port *bp, int set)
{
	struct eaps_state *bs = bp->bp_bs;

	EAPS_LOCK(bs);
	if ((bp->bp_operedge = set) == 0)
		bp->bp_flags &= ~EAPS_PORT_ADMEDGE;
	else
		bp->bp_flags |= EAPS_PORT_ADMEDGE;
	EAPS_UNLOCK(bs);
	return (0);
}

int
eaps_set_autoedge(struct eaps_port *bp, int set)
{
	struct eaps_state *bs = bp->bp_bs;

	EAPS_LOCK(bs);
	if (set) {
		bp->bp_flags |= EAPS_PORT_AUTOEDGE;
		/* we may be able to transition straight to edge */
		if (bp->bp_edge_delay_timer.active == 0)
			eaps_edge_delay_expiry(bs, bp);
	} else
		bp->bp_flags &= ~EAPS_PORT_AUTOEDGE;
	EAPS_UNLOCK(bs);
	return (0);
}

int
eaps_set_ptp(struct eaps_port *bp, int set)
{
	struct eaps_state *bs = bp->bp_bs;

	EAPS_LOCK(bs);
	bp->bp_ptp_link = set;
	EAPS_UNLOCK(bs);
	return (0);
}

int
eaps_set_autoptp(struct eaps_port *bp, int set)
{
	struct eaps_state *bs = bp->bp_bs;

	EAPS_LOCK(bs);
	if (set) {
		bp->bp_flags |= EAPS_PORT_AUTOPTP;
		if (bp->bp_role != EAPS_ROLE_DISABLED)
			taskqueue_enqueue(taskqueue_swi, &bp->bp_mediatask);
	} else
		bp->bp_flags &= ~EAPS_PORT_AUTOPTP;
	EAPS_UNLOCK(bs);
	return (0);
}

/*
 * Calculate the path cost according to the link speed.
 */
static uint32_t
eaps_calc_path_cost(struct eaps_port *bp)
{
	struct ifnet *ifp = bp->bp_ifp;
	uint32_t path_cost;

	/* If the priority has been manually set then retain the value */
	if (bp->bp_flags & EAPS_PORT_ADMCOST)
		return bp->bp_path_cost;

	if (ifp->if_link_state == LINK_STATE_DOWN) {
		/* Recalc when the link comes up again */
		bp->bp_flags |= EAPS_PORT_PNDCOST;
		return (EAPS_DEFAULT_PATH_COST);
	}

	if (ifp->if_baudrate < 1000)
		return (EAPS_DEFAULT_PATH_COST);

 	/* formula from section 17.14, IEEE Std 802.1D-2004 */
	path_cost = 20000000000ULL / (ifp->if_baudrate / 1000);

	if (path_cost > EAPS_MAX_PATH_COST)
		path_cost = EAPS_MAX_PATH_COST;

	/* STP compat mode only uses 16 bits of the 32 */
	if (bp->bp_protover == EAPS_PROTO_STP && path_cost > 65535)
		path_cost = 65535;

	return (path_cost);
}

/*
 * Notify the bridge that a port state has changed, we need to do this from a
 * taskqueue to avoid a LOR.
 */
static void
eaps_notify_state(void *arg, int pending)
{
	struct eaps_port *bp = (struct eaps_port *)arg;
	struct eaps_state *bs = bp->bp_bs;

	if (bp->bp_active == 1 && bs->bs_state_cb != NULL)
		(*bs->bs_state_cb)(bp->bp_ifp, bp->bp_state);
}

/*
 * Flush the routes on the bridge port, we need to do this from a
 * taskqueue to avoid a LOR.
 */
static void
eaps_notify_rtage(void *arg, int pending)
{
	struct eaps_port *bp = (struct eaps_port *)arg;
	struct eaps_state *bs = bp->bp_bs;
	int age = 0;

	EAPS_LOCK(bs);
	switch (bp->bp_protover) {
		case EAPS_PROTO_STP:
			/* convert to seconds */
			age = bp->bp_desg_fdelay / EAPS_TICK_VAL;
			break;

		case EAPS_PROTO_RSTP:
			age = 0;
			break;
	}
	EAPS_UNLOCK(bs);

	if (bp->bp_active == 1 && bs->bs_rtage_cb != NULL)
		(*bs->bs_rtage_cb)(bp->bp_ifp, age);

	/* flush is complete */
	EAPS_LOCK(bs);
	bp->bp_fdbflush = 0;
	EAPS_UNLOCK(bs);
}

void
eaps_linkstate(struct eaps_port *bp)
{
	struct eaps_state *bs = bp->bp_bs;

	if (!bp->bp_active)
		return;

	eaps_ifupdstatus(bp, 0);
	EAPS_LOCK(bs);
	eaps_update_state(bs, bp);
	EAPS_UNLOCK(bs);
}

static void
eaps_ifupdstatus(void *arg, int pending)
{
	struct eaps_port *bp = (struct eaps_port *)arg;
	struct eaps_state *bs = bp->bp_bs;
	struct ifnet *ifp = bp->bp_ifp;
	struct ifmediareq ifmr;
	int error, changed;

	if (!bp->bp_active)
		return;

	bzero((char *)&ifmr, sizeof(ifmr));
	error = (*ifp->if_ioctl)(ifp, SIOCGIFMEDIA, (caddr_t)&ifmr);

	EAPS_LOCK(bs);
	changed = 0;
	if ((error == 0) && (ifp->if_flags & IFF_UP)) {
		if (ifmr.ifm_status & IFM_ACTIVE) {
			/* A full-duplex link is assumed to be point to point */
			if (bp->bp_flags & EAPS_PORT_AUTOPTP) {
				int fdx;

				fdx = ifmr.ifm_active & IFM_FDX ? 1 : 0;
				if (bp->bp_ptp_link ^ fdx) {
					bp->bp_ptp_link = fdx;
					changed = 1;
				}
			}

			/* Calc the cost if the link was down previously */
			if (bp->bp_flags & EAPS_PORT_PNDCOST) {
				uint32_t cost;

				cost = eaps_calc_path_cost(bp);
				if (bp->bp_path_cost != cost) {
					bp->bp_path_cost = cost;
					changed = 1;
				}
				bp->bp_flags &= ~EAPS_PORT_PNDCOST;
			}

			if (bp->bp_role == EAPS_ROLE_DISABLED) {
				eaps_enable_port(bs, bp);
				changed = 1;
			}
		} else {
			if (bp->bp_role != EAPS_ROLE_DISABLED) {
				eaps_disable_port(bs, bp);
				changed = 1;
				if ((bp->bp_flags & EAPS_PORT_ADMEDGE) &&
				    bp->bp_protover == EAPS_PROTO_RSTP)
					bp->bp_operedge = 1;
			}
		}
	} else if (bp->bp_infois != EAPS_INFO_DISABLED) {
		eaps_disable_port(bs, bp);
		changed = 1;
	}
	if (changed)
		eaps_assign_roles(bs);
	EAPS_UNLOCK(bs);
}

static void
eaps_enable_port(struct eaps_state *bs, struct eaps_port *bp)
{
	bp->bp_infois = EAPS_INFO_AGED;
}

static void
eaps_disable_port(struct eaps_state *bs, struct eaps_port *bp)
{
	bp->bp_infois = EAPS_INFO_DISABLED;
}

static void
eaps_tick(void *arg)
{
	struct eaps_state *bs = arg;
	struct eaps_port *bp;

	EAPS_LOCK_ASSERT(bs);

	if (bs->bs_running == 0)
		return;

	CURVNET_SET(bs->bs_vnet);

	/* poll link events on interfaces that do not support linkstate */
	if (eaps_timer_dectest(&bs->bs_link_timer)) {
		LIST_FOREACH(bp, &bs->bs_bplist, bp_next) {
			if (!(bp->bp_ifp->if_capabilities & IFCAP_LINKSTATE))
				taskqueue_enqueue(taskqueue_swi, &bp->bp_mediatask);
		}
		eaps_timer_start(&bs->bs_link_timer, EAPS_LINK_TIMER);
	}

	LIST_FOREACH(bp, &bs->bs_bplist, bp_next) {
		/* no events need to happen for these */
		eaps_timer_dectest(&bp->bp_tc_timer);
		eaps_timer_dectest(&bp->bp_recent_root_timer);
		eaps_timer_dectest(&bp->bp_forward_delay_timer);
		eaps_timer_dectest(&bp->bp_recent_backup_timer);

		if (eaps_timer_dectest(&bp->bp_hello_timer))
			eaps_hello_timer_expiry(bs, bp);

		if (eaps_timer_dectest(&bp->bp_message_age_timer))
			eaps_message_age_expiry(bs, bp);

		if (eaps_timer_dectest(&bp->bp_migrate_delay_timer))
			eaps_migrate_delay_expiry(bs, bp);

		if (eaps_timer_dectest(&bp->bp_edge_delay_timer))
			eaps_edge_delay_expiry(bs, bp);

		/* update the various state machines for the port */
		eaps_update_state(bs, bp);

		if (bp->bp_txcount > 0)
			bp->bp_txcount--;
	}

	CURVNET_RESTORE();

	callout_reset(&bs->bs_bstpcallout, hz, eaps_tick, bs);
}

static void
eaps_timer_start(struct eaps_timer *t, uint16_t v)
{
	t->value = v;
	t->active = 1;
	t->latched = 0;
}

static void
eaps_timer_stop(struct eaps_timer *t)
{
	t->value = 0;
	t->active = 0;
	t->latched = 0;
}

static void
eaps_timer_latch(struct eaps_timer *t)
{
	t->latched = 1;
	t->active = 1;
}

static int
eaps_timer_dectest(struct eaps_timer *t)
{
	if (t->active == 0 || t->latched)
		return (0);
	t->value -= EAPS_TICK_VAL;
	if (t->value <= 0) {
		eaps_timer_stop(t);
		return (1);
	}
	return (0);
}

static void
eaps_hello_timer_expiry(struct eaps_state *bs, struct eaps_port *bp)
{
	if ((bp->bp_flags & EAPS_PORT_NEWINFO) ||
	    bp->bp_role == EAPS_ROLE_DESIGNATED ||
	    (bp->bp_role == EAPS_ROLE_ROOT &&
	     bp->bp_tc_timer.active == 1)) {
		eaps_timer_start(&bp->bp_hello_timer, bp->bp_desg_htime);
		bp->bp_flags |= EAPS_PORT_NEWINFO;
		eaps_transmit(bs, bp);
	}
}

static void
eaps_message_age_expiry(struct eaps_state *bs, struct eaps_port *bp)
{
	if (bp->bp_infois == EAPS_INFO_RECEIVED) {
		bp->bp_infois = EAPS_INFO_AGED;
		eaps_assign_roles(bs);
		DPRINTF("aged info on %s\n", bp->bp_ifp->if_xname);
	}
}

static void
eaps_migrate_delay_expiry(struct eaps_state *bs, struct eaps_port *bp)
{
	bp->bp_flags |= EAPS_PORT_CANMIGRATE;
}

static void
eaps_edge_delay_expiry(struct eaps_state *bs, struct eaps_port *bp)
{
	if ((bp->bp_flags & EAPS_PORT_AUTOEDGE) &&
	    bp->bp_protover == EAPS_PROTO_RSTP && bp->bp_proposing &&
	    bp->bp_role == EAPS_ROLE_DESIGNATED) {
		bp->bp_operedge = 1;
		DPRINTF("%s -> edge port\n", bp->bp_ifp->if_xname);
	}
}

static int
eaps_addr_cmp(const uint8_t *a, const uint8_t *b)
{
	int i, d;

	for (i = 0, d = 0; i < ETHER_ADDR_LEN && d == 0; i++) {
		d = ((int)a[i]) - ((int)b[i]);
	}

	return (d);
}

#if 0
/*
 * compare the bridge address component of the bridgeid
 */
static int
eaps_same_bridgeid(uint64_t id1, uint64_t id2)
{
	u_char addr1[ETHER_ADDR_LEN];
	u_char addr2[ETHER_ADDR_LEN];

	PV2ADDR(id1, addr1);
	PV2ADDR(id2, addr2);

	if (eaps_addr_cmp(addr1, addr2) == 0)
		return (1);

	return (0);
}
#endif

#if 0
void
eaps_reinit(struct eaps_state *bs)
{
	struct eaps_port *bp;
	struct ifnet *ifp, *mif;
	u_char *e_addr;
	void *bridgeptr;
	static const u_char llzero[ETHER_ADDR_LEN];	/* 00:00:00:00:00:00 */

	EAPS_LOCK_ASSERT(bs);

	if (LIST_EMPTY(&bs->bs_bplist))
		goto disablestp;

	mif = NULL;
	bridgeptr = LIST_FIRST(&bs->bs_bplist)->bp_ifp->if_bridge;
	KASSERT(bridgeptr != NULL, ("Invalid bridge pointer"));
	/*
	 * Search through the Ethernet adapters and find the one with the
	 * lowest value. Make sure the adapter which we take the MAC address
	 * from is part of this bridge, so we can have more than one independent
	 * bridges in the same STP domain.
	 */
	IFNET_RLOCK_NOSLEEP();
	TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
		if (ifp->if_type != IFT_ETHER)
			continue;	/* Not Ethernet */

		if (ifp->if_bridge != bridgeptr)
			continue;	/* Not part of our bridge */

		if (eaps_addr_cmp(IF_LLADDR(ifp), llzero) == 0)
			continue;	/* No mac address set */

		if (mif == NULL) {
			mif = ifp;
			continue;
		}
		if (eaps_addr_cmp(IF_LLADDR(ifp), IF_LLADDR(mif)) < 0) {
			mif = ifp;
			continue;
		}
	}
	IFNET_RUNLOCK_NOSLEEP();
	if (mif == NULL)
		goto disablestp;

	e_addr = IF_LLADDR(mif);
	bs->bs_bridge_pv.pv_dbridge_id =
	    (((uint64_t)bs->bs_bridge_priority) << 48) |
	    (((uint64_t)e_addr[0]) << 40) |
	    (((uint64_t)e_addr[1]) << 32) |
	    (((uint64_t)e_addr[2]) << 24) |
	    (((uint64_t)e_addr[3]) << 16) |
	    (((uint64_t)e_addr[4]) << 8) |
	    (((uint64_t)e_addr[5]));

	bs->bs_bridge_pv.pv_root_id = bs->bs_bridge_pv.pv_dbridge_id;
	bs->bs_bridge_pv.pv_cost = 0;
	bs->bs_bridge_pv.pv_dport_id = 0;
	bs->bs_bridge_pv.pv_port_id = 0;

	if (bs->bs_running && callout_pending(&bs->bs_bstpcallout) == 0)
		callout_reset(&bs->bs_bstpcallout, hz, eaps_tick, bs);

	LIST_FOREACH(bp, &bs->bs_bplist, bp_next) {
		bp->bp_port_id = (bp->bp_priority << 8) |
		    (bp->bp_ifp->if_index  & 0xfff);
		taskqueue_enqueue(taskqueue_swi, &bp->bp_mediatask);
	}

	eaps_assign_roles(bs);
	eaps_timer_start(&bs->bs_link_timer, EAPS_LINK_TIMER);
	return;

disablestp:
	/* Set the bridge and root id (lower bits) to zero */
	bs->bs_bridge_pv.pv_dbridge_id =
	    ((uint64_t)bs->bs_bridge_priority) << 48;
	bs->bs_bridge_pv.pv_root_id = bs->bs_bridge_pv.pv_dbridge_id;
	bs->bs_root_pv = bs->bs_bridge_pv;
	/* Disable any remaining ports, they will have no MAC address */
	LIST_FOREACH(bp, &bs->bs_bplist, bp_next) {
		bp->bp_infois = EAPS_INFO_DISABLED;
		eaps_set_port_role(bp, EAPS_ROLE_DISABLED);
	}
	callout_stop(&bs->bs_bstpcallout);
}
#endif

static int
eaps_modevent(module_t mod, int type, void *data)
{
	switch (type) {
	case MOD_LOAD:
		mtx_init(&eaps_list_mtx, "eaps list", NULL, MTX_DEF);
		LIST_INIT(&eaps_list);
		break;
	case MOD_UNLOAD:
		mtx_destroy(&eaps_list_mtx);
		break;
	default:
		return (EOPNOTSUPP);
	}
	return (0);
}

static moduledata_t eaps_mod = {
	"br_eaps",
	eaps_modevent,
	0
};

DECLARE_MODULE(br_eaps, eaps_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(br_eaps, 1);

void
eaps_attach(struct eaps_state *bs, struct eaps_cb_ops *cb)
{

	EAPS_LOCK_INIT(bs);
	callout_init_mtx(&bs->bs_bstpcallout, &bs->bs_mtx, 0);
	LIST_INIT(&bs->bs_bplist);

	bs->bs_bridge_max_age = EAPS_DEFAULT_MAX_AGE;
	bs->bs_bridge_htime = EAPS_DEFAULT_HELLO_TIME;
	bs->bs_bridge_fdelay = EAPS_DEFAULT_FORWARD_DELAY;
	bs->bs_bridge_priority = EAPS_DEFAULT_BRIDGE_PRIORITY;
	bs->bs_hold_time = EAPS_DEFAULT_HOLD_TIME;
	bs->bs_migration_delay = EAPS_DEFAULT_MIGRATE_DELAY;
	bs->bs_txholdcount = EAPS_DEFAULT_HOLD_COUNT;
	bs->bs_protover = EAPS_PROTO_RSTP;
	bs->bs_state_cb = cb->bcb_state;
	bs->bs_rtage_cb = cb->bcb_rtage;
	bs->bs_vnet = curvnet;

	getmicrotime(&bs->bs_last_tc_time);

	mtx_lock(&eaps_list_mtx);
	LIST_INSERT_HEAD(&eaps_list, bs, bs_list);
	mtx_unlock(&eaps_list_mtx);
}

void
eaps_detach(struct eaps_state *bs)
{
	KASSERT(LIST_EMPTY(&bs->bs_bplist), ("bstp still active"));

	mtx_lock(&eaps_list_mtx);
	LIST_REMOVE(bs, bs_list);
	mtx_unlock(&eaps_list_mtx);
	callout_drain(&bs->bs_bstpcallout);
	EAPS_LOCK_DESTROY(bs);
}

void
eaps_init(struct eaps_state *bs)
{
	EAPS_LOCK(bs);
	callout_reset(&bs->bs_bstpcallout, hz, eaps_tick, bs);
	bs->bs_running = 1;
	eaps_reinit(bs);
	EAPS_UNLOCK(bs);
}

void
eaps_stop(struct eaps_state *bs)
{
	struct eaps_port *bp;

	EAPS_LOCK(bs);

	LIST_FOREACH(bp, &bs->bs_bplist, bp_next)
		eaps_set_port_state(bp, EAPS_IFSTATE_DISCARDING);

	bs->bs_running = 0;
	callout_stop(&bs->bs_bstpcallout);
	EAPS_UNLOCK(bs);
}

int
eaps_create(struct eaps_state *bs, struct eaps_port *bp, struct ifnet *ifp)
{
	bzero(bp, sizeof(struct eaps_port));

	EAPS_LOCK(bs);
	bp->bp_ifp = ifp;
	bp->bp_bs = bs;
	bp->bp_priority = EAPS_DEFAULT_PORT_PRIORITY;
	TASK_INIT(&bp->bp_statetask, 0, eaps_notify_state, bp);
	TASK_INIT(&bp->bp_rtagetask, 0, eaps_notify_rtage, bp);
	TASK_INIT(&bp->bp_mediatask, 0, eaps_ifupdstatus, bp);

	/* Init state */
	bp->bp_infois = EAPS_INFO_DISABLED;
	bp->bp_flags = EAPS_PORT_AUTOEDGE|EAPS_PORT_AUTOPTP;
	eaps_set_port_state(bp, EAPS_IFSTATE_DISCARDING);
	eaps_set_port_proto(bp, bs->bs_protover);
	eaps_set_port_role(bp, EAPS_ROLE_DISABLED);
	eaps_set_port_tc(bp, EAPS_TCSTATE_INACTIVE);
	bp->bp_path_cost = eaps_calc_path_cost(bp);
	EAPS_UNLOCK(bs);
	return (0);
}

int
eaps_enable(struct eaps_port *bp)
{
	struct eaps_state *bs = bp->bp_bs;
	struct ifnet *ifp = bp->bp_ifp;

	KASSERT(bp->bp_active == 0, ("already a bstp member"));

	switch (ifp->if_type) {
		case IFT_ETHER:	/* These can do spanning tree. */
			break;
		default:
			/* Nothing else can. */
			return (EINVAL);
	}

	EAPS_LOCK(bs);
	LIST_INSERT_HEAD(&bs->bs_bplist, bp, bp_next);
	bp->bp_active = 1;
	bp->bp_flags |= EAPS_PORT_NEWINFO;
	eaps_reinit(bs);
	eaps_update_roles(bs, bp);
	EAPS_UNLOCK(bs);
	return (0);
}

void
eaps_disable(struct eaps_port *bp)
{
	struct eaps_state *bs = bp->bp_bs;

	KASSERT(bp->bp_active == 1, ("not a bstp member"));

	EAPS_LOCK(bs);
	eaps_disable_port(bs, bp);
	LIST_REMOVE(bp, bp_next);
	bp->bp_active = 0;
	eaps_reinit(bs);
	EAPS_UNLOCK(bs);
}

/*
 * The eaps_port structure is about to be freed by the parent bridge.
 */
void
eaps_destroy(struct eaps_port *bp)
{
	KASSERT(bp->bp_active == 0, ("port is still attached"));
	taskqueue_drain(taskqueue_swi, &bp->bp_statetask);
	taskqueue_drain(taskqueue_swi, &bp->bp_rtagetask);
	taskqueue_drain(taskqueue_swi, &bp->bp_mediatask);
}
