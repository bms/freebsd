#
# Copyright (c) 2006 The FreeBSD Project
# All rights reserved.
# Author: Victor Cruceru <soc-victor@freebsd.org>
#
# Redistribution of this software and documentation and use in source and
# binary forms, with or without modification, are permitted provided that
# the following conditions are met:
#
# 1. Redistributions of source code or documentation must retain the above
#    copyright notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
#

CONTRIB= ${.CURDIR}/../../../../contrib/bsnmp
.PATH: ${CONTRIB}/snmp_smux

MOD=	smux
SRCS=	smux_snmp.c smux_proto.c

#Not having -DNEBUG will enable asserts and a lot of debug mess
CFLAGS+= -DNDEBUG 
CFLAGS+= -I${CONTRIB}/lib -I${CONTRIB}/snmpd

XSYM= smux begemotSmux

BMIBS=	BEGEMOT-SMUX-MIB.txt
MAN=	snmp_smux.3
DEFS=	${MOD}_tree.def

.include <bsd.snmpmod.mk>

smilint:
	env SMIPATH=.:/usr/share/snmp/mibs:/usr/local/share/snmp/mibs \
	    smilint -c /dev/null -l6 -i group-membership BEGEMOT-SMUX-MIB
