/*
 *  shared_structs.h
 *
 *  Copyright (c) 2015-2016 by Paul Rogers <paul.rogers@flumps.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef _PAC_SHARED_STRUCTS_H
#define _PAC_SHARED_STRUCTS_H

// Open Door port (singular)
typedef struct doorPort
{
        unsigned short usPort;
        unsigned short usProto;
        unsigned short usProtoFlags;
} tDoorPort;

// Values for describing various protocol flags
#define FLAG_ENC_BASE		2
#define FLAG_SUPP_TCP		6
#define FLAG_SUPP_ICMP		7
#define FLAG_TCP_SYN		1
#define FLAG_TCP_ACK		2
#define FLAG_TCP_PSH		4
#define FLAG_TCP_URG		8
#define FLAG_TCP_FIN		16
#define FLAG_TCP_RST		32
#define FLAG_ICMP_ECHO		1
#define FLAG_ICMP_REPLY		2
#define FLAG_ICMP_DESTUNREACH	4
#define FLAG_ICMP_REDIRECT	8
#define FLAG_ICMP_TIMEEXCEED	16
#define FLAG_ICMP_TSTAMP	32
#define FLAG_ICMP_TSTAMPREPLY	64

#define LEN_PORT		5

// Total of supported protocols (i.e. those defined >= 0)
#define KNOCK_SUPP_PROTOS	3
#define KNOCK_PROTO_TCP		0
#define KNOCK_PROTO_UDP		1
#define KNOCK_PROTO_ICMP	2

// Global constants
extern const int TRUE;
extern const int FALSE;

#endif
