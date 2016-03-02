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

#endif
