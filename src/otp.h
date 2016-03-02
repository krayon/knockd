/*
 *  ott.h
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
#ifndef _PAC_OTP_H
#define _PAC_OTP_H

int  funcGetTimeUTC(void);
int  funcGetTimeSlotStart(const int* piSecsRotate);
int  funcLenDbl(const double* pdD);
int  funcLenInt(const int* piI);
void funcInt2Char(const int* piI, const int* piLenI, char* pcI);
void funcDbl2Char(const double* pdD, const int* piLenD, char* pcD);
void funcChar2Int(const char* pcI, int* piI);
void funcHex2Dbl(const char* pcHex, double* pdHex);
void funcHex2Int(const char* pcHex, int* piHex);
void funcGenSHA512(char* pcPlain, char* pcHexFull);
int  funcUpdateInvalidPort(const int* piPortMin, const int* piPortMax, const char* pcHashOOR, int* piInitHashPos, int* piPort);
int  funcParseDbl2OTP(const double* pdOTP, const char* pcHashOOR, const int* piNumPorts, const int* piInitHashPos, const int* piPortMin, const int* piPortMax, const int* piProto, const int* piProtoFlags, tDoorPort* ptpdaPorts);
int  funcGenOTP(const char* pcHashPasswd, const int* piNumPorts, const int* piOTPRotate, const int* piInitHashPos, const int* piPortMin, const int* piPortMax, const int* piProto, const int* piProtoFlags, tDoorPort* ptdpaPorts);

#endif

/* vim: set ts=2 sw=2 noet: */
