/*
 *  otp.c
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

#include <float.h>
#include <math.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "shared_structs.h"

// Error return codes
#define ERR_OVERFLOW		-1
#define ERR_INVALID_HEX		-2

// Lengths of the digits representing the various components in the OTP double
#define LEN_PROTO		1
#define LEN_PROTO_FLAGS		1
#define LEN_SINGLE_OTP		7

#define KNOCK_PROTO_DYN		-1

// Global constants
const int  giDigestLen = SHA512_DIGEST_LENGTH;
const char gcMapHex[] = "0123456789abcdefABCDEF";

const int  giDigestHexLen = (giDigestLen * 2) + 1;

//
// funcGetTimeUTC - Returns the epoch seconds value in UTC.
//
// Inputs:	None
//
// Returns:	(int) epoch seconds in UTC.
//
int funcGetTimeUTC(void)
{
	int iTime = (int)time(NULL);
	return iTime;
}

//
// funcLenInt - Returns the length of an integer
//
// Inputs:	(const pint) piI	- a pointer to the integer we require a length for
//
// Returns:	(int)  the length of the integer. Don't forget to add 1 if using to convert an integer to a string (null character).
//
int funcLenInt(const int* piI)
{
	int iLen = snprintf(NULL, 0, "%d", *piI);
	return iLen;
}

//
// funcLenDbl - Returns the length of a double
//		Need to do it this way as snprintf truncates digits in the way achieved in funcLenInt.
//
// Inputs:	(double) dD	- a double we require a length for
//
// Returns:	(int)  the length of the double. Don't forget to add 1 if using to convert a double to a string (null character).
//
int funcLenDbl(const double* pdD)
{
	int iDigits = 0;
	double dD = *pdD;

	while (dD >= 1)
	{
		iDigits++;
		dD /= 10;
	}

	return iDigits;
}

//
// funcGetTimeSlotStart - Returns the epoch second value in UTC that represents the time for seeding into the hash generator
//
// Inputs:	(const pint) piSecsRotate	- a pointer to the number of seconds the hash should rotate
//
// Returns:	(int) epoch seconds that represents the time start time slot
//
int funcGetTimeSlotStart(const int* piSecsRotate)
{
	int iTimeUTC = funcGetTimeUTC();
	return ( iTimeUTC / *piSecsRotate );
}

//
// funcInt2Char - Returns the string version of an integer
//
// Inputs:	(const pint)   	  piI		- a pointer to the integer to convert to a string
// 		(const pint)   	  piLenI	- a pointer to the length of the integer to convert to a string
//		(returned pchar)  pcI		- a pointer to a char array containing the string representation of the integer.
//
// Returns:	(int) status - 0 success.
//
void funcInt2Char(const int* piI, const int* piLenI, char* pcI)
{
	sprintf(pcI, "%d", *piI);
	pcI[*piLenI] = '\0';
}

//
// funcDbl2Char - Returns the string version of a double
//
// Inputs:	(const pdbl)   	  pdD		- a pointer to the double to convert to a string
// 		(const pint)   	  piLenD	- a pointer to the length of the double to convert to a string
//		(returned pchar)  pcD		- a pointer to a char array containing the string representation of the double.
//
// Returns:	(int) status - 0 success.
//
void funcDbl2Char(const double* pdD, const int* piLenD, char* pcD)
{
	sprintf(pcD, "%.*g", funcLenDbl(pdD), *pdD);
	pcD[*piLenD] = '\0';
}

//
// funcChar2Int - Returns the integer version of a string
//
// Inputs:	(const pchar)	pcI	- pointer to the char arrary to convert to an integer
//		(returned pint)	piI	- pointer to an integer
//
// Returns:	(int) status - 0 success.
//
void funcChar2Int(const char* pcI, int* piI)
{
	sscanf(pcI, "%d", piI);
}

//
// funcHex2Dbl - Converts a hex string to a double
//
// Inputs:	(ptr char) pcHex	- hex string to be converted
//
// Returns:	Nothing.
//
void funcHex2Dbl(const char* pcHex, double* pdHex)
{
	double dHex = 0;
	int iChrMapPos;
	_Bool bEoCA = FALSE;
	int iI = 0;

	// Loop round the hex string until the end or until an error is detected.
	while ( ( ( iChrMapPos = *pcHex++ ) != '\0') || ( bEoCA == FALSE ) )
	{
		int iJ = 0;

		// Loop round the map to hex compared with the current character in the hex string.
		while (1)
		{
			// If we reach the end of the map to hex....
			if (gcMapHex[iJ] == '\0')
			{
				// And it is not a valid hex string (we're at charcter position 0), return an error.
				if (iI == 0)
				{
					printf("ERROR! funcHex2Dbl() - not a valid hex string: \n%s\n", pcHex);
					dHex = ERR_INVALID_HEX;
				}

				// Set error flags and break.
				bEoCA = TRUE;
				break;
			}

			// If we find the character in the map to hex, exit out of loop.
			if (gcMapHex[iJ] == iChrMapPos) break;
			// Otherwise increment J and loop.
			iJ++;
		}

		// Did we find an error - then break out the loop otherwise you will go past end of the char array.
		if (bEoCA == TRUE) break;

		// If the hex numeric value is >= 16, it was a capital so subtract 6 to get an unsigned case value.
		int iHexMax = 16;
		if (iJ >= iHexMax) iJ -= 6;

		// If we won't overflow a double max, multiply the double by 16 (max hex numeric).
		if (dHex <= DBL_MAX / iHexMax) dHex *= iHexMax;
		else
		{
			// Error out as a double overflow would have occurred.
			printf("ERROR! funcHex2Dbl() would have experienced a double overflow\n");
			bEoCA = TRUE;
			dHex = ERR_OVERFLOW;
			break;
		}

		// Add the hex numeric value to the double.
		dHex += iJ;
		iI++;
	}

	// Set the pointer value to the double value (to be used by the calling function).
	*pdHex = dHex;
}

//
// funcHex2Int - Converts a hex string to an integer
//
// Inputs:	(ptr char)	pcHex	- hex string to be converted
//
// Returns:	Nothing.
//
void funcHex2Int(const char* pcHex, int* piHex)
{
	int iHex = 0;
	int iChrMapPos;
	_Bool bEoCA = FALSE;
	int iI = 0;

	// Loop round the hex string until the end or until an error is detected.
	while ( ( ( iChrMapPos = *pcHex++ ) != '\0') || ( bEoCA == FALSE ) )
	{
		int iJ = 0;

		// Loop round the map to hex compared with the current character in the hex string.
		while (1)
		{
			// If we reach the end of the map to hex, it is not a valid hex string - return an error.
			if (gcMapHex[iJ] == '\0')
			{
				// And it is not a valid hex string (we're at charcter position 0), return an error.
				if (iI == 0)
				{
					printf("ERROR! funcHex2Int() - not a valid hex string: \n%s\n", pcHex);
					iHex = ERR_INVALID_HEX;
				}

				// Set error flags and break.
				bEoCA = TRUE;
				break;
			}

			// If we find the character in the map to hex, exit out of loop.
			if (gcMapHex[iJ] == iChrMapPos) break;
			// Otherwise increment J and loop.
			iJ++;
		}

		// Did we find an error - then break out the loop otherwise you will go past end of the char array.
		if (bEoCA == TRUE) break;

		// If the hex numeric value is >= 16, it was a capital so subtract 6 to get an unsigned case value.
		int iHexMax = 16;
		if (iJ >= iHexMax) iJ -= 6;

		// If we won't overflow an integer max, multiply the double by 16 (max hex numeric).
		if (iHex <= INT_MAX / iHexMax) iHex *= iHexMax;
		else
		{
			// Error out as an integer overflow would have occurred.
			printf("ERROR! funcHex2Int() would have experienced an integer overflow\n");
			bEoCA = TRUE;
			iHex = ERR_OVERFLOW;
			break;
		}

		// Add the hex numeric value to the int.
		iHex += iJ;
		iI++;
	}

	// Set the pointer value to the integer value (to be used by the calling function).
	*piHex = iHex;
}

//
// funcGenSHA512 - Returns the SHA512 hex hash of the plaintext passed to it.
//
// Inputs:	(pchar)          pcPlain	- the plain text char arrary to be hashed - can't be a constant due to SHA512_Update constructor not being a const.
//		(returned pchar) pcHexFull	- the hex hash of the plain text.
//
// Returns:	Nothing.
//
void funcGenSHA512(char* pcPlain, char* pcHexFull)
{
	const size_t sztPlain = strlen(pcPlain);
	SHA512_CTX ctxSHA512;

	// char array to hold the digest
	unsigned char ucDigest[giDigestLen];

	// generate the digest
	SHA512_Init(&ctxSHA512);
	SHA512_Update(&ctxSHA512, pcPlain, sztPlain);
	SHA512_Final(ucDigest, &ctxSHA512);

	int iI;
	char* pcHexInternal;
	unsigned char* pucDigest;

	pucDigest = ucDigest;
	pcHexFull[0] = '\0';

	for (iI = 0, pcHexInternal = pcHexFull; iI < giDigestLen; iI++)
	{
		*pcHexInternal++ = gcMapHex[(*pucDigest >> 4) & 0x0f];
		*pcHexInternal++ = gcMapHex[(*pucDigest++   ) & 0x0f];
	}

	*pcHexInternal = '\0';
}

//
// funcUpdateInvalidPort - Verifies if the port is within the prescribed valid range and if not,
//			   use the out of range hash to generate a new random port within the valid range.
//
// Inputs:	(const pint)	piPortMin	- pointer to the integer representing the minimum port in the range
//		(const pint)	piPortMax	- pointer to the integer representing the maximum port in the range
//		(const pchar)	pcHashOOR	- pointer to a hash to be used for determining the new random port if piPort is determined to be out of range
//		(const pint)    piInitHashPos	- pointer to the initial point in the out of range hash to start deriving ports
//		(returned pint)	piPort		- pointer to the port to be checked and updated if necessary. Original is not changed if valid.
//
// Returns:	(int) status of function: 0 - success, ERR_OVERFLOW, ERR_INVALID_HEX
//
int funcUpdateInvalidPort(const int* piPortMin, const int* piPortMax, const char* pcHashOOR, int* piInitHashPos, int* piPort)
{
	// If the OTP generated is outside of the range of valid ports, then we need to create a random one within the range.
	if ( (*piPort < *piPortMin) || (*piPort > *piPortMax) )
	{
		// Calculate the range we got to work with.
		int iPortDiff = *piPortMax - *piPortMin;
		int iLenPortDiff = funcLenInt(&iPortDiff);
		int iI;
		int iaPortDiff[iLenPortDiff];

		// Split the range we got to work with into an array so we can randomise each digit but keep it in range
		for (iI = (iLenPortDiff - 1); iI >= 0; iI--, iPortDiff /= 10)
		{
			iaPortDiff[iI] = iPortDiff % 10;
		}

		int iPort = 0;

		// Loop round each digit in the range we got to work with and generate
		// a new random port that is within the valid range.
		for (iI = 0; iI < iLenPortDiff; iI++)
		{
			// We add one to the value of the current digit to ensure the divisor in the MOD calculation below
			// is not zero.
			int iDiffVal = iaPortDiff[iI] + 1;

			// Only need to return one character from the Out Of Range (OOR) hash
			// (a different part of the overall hash to minimise clashes).
			int iLenOffset = 1;

			// Grab one character of the OOR hash starting from the right hand side.
			char cOffset[iLenOffset + 1];
			bzero(cOffset, iLenOffset + 1);
			strncpy(cOffset, pcHashOOR+( strlen(pcHashOOR) + *piInitHashPos ), 1);
			cOffset[iLenOffset] = '\0';

			// Convert the hex character to an interger so we can use it in the port generation.
			int iOffset = 0;
			funcHex2Int(cOffset, &iOffset);
			// Error check.
			if (iOffset < 0) return iOffset;

			// Do not need the character anymore.
			bzero(cOffset, iLenOffset + 1);

			// Generate the random digit for port at position iI. We mod with the difference
			// between max and min ports at this particular digit position to ensure the
			// randomlu generated port falls within the valid range.
			int iMod = iOffset % iDiffVal;

			// Update the port number with the new random digit
			iPort = (10 * iPort) + iMod;

			// Move the position of where we are grabbing the next character from
			// the OOR hash back one character (remember it is from the right).
			*piInitHashPos -= iLenOffset;
		}

		// Add the minimum port to the random port generated above.
		iPort += *piPortMin;
		// Return either the original port or the new generated port.
		*piPort = iPort;
	}

	return 0;
}

//
// funcParseDbl2OTP - Parses the ul list of all ports and verifies if the port in the ulng is valid and if not
//		      generate a random port based on cHashOOR that is in range.
//
// Inputs:	(const pdbl)            pdOTP		- pointer to a double representing the OTPs
//		(const pchar)           pcHashOOR	- pointer to a hash to be used for determining random ports for out of range ports in the OTP
//		(const pint)            piNumPorts	- pointer to a number of ports to be generated
//		(const pint)            piInitHashPos	- pointer to the initial point in the out of range hash to start deriving ports
//		(const pint)            piPortMin	- pointer to the first port in the valid range for ports
//		(const pint)            piPortMax	- pointer to the last port in the valid range for ports
//		(const pint)            piProto		- pointer to the integer indicating what protocol or if dynamic protocols are enabled
//		(const pint)            piProtoFlags	- pointer to the integer indicating what protocol flags or if dynamic protocol flags are enabled
//		(returned ptDoorPorta)  ptpdaPorts	- pointer of typedef tDoorPort (struct of a port)
//
int funcParseDbl2OTP(const double* pdOTP, const char* pcHashOOR, const int* piNumPorts, const int* piInitHashPos, const int* piPortMin, const int* piPortMax, const int* piProto, const int* piProtoFlags, tDoorPort* ptpdaPorts)
{
	int iI;
	int iLenD = funcLenDbl(pdOTP);
	// Char array to hold the double of the One Time Ports (OTP).
	char cOTP[iLenD];
	bzero(cOTP, iLenD);

	// The length of a valid single port representation with the OTP double.
	//
	// The structure of the OTP double is as such:
	//
	// a) Proto
	// |
	// |/- b) TCP control bits
	// ||
	// ||/- c)Port (TCP and UDP ports / ICMP control bits)
	// |||
	// |||	  abc
	// |||    |||
	// 65171076451939....
	// 65171076451939....
	int iLenSingleOTP = LEN_SINGLE_OTP;

	// If however we are not automatically deriving the Protocol and/or Protocol Flags
	// and it is manually set during the configuration, we need to retrieve LEN_PROTO
	// and/or LEN_PROTO_FLAGS less characters.
	if (*piProto >= 0) iLenSingleOTP -= LEN_PROTO;
	if (*piProtoFlags >= 0) iLenSingleOTP -= LEN_PROTO_FLAGS;

	// Convert the whole OTP double to a char array for parsing.
	funcDbl2Char(pdOTP, &iLenD, cOTP);

	// String parsing initial starting position based on the initial one set in the
	// configuration for the knock.
	int iInitOORHashPos = *piInitHashPos;

	// Loop based on the number of ports we are supposed to automatically generate
	// based on the configuration for the knock.
	for (iI = 0; iI < *piNumPorts; iI++)
	{
		// char array to hold the single OTP representation.
		char cSingleOTP[iLenSingleOTP + 1];
		bzero(cSingleOTP, iLenSingleOTP + 1);

		// Retrieve the single OTP representation from the complete OTP.
		strncpy(cSingleOTP, cOTP+(iI * iLenSingleOTP), iLenSingleOTP);
		cSingleOTP[iLenSingleOTP] = '\0';

		// Initialise the individual attributes of the single OTP representation.
		char cPort[LEN_PORT + 1];
		char cProto[LEN_PROTO + 1];
		char cProtoFlags[LEN_PROTO_FLAGS + 1];
		int iPort = 0;
		int iProtoRaw = 0;
		int iProtoFlagsRaw = 0;
		bzero(cPort, LEN_PORT + 1);
		bzero(cProto, LEN_PROTO + 1);
		bzero(cProtoFlags, LEN_PROTO_FLAGS + 1);

		// Position indicator as to where we substring the next piece from the char array
		// version of the complete OTP.
		int iStartPos = 0;

		// If the Protocol config for the knock was not set, we all use the first
		// character in the single OTP representation to determine the Protocol.
		if (*piProto < 0)
		{
			strncpy(cProto, cSingleOTP+iStartPos, LEN_PROTO);
			cProto[LEN_PROTO] = '\0';
			funcChar2Int(cProto, &iProtoRaw);
			bzero(cProto, LEN_PROTO + 1);
			iStartPos += LEN_PROTO;
		}

		// If the Protocol Flag config for the knock was not set, we all use the first
		// character in the single OTP representation to determine the Protocol Flag.
		if (*piProtoFlags < 0)
		{
			strncpy(cProtoFlags, cSingleOTP+iStartPos, LEN_PROTO_FLAGS);
			cProtoFlags[LEN_PROTO_FLAGS] = '\0';
			funcChar2Int(cProtoFlags, &iProtoFlagsRaw);
			bzero(cProtoFlags, LEN_PROTO_FLAGS + 1);
			iStartPos += LEN_PROTO_FLAGS;
		}

		// Separate out the port to be used.
		strncpy(cPort, cSingleOTP+iStartPos, LEN_PORT);
		cPort[LEN_PORT] = '\0';
		funcChar2Int(cPort, &iPort);

		// No need for the char single OTP representation.
		bzero(cSingleOTP, iLenSingleOTP);

		// Calculate the final individual attributes for Protocol and Protocol FLags.
		// Only need valid protocol numbers - convert to a base 2 number.
		int iProto = ( iProtoRaw % KNOCK_SUPP_PROTOS );
		int iProtoFlags = 0;
		// If the protocol doesn't support flags, need to set the mod value to 1 so we
		// always return 0 for the protocol flags attribute.
		int iPFMod = 1;

		// Set the appropriate mod value to produce valid flag combinations depending on
		// the supported protocol generated.
		if (iProto == KNOCK_PROTO_TCP) iPFMod = FLAG_SUPP_TCP;
		else if (iProto == KNOCK_PROTO_ICMP) iPFMod = FLAG_SUPP_ICMP;

		iProtoFlags = iProtoFlagsRaw % iPFMod;

		// Now check the port validity - update it and add to the struct
		int iRet = funcUpdateInvalidPort(piPortMin, piPortMax, pcHashOOR, &iInitOORHashPos, &iPort);
		if (iRet < 0) return iRet;

		// Update the array of single port structs to contain the individual attributes.
		ptpdaPorts[iI].usPort = iPort;
		ptpdaPorts[iI].usProto = (int) pow(FLAG_ENC_BASE, iProto);
		ptpdaPorts[iI].usProtoFlags = (int) pow(FLAG_ENC_BASE, iProtoFlags);
	}

	return 0;
}

//
// funcGenOTP - Generates the list of valid one time ports using a hashed shared secret password and the current UTC time
//		based on the rotation policy set.
//
//		I bzero alot here to ensure the smallest amount of time that 'in the clear' variables are in memory for.
//
//		The hashing algorithm you use needs to be able to support the number of ports you are allowed to generate.
//		For example, SHA512 will allow you to generate 22 ports with random protocols and protocol flags.
//		If you want more, disable random protocol and/or protocol flags to support 26 or 30 ports respectively.
//
// Inputs:	(const pchar)      pcHashPasswd		- pointer to already hashed passord to use in the hash generation (as this should be done one time at configuration read)
//		(const pint)       piNumPorts		- pointer to the number of ports to be generated
//		(const pint)       piOTPRotate		- pointer to the port generation rotation time in seconds
//		(const pint)       piInitHashPos	- pointer to the initial point in hash to start deriving ports
//		(const pint)       piPortMin		- pointer to the first port in the valid range
//		(const pint)       piPortMax		- pointer to the last port in the valid range
//		(const pint)       piProto		- pointer to the integer indicating what protocol or if dynamic protocols are enabled
//		(const pint)       piProtoFlags		- pointer to the integer indicating what protocol flags or if dynamic protocol flags are enabled
//		(returned ptdparr) ptdpaPorts		- pointer containing the tDoorPort array of OTPs.
//
// Returns:	(int) status 0 - success
//
int funcGenOTP(const char* pcHashPasswd, const int* piNumPorts, const int* piOTPRotate, const int* piInitHashPos, const int* piPortMin, const int* piPortMax, const int* piProto, const int* piProtoFlags, tDoorPort* ptdpaPorts)
{
	// Gets the current UTC based time slot given the rotation policy set.
	// Need it in a char array in order to generate the hash.
	int iTimeSlotStart = funcGetTimeSlotStart(piOTPRotate);
	int iLenTimeSlotStart = funcLenInt(&iTimeSlotStart);
	char cTimeSlotStart[iLenTimeSlotStart + 1];
	bzero (cTimeSlotStart, sizeof(cTimeSlotStart));
	funcInt2Char(&iTimeSlotStart, &iLenTimeSlotStart, cTimeSlotStart);

	char cHashTimeSlotStart[giDigestHexLen];
	bzero(cHashTimeSlotStart, giDigestHexLen);

	// Generate the hash of the time slot we are in.
	funcGenSHA512(cTimeSlotStart, cHashTimeSlotStart);
	bzero(cTimeSlotStart, sizeof(cTimeSlotStart));

	// Subtract one from the length because itself includes room for a null character and given we are doubling the size we don't need two nulls!
	int iLenConcat = (giDigestHexLen * 2) - 1;
	char cHashConcat[iLenConcat];
	bzero(cHashConcat, iLenConcat);

	// Concatenate the hashed password and hashed time slot into a single char array.
	strncpy(cHashConcat, pcHashPasswd, giDigestHexLen);
	strncat(cHashConcat, cHashTimeSlotStart, giDigestHexLen);
	cHashConcat[iLenConcat - 1] = '\0';

	bzero(cHashTimeSlotStart, giDigestHexLen);

	char cHashOTPInit[giDigestHexLen];
	bzero(cHashOTPInit, giDigestHexLen);

	// Generate the hash of the combined password and time slot hashes
	funcGenSHA512(cHashConcat, cHashOTPInit);
	bzero(cHashConcat, sizeof(cHashConcat));

	// Get the character we will use to determine the starting position for parsing the OTP portion
	// from the right most character of the hash to know where to randomly pick part of the OTP hash
	// to be used in OOR generation.
	int iLenOTPStartPos = 2;
	char cOTPStartPos[iLenOTPStartPos];
	bzero(cOTPStartPos, iLenOTPStartPos);

	strncpy(cOTPStartPos, cHashOTPInit+(giDigestLen + *piInitHashPos), 1);
	cOTPStartPos[iLenOTPStartPos - 1] = '\0';

	// Convert the character of the starting position to an integer.
	int iOTPStartPos = 0;
	funcHex2Int(cOTPStartPos, &iOTPStartPos);
	// Error checking.
	if (iOTPStartPos < 0) return iOTPStartPos;

	bzero(cOTPStartPos, iLenOTPStartPos);
	iLenOTPStartPos = 0;

	// Using the starting position integer above, retrieve the part of the hash to be used in OTP generation.
	int iLenOTPHash = (*piNumPorts * 6) + 1;
	char cHashOTP[iLenOTPHash];
	bzero(cHashOTP, iLenOTPHash);

	strncpy(cHashOTP, cHashOTPInit+iOTPStartPos, iLenOTPHash);
	cHashOTP[iLenOTPHash - 1] = '\0';

	// From the right most side of the hash, retrieve a large enough chunk to be used in
	// randomly generating new ports for those which were found to be OOR
	int iLenPorts = (*piNumPorts * 5) + 1;
	char cHashOOR[iLenPorts];
	bzero(cHashOOR, iLenPorts);

	// Take a copy of the hash as we need to substring another part for OOR port generation.
	char cHashOTPInit2[giDigestHexLen];
	bzero(cHashOTPInit2, giDigestHexLen);
	strncpy(cHashOTPInit2, cHashOTPInit+0, giDigestHexLen);
	cHashOTPInit2[giDigestHexLen] = '\0';

	strncpy(cHashOOR, cHashOTPInit2+( giDigestHexLen + ( ( *piInitHashPos - ( iLenPorts - 1 ) ) - 1 ) ), iLenPorts);
	cHashOOR[iLenPorts - 1] = '\0';

	// Empty the hash as we don't need it anymore
	bzero(cHashOTPInit, sizeof(cHashOTPInit));

	// Now need to convert the hex string to a double
	double dOTP;
	funcHex2Dbl(cHashOTP, &dOTP);
	// Error checking.
	if (dOTP < 0) return (int) dOTP;

	// Empty the hash as we don't need it anymore
	bzero(cHashOTP, sizeof(cHashOTP));

	// New we have the double representation of the OTP sequence, we need to parse it into separate
	// port, protocol and protocol flag components based on the knock configuration.
	int iRet = funcParseDbl2OTP(&dOTP, cHashOOR, piNumPorts, piInitHashPos, piPortMin, piPortMax, piProto, piProtoFlags, ptdpaPorts);
	// Error checking.
	if (iRet < 0) return iRet;

	return 0;
}
