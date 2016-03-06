#
# Copyright (c) 2004-2012 by Judd Vinet <jvinet@zeroflux.org>
#
# Additional changes by Paul Rogers <paul.rogers@flumps.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

AC_PREREQ( 2.60 )
AC_INIT( [knock], [0.8.0], [https://github.com/jvinet/knock/issues] )
AM_INIT_AUTOMAKE( [dist-xz no-dist-gzip foreign subdir-objects] )

AC_CONFIG_HEADER( [config.h] )

AC_PROG_CC
AC_PROG_INSTALL
AC_USE_SYSTEM_EXTENSIONS

AC_ARG_ENABLE(
	[knockd],
	[
		AS_HELP_STRING(
			[--disable-knockd],
			[Disable building knockd (requires libpcap) @<:@default=enabled@:>@]
		)
	]
)

AC_ARG_ENABLE(
	[otp],
	[
		AS_HELP_STRING(
			[--disable-otp],
			[Disable building dynamic port knocking (one time ports) into knockd (requires openssl) @<:@default=enabled@:>@]
		)
	]
)

AS_IF(
	[test "x$enable_knockd" != "xno"],
	[
		AC_CHECK_LIB(
			[pcap],
			[pcap_dispatch],
			,
			[ AC_MSG_ERROR( [you need the libpcap library to build knockd] ) ]
		)
		AC_CHECK_HEADERS(
			[pcap.h],
			[pcap_have_headers=1],
			[ AC_MSG_ERROR( [you need the libpcap headers to build knockd] ) ]
		)
	]
)

AS_IF(
	[test "x$enable_otp" != "xno"],
	[
		AC_CHECK_LIB(
			[crypto],
			[SHA512_Init],
			,
			[ AC_MSG_ERROR( [you need the openssl library to build with one time port support] ) ]
		)
		AC_CHECK_HEADERS(
			[openssl/bio.h openssl/bugfer.h openssl/evp.h openssl/sha.h],
			[openssl_have_headers=1],
			[ AC_MSG_ERROR( [you need the openssl headers to build with one time port support] ) ]
		)
	]
)

AM_CONDITIONAL(
	[BUILD_KNOCKD],
	[test "x$enable_knockd" != "xno"]
)

AC_CONFIG_FILES( [Makefile] )

AC_OUTPUT
