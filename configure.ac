AC_PREREQ(2.60)
AC_INIT([knock], [0.8.0], [https://github.com/jvinet/knock/issues])
AM_INIT_AUTOMAKE([dist-xz no-dist-gzip foreign subdir-objects])

AC_CONFIG_HEADER([config.h])

AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS

AC_ARG_ENABLE([knockd],
  [AS_HELP_STRING([--disable-knockd], [Disable building knockd (requires libpcap) @<:@default=enabled@:>@])])

AC_ARG_ENABLE([otp],
  [AS_HELP_STRING([--disable-otp], [Disable building dynamic port knocking (one time ports) into knockd (requires openssl) @<:@default=enabled@:>@])])

AS_IF([test "x$enable_knockd" != "xno"], [
  AC_CHECK_LIB([pcap], [pcap_dispatch], ,
    [AC_MSG_ERROR([you need the libpcap library to build knockd])])
])

AS_IF([test "x$enable_otp" != "xno"], [
  AC_CHECK_HEADERS(openssl/sha.h, [openssl_have_headers=1])
  AC_CHECK_LIB([crypto], [BN_new], AC_CHECK_LIB(ssl, SSL_accept, [openssl_have_libs=1],,-lcrypto),
    [AC_MSG_ERROR([you need the openssl library to build knockd])])
])

AM_CONDITIONAL([BUILD_KNOCKD], [test "x$enable_knockd" != "xno"])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
