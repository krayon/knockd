AM_CPPFLAGS=-D_DEFAULT_SOURCE
AM_CFLAGS=-g -Wall -pedantic -fno-exceptions -D_BSD_SOURCE

bin_PROGRAMS = knock
man_MANS = doc/knock.1

if BUILD_KNOCKD
sbin_PROGRAMS = knockd
dist_sbin_SCRIPTS = src/knock_helper_ipt.sh
man_MANS += doc/knockd.1
sysconf_DATA = knockd.conf
knockd_SOURCES = src/knockd.c src/list.c src/list.h src/otp.c src/otp.h src/shared_structs.c src/shared_structs.h src/knock_helper_ipt.sh
knockd_LDADD = -lm
endif

dist_doc_DATA = README.md TODO ChangeLog COPYING

knock_SOURCES = src/knock.c

%.1: %.1.in
	sed -e "s/#VERSION#/$(VERSION)/" $< > $@

# https://stackoverflow.com/questions/4219255/list-targets-makefile/26339924#26339924
.PHONY: list
list:
	$(MAKE) -pRrq : 2>/dev/null | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | sort -u | egrep -v -e '^[^[:alnum:]]' -e '^$@$$'

EXTRA_DIST = doc/knock.1 doc/knock.1.in doc/knockd.1 doc/knockd.1.in knockd.conf
CLEANFILES = $(man_MANS)
