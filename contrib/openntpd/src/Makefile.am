#
# Copyright (c) 2014 Brent Cook
# Parts based on Makefile.in from Portable OpenNTPD:
# Copyright (c) 2004-2008 Darren Tucker.
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

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CPPFLAGS += -DYYSTYPE_IS_DECLARED

ACLOCAL_AMFLAGS = -Im4
CLEANFILES = parse.c

sbin_PROGRAMS = ntpd
dist_man_MANS = ntpctl.8 ntpd.8 ntpd.conf.5

ntpd_CFLAGS = $(CFLAGS)
ntpd_CFLAGS += -DSYSCONFDIR=\"$(sysconfdir)\"
ntpd_CFLAGS += -DLOCALSTATEDIR=\"$(localstatedir)\"

ntpd_LDADD = $(PLATFORM_LDADD) $(PROG_LDADD) -lm
ntpd_LDADD += $(top_builddir)/compat/libcompat.la
ntpd_LDADD += $(top_builddir)/compat/libcompatnoopt.la

ntpd_SOURCES = client.c
ntpd_SOURCES += config.c
if HAVE_LIBTLS
ntpd_SOURCES += constraint.c
else
ntpd_SOURCES += constraint-disabled.c
endif
ntpd_SOURCES += control.c
ntpd_SOURCES += log.c
ntpd_SOURCES += ntp.c
ntpd_SOURCES += ntp.h
ntpd_SOURCES += ntp_dns.c
ntpd_SOURCES += ntp_msg.c
ntpd_SOURCES += ntpd.c
ntpd_SOURCES += ntpd.h
ntpd_SOURCES += parse.y
if HAVE_SENSORS
ntpd_SOURCES += sensors.c
else
ntpd_SOURCES += fake-sensors.c
endif
ntpd_SOURCES += server.c
ntpd_SOURCES += util.c

install-exec-hook:
	@ln -f "$(DESTDIR)$(sbindir)/ntpd" "$(DESTDIR)$(sbindir)/ntpctl"
	@if [ ! -d "$(DESTDIR)$(sysconfdir)" ]; then \
		$(INSTALL) -m 755 -d "$(DESTDIR)$(sysconfdir)"; \
	fi
	@if [ ! -d "$(DESTDIR)$(localstatedir)/run" ]; then \
		$(INSTALL) -m 755 -d "$(DESTDIR)$(localstatedir)/run"; \
	fi
	@if [ ! -d "$(DESTDIR)$(localstatedir)/db" ]; then \
		$(INSTALL) -m 755 -d "$(DESTDIR)$(localstatedir)/db"; \
	fi
	@if [ ! -d "$(PRIVSEP_PATH)" ]; then \
		echo; \
		echo " Please created a privilege separation directory for ntpd." ; \
		echo " For OS X, see INSTALL for instructions." ; \
		echo " On Linux / BSD systems, this will probably work:"; \
		echo ; \
		echo "   mkdir -p \"$(PRIVSEP_PATH)\"" ; \
		echo "   chown 0 \"$(PRIVSEP_PATH)\"" ; \
		echo "   chgrp 0 \"$(PRIVSEP_PATH)\"" ; \
		echo "   chmod 0755 \"$(PRIVSEP_PATH)\"" ; \
	fi
	@if egrep "^$(PRIVSEP_USER):" /etc/group >/dev/null; then \
		: ; \
	else \
		echo; \
		echo " Please create a dedicated group for ntpd." ; \
		echo " For OS X, see INSTALL for instructions." ; \
		echo " On Linux / BSD systems, this will probably work:"; \
		echo ; \
		echo "   groupadd $(PRIVSEP_USER)" ; \
	fi
	@if egrep "^$(PRIVSEP_USER):" /etc/passwd >/dev/null; then \
		: ; \
	else \
		echo; \
		echo " Please create a dedicated user for ntpd and ensure it" ; \
		echo " cannot be used to log in." ; \
		echo " For OS X, see INSTALL for instructions." ; \
		echo " On Linux / BSD systems, this will probably work:" ; \
		echo ; \
		echo "   useradd -g $(PRIVSEP_USER) -s /sbin/nologin -d $(PRIVSEP_PATH) -c 'OpenNTP daemon' $(PRIVSEP_USER)" ; \
	fi
	@if [ -d $(PRIVSEP_PATH) ]; then \
		if [ `ls -A $(PRIVSEP_PATH)|wc -l` != "0" ]; then \
		echo; \
		echo " WARNING: the privilege separation path is specified as $(PRIVSEP_PATH), " ; \
		echo "          but this directory contains files!" ; \
		echo ; \
		echo " Please ensure that $(PRIVSEP_PATH) is empty. If you installed a previous " ; \
		echo " OpenNTPD version and created a user with a home directory at /var/empty/ntpd, " ; \
		echo " please adjust that user to use /var/empty instead and delete /var/empty/ntpd." ; \
		fi; \
	fi
	@echo
