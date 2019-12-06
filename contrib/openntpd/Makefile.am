#
# Copyright (c) 2014-2015 Brent Cook
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

SUBDIRS = include compat src
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = VERSION ntpd.conf

install-exec-hook:
	@if [ ! -f "$(DESTDIR)$(sysconfdir)/ntpd.conf" ]; then \
		$(INSTALL) -m 644 "$(srcdir)/ntpd.conf" "$(DESTDIR)$(sysconfdir)/ntpd.conf"; \
	else \
		echo; \
		echo " $(DESTDIR)$(sysconfdir)/ntpd.conf already exists, install will not overwrite"; \
	fi

uninstall-local:
	@if cmp -s "$(DESTDIR)$(sysconfdir)/ntpd.conf" "$(srcdir)/ntpd.conf"; then \
		rm -f "$(DESTDIR)$(sysconfdir)/ntpd.conf"; \
	fi
	@rm -f "$(DESTDIR)$(sbindir)/ntpctl"
