#
# Copyright (c) 2026. ALL RIGHTS RESERVED.
# See file LICENSE for terms.
#

if HAVE_CXI

module_LTLIBRARIES       = libuct_cxi.la
libuct_cxi_la_CPPFLAGS   = $(BASE_CPPFLAGS)
libuct_cxi_la_CFLAGS     = $(BASE_CFLAGS) $(LT_CFLAGS)
libuct_cxi_la_LIBADD     = $(top_builddir)/src/ucs/libucs.la \
                           $(top_builddir)/src/uct/libuct.la \
                           $(CXI_LIBS)
libuct_cxi_la_LDFLAGS    = -version-info $(SOVERSION)

noinst_HEADERS = \
    cxi_iface.h \
    base/cxi_device.h \
    base/cxi_md.h

libuct_cxi_la_SOURCES = \
    cxi_iface.c \
    base/cxi_device.c \
    base/cxi_md.c

PKG_CONFIG_NAME=cxi

include $(top_srcdir)/config/module.am
# TODO: enable pkg-config processing when module static build is enabled
# include $(top_srcdir)/config/module-pkg-config.am

endif
