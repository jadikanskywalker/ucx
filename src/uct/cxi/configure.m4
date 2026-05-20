#
# Copyright (c) 2026. ALL RIGHTS RESERVED.
# See file LICENSE for terms.
#

cxi_supported=no

AC_ARG_WITH([cxi],
            [AS_HELP_STRING([--with-cxi[=DIR]], [Build CXI transport support])],
            [],
            [with_cxi=no])

AS_IF([test "x$with_cxi" != "xno"],
      [AC_MSG_CHECKING([for libcxi])
       saved_LIBS="$LIBS"
       LIBS="$LIBS -lcxi"
       AC_LINK_IFELSE(
           [AC_LANG_PROGRAM([[#include <libcxi/libcxi.h>]],
                            [[struct cxil_dev *d; cxil_open_device(0, &d);]])],
           [AC_MSG_RESULT([yes])
            AC_SUBST([CXI_LIBS], [-lcxi])
            AC_DEFINE([HAVE_LIBCXI], [1], [Have libcxi])
            cxi_supported=yes
            uct_modules="${uct_modules}:cxi"
            AC_DEFINE([HAVE_TL_CXI], [1], [Defined if CXI transport exists])],
           [AC_MSG_RESULT([no])
            AS_IF([test "x$with_cxi" != "x"],
                  [AC_MSG_ERROR([CXI transport requested but libcxi not found])])])
       LIBS="$saved_LIBS"])

AM_CONDITIONAL([HAVE_CXI], [test "x$cxi_supported" = "xyes"])
AC_CONFIG_FILES([src/uct/cxi/Makefile
                 src/uct/cxi/ucx-cxi.pc])
