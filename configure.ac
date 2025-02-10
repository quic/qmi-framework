# Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

AC_INIT([QMI_FRAMEWORK], [1.0], [bug-automake@gnu.org])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])
AM_PROG_AR
LT_INIT
# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
PKG_PROG_PKG_CONFIG
AM_PROG_AR

AS_CASE([$host],
  [*-linux-gnu], [
  compile_for_gnu=yes
  ], [
  compile_for_gnu=no
  ]
)

AM_CONDITIONAL([GNU_CC],
[test "$compile_for_gnu" = yes])

#Enable QMI FW logging
AM_CONDITIONAL(ENABLE_QMI_LOG, test "x${with_qmilog}" = "xyes")

QCCI_DEBUG_LEVEL=3
QCSI_DEBUG_LEVEL=3
AC_DEFINE_UNQUOTED([QCCI_DEBUG_LEVEL], [$QCCI_DEBUG_LEVEL], [Debug level value])
AC_DEFINE_UNQUOTED([QCSI_DEBUG_LEVEL], [$QCSI_DEBUG_LEVEL], [Debug level value])

AC_CONFIG_FILES([
 Makefile	  \
 common/Makefile  \
 qencdec/Makefile \
 qcci/Makefile	  \
 qcsi/Makefile    \
 tests/Makefile
])
AC_OUTPUT
