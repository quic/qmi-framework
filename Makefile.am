# Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

# Makefile.am - Automake script for QMI Framework
AM_CPPFLAGS = -I$(top_srcdir)/include
ACLOCAL_AMFLAGS = -I m4
pkginclude_HEADERS = \
                include/common_v01.h \
                include/qcsi.h \
                include/qcsi_target_ext.h \
                include/qmi_cci_target_ext.h \
                include/qmi_client.h \
                include/qmi_idl_lib.h \
                include/qmi_idl_lib_internal.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = qmi-framework.pc

SUBDIRS = common qencdec qcci qcsi tests
