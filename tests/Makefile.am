# Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

AM_CFLAGS = -Wundef \
        -Wstrict-prototypes \
        -Wno-trigraphs \
        -g -O0 \
        -fno-inline \
        -fno-short-enums \
        -fpic \
        $(QMI_CFLAGS)

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/qcsi -I$(top_srcdir)/common

requiredlibs = ../qencdec/libqencdec.la ../common/libqmi_common.la ../qcci/libqcci.la ../qcsi/libqcsi.la

if GNU_CC
requiredlibs += -lpthread
endif

bin_PROGRAMS = qcci_test
qcci_test_SOURCES = qcci_test.c test_service_v01.c
qcci_test_LDADD = $(requiredlibs)
qcci_test_CC = @CC@

bin_PROGRAMS += qcsi_test
qcsi_test_SOURCES = qcsi_test.c qcsi_test_ping.c test_service_v01.c
qcsi_test_LDADD = $(requiredlibs)
qcsi_test_CC = @CC@
