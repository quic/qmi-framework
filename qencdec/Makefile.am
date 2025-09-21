# Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

AM_CFLAGS = -Wundef \
        -Wstrict-prototypes \
        -Wno-trigraphs \
        -g -O0 \
        -fno-inline \
        -fno-short-enums \
        -fpic

AM_CPPFLAGS = \
        -I../include

h_sources = qmi_idl_lib_target.h

c_sources = qmi_idl_accessor.c \
        qmi_idl_lib.c

lib_LTLIBRARIES = libqencdec.la
libqencdec_la_CC = @CC@
libqencdec_la_SOURCES = $(c_sources)
libqencdec_la_CFLAGS = $(AM_CFLAGS)
libqencdec_la_CPPFLAGS = $(AM_CPPFLAGS)
libqencdec_la_LDFLAGS = -shared -version-info 1:0:0
