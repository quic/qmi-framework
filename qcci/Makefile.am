# Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

AM_CFLAGS = -Wundef \
        -Wstrict-prototypes \
        -Wno-trigraphs \
        -g -O0 \
        -fno-inline \
        -fno-short-enums \
        -fpic \
        -DQMI_CCI_ANDROID \
        -DQMI_FW_SYSLOG

AM_CPPFLAGS = \
        -I../include \
        -I../common/ \
        -I$(top_builddir) \
        $(QMI_CFLAGS) \
        $(QMIFV_CFLAGS)

if ENABLE_QMI_LOG
AM_CFLAGS += -DQMI_ANDROID_LOGGING_LE
endif

h_sources = \
        qcci_os.h

requiredlibs = -lpthread \
        ../qencdec/libqencdec.la

if ENABLE_QMI_LOG
requiredlibs += -llog
endif

library_includedir = $(pkgincludedir)
library_include_HEADERS = $(h_sources)

c_sources = qcci.c \
        qcci_os.c \
        qcci_xport_qrtr.c

lib_LTLIBRARIES = libqcci.la
libqcci_la_CC = @CC@
libqcci_la_SOURCES = $(c_sources) $(h_sources)
libqcci_la_CFLAGS = $(AM_CFLAGS)
libqcci_la_CPPFLAGS = $(AM_CPPFLAGS)
libqcci_la_LDFLAGS = -shared -version-info 1:0:0
libqcci_la_LIBADD = $(requiredlibs)
