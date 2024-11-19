#!/bin/sh
# Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

# autogen.sh -- Autotools bootstrapping
#
rm -rf autom4te.cache
libtoolize --copy --force
aclocal &&\
autoheader &&\
autoconf &&\
automake --add-missing --copy
