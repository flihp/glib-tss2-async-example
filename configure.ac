# Copyright (c) 2018, Intel Corporation
# SPDX-License-Identifier: BSD-2-Clause

AC_INIT([tss2-gio-event],[m4_esyscmd_s([cat ./VERSION])])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_CC
AC_PROG_LN_S
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_FILES([Makefile])

AC_SEARCH_LIBS([dlopen], [dl dld], [], [
  AC_MSG_ERROR([unable to find the dlopen() function])
])
PKG_CHECK_MODULES([GLIB], [glib-2.0])
PKG_CHECK_MODULES([TSS2_SYS], [tss2-sys >= 2])
PKG_CHECK_MODULES([TSS2_TCTI_TABRMD], [tss2-tcti-tabrmd >= 2])

AX_ADD_COMPILER_FLAG([-Wall])
AX_ADD_COMPILER_FLAG([-Wextra])
AX_ADD_COMPILER_FLAG([-Werror])
AX_ADD_COMPILER_FLAG([-std=gnu99])
AX_ADD_COMPILER_FLAG([-Wformat])
AX_ADD_COMPILER_FLAG([-Wformat-security])

AC_OUTPUT
