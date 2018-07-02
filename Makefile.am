# Copyright (c) 2018, Intel Corporation
# SPDX-License-Identifier: BSD-2-Clause

ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = src/glib-timer-event src/glib-tss2-event

src_glib_timer_event_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS)
src_glib_timer_event_LDADD = $(GLIB_LIBS)
src_glib_timer_event_SOURCES = src/glib-timer-event.c

src_glib_tss2_event_CFLAGS = $(AM_CFLAGS) $(GLIB_CFLAGS) $(TSS2_SYS_CFLAGS) $(TSS2_TCTI_TABRMD_CFLAGS)
src_glib_tss2_event_LDADD = $(GLIB_LIBS) $(TSS2_SYS_LIBS) $(TSS2_TCTI_TABRMD_LIBS)
src_glib_tss2_event_SOURCES = src/tss2-init-helper.h src/tss2-init-helper.c src/glib-tss2-event.c
