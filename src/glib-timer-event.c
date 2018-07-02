/*
 * Copyright (c) 2018, Intel Corporation
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <glib.h>
#include <stdlib.h>

#define TIMEOUT_COUNT_MAX 10
#define TIMEOUT_INTERVAL  100

typedef struct {
    GMainLoop *loop;
    size_t timeout_count;
} data_t;

gboolean
timeout_callback (gpointer user_data)
{
    data_t *data = (data_t*)user_data;

    g_print ("timeout_count: %zu\n", data->timeout_count);
    if (data->timeout_count < TIMEOUT_COUNT_MAX) {
        ++data->timeout_count;
        return G_SOURCE_CONTINUE;
    } else {
        g_main_loop_quit (data->loop);
        return G_SOURCE_REMOVE;
    }
}

int
main (void)
{
    GMainContext *context;
    GSource *source;
    data_t data = { 0 };

    source = g_timeout_source_new (TIMEOUT_INTERVAL);
    g_source_set_callback (source, timeout_callback, &data, NULL);
    context = g_main_context_new ();
    g_source_attach (source, context);
    g_source_unref (source);

    data.loop = g_main_loop_new (context, FALSE);
    g_main_context_unref (context);

    g_main_loop_run (data.loop);
    g_main_loop_unref (data.loop);
    return 0;
}
