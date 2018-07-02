/*
 * Copyright (c) 2018, Intel Corporation
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <dlfcn.h>
#include <glib.h>
#include <glib-unix.h>
#include <inttypes.h>

#include <tss2/tss2_sys.h>

#include "tss2-init-helper.h"

#define TCTI_NAME_DEFAULT "device"
#define TCTI_CONF_DEFAULT NULL
#define OPTS_T_DEFAULT { \
    .tcti_name = TCTI_NAME_DEFAULT, \
    .tcti_conf = TCTI_CONF_DEFAULT, \
}
/*
 * Structure / type to hold parameters received on the command line.
 */
typedef struct {
    char *tcti_name;
    char *tcti_conf;
} opts_t;
/*
 * Structure / type to hold application data.
 */
typedef struct {
    TSS2_SYS_CONTEXT *sys_ctx;
    TSS2_TCTI_CONTEXT *tcti_ctx;
    GMainLoop *loop;
    void *tcti_dl_handle;
    size_t timeout_count;
    gboolean done;
} data_t;
/*
 * Callback function used with timer event. This function checks the 'done'
 * boolean in the data_t structure (passed as user_data). If the flag is set
 * then the we terminate the GMainLoop. If this flag is not set then the
 * function increments the 'timeout_count'. To show the user progress /
 * timer events we write 'tick' to the console when the current counter value
 * is even or 'tock' otherwise.
 */
gboolean
timer_callback (gpointer user_data)
{
    data_t *data = (data_t*)user_data;

    if (data->done) {
        g_debug ("CreatePrimary done, removing timer GSource and terminating "
                 "GMainLoop");
        g_main_loop_quit (data->loop);
        return G_SOURCE_REMOVE;
    }
    if (data->timeout_count % 2) {
        g_print ("tock\n");
    } else {
        g_print ("tick\n");
    }
    ++data->timeout_count;
    g_debug ("%s: continuing timer GSource with timeout_count: %zu",
             __func__, data->timeout_count);
    return G_SOURCE_CONTINUE;
}
/*
 */
gboolean
create_primary_callback (gint fd,
                         GIOCondition condition,
                         gpointer user_data)
{
    data_t *data = (data_t*)user_data;
    TSS2_RC rc;
    TPM2_HANDLE handle;
    TPM2B_PUBLIC out_public = { 0 };
    TPM2B_CREATION_DATA creation_data = { 0 };
    TPM2B_DIGEST creation_digest = { 0 };
    TPMT_TK_CREATION creation_ticket = { 0 };
    TPM2B_NAME name = {
        .size = sizeof (TPM2B_DIGEST) - sizeof (UINT16)
    };

    g_debug ("%s", __func__);
    rc = Tss2_Sys_ExecuteFinish (data->sys_ctx, 0);
    rc = Tss2_Sys_CreatePrimary_Complete (data->sys_ctx,
                                          &handle,
                                          &out_public,
                                          &creation_data,
                                          &creation_digest,
                                          &creation_ticket,
                                          &name);
    data->done = TRUE;
    return G_SOURCE_REMOVE;
}
/*
 * Parse command line options using GOptions.
 */
void
parse_opts (int argc,
            char *argv[],
            opts_t *opts)
{
    GOptionContext *ctx;
    GError *err = NULL;
    GOptionEntry entries[] = {
        {
            .long_name = "tcti-name",
            .short_name = 't',
            .flags = G_OPTION_FLAG_NONE,
            .arg = G_OPTION_ARG_STRING,
            .arg_data = &opts->tcti_name,
            .description = "name of TCTI library, located using search "
                "rules from dlopen",
            .arg_description = "device",
        },
        {
            .long_name = "tcti-conf",
            .short_name = 'c',
            .flags = G_OPTION_FLAG_NONE,
            .arg = G_OPTION_ARG_STRING,
            .arg_data = &opts->tcti_conf,
            .description = "configuration string for TCTI",
            .arg_description = "/dev/tpm0",
        },
        { NULL, '\0', 0, 0, NULL, NULL, NULL },
    };

    ctx = g_option_context_new (" - GIO & TSS2 async event demo");
    g_option_context_add_main_entries (ctx, entries, NULL);
    if (!g_option_context_parse (ctx, &argc, &argv, &err)) {
        g_critical ("Failed to parse options: &s", err->message);
    }
    g_option_context_free (ctx);
}
/*
 * Get FD to poll from TCTI, create GSource for use with GMainLoop.
 */
GSource*
setup_tcti_gsource (TSS2_TCTI_CONTEXT *tcti_ctx)
{
    TSS2_RC rc;
    TSS2_TCTI_POLL_HANDLE poll_handles[1];
    size_t poll_handle_count;

    /* get fds to poll for I/O events */
    rc = Tss2_Tcti_GetPollHandles (tcti_ctx,
                                   poll_handles,
                                   &poll_handle_count);
    g_assert (rc == TSS2_RC_SUCCESS);
    g_assert (poll_handle_count == 1);
    /* is this the default? */
    if (!g_unix_set_fd_nonblocking (poll_handles[0].fd, TRUE, NULL)) {
        g_error ("failed to set fd %d to non-blocking", poll_handles[0].fd);
    }

    /* setup GLib source to monitor this fd */
    return g_unix_fd_source_new (poll_handles[0].fd, G_IO_IN);
}
/*
 * cleanup objects held in data_t
 */
void
cleanup (data_t *data)
{
    if (data->loop != NULL)
        g_main_loop_unref (data->loop);
    if (data->sys_ctx) {
        Tss2_Sys_Finalize (data->sys_ctx);
        g_free (data->sys_ctx);
    }
    if (data->tcti_ctx) {
        Tss2_Tcti_Finalize (data->tcti_ctx);
        g_free (data->tcti_ctx);
    }
    if (data->tcti_dl_handle) {
        dlclose (data->tcti_dl_handle);
    }
}
/*
 * Create primary key in NULL hierarchy. Key will be RSA 2k.
 */
TSS2_RC
create_primary_async (TSS2_SYS_CONTEXT *sys_ctx)
{
    TSS2_RC rc;
    TPM2B_SENSITIVE_CREATE in_sensitive = { 0 };
    /* structure describing the key being created */
    TPM2B_PUBLIC in_public = {
        .publicArea.type = TPM2_ALG_RSA,
        .publicArea.nameAlg = TPM2_ALG_SHA256,
        .publicArea.nameAlg = TPM2_ALG_SHA256,
        .publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM | \
            TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN | \
            TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED | \
            TPMA_OBJECT_DECRYPT,
        .publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES,
        .publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128,
        .publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB,
        .publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL,
        .publicArea.parameters.rsaDetail.keyBits = 2048,
    };
    TPM2B_DATA outside_info = { 0 };
    TPML_PCR_SELECTION creation_pcr = { 0 };
    TSS2L_SYS_AUTH_COMMAND cmd_auths = {
        .count = 1,
        .auths = {{
            .sessionHandle = TPM2_RS_PW,
        }}
    };

    g_debug ("%s", __func__);
    rc = Tss2_Sys_CreatePrimary_Prepare (sys_ctx,
                                         TPM2_RH_NULL,
                                         &in_sensitive,
                                         &in_public,
                                         &outside_info,
                                         &creation_pcr);
    if (rc != TSS2_RC_SUCCESS) {
        g_critical ("Tss2_Sys_CreatePrimary returned: 0x%" PRIx32, rc);
    }
    rc = Tss2_Sys_SetCmdAuths (sys_ctx, &cmd_auths);
    if (rc != TSS2_RC_SUCCESS) {
        g_critical ("Tss2_Sys_SetCmdAuths returned: 0x%" PRIx32, rc);
    }
    rc = Tss2_Sys_ExecuteAsync (sys_ctx);
    if (rc != TSS2_RC_SUCCESS) {
        g_critical ("Tss2_Sys_ExecuteAsync returned: 0x%" PRIx32, rc);
    }

    return rc;
}
/*
 * setup timer source / callback & attach to provided context
 */
void
create_timer_event (GMainContext *context,
                    GSourceFunc callback,
                    data_t *data)
{
    GSource *source;

    source = g_timeout_source_new (100);
    g_source_set_callback (source, callback, data, NULL);
    g_source_attach (source, context);
    g_source_unref (source);
}
/*
 * setup source / callback for TCTI & attach to provided contexti
 */
void
create_tss2_event (GMainContext *context,
                   GSourceFunc callback,
                   data_t *data)
{
    GSource *source;

    source = setup_tcti_gsource (data->tcti_ctx);
    g_assert (source != NULL);
    g_source_attach (source, context);
    g_source_set_callback (source, callback, data, NULL);
    g_source_unref (source);
}
/*
 * Initialize data_t from command line options / arguments in opts_t
 */
TSS2_RC
tcti_init (opts_t *opts,
           data_t *data)
{
    const TSS2_TCTI_INFO *info;
    TSS2_RC rc;

    rc = tcti_get_info (opts->tcti_name, &info, &data->tcti_dl_handle);
    if (rc != TSS2_RC_SUCCESS) {
        return rc;
    }
    return tcti_init_from_info (info, opts->tcti_conf, &data->tcti_ctx);
}
int
main (int argc,
      char *argv[])
{
    GMainContext *context;
    TSS2_RC rc;
    data_t data = { 0 };
    opts_t opts = OPTS_T_DEFAULT;

    parse_opts (argc, argv, &opts);
    context = g_main_context_new ();
    create_timer_event (context, timer_callback, &data);
    rc = tcti_init (&opts, &data);
    g_assert (rc == TSS2_RC_SUCCESS);
    data.sys_ctx = sys_init_from_tcti (data.tcti_ctx);
    g_assert (data.sys_ctx != NULL);
    create_tss2_event (context, (GSourceFunc)create_primary_callback, &data);
    data.loop = g_main_loop_new (context, FALSE);
    g_main_context_unref (context);
    rc = create_primary_async (data.sys_ctx);
    g_assert (rc == TSS2_RC_SUCCESS);
    g_main_loop_run (data.loop);
    g_print ("Created primary RSA 2k key in %.1f seconds\n",
             (float)data.timeout_count / 10);
    cleanup (&data);
    return 0;
}
