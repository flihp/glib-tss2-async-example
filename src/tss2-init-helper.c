/*
 * Copyright (c) 2018, Intel Corporation
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <dlfcn.h>
#include <errno.h>
#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_tcti.h>

#include "tss2-init-helper.h"

/*
 * This function does all the dl* magic required to get a reference to a TCTI
 * modules TSS2_TCTI_INFO structure. A successful call will return
 * TSS2_RC_SUCCESS, a reference to the info structure in the 'info' parameter
 * and a reference to the dlhandle returned by dlopen. The caller will need
 * to close this handle after they're done using the TCTI.
 */
TSS2_RC
tcti_get_info (const char *filename,
               const TSS2_TCTI_INFO **info,
               void **tcti_dl_handle)
{
    TSS2_TCTI_INFO_FUNC info_func;
    gchar filename_xfrm [PATH_MAX];
    size_t size;

    g_debug ("%s", __func__);
    *tcti_dl_handle = dlopen (filename, RTLD_LAZY);
    if (*tcti_dl_handle == NULL) {
        size = snprintf (filename_xfrm,
                         sizeof (filename_xfrm),
                         "libtss2-tcti-%s.so.0",
                         filename);
        if (size >= sizeof (filename_xfrm)) {
            g_critical ("TCTI name truncated in transform.");
            return TSS2_TCTI_RC_BAD_VALUE;
        }
        g_debug ("dlopen failed on \"%s\", trying \"%s\"",
                 filename, filename_xfrm);
        *tcti_dl_handle = dlopen (filename_xfrm, RTLD_LAZY);
        if (*tcti_dl_handle == NULL) {
            g_warning ("failed to dlopen library: %s", filename);
            return TSS2_TCTI_RC_BAD_VALUE;
        }
    }
    info_func = dlsym (*tcti_dl_handle, TSS2_TCTI_INFO_SYMBOL);
    if (info_func == NULL) {
        g_warning ("Failed to get reference to symbol: %s", dlerror ());
        dlclose (*tcti_dl_handle);
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    *info = info_func ();
    return TSS2_RC_SUCCESS;
}
/*
 * This function allocates and initializes a TCTI context structure using the
 * initialization function in the provide 'info' parameter according to the
 * provided configuration string. The caller must deallocate the reference
 * returned in the 'context' parameter when TSS2_RC_SUCCESS is returned.
 */
TSS2_RC
tcti_init_from_info (const TSS2_TCTI_INFO *info,
                     const char *conf,
                     TSS2_TCTI_CONTEXT **context)
{
    TSS2_RC        rc       = TSS2_RC_SUCCESS;
    size_t         ctx_size;

    g_debug ("%s", __func__);
    if (info == NULL || info->init == NULL) {
        g_warning ("%s: TCTI_INFO structure or init function pointer is NULL, "
                   "cannot initialize context.", __func__);
        return TSS2_TCTI_RC_BAD_VALUE;
    }
    rc = info->init (NULL, &ctx_size, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        g_warning ("failed to get size for device TCTI context structure: "
                   "0x%x", rc);
        goto out;
    }
    *context = g_malloc0 (ctx_size);
    if (*context == NULL) {
        g_warning ("failed to allocate memory");
        rc = TSS2_TCTI_RC_GENERAL_FAILURE;
        goto out;
    }
    rc = info->init (*context, &ctx_size, conf);
    if (rc != TSS2_RC_SUCCESS) {
        g_warning ("failed to initialize device TCTI context: 0x%x", rc);
        g_free (*context);
        *context = NULL;
    }
out:
    return rc;
}

TSS2_SYS_CONTEXT*
sys_init_from_tcti (TSS2_TCTI_CONTEXT *tcti_ctx)
{
    TSS2_SYS_CONTEXT *sapi_ctx;
    TSS2_RC rc;
    size_t size;
    TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;

    g_debug ("%s", __func__);
    size = Tss2_Sys_GetContextSize (0);
    g_debug ("TSS2 SYS context size: %zu", size);
    sapi_ctx = (TSS2_SYS_CONTEXT*)calloc (1, size);
    if (sapi_ctx == NULL) {
        g_critical ("Failed to allocate 0x%zx bytes for the SAPI contextn",
                    size);
        return NULL;
    }
    rc = Tss2_Sys_Initialize (sapi_ctx, size, tcti_ctx, &abi_version);
    if (rc != TSS2_RC_SUCCESS) {
        g_critical ("Failed to initialize SAPI context: 0x%xn", rc);
        free (sapi_ctx);
        return NULL;
    }
    return sapi_ctx;
}
