/*
 * Copyright (c) 2018, Intel Corporation
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2-tcti-tabrmd.h>

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
               void **tcti_dl_handle);
/*
 * This function allocates and initializes a TCTI context structure using the
 * initialization function in the provide 'info' parameter according to the
 * provided configuration string. The caller must deallocate the reference
 * returned in the 'context' parameter when TSS2_RC_SUCCESS is returned.
 */
TSS2_RC
tcti_init_from_info (const TSS2_TCTI_INFO *info,
                     const char *conf,
                     TSS2_TCTI_CONTEXT **context);

/*
 * Allocate and initialize an instance of a SAPI context. This context will be
 * configured to use the provided TCTI context. A successful call to this
 * function will return a SAPI context allocated by the function. It must be
 * freed by the caller.
 * A failed call to this function will return NULL.
 */
TSS2_SYS_CONTEXT*
sys_init_from_tcti (TSS2_TCTI_CONTEXT *tcti_ctx);
