// Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
/**
 * @file    qcsi_os.c
 * @brief   The QMI common service interface os specific module
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "qcsi_common.h"
#include "config.h"
#include "qcsi_os.h"

#ifdef __ANDROID__
#include <android/log.h>
#else
#include <syslog.h>
#endif

#define QMI_FW_CONF_FILE "/etc/qmi_fw.conf"

#define MAX_LINE_LENGTH 80

extern qcsi_xport_ops_type qcsi_qrtr_ops;

int qcsi_loglevel = QCSI_LOG_ERR;

static void qcsi_set_loglevel(const char *val)
{
    if (!val || !*val)
        return;

    if (!strcasecmp(val, "NONE"))
        qcsi_loglevel = QCSI_LOG_NONE;
    else if (!strcasecmp(val, "ERR"))
        qcsi_loglevel = QCSI_LOG_ERR;
    else if (!strcasecmp(val, "WARN"))
        qcsi_loglevel = QCSI_LOG_WARN;
    else if (!strcasecmp(val, "INFO"))
        qcsi_loglevel = QCSI_LOG_INFO;
    else if (!strcasecmp(val, "DBG"))
        qcsi_loglevel = QCSI_LOG_DBG;
    else if (!strcasecmp(val, "TRACE"))
        qcsi_loglevel = QCSI_LOG_TRACE;
}

static void qcsi_log_init_once(void)
{
    static int init;
    if (init)
        return;


	FILE *f = fopen(QMI_FW_CONF_FILE, "r");
    if (f) {
        char line[MAX_LINE_LENGTH];

        while (fgets(line, sizeof(line), f)) {
            char *p = line;
            while (*p && isspace((unsigned char)*p))
                p++;

            const char *key = "QMI_LOG_LEVEL=";
            size_t key_len = strlen(key);

            if (!strncmp(p, key, key_len)) {
                char *val = p + key_len;

                char *end = val + strlen(val);
                while (end > val && isspace((unsigned char)end[-1]))
                    *--end = '\0';

                qcsi_set_loglevel(val);
                break; 
            }
        }

        fclose(f);
    }

    const char *env = getenv("QMI_LOG_LEVEL");
    if (env) {
        qcsi_set_loglevel(env);
    }

#ifndef __ANDROID__
    openlog("qcsi", LOG_PID, LOG_USER);
#endif
    init = 1;
}

void qcsi_log_write(qcsi_log_level_t lvl, const char *fmt, ...)
{

    if (lvl > qcsi_loglevel)
        return;

    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

#ifdef __ANDROID__
    int pr = ANDROID_LOG_DEBUG;
    if (lvl == QCSI_LOG_ERR) pr = ANDROID_LOG_ERROR;
    else if (lvl == QCSI_LOG_WARN) pr = ANDROID_LOG_WARN;
    else if (lvl == QCSI_LOG_INFO) pr = ANDROID_LOG_INFO;
    __android_log_print(pr, "QMI_OS", "%s", buf);
#else
    int pr = LOG_DEBUG;
    if (lvl == QCSI_LOG_ERR) pr = LOG_ERR;
    else if (lvl == QCSI_LOG_WARN) pr = LOG_WARNING;
    else if (lvl == QCSI_LOG_INFO) pr = LOG_INFO;
    syslog(pr, "QMI_OS: %s", buf);
#endif
}


/**
 * @brief Initialize the QCSI library.
 *
 * This function is called when the QCSI shared library is loaded, before the
 * application's main() is started.
 *
 * @dependencies None
 * @arguments None
 * @return None
 * @sideeffects None
 */
#ifdef __GNUC__
void __attribute__ ((constructor)) qcsi_fw_init(void)
{
	qcsi_log_init_once();
	qcsi_init(&qcsi_qrtr_ops, NULL);
}
#endif

/**
 * @brief Cleans up the QCSI library.
 *
 * This function is called after exit() or after the application's main()
 * completes.
 *
 * @dependencies None
 * @arguments None
 * @return None
 * @sideeffects None
 */
#ifdef __GNUC__
void __attribute__ ((destructor)) qcsi_fw_deinit(void)
{
	qcsi_deinit();
}
#endif
