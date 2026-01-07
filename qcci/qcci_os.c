// Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
/**
 * @file    qcci_os.c
 * @brief   The QMI common client interface target specific module
 */
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include "qmi_cci.h"
#include "qcci_os.h"
#include "qcci_common.h"
#include "config.h"

#define QMI_FW_CONF_FILE "/etc/qmi_fw.conf"

#define MAX_LINE_LENGTH 80

extern qcci_xport_ops_type qcci_qrtr_ops;
extern void qcci_xport_qrtr_deinit(void);


#ifdef __ANDROID__
#include <android/log.h>
#else
#include <syslog.h>
#endif

int qcci_loglevel = QCCI_LOG_ERR;

static void qcci_set_loglevel(const char *val)
{
    if (!val || !*val)
        return;

    if (!strcasecmp(val, "NONE"))
        qcci_loglevel = QCCI_LOG_NONE;
    else if (!strcasecmp(val, "ERR"))
        qcci_loglevel = QCCI_LOG_ERR;
    else if (!strcasecmp(val, "WARN"))
        qcci_loglevel = QCCI_LOG_WARN;
    else if (!strcasecmp(val, "INFO"))
        qcci_loglevel = QCCI_LOG_INFO;
    else if (!strcasecmp(val, "DBG"))
        qcci_loglevel = QCCI_LOG_DBG;
    else if (!strcasecmp(val, "TRACE"))
        qcci_loglevel = QCCI_LOG_TRACE;
}

static void qcci_log_init_once(void)
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

                qcci_set_loglevel(val);
                break; 
            }
        }

        fclose(f);
    }

    const char *env = getenv("QMI_LOG_LEVEL");
    if (env) {
        qcci_set_loglevel(env);
    }

#ifndef __ANDROID__
    openlog("qcci", LOG_PID, LOG_USER);
#endif
    init = 1;
}

void qcci_log_write(qcci_log_level_t lvl, const char *fmt, ...)
{

    if (lvl > qcci_loglevel)
        return;

    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

#ifdef __ANDROID__
    int pr = ANDROID_LOG_DEBUG;
    if (lvl == QCCI_LOG_ERR) pr = ANDROID_LOG_ERROR;
    else if (lvl == QCCI_LOG_WARN) pr = ANDROID_LOG_WARN;
    else if (lvl == QCCI_LOG_INFO) pr = ANDROID_LOG_INFO;
    __android_log_print(pr, "QMI_OS", "%s", buf);
#else
    int pr = LOG_DEBUG;
    if (lvl == QCCI_LOG_ERR) pr = LOG_ERR;
    else if (lvl == QCCI_LOG_WARN) pr = LOG_WARNING;
    else if (lvl == QCCI_LOG_INFO) pr = LOG_INFO;
    syslog(pr, "QMI_OS: %s", buf);
#endif
}


/**
 * @brief Initialize the QCCI library.
 *
 * This function is called when the QCCI shared library is loaded, before the
 * application's main() is started.
 *
 * @dependencies None
 * @arguments None
 * @return None
 * @sideeffects None
 */
#ifdef __GNUC__
void __attribute__ ((constructor)) qcci_fw_init(void)
{
	qcci_log_init_once();
	qcci_init(&qcci_qrtr_ops, NULL);
}
#endif

/**
 * @brief Cleans up the QCCI library.
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
void __attribute__ ((destructor)) qcci_fw_deinit(void)
{
	qcci_xport_qrtr_deinit();
	qcci_deinit();
}
#endif

/**
 * @brief Initializes a signal.
 *
 * @param[in] ptr Pointer to the QMI_CCI_OS_SIGNAL structure.
 * @param[in] os_params OS param.
 */
void qcci_os_signal_init(
	QMI_CCI_OS_SIGNAL *ptr,
	qmi_client_os_params *os_params)
{
	int rc;

	QCCI_OS_UNUSED_PARAM(os_params);

	ptr->sig_set = 0;
	ptr->timed_out = 0;
	pthread_condattr_init(&ptr->attr);
	rc = pthread_condattr_setclock(&ptr->attr, CLOCK_MONOTONIC);
	if(!rc)
	{
		rc = pthread_cond_init(&ptr->cond, &ptr->attr);
		if(!rc)
		{
			ptr->clock = CLOCK_MONOTONIC;
		}
		else
		{
			pthread_cond_init(&ptr->cond, NULL);
			ptr->clock = CLOCK_REALTIME;
		}
	}
	else
	{
		pthread_cond_init(&ptr->cond, NULL);
		ptr->clock = CLOCK_REALTIME;
	}
	pthread_mutex_init(&ptr->mutex, NULL);
}

/**
 * @brief De-initializes a signal.
 *
 * @param[in] ptr Pointer to the QMI_CCI_OS_SIGNAL structure.
 */
void qcci_os_signal_deinit(QMI_CCI_OS_SIGNAL *ptr)
{
	ptr->sig_set = 0;
	ptr->timed_out = 0;
	pthread_condattr_destroy(&ptr->attr);
	pthread_cond_destroy(&ptr->cond);
	pthread_mutex_destroy(&ptr->mutex);
}

/**
 * @brief Wait for a signal with a timeout.
 *
 * This function waits for a signal with a specified timeout.
 *
 * @param[in] ptr Pointer to the QMI_CCI_OS_SIGNAL structure.
 * @param[in] timeout_ms Timeout in milliseconds.
 */
void qcci_os_signal_wait(QMI_CCI_OS_SIGNAL *ptr, unsigned int timeout_ms)
{
	ptr->timed_out = 0;
	if(timeout_ms) {
		int rc = 0;
		struct timeval tv = {0};
		struct timespec ts = {0};
		if (ptr->clock == CLOCK_MONOTONIC) {
			clock_gettime(CLOCK_MONOTONIC, &ts);
			ts.tv_sec = ts.tv_sec + timeout_ms / 1000;
			ts.tv_nsec = ts.tv_nsec + (timeout_ms % 1000) * 1000 * 1000;
		} else {
			gettimeofday(&tv, NULL);
			ts.tv_sec = tv.tv_sec + timeout_ms / 1000;
			ts.tv_nsec = tv.tv_usec * 1000 + (timeout_ms % 1000) * 1000 * 1000;
		}
		if (ts.tv_nsec >= 1000000000) {
			ts.tv_sec++;
			ts.tv_nsec = (ts.tv_nsec % 1000000000);
		}
		pthread_mutex_lock(&ptr->mutex);
		while(!ptr->sig_set) {
			rc = pthread_cond_timedwait(&ptr->cond, &ptr->mutex, &ts);
			if(rc == ETIMEDOUT) {
				ptr->timed_out = 1;
				break;
			}
		}
		pthread_mutex_unlock(&ptr->mutex);
	} else {
		pthread_mutex_lock(&ptr->mutex);
		while(!ptr->sig_set)
			pthread_cond_wait(&ptr->cond, &ptr->mutex);
		pthread_mutex_unlock(&ptr->mutex);
	}
}

