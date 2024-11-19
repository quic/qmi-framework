// Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
/**
 * @file    qcci_os.c
 * @brief   The QMI common client interface target specific module
 */
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include "qmi_client.h"
#include "qcci_os.h"
#include "qcci_internal.h"
#include "config.h"

#ifdef QMI_FW_SYSLOG
	#define QCCI_DEFAULT_DBG_LEVEL 4
#else
	#define QCCI_DEFAULT_DBG_LEVEL 5
#endif

#ifdef QMI_CCI_SYSTEM
	#define QMI_FW_CONF_FILE "/etc/qmi_fw.conf"
#else
	#define QMI_FW_CONF_FILE "/vendor/etc/qmi_fw.conf"
#endif

#define MAX_LINE_LENGTH 80
#define QCCI_DBG_CONF_STR "QMI_CCI_DEBUG_LEVEL="

extern qcci_xport_ops_type qcci_qrtr_ops;
extern void qcci_xport_qrtr_deinit(void);


unsigned int qcci_debug_level;

/**
 * @brief Debug level init.
 *
 */
#if defined(QMI_FW_ANDROID) || defined(QMI_FW_SYSLOG) || defined(QMI_ANDROID_LOGGING_LE)
static void qcci_debug_init(void)
{
    qcci_debug_level = QCCI_DEBUG_LEVEL;
}
#else
static void qcci_debug_init(void)
{
}
#endif /* QMI_FW_ANDROID) || QMI_FW_SYSLOG */

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
	qcci_debug_init();
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

