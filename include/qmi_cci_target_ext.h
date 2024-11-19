// Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef QMI_CCI_TARGET_EXT_H
#define QMI_CCI_TARGET_EXT_H

#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t sig_set;
	uint32_t timed_out;
	uint32_t clock;
	pthread_cond_t cond;
	pthread_condattr_t attr;
	pthread_mutex_t mutex;
} qmi_cci_os_signal_type;

typedef qmi_cci_os_signal_type qmi_client_os_params;

#define QMI_CCI_OS_SIGNAL qmi_cci_os_signal_type

void qcci_os_signal_init(
	QMI_CCI_OS_SIGNAL *ptr,
	qmi_client_os_params *os_params);

#define QMI_CCI_OS_SIGNAL_INIT(ptr, os_params) qcci_os_signal_init(ptr, os_params)

void qcci_os_signal_deinit(QMI_CCI_OS_SIGNAL *ptr);
#define QMI_CCI_OS_SIGNAL_DEINIT(ptr) qcci_os_signal_deinit(ptr)

#define QMI_CCI_OS_EXT_SIGNAL_INIT(ptr, os_params) \
	do { \
		ptr = os_params; \
		QMI_CCI_OS_SIGNAL_INIT(ptr, NULL); \
	} while(0)

#define QMI_CCI_OS_SIGNAL_CLEAR(ptr) (ptr)->sig_set = 0

void qcci_os_signal_wait(QMI_CCI_OS_SIGNAL *ptr, unsigned int timeout_ms);
#define QMI_CCI_OS_SIGNAL_WAIT qcci_os_signal_wait

#define QMI_CCI_OS_SIGNAL_TIMED_OUT(ptr) (ptr)->timed_out
#define QMI_CCI_OS_SIGNAL_SET(ptr)  \
	do { \
		pthread_mutex_lock(&(ptr)->mutex); \
		(ptr)->sig_set = 1; \
		pthread_cond_signal(&(ptr)->cond); \
		pthread_mutex_unlock(&(ptr)->mutex); \
	} while(0)

#ifdef __cplusplus
}
#endif
#endif
