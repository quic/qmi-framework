// Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef QMI_CSI_TARGET_EXT_H
#define QMI_CSI_TARGET_EXT_H

#include <pthread.h>
#include <sys/select.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QMI_NO_ERR 0

#define QMI_CSI_OS_SIGNAL_INIT(ptr) \
	do { \
		(ptr)->sig_set = 0; \
		pthread_mutex_init(&(ptr)->mutex, NULL); \
		pthread_cond_init(&(ptr)->cond, NULL); \
	} while(0)
#define QMI_CSI_OS_SIGNAL_CLEAR(ptr) (ptr)->sig_set = 0
#define QMI_CSI_OS_SIGNAL_SET(ptr)  \
	do { \
		pthread_mutex_lock(&(ptr)->mutex); \
		(ptr)->sig_set = 1; \
		pthread_cond_signal(&(ptr)->cond); \
		pthread_mutex_unlock(&(ptr)->mutex); \
	} while(0)
#define QMI_CSI_OS_SIGNAL_WAIT(ptr) \
	do { \
		pthread_mutex_lock(&(ptr)->mutex); \
		while(!(ptr)->sig_set) \
			pthread_cond_wait(&(ptr)->cond, &(ptr)->mutex); \
		pthread_mutex_unlock(&(ptr)->mutex); \
	} while(0)

#define QMI_CSI_OS_PARAMS_PROLOG(svc, params) \
	do { \
		FD_ZERO(&params->fds); \
		params->max_fd = 0; \
	} while (0)
typedef struct {
	fd_set fds;
	int    max_fd;
} qcsi_os_params;

#ifdef __cplusplus
}
#endif
#endif
