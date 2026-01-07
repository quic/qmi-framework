// Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef qcsi_OS_H
#define qcsi_OS_H
/**
 * @file qcsi_os.h
 *
 * @brief QMI CSI OS-specific utilities.
 */
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <strings.h>
#include <sys/select.h>
#include "qmi_idl_lib_internal.h"

#if defined(__GLIBC__)
#include <endian.h>
#elif defined(__ANDROID__)
#include <sys/endian.h>
#endif

/** QMI CSI lock type */
typedef pthread_mutex_t qcsi_lock_type;

/** Initialize the lock */
#define LOCK_INIT(ptr) \
	do { \
		pthread_mutexattr_t   mta; \
		pthread_mutexattr_init(&mta);  \
		pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_RECURSIVE); \
		pthread_mutex_init(ptr, &mta); \
		pthread_mutexattr_destroy(&mta);  \
	} while(0)

/** Deinitialize the lock */
#define LOCK_DEINIT(ptr) pthread_mutex_destroy(ptr)

/** Lock the mutex */
#define LOCK(ptr) pthread_mutex_lock(ptr)

/** Unlock the mutex */
#define UNLOCK(ptr) pthread_mutex_unlock(ptr)

/** Allocate memory */
#define MALLOC malloc

/** Allocate and zero-initialize memory */
#define CALLOC calloc

/** Free allocated memory */
#define FREE free

typedef enum {
    QCSI_LOG_NONE = 0,
    QCSI_LOG_ERR,
    QCSI_LOG_WARN,
    QCSI_LOG_INFO,
    QCSI_LOG_DBG,
    QCSI_LOG_TRACE,
} qcsi_log_level_t;

extern int qcsi_loglevel;

void qcsi_log_write(qcsi_log_level_t lvl, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define QCSI_LOG_ERR(fmt, ...)   qcsi_log_write(QCSI_LOG_ERR,   "QCSI: " fmt, ##__VA_ARGS__)
#define QCSI_LOG_WARN(fmt, ...)  qcsi_log_write(QCSI_LOG_WARN,  "QCSI: " fmt, ##__VA_ARGS__)
#define QCSI_LOG_INFO(fmt, ...)  qcsi_log_write(QCSI_LOG_INFO,  "QCSI: " fmt, ##__VA_ARGS__)
#define QCSI_LOG_DBG(fmt, ...)   qcsi_log_write(QCSI_LOG_DBG,   "QCSI: " fmt, ##__VA_ARGS__)
#define QCSI_LOG_TRACE(fmt, ...) qcsi_log_write(QCSI_LOG_TRACE, "QCSI: " fmt, ##__VA_ARGS__)

/**
 * @brief Macro for logging transmitted messages.
 */
#define QCSI_LOG_TX_PKT(svc_obj, cntl_flag, txn_id, msg_id, \
			msg_len, addr, addr_len) \
  do { \
    QCSI_LOG_DBG("QMI_CSI_TX: cntl_flag - %02x, txn_id - %04x, "\
		"msg_id - %04x, msg_len - %04x, svc_id - %08x\n", \
		cntl_flag, txn_id, msg_id, msg_len, (svc_obj)->service_id); \
  } while(0)

/**
 * @brief Macro for logging received messages.
 */
#define QCSI_LOG_RX_PKT(svc_obj, cntl_flag, txn_id, msg_id, \
			msg_len, addr, addr_len) \
  do { \
    QCSI_LOG_DBG("QMI_CSI_RX: cntl_flag - %02x, txn_id - %04x, " \
		"msg_id - %04x, msg_len - %04x, svc_id - %08x\n", \
                 cntl_flag, txn_id, msg_id, msg_len, (svc_obj)->service_id); \
  } while(0)


/**
 * @brief Convert CPU byte order to little-endian.
 *
 * @param x Value to convert.
 * @return Converted value.
 */
static inline uint32_t qcsi_os_cpu_to_le32(uint32_t x)
{
	return htole32(x);
}

/**
 * @brief Convert little-endian byte order to CPU byte order.
 *
 * @param x Value to convert.
 * @return Converted value.
 */
static inline uint32_t qcsi_os_le32_to_cpu(uint32_t x)
{
	return le32toh(x);
}

#endif
