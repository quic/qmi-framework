// Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef QCCI_OS_H
#define QCCI_OS_H
/**
 * @file qcci_os.h
 *
 * @brief QMI CCI OS-specific utilities.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sys/time.h>
#include <stdarg.h>

#if defined(__GLIBC__)
#include <endian.h>
#elif defined(__ANDROID__)
#include <sys/endian.h>
#endif

/** QMI CCI lock type */
typedef pthread_mutex_t qcci_os_lock_type;

/** Initialize the OS lock */
#define QCCI_OS_LOCK_INIT(ptr)

/** Deinitialize the OS lock */
#define QCCI_OS_LOCK_DEINIT(ptr) pthread_mutex_destroy(ptr)

/** Lock the OS lock */
#define QCCI_OS_LOCK(ptr) pthread_mutex_lock(ptr)

/** Unlock the OS lock */
#define QCCI_OS_UNLOCK(ptr) pthread_mutex_unlock(ptr)

/** Allocate memory */
#define QCCI_OS_MALLOC malloc

/** Allocate and zero-initialize memory */
#define QCCI_OS_CALLOC calloc

/** Free allocated memory */
#define QCCI_OS_FREE(ptr) \
	do { \
		free(ptr); \
		ptr = NULL; \
	} while(0)

#define QCCI_OS_UNUSED_PARAM(param) \
	do{ \
		param = param; \
	} while(0)



typedef enum {
    QCCI_LOG_NONE = 0,
    QCCI_LOG_ERR,
    QCCI_LOG_WARN,
    QCCI_LOG_INFO,
    QCCI_LOG_DBG,
    QCCI_LOG_TRACE,
} qcci_log_level_t;

extern int qcci_loglevel;

void qcci_log_write(qcci_log_level_t lvl, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define QCCI_LOG_ERR(fmt, ...)   qcci_log_write(QCCI_LOG_ERR,   "QCCI: " fmt, ##__VA_ARGS__)
#define QCCI_LOG_WARN(fmt, ...)  qcci_log_write(QCCI_LOG_WARN,  "QCCI: " fmt, ##__VA_ARGS__)
#define QCCI_LOG_INFO(fmt, ...)  qcci_log_write(QCCI_LOG_INFO,  "QCCI: " fmt, ##__VA_ARGS__)
#define QCCI_LOG_DBG(fmt, ...)   qcci_log_write(QCCI_LOG_DBG,   "QCCI: " fmt, ##__VA_ARGS__)
#define QCCI_LOG_TRACE(fmt, ...) qcci_log_write(QCCI_LOG_TRACE, "QCCI: " fmt, ##__VA_ARGS__)

/**
 * @brief Macro for logging transmitted messages.
 */
#define QCCI_LOG_TX_PKT(svc_obj, cntl_flag, txn_id, msg_id, \
			msg_len, addr, addr_len) \
  do { \
    QCCI_LOG_DBG("QMI_CCI_TX: cntl_flag - %02x, txn_id - %04x, "\
		"msg_id - %04x, msg_len - %04x, svc_id - %08x\n", \
		cntl_flag, txn_id, msg_id, msg_len, (svc_obj)->service_id); \
  } while(0)

/**
 * @brief Macro for logging received messages.
 */
#define QCCI_LOG_RX_PKT(svc_obj, cntl_flag, txn_id, msg_id, \
			msg_len, addr, addr_len) \
  do { \
    QCCI_LOG_DBG("QMI_CCI_RX: cntl_flag - %02x, txn_id - %04x, " \
		"msg_id - %04x, msg_len - %04x, svc_id - %08x\n", \
                 cntl_flag, txn_id, msg_id, msg_len, (svc_obj)->service_id); \
  } while(0)

/**
 * @brief Convert CPU byte order to little-endian.
 *
 * @param x Value to convert.
 * @return Converted value.
 */
static inline uint32_t qcci_os_cpu_to_le32(uint32_t x)
{
	return htole32(x);
}

/**
 * @brief Convert little-endian byte order to CPU byte order.
 *
 * @param x Value to convert.
 * @return Converted value.
 */
static inline uint32_t qcci_os_le32_to_cpu(uint32_t x)
{
	return le32toh(x);
}

#endif
