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

/**
 * @brief Macros for logging.
 */
#if defined(QMI_FW_ADB_LOG) || defined(QMI_ANDROID_LOGGING_LE)
#define LOG_TAG "QMI_FW"

#ifdef QMI_ANDROID_LOGGING_LE
#include <cutils/log.h>
#else
#include <utils/Log.h>
#endif

#ifdef QMI_CCI_ANDROID
extern unsigned int qcci_debug_level;
#define QCCI_LOG_INFO(x...) do { \
		if (qcci_debug_level <= ANDROID_LOG_INFO) \
			SLOGI("QCCI: "x); \
	} while(0)
#define QCCI_LOG_DBG(x...) do { \
		if (qcci_debug_level <= ANDROID_LOG_DEBUG) \
			SLOGD("QCCI: "x); \
	} while(0)
#else
#define QCCI_LOG_INFO(x...)
#define QCCI_LOG_DBG(x...)
#endif

#define QCCI_LOG_ERR(x...) ALOGE(x);

#elif defined(QMI_FW_SYSLOG)
#include <syslog.h>

extern unsigned int qcci_debug_level;
#define QCCI_LOG_INFO(x...) do { \
		if (qcci_debug_level >= LOG_INFO) \
			syslog(LOG_INFO, "QMI_FW: QCCI: "x); \
	} while(0)
#define QCCI_LOG_DBG(x...) do { \
		if (qcci_debug_level >= LOG_DEBUG) \
			syslog(LOG_DEBUG, "QMI_FW: QCCI: "x); \
	} while(0)

#define QCCI_LOG_ERR(x...)  syslog(LOG_ERR, x)

#else
#define QCCI_LOG_INFO(x...) do { \
		fprintf(stdout, "%s(%d) ", __FUNCTION__, __LINE__); \
		fprintf(stdout, ##x);                               \
	} while(0)

#define QCCI_LOG_DBG(x...) do { \
		fprintf(stdout, "%s(%d) ", __FUNCTION__, __LINE__); \
		fprintf(stdout, ##x);                               \
	} while(0)

#define QCCI_LOG_ERR(x...) do { \
		fprintf(stderr, "%s(%d) ", __FUNCTION__, __LINE__); \
		fprintf(stderr, ##x);                               \
	} while(0)
#endif

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
