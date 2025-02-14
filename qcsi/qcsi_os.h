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

/**
 * @brief Macros for logging.
 */
#if defined(QMI_FW_ADB_LOG) || defined(QMI_ANDROID_LOGGING_LE)
#define LOG_TAG "QMI_OS_FW"

#ifdef QMI_ANDROID_LOGGING_LE
#include <cutils/log.h>
#else
#include <utils/Log.h>
#endif

#ifdef QMI_CSI_ANDROID
extern unsigned int qcsi_debug_level;
#define QCSI_LOG_INFO(x...) do { \
		if (qcsi_debug_level <= ANDROID_LOG_INFO) \
			SLOGI("QCSI: "x); \
	} while(0)
#define QCSI_LOG_DBG(x...) do { \
		if (qcsi_debug_level <= ANDROID_LOG_DEBUG) \
			SLOGD("QCSI: "x); \
	} while(0)
#else
#define QCSI_LOG_INFO(x...)
#define QCSI_LOG_DBG(x...)
#endif

#define QCSI_LOG_ERR(x...) ALOGE(x);

#elif defined(QMI_FW_SYSLOG)
#include <syslog.h>

extern unsigned int qcsi_debug_level;
#define QCSI_LOG_INFO(x...) do { \
		if (qcsi_debug_level >= LOG_INFO) \
			syslog(LOG_INFO, "QMI_OS_FW: QCSI: "x); \
	} while(0)
#define QCSI_LOG_DBG(x...) do { \
		if (qcsi_debug_level >= LOG_DEBUG) \
			syslog(LOG_DEBUG, "QMI_OS_FW: QCSI: "x); \
	} while(0)

#define QCSI_LOG_ERR(x...)  syslog(LOG_ERR, x)

#else
#define QCSI_LOG_INFO(x...) do { \
		fprintf(stdout, "%s(%d) ", __FUNCTION__, __LINE__); \
		fprintf(stdout, ##x);                               \
	} while(0)

#define QCSI_LOG_DBG(x...) do { \
		fprintf(stdout, "%s(%d) ", __FUNCTION__, __LINE__); \
		fprintf(stdout, ##x);                               \
	} while(0)

#define QCSI_LOG_ERR(x...) do { \
		fprintf(stderr, "%s(%d) ", __FUNCTION__, __LINE__); \
		fprintf(stderr, ##x);                               \
	} while(0)
#endif

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
