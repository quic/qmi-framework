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
#include "qcsi_common.h"
#include "config.h"

#ifdef QMI_CCI_SYSTEM
	#define QMI_FW_CONF_FILE "/etc/qmi_fw.conf"
#else
	#define QMI_FW_CONF_FILE "/vendor/etc/qmi_fw.conf"
#endif

#define MAX_LINE_LENGTH 80
#define qcsi_DBG_CONF_STR "qcsi_DEBUG_LEVEL="

#ifdef QMI_FW_SYSLOG
	#define DEFAULT_DBG_LEVEL 4
#else
	#define DEFAULT_DBG_LEVEL 5
#endif

unsigned int qcsi_debug_level; /*= DEFAULT_DBG_LEVEL;*/
extern qcsi_xport_ops_type qcsi_qrtr_ops;
/**
 * @brief Initialize the QMI CSI debug level.
 *
 * This function initializes the QMI CSI debug level by reading the configuration
 * file specified by QMI_FW_CONF_FILE. If the configuration file contains a valid
 * debug level, it sets qcsi_debug_level to that value.
 */
void qcsi_debug_init(void)
{
    qcsi_debug_level = QCSI_DEBUG_LEVEL;
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
	qcsi_debug_init();
	qcsi_init(&qcsi_qrtr_ops, NULL);
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
void __attribute__ ((destructor)) qcsi_fw_deinit(void)
{
	qcsi_deinit();
}
#endif
