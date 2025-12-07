// Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
/**
 * @file    qcci.c
 * @brief   The QMI common client interface common module
 *
 * @details
 * QMI common client routines. All clients will be built on top of these
 * routines for initializing, sending messages, and receiving responses/
 * indications.
 *
 * @note
 * qmi_cci_init() needs to be called before sending or receiving any
 * service-specific messages.
 */
#include <string.h>
#include "qmi_cci.h"
#include "qmi_idl_lib.h"
#include "qmi_idl_lib_internal.h"
#include "qcci_os.h"
#include "qcci_common.h"

/**
 * @brief Macro for copying OS parameters.
 */
#ifndef QMI_CCI_COPY_OS_PARAMS
	#define QMI_CCI_COPY_OS_PARAMS(dest, src)
#endif

/**
 * @brief Macro for initializing OS signal with self parameters.
 */
#ifndef QMI_CCI_OS_SIGNAL_INIT_SELF
	#define QMI_CCI_OS_SIGNAL_INIT_SELF(ptr, os_params) \
				QMI_CCI_OS_SIGNAL_INIT(ptr, os_params)
#endif

/**
 * @brief Macro to check if the transaction type is synchronous.
 */
#define QCCI_IS_SYNC_TXN(txn_type) \
	(((txn_type) == TXN_SYNC_MSG) || ((txn_type) == TXN_SYNC_RAW))

/**
 * @brief Macro to check if the transaction type is raw.
 */
#define QCCI_IS_RAW_TXN(txn_type) \
	(((txn_type) == TXN_SYNC_RAW) || ((txn_type) == TXN_ASYNC_RAW))

/**
 * @brief Macro to invalidate the receive buffer of a transaction.
 */
#define QCCI_TXN_RX_BUF_INVALIDATE(txn) do { \
		(txn)->rx_buf = NULL; \
		(txn)->rx_buf_len = 0;  \
		(txn)->rx_cb_data = NULL; \
	} while(0)

/**
 * @brief Macro to invalidate the transmit buffer of a transaction.
 */
#define QCCI_TXN_TX_BUF_INVALIDATE(txn) do { \
		if((txn)->tx_buf) \
			QCCI_OS_FREE((txn)->tx_buf);  \
		(txn)->tx_buf = NULL; \
		(txn)->tx_buf_len = 0;  \
	} while(0)


/**
 * @brief Macro to define an invalid client ID.
 */
#define QCCI_INVALID_CLID 0

/**
 * @brief Macro to define an invalid handle.
 */
#define QCCI_INVALID_HANDLE QCCI_CAST_CLID_TO_HANDLE(QCCI_INVALID_CLID)

/**
 * @brief Macro to cast client ID to handle.
 */
#define QCCI_CAST_CLID_TO_HANDLE(clid) ((qmi_client_type)(uintptr_t)(clid))

/**
 * @brief Macro to cast handle to client ID.
 */
#define QCCI_CAST_HANDLE_TO_CLID(handle) ((uint32_t)(uintptr_t)(handle))

/**
 * @brief Macro to get client handle.
 */
#define QCCI_CLIENT_HANDLE(clnt) QCCI_CAST_CLID_TO_HANDLE((clnt)->clid)

/**
 * @brief Macro to define the client table count.
 */
#ifndef QCCI_CLIENT_TBL_COUNT
	#define QCCI_CLIENT_TBL_COUNT (16)
#endif

/**
 * @brief Macro to get the index from client ID.
 */
#define QCCI_CLID2IDX(clid) ((clid) & (QCCI_CLIENT_TBL_COUNT - 1))

/**
 * @brief Macro to get the minimum of two values.
 */
#define QCCI_MIN(a, b) ((a) > (b) ? (b) : (a))

/**
 * @brief Global definitions.
 */
static int qcci_fw_inited = 0;
static qcci_os_lock_type qcci_cmn_lock;
static uint32_t qcci_next_clid = 1;
static LIST(qcci_client_type, qcci_client_tbl)[QCCI_CLIENT_TBL_COUNT];
static qcci_xport_ops_type *qcci_xport_ops;
static void *qcci_xport_data;
static LIST(qcci_client_type, qcci_client_release_tbl);

/**
 * @brief Log transmitted messages.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] cntl_flag Control flag.
 * @param[in] txn_id Transaction ID.
 * @param[in] msg_id Message ID.
 * @param[in] raw_msg Pointer to the raw message.
 * @param[in] len Length of the message.
 */
static void qcci_log_tx(
	qcci_client_type	*clnt,
	uint8_t 		cntl_flag,
	uint16_t 		txn_id,
	uint16_t 		msg_id,
	void 			*raw_msg,
	uint16_t 		len)
{
	QCCI_LOG_TX_PKT(clnt->service_obj, cntl_flag, txn_id,
				msg_id, len, clnt->info.client.server_addr,
				QCCI_MAX_ADDR_LEN);

	if(clnt->info.client.log_cb) {
		clnt->info.client.log_cb(QCCI_CLIENT_HANDLE(clnt),
				QMI_IDL_REQUEST, msg_id, txn_id,
				raw_msg, len, QMI_NO_ERR,
				clnt->info.client.log_cb_data);
	}
}


/**
 * @brief Log received messages.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] cntl_flag Control flag.
 * @param[in] txn_id Transaction ID.
 * @param[in] msg_id Message ID.
 * @param[in] raw_msg Pointer to the raw message.
 * @param[in] len Length of the message.
 * @param[in] status Status of the message.
 */
static void qcci_log_rx(
	qcci_client_type 	*clnt,
	uint8_t 		cntl_flag,
	uint16_t 		txn_id,
	uint16_t 		msg_id,
	void 			*raw_msg,
	uint16_t 		len,
	int 			status)
{
	if(status == QMI_NO_ERR)
		QCCI_LOG_RX_PKT(clnt->service_obj, cntl_flag, txn_id,
					msg_id, len,
					clnt->info.client.server_addr,
					QCCI_MAX_ADDR_LEN);

	if(clnt->info.client.log_cb) {
		qmi_idl_type_of_message_type type;

		type = cntl_flag == QMI_RESPONSE_CONTROL_FLAG ?
				QMI_IDL_RESPONSE : QMI_IDL_INDICATION;
		clnt->info.client.log_cb(QCCI_CLIENT_HANDLE(clnt), type,
					msg_id, txn_id, raw_msg, len, status,
					clnt->info.client.log_cb_data);
	}
}

/**
 * @brief Get service information.
 *
 * @param[in] service_obj Service object.
 * @param[out] service_id Pointer to store the service ID.
 * @param[out] idl_version Pointer to store the IDL version.
 * @param[out] max_msg_len Pointer to store the maximum message length.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 */
static qmi_cci_error_type qcci_service_info_get(
	qmi_idl_service_object_type	service_obj,
	uint32_t 			*service_id,
	uint32_t 			*idl_version,
	uint32_t 			*max_msg_len)
{
	qmi_cci_error_type rc;

	if (!service_obj)
		return QMI_CLIENT_PARAM_ERR;

	/* Get service id */
	if (service_id) {
		rc = qmi_idl_get_service_id(service_obj, service_id);
		if (rc != QMI_IDL_LIB_NO_ERR)
			return rc;
	}

	/* Get IDL version */
	if (idl_version) {
		rc = qmi_idl_get_idl_version(service_obj, idl_version);
		if (rc != QMI_IDL_LIB_NO_ERR)
			return rc;
	}

	/* Get msg max len */
	if (max_msg_len) {
		rc = qmi_idl_get_max_service_len(service_obj, max_msg_len);
		if (rc !=  QMI_IDL_LIB_NO_ERR)
			return rc;
	}

	return QMI_NO_ERR;
}

/**
 * @brief Lookup a service.
 *
 * This function looks up a service to ensure the server actually exists.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] svc Pointer to the service information structure.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_SERVICE_ERR Service error.
 * @retval QMI_CLIENT_ALLOC_FAILURE Allocation failure.
 */
static qmi_cci_error_type qcci_service_lookup(
	qcci_client_type	*clnt,
	qcci_service_info	*svc)
{
	qmi_service_info *service_array = NULL;
	unsigned int num_entries = 0, num_services = 0, i;
	qmi_cci_error_type rc;

	/* redo lookup to make sure the server actually exits */
	while (1) {
		rc = qmi_cci_get_service_list(clnt->service_obj,
				service_array, &num_entries, &num_services);
		if (rc != QMI_NO_ERR) {
			if (service_array) {
				QCCI_OS_FREE(service_array);
				service_array = NULL;
			}
			break;
		}

		if (num_entries == num_services)
			break;

		if (service_array)
			QCCI_OS_FREE(service_array);

		service_array = QCCI_OS_MALLOC(sizeof(*service_array) * num_services);
		if (!service_array) {
			return QMI_CLIENT_ALLOC_FAILURE;
		}

		num_entries = num_services;
	}

	rc = QMI_SERVICE_ERR;
	if (!service_array) {
		return rc;
	}

	for (i = 0; i < num_entries; i++) {
		qcci_service_info *s;
		s = (qcci_service_info *)&service_array[i];

		if (!memcmp(s->addr, svc->addr, clnt->xport_addr_len)) {
			rc = QMI_NO_ERR;
			break;
		}
	}
	QCCI_OS_FREE(service_array);

	return rc;
}

/**
 * @brief Lookup and return the client structure by client ID.
 *
 * This function looks up and returns the client structure by taking in the
 * client ID as a key.
 *
 * @param[in] clid Client ID.
 *
 * @return Pointer to the client handle upon success.
 *
 * @note qcci_cmn_lock must be held by the caller.
 */
static qcci_client_type *qcci_client_lookup(uint32_t clid)
{
	qcci_client_type *clnt;

	LIST_FIND(qcci_client_tbl[QCCI_CLID2IDX(clid)], clnt, link,
		  clnt->clid == clid);
	return clnt;
}

/**
 * @brief Link a client handle to the client list.
 *
 * This function links a client handle to the client list.
 *
 * @param[in] clnt Pointer to the client structure.
 *
 * @note qcci_cmn_lock must be held by the caller.
 */
static void qcci_client_link(qcci_client_type *clnt)
{
	uint32_t idx;

	if (!clnt)
		return;

	clnt->clid = QCCI_INVALID_CLID;

	/* Get a new unused and valid clid */
	while (clnt->clid == QCCI_INVALID_CLID) {
		clnt->clid = qcci_next_clid++;
		if (qcci_client_lookup(clnt->clid) != NULL) {
			clnt->clid = QCCI_INVALID_CLID;
		}
	}
	idx = QCCI_CLID2IDX(clnt->clid);
	LIST_ADD(qcci_client_tbl[idx], clnt, link);
}

/**
 * @brief Unlink a client handle from the client list.
 *
 * This function unlinks a client handle from the client list.
 *
 * @param[in] clnt Pointer to the client structure.
 *
 * @note qcci_cmn_lock must be held by the caller.
 */
static void qcci_client_unlink(qcci_client_type *clnt)
{
	if (!clnt)
		return;

	if (qcci_client_lookup(clnt->clid) != NULL) {
		LIST_REMOVE(qcci_client_tbl[QCCI_CLID2IDX(clnt->clid)],
							clnt, link);
		LINK_INIT(clnt->link);
		LIST_ADD(qcci_client_release_tbl, clnt, link);
	}
}

/**
 * @brief Allocate a client handle and return its pointer.
 *
 * This function allocates a client handle and returns its pointer.
 *
 * @param[in] service_obj Service object.
 * @param[in] category Client category.
 * @param[in] os_params Pointer to OS parameters.
 * @param[in] ind_cb Indication callback function.
 * @param[in] ind_cb_data Pointer to indication callback data.
 * @param[out] client Pointer to store the allocated client handle.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_FW_NOT_UP Framework not initialized.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 * @retval QMI_CLIENT_ALLOC_FAILURE Allocation failure.
 * @retval QMI_CLIENT_INVALID_SIG Invalid signal.
 *
 * @note The client handle will be inserted into the client list.
 *       The pointer MUST be freed using qcci_client_free() only.
 */
static qmi_cci_error_type qcci_client_alloc(
	qmi_idl_service_object_type	service_obj,
	qcci_client_category_type	category,
	qmi_client_os_params		*os_params,
	qmi_client_ind_cb		ind_cb,
	void				*ind_cb_data,
	qcci_client_type		**client)
{
	qcci_client_type *clnt;
	*client = NULL;

	/* This is NOT thread safe, but coming down to it,
	 * it is better than nothing protecting locking an
	 * uninitialized lock */
	if (!qcci_fw_inited)
		return QMI_CLIENT_FW_NOT_UP;

	if (!service_obj)
		return QMI_CLIENT_PARAM_ERR;

	clnt = QCCI_OS_CALLOC(1, sizeof(*clnt));
	if (!clnt)
		return QMI_CLIENT_ALLOC_FAILURE;

	QMI_CCI_OS_SIGNAL_INIT(&clnt->signal, os_params);
#ifdef QMI_CCI_OS_SIGNAL_VALID
	if (!QMI_CCI_OS_SIGNAL_VALID(&clnt->signal)) {
		QCCI_OS_FREE(clnt);
		return QMI_CLIENT_INVALID_SIG;
	}
#endif
	if (category == QCCI_NOTIFIER_CLIENT) {
		if (os_params) {
			QMI_CCI_OS_EXT_SIGNAL_INIT(
				clnt->info.notifier.ext_signal, os_params);
#ifdef QMI_CCI_OS_EXT_SIGNAL_VALID
			if (!QMI_CCI_OS_EXT_SIGNAL_VALID(
				clnt->info.notifier.ext_signal)) {
				QMI_CCI_OS_SIGNAL_DEINIT(&clnt->signal);
				QCCI_OS_FREE(clnt);
				return QMI_CLIENT_INVALID_SIG;
			}
#endif
		} else {
			clnt->info.notifier.ext_signal = NULL;
		}
	} else {
		LIST_INIT(clnt->info.client.txn_list);
		clnt->info.client.next_txn_id = 1;

		LIST_INIT(clnt->info.client.tx_q);
		clnt->info.client.accepting_txns = 1;

		clnt->info.client.ind_cb = ind_cb;
		clnt->info.client.ind_cb_data = ind_cb_data;
	}

	QCCI_OS_LOCK_INIT(&clnt->lock);
	clnt->category = category;
	clnt->service_obj = service_obj;

	/* Allocate one ref for this call */
	clnt->ref_count = 1;
	LINK_INIT(clnt->link);

	QCCI_OS_LOCK(&qcci_cmn_lock);

	/* Link to client list */
	qcci_client_link(clnt);

	QCCI_OS_UNLOCK(&qcci_cmn_lock);

	*client = clnt;
	return QMI_NO_ERR;
}

/**
 * @brief Frees a client handle.
 *
 * This function frees a client handle.
 *
 * @param[in] clnt Pointer to the client structure.
 *
 * @note The client handle will be unlinked if required.
 */
static void qcci_client_free(qcci_client_type *clnt)
{
	/* Unlink just to be sure, in most cases this should do nothing
	 * as qcci_client_get_ref(handle, 1) would have removed this
	 * from the list */
	QCCI_OS_LOCK(&qcci_cmn_lock);
	qcci_client_unlink(clnt);
	QCCI_OS_UNLOCK(&qcci_cmn_lock);

	QMI_CCI_OS_SIGNAL_DEINIT(&clnt->signal);
	QCCI_OS_LOCK_DEINIT(&clnt->lock);

	if (clnt->category == QCCI_NOTIFIER_CLIENT) {
		if(clnt->info.notifier.ext_signal)
			QMI_CCI_OS_SIGNAL_DEINIT(
						clnt->info.notifier.ext_signal);
	}

	if (clnt->release_cb)
		clnt->release_cb(clnt->release_cb_data);

	/* Debug */
	{
		qcci_client_type *i = NULL;

		QCCI_OS_LOCK(&qcci_cmn_lock);

		LIST_FIND(qcci_client_release_tbl, i, link, i->clid == clnt->clid);
		if (i)
			LIST_REMOVE(qcci_client_release_tbl, clnt, link);

		QCCI_OS_UNLOCK(&qcci_cmn_lock);
	}

	QCCI_OS_FREE(clnt);
}

/**
 * @brief Gets a reference on the client handle.
 *
 * This function gets a reference on the client handle.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] ref_count Reference count.
 *
 * @return Pointer to the client handle upon success.
 */
static qcci_client_type *qcci_client_get_ref(
	qmi_client_type	client_handle,
	int		unlink)
{
	uint32_t clid = QCCI_CAST_HANDLE_TO_CLID(client_handle);
	qcci_client_type *clnt;

	QCCI_OS_LOCK(&qcci_cmn_lock);

	clnt = qcci_client_lookup(clid);
	if (!clnt || clnt->ref_count < 0) {
		QCCI_OS_UNLOCK(&qcci_cmn_lock);
		return NULL;
	}

	clnt->ref_count++;

	/* Unlink the client from the global table so future get_ref's fail */
	if (unlink)
		qcci_client_unlink(clnt);

	QCCI_OS_UNLOCK(&qcci_cmn_lock);

	return clnt;
}

/**
 * @brief Releases a reference on the client.
 *
 * This function releases a reference on the client.
 *
 * @param[in] clnt Pointer to the client structure.
 *
 * @return Current reference count after releasing one's reference.
 *
 * @note The client structure must NOT be accessed after calling this function.
 */
static void qcci_client_put_ref(qcci_client_type *clnt)
{
	int ref = 0;

	if (!clnt)
		return;

	QCCI_OS_LOCK(&qcci_cmn_lock);

	ref = --clnt->ref_count;

	QCCI_OS_UNLOCK(&qcci_cmn_lock);

	if (ref == 0)
		qcci_client_free(clnt);
}


/**
 * @brief Open a client transport.
 *
 * This function opens a client transport.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] service_id Service ID.
 * @param[in] idl_version IDL version.
 * @param[in] max_msg_len Maximum message length.
 * @param[in] svc Pointer to the service information structure.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_TRANSPORT_ERR Transport error.
 */
static qmi_cci_error_type qcci_client_xport_open(
	qcci_client_type	*clnt,
	uint32_t		service_id,
	uint32_t		idl_version,
	uint32_t		max_msg_len,
	qcci_service_info	*svc)
{
	uint8_t *server_addr = NULL;

	clnt->xport_addr_len = qcci_xport_ops->addr_len();

	if (svc) {
		server_addr = clnt->info.client.server_addr;
		memcpy(server_addr, svc->addr, clnt->xport_addr_len);
	}

	clnt->xport_handle = qcci_xport_ops->open(qcci_xport_data,
			     clnt, service_id, idl_version,
			     server_addr, max_msg_len);

	return clnt->xport_handle ? QMI_NO_ERR : QMI_CLIENT_TRANSPORT_ERR;
}

/**
 * @brief Close a client transport.
 *
 * This function closes a client transport.
 *
 * @param[in] clnt Pointer to the client structure.
 */
static void qcci_client_xport_close(qcci_client_type *clnt)
{
	if (clnt->xport_handle) {
		/* Close transport */
		qcci_xport_ops->close(clnt->xport_handle);

		clnt->xport_handle = NULL;
	}
}

/**
 * @brief Increment the reference count of a transaction (unsafe).
 *
 * This function increments the reference count of a transaction (unsafe).
 *
 * @param[in] txn Pointer to the transaction structure.
 */
static void qcci_txn_get_ref_unsafe(qcci_txn_type *txn)
{
	txn->ref_count++;
}

/**
 * @brief Increment the reference count of a transaction.
 *
 * This function increments the reference count of a transaction.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] txn Pointer to the transaction structure.
 */
static void qcci_txn_get_ref(
	qcci_client_type	*clnt,
	qcci_txn_type	*txn)
{
	QCCI_OS_LOCK(&clnt->lock);

	qcci_txn_get_ref_unsafe(txn);

	QCCI_OS_UNLOCK(&clnt->lock);
}

/**
 * @brief Decrement the reference count of a transaction (unsafe).
 *
 * This function decrements the reference count of a transaction (unsafe).
 *
 * @param[in] txn Pointer to the transaction structure.
 */
static void qcci_txn_put_ref_unsafe(qcci_txn_type *txn)
{
	if (txn && txn->ref_count > 0) {
		txn->ref_count--;
		if (txn->ref_count == 0) {
			QMI_CCI_OS_SIGNAL_DEINIT(&txn->signal);
			QCCI_OS_FREE(txn);
		}
	} else {
		QCCI_LOG_ERR("txn invalid ref_count txn:%p\n", txn);
	}
}

/**
 * @brief Decrement the reference count of a transaction.
 *
 * This function decrements the reference count of a transaction.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] txn Pointer to the transaction structure.
 */
static void qcci_txn_put_ref(
	qcci_client_type	*clnt,
	qcci_txn_type	*txn)
{
	QCCI_OS_LOCK(&clnt->lock);

	qcci_txn_put_ref_unsafe(txn);

	QCCI_OS_UNLOCK(&clnt->lock);
}

/**
 * @brief Create a transaction and return the handle.
 *
 * This function creates a transaction and returns the handle.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] txn Pointer to the transaction structure.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_ALLOC_FAILURE Allocation failure.
 *
 * @note The transaction is added to the client's outstanding transaction list.
 */
static qmi_cci_error_type qcci_get_txn(
	qcci_client_type		*clnt,
	qcci_txn_enum_type		type,
	unsigned int			msg_id,
	void				*resp_buf,
	unsigned int			resp_buf_len,
	qmi_client_recv_msg_async_cb	rx_cb,
	void				*rx_cb_data,
	qcci_txn_type 		**txn_handle)
{
	qcci_txn_type *txn;

	*txn_handle = NULL;

	QCCI_OS_LOCK(&clnt->lock);

	if (clnt->category != QCCI_CONNECTED_CLIENT) {
		QCCI_OS_UNLOCK(&clnt->lock);
		return QMI_SERVICE_ERR;
	}

	txn = QCCI_OS_CALLOC(1, sizeof(*txn));
	if (!txn)
		return QMI_CLIENT_ALLOC_FAILURE;

	LINK_INIT(txn->link);
	LINK_INIT(txn->tx_link);
	txn->type = type;
	txn->msg_id = msg_id;
	txn->rx_cb = rx_cb;
	txn->rx_cb_data = rx_cb_data;
	txn->rx_buf = resp_buf;
	txn->rx_buf_len = resp_buf_len;
	txn->client = clnt;
	txn->ref_count = 1; /* The txn_list takes a reference.
                         The txn_list's reference will be
                         released only when it is removed
                         from the list */

	while((txn->txn_id = clnt->info.client.next_txn_id++) == 0);

	QMI_CCI_OS_SIGNAL_INIT_SELF(&txn->signal, &clnt->signal);
	LIST_ADD(clnt->info.client.txn_list, txn, link);

	QCCI_OS_UNLOCK(&clnt->lock);

	*txn_handle = txn;
	return QMI_NO_ERR;
}

/**
 * @brief Find and remove a transaction from the client's transaction list.
 *
 * This function finds and removes a transaction from the client's transaction
 * list and releases the list's reference count on the transaction if found.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] txn Pointer to the transaction structure.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_INTERNAL_ERR Internal error.
 *
 * @note Caller must have a reference to the client structure.
 */
static qmi_cci_error_type qcci_remove_txn(
	qcci_client_type	*clnt,
	qcci_txn_type	*txn)
{
	qcci_txn_type *i;
	qmi_cci_error_type rc = QMI_INTERNAL_ERR;

	if (!clnt || !txn)
		return rc;

	QCCI_OS_LOCK(&clnt->lock);

	LIST_FIND(clnt->info.client.txn_list, i, link, i == txn);
	if (i) {
		LIST_REMOVE(clnt->info.client.txn_list, i, link);
		qcci_txn_put_ref_unsafe(i);
		rc = QMI_NO_ERR;
	}

	QCCI_OS_UNLOCK(&clnt->lock);

	return rc;
}

/**
 * @brief Handle transaction error based on its type and set return code to error.
 *
 * This function handles transaction error based on its type and sets the return
 * code to error.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] txn Pointer to the transaction structure.
 * @param[in] error Error code.
 *
 * @note Transaction is freed in the async case. The thread waiting on a sync
 *       response will free the transaction after waking up.
 */
static void qcci_txn_handle_error(
	qcci_client_type	*clnt,
	qcci_txn_type	*txn,
	int			error)
{
	if (!txn)
		return;

	qcci_log_rx(clnt, QMI_IDL_RESPONSE, txn->txn_id, txn->msg_id, NULL,
		0, error);

	txn->rc = error;

	if (QCCI_IS_SYNC_TXN(txn->type)) {
		/* txn freed by the waiting function */
		QMI_CCI_OS_SIGNAL_SET(&txn->signal);
	} else {
		if(txn->rx_cb)
			txn->rx_cb(QCCI_CLIENT_HANDLE(clnt),
				txn->msg_id, txn->rx_buf, 0,
				txn->rx_cb_data, txn->rc);
	}
}

/**
 * @brief Cleans up all client transactions.
 *
 * This function cleans up all client transactions.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] error Error code.
 *
 * @note The caller must have acquired a reference to the client structure.
 */
static void qcci_client_txns_cleanup(
	qcci_client_type	*clnt,
	qmi_cci_error_type	error)

{
	qcci_txn_type *txn;

	if (clnt->category == QCCI_NOTIFIER_CLIENT)
		return;

	txn = LIST_HEAD(clnt->info.client.tx_q);
	LIST_INIT(clnt->info.client.tx_q);

	while (txn) {
		qcci_txn_type *to_free = txn;
		txn = txn->tx_link.next;
		/* No need for lock as it is no longer in the list */
		QCCI_TXN_TX_BUF_INVALIDATE(to_free); /* TODO: check is RX free needed */
		/* Give up tx_q list reference */
		qcci_txn_put_ref_unsafe(to_free);
	}

	txn = LIST_HEAD(clnt->info.client.txn_list);
	LIST_INIT(clnt->info.client.txn_list);

	/* Handle error on each txn */
	while (txn) {
		qcci_txn_type *to_free = txn;
		txn = txn->link.next;

		/* handle transaction error base on its type */
		qcci_txn_handle_error(clnt, to_free, error);
		QCCI_TXN_RX_BUF_INVALIDATE(to_free);
		qcci_txn_put_ref_unsafe(to_free);
	}
}

/**
 * @brief Process received response for a transaction.
 *
 * This function processes the received response for a transaction.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] txn_id Transaction ID.
 * @param[in] msg_id Message ID.
 * @param[in] buf Pointer to the buffer containing the response.
 * @param[in] msg_len Length of the message.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_INTERNAL_ERR Internal error.
 */
static qmi_cci_error_type qcci_txn_rx_process_resp(
	qcci_client_type	*clnt,
	uint16_t		txn_id,
	uint16_t		msg_id,
	uint8_t			*buf,
	uint16_t		msg_len)
{
	qcci_txn_type *txn;

	/* Process transaction */
	QCCI_OS_LOCK(&clnt->lock);

	LIST_FIND(clnt->info.client.txn_list, txn, link, txn->txn_id == txn_id);
	if(txn) {
		/* Txn list lock's reference is transferred to xport_recv */
		LIST_REMOVE(clnt->info.client.txn_list, txn, link);
	}

	QCCI_OS_UNLOCK(&clnt->lock);

	/* transaction not found */
	if (!txn) {
		QCCI_LOG_ERR("Txn not found. svc_id: %d",
				clnt->service_obj->service_id);
		return QMI_INTERNAL_ERR;
	}

	/* mismatched msg_id, something went wrong - bail */
	if (txn->msg_id != msg_id) {
		qcci_txn_handle_error(clnt, txn, QMI_INVALID_TXN);
		qcci_txn_put_ref(clnt, txn);
		return QMI_INTERNAL_ERR;
	}

	if (!txn->rx_buf)
		goto txn_put_ref_bail;

	if (QCCI_IS_RAW_TXN(txn->type)) {
		txn->reply_len = QCCI_MIN(msg_len, txn->rx_buf_len);
		memcpy(txn->rx_buf, buf, txn->reply_len);
		txn->rc = QMI_NO_ERR;
	} else {
		txn->rc = qmi_idl_message_decode(clnt->service_obj,
				QMI_IDL_RESPONSE, msg_id, buf,
				msg_len, txn->rx_buf, txn->rx_buf_len);
	}

	if (QCCI_IS_SYNC_TXN(txn->type)) {
		QMI_CCI_OS_SIGNAL_SET(&txn->signal);
	} else {
		if (txn->rx_cb)
			txn->rx_cb(QCCI_CLIENT_HANDLE(clnt),
				msg_id, txn->rx_buf, txn->rx_buf_len,
				txn->rx_cb_data, txn->rc);
	}

txn_put_ref_bail:
	qcci_txn_put_ref(clnt, txn);

	return QMI_NO_ERR;
}

/**
 * @brief Process received indication for a transaction.
 *
 * This function processes the received indication for a transaction.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] msg_id Message ID.
 * @param[in] buf Pointer to the buffer containing the indication.
 * @param[in] msg_len Length of the message.
 *
 * @retval QMI_NO_ERR Success.
 */
static qmi_cci_error_type qcci_txn_rx_process_ind(
	qcci_client_type	*clnt,
	uint16_t		msg_id,
	uint8_t			*buf,
	uint16_t		msg_len)
{
	if (clnt->info.client.ind_cb) {
		clnt->info.client.ind_cb(QCCI_CLIENT_HANDLE(clnt),
				msg_id, msg_len ? buf : NULL,
				msg_len,
				clnt->info.client.ind_cb_data);
	}
	return QMI_NO_ERR;
}

/**
 * @brief Tries and transmits all pending transactions in the tx queue.
 *
 * This function tries and transmits all pending transactions in the tx queue.
 *
 * @param[in] clnt Pointer to the client structure.
 *
 * @note The caller must have acquired a reference to the client structure.
 */
static void qcci_flush_tx_q(qcci_client_type *clnt)
{
	qcci_txn_type *txn;
	uint8_t dest_addr[QCCI_MAX_ADDR_LEN]; /* TODO: Check if it is needed */
	int rc;

	QCCI_OS_LOCK(&clnt->lock);

	if (clnt->category != QCCI_CONNECTED_CLIENT) {
		qcci_client_txns_cleanup(clnt, QMI_SERVICE_ERR);
		QCCI_OS_UNLOCK(&clnt->lock);
		return;
	}

	memcpy(dest_addr, clnt->info.client.server_addr, QCCI_MAX_ADDR_LEN);

	while (NULL != (txn = LIST_HEAD(clnt->info.client.tx_q))) {
		if (clnt->info.client.accepting_txns) {
			rc = qcci_xport_ops->send(clnt->xport_handle,
				dest_addr, txn->tx_buf, txn->tx_buf_len);
		} else {
			rc = QMI_CLIENT_INVALID_CLNT;
		}

		/* xport is flow controlled, try again later */
		if(rc == QMI_XPORT_BUSY_ERR)
			break;

		LIST_REMOVE(clnt->info.client.tx_q, txn, tx_link);
		QCCI_TXN_TX_BUF_INVALIDATE(txn);

		/* Error sending txn */
		if(rc != QMI_NO_ERR) {
			/* TODO: optimize this code */
			qcci_txn_type *to_find = txn;

			QCCI_LOG_ERR("Error sending TXN: svc_id: %d"
				"txn_id: %d msg_id: %d",
				clnt->service_obj->service_id, txn->txn_id,
				txn->msg_id);
			LIST_FIND(clnt->info.client.txn_list, txn, link,
				txn == to_find);
			if(txn) {
				LIST_REMOVE(clnt->info.client.txn_list,
					txn, link);
				/* Txn_list's ref count is transferred
				 * into qcci_txn_handle_error */
				qcci_txn_handle_error(clnt, txn, rc);
				qcci_txn_put_ref_unsafe(txn);
			}

			if (rc == QMI_SERVICE_ERR) {
				/* Release tx_q ref count */
				qcci_txn_put_ref_unsafe(txn);
				QCCI_OS_UNLOCK(&clnt->lock);

				qcci_xport_event_server_error(clnt,
						dest_addr, QMI_SERVICE_ERR);
				return;
			}
		}

		/* Release tx_q ref count */
		qcci_txn_put_ref_unsafe(txn);
	}
	QCCI_OS_UNLOCK(&clnt->lock);
}

/**
 * @brief Transmit a message.
 *
 * This function transmits a message.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] txn Pointer to the transaction structure.
 * @param[in] msg Pointer to the message buffer.
 * @param[in] len Length of the message.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 * @retval QMI_SERVICE_ERR Service error.
 * @retval QMI_CLIENT_INVALID_CLNT Invalid client.
 *
 * @note The caller must have obtained a reference to the client handle.
 *       The caller should free the buffer only if this function returns error.
 *       The caller should provide buffers which are allocated on the heap only.
 */
static qmi_cci_error_type qcci_msg_send(
	qcci_client_type	*clnt,
	qcci_txn_type	*txn,
	void			*msg,
	uint32_t 		len)
{
	int flush_req = 0;

	if (!txn || !len || !msg) {
		return QMI_CLIENT_PARAM_ERR;
	}

	/* Check server addr validity once before sending. */
	QCCI_OS_LOCK(&clnt->lock);

	if (clnt->category != QCCI_CONNECTED_CLIENT) {
		QCCI_OS_UNLOCK(&clnt->lock);
		return QMI_SERVICE_ERR;
	}

	if (!clnt->info.client.accepting_txns) {
		QCCI_OS_UNLOCK(&clnt->lock);
		return QMI_CLIENT_INVALID_CLNT;
	}

	qcci_txn_get_ref_unsafe(txn);

	txn->tx_buf = msg;
	txn->tx_buf_len = len;

	LIST_ADD(clnt->info.client.tx_q, txn, tx_link);

	/* Flush only if this is the first packet. If another
	   packet is pending a flush, then we let the resume
	   process continue the flush */
	flush_req = LIST_CNT(clnt->info.client.tx_q) <= 1;

	qcci_log_tx(clnt, QMI_REQUEST_CONTROL_FLAG, txn->txn_id, txn->msg_id,
		       (void *)((uint8_t *)msg + QMI_HEADER_SIZE),
		       len - QMI_HEADER_SIZE);

	QCCI_OS_UNLOCK(&clnt->lock);

	if (flush_req) {
		qcci_flush_tx_q(clnt);
	}

	return QMI_NO_ERR;
}

/**
 * @brief Encode and send a message to the client.
 *
 * This function encodes and sends a message to the client.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] txn Pointer to the transaction structure.
 * @param[in] c_struct Pointer to the C structure.
 * @param[in] c_struct_len Length of the C structure.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 * @retval QMI_CLIENT_ALLOC_FAILURE Allocation failure.
 * @retval QMI_IDL_LIB_NO_ERR IDL library error.
 */
static qmi_cci_error_type qcci_msg_encode_and_send(
	qcci_client_type	*clnt,
	qcci_txn_type	*txn,
	void			*c_struct,
	int			c_struct_len)
{
	uint32_t max_msg_len;
	uint32_t out_len, idl_c_struct_len;
	unsigned char *msg;
	int rc;

	rc = qmi_idl_get_message_c_struct_len(clnt->service_obj,
			QMI_IDL_REQUEST, txn->msg_id, &idl_c_struct_len);
	if (rc != QMI_IDL_LIB_NO_ERR)
		return rc;

	/* Allow users to pass c_stuct_len == 0. This is useful in cases when
	   the c structure has only optional members(thus idl_c_stuct_len
	   would be non-zero) and the user requires to send the message
	   with all options turned off
	*/
	if (c_struct_len != 0 && c_struct_len != (int)idl_c_struct_len)
		return QMI_CLIENT_PARAM_ERR;

	if (c_struct && c_struct_len) {
		rc = qmi_idl_get_max_message_len(clnt->service_obj,
			QMI_IDL_REQUEST, txn->msg_id, &max_msg_len);
		if (rc != QMI_IDL_LIB_NO_ERR)
			return rc;

		msg = QCCI_OS_MALLOC(max_msg_len + QMI_HEADER_SIZE);
		if(!msg)
			return QMI_CLIENT_ALLOC_FAILURE;

		rc = qmi_idl_message_encode(clnt->service_obj,
			     QMI_IDL_REQUEST, txn->msg_id, c_struct,
			     c_struct_len, msg + QMI_HEADER_SIZE,
			     max_msg_len, (uint32_t *)&out_len);
		if(rc != QMI_IDL_LIB_NO_ERR) {
			QCCI_OS_FREE(msg);
			return rc;
		}
	} else {
		/* Empty message */
		out_len = 0;
		msg = QCCI_OS_MALLOC(QMI_HEADER_SIZE);
		if(!msg)
			return QMI_CLIENT_ALLOC_FAILURE;
	}

	/* fill in header */
	encode_header(msg, QMI_REQUEST_CONTROL_FLAG, txn->txn_id, txn->msg_id,
		(uint16_t)out_len);

	out_len += QMI_HEADER_SIZE;

	rc = qcci_msg_send(clnt, txn, msg, out_len);
	if(rc != QMI_NO_ERR) {
		QCCI_OS_FREE(msg);
	}

	return rc;
}

/**
 * @brief Wait for a transaction response message.
 *
 * This function waits for a transaction response message.
 *
 * @param[in] txn Pointer to the transaction structure.
 * @param[in] timeout_msecs Timeout in milliseconds.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_TIMEOUT_ERR Timeout error.
 *
 * @note The caller is required to hold a reference to the client structure.
 */
static qmi_cci_error_type qcci_response_wait_loop(
	qcci_txn_type	*txn,
	unsigned int		timeout_msecs)
{
	qmi_cci_error_type ret = QMI_NO_ERR;

	do {
		QMI_CCI_OS_SIGNAL_WAIT(&txn->signal, timeout_msecs);
		QMI_CCI_OS_SIGNAL_CLEAR(&txn->signal);

		if (QMI_CCI_OS_SIGNAL_TIMED_OUT(&txn->signal)) {
			ret = QMI_TIMEOUT_ERR;
			break;
		}

		/* Not a stray wake-up break out */
		if (txn->rc != QMI_TIMEOUT_ERR) {
			ret = txn->rc;
			break;
		}
	} while(1);

	return ret;
}

/**
 * @brief Send a message asynchronously.
 *
 * This function sends a message asynchronously.
 *
 * @param[in] user_handle User handle.
 * @param[in] msg_id Message ID.
 * @param[in] req Pointer to the request buffer.
 * @param[in] req_len Length of the request.
 * @param[in] resp Pointer to the response buffer.
 * @param[in] resp_len Length of the response.
 * @param[in] resp_cb Response callback function.
 * @param[in] resp_cb_data Pointer to response callback data.
 * @param[in] txn_type Transaction type.
 * @param[out] txn_handle Pointer to store the transaction handle.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 * @retval QMI_CLIENT_INVALID_CLNT Invalid client.
 */
static qmi_cci_error_type qcci_send_msg_async(
	qmi_client_type			user_handle,
	unsigned int			msg_id,
	void				*req,
	unsigned int			req_len,
	void				*resp,
	unsigned int			resp_len,
	qmi_client_recv_msg_async_cb	resp_cb,
	void				*resp_cb_data,
	qcci_txn_enum_type		txn_type,
	qmi_txn_handle			*txn_handle)
{
	qcci_client_type *clnt;
	qcci_txn_type *txn = NULL;
	qmi_cci_error_type rc;

	if (!resp)
		return QMI_CLIENT_PARAM_ERR;

	if (req_len > 0 && req == NULL)
		return QMI_CLIENT_PARAM_ERR;

	if (txn_handle)
		*txn_handle = (qmi_txn_handle)NULL;

	clnt = qcci_client_get_ref(user_handle, 0);
	if (!clnt)
		return QMI_CLIENT_INVALID_CLNT;

	if (!clnt->xport_handle) {
		rc = QMI_CLIENT_INVALID_CLNT;
		goto clnt_put_ref_bail;
	}

	rc = qcci_get_txn(clnt, txn_type, msg_id, resp, resp_len,
			resp_cb, resp_cb_data, &txn);
	if (rc != QMI_NO_ERR)
		goto clnt_put_ref_bail;

	if (txn_handle)
		*txn_handle = (qmi_txn_handle)txn;

	if (QCCI_IS_SYNC_TXN(txn_type)) {
		qcci_txn_get_ref(clnt, txn);
		/* clear signal */
		QMI_CCI_OS_SIGNAL_CLEAR(&txn->signal);
		txn->rc = QMI_TIMEOUT_ERR;
	}

	if (QCCI_IS_RAW_TXN(txn_type)) {
		uint8_t *req_buf;

		/* Allocate request buffer with QMI header */
		req_buf = QCCI_OS_MALLOC(req_len + QMI_HEADER_SIZE);
		if (!req_buf) {
			rc = QMI_CLIENT_ALLOC_FAILURE;
			goto txn_put_ref_bail;
		}

		/* encode header and copy payload */
		encode_header(req_buf, QMI_REQUEST_CONTROL_FLAG, txn->txn_id,
			      (uint16_t)msg_id, (uint16_t)req_len);

		if(req_len > 0)
			memcpy(req_buf + QMI_HEADER_SIZE, req, req_len);

		/* send message and return */
		rc = qcci_msg_send(clnt, txn, req_buf,
						req_len + QMI_HEADER_SIZE);
		if (rc != QMI_NO_ERR)
			QCCI_OS_FREE(req_buf);
	} else {
		rc = qcci_msg_encode_and_send(clnt, txn, req, req_len);
	}

	if (rc == QMI_NO_ERR)
		goto clnt_put_ref_bail;

txn_put_ref_bail:
	qcci_remove_txn(clnt, txn);
	if (QCCI_IS_SYNC_TXN(txn_type))
		qcci_remove_txn(clnt, txn);
	qcci_txn_put_ref(clnt, txn);

clnt_put_ref_bail:
	qcci_client_put_ref(clnt);
	return rc;
}

/**
 * @brief Send a message synchronously.
 *
 * This function sends a message synchronously.
 *
 * @param[in] user_handle User handle.
 * @param[in] msg_id Message ID.
 * @param[in] req Pointer to the request buffer.
 * @param[in] req_len Length of the request.
 * @param[in] resp Pointer to the response buffer.
 * @param[in] resp_len Length of the response.
 * @param[in] txn_type Transaction type.
 * @param[out] resp_recv_len Pointer to store the received response length.
 * @param[in] timeout_msecs Timeout in milliseconds.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_INVALID_CLNT Invalid client.
 *
 * @note The caller must have obtained a reference to the client handle.
 */
static qmi_cci_error_type qcci_send_msg_sync(
	qmi_client_type		user_handle,
	unsigned int		msg_id,
	void			*req,
	unsigned int		req_len,
	void			*resp,
	unsigned int		resp_len,
	qcci_txn_enum_type	txn_type,
	unsigned int		*resp_recv_len,
	unsigned int		timeout_msecs)
{
	qcci_client_type *clnt;
	qcci_txn_type *txn;
	qmi_cci_error_type rc;

	clnt = qcci_client_get_ref(user_handle, 0);
	if(!clnt)
		return QMI_CLIENT_INVALID_CLNT;

	rc = qcci_send_msg_async(user_handle, msg_id, req, req_len,
			resp, resp_len, NULL, NULL, txn_type,
			(qmi_txn_handle *)&txn);
	if (rc != QMI_NO_ERR)
		goto clnt_put_ref_bail;

	rc = qcci_response_wait_loop(txn, timeout_msecs);
	if (rc == QMI_NO_ERR) {
		if (resp_recv_len)
			*resp_recv_len = txn->reply_len;
	}

	qmi_cci_delete_async_txn(user_handle, txn);
	qcci_txn_put_ref(clnt, txn);

clnt_put_ref_bail:
	qcci_client_put_ref(clnt);
	return rc;
}

/**
 * @brief Internal callback function used by qmi_cci_release().
 *
 * This function is an internal callback used by qmi_cci_release() to unblock
 * the release process.
 *
 * @param[in] cb_data Pointer to callback data.
 */
static void qcci_client_release_cb_internal(void *cb_data)
{
	QMI_CCI_OS_SIGNAL *signal = (QMI_CCI_OS_SIGNAL *)cb_data;
	if (signal)
		QMI_CCI_OS_SIGNAL_SET(signal);
}

/**
 * @brief Initialize the common client interface.
 *
 * This function initializes the common client interface.
 *
 * @param[in] service_info Pointer to the service information.
 * @param[in] service_obj Service object.
 * @param[in] ind_cb Indication callback function.
 * @param[in] ind_cb_data Pointer to indication callback data.
 * @param[in] os_params Pointer to OS parameters.
 * @param[out] user_handle Pointer to store the user handle.
 * @param[in] category Client category.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 * @retval QMI_CLIENT_INVALID_CLNT Invalid client.
 *
 * @note The caller must have obtained a reference to the client handle.
 */
qmi_cci_error_type qcci_client_cmn_init(
	qmi_service_info		*service_info,
	qmi_idl_service_object_type	service_obj,
	qmi_client_ind_cb		ind_cb,
	void				*ind_cb_data,
	qmi_client_os_params		*os_params,
	qmi_client_type			*user_handle,
	qcci_client_category_type	category)
{
	qcci_service_info *svc = (qcci_service_info *)service_info;
	qcci_client_type *clnt;
	uint32_t service_id, idl_version, max_msg_len;
	qmi_cci_error_type rc;

	if (!user_handle)
		return QMI_CLIENT_PARAM_ERR;

	*user_handle = QCCI_INVALID_HANDLE;

	rc = qcci_service_info_get(service_obj, &service_id,
				&idl_version, &max_msg_len);
	if(rc != QMI_NO_ERR)
		return rc;

	if (category == QCCI_NOTIFIER_CLIENT) {
		max_msg_len = 0;
	} else {
		if (!svc)
		return QMI_CLIENT_PARAM_ERR;
	}

	rc = qcci_client_alloc(service_obj, category,
				  os_params, ind_cb, ind_cb_data, &clnt);
	if(rc != QMI_NO_ERR)
		return rc;

	clnt = qcci_client_get_ref(QCCI_CLIENT_HANDLE(clnt), 0);
	if (!clnt) {
		/* Should never happen */
		return QMI_CLIENT_INVALID_CLNT;
	}

	QCCI_OS_LOCK(&clnt->lock);

	rc = qcci_client_xport_open(clnt, service_id, idl_version,
				max_msg_len, svc);
	if(rc != QMI_NO_ERR) {
		goto unlock_put_ref_bail;
	}

	if (category == QCCI_NOTIFIER_CLIENT)
	{
		*user_handle = QCCI_CLIENT_HANDLE(clnt);
		rc = QMI_NO_ERR;

		/* if server exists, signal notifier */
		if (qcci_xport_ops->lookup(qcci_xport_data, 1,
					service_id, idl_version,
					NULL, NULL)) {

			if (os_params)
				QMI_CCI_OS_SIGNAL_SET(os_params);

			clnt->info.notifier.notify_pending = 1;
		}
	} else {
		rc = qcci_service_lookup(clnt, svc);
		if (rc != QMI_NO_ERR) {
			qcci_client_xport_close(clnt);
			goto unlock_put_ref_bail;
		}
		*user_handle = QCCI_CLIENT_HANDLE(clnt);
	}

unlock_put_ref_bail:
	QCCI_OS_UNLOCK(&clnt->lock);
	qcci_client_put_ref(clnt);
	return rc;
}


/**
 * @brief Release the reference taken for this transport.
 *
 * This function releases the reference taken for this transport.
 *
 * @param[in] clnt Pointer to the client structure.
 */
void qcci_xport_closed(qcci_client_type *clnt)
{
	/* Release the reference taken for this transport */
	qcci_client_put_ref(clnt);
}

/**
 * @brief Handle new server event.
 *
 * This function handles the event when a new server is detected.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] addr Pointer to the address.
 */
void qcci_xport_event_new_server(qcci_client_type *clnt, void *addr)
{
	qmi_client_notify_cb notify_cb = NULL;
	void *cb_data = NULL;
	QMI_CCI_OS_SIGNAL *ext_signal = NULL;

	QCCI_OS_UNUSED_PARAM(addr);

	if (!clnt)
		return;

	QCCI_OS_LOCK(&clnt->lock);
	if (clnt->category == QCCI_NOTIFIER_CLIENT) {
		notify_cb = clnt->info.notifier.notify_cb;
		cb_data   = clnt->info.notifier.notify_cb_data;
		if (!notify_cb)
			clnt->info.notifier.notify_pending = 1;
		ext_signal = clnt->info.notifier.ext_signal;
	}
	QCCI_OS_UNLOCK(&clnt->lock);

	if (ext_signal)
		QMI_CCI_OS_SIGNAL_SET(ext_signal);

	if (notify_cb) {
		notify_cb(QCCI_CLIENT_HANDLE(clnt), clnt->service_obj,
			QMI_CLIENT_SERVICE_COUNT_INC, cb_data);
	}
}

/**
 * @brief Handle server removal event.
 *
 * This function handles the event when a server is removed.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] addr Pointer to the address.
 */
void qcci_xport_event_remove_server(qcci_client_type *clnt, void *addr)
{
	qcci_xport_event_server_error(clnt, addr, QMI_SERVICE_ERR);
}

/**
 * @brief Resume the transport.
 *
 * This function resumes the transport.
 *
 * @param[in] clnt Pointer to the client structure.
 */
void qcci_xport_resume(qcci_client_type *clnt)
{
	if (!clnt)
		return;

	/* xport already has a ref count, we dont need one */
	qcci_flush_tx_q(clnt);
}

/**
 * @brief Receive a message from the transport.
 *
 * This function receives a message from the transport.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] addr Pointer to the address.
 * @param[in] buf Pointer to the buffer containing the message.
 * @param[in] len Length of the message.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 * @retval QMI_INTERNAL_ERR Internal error.
 */
qmi_cci_error_type qcci_xport_recv(
	qcci_client_type	*clnt,
	void			*addr,
	uint8_t			*buf,
	uint32_t		len)
{
	uint8_t cntl_flag;
	uint16_t txn_id, msg_id, msg_len;

	if (!clnt || len < QMI_HEADER_SIZE)
		return QMI_CLIENT_PARAM_ERR;

	QCCI_OS_UNUSED_PARAM(addr);

	/* decode message header and find the transaction */
	decode_header(buf, &cntl_flag, &txn_id, &msg_id, &msg_len);
	buf += QMI_HEADER_SIZE;
	len -= QMI_HEADER_SIZE;

	if (msg_len != len)
	{
		QCCI_LOG_ERR("Received msg len(%d) and header msg_len(%d)"
			" are not matching\n", len, msg_len);
		return QMI_INTERNAL_ERR;
	}

	qcci_log_rx(clnt, cntl_flag, txn_id, msg_id, buf, len, QMI_NO_ERR);

	QCCI_OS_LOCK(&clnt->lock);

	if (clnt->category != QCCI_CONNECTED_CLIENT) {
		QCCI_LOG_ERR("Received msg to invalid client svc_id: %d\n",
				clnt->service_obj->service_id);
		QCCI_OS_UNLOCK(&clnt->lock);
		return QMI_INTERNAL_ERR;
	}

	QCCI_OS_UNLOCK(&clnt->lock);

	if (cntl_flag == QMI_RESPONSE_CONTROL_FLAG)
		return qcci_txn_rx_process_resp(clnt, txn_id,
						msg_id, buf, len);
	else if (cntl_flag == QMI_INDICATION_CONTROL_FLAG)
		return qcci_txn_rx_process_ind(clnt, msg_id, buf, len);
	else {
		QCCI_LOG_ERR("cntl_flag invalid. svc_id: %d cntl_flag: %d",
				clnt->service_obj->service_id, cntl_flag);
		return QMI_INTERNAL_ERR;
	}
}

/**
 * @brief Signal the infrastructure of a server unreachable event with an error code.
 *
 * This function is used by the transport to signal the infrastructure of a
 * server unreachable event with an error code.
 *
 * @param[in] clnt Pointer to infrastructure's client struct.
 * @param[in] addr Pointer to source address.
 * @param[in] error Error type in connection termination.
 */
void qcci_xport_event_server_error(
	qcci_client_type	*clnt,
	void			*addr,
	int			error)
{
	qmi_client_error_cb err_cb = NULL;
	qmi_client_notify_cb notify_cb = NULL;
	QMI_CCI_OS_SIGNAL *ext_signal = NULL;
	void *cb_data;

	if (!clnt)
		return;

	/* signal notifier of the event */
	QCCI_OS_LOCK(&clnt->lock);

	if (clnt->category == QCCI_NOTIFIER_CLIENT) {
		ext_signal = clnt->info.notifier.ext_signal;
		notify_cb = clnt->info.notifier.notify_cb;
		cb_data   = clnt->info.notifier.notify_cb_data;
	} else if (clnt->category == QCCI_CONNECTED_CLIENT) {
		if (memcmp(addr, clnt->info.client.server_addr,
			  clnt->xport_addr_len) == 0) {
			memset(clnt->info.client.server_addr, 0,
					QCCI_MAX_ADDR_LEN);
			clnt->category = QCCI_DORMANT_CLIENT;
			err_cb = clnt->info.client.err_cb;
			cb_data = clnt->info.client.err_cb_data;
			if (!err_cb)
				clnt->info.client.err_pending = 1;
		} else {
			QCCI_OS_UNLOCK(&clnt->lock);
			return;
		}
	}

	qcci_client_txns_cleanup(clnt, error);

	QCCI_OS_UNLOCK(&clnt->lock);

	if (ext_signal)
		QMI_CCI_OS_SIGNAL_SET(ext_signal);

	if (err_cb)
		err_cb(QCCI_CLIENT_HANDLE(clnt), error, cb_data);

	if (notify_cb)
		notify_cb(QCCI_CLIENT_HANDLE(clnt), clnt->service_obj,
			  QMI_CLIENT_SERVICE_COUNT_DEC, cb_data);
}


/**
 * @brief One time initialization of the QCCI stack.
 *
 * This function performs a one-time initialization of the QCCI stack.
 *
 * @param[in] xport_ops Pointer to the transport operations structure.
 * @param[in] xport_data Pointer to the transport data.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 *
 * @note This function is NOT re-enterable or thread safe. The only safe place
 *       to call this is during initialization.
 */
qmi_cci_error_type qcci_init(
	qcci_xport_ops_type	*xport_ops,
	void			*xport_data)
{
	if (!xport_ops) {
		return QMI_CLIENT_PARAM_ERR;
	}

	if (qcci_fw_inited == 0) {

		//qcci_os_init();

		qcci_xport_ops = xport_ops;
		qcci_xport_data = xport_data;

		QCCI_OS_LOCK_INIT(&qcci_cmn_lock);

		qcci_fw_inited = 1;
	}

	return QMI_NO_ERR;
}

/**
 * @brief De-initialization of the QCCI stack.
 *
 * This function performs de-initialization of the QCCI stack.
 *
 * @retval QMI_NO_ERR Success.
 *
 * @note This function is NOT re-enterable or thread safe. The only safe place
 *       to call this is during library de-initialization.
 */
qmi_cci_error_type qcci_deinit(void)
{
	if (qcci_fw_inited) {
		qcci_fw_inited = 0;
		QCCI_OS_LOCK_DEINIT(&qcci_cmn_lock);
		qcci_xport_ops = NULL;
		qcci_xport_data = NULL;
	}

	return QMI_NO_ERR;
}

/**
 * @brief Initialize a notifier client.
 *
 * This function initializes a notifier client.
 *
 * @param[in] service_obj Service object.
 * @param[in] os_params Pointer to OS parameters.
 * @param[out] user_handle Pointer to store the user handle.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 */
qmi_cci_error_type qmi_cci_notifier_init(
	qmi_idl_service_object_type	service_obj,
	qmi_client_os_params		*os_params,
	qmi_client_type			*user_handle)
{
	return qcci_client_cmn_init(NULL, service_obj, NULL, NULL, os_params,
				user_handle, QCCI_NOTIFIER_CLIENT);
}

/**
 * @brief Initialize a connected client.
 *
 * This function initializes a connected client.
 *
 * @param[in] service_info Pointer to the service information.
 * @param[in] service_obj Service object.
 * @param[in] ind_cb Indication callback function.
 * @param[in] ind_cb_data Pointer to indication callback data.
 * @param[in] os_params Pointer to OS parameters.
 * @param[out] user_handle Pointer to store the user handle.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 */
qmi_cci_error_type qmi_cci_init(
	qmi_service_info		*service_info,
	qmi_idl_service_object_type	service_obj,
	qmi_client_ind_cb		ind_cb,
	void				*ind_cb_data,
	qmi_client_os_params		*os_params,
	qmi_client_type			*user_handle)
{
	return qcci_client_cmn_init(service_info, service_obj, ind_cb,
				ind_cb_data, os_params,
				user_handle, QCCI_CONNECTED_CLIENT);
}

/**
 * @brief Send a raw message asynchronously.
 *
 * This function sends a raw message asynchronously.
 *
 * @param[in] user_handle User handle.
 * @param[in] msg_id Message ID.
 * @param[in] req_buf Pointer to the request buffer.
 * @param[in] req_buf_len Length of the request buffer.
 * @param[in] resp_buf Pointer to the response buffer.
 * @param[in] resp_buf_len Length of the response buffer.
 * @param[in] resp_cb Response callback function.
 * @param[in] resp_cb_data Pointer to response callback data.
 * @param[out] txn_handle Pointer to store the transaction handle.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 */
qmi_cci_error_type qmi_cci_send_raw_msg_async(
	qmi_client_type				user_handle,
	unsigned int				msg_id,
	void					*req_buf,
	unsigned int				req_buf_len,
	void					*resp_buf,
	unsigned int				resp_buf_len,
	qmi_client_recv_raw_msg_async_cb	resp_cb,
	void					*resp_cb_data,
	qmi_txn_handle				*txn_handle)
{
	return qcci_send_msg_async(user_handle, msg_id,
			req_buf, req_buf_len,
			resp_buf, resp_buf_len,
			resp_cb, resp_cb_data,
			TXN_ASYNC_RAW, txn_handle);
}

/**
 * @brief Send a message asynchronously.
 *
 * This function sends a message asynchronously.
 *
 * @param[in] user_handle User handle.
 * @param[in] msg_id Message ID.
 * @param[in] req_c_struct Pointer to the request C structure.
 * @param[in] req_c_struct_len Length of the request C structure.
 * @param[in] resp_c_struct Pointer to the response C structure.
 * @param[in] resp_c_struct_len Length of the response C structure.
 * @param[in] resp_cb Response callback function.
 * @param[in] resp_cb_data Pointer to response callback data.
 * @param[out] txn_handle Pointer to store the transaction handle.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 */
qmi_cci_error_type qmi_cci_send_msg_async(
	qmi_client_type			user_handle,
	unsigned int			msg_id,
	void				*req_c_struct,
	unsigned int			req_c_struct_len,
	void				*resp_c_struct,
	unsigned int			resp_c_struct_len,
	qmi_client_recv_msg_async_cb	resp_cb,
	void				*resp_cb_data,
	qmi_txn_handle			*txn_handle)
{
	return qcci_send_msg_async(user_handle, msg_id,
			req_c_struct, req_c_struct_len,
			resp_c_struct, resp_c_struct_len,
			resp_cb, resp_cb_data,
			TXN_ASYNC_MSG, txn_handle);
}

/**
 * @brief Delete an asynchronous transaction.
 *
 * This function deletes an asynchronous transaction.
 *
 * @param[in] user_handle User handle.
 * @param[in] async_txn_handle Asynchronous transaction handle.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 * @retval QMI_CLIENT_INVALID_CLNT Invalid client.
 * @retval QMI_INVALID_TXN Invalid transaction.
 */
qmi_cci_error_type qmi_cci_delete_async_txn(
	qmi_client_type	user_handle,
	qmi_txn_handle	async_txn_handle)
{
	qcci_client_type *clnt;
	qcci_txn_type *txn;
	qcci_txn_type *find_txn = (qcci_txn_type *)async_txn_handle;
	int rc = QMI_INVALID_TXN;

	if (!async_txn_handle)
		return QMI_CLIENT_PARAM_ERR;

	clnt = qcci_client_get_ref(user_handle, 0);
	if (!clnt)
		return QMI_CLIENT_INVALID_CLNT;

	QCCI_OS_LOCK(&clnt->lock);
	if (clnt->category == QCCI_NOTIFIER_CLIENT) {
		QCCI_OS_UNLOCK(&clnt->lock);
		rc = QMI_CLIENT_INVALID_CLNT;
		goto bail;
	}

	/* Find and remove txn from tx queue first */
	LIST_FIND(clnt->info.client.tx_q, txn, tx_link, txn == find_txn);
	if (txn) {
		QCCI_TXN_TX_BUF_INVALIDATE(txn);
		LIST_REMOVE(clnt->info.client.tx_q, txn, tx_link);
		/* Release the tx_q ref count */
		qcci_txn_put_ref_unsafe(txn);
	}

	/* Look for txn */
	LIST_FIND(clnt->info.client.txn_list, txn, link, txn == find_txn);
	if (txn)
		LIST_REMOVE(clnt->info.client.txn_list, txn, link);

	if (txn) {
		QCCI_TXN_RX_BUF_INVALIDATE(txn);
		qcci_txn_put_ref_unsafe(txn);
		rc = QMI_NO_ERR;
	}

	QCCI_OS_UNLOCK(&clnt->lock);

bail:
	qcci_client_put_ref(clnt);
	return rc;
}

/**
 * @brief Send a raw message synchronously.
 *
 * This function sends a raw message synchronously.
 *
 * @param[in] user_handle User handle.
 * @param[in] msg_id Message ID.
 * @param[in] req_buf Pointer to the request buffer.
 * @param[in] req_buf_len Length of the request buffer.
 * @param[in] resp_buf Pointer to the response buffer.
 * @param[in] resp_buf_len Length of the response buffer.
 * @param[out] resp_buf_recv_len Pointer to store the received response length.
 * @param[in] timeout_msecs Timeout in milliseconds.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 * @retval QMI_CLIENT_INVALID_CLNT Invalid client.
 */
qmi_cci_error_type qmi_client_send_raw_msg_sync(
	qmi_client_type	user_handle,
	unsigned int	msg_id,
	void		*req_buf,
	unsigned int	req_buf_len,
	void		*resp_buf,
	unsigned int	resp_buf_len,
	unsigned int	*resp_buf_recv_len,
	unsigned int	timeout_msecs)
{
  return qcci_send_msg_sync(user_handle, msg_id,
			req_buf, req_buf_len,
			resp_buf, resp_buf_len,
			TXN_SYNC_RAW, resp_buf_recv_len, timeout_msecs);
}

/**
 * @brief Send a message synchronously.
 *
 * This function sends a message synchronously.
 *
 * @param[in] user_handle User handle.
 * @param[in] msg_id Message ID.
 * @param[in] req_c_struct Pointer to the request C structure.
 * @param[in] req_c_struct_len Length of the request C structure.
 * @param[in] resp_c_struct Pointer to the response C structure.
 * @param[in] resp_c_struct_len Length of the response C structure.
 * @param[in] timeout_msecs Timeout in milliseconds.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 * @retval QMI_CLIENT_INVALID_CLNT Invalid client.
 */
qmi_cci_error_type qmi_cci_send_msg_sync(
	qmi_client_type	user_handle,
	unsigned int	msg_id,
	void		*req_c_struct,
	unsigned int	req_c_struct_len,
	void		*resp_c_struct,
	unsigned int	resp_c_struct_len,
	unsigned int	timeout_msecs)
{
  return qcci_send_msg_sync(user_handle, msg_id,
			req_c_struct, req_c_struct_len,
			resp_c_struct, resp_c_struct_len,
			TXN_SYNC_MSG, NULL, timeout_msecs);
}

/**
 * @brief Release a client asynchronously.
 *
 * This function releases a client asynchronously.
 *
 * @param[in] user_handle User handle.
 * @param[in] release_cb Release callback function.
 * @param[in] release_cb_data Pointer to release callback data.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_INVALID_CLNT Invalid client.
 */
qmi_cci_error_type qmi_cci_release_async(
	qmi_client_type		user_handle,
	qmi_client_release_cb	release_cb,
	void			*release_cb_data)
{
	qcci_client_type *clnt;

	clnt = qcci_client_get_ref(user_handle, 1);
	if (!clnt)
		return QMI_CLIENT_INVALID_CLNT;

	QCCI_OS_LOCK(&clnt->lock);

	if (clnt->category != QCCI_NOTIFIER_CLIENT) {
		/* From now on all calls to qcci_send will fail */
		clnt->info.client.accepting_txns = 0;
	}

	qcci_client_txns_cleanup(clnt, QMI_INTERNAL_ERR);

	clnt->release_cb = release_cb;
	clnt->release_cb_data = release_cb_data;

	qcci_xport_ops->close(clnt->xport_handle);
	clnt->xport_handle = NULL;

	QCCI_OS_UNLOCK(&clnt->lock);

	qcci_client_put_ref(clnt);

	return QMI_NO_ERR;
}
/**
 * @brief Release a client.
 *
 * This function releases a client.
 *
 * @param[in] user_handle User handle.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_INVALID_CLNT Invalid client.
 */
qmi_cci_error_type qmi_cci_release(qmi_client_type user_handle)
{
	qcci_client_type *clnt;
	qmi_cci_error_type rc;
	QMI_CCI_OS_SIGNAL signal;

	clnt = qcci_client_get_ref(user_handle, 0);
	if (!clnt)
		return QMI_CLIENT_INVALID_CLNT;

	QMI_CCI_OS_SIGNAL_INIT_SELF(&signal, &clnt->signal);
	QMI_CCI_OS_SIGNAL_CLEAR(&signal);

	/* Release this call's reference */
	qcci_client_put_ref(clnt);

	rc = qmi_cci_release_async(user_handle, qcci_client_release_cb_internal,
				      (void *)&signal);

	if (rc == QMI_NO_ERR)
		QMI_CCI_OS_SIGNAL_WAIT(&signal, 0);

	QMI_CCI_OS_SIGNAL_DEINIT(&signal);
	return rc;
}

/**
 * @brief Encode a message.
 *
 * This function encodes a message.
 *
 * @param[in] user_handle User handle.
 * @param[in] req_resp_ind Type of message (request, response, or indication).
 * @param[in] message_id Message ID.
 * @param[in] p_src Pointer to the source buffer.
 * @param[in] src_len Length of the source buffer.
 * @param[out] p_dst Pointer to the destination buffer.
 * @param[in] dst_len Length of the destination buffer.
 * @param[out] dst_encoded_len Pointer to store the encoded length.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_INVALID_CLNT Invalid client.
 */
qmi_cci_error_type qmi_cci_message_encode(
	qmi_client_type			user_handle,
	qmi_idl_type_of_message_type	req_resp_ind,
	unsigned int			message_id,
	const void			*p_src,
	unsigned int			src_len,
	void				*p_dst,
	unsigned int			dst_len,
	unsigned int			*dst_encoded_len)
{
	qcci_client_type *clnt;
	qmi_idl_service_object_type service_obj;

	clnt = qcci_client_get_ref(user_handle, 0);
	if (!clnt)
		return QMI_CLIENT_INVALID_CLNT;

	service_obj = clnt->service_obj;
	qcci_client_put_ref(clnt);

	return qmi_idl_message_encode(
		       service_obj,
		       req_resp_ind,
		       (uint16_t)message_id,
		       p_src,
		       src_len,
		       p_dst,
		       dst_len,
		       (uint32_t*)dst_encoded_len);
}

/**
 * @brief Decode a message.
 *
 * This function decodes a message.
 *
 * @param[in] user_handle User handle.
 * @param[in] req_resp_ind Type of message (request, response, or indication).
 * @param[in] message_id Message ID.
 * @param[in] p_src Pointer to the source buffer.
 * @param[in] src_len Length of the source buffer.
 * @param[out] p_dst Pointer to the destination buffer.
 * @param[in] dst_len Length of the destination buffer.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_INVALID_CLNT Invalid client.
 */
qmi_cci_error_type qmi_cci_message_decode(
	qmi_client_type			user_handle,
	qmi_idl_type_of_message_type	req_resp_ind,
	unsigned int			message_id,
	const void			*p_src,
	unsigned int			src_len,
	void				*p_dst,
	unsigned int			dst_len)
{
	qcci_client_type *clnt;
	qmi_idl_service_object_type service_obj;

	clnt = qcci_client_get_ref(user_handle, 0);
	if(!clnt)
		return QMI_CLIENT_INVALID_CLNT;

	service_obj = clnt->service_obj;
	qcci_client_put_ref(clnt);

	return qmi_idl_message_decode(
		       service_obj,
		       req_resp_ind,
		       (uint16_t)message_id,
		       p_src,
		       src_len,
		       p_dst,
		       dst_len);
}
/**
 * @brief Get the service list.
 *
 * This function gets the service list.
 *
 * @param[in] service_obj Service object.
 * @param[out] service_info_array Pointer to the service information array.
 * @param[in,out] num_entries Pointer to the number of entries.
 * @param[out] num_services Pointer to the number of services.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 * @retval QMI_SERVICE_ERR Service error.
 */
qmi_cci_error_type qmi_cci_get_service_list(
	qmi_idl_service_object_type	service_obj,
	qmi_service_info		*service_info_array,
	unsigned int			*num_entries,
	unsigned int			*num_services)
{
	qcci_service_info *svc = (qcci_service_info *)service_info_array;
	unsigned int entries = 0;
	uint32_t service_id, idl_version;
	int rc;

	if (!num_services)
		return QMI_CLIENT_PARAM_ERR;

	*num_services = 0;

	if (num_entries && *num_entries && svc) {
		entries = *num_entries;
		*num_entries = 0;
	}

	/* Extract service id */
	rc = qmi_idl_get_service_id(service_obj, &service_id);
	if (rc !=  QMI_IDL_LIB_NO_ERR)
		return rc;

	/* Get IDL version */
	rc = qmi_idl_get_idl_version(service_obj, &idl_version);
	if (rc !=  QMI_IDL_LIB_NO_ERR)
		return rc;

	/* go through all the xports and find the service */
	QCCI_OS_LOCK(&qcci_cmn_lock);

	*num_services = qcci_xport_ops->lookup(
				qcci_xport_data,
				1, service_id, idl_version,
				entries ? (uint32_t*)&entries : NULL,
				entries ? svc : NULL);
	QCCI_OS_UNLOCK(&qcci_cmn_lock);

	if (num_entries)
		(*num_entries) = *num_services ? entries : 0;;

	return *num_services ? QMI_NO_ERR : QMI_SERVICE_ERR;
}

#ifndef QMI_CLIENT_INSTANCE_ANY
#define QMI_CLIENT_INSTANCE_ANY 0xffff

/**
 * @brief Get any service.
 *
 * This function gets any service.
 *
 * @param[in] service_obj Service object.
 * @param[out] service_info Pointer to the service information.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 */
qmi_cci_error_type qmi_cci_get_any_service(
	qmi_idl_service_object_type	service_obj,
	qmi_service_info		*service_info)
{
	return qmi_cci_get_service_instance(service_obj,
				QMI_CLIENT_INSTANCE_ANY, service_info);
}
#endif

/**
 * @brief Get a specific service instance.
 *
 * This function gets a specific service instance.
 *
 * @param[in] service_obj Service object.
 * @param[in] instance_id Instance ID.
 * @param[out] service_info Pointer to the service information.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 */
qmi_cci_error_type qmi_cci_get_service_instance(
	qmi_idl_service_object_type	service_obj,
	qmi_service_instance		instance_id,
	qmi_service_info		*service_info)
{
	unsigned int num_entries = 1, num_services, i;
	qmi_cci_error_type rc;
	qmi_service_info *service_array;

	if (!service_info)
		return QMI_CLIENT_PARAM_ERR;

	if (instance_id == QMI_CLIENT_INSTANCE_ANY) {
		return qmi_cci_get_service_list(service_obj, service_info,
						&num_entries, &num_services);
	}

	rc = qmi_cci_get_service_list(service_obj, NULL,
					NULL, &num_services);
	if (rc != QMI_NO_ERR)
		return rc;

	service_array = QCCI_OS_MALLOC(sizeof(*service_array) * num_services);
	if (!service_array)
		return QMI_CLIENT_ALLOC_FAILURE;

	num_entries = num_services;
	rc = qmi_cci_get_service_list(service_obj, service_array,
					&num_entries, &num_services);
	if (rc != QMI_NO_ERR)
		goto free_bail;

	rc = QMI_SERVICE_ERR;
	for (i = 0; i < num_entries; i++) {
		qcci_service_info *svc;
		svc = (qcci_service_info *)&service_array[i];
		if (svc->instance == instance_id) {
			memcpy(service_info, svc, sizeof(qmi_service_info));
			rc = QMI_NO_ERR;
			break;
		}
	}

free_bail:
	QCCI_OS_FREE(service_array);
	return rc;
}

/**
 * @brief Get the instance ID from the service information.
 *
 * This function gets the instance ID from the service information.
 *
 * @param[in] service_info Pointer to the service information.
 * @param[out] instance_id Pointer to store the instance ID.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 */
qmi_cci_error_type qmi_cci_get_instance_id(
	qmi_service_info	*service_info,
	qmi_service_instance	*instance_id)
{
	qcci_service_info *svc = (qcci_service_info *)service_info;

	if (!svc || !instance_id)
		return QMI_CLIENT_PARAM_ERR;

	*instance_id = svc->instance;
	return QMI_NO_ERR;
}

/**
 * @brief Register a log callback.
 *
 * This function registers a log callback.
 *
 * @param[in] user_handle User handle.
 * @param[in] log_cb Log callback function.
 * @param[in] log_cb_data Pointer to log callback data.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 * @retval QMI_CLIENT_INVALID_CLNT Invalid client.
 */
qmi_cci_error_type qmi_cci_register_log_cb(
	qmi_client_type		user_handle,
	qmi_client_log_cb	log_cb,
	void			*log_cb_data)
{
	qcci_client_type *clnt;
	int rc = QMI_CLIENT_INVALID_CLNT;

	if (!log_cb)
		return QMI_CLIENT_PARAM_ERR;

	clnt = qcci_client_get_ref(user_handle, 0);
	if (!clnt)
		return QMI_CLIENT_INVALID_CLNT;

	QCCI_OS_LOCK(&clnt->lock);
	if (clnt->category == QCCI_CONNECTED_CLIENT) {
		clnt->info.client.log_cb_data = log_cb_data;
		clnt->info.client.log_cb = log_cb;
		rc = QMI_NO_ERR;
	}
	QCCI_OS_UNLOCK(&clnt->lock);
	qcci_client_put_ref(clnt);
	return rc;
}

/**
 * @brief Register an error callback.
 *
 * This function registers an error callback.
 *
 * @param[in] user_handle User handle.
 * @param[in] err_cb Error callback function.
 * @param[in] err_cb_data Pointer to error callback data.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 * @retval QMI_CLIENT_INVALID_CLNT Invalid client.
 * @retval QMI_SERVICE_ERR Service error.
 */
qmi_cci_error_type qmi_cci_register_error_cb(
	qmi_client_type		user_handle,
	qmi_client_error_cb	err_cb,
	void 			*err_cb_data)
{
	qcci_client_type *clnt;
	unsigned int err_pending = 0;
	int rc = QMI_NO_ERR;

	if (!err_cb)
		return QMI_CLIENT_PARAM_ERR;

	clnt = qcci_client_get_ref(user_handle, 0);
	if (!clnt)
		return QMI_CLIENT_INVALID_CLNT;

	/* Do not allow error callback registration
	 * on the notifier as it is not connected to any
	 * physical service */
	QCCI_OS_LOCK(&clnt->lock);
	if (clnt->category == QCCI_NOTIFIER_CLIENT) {
		rc = QMI_CLIENT_INVALID_CLNT;
	} else {
		clnt->info.client.err_cb = err_cb;
		clnt->info.client.err_cb_data = err_cb_data;
		err_pending = clnt->info.client.err_pending;
	}
	QCCI_OS_UNLOCK(&clnt->lock);

	if (err_pending) {
		err_cb(QCCI_CLIENT_HANDLE(clnt), QMI_SERVICE_ERR, err_cb_data);
		rc = QMI_SERVICE_ERR;
	}

	qcci_client_put_ref(clnt);
	return rc;
}

/**
 * @brief Register a notify callback.
 *
 * This function registers a notify callback.
 *
 * @param[in] user_handle User handle.
 * @param[in] notify_cb Notify callback function.
 * @param[in] notify_cb_data Pointer to notify callback data.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 * @retval QMI_CLIENT_INVALID_CLNT Invalid client.
 */
qmi_cci_error_type qmi_cci_register_notify_cb
(
	qmi_client_type user_handle,
	qmi_client_notify_cb notify_cb,
	void *notify_cb_data
)
{
	qcci_client_type *clnt;
	unsigned int notify_pending = 0;
	int rc = QMI_NO_ERR;

	if (!notify_cb)
		return QMI_CLIENT_PARAM_ERR;

	clnt = qcci_client_get_ref(user_handle, 0);
	if (!clnt)
		return QMI_CLIENT_INVALID_CLNT;

	QCCI_OS_LOCK(&clnt->lock);
	if (clnt->category != QCCI_NOTIFIER_CLIENT) {
		/* Do not allow notify callback registration
		 * on a connected or dormant client */
		rc = QMI_CLIENT_INVALID_CLNT;
	} else {
		clnt->info.notifier.notify_cb = notify_cb;
		clnt->info.notifier.notify_cb_data = notify_cb_data;
		notify_pending = clnt->info.notifier.notify_pending;
	}
	QCCI_OS_UNLOCK(&clnt->lock);

	if (notify_pending) {
		notify_cb(QCCI_CLIENT_HANDLE(clnt), clnt->service_obj,
			  QMI_CLIENT_SERVICE_COUNT_INC, notify_cb_data);
	}
	qcci_client_put_ref(clnt);
	return rc;
}

/**
 * @brief Get a transaction ID from the transaction handle.
 *
 * This function gets a transaction ID from the transaction handle.
 *
 * @param[in] user_handle User handle.
 * @param[in] async_txn_handle Asynchronous transaction handle.
 * @param[out] txn_id Pointer to store the transaction ID.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 * @retval QMI_CLIENT_INVALID_CLNT Invalid client.
 */
qmi_cci_error_type qmi_client_get_async_txn_id(
	qmi_client_type	user_handle,
	qmi_txn_handle	async_txn_handle,
	uint32_t	*txn_id)
{
	qcci_txn_type *i;
	qcci_client_type *clnt;
	qcci_txn_type *txn = (qcci_txn_type *)async_txn_handle;
	qmi_cci_error_type rc = QMI_INVALID_TXN;

	if (!txn_id || !txn)
		return QMI_CLIENT_PARAM_ERR;

	clnt = qcci_client_get_ref(user_handle, 0);
	if(!clnt)
		return QMI_CLIENT_INVALID_CLNT;

	*txn_id = 0;

	QCCI_OS_LOCK(&clnt->lock);
	if (clnt->category == QCCI_NOTIFIER_CLIENT) {
		rc = QMI_CLIENT_INVALID_CLNT;
		QCCI_OS_UNLOCK(&clnt->lock);
		goto bail;
	}
	QCCI_OS_UNLOCK(&clnt->lock);

	QCCI_OS_LOCK(&clnt->lock);
	LIST_FIND(clnt->info.client.txn_list, i, link, i == txn);
	if (i) {
		*txn_id = i->txn_id;
		rc = QMI_NO_ERR;
	}
	QCCI_OS_UNLOCK(&clnt->lock);

bail:
	qcci_client_put_ref(clnt);

	return rc;
}

/**
 * @brief Initialize a client instance.
 *
 * This function initializes a client instance.
 *
 * @param[in] service_obj Service object.
 * @param[in] instance_id Instance ID.
 * @param[in] ind_cb Indication callback function.
 * @param[in] ind_cb_data Pointer to indication callback data.
 * @param[in] os_params Pointer to OS parameters.
 * @param[in] timeout Timeout in milliseconds.
 * @param[out] user_handle Pointer to store the user handle.
 *
 * @retval QMI_NO_ERR Success.
 * @retval QMI_CLIENT_PARAM_ERR Parameter error.
 * @retval QMI_SERVICE_ERR Service error.
 * @retval QMI_TIMEOUT_ERR Timeout error.
 */
qmi_cci_error_type qmi_cci_init_instance(
	qmi_idl_service_object_type	service_obj,
	qmi_service_instance		instance_id,
	qmi_client_ind_cb		ind_cb,
	void				*ind_cb_data,
	qmi_client_os_params		*os_params,
	uint32_t			timeout,
	qmi_client_type			*user_handle)
{
	qmi_cci_error_type rc;
	qmi_client_type notifier;
	qmi_service_info info;
	qmi_client_os_params notifier_os_params;

	if (!user_handle || !service_obj)
		return QMI_CLIENT_PARAM_ERR;

	/* The common case when we do not have to wait for the service,
	 * avoid creation of the notifier */
	rc = qmi_cci_get_service_instance(service_obj, instance_id, &info);
	if (rc == QMI_NO_ERR) {
		rc = qmi_cci_init(&info, service_obj, ind_cb,
				ind_cb_data, os_params, user_handle);
		if (rc == QMI_NO_ERR || rc != QMI_SERVICE_ERR)
			return rc;
	}

	memset(&notifier_os_params, 0, sizeof(notifier_os_params));
	QMI_CCI_COPY_OS_PARAMS(&notifier_os_params, os_params);

	rc = qmi_cci_notifier_init(service_obj, &notifier_os_params,
					&notifier);
	if (rc != QMI_NO_ERR)
		return rc;

	while (1) {
		QMI_CCI_OS_SIGNAL_CLEAR(&notifier_os_params);
		rc = qmi_cci_get_service_instance(service_obj,
						instance_id, &info);
		if (rc == QMI_NO_ERR) {
			rc = qmi_cci_init(&info, service_obj,
					ind_cb, ind_cb_data,
					os_params, user_handle);
			/* Success or a generic error occured */
			if (rc == QMI_NO_ERR || rc != QMI_SERVICE_ERR)
				break;
		}
		QMI_CCI_OS_SIGNAL_WAIT(&notifier_os_params, timeout);
		if (QMI_CCI_OS_SIGNAL_TIMED_OUT(&notifier_os_params)) {
			rc = QMI_TIMEOUT_ERR;
			break;
		}
	}
	qmi_cci_release(notifier);
	return rc;
}
