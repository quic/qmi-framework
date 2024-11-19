// Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
/**
 * @file    qcsi_common.c
 * @brief   The QMI Common Service Interface (CSI)
 *
 * @details
 * QMI common server routines. All servers will be built on top of these
 * routines for initializing, sending responses, and indications.
 */
#include <string.h>
#include "qmi_idl_lib.h"
#include "qcsi.h"
#include "qcsi_os.h"
#include "qcsi_common.h"
#include "common_v01.h"
#include <limits.h>

#define MAX_XPORTS 10
#define QCSI_MIN(a, b) ((a) > (b) ? (b) : (a))

static int qcsi_fw_inited = 0;
static void *qcsi_xport_data;
static qcsi_xport_ops_type *qcsi_xport_ops;
extern void qcsi_debug_init(void);
#define DEFAULT_MAX_TX_BUFS (30)

/* Global lists of services, clients and outstanding txns */
static qcsi_lock_type service_list_lock;
static LIST(qcsi_service_type, service_list);
static qcsi_lock_type client_list_lock;
static LIST(qcsi_client_type, client_list);
static qcsi_lock_type txn_list_lock;
static LIST(qcsi_txn_type, txn_list);

/* Globally unique service, client and txn descriptors - monotonically
 * increasing numbers. Use list locks to protect these
 */
static uint32_t global_service_desc;
static uint32_t global_client_desc;
static uint32_t global_txn_desc;

struct qcsi_xport_tbl_s {
	qcsi_xport_ops_type *ops;
	void *xport_data;
};

static uint32_t inited;

/**
 * @brief Translate QCSI errors to common error types.
 *
 * This function translates QCSI errors to common error types.
 *
 * @param[in] csi_err QCSI error code.
 *
 * @retval QMI_ERR_NONE_V01 No error.
 * @retval QMI_ERR_CLIENT_IDS_EXHAUSTED_V01 Client IDs exhausted.
 * @retval QMI_ERR_ENCODING_V01 Encoding error.
 * @retval QMI_ERR_NO_MEMORY_V01 No memory.
 * @retval QMI_ERR_INTERNAL_V01 Internal error.
 */
static uint16_t qcsi_err_translate(uint32_t csi_err)
{
	qmi_error_type_v01 rc = QMI_ERR_INTERNAL_V01;
	switch(csi_err) {
	case QCSI_NO_ERR:
		rc = QMI_ERR_NONE_V01;
		break;
	case QCSI_CONN_REFUSED:
		rc = QMI_ERR_CLIENT_IDS_EXHAUSTED_V01;
		break;
	case QCSI_ENCODE_ERR:
	case QCSI_DECODE_ERR:
		rc = QMI_ERR_ENCODING_V01;
		break;
	case QCSI_NO_MEM:
		rc = QMI_ERR_NO_MEMORY_V01;
		break;
	default:
		rc = QMI_ERR_INTERNAL_V01;
		break;
	}
	return (uint32_t)rc;
}

/**
 * @brief Add a service to the global list.
 *
 * This function adds a service to the global list.
 *
 * @param[in] svc Pointer to the service structure.
 *
 * @retval Service handle.
 */
static uint32_t add_service(qcsi_service_type *svc)
{
	uint32_t service_handle;

	LOCK(&service_list_lock);
	service_handle = svc->handle = ++global_service_desc;
	LIST_ADD(service_list, svc, link);
	UNLOCK(&service_list_lock);

	return service_handle;
}

/**
 * @brief Remove a service from the global list.
 *
 * This function removes a service from the global list.
 *
 * @param[in] svc Pointer to the service structure.
 */
static void remove_service(qcsi_service_type *svc)
{
	LOCK(&service_list_lock);
	LIST_REMOVE(service_list, svc, link);
	UNLOCK(&service_list_lock);
}

/**
 * @brief Find a service in the global list.
 *
 * This function finds a service in the global list.
 *
 * @param[in] handle Service handle.
 *
 * @retval Pointer to the service structure.
 */
static qcsi_service_type *find_service(uint32_t handle)
{
	qcsi_service_type *svc = LIST_HEAD(service_list);

	while(svc) {
		if(svc->handle == handle)
			return svc;
		svc = svc->link.next;
	}
	return NULL;
}

/**
 * @brief Add a client to the service and global client lists.
 *
 * This function adds a client to the service and global client lists.
 *
 * @param[in] svc Pointer to the service structure.
 * @param[in] clnt Pointer to the client structure.
 */
static void add_client(qcsi_service_type *svc, qcsi_client_type *clnt)
{
	/* set unique client handle */
	clnt->handle = ++global_client_desc;
	LIST_ADD(svc->client_list, clnt, local);
	LIST_ADD(client_list, clnt, global);
}

/**
 * @brief Remove a client from the service and global client lists.
 *
 * This function removes a client from the service and global client lists.
 *
 * @param[in] svc Pointer to the service structure.
 * @param[in] clnt Pointer to the client structure.
 */
static void remove_client(qcsi_service_type *svc, qcsi_client_type *clnt)
{
	LIST_REMOVE(svc->client_list, clnt, local);
	LIST_REMOVE(client_list, clnt, global);
}

/**
 * @brief Find a client in the global client list.
 *
 * This function finds a client in the global client list.
 *
 * @param[in] handle Client handle.
 *
 * @retval Pointer to the client structure.
 */
static qcsi_client_type *find_client(uint32_t handle)
{
	qcsi_client_type *clnt = LIST_HEAD(client_list);

	while(clnt) {
		if(clnt->handle == handle)
			return clnt;
		clnt = clnt->global.next;
	}
	return NULL;
}

/**
 * @brief Add a transaction to the client and global transaction lists.
 *
 * This function adds a transaction to the client and global transaction lists.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] txn Pointer to the transaction structure.
 *
 * @retval Transaction handle.
 */
static uint32_t add_txn(qcsi_client_type *clnt, qcsi_txn_type *txn)
{
	txn->handle = ++global_txn_desc;
	LIST_ADD(clnt->txn_list, txn, local);
	LIST_ADD(txn_list, txn, global);
	return txn->handle;
}

/**
 * @brief Remove a transaction from the client and global transaction lists.
 *
 * This function removes a transaction from the client and global transaction lists.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] txn Pointer to the transaction structure.
 */
static void remove_txn(qcsi_client_type *clnt, qcsi_txn_type *txn)
{
	LIST_REMOVE(clnt->txn_list, txn, local);
	LIST_REMOVE(txn_list, txn, global);
}

/**
 * @brief Find a transaction in the global transaction list.
 *
 * This function finds a transaction in the global transaction list.
 *
 * @param[in] handle Transaction handle.
 *
 * @retval Pointer to the transaction structure.
 */
static qcsi_txn_type *find_txn(uint32_t handle)
{
	qcsi_txn_type *txn = LIST_HEAD(txn_list);
	while(txn) {
		if(txn->handle == handle)
			return txn;
		txn = txn->global.next;
	}
	return NULL;
}

/**
 * @brief Get a transaction from the client's free list or allocate a new one.
 *
 * This function gets a transaction from the client's free list or allocates a new one.
 *
 * @param[in] clnt Pointer to the client structure.
 * @param[in] txn_id Transaction ID.
 * @param[in] msg_id Message ID.
 * @param[out] txn_handle Pointer to store the transaction handle.
 *
 * @retval Pointer to the transaction structure.
 */
static qcsi_txn_type *get_txn
(
	qcsi_client_type *clnt,
	uint16_t txn_id,
	uint16_t msg_id,
	uint32_t *txn_handle
)
{
	qcsi_txn_type *txn = NULL;
	if(LIST_CNT(clnt->txn_free_list) > 0) {
		txn = LIST_TAIL(clnt->txn_free_list);
		LIST_REMOVE(clnt->txn_free_list, txn, local);
		txn->pool_allocated = 1;
	} else {
		txn = CALLOC(1, sizeof(*txn));
		if(!txn) {
			return NULL;
		}
		/* txn->pool_allocated = 0 (calloc) */
	}
	LINK_INIT(txn->local);
	LINK_INIT(txn->global);
	txn->client = clnt;
	txn->txn_id = txn_id;
	txn->msg_id = msg_id;
	*txn_handle = add_txn(clnt, txn);
	return txn;
}

/**
 * @brief Release a transaction.
 *
 * This function releases a transaction.
 *
 * @param[in] txn Pointer to the transaction structure.
 */
static void release_txn
(
	qcsi_txn_type *txn
)
{
	qcsi_client_type *clnt = txn->client;
	if(txn->pool_allocated) {
		LINK_INIT(txn->local);
		LIST_ADD(clnt->txn_free_list, txn, local);
	} else {
		FREE(txn);
	}
}

/**
 * @brief Find a client by address.
 *
 * This function finds a client by address.
 *
 * @param[in] xport Pointer to the transport structure.
 * @param[in] addr Pointer to the address.
 *
 * @retval Pointer to the client structure.
 */
static qcsi_client_type *find_client_by_addr
(
	qcsi_xport_type *xport,
	void *addr
)
{
	qcsi_client_type *clnt;

	if(!xport || !xport->service)
		return NULL;

	clnt = LIST_HEAD(xport->service->client_list);
	while(clnt) {
		if(clnt->xport.xport == xport &&
		    !memcmp(clnt->xport.addr, addr, xport->addr_len))
			return clnt;
		clnt = clnt->local.next;
	}
	return NULL;
}


/**
 * @brief Clean up all transactions for a client.
 *
 * This function cleans up all transactions for a client.
 *
 * @param[in] clnt Pointer to the client structure.
 */
static void clean_txns(qcsi_client_type *clnt)
{
	qcsi_txn_type *txn;
	LOCK(&txn_list_lock);
	txn = LIST_HEAD(clnt->txn_list);
	while(txn) {
		qcsi_txn_type *to_free = txn;
		txn = txn->local.next;
		/* remove from global txn list */
		LIST_REMOVE(txn_list, to_free, global);
		release_txn(to_free);
	}
	UNLOCK(&txn_list_lock);
}

/**
 * @brief Create a new client.
 *
 * This function creates a new client.
 *
 * @param[in] xport Pointer to the transport structure.
 * @param[in] addr Pointer to the address.
 *
 * @retval Pointer to the client structure.
 */
static qcsi_client_type *create_client
(
	qcsi_xport_type *xport,
	void *addr
)
{
	qcsi_service_type *svc = xport->service;
	qcsi_client_type  *clnt;
	int i;

	/* client not found, create new connection */
	clnt = CALLOC(1, sizeof(qcsi_client_type));
	if(!clnt)
		return NULL;
	LINK_INIT(clnt->local);
	LINK_INIT(clnt->global);
	LIST_INIT(clnt->txn_list);

	for(i = 0; i < TXN_POOL_SIZE; i++) {
		struct qcsi_txn_s *txn = &clnt->txn_pool[i];
		txn->pool_allocated = 1;
		LIST_ADD(clnt->txn_free_list, txn, local);
	}

	add_client(svc, clnt);

	/* initialize client struct fields */
	clnt->service = svc;
	clnt->xport.xport = xport;
	clnt->next_ind_txn_id = 1;
	memcpy(clnt->xport.addr, addr, xport->addr_len);

	return clnt;
}

/**
 * @brief Encode and send a message to the client.
 *
 * This function encodes and sends a message to the client.
 *
 * @param[in] svc Pointer to the service structure.
 * @param[in] clnt Pointer to the client structure.
 * @param[in] msg_id Message ID.
 * @param[in] msg Pointer to the message buffer.
 * @param[in] msg_len Length of the message.
 *
 * @retval QCSI_NO_ERR Success.
 * @retval QCSI_ENCODE_ERR Encoding error.
 * @retval QCSI_TRANSPORT_ERR Transport error.
 */
static qcsi_error internal_send
(
	qcsi_service_type *svc,
	qcsi_client_type *clnt,
	qmi_idl_type_of_message_type msg_type,
	txn_id_type txn_id,
	uint16_t msg_id,
	void *c_struct,
	unsigned int c_struct_len,
	int encode
)
{
	qcsi_xport_type *xport;
	uint32_t max_msg_len = 0, out_len;
	qcsi_error rc;
	int32_t encdec_rc;
	unsigned char *msg;
	uint8_t cntl_flag;
	uint32_t send_flags = 0;

	if(encode) {
		uint32_t idl_c_struct_len;
		encdec_rc = qmi_idl_get_message_c_struct_len(svc->service_obj, msg_type, msg_id,
				&idl_c_struct_len);
		if(encdec_rc != QMI_IDL_LIB_NO_ERR)
			return QCSI_ENCODE_ERR;

		if(c_struct_len != idl_c_struct_len)
			return QCSI_ENCODE_ERR;

		encdec_rc = qmi_idl_get_max_message_len(svc->service_obj, msg_type, msg_id,
							&max_msg_len);
		if(encdec_rc != QMI_IDL_LIB_NO_ERR)
			return QCSI_ENCODE_ERR;
	} else {
		max_msg_len = c_struct_len;
	}

	if(c_struct && c_struct_len) {
		if (max_msg_len > UINT_MAX - QMI_HEADER_SIZE)
			return QCSI_INTERNAL_ERR;

		msg = MALLOC(max_msg_len + QMI_HEADER_SIZE);
		if(!msg)
			return QCSI_NO_MEM;

		if(encode) {
			if( qmi_idl_message_encode(
				    svc->service_obj,
				    msg_type,
				    msg_id,
				    c_struct,
				    c_struct_len,
				    msg + QMI_HEADER_SIZE,
				    max_msg_len,
				    &out_len) != QMI_IDL_LIB_NO_ERR) {
				FREE(msg);
				return QCSI_ENCODE_ERR;
			}
		} else {
			memcpy(msg + QMI_HEADER_SIZE, c_struct, c_struct_len);
			out_len = c_struct_len;
		}
	} else {
		/* Empty message */
		out_len = 0;
		msg = MALLOC(QMI_HEADER_SIZE);
		if(!msg)
			return QCSI_NO_MEM;
	}

	/* Log the encoded message payload */
	if(svc->log_message_cb) {
		svc->log_message_cb(svc->service_obj,msg_type,(unsigned int)msg_id,
				    msg+QMI_HEADER_SIZE,(unsigned int)out_len, (unsigned int)txn_id);
	}

	switch(msg_type) {
	case QMI_IDL_INDICATION:
		cntl_flag = QMI_INDICATION_CONTROL_FLAG;
		send_flags |= QCSI_SEND_FLAG_RATE_LIMITED;
		break;
	case QMI_IDL_RESPONSE:
		cntl_flag = QMI_RESPONSE_CONTROL_FLAG;
		break;
	default:
		cntl_flag = QMI_REQUEST_CONTROL_FLAG;
		break;
	}

	/* fill in header */
	encode_header(msg, cntl_flag, txn_id, msg_id, (uint16_t)out_len);

	out_len += QMI_HEADER_SIZE;

	if(clnt) {
		QCSI_LOG_TX_PKT(svc->service_obj, cntl_flag, txn_id, msg_id,
				      out_len, clnt->xport.addr, clnt->xport.xport->addr_len);
		xport = clnt->xport.xport;

		rc = qcsi_xport_ops->send(xport->handle, (void *)clnt->xport.addr, msg, out_len,
					      send_flags, &clnt->xport.client_data);

	} else {
		/* broadcast too all clients. ignore errors */
		clnt = LIST_HEAD(svc->client_list);
		while(clnt) {
			QCSI_LOG_TX_PKT(svc->service_obj, cntl_flag, txn_id, msg_id,
					      out_len, clnt->xport.addr, clnt->xport.xport->addr_len);
			xport = clnt->xport.xport;

			qcsi_xport_ops->send(xport->handle, clnt->xport.addr, msg, out_len,
						 send_flags, &clnt->xport.client_data);
			clnt = clnt->local.next;
		}
		rc = QCSI_NO_ERR;
	}

	FREE(msg);

	return rc;
}

/**
 * @brief Encode and send an error response to the client.
 *
 * This function encodes and sends an error response to the client.
 *
 * @param[in] xport Pointer to the transport structure.
 * @param[in] addr Pointer to the address.
 * @param[in] msg_id Message ID.
 * @param[in] txn_id Transaction ID.
 * @param[in] result Result code.
 * @param[in] error Error code.
 *
 * @retval QCSI_NO_ERR Success.
 * @retval QCSI_NO_MEM No memory.
 * @retval QCSI_ENCODE_ERR Encoding error.
 */
static qcsi_error encode_and_send_resp
(
	qcsi_xport_type *xport,
	void *addr,
	uint16_t msg_id,
	uint16_t txn_id,
	uint16_t result,
	uint16_t error
)
{
	uint32_t resp_msg_len;
	qcsi_error rc;
	unsigned char *msg;

	resp_msg_len = qmi_idl_get_std_resp_tlv_len();

	msg = MALLOC(resp_msg_len + QMI_HEADER_SIZE);
	if(!msg)
		return QCSI_NO_MEM;

	if( qmi_idl_encode_resp_tlv(
		    result,
		    error,
		    msg + QMI_HEADER_SIZE,
		    resp_msg_len
	    ) != QMI_IDL_LIB_NO_ERR) {
		FREE(msg);
		return QCSI_ENCODE_ERR;
	}

	/* fill in header */
	encode_header(msg, QMI_RESPONSE_CONTROL_FLAG, txn_id, msg_id,
		      (uint16_t)resp_msg_len);
	QCSI_LOG_TX_PKT(xport->service->service_obj, QMI_RESPONSE_CONTROL_FLAG,
			      txn_id, msg_id, resp_msg_len, addr, xport->addr_len);
	resp_msg_len += QMI_HEADER_SIZE;

	/* Do not rate limit responses */
	rc = qcsi_xport_ops->send(xport->handle, addr, msg, resp_msg_len, 0, NULL);

	FREE(msg);

	return rc;
}

/**
 * @brief Handle a new client connection.
 *
 * This function handles a new client connection.
 *
 * @param[in] xport Pointer to the transport structure.
 * @param[in] addr Pointer to the address.
 *
 * @retval QCSI_NO_ERR Success.
 * @retval QCSI_NO_MEM No memory.
 * @retval QCSI_CONN_REFUSED Connection refused.
 * @retval QCSI_INTERNAL_ERR Internal error.
 */
qcsi_error qcsi_xport_connect
(
	qcsi_xport_type *xport,
	void *addr
)
{
	qcsi_client_type  *clnt;
	qcsi_service_type *svc;
	qcsi_connect connect_cb = NULL;
	uint32_t client_handle = 0xffffffff;
	void *service_cookie = NULL;
	void *connection_handle = NULL;
	qcsi_error rc = QCSI_INTERNAL_ERR;
	qcsi_cb_error cb_rc;

	if(!xport || !xport->service || !addr)
		return QCSI_INTERNAL_ERR;

	LOCK(&client_list_lock);
	/* figure out if client address exists in client list */
	clnt = find_client_by_addr(xport, addr);

	if(clnt) {
		/* client exists, do nothing */
		UNLOCK(&client_list_lock);
		return QCSI_NO_ERR;
	}

	clnt = create_client(xport, addr);

	if(!clnt) {
		UNLOCK(&client_list_lock);
		return QCSI_NO_MEM;
	}

	/* cache params to the callback */
	svc = clnt->service;
	connect_cb = svc->service_connect;
	service_cookie = svc->service_cookie;
	client_handle = clnt->handle;

	UNLOCK(&client_list_lock);

	/* invoke service_connect without lock held */
	if(connect_cb) {
		cb_rc = connect_cb((qmi_client_handle)(uintptr_t)client_handle,
				   service_cookie, &connection_handle);

		/* re-lock client list and re-lookup client with handle */
		LOCK(&client_list_lock);
		clnt = find_client(client_handle);
		if(cb_rc != QCSI_CB_NO_ERR) {
			if(clnt) {
				remove_client(clnt->service, clnt);
				FREE(clnt);
			}
			if(cb_rc == QCSI_CB_NO_MEM) {
				rc = QCSI_NO_MEM;
			} else {
				rc = QCSI_CONN_REFUSED;
			}
		} else {
			/* check to see if clnt still exists */
			if(clnt) {
				clnt->connection_handle = connection_handle;
				rc = QCSI_NO_ERR;
			}
		}
		UNLOCK(&client_list_lock);
	}

	return rc;
}

/**
 * @brief Receive a message from the transport.
 *
 * This function receives a message from the transport.
 *
 * @param[in] xport Pointer to the transport structure.
 * @param[in] addr Pointer to the address.
 * @param[in] buf Pointer to the buffer containing the message.
 * @param[in] len Length of the message.
 *
 * @retval QCSI_NO_ERR Success.
 * @retval QMI_ERR_INTERNAL_V01 Internal error.
 */
qcsi_error qcsi_xport_recv
(
	qcsi_xport_type *xport,
	void *addr,
	uint8_t *buf,
	uint32_t len
)
{
	qcsi_service_type *svc;
	qcsi_client_type  *clnt;
	qcsi_txn_type     *txn;
	unsigned char *c_struct = NULL;
	uint32_t txn_handle, c_struct_len;
	uint8_t cntl_flag;
	uint16_t txn_id, msg_id, msg_len;
	int rc = QMI_ERR_INTERNAL_V01;
	void *connection_handle, *service_cookie;

	if(!xport || !xport->service || !addr || len < QMI_HEADER_SIZE)
		return QCSI_INTERNAL_ERR;

	svc = xport->service;

	decode_header(buf, &cntl_flag, &txn_id, &msg_id, &msg_len);

	QCSI_LOG_TX_PKT(svc->service_obj, cntl_flag, txn_id, msg_id, msg_len,
			      addr, xport->addr_len);

	/* got a client struct, handle only request */
	if(cntl_flag != QMI_REQUEST_CONTROL_FLAG) {
		rc = QMI_ERR_MALFORMED_MSG_V01;
		goto rx_cb_bail;
	}

	/* if received message is shorter than the size in the header then there
	 * might have been a memory allocation error
	 */
	if((len - QMI_HEADER_SIZE) != msg_len) {
		rc = QMI_ERR_NO_MEMORY_V01;
		goto rx_cb_bail;
	}

	LOCK(&client_list_lock);

	/* figure out if client address exists in client list */
	clnt = find_client_by_addr(xport, addr);
	if(!clnt) {
		UNLOCK(&client_list_lock);
		/* Auto connect on first packet */
		rc = qcsi_xport_connect(xport, addr);
		if(rc != QCSI_NO_ERR) {
			rc = qcsi_err_translate(rc);
			goto rx_cb_bail;
		}

		/* Lock and find the client, if not found,
		 * do not proceed. */
		LOCK(&client_list_lock);
		clnt = find_client_by_addr(xport, addr);
		if(!clnt) {
			rc = QMI_ERR_INTERNAL_V01;
			UNLOCK(&client_list_lock);
			goto rx_cb_bail;
		}
	}

	LOCK(&txn_list_lock);
	txn = get_txn(clnt, txn_id, msg_id, &txn_handle);
	UNLOCK(&txn_list_lock);
	if(!txn) {
		rc = QMI_ERR_NO_MEMORY_V01;
		UNLOCK(&client_list_lock);
		goto rx_cb_bail;
	}

	/* cache handle values before unlocking and invoking callback */
	connection_handle = clnt->connection_handle;
	service_cookie = svc->service_cookie;
	UNLOCK(&client_list_lock);

	/* Log the encoded message payload */
	if(svc->log_message_cb) {
		svc->log_message_cb(svc->service_obj, QMI_IDL_REQUEST, (unsigned int)msg_id,
				    buf+QMI_HEADER_SIZE,
				    (unsigned int)msg_len, (unsigned int)txn_id);
	}

	/* Handle pre-request */
	if(svc->service_process_pre_req) {
		rc = svc->service_process_pre_req(connection_handle,
						  (qmi_req_handle)(uintptr_t)txn_handle,
						  msg_id,
						  msg_len ? buf + QMI_HEADER_SIZE: NULL,
						  msg_len,
						  service_cookie);

		if(rc == QCSI_CB_REQ_HANDLED) {
			return QCSI_NO_ERR;
		}
		if(rc != QCSI_CB_NO_ERR) {
			rc = QMI_ERR_NOT_SUPPORTED_V01;
			goto rx_cb_free_txn_bail;
		}
	}

	/* decode message */
	rc = qmi_idl_get_message_c_struct_len(svc->service_obj, QMI_IDL_REQUEST,
					      msg_id, &c_struct_len);

	/* If this message is unknown, see if the service is interested
	 * in the raw message */
	if(rc == QMI_IDL_LIB_MESSAGE_ID_NOT_FOUND && svc->service_process_raw_req) {
		rc = svc->service_process_raw_req(connection_handle,
						  (qmi_req_handle)(uintptr_t)txn_handle,
						  msg_id,
						  msg_len ? buf + QMI_HEADER_SIZE: NULL,
						  msg_len,
						  service_cookie);
		if(rc != QCSI_CB_NO_ERR) {
			rc = QMI_ERR_INTERNAL_V01;
			goto rx_cb_free_txn_bail;
		}
		return QCSI_NO_ERR;
	} else if(rc != QMI_IDL_LIB_NO_ERR) {
		rc = QMI_ERR_ENCODING_V01;
		goto rx_cb_free_txn_bail;
	}

	/* Decode the message */
	if(c_struct_len) {
		c_struct = MALLOC(c_struct_len);

		if(!c_struct) {
			rc = QMI_ERR_NO_MEMORY_V01;
			goto rx_cb_free_txn_bail;
		}

		rc = qmi_idl_message_decode(
			     svc->service_obj,
			     QMI_IDL_REQUEST,
			     msg_id,
			     buf + QMI_HEADER_SIZE,
			     len - QMI_HEADER_SIZE,
			     c_struct,
			     (uint16_t)c_struct_len);
		if(rc != QMI_IDL_LIB_NO_ERR) {
			if (rc < QMI_IDL_LIB_NO_ERR) {
				rc = QMI_ERR_ENCODING_V01;
			}
			FREE(c_struct);
			goto rx_cb_free_txn_bail;
		}
	}

	/* Finally handle the request */
	if(svc->service_process_req(
		    connection_handle,
		    (qmi_req_handle)(uintptr_t)txn_handle,
		    msg_id,
		    c_struct,
		    c_struct_len,
		    service_cookie
	    ) != QCSI_CB_NO_ERR) {
		if(c_struct)
			FREE(c_struct);
		goto rx_cb_free_txn_bail;
	}

	if(c_struct)
		FREE(c_struct);

	return QCSI_NO_ERR;

rx_cb_free_txn_bail:
	LOCK(&txn_list_lock);
	txn = find_txn(txn_handle);
	if(txn) {
		remove_txn(txn->client, txn);
		release_txn(txn);
	}
	UNLOCK(&txn_list_lock);
rx_cb_bail:
	encode_and_send_resp(xport, addr, msg_id, txn_id,
			     QMI_RESULT_FAILURE_V01, (uint16_t)rc);
	return QCSI_NO_ERR;
}

/**
 * @brief Resume a client connection.
 *
 * This function resumes a client connection.
 *
 * @param[in] xport Pointer to the transport structure.
 * @param[in] addr Pointer to the address.
 */
void qcsi_xport_resume_client
(
	qcsi_xport_type *xport,
	void *addr
)
{
	qcsi_service_type *svc;
	qcsi_client_type  *clnt;
	qcsi_resume_ind resume_cb = NULL;
	qmi_client_handle client_handle;
	void *service_cookie, *connection_handle;

	if(!xport || !xport->service || !addr)
		return;

	svc = xport->service;

	LOCK(&client_list_lock);
	/* try to look for client, if found, call disconnect handler */
	clnt = find_client_by_addr(xport, addr);
	if(clnt) {
		resume_cb = svc->resume_ind_cb;
		client_handle = (qmi_client_handle)(uintptr_t)clnt->handle;
		connection_handle = clnt->connection_handle;
		service_cookie = svc->service_cookie;
	}
	UNLOCK(&client_list_lock);

	if(resume_cb) {
		resume_cb(client_handle, connection_handle, service_cookie);
	}
}

/**
 * @brief Disconnect a client.
 *
 * This function disconnects a client.
 *
 * @param[in] xport Pointer to the transport structure.
 * @param[in] addr Pointer to the address.
 *
 * @retval QCSI_NO_ERR Success.
 * @retval QCSI_INTERNAL_ERR Internal error.
 */
qcsi_error qcsi_xport_disconnect
(
	qcsi_xport_type *xport,
	void *addr
)
{
	qcsi_service_type *svc;
	qcsi_client_type  *clnt;

	if(!xport || !xport->service || !addr)
		return QCSI_INTERNAL_ERR;

	svc = xport->service;

	LOCK(&client_list_lock);
	/* try to look for client, if found, call disconnect handler */
	clnt = find_client_by_addr(xport, addr);
	if(clnt) {
		/* remove client from active list */
		remove_client(svc, clnt);
		svc->service_disconnect(clnt->connection_handle, svc->service_cookie);
		clean_txns(clnt);
		FREE(clnt);
	}
	UNLOCK(&client_list_lock);
	return QCSI_NO_ERR;
}

/**
 * @brief Handle transport closure.
 *
 * This function handles transport closure.
 *
 * @param[in] xport Pointer to the transport structure.
 */
void qcsi_xport_closed
(
	qcsi_xport_type *xport
)
{
	qcsi_service_type *svc;
	qcsi_client_type  *clnt;

	if(!xport || !xport->service)
		return;

	/* go through client list and clean up clients associated with the xport */
	svc = xport->service;
	LOCK(&client_list_lock);
	clnt = LIST_HEAD(svc->client_list);
	while(clnt) {
		qcsi_client_type *to_free = clnt;
		clnt = clnt->local.next;
		if(to_free->xport.xport == xport) {
			/* call disconnect callback? */
			clean_txns(to_free);
			/* remove from global client list */
			remove_client(svc, to_free);
			FREE(to_free);
		}
	}
	UNLOCK(&client_list_lock);

	/* remove xport from xport list. When no xport left, free service */
	if(svc->xport == xport)
		svc->xport = NULL;

	FREE(xport);
	if (!svc->xport) {
		/* if handle fully initialized then remove from list*/
		if (svc->handle)
			remove_service(svc);
		//FREE(svc->xport);
		FREE(svc);
	}
}

/**
 * @brief Register a service with options.
 *
 * This function registers a service with options.
 *
 * @param[in] service_obj Service object.
 * @param[in] service_connect Service connect callback function.
 * @param[in] service_disconnect Service disconnect callback function.
 * @param[in] service_process_req Service process request callback function.
 * @param[in] service_cookie Pointer to service cookie.
 * @param[in] os_params Pointer to OS parameters.
 * @param[in] options Pointer to service options.
 * @param[out] service_provider Pointer to store the service provider handle.
 *
 * @retval QCSI_NO_ERR Success.
 * @retval QCSI_INTERNAL_ERR Internal error.
 * @retval QCSI_NO_MEM No memory.
 */
qcsi_error
qcsi_register_with_options
(
	qmi_idl_service_object_type               service_obj,
	qcsi_connect                           service_connect,
	qcsi_disconnect                        service_disconnect,
	qcsi_process_req                        service_process_req,
	void                                      *service_cookie,
	qcsi_os_params                         *os_params,
	qcsi_options                           *options,
	qcsi_service_handle                    *service_provider
)
{
	qcsi_service_type *svc;
	qcsi_xport_type *xport;
	uint32_t service_id, max_msg_len;
	int active = 0;

	if(!service_obj || !service_connect || !service_disconnect
	    || !service_process_req || !service_provider)
		return QCSI_INTERNAL_ERR;

	*service_provider = NULL;

	svc = CALLOC(1, sizeof(qcsi_service_type));
	if(!svc) {
		/* failed to allocate memory */
		return QCSI_INTERNAL_ERR;
	}

	LINK_INIT(svc->link);
	LIST_INIT(svc->client_list);
	svc->service_obj = service_obj;
	svc->service_connect = service_connect;
	svc->service_disconnect = service_disconnect;
	svc->service_process_req = service_process_req;
	svc->service_process_raw_req = NULL;
	svc->service_process_pre_req = NULL;
	svc->log_message_cb = NULL;
	svc->service_cookie = service_cookie;
	svc->resume_ind_cb = NULL;


	/* Set xport options to its default values */
	svc->xport_options.rate_limited_queue_size = DEFAULT_MAX_TX_BUFS;

	if(qmi_idl_get_service_id(service_obj, &service_id) != QMI_IDL_LIB_NO_ERR ||
	    qmi_idl_get_idl_version(service_obj, &(svc->idl_version)) != QMI_IDL_LIB_NO_ERR
	    ||
	    qmi_idl_get_max_service_len(service_obj, &max_msg_len) != QMI_IDL_LIB_NO_ERR) {
		FREE(svc);
		return QCSI_INTERNAL_ERR;
	}

	if(options) {
		if(options->options_set & QCSI_OPTIONS_INSTANCE_ID_VALID) {
			svc->idl_version |= SET_INSTANCE(options->instance_id);
		}

#ifdef qcsi_OPTIONS_MAX_OUTSTANDING_INDS_VALID
		if(options->options_set & QCSI_OPTIONS_MAX_OUTSTANDING_INDS_VALID) {
			if(options->max_outstanding_inds > 0) {
				svc->xport_options.rate_limited_queue_size = options->max_outstanding_inds;
			}
		}
#endif
#ifdef qcsi_OPTIONS_RAW_REQUEST_VALID
		if(options->options_set & QCSI_OPTIONS_RAW_REQUEST_VALID) {
			svc->service_process_raw_req = options->raw_request_cb;
		}
#endif

#ifdef qcsi_OPTIONS_PRE_REQUEST_VALID
		if(options->options_set & QCSI_OPTIONS_PRE_REQUEST_VALID) {
			svc->service_process_pre_req = options->pre_request_cb;
		}
#endif

#ifdef qcsi_OPTIONS_RESUME_VALID
		if(options->options_set & QCSI_OPTIONS_RESUME_VALID) {
			svc->resume_ind_cb = options->resume_ind_cb;
		}
#endif

#ifdef qcsi_OPTIONS_LOG_MSG_CB_VALID
		if(options->options_set & QCSI_OPTIONS_LOG_MSG_CB_VALID) {
			svc->log_message_cb = options->log_msg_cb;
		}
#endif

	}

	max_msg_len += QMI_HEADER_SIZE;

	/* handle OS-specific parameters such as storing away signal/event & TCB */
#ifdef QCSI_OS_PARAMS_PROLOG
	QCSI_OS_PARAMS_PROLOG(svc, os_params);
#endif

	xport = CALLOC(1, sizeof(qcsi_xport_type));
	if (!xport) {
		FREE(svc);
		return QCSI_NO_MEM;
	}

	svc->xport = xport;

	xport->ops = (struct qcsi_xport_ops_s *)qcsi_xport_ops;
	xport->addr_len = QCSI_MIN(MAX_ADDR_LEN, qcsi_xport_ops->addr_len());
	xport->service = svc;
	/* open xport */
	xport->handle = qcsi_xport_ops->open(qcsi_xport_data, xport,
						 max_msg_len, os_params, &svc->xport_options);

	if(!xport->handle) {
		FREE(xport);
		return QCSI_INTERNAL_ERR;
	}

	/* register service on xport */
	if (qcsi_xport_ops->reg(xport->handle, service_id, svc->idl_version)
	    != QCSI_NO_ERR)
	{
		qcsi_xport_ops->close(xport->handle);
		FREE(svc->xport);
		FREE(svc);
		return QCSI_INTERNAL_ERR;
	}

	/* handle OS-specific parameters such as returning fd_set */
#ifdef QCSI_OS_PARAMS_EPILOG
	QCSI_OS_PARAMS_EPILOG(svc, params);
#endif

	/* add to service list */
	*service_provider = (qcsi_service_handle)(uintptr_t)add_service(svc);

	return QCSI_NO_ERR;
}

/**
 * @brief Register a service.
 *
 * This function registers a service.
 *
 * @param[in] service_obj Service object.
 * @param[in] service_connect Service connect callback function.
 * @param[in] service_disconnect Service disconnect callback function.
 * @param[in] service_process_req Service process request callback function.
 * @param[in] service_cookie Pointer to service cookie.
 * @param[in] os_params Pointer to OS parameters.
 * @param[out] service_provider Pointer to store the service provider handle.
 *
 * @retval QCSI_NO_ERR Success.
 * @retval QCSI_INTERNAL_ERR Internal error.
 */
qcsi_error qcsi_register (
	qmi_idl_service_object_type               service_obj,
	qcsi_connect                           service_connect,
	qcsi_disconnect                        service_disconnect,
	qcsi_process_req                       service_process_req,
	void                                      *service_cookie,
	qcsi_os_params                         *os_params,
	qcsi_service_handle                    *service_provider)
{
	return qcsi_register_with_options(
		       service_obj,
		       service_connect,
		       service_disconnect,
		       service_process_req,
		       service_cookie,
		       os_params,
		       NULL,
		       service_provider);
}

/**
 * @brief Handle an event for a service.
 *
 * This function handles an event for a service.
 *
 * @param[in] service_provider Service provider handle.
 * @param[in] os_params Pointer to OS parameters.
 *
 * @retval QCSI_NO_ERR Success.
 * @retval QCSI_INVALID_HANDLE Invalid handle.
 */
qcsi_error qcsi_handle_event(
    qcsi_service_handle service_provider,
    qcsi_os_params *os_params)
{
	qcsi_service_type *svc;

	LOCK(&service_list_lock);
	svc = find_service((uint32_t)(uintptr_t)service_provider);

	if(!svc) {
		UNLOCK(&service_list_lock);
		return QCSI_INVALID_HANDLE;
	}

	/* unlock. service must not unregister
	 * at the same time since we don't hold the lock
	 */
	UNLOCK(&service_list_lock);

	/* call handle_event on the xport, if available */
	if (qcsi_xport_ops->handle_event)
		qcsi_xport_ops->handle_event((void *)svc->xport->handle, os_params);

	return QCSI_NO_ERR;
}

/**
 * @brief Send a response internally.
 *
 * This function sends a response internally.
 *
 * @param[in] req_handle Request handle.
 * @param[in] msg_id Message ID.
 * @param[in] c_struct Pointer to the C structure.
 * @param[in] c_struct_len Length of the C structure.
 * @param[in] encode Flag indicating whether to encode the message.
 *
 * @retval QCSI_NO_ERR Success.
 * @retval QCSI_INVALID_ARGS Invalid arguments.
 * @retval QCSI_INVALID_HANDLE Invalid handle.
 */
qcsi_error qcsi_send_resp_internal(
    qmi_req_handle req_handle,
    unsigned int msg_id,
    void *c_struct,
    unsigned int c_struct_len,
    int encode)
{
	qcsi_txn_type *txn;
	qcsi_client_type *clnt;
	qcsi_error rc;

	if(c_struct_len <= 0)
		return QCSI_INVALID_ARGS;

	/* as long as we hold the txn_list_lock, the client, service, and xport ptrs
	* will be valid
	*/
	LOCK(&txn_list_lock);
	txn = find_txn((uint32_t)(uintptr_t)req_handle);

	if(!txn || msg_id > 0xffff || txn->msg_id != (uint16_t)msg_id || !txn->client
	    || !txn->client->service ||
	    !txn->client->xport.xport) {
		rc = QCSI_INVALID_HANDLE;
		goto send_resp_bail;
	}

	clnt = txn->client;

	/* remove the transaction from the active list so it doesn't get freed
	 * while we are holding onto the pointer
	 */
	remove_txn(clnt, txn);

	/* encode and send */
	rc = internal_send(clnt->service, clnt, QMI_IDL_RESPONSE, txn->txn_id,
			   (uint16_t)msg_id, c_struct, c_struct_len, encode);

	release_txn(txn);

send_resp_bail:
	UNLOCK(&txn_list_lock);
	QCSI_LOG_ERR("%s Internal send: rc: %d \n", __func__,rc);
	return rc;
}

/**
 * @brief Send a response.
 *
 * This function sends a response.
 *
 * @param[in] req_handle Request handle.
 * @param[in] msg_id Message ID.
 * @param[in] c_struct Pointer to the C structure.
 * @param[in] c_struct_len Length of the C structure.
 *
 * @retval QCSI_NO_ERR Success.
 * @retval QCSI_INVALID_ARGS Invalid arguments.
 * @retval QCSI_INVALID_HANDLE Invalid handle.
 */
qcsi_error qcsi_send_resp(
    qmi_req_handle req_handle,
    unsigned int msg_id,
    void *c_struct,
    unsigned int c_struct_len)
{
	return qcsi_send_resp_internal(req_handle, msg_id, c_struct, c_struct_len,
					  1);
}

/**
 * @brief Send a raw response.
 *
 * This function sends a raw response.
 *
 * @param[in] req_handle Request handle.
 * @param[in] msg_id Message ID.
 * @param[in] c_struct Pointer to the C structure.
 * @param[in] c_struct_len Length of the C structure.
 *
 * @retval QCSI_NO_ERR Success.
 * @retval QCSI_INVALID_ARGS Invalid arguments.
 * @retval QCSI_INVALID_HANDLE Invalid handle.
 */
qcsi_error qcsi_send_resp_raw(
    qmi_req_handle req_handle,
    unsigned int msg_id,
    void *c_struct,
    unsigned int c_struct_len)
{
	return qcsi_send_resp_internal(req_handle, msg_id, c_struct, c_struct_len, 0);
}

/**
 * @brief Sends an internal indication to a client.
 *
 * This function encodes and sends an indication message to a specified client.
 *
 * @param client_handle Handle to the client.
 * @param msg_id ID of the message to be sent.
 * @param c_struct Pointer to the structure containing the message data.
 * @param c_struct_len Length of the structure.
 * @param encode Flag indicating whether to encode the message.
 *
 * @return qcsi_error Error code indicating the result of the operation.
 */
qcsi_error
qcsi_send_ind_internal
(
	qmi_client_handle  client_handle,
	unsigned int       msg_id,
	void               *c_struct,
	unsigned int       c_struct_len,
	int                encode
)
{
	qcsi_client_type *clnt;
	qcsi_error rc;

	LOCK(&client_list_lock);
	clnt = find_client((uint32_t)(uintptr_t)client_handle);

	if(!clnt || !clnt->service || !clnt->xport.xport) {
		rc = QCSI_INVALID_HANDLE;
		goto send_ind_bail;
	}

	/* encode and send */
	rc = internal_send(clnt->service, clnt, QMI_IDL_INDICATION,
			   clnt->next_ind_txn_id,
			   (uint16_t)msg_id, c_struct, c_struct_len, encode);
	if (rc == QCSI_NO_ERR) {
		clnt->next_ind_txn_id++;
		if (clnt->next_ind_txn_id == 0) {
			clnt->next_ind_txn_id++;
		}
	}


send_ind_bail:
	UNLOCK(&client_list_lock);
	return rc;
}

/**
 * @brief Sends an indication to a client.
 *
 * This function sends an indication message to a specified client.
 *
 * @param client_handle Handle to the client.
 * @param msg_id ID of the message to be sent.
 * @param c_struct Pointer to the structure containing the message data.
 * @param c_struct_len Length of the structure.
 *
 * @return qcsi_error Error code indicating the result of the operation.
 */
qcsi_error
qcsi_send_ind
(
	qmi_client_handle  client_handle,
	unsigned int             msg_id,
	void                    *c_struct,
	unsigned int             c_struct_len
)
{
	return qcsi_send_ind_internal(client_handle, msg_id, c_struct, c_struct_len,
					 1);
}

/**
 * @brief Sends a raw indication to a client.
 *
 * This function sends a raw indication message to a specified client.
 *
 * @param client_handle Handle to the client.
 * @param msg_id ID of the message to be sent.
 * @param buf Pointer to the buffer containing the message data.
 * @param buf_len Length of the buffer.
 *
 * @return qcsi_error Error code indicating the result of the operation.
 */
qcsi_error
qcsi_send_ind_raw
(
	qmi_client_handle  client_handle,
	unsigned int       msg_id,
	void               *buf,
	unsigned int       buf_len
)
{
	return qcsi_send_ind_internal(client_handle, msg_id, buf, buf_len, 0);
}

/**
 * @brief Sends an internal broadcast indication.
 *
 * This function encodes and sends a broadcast indication message to all clients of a specified service.
 *
 * @param service_provider Handle to the service provider.
 * @param msg_id ID of the message to be sent.
 * @param c_struct Pointer to the structure containing the message data.
 * @param c_struct_len Length of the structure.
 * @param encode Flag indicating whether to encode the message.
 *
 * @return qcsi_error Error code indicating the result of the operation.
 */
qcsi_error
qcsi_send_broadcast_ind_internal
(
	qcsi_service_handle   service_provider,
	unsigned int             msg_id,
	void                     *c_struct,
	unsigned int             c_struct_len,
	int                      encode
)
{
	qcsi_service_type *svc;
	qcsi_error rc;

	/* lock client list first so if we find the service, the client list is
	 * not going to be changed
	 */
	LOCK(&client_list_lock);
	LOCK(&service_list_lock);
	svc = find_service((uint32_t)(uintptr_t)service_provider);

	if(!svc) {
		rc = QCSI_INVALID_HANDLE;
		goto broadcast_ind_bail;
	}

	/* encode and send */
	rc = internal_send(svc, NULL, QMI_IDL_INDICATION, 0, (uint16_t)msg_id,
			   c_struct, c_struct_len, encode);

broadcast_ind_bail:
	UNLOCK(&service_list_lock);
	UNLOCK(&client_list_lock);
	return rc;
}

/**
 * @brief Sends a broadcast indication.
 *
 * This function sends a broadcast indication message to all clients of a specified service.
 *
 * @param service_provider Handle to the service provider.
 * @param msg_id ID of the message to be sent.
 * @param c_struct Pointer to the structure containing the message data.
 * @param c_struct_len Length of the structure.
 *
 * @return qcsi_error Error code indicating the result of the operation.
 */
qcsi_error
qcsi_send_broadcast_ind
(
	qcsi_service_handle   service_provider,
	unsigned int             msg_id,
	void                     *c_struct,
	unsigned int             c_struct_len
)
{
	return qcsi_send_broadcast_ind_internal(service_provider, msg_id,
			c_struct, c_struct_len, 1);
}

/**
 * @brief Sends a raw broadcast indication.
 *
 * This function sends a raw broadcast indication message to all clients of a specified service.
 *
 * @param service_provider Handle to the service provider.
 * @param msg_id ID of the message to be sent.
 * @param buf Pointer to the buffer containing the message data.
 * @param buf_len Length of the buffer.
 *
 * @return qcsi_error Error code indicating the result of the operation.
 */
qcsi_error
qcsi_send_broadcast_ind_raw
(
	qcsi_service_handle   service_provider,
	unsigned int             msg_id,
	void                     *buf,
	unsigned int             buf_len
)
{
	return qcsi_send_broadcast_ind_internal(service_provider, msg_id,
			buf, buf_len, 0);
}

/**
 * @brief Unregisters a service provider.
 *
 * This function closes the transports associated with a service
 * provider and unregisters it.
 *
 * @param service_provider Handle to the service provider.
 *
 * @return qcsi_error Error code indicating the result of the operation.
 */
qcsi_error
qcsi_unregister
(
	qcsi_service_handle     service_provider
)
{
	qcsi_service_type *svc;
	qcsi_xport_type *xport;
	unsigned int i;

	/* Tricky problem because we may get a callback at the same time as the xport
	 * is being closed. Instead, a close callback is used to synchronize freeing
	 * of memory. We just need to close the transports here.
	 */
	LOCK(&service_list_lock);
	svc = find_service((uint32_t)(uintptr_t)service_provider);

	if(!svc) {
		UNLOCK(&service_list_lock);
		return QCSI_INVALID_HANDLE;
	}

	/* save pointer to xport table and unlock */
	UNLOCK(&service_list_lock);

	qcsi_xport_ops->close(svc->xport->handle);


	return QCSI_NO_ERR;
}


/**
 * @brief One time initialization of the QCSI stack.
 *
 * This function performs a one-time initialization of the QCSI stack.
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
qcsi_error qcsi_init(
	qcsi_xport_ops_type	*xport_ops,
	void			*xport_data)
{
	if (!xport_ops) {
		return QCSI_INVALID_HANDLE;  //TODO: err code
	}

	if (qcsi_fw_inited == 0) {

		LOCK_INIT(&service_list_lock);
		LOCK_INIT(&client_list_lock);
		LOCK_INIT(&txn_list_lock);

		qcsi_xport_ops = xport_ops;
		qcsi_xport_data = xport_data;

		qcsi_fw_inited = 1;
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
qcsi_error qcsi_deinit(void)
{
	if (qcsi_fw_inited) {
		qcsi_fw_inited = 0;
		qcsi_xport_ops = NULL;
		qcsi_xport_data = NULL;
	}

	return QMI_NO_ERR;
}

/**
 * @brief Retrieves the transaction ID for a request.
 *
 * This function retrieves the transaction ID associated with a given request handle.
 *
 * @param req_handle Handle to the request.
 * @param txn_id Pointer to store the transaction ID.
 *
 * @return qcsi_error Error code indicating the result of the operation.
 */
qcsi_error
qcsi_get_txn_id
(
	qmi_req_handle     req_handle,
	unsigned int       *txn_id
)
{
	qcsi_txn_type *txn;

	if(!txn_id)
		return QCSI_INTERNAL_ERR;

	LOCK(&txn_list_lock);
	txn = find_txn((uint32_t)(uintptr_t)req_handle);
	if(!txn ) {
		UNLOCK(&txn_list_lock);
		return QCSI_INVALID_HANDLE;
	}

	*txn_id = txn->txn_id;
	UNLOCK(&txn_list_lock);
	return  QCSI_NO_ERR;
}
