// Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef QCCI_INTERNAL_H
#define QCCI_INTERNAL_H
/**
 * @file qcci_internal.h
 *
 * @brief QMI CCI internal header file.
 */

#include "qmi_common.h"

#ifndef QCCI_MAX_ADDR_LEN
#define QCCI_MAX_ADDR_LEN MAX_ADDR_LEN
#endif

struct qcci_client_s;
/** QMI CCI client type */
typedef struct qcci_client_s qcci_client_type;

/** QMI CCI client category type */
typedef enum {
	QCCI_NOTIFIER_CLIENT = 0,
	QCCI_DORMANT_CLIENT,
	QCCI_CONNECTED_CLIENT
} qcci_client_category_type;

struct qcci_txn_s;
struct qcci_xport_ops_s;

/** QMI CCI client structure */
struct qcci_client_s {

	/* Client ID */
	uint32_t clid;
	int ref_count;

	/* service object */
	qmi_idl_service_object_type service_obj;

	/* xport data */
	void *xport_handle;
	uint32_t xport_addr_len;

	/* release callback */
	qmi_client_release_cb release_cb;
	void *release_cb_data;

	/* OS-defined data such as signal/event */
	QMI_CCI_OS_SIGNAL signal;

	/* Common lock */
	qcci_os_lock_type lock;

	qcci_client_category_type category;
	union {
		struct {
			qmi_client_error_cb err_cb;
			void *err_cb_data;
			uint32_t err_pending;

			/* indication callback */
			qmi_client_ind_cb ind_cb;
			void *ind_cb_data;

			/* server address */
			uint8_t server_addr[QCCI_MAX_ADDR_LEN];

			/* list of outstanding transactions */
			LIST(struct qcci_txn_s, txn_list);
			uint16_t next_txn_id;

			LIST(struct qcci_txn_s, tx_q);
			int accepting_txns;

			qmi_client_log_cb log_cb;
			void *log_cb_data;
		} client;

		struct {
			qmi_client_notify_cb notify_cb;
			void *notify_cb_data;
			uint32_t notify_pending;

			/* pointer to external signal, if provided */
			QMI_CCI_OS_SIGNAL *ext_signal;
		} notifier;
	} info;

	/* Link required as part of the global client table */
	LINK(qcci_client_type, link);
};

/** QMI CCI transaction type */
typedef enum {
	TXN_SYNC_MSG,
	TXN_SYNC_RAW,
	TXN_ASYNC_MSG,
	TXN_ASYNC_RAW
} qcci_txn_enum_type;

/** QMI CCI transaction structure */
typedef struct qcci_txn_s {
	/* links to prev and next txns */
	LINK(struct qcci_txn_s, link);

	/* TX Queue list */
	LINK(struct qcci_txn_s, tx_link);

	/* type of txn */
	qcci_txn_enum_type type;

	/* txn and msg ids */
	uint16_t txn_id;
	uint16_t msg_id;

	/* raw and message async rx cb */
	qmi_client_recv_msg_async_cb rx_cb;
	void *rx_cb_data;

	uint8_t *rx_buf;
	uint32_t rx_buf_len;
	uint32_t reply_len;

	/* return code */
	int32_t rc;

	int ref_count;

	qcci_client_type *client;

	QMI_CCI_OS_SIGNAL signal;

	void *tx_buf;
	uint32_t tx_buf_len;

} qcci_txn_type;

/** QMI CCI service information */
typedef struct {
	uint8_t xport;
	uint8_t version;
	uint8_t instance;
	uint8_t reserved;
	uint8_t addr[QCCI_MAX_ADDR_LEN];
} qcci_service_info;

/**
 * @brief Callback function to open a new transport.
 *
 * @param[in] xport_data Opaque parameter to the transport (e.g., port ID)
 * @param[in] clnt Pointer to the infrastructure's client struct
 * @param[in] service_id Service ID
 * @param[in] version Version of the service
 * @param[in] addr Address of the server
 * @param[in] max_rx_len Maximum length of messages that can be received
 */
typedef void *(*qcci_open_fn_type)
(
	void *xport_data,
	qcci_client_type *clnt,
	uint32_t service_id,
	uint32_t version,
	void *addr,
	uint32_t max_rx_len
);

/**
 * @brief Callback function to send data to a server.
 *
 * This callback function is called by the QCCI infrastructure to send data to
 * a server.
 *
 * @param[in] handle Opaque handle returned by the open call
 * @param[in] addr Opaque address sent to the infrastructure through the connect or recv calls
 * @param[in] msg Pointer to the message to be sent
 * @param[in] msg_len Length of the message
 *
 * @retval QMI_NO_ERR Success
 */
typedef qmi_cci_error_type (*qcci_send_fn_type)
(
	void *handle,
	void *addr,
	uint8_t *msg,
	uint32_t msg_len
);

/**
 * @brief Callback function to close the transport.
 *
 * This callback function is called by the QCCI infrastructure to close the
 * transport, usually when the service is unregistered. It is crucial that the
 * transport synchronizes the deallocation of memory and its callback functions
 * so the callbacks do not occur after the data associated with the transport
 * has been deallocated.
 *
 * @param[in] handle Opaque handle returned by the open call
 */
typedef void (*qcci_close_fn_type)
(
	void *handle
);

/**
 * @brief Callback function to open a new transport.
 *
 * This callback function is called by the QCCI infrastructure to open a new
 * transport.
 *
 * @param[in] xport_data Opaque data associated with the transport
 * @param[in] xport_num Framework assigned enumeration of the transport
 * @param[in] service_id Service ID
 * @param[in] version Version of the service
 * @param[in/out] num_entries Number of entries in the array and number of entries filled
 * @param[out] service_list Linked list of server records
 *
 * @retval Total number of servers found
 */
typedef uint32_t (*qcci_lookup_fn_type)
(
	void    *xport_data,
	uint8_t  xport_num,
	uint32_t service_id,
	uint32_t version,
	uint32_t *num_entries,
	qcci_service_info *service_info
);

/**
 * @brief Callback function to retrieve the length of the address of the transport.
 *
 * This callback function is called by the QCCI infrastructure to retrieve the
 * length of the (destination) address of the transport.
 *
 * @retval Length of address
 */
typedef uint32_t (*qcci_addr_len_fn_type)
(
	void
);

/** Transport operations table type */
typedef struct qcci_xport_ops_s {
	qcci_open_fn_type open;
	qcci_send_fn_type send;
	qcci_close_fn_type close;
	qcci_lookup_fn_type lookup;
	qcci_addr_len_fn_type addr_len;
} qcci_xport_ops_type;

/**
 * @brief Register a transport with the infrastructure.
 *
 * This function is used to register a transport with the infrastructure.
 *
 * @param[in] ops Pointer to transport operations table
 * @param[in] xport_data Opaque data associated with the transport, such as port ID or other parameters
 *
 * @note A client is aware of transports started before its creation. There is no way
 * to make a client aware of transports started after its creation.
 * This function call is not SMP safe with the rest of the QCCI stack.
 * This function call is not re-entrant.
 */
void qcci_xport_start
(
	qcci_xport_ops_type *ops,
	void *xport_data
);

/**
 * @brief Un-register a transport with the infrastructure.
 *
 * This function is used to un-register a transport with the infrastructure.
 *
 * @param[in] ops Pointer to transport operations table
 * @param[in] xport_data Opaque data associated with the transport, such as port ID or other parameters
 *
 * @note This function call is not SMP safe with the rest of the QCCI stack.
 * This function call is not re-entrant.
 * This call only ensures that future clients won't use the transport.
 * Clients started after the transport is started to this point will continue
 * to use the transport. There is no way to work around this.
 * Due to all these limitations, the only place this function is safe to
 * call is on the process exit.
 */
void qcci_xport_stop
(
	qcci_xport_ops_type *ops,
	void *xport_data
);

/**
 * @brief Signal the infrastructure to resume if a previous send was blocked on flow control.
 *
 * This function is used by the transport to signal the infrastructure to
 * resume if a previous send was blocked on flow control.
 *
 * @param[in] clnt Pointer to infrastructure's client struct
 *
 * @retval QCCI_NO_ERR Success
 */
void qcci_xport_resume
(
	qcci_client_type *clnt
);

/**
 * @brief Signal the infrastructure to process the incoming message.
 *
 * This function is used by the transport to signal the infrastructure to
 * process the incoming message, one at a time.
 *
 * @param[in] clnt Pointer to infrastructure's client struct
 * @param[in] addr Pointer to source address
 * @param[in] buf Pointer to message to be received
 * @param[in] len Length of the message
 *
 * @retval QMI_CSI_NO_ERR Success
 */
qmi_cci_error_type qcci_xport_recv
(
	qcci_client_type *clnt,
	void *addr,
	uint8_t *buf,
	uint32_t len
);

/**
 * @brief Signal the infrastructure after the transport is fully closed.
 *
 * This function is used by the transport to signal the infrastructure after
 * the transport is fully closed so the infrastructure can free up the client's
 * data structure.
 *
 * @param[in] clnt Pointer to infrastructure's client struct
 */
void qcci_xport_closed
(
	qcci_client_type *clnt
);

/**
 * @brief Signal the infrastructure of a new server registration event.
 *
 * This function is used by the transport to signal the infrastructure of a new
 * server registration event. The client can query lookup for the new server.
 *
 * @param[in] clnt Pointer to infrastructure's client struct
 * @param[in] addr Pointer to source address
 */
void qcci_xport_event_new_server
(
	qcci_client_type *clnt,
	void *addr
);

/**
 * @brief Signal the infrastructure of a server unregistration event.
 *
 * This function is used by the transport to signal the infrastructure of a
 * server unregistration event.
 *
 * @param[in] clnt Pointer to infrastructure's client struct
 * @param[in] addr Pointer to source address
 */
void qcci_xport_event_remove_server
(
	qcci_client_type *clnt,
	void *addr
);

/**
 * @brief Signal the infrastructure of a server unreachable event with an error code.
 *
 * This function is used by the transport to signal the infrastructure of a
 * server unreachable event with an error code.
 *
 * @param[in] clnt Pointer to infrastructure's client struct
 * @param[in] addr Pointer to source address
 * @param[in] error Error type in connection termination
 */
void qcci_xport_event_server_error
(
	qcci_client_type *clnt,
	void *addr,
	int error
);

/**
 * @brief One-time initialization of the QCCI stack.
 *
 * This function performs a one-time initialization of the QCCI stack.
 *
 * @param[in] xport_ops Pointer to transport operations table
 * @param[in] xport_data Opaque data associated with the transport
 *
 * @return QMI error codes
 *
 * @note This function is NOT re-enterable or thread safe. The only safe place
 * to call this is during initialization.
 */
qmi_cci_error_type qcci_init(
	qcci_xport_ops_type	*xport_ops,
	void			*xport_data);

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
qmi_cci_error_type qcci_deinit(void);

#endif
