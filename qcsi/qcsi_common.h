// Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef QCSI_CMN_H
#define QCSI_CMN_H
/**
 * @file qcsi_common.h
 * @brief The QMI Common Service Interface (CSI) common header file
 *
 * DESCRIPTION
 * QMI Common Service Interface types
 */

#include <stdint.h>
#include "qmi_common.h"
#include "qcsi.h"

/**
 * @brief The data structure looks as follows:
 * - The service list has a list of active services
 * - Each service has a table of transports (xports) associated with it
 * - Each service also has a list of connected clients
 * - Each client has a pointer to the xport it connected from
 * - Each client also has a list of outstanding transactions (txns)
 *
 * Service list -> service 1 -> service 2 ->...
 *                 ^
 *                 |
 *                 +-> [xport 1] [xport 2] [...]
 *                 |      ^
 *                 |      |-----------+
 *                 |      |           |
 * Glb clnt lst -> +-> client 1 -> client 2 ->...
 *                      ^
 *                      |
 * Global txn list ->   +-> txn 1 -> txn 2 ->...
 *
 * The global client and txn lists allow client and txn handles to be validated
 *
 * The transport abstraction abstracts the xport from the common QCSI layer
 * Up-calls from the xport:
 * - connect, receive, notify, disconnect and closed
 *
 * The receive call is used to push data up the stack, 1 msg at a time
 *
 * The notify call is used to notify the stack of an event (e.g. Rx ready,
 * connect, disconnect) on the transport channel. It is optional for systems
 * supporting select()
 *
 * These callbacks should be serialized on a per transport basis
 * (e.g. while in receive, connect/disconnect/closed should not happen)
 *
 * The xport_start function registers a function table with the common layer
 * consisting of:
 * - open, register server, unregister server, send, handle event, close and
 *   get address length functions
 *
 * The handle event function is optional and is used for handling requests
 * and events from the server's context, instead of inside the transport's
 * Rx callback so as not to block or starve other requests.
 *
 * The get address length function is used to determine how many bytes of the
 * address pointer is to be copied or compared as each transport has a different
 * address structure.
 *
 * The os_param parameter into qcsi_register is used in two ways:
 *
 * 1) On Linux, it is used as an output containing the active fd_set that
 *    can be passed into select() so the service can listen on multiple file
 *    descriptors or transports. Upon returning from select(), the active
 *    read fd_set is passed into qcsi_handle_event() as another os_param
 *    so the file descriptor can be read and the events can be processed by
 *    invoking the service's callbacks. To not block on the read, the file
 *    descriptors need to be configured as non-blocking by the xport layer.
 *
 * 2) On AMSS, it is used as an input containing the TCB and signal to set
 *    when an event occurs on the transport. Upon receiving the signal, the
 *    service calls qcsi_handle_event() with the received signal as an
 *    os_param to allow the event and service callbacks to be executed in the
 *    service's context.
 */

/** Transaction ID type */
typedef uint16_t txn_id_type;
struct qcsi_service_s;
struct qcsi_client_s;
struct qcsi_txn_s;
struct qcsi_xport_s;
struct qcsi_xport_ops_s;

#ifndef TXN_POOL_SIZE
	#define TXN_POOL_SIZE 5
#endif

/**
 * @brief Xport Send option flags.
 *
 * This option can be used with an xport's send method to instruct
 * the transport to make sure that sending this packet does not increase
 * the total number of packets in the TX Queue beyond a predefined limit.
 * The limit is configured at open.
 */
#define QCSI_SEND_FLAG_RATE_LIMITED (1)

/**
 * @brief Xport options structure.
 *
 * If xport's send method is called with the flag QCSI_SEND_FLAG_RATE_LIMITED
 * set, then make sure that the internal transmit queue length does not exceed
 * this value.
 */
typedef struct {
	uint32_t rate_limited_queue_size; /**< Rate-limited queue size */
} qcsi_xport_options_type;

struct qcci_xport_ops_s;


/**
 * @brief QMI CSI service structure.
 */
typedef struct qcsi_service_s {
	LINK(struct qcsi_service_s, link); /**< Links to previous and next in service list */
	uint32_t handle; /**< Unique service handle */
	qmi_idl_service_object_type service_obj; /**< Service registration data */
	qcsi_connect service_connect; /**< Service connect callback */
	qcsi_disconnect service_disconnect; /**< Service disconnect callback */
	qcsi_process_req service_process_req; /**< Service process request callback */
	qcsi_process_req service_process_raw_req; /**< Service process raw request callback */
	qcsi_process_req service_process_pre_req; /**< Service process pre-request callback */
	qcsi_resume_ind resume_ind_cb; /**< Resume indication callback */
	qcsi_log_msg log_message_cb; /**< Log message callback */
	void *service_cookie; /**< Service cookie */
	qcsi_xport_options_type xport_options; /**< Transport options */
	struct qcsi_xport_s *xport; /**< Xport associated with the server */
	uint32_t num_xports; /**< Number of xports */
	LIST(struct qcsi_client_s, client_list); /**< List of active clients associated with this service */
	uint32_t idl_version; /**< IDL Version, which contains instance ID if set */

#ifdef QCSI_OS_DATA
	QCSI_OS_DATA; /**< Placeholder for implementation/OS specific data */
#endif
} qcsi_service_type;

/**
 * @brief QMI CSI transport structure.
 */
typedef struct qcsi_xport_s {
	struct qcsi_xport_ops_s *ops; /**< Xport operations table */
	uint32_t addr_len; /**< Address length of xport */
	void *handle; /**< Opaque handle returned by xport open */
	struct qcsi_service_s *service; /**< Pointer back to service */
} qcsi_xport_type;

/**
 * @brief QMI CSI transaction structure.
 */
typedef struct qcsi_txn_s {
	LINK(struct qcsi_txn_s, local); /**< Local links to previous and
                                         next in transaction list */
	LINK(struct qcsi_txn_s, global); /**< Global links to previous and
                                          next in transaction list */
	uint32_t handle; /**< Unique transaction handle */
	struct qcsi_client_s *client; /**< Pointer to client */
	txn_id_type txn_id; /**< Transaction ID */
	uint16_t pool_allocated; /**< Pool allocated flag */
	uint16_t msg_id; /**< Message ID for verification */
} qcsi_txn_type;

/**
 * @brief Client structure for QMI CSI.
 */
typedef struct qcsi_client_s {
	LINK(struct qcsi_client_s, local); /**< Local link in client list */
	LINK(struct qcsi_client_s, global); /**< Global link in client list */

	uint32_t handle; /**< Unique client handle */

	struct {
		qcsi_xport_type *xport; /**< Pointer to xport */
		uint8_t addr[MAX_ADDR_LEN]; /**< Address of client - opaque storage */
		void *client_data; /**< Per-client xport-level storage, e.g., tx queue */
	} xport;

	void *connection_handle; /**< Connection handle */

	LIST(struct qcsi_txn_s, txn_list); /**< List of active transactions */
	LIST(struct qcsi_txn_s, txn_free_list); /**< List of free transactions */

	struct qcsi_txn_s txn_pool[TXN_POOL_SIZE]; /**< Transaction pool */

	struct qcsi_service_s *service; /**< Pointer back to service */

	uint16_t next_ind_txn_id; /**< TXN ID counter for indications */
} qcsi_client_type;

/**
 * @brief Callback function type for opening a new transport.
 *
 * This callback function is called by the QCSI infrastructure to open a new
 * transport.
 *
 * @param[in] xport_data Opaque parameter to the xport (e.g., port ID).
 * @param[in] xport Pointer to infrastructure's transport struct.
 *                  Can be treated as opaque, but prototyped for ease of
 *                  debugging.
 * @param[in] max_rx_len Maximum length of messages that can be received.
 *                       Used by xport to allocate a buffer if the underlying
 *                       transport cannot pass the message through a callback.
 * @param[in] os_params OS-specific parameters passed into qcsi_register.
 *                      Used as output in case of fd_set to be used with
 *                      select().
 * @param[in] options Options for the xport.
 *                    See qcsi_xport_options_type for more information.
 *
 * @retval Opaque handle to the transport. NULL on failure.
 */
typedef void *(*qcsi_open_fn_type)
(
	void *xport_data,
	qcsi_xport_type *xport,
	uint32_t max_rx_len,
	qcsi_os_params *os_params,
	qcsi_xport_options_type *options
);

/**
 * @brief Callback function type for registering a new server.
 *
 * This callback function is called by the QCSI infrastructure to register a
 * new server.
 *
 * @param[in] handle Opaque handle returned by the open call.
 * @param[in] service_id Service ID of the server.
 * @param[in] version Version of the service.
 *
 * @retval QCSI_NO_ERR Success.
 */
typedef qcsi_error (*qcsi_reg_fn_type)
(
	void *handle,
	uint32_t service_id,
	uint32_t version
);

/**
 * @brief Callback function type for sending data to a client.
 *
 * This callback function is called by the QCSI infrastructure to send data to
 * a client.
 *
 * @param[in] handle Opaque handle returned by the open call.
 * @param[in] addr Opaque address sent to the infrastructure through the
 *                 connect or recv calls.
 * @param[in] msg Pointer to message to be sent.
 * @param[in] msg_len Length of the message.
 * @param[in] flags Or'd flag options for this send.
 *                   Currently supported:
 *                     - QCSI_SEND_FLAG_RATE_LIMITED: Rate limit this send.
 * @param[in] client_data Pointer to client-specific storage, if defined.
 *
 * @retval QCSI_NO_ERR Success.
 */
typedef qcsi_error (*qcsi_send_fn_type)
(
	void *handle,
	void *addr,
	uint8_t *msg,
	uint32_t msg_len,
	uint32_t flags,
	void **client_data
);

/**
 * @brief Callback function type for handling events.
 *
 * This callback function is called by the QCSI infrastructure to handle events
 * after the service wakes up and calls qcsi_handle_events. The function
 * should dequeue all received data and call the appropriate functions into
 * the infrastructure.
 *
 * @param[in] handle Opaque handle returned by the open call.
 * @param[in] os_params OS-specific parameters (e.g., fd_set returned by
 *                      select(), signals, events, or NULL).
 */
typedef void (*qcsi_handle_event_fn_type)
(
	void *handle,
	qcsi_os_params *os_params
);

/**
 * @brief Callback function type for closing the transport.
 *
 * This callback function is called by the QCSI infrastructure to close the
 * transport, usually when the service is unregistered. It is crucial that the
 * xport synchronize the deallocation of memory and its callback functions
 * before calling qcsi_xport_closed() to free up the rest of the data
 * associated with the service.
 *
 * @param[in] handle Opaque handle returned by the open call.
 */
typedef void (*qcsi_close_fn_type)
(
	void *handle
);

/**
 * @brief Callback function type for retrieving the length of the address.
 *
 * This callback function is called by the QCSI infrastructure to retrieve the
 * length of the (source) address of the xport.
 *
 * @retval Length of address.
 */
typedef uint32_t (*qcsi_addr_len_fn_type)
(
	void
);

/**
 * @brief Transport operations table type.
 */
typedef struct qcsi_xport_ops_s {
	qcsi_reg_fn_type  reg;
	qcsi_reg_fn_type  unreg;
	qcsi_handle_event_fn_type handle_event;
	qcsi_close_fn_type close;
	qcsi_addr_len_fn_type addr_len;
	qcsi_open_fn_type open;
	qcsi_send_fn_type send;
} qcsi_xport_ops_type;

/**
 * @brief function is used to register a transport with the infrastructure
 *
 * param[in]   ops                Pointer to transport operations table
 * param[in]   xport_data         Opaque data associated with the transport,
 *                               such as port ID or other parameters.
 */
qcsi_error qcsi_init
(
        qcsi_xport_ops_type     *xport_ops,
        void                    *xport_data
);

/**
 * @brief function is used to deregister a transport with the infrastructure.
 *
 */
qcsi_error qcsi_deinit(void);

/**
 * @brief Signal the infrastructure that a previously busy endpoint is now
 *        accepting indications.
 *
 * @param[in] xport Pointer to infrastructure's xport struct.
 * @param[in] addr Pointer to source address.
 */
void qcsi_xport_resume_client
(
	qcsi_xport_type *xport,
	void *addr
);

/**
 * @brief Signal to the infrastructure that a new client has connected.
 *
 * In a connectionless environment, this step is unnecessary.
 *
 * @param[in] xport Pointer to infrastructure's xport struct.
 * @param[in] addr Pointer to source address.
 *
 * @retval QCSI_NO_ERR Success.
 */
qcsi_error qcsi_xport_connect
(
	qcsi_xport_type *xport,
	void *addr
);

/**
 * @brief Signal the infrastructure to process the incoming message.
 *
 * In most cases, it is triggered by a callback to the handle_event function.
 *
 * @param[in] xport Pointer to infrastructure's xport struct.
 * @param[in] addr Pointer to source address.
 * @param[in] msg Pointer to message to be received.
 * @param[in] msg_len Length of the message.
 *
 * @retval QCSI_NO_ERR Success.
 */
qcsi_error qcsi_xport_recv
(
	qcsi_xport_type *xport,
	void *addr,
	uint8_t *buf,
	uint32_t len
);

/**
 * @brief Signal to the infrastructure that a client has disconnected.
 *
 * This function is used by the transport to signal to the infrastructure that
 * a client has disconnected. The data associated with the client will be freed.
 *
 * @param[in] xport Pointer to infrastructure's xport struct.
 * @param[in] addr Pointer to source address.
 *
 * @retval QCSI_NO_ERR Success.
 */
qcsi_error qcsi_xport_disconnect
(
	qcsi_xport_type *xport,
	void *addr
);

/**
 * @brief Signal to the infrastructure that the transport has been fully closed.
 *
 * This function is used by the transport to signal to the infrastructure that
 * the transport has been fully closed, no more callbacks can occur, and the
 * xport-specific data has been deallocated. The infrastructure will then free
 * data associated with the clients and service that unregistered.
 *
 * @param[in] xport Pointer to infrastructure's xport struct.
 */
void qcsi_xport_closed
(
	qcsi_xport_type *xport
);

#endif
