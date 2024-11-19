// Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#ifndef QCSI_H
#define QCSI_H
/******************************************************************************
  @file    qcsi.h
  @brief   The QMI Common Service Interface (CSI) Header file.

  DESCRIPTION
  QMI common server routines.  All server will be build on top of these
  routines for initializing, sending responses and indications.
*******************************************************************************/
#include "qcsi_target_ext.h"
#include "qmi_idl_lib.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef enum {
	QCSI_NO_ERR = 0,
	QCSI_CONN_REFUSED,
	QCSI_CONN_BUSY,
	QCSI_INVALID_HANDLE,
	QCSI_INVALID_ARGS,
	QCSI_ENCODE_ERR,
	QCSI_DECODE_ERR,
	QCSI_NO_MEM,
	QCSI_INTERNAL_ERR
} qcsi_error;

typedef enum {
	QCSI_CB_NO_ERR = 0,
	QCSI_CB_CONN_REFUSED,
	QCSI_CB_NO_MEM,
	QCSI_CB_INTERNAL_ERR,
	QCSI_CB_UNSUPPORTED_ERR,
	QCSI_CB_REQ_HANDLED,
} qcsi_cb_error;

/* Describe handles including theory of operation */
/* Private opaque handles */
typedef struct         qmi_client_handle_struct      *qmi_client_handle;
typedef struct         qmi_req_handle_struct         *qmi_req_handle;

/* Service handle */
typedef struct         qcsi_service_struct        *qcsi_service_handle;

typedef struct qcsi_options_struct qcsi_options;

/*=============================================================================
  INTERNAL DEFINES
=============================================================================*/
#define QCSI_OPTIONS_INSTANCE_ID_VALID (1)
#define QCSI_OPTIONS_MAX_OUTSTANDING_INDS_VALID (2)
#define QCSI_OPTIONS_RAW_REQUEST_VALID (8)
#define QCSI_OPTIONS_PRE_REQUEST_VALID (16)
#define QCSI_OPTIONS_RESUME_VALID (32)
#define QCSI_OPTIONS_LOG_MSG_CB_VALID (128)

/*=============================================================================
  MACRO  QCSI_OPTIONS_INIT
=============================================================================*/
/*!
@brief
  Initialize the QMI CSI Options object. Always call this before
  setting any other options field.

@param[in]  opt                 Service options object
*/
/*=========================================================================*/
#define QCSI_OPTIONS_INIT(opt) (opt).options_set = 0

/*=============================================================================
  MACRO  QCSI_OPTIONS_SET_INSTANCE_ID
=============================================================================*/
/*!
@brief
  Set the instance ID of the service. Default: 0

@param[in]  opt                 Service options object
@param[in]  inst                Instance ID of the service
*/
/*=========================================================================*/
#define QCSI_OPTIONS_SET_INSTANCE_ID(opt, inst) \
	do { \
		(opt).instance_id = inst; \
		(opt).options_set |= QCSI_OPTIONS_INSTANCE_ID_VALID; \
	} while(0)

/*=============================================================================
  MACRO  QCSI_OPTIONS_SET_MAX_OUTSTANDING_INDS
=============================================================================*/
/*!
@brief
  Set the Max number of indications which are allowed to be in flight
  (Outstanding) Default: Implementation defined

@param[in]  opt                   Service options object
@param[in]  _max_outstanding_inds Maximum number of outstanding indications
                                  allowed
*/
/*=========================================================================*/
#define QCSI_OPTIONS_SET_MAX_OUTSTANDING_INDS(opt, _max_outstanding_inds) \
	do {  \
		(opt).max_outstanding_inds = _max_outstanding_inds;  \
		(opt).options_set |= QCSI_OPTIONS_MAX_OUTSTANDING_INDS_VALID;  \
	} while(0)
/*=============================================================================
  MACRO  QCSI_OPTIONS_SET_RAW_REQUEST_CB
=============================================================================*/
/*!
@brief
  Sets a raw request handler. If the received request message ID is not
  defined in the IDL, this handler will be called with the pre-decoded
  (raw) request buffer. Note the handler has the same prototype as
  qcsi_process_req (See down) except the raw buffer is passed in the
  `req_c_struct` field and the buffer length is passed in the
  `req_c_struct_len` field. Returning anything other than QCSI_CB_NO_ERR
  will cause the framework to send an error response on the behalf of the
  service. Default: messages not defined in the IDL will incur a auto-error
  response to be sent back to the client on service's behalf.

@param[in]  opt                 Service options object
@param[in]  _raw_req            Raw request handler
*/
/*=========================================================================*/
#define QCSI_OPTIONS_SET_RAW_REQUEST_CB(opt, _raw_req) \
	do {  \
		(opt).raw_request_cb = _raw_req;  \
		(opt).options_set |= QCSI_OPTIONS_RAW_REQUEST_VALID; \
	} while(0)

/*=============================================================================
  MACRO  QCSI_OPTIONS_SET_PRE_REQUEST_CB
=============================================================================*/
/*!
@brief
  Sets the pre-request handler. If provided, the framework shall call this
  function before decoding the request message. The service then can decide
  if it wants to handle this message raw (Returns QCSI_CB_REQ_HANDLED),
  request the framework to go ahead and decode the message and call the
  request cb (Returns QCSI_CB_NO_ERR) or refuse the request
  message (Returns an error code other than QCSI_CB_NO_ERR or
  QCSI_CB_REQ_HANDLED). The callback just like the raw request callback
  also uses the qcsi_process_req prototype with the raw message provided
  in the field `req_c_struct` and the length of the buffer in `req_c_struct_len`.

@param[in]  opt                 Service options object
@param[in]  _pre_req            Pre-request handler
*/
/*=========================================================================*/
#define QCSI_OPTIONS_SET_PRE_REQUEST_CB(opt, _pre_req) \
	do {  \
		(opt).pre_request_cb = _pre_req;  \
		(opt).options_set |= QCSI_OPTIONS_PRE_REQUEST_VALID; \
	} while(0)

/*=============================================================================
  MACRO  QCSI_OPTIONS_SET_RESUME_IND_CB
=============================================================================*/
/*!
@brief
  Sets a TX resume handler which will be called by the framework
  when a previously busy client is now accepting indications.
  Note that the callback will be called only when a call to
  qcsi_send_ind*() returns QCSI_CONN_BUSY

@param[in]  opt                 Service options object
@param[in]  _resume_cb          Resume TX callback function
                                (See prototype: qcsi_resume)
*/
/*=========================================================================*/
#define QCSI_OPTIONS_SET_RESUME_IND_CB(opt, _resume_cb_) \
	do {  \
		(opt).resume_ind_cb = _resume_cb_;  \
		(opt).options_set |= QCSI_OPTIONS_RESUME_VALID; \
	} while(0)

/*=============================================================================
  MACRO  QCSI_OPTIONS_SET_LOG_MSG_CB
=============================================================================*/
/*!
@brief
  Sets a logging message callback

@param[in]  opt                 Service options object
@param[in]  _log_msg_cb_        Log Message Callback
*/
/*=========================================================================*/
#define QCSI_OPTIONS_SET_LOG_MSG_CB(opt, _log_msg_cb_) \
	do {  \
		(opt).log_msg_cb = _log_msg_cb_; \
		(opt).options_set |= QCSI_OPTIONS_LOG_MSG_CB_VALID; \
	} while(0)

/*============================================================================
                            CALLBACK FUNCTIONS
============================================================================*/


/*=============================================================================
  CALLBACK FUNCTION qcsi_connect
=============================================================================*/
/*!
@brief
  This callback function is called by the QCSI infrastructure when
  infrastructure receives a request from each client(user of the service).

@param[in]   client_handle       Handle used by the infrastructure to
                                 identify different services.
@param[in]   service_cookie      Service specific data. Service cookie is
                                 registered with the infrastructure during
                                 service registration(qcsi_register).
@param[out]  connection_handle   Services return this handle as a token to
                                 represent this client connection
                                 to the service.

@retval    QCSI_CB_NO_ERR     Success
@retval    QCSI_CB.....       Look into the enumeration qcsi_error for
                                 the error values.
*/
/*=========================================================================*/
typedef qcsi_cb_error (*qcsi_connect)
(
	qmi_client_handle         client_handle,
	void                      *service_cookie,
	void                      **connection_handle
);

/*=============================================================================
  CALLBACK FUNCTION qcsi_disconnect
=============================================================================*/
/*!
@brief
  This callback function is called by the QCSI infrastructure when the each
  client(user of service) deregisters with the  QCSI infrastructure.

@param[in]  connection_handle      Service handle as given by the service in
                                   qcsi_connect for the client
                                   disconnecting.
@param[in]  service_cookie         Service specific data.Service cookie is
                                   registered with the infrastructure during
                                   service registration(qcsi_register).
@retval    QCSI_CB_NO_ERR       Success
@retval    QCSI_CB.....         Look into the enumeration qcsi_error for
                                   the error values.
*/
/*=========================================================================*/
typedef void (*qcsi_disconnect)
(
	void                     *connection_handle,
	void                     *service_cookie
);

/*=============================================================================
  CALLBACK FUNCTION qcsi_process_req
=============================================================================*/
/*!
@brief
   This callback is invoked when the infrastructure receives an
   incoming message. The infrastructure decodes the data and gives it to
   the services.

@param[in]  connection_handle      Service handle as given by the service in
                                   qcsi_connect.
@param[in]  req_handle             Handle provided by the infrastructure
                                   to specify this particular transaction and
                                   message.
@param[in]  msg_id                 Message Id pertaining to this particular
                                   message.
@param[in]  req_c_struct           C struct with the decoded data.
@param[in]  req_c_struct_len       Length of the c struct.
@param[in]  service_cookie         Service specific data.Service cookie is
                                   registered with the infrastructure during
                                   service registration(qcsi_register).


@retval    QCSI_CB_NO_ERR       Success
@retval    QCSI_CB.....         Look into the enumeration qcsi_error for
                                   the error values.
*/
/*=========================================================================*/
typedef qcsi_cb_error (*qcsi_process_req)
(
	void                     *connection_handle,
	qmi_req_handle           req_handle,
	unsigned int             msg_id,
	void                     *req_c_struct,
	unsigned int             req_c_struct_len,
	void                     *service_cookie
);

/*=============================================================================
  CALLBACK FUNCTION qcsi_resume_ind
=============================================================================*/
/*!
@brief
  This callback function (if provided) is called by the framework
  when a previously busy client becomes available for more indications.
  (See QCSI_OPTIONS_SET_RESUME_CB)

@param[in]   client_handle       Handle used by the infrastructure to
                                 identify different services.
@param[in]  connection_handle    Service handle as given by the service in
                                 qcsi_connect.
@param[in]   service_cookie      Service specific data. Service cookie is
                                 registered with the infrastructure during
                                 service registration(qcsi_register).
                                 represent this client connection
                                 to the service.

@retval    None
*/
/*=========================================================================*/
typedef void (*qcsi_resume_ind)
(
	qmi_client_handle         client_handle,
	void                      *connection_handle,
	void                      *service_cookie
);

/*=============================================================================
  CALLBACK FUNCTION qcsi_log_msg
=============================================================================*/
/*!
@brief
  This callback function (if provided) is called by the framework
  when messages are received or sent, allowing the service to log
  the message however they would like.

@param[in]  service_obj         Object containing meta information to
                                encode/decode the messages.
@param[in]  msg_type            Request, Response, or Indication.
@param[in]  msg_id              Message Id pertaining to this particular
                                message.
@param[in]  req_msg_buf         Encoded buffer with the message data.
@param[in]  req_msg_len         Length of the encoded message buffer.

@retval    None
*/
/*=========================================================================*/
typedef void (*qcsi_log_msg)
(
	qmi_idl_service_object_type               service_obj,
	qmi_idl_type_of_message_type              msg_type,
	unsigned int                              msg_id,
	void                                      *req_msg_buf,
	unsigned int                              req_msg_len,
	unsigned int                              txn_id
);

/*===========================================================================
                        FUNCTIONS
============================================================================*/


/*=============================================================================
  FUNCTION  qcsi_register
=============================================================================*/
/*!
@brief
  Register a service with the QCSI infrastructure.

@param[in]  service_obj         Object containing meta information to
                                encode/decode the messages.
@param[in]  service_connect     Callback to register each client with the
                                service.
@param[in]  service_disconnect  Callback to unregister each client from
                                service.
@param[in]  service_process_req Callback that handles the incoming requests.
@param[in]  service_cookie      User data.
@param[out] service_provider    Handle that infra provides to represent this
                                service connection.
@retval    QCSI_NO_ERR       Success
@retval    qcsi_.....        Look into the enumeration qcsi_error for
                                the error values.
*/
/*=========================================================================*/

qcsi_error
qcsi_register
(
	qmi_idl_service_object_type               service_obj,
	qcsi_connect                           service_connect,
	qcsi_disconnect                        service_disconnect,
	qcsi_process_req                       service_process_req,
	void                                      *service_cookie,
	qcsi_os_params                         *os_params,
	qcsi_service_handle                    *service_provider
);


/*=============================================================================
  FUNCTION  qcsi_register_with_options
=============================================================================*/
/*!
@brief
  Register a service with the QCSI infrastructure.

@param[in]  service_obj         Object containing meta information to
                                encode/decode the messages.
@param[in]  service_connect     Callback to register each client with the
                                service.
@param[in]  service_disconnect  Callback to unregister each client from
                                service.
@param[in]  service_process_req Callback that handles the incoming requests.
@param[in]  service_cookie      User data.
@param[in]  options             Options as defined by qcsi_options
@param[out] service_provider    Handle that infra provides to represent this
                                service connection.
@retval    QCSI_NO_ERR       Success
@retval    QCSI_.....        Look into the enumeration qcsi_error for
                                the error values.
*/
/*=========================================================================*/

qcsi_error
qcsi_register_with_options
(
	qmi_idl_service_object_type               service_obj,
	qcsi_connect                           service_connect,
	qcsi_disconnect                        service_disconnect,
	qcsi_process_req                       service_process_req,
	void                                      *service_cookie,
	qcsi_os_params                         *os_params,
	qcsi_options                           *options,
	qcsi_service_handle                    *service_provider
);

/*=============================================================================
  FUNCTION  qcsi_handle_event
=============================================================================*/
/*!
@brief
  Handle event after the server thread receives an event notification.
  Callbacks from qcsi_register may be invoked in the server's context.

@param[in] service_provider    Opaque handle that defines the service.
@param[in] os_params           OS-defined parameters such as file handle.

@retval    QCSI_NO_ERR       Success
@retval    Other error codes    Failure
*/
/*=========================================================================*/

qcsi_error
qcsi_handle_event
(
	qcsi_service_handle                    service_provider,
	qcsi_os_params                         *os_params
);

/*=============================================================================
  FUNCTION  qcsi_send_resp
=============================================================================*/
/*!
@brief
  Sends a response to the client.

@param[in]  req_handle            Handle used by QCSI infrastructure to
                                  identify the transaction and the destination
                                  client.
@param[in]  msg_id                Message ID for this particular message.
@param[in]  resp_c_struct         C data structure for this response.
@param[in]  resp_c_struct_len     Size of the response c struct.

@retval  QCSI_NO_ERR           Success.
@retval  qcsi_.....            Look into the enumeration qcsi_error for
                                  the error values.
*/
/*=========================================================================*/
qcsi_error
qcsi_send_resp
(
	qmi_req_handle     req_handle,
	unsigned int       msg_id,
	void               *resp_c_struct,
	unsigned int       resp_c_struct_len
);

/*=============================================================================
  FUNCTION  qcsi_send_resp_raw
=============================================================================*/
/*!
@brief
  Sends a response to the client without encoding.

@param[in]  req_handle            Handle used by QCSI infrastructure to
                                  identify the transaction and the destination
                                  client.
@param[in]  msg_id                Message ID for this particular message.
@param[in]  resp_buf              Response buffer
@param[in]  resp_buf_len          Size of the response buffer

@retval  QCSI_NO_ERR           Success.
@retval  QCSI_.....            Look into the enumeration qcsi_error for
                                  the error values.
*/
/*=========================================================================*/
qcsi_error
qcsi_send_resp_raw
(
	qmi_req_handle     req_handle,
	unsigned int       msg_id,
	void               *resp_buf,
	unsigned int       resp_buf_len
);

/*=============================================================================
  FUNCTION  qcsi_send_ind
=============================================================================*/
/*!
@brief
  Sends an indication to the client.

@param[in]  client_handle            Handle used by QCSI infrastructure
                                     to identify the destination client.
@param[in]  msg_id                   Message ID for this particular message.
@param[in]  ind_c_struct             C data strcuture for this indication.
@param[in]  ind_c_struct_len         Size of the indication c struct

@retval    QCSI_NO_ERR            Success.
@retval    QCSI_.....             Look into the enumeration qcsi_error for
                                     the error values.
*/
/*=========================================================================*/
qcsi_error
qcsi_send_ind
(
	qmi_client_handle  client_handle,
	unsigned int       msg_id,
	void               *ind_c_struct,
	unsigned int       ind_c_struct_len
);

/*=============================================================================
  FUNCTION  qcsi_send_ind_raw
=============================================================================*/
/*!
@brief
  Sends an indication to the client without encoding

@param[in]  client_handle            Handle used by QCSI infrastructure
                                     to identify the destination client.
@param[in]  msg_id                   Message ID for this particular message.
@param[in]  ind_buf                  Indication buffer.
@param[in]  ind_buf_len              Size of the indication buffer.

@retval    QCSI_NO_ERR            Success.
@retval    QCSI_.....             Look into the enumeration qcsi_error for
                                     the error values.
*/
/*=========================================================================*/
qcsi_error
qcsi_send_ind_raw
(
	qmi_client_handle  client_handle,
	unsigned int       msg_id,
	void               *ind_buf,
	unsigned int       ind_buf_len
);

/*=============================================================================
  FUNCTION  qcsi_send_broadcast_ind
=============================================================================*/
/*!
@brief
  Sends a broadcast indication to all registered clients.

@param[in]  service_provider         Handle used by QCSI infrastructure
                                     to identify the service that intends to
                                     send a broadcast message.
@param[in]  msg_id                   Message ID for this particular message.
@param[in]  ind_c_struct             C data structure for this broadcast
                                     indication.
@param[in]  ind_c_struct_len         Size of the broadcast indication

@retval    QCSI_NO_ERR            Success
@retval    QCSI_.....             Look into the enumeration qcsi_error for
                                     the error values.
*/
/*=========================================================================*/

qcsi_error
qcsi_send_broadcast_ind
(
	qcsi_service_handle   service_provider,
	unsigned int             msg_id,
	void                     *ind_c_struct,
	unsigned int             ind_c_struct_len
);

/*=============================================================================
  FUNCTION  qcsi_send_broadcast_ind_raw
=============================================================================*/
/*!
@brief
  Sends a raw broadcast indication to all registered clients

@param[in]  service_provider         Handle used by QCSI infrastructure
                                     to identify the service that intends to
                                     send a broadcast message.
@param[in]  msg_id                   Message ID for this particular message.
@param[in]  ind_buf                  broadcast indication buffer
@param[in]  ind_buf_len              Size of the broadcast indication

@retval    qcsi_NO_ERR            Success
@retval    QCSI_.....             Look into the enumeration qcsi_error for
                                     the error values.
*/
/*=========================================================================*/

qcsi_error
qcsi_send_broadcast_ind_raw
(
	qcsi_service_handle   service_provider,
	unsigned int             msg_id,
	void                     *ind_buf,
	unsigned int             ind_buf_len
);

/*=============================================================================
  FUNCTION  qcsi_unregister
=============================================================================*/
/*!
@brief
  Unregisters a server.

@param[in]  service_provider         Handle given in the qcsi_register by
                                     the service.
@retval     QCSI_NO_ERR           Success
@retval     QCSI_.....            Look into the enumeration qcsi_error for
                                     the error values.
*/
/*=========================================================================*/
qcsi_error
qcsi_unregister
(
	qcsi_service_handle service_provider
);

/*=============================================================================
  PRIVATE qcsi_options_struct
=============================================================================*/
/*!
@brief
  Provide storage class for the options structure. This structure should not
  be directly manipulated. Please use the QCSI_OPTIONS_* macros.
*/
/*=========================================================================*/
struct qcsi_options_struct {
	unsigned int        options_set;
	unsigned int        instance_id;
	unsigned int        max_outstanding_inds;
	uint64_t            scope;
	qcsi_process_req raw_request_cb;
	qcsi_process_req pre_request_cb;
	qcsi_resume_ind  resume_ind_cb;
	qcsi_log_msg     log_msg_cb;
};

#ifdef __cplusplus
}
#endif
#endif /* QCSI_H */
