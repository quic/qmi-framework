// Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
/**
  @file
    qmi_idl_lib.h

  @brief
    This file contains the public APIs for the QMI IDL message library. It
    includes functions for encode/decoding messages and accessing fields of
    QMI IDL Service Objects generated by the idl_compiler.
*/
#ifndef QMI_IDL_LIB_H
#define QMI_IDL_LIB_H

#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QMI_IDL_LIB_NO_ERR                           0
#define QMI_IDL_LIB_EXTENDED_ERR                    -40
#define QMI_IDL_LIB_BUFFER_TOO_SMALL                -41
#define QMI_IDL_LIB_ARRAY_TOO_BIG                   -42
#define QMI_IDL_LIB_MESSAGE_ID_NOT_FOUND            -43
#define QMI_IDL_LIB_TLV_DUPLICATED                  -44
#define QMI_IDL_LIB_LENGTH_INCONSISTENCY            -45
#define QMI_IDL_LIB_MISSING_TLV                     -46
#define QMI_IDL_LIB_PARAMETER_ERROR                 -47
#define QMI_IDL_LIB_UNRECOGNIZED_SERVICE_VERSION    -48
#define QMI_IDL_LIB_UNKNOWN_MANDATORY_TLV           -49
#define QMI_IDL_LIB_INCOMPATIBLE_SERVICE_VERSION    -50
#define QMI_IDL_LIB_RANGE_FAILURE                   -51

/* QMI message types for ipc_message_encode() and ipc_message_decode() */
/**
   qmi_idl_type_of_message_type
     - QMI message type, distinguishes between request, response and indication.
*/
typedef enum {
	QMI_IDL_REQUEST = 0,          /**< QMI Request  */
	QMI_IDL_RESPONSE,             /**< QMI Response */
	QMI_IDL_INDICATION,           /**< QMI Indication */
	QMI_IDL_NUM_MSG_TYPES         /**< Sentinel for error checking */
} qmi_idl_type_of_message_type;

/**
   qmi_idl_service_object_type
     - QMI IDL service object, just a handle for clients to use.
*/

typedef struct qmi_idl_service_object *qmi_idl_service_object_type;

typedef struct qmi_idl_type_table_object qmi_idl_type_table_object;

/*===========================================================================
  FUNCTION  qmi_idl_get_service_id
===========================================================================*/
/*!
@brief
  Accessor function for getting the service ID from a service object.

@param[in]  service        Pointer to service object, result from service
                           object accessor function from service header file.
@param[out] service_id     Pointer to return value, the service ID

@retval    QMI_NO_ERR     Success
@retval    QMI_IDL_...    Error, see error codes defined in this file

*/
/*=========================================================================*/
int32_t qmi_idl_get_service_id
(
	const qmi_idl_service_object_type service,
	uint32_t *service_id
);

/*===========================================================================
  FUNCTION  qmi_idl_get_idl_minor_version
===========================================================================*/
/*!
@brief
  Accessor function for getting the IDL version from a service object.

@param[in]  service        Pointer to service object, result from service
                           object accessor function from service header file.
@param[out] idl_version     Pointer to return value, the service ID

@retval    QMI_NO_ERR     Success
@retval    QMI_IDL_...    Error, see error codes defined in this file

*/
/*=========================================================================*/
int32_t qmi_idl_get_idl_minor_version
(
	const qmi_idl_service_object_type service,
	uint32_t *idl_version
);

/*===========================================================================
  FUNCTION  qmi_idl_get_idl_version
===========================================================================*/
/*!
@brief
  Accessor function for getting the IDL version from a service object.

@param[in]  service        Pointer to service object, result from service
                           object accessor function from service header file.
@param[out] idl_version     Pointer to return value, the service ID

@retval    QMI_NO_ERR     Success
@retval    QMI_IDL_...    Error, see error codes defined in this file

*/
/*=========================================================================*/
int32_t qmi_idl_get_idl_version
(
	const qmi_idl_service_object_type service,
	uint32_t *idl_version
);


/*===========================================================================
  FUNCTION  qmi_idl_get_max_service_len
===========================================================================*/
/*!
@brief
  Accessor function for getting the maximum message length for a particular
  service.

@param[in]  service        Pointer to service object, result from service
                           object accessor function from service header file.
@param[out] service_len    Pointer to return value, the maximum message
                           length for the service.

@retval    QMI_NO_ERR     Success
@retval    QMI_IDL_...    Error, see error codes defined in this file

*/
/*=========================================================================*/
int32_t qmi_idl_get_max_service_len
(
	const qmi_idl_service_object_type service,
	uint32_t *service_len
);

/*===========================================================================
  FUNCTION  qmi_idl_get_max_message_len
===========================================================================*/
/*!
@brief
  Accessor function for getting the maximum message length for a particular
  message.

@param[in]  service       Pointer to service object, result from service
                          object accessor function from service header file.
@param[in]  message_type  The type of message: request, response, or indication.
@param[in]  message_id    Message ID from IDL.
@param[out] message_len   Pointer to the return value, the maximum message
                          length for the service, message type, and message ID.

@retval    QMI_NO_ERR     Success
@retval    QMI_IDL_...    Error, see error codes defined in this file

*/
/*=========================================================================*/
int32_t qmi_idl_get_max_message_len
(
	const qmi_idl_service_object_type service,
	qmi_idl_type_of_message_type message_type,
	uint16_t message_id,
	uint32_t *message_len
);

/*===========================================================================
  FUNCTION  qmi_idl_get_message_c_struct_len
===========================================================================*/
/*!
@brief
  Accessor function for getting the c struct size for a particular
  message.

@param[in]  service       Pointer to service object, result from service
                          object accessor function from service header file.
@param[in]  message_type  The type of message: request, response, or indication.
@param[in]  message_id    Message ID from IDL.
@param[out] c_struct_len  Pointer to the return value, the c struct size for
                          structure corresponding to the service,message type
                          and message_id.

@retval    QMI_NO_ERR     Success
@retval    QMI_IDL_...    Error, see error codes defined in this file

*/
/*=========================================================================*/
int32_t qmi_idl_get_message_c_struct_len
(
	const qmi_idl_service_object_type service,
	qmi_idl_type_of_message_type message_type,
	uint16_t message_id,
	uint32_t *c_struct_len
);

/*===========================================================================
  FUNCTION  qmi_idl_get_max_c_struct_len
===========================================================================*/
/*!
@brief
  Accessor function for getting the max c struct size for a particular
  service.

@param[in]  service       Pointer to service object, result from service
                          object accessor function from service header file.
@param[out] c_struct_len  Pointer to the return value, the c struct size for
                          structure corresponding to the service,message type
                          and message_id.

@retval    QMI_NO_ERR     Success
@retval    QMI_IDL_...    Error, see error codes defined in this file

*/
/*=========================================================================*/
int32_t qmi_idl_get_max_c_struct_len
(
	const qmi_idl_service_object_type p_service,
	uint32_t *c_struct_len
);

/*===========================================================================
  FUNCTION  qmi_idl_message_decode
===========================================================================*/
/*!
@brief
  Decodes the body (TLV's) of a QMI message body from the wire format to the
  C structure.

@param[in]  service       Pointer to service object, result from service
                          object accessor function from service header file.
@param[in]  message_type  The type of message: request, response, or indication.
@param[in]  message_id    Message ID from IDL.
@param[in]  p_src         Pointer to beginning of first TLV in message.
@param[in]  src_len       Length of p_src buffer in bytes.
@param[out] p_dst         Pointer to C structure for decoded data
@param[in]  dst_len       Length (size) of p_dst C structure in bytes.

@retval    QMI_NO_ERR     Success
@retval    QMI_IDL_...    Error, see error codes defined in this file
*/
/*=========================================================================*/
int32_t qmi_idl_message_decode
(
	const qmi_idl_service_object_type service,
	qmi_idl_type_of_message_type message_type,
	uint16_t message_id,
	const void *p_src,
	uint32_t src_len,
	void *p_dst,
	uint32_t dst_len
);

/*===========================================================================
  FUNCTION  qmi_idl_message_encode
===========================================================================*/
/*!
@brief
  Encodes the body (TLV's) of a QMI message from the C data structure to the
  wire format.

@param[in]  service       Pointer to service object, result from service
                          object accessor function from service header file.
@param[in]  message_type  The type of message: request, response, or indication.
@param[in]  message_id    Message ID from IDL.
@param[in]  p_src         Pointer to C structure containing message data.
@param[in]  src_len       Length (size) of p_src C structure in bytes.
@param[out] p_dst         Pointer to beginning of first TLV in message.
@param[in]  dst_len       Length of p_dst buffer in bytes.
@param[out] dst_decoded_len Pointer to the return value, the length of
                          encoded message (to be filled in as the length
                          field in the QMI header).

@retval    QMI_NO_ERR     Success
@retval    QMI_IDL_...    Error, see error codes defined in this file

*/
/*=========================================================================*/
int32_t qmi_idl_message_encode
(
	const qmi_idl_service_object_type service,
	qmi_idl_type_of_message_type message_type,
	uint16_t message_id,
	const void *p_src,
	uint32_t src_len,
	void *p_dst,
	uint32_t dst_len,
	uint32_t *dst_encoded_len
);

/*===========================================================================
  FUNCTION  qmi_idl_message_encode
===========================================================================*/
/*!
@brief
  Encodes the TLV of the standard response message, primarily for use of the
  QMI infrastructure

@param[in]  result        Result value for the response TLV
@param[in]  error         Error value for the response TLV
@param[out] p_dst         Pointer to buffer to hold the response TLV.
@param[in]  dst_len       Length of p_dst buffer in bytes.

@retval    QMI_NO_ERR     Success
@retval    QMI_IDL_...    Error, see error codes defined in this file

*/
/*=========================================================================*/
int32_t qmi_idl_encode_resp_tlv
(
	uint16_t result,
	uint16_t error,
	void *p_dst,
	uint32_t dst_len
);

/*===========================================================================
  FUNCTION  qmi_idl_get_std_resp_tlv_len
===========================================================================*/
/*!
@brief
  Returns the length of a standard response message

@retval    length of the standard response

*/
/*=========================================================================*/
uint32_t qmi_idl_get_std_resp_tlv_len(void);

/*===========================================================================
  FUNCTION  qmi_idl_inherit_service_object
===========================================================================*/
/*!
@brief
  Inherits a parent service object

@param[in/out] child_service    The service object that will be used with QCCI/QCSI
@param[in]     parent_service   The service object to inherit messages from. Parent_service_obj
                                of this field MUST be NULL.

@retval    QMI_NO_ERR     Success
@retval    QMI_IDL_...    Error, see error codes defined in this file

*/
/*=========================================================================*/
int32_t qmi_idl_inherit_service_object
(
	qmi_idl_service_object_type child_service,
	qmi_idl_service_object_type parent_service
);

/*===========================================================================
  FUNCTION  qmi_idl_inherit_service_object
===========================================================================*/
/*!
@brief
  Returns a parent service object that was previously inherited.

@param[in] service    The service object that will be used with QCCI/QCSI

@retval inherited service object, or NULL

*/
/*=========================================================================*/
qmi_idl_service_object_type qmi_idl_get_inherited_service_object
(
	qmi_idl_service_object_type service
);

#ifdef __cplusplus
}
#endif
#endif  /* QMI_IDL_LIB_H */
