// Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
/**
 * @file qcci_xport_qrtr.c
 * @brief Implementation of QMI CCI transport over QRTR.
 *
 * This file contains the implementation of the QMI CCI transport layer over QRTR.
 */
#include <stdio.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <linux/qrtr.h>
#include "qmi_cci.h"
#include "qcci_os.h"
#include "qcci_common.h"

#define ALIGN_SIZE(x) ((4 - ((x) & 3)) & 3)

/**
* @brief Macro to translate between IPC Router specific instance information
* to QCCI specific instance information.
*
* QCCI treats instance and version fields separately and uses IDL version
* as the instance during service lookup. IPC Router passes the instance
* (MS 24 bits) + IDL Version(LS 8 bits) fields together as the instance info.
*/
#define GET_XPORT_SVC_INSTANCE(x) GET_VERSION(x)

/**
 * @brief Structure for IPC Router server address.
 */
struct xport_qrtr_server_addr {
	uint32_t service;  /**< Service ID. */
	uint32_t instance; /**< Instance ID. */
	uint32_t node_id;  /**< Node ID. */
	uint32_t port_id;  /**< Port ID. */
};

/**
 * @brief Structure for reader thread data.
 */
struct reader_tdata {
	pthread_attr_t reader_tattr; /**< Reader thread attributes. */
	pthread_t reader_tid;        /**< Reader thread ID. */
	int wakeup_pipe[2];          /**< Wakeup pipe. */
};

/**
 * @brief Structure for MSM IPC port name.
 */
struct msm_ipc_port_name {
	uint32_t service;  /**< Service ID. */
	uint32_t instance; /**< Instance ID. */
};

/**
 * @brief Structure for transport handle.
 */
struct xport_handle {
	qcci_client_type *clnt;       /**< Client type. */
	int fd;                          /**< File descriptor. */
	struct reader_tdata rdr_tdata;   /**< Reader thread data. */
	uint32_t max_rx_len;             /**< Maximum receive length. */
	struct msm_ipc_port_name srv_name; /**< Service name. */
	int srv_conn_reset;              /**< Service connection reset flag. */
	uint8_t svc_addr[MAX_ADDR_LEN];  /**< Service address. */
	uint8_t is_client;               /**< Client flag. */
	LINK(struct xport_handle, link); /**< Link to the next transport handle. */
};

/**
 * @brief Structure for control port.
 */
struct xport_ctrl_port {
	int ctl_fd;                      /**< Control file descriptor. */
	struct reader_tdata rdr_tdata;   /**< Reader thread data. */
	qcci_os_lock_type xport_list_lock; /**< Transport list lock. */
	LIST(struct xport_handle, xport); /**< List of transport handles. */
};

static struct xport_ctrl_port *ctrl_port;
static int lookup_sock_fd = -1;
static pthread_mutex_t ctrl_port_init_lock;
static pthread_mutex_t lookup_fd_lock;

/**
 * @brief Close the lookup socket file descriptor.
 */
static void close_lookup_sock_fd(void);

/**
 * @brief Deinitialize the control port.
 */
static void qcci_xport_ctrl_port_deinit(void);

/**
 * @brief Deinitialize the QMI CCI transport over QRTR.
 */
void qcci_xport_qrtr_deinit(void)
{
	qcci_xport_ctrl_port_deinit();
}

/**
 * @brief Open the lookup socket file descriptor.
 *
 * @return 0 on success, -1 on failure.
 */
static int open_lookup_sock_fd(void)
{
	pthread_mutex_lock(&lookup_fd_lock);
	if (lookup_sock_fd < 0) {
		lookup_sock_fd = socket(AF_QIPCRTR, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (lookup_sock_fd < 0) {
			pthread_mutex_unlock(&lookup_fd_lock);
			QCCI_LOG_ERR("%s: Lookup sock fd creation failed\n", __func__);
			return -1;
		}
	}
	pthread_mutex_unlock(&lookup_fd_lock);
	return 0;
}

/**
 * @brief Close the lookup socket file descriptor.
 */
static void close_lookup_sock_fd(void)
{
	pthread_mutex_lock(&lookup_fd_lock);
	close(lookup_sock_fd);
	lookup_sock_fd = -1;
	pthread_mutex_unlock(&lookup_fd_lock);
}

/**
 * @brief Send a lookup command.
 *
 * @param sock Socket file descriptor.
 * @param service Service ID.
 * @param version Version ID.
 * @return 0 on success, -1 on failure.
 */
static int send_lookup_cmd(int sock, uint32_t service, uint32_t version)
{
	struct qrtr_ctrl_pkt pkt;
	struct sockaddr_qrtr sq;
	socklen_t sl = sizeof(sq);
	int rc;

	memset(&pkt, 0, sizeof(pkt));
	pkt.cmd = qcci_os_cpu_to_le32(QRTR_TYPE_NEW_LOOKUP);
	pkt.server.service = service;
	pkt.server.instance = version;

	rc = getsockname(sock, (void *)&sq, &sl);
	if (rc || sq.sq_family != AF_QIPCRTR) {
		QCCI_LOG_ERR("%s: getsockname failed rc [%d]\n", __func__, rc);
		return -1;
	}

	sq.sq_port = QRTR_PORT_CTRL;

	rc = sendto(sock, &pkt, sizeof(pkt), 0, (void *)&sq, sizeof(sq));
	if (rc < 0) {
		QCCI_LOG_ERR("%s: sendto failed rc [%d]\n", __func__, rc);
		return -1;
	}

	return 0;
}


/*!
 * @brief	This function releases the xport handle
 *			associated with the control port.
 *
 * @param[in] xp
 *   Pointer to the xport handle to be released.
 *
 * @return	None
 */
static void release_xp(struct xport_handle *xp)
{
	struct xport_handle *temp;

	pthread_mutex_lock(&ctrl_port->xport_list_lock);
	LIST_FIND(ctrl_port->xport, temp, link, temp == xp);
	if (temp)
		LIST_REMOVE(ctrl_port->xport, temp, link);
	pthread_mutex_unlock(&ctrl_port->xport_list_lock);
	qcci_xport_closed(xp->clnt);
	free(xp);
}

/*!
 * @brief	This function process the received control message.
 *
 * @param[in] rx_ctl_ms	Pointer to the control message.
 *
 * @return	None
 */
static void ctrl_msg_process_rx(struct qrtr_ctrl_pkt *rx_ctl_msg)
{
	struct xport_handle *xp;
	struct xport_qrtr_server_addr src_addr;
	struct xport_qrtr_server_addr *s_addr;

	src_addr.service = rx_ctl_msg->server.service;
	src_addr.instance = rx_ctl_msg->server.instance;
	src_addr.node_id = rx_ctl_msg->server.node;
	src_addr.port_id = rx_ctl_msg->server.port;
	if (rx_ctl_msg->cmd == QRTR_TYPE_NEW_SERVER) {
		QCCI_LOG_DBG("Received NEW_SERVER cmd for %08x:%08x\n",
			     rx_ctl_msg->server.service,
			     rx_ctl_msg->server.instance);
		pthread_mutex_lock(&ctrl_port->xport_list_lock);
		for(xp = (ctrl_port->xport).head; xp; xp = (xp)->link.next)
			if (xp->srv_name.service ==  rx_ctl_msg->server.service &&
			    xp->srv_name.instance == GET_XPORT_SVC_INSTANCE(rx_ctl_msg->server.instance))
				qcci_xport_event_new_server(xp->clnt, &src_addr);
		pthread_mutex_unlock(&ctrl_port->xport_list_lock);
	} else if (rx_ctl_msg->cmd == QRTR_TYPE_DEL_SERVER) {
		QCCI_LOG_DBG("Received REMOVE_SERVER cmd for %08x:%08x\n",
			     rx_ctl_msg->server.service, rx_ctl_msg->server.instance);
		pthread_mutex_lock(&ctrl_port->xport_list_lock);
		for(xp = (ctrl_port->xport).head; xp; xp = (xp)->link.next) {
			if (xp->srv_name.service ==  rx_ctl_msg->server.service &&
			    xp->srv_name.instance == GET_XPORT_SVC_INSTANCE(rx_ctl_msg->server.instance)) {
				if (xp->is_client) {
					s_addr = (struct xport_qrtr_server_addr *)xp->svc_addr;
					if (s_addr->node_id == src_addr.node_id &&
					    s_addr->port_id == src_addr.port_id) {
						xp->srv_conn_reset = 1;
						/* Wake up the client reader thread only if the REMOVE_SERVER is
						 * intended for this client.
						 */
						if (write(xp->rdr_tdata.wakeup_pipe[1], "r", 1) < 0)
							QCCI_LOG_ERR("%s: Error writing to pipe\n", __func__);
					}
				} else {
					/*It is a notifier port*/
					qcci_xport_event_remove_server(xp->clnt, &src_addr);
				}
			}
		}
		pthread_mutex_unlock(&ctrl_port->xport_list_lock);
	}
}

/*!
 * @brief	This function reads all the control messages from
 *			control port for a specific process.
 *
 * @param[in] arg	Pointer to the argument passed to the thread.
 *
 * @return	None
 */
static void *ctrl_msg_reader_thread(void *arg)
{
	struct xport_handle *xp;
	unsigned char ch;
	struct qrtr_ctrl_pkt rx_ctl_msg;
	int rx_len, i;
	struct pollfd pbits[2];

	while(1) {
		pbits[0].fd = ctrl_port->rdr_tdata.wakeup_pipe[0];
		pbits[0].events = POLLIN;
		pbits[1].fd = ctrl_port->ctl_fd;
		pbits[1].events = POLLIN;

		i = poll(pbits, 2, -1);
		if(i < 0) {
			if (errno == EINTR)
				QCCI_LOG_DBG("%s: poll error (%d)\n",
					     __func__, errno);
			else
				QCCI_LOG_ERR("%s: poll error (%d)\n",
					     __func__, errno);
			continue;
		}

		if(pbits[1].revents & POLLIN) {
			rx_len = recvfrom(ctrl_port->ctl_fd, &rx_ctl_msg,
					  sizeof(rx_ctl_msg), MSG_DONTWAIT,
					  NULL, NULL);
			if (rx_len < 0) {
				QCCI_LOG_ERR("%s: Error recvfrom ctl_fd : %d\n",
					     __func__, rx_len);
				break;
			} else if (rx_len == 0) {
				QCCI_LOG_ERR("%s: No data read from %d\n",
					     __func__, ctrl_port->ctl_fd);
				continue;
			}
			ctrl_msg_process_rx(&rx_ctl_msg);
		}
		if(pbits[0].revents & POLLIN) {
			if(read(ctrl_port->rdr_tdata.wakeup_pipe[0], &ch, 1) < 0) {
				QCCI_LOG_ERR("%s: Error reading from pipe\n", __func__);
				continue;
			}
			QCCI_LOG_DBG("%s: wakeup_pipe[0]=%x ch=%c\n", __func__, pbits[0].revents, ch);
			if(ch == 'd') {
				close(ctrl_port->rdr_tdata.wakeup_pipe[0]);
				close(ctrl_port->rdr_tdata.wakeup_pipe[1]);
				close(ctrl_port->ctl_fd);
				pthread_attr_destroy(&ctrl_port->rdr_tdata.reader_tattr);
				pthread_mutex_lock(&ctrl_port->xport_list_lock);
				while(NULL != (xp = LIST_HEAD(ctrl_port->xport)))
					LIST_REMOVE(ctrl_port->xport, xp, link);
				pthread_mutex_unlock(&ctrl_port->xport_list_lock);
				pthread_mutex_lock(&ctrl_port_init_lock);
				free(ctrl_port);
				ctrl_port = NULL;
				pthread_mutex_unlock(&ctrl_port_init_lock);
				break;
			}
		}
		if (pbits[1].revents & POLLERR) {
			rx_len = recvfrom(ctrl_port->ctl_fd, &rx_ctl_msg, sizeof(rx_ctl_msg),
					  MSG_DONTWAIT,
					  NULL, NULL);
			if (errno != ENETRESET)
				continue;

			QCCI_LOG_ERR("%s: control thread received ENETRESET %d\n", __func__, errno);
			pthread_mutex_lock(&ctrl_port_init_lock);
			close(ctrl_port->ctl_fd);
			ctrl_port->ctl_fd = socket(AF_QIPCRTR, SOCK_DGRAM | SOCK_CLOEXEC, 0);
			if(ctrl_port->ctl_fd < 0)
				break;
			if(send_lookup_cmd(ctrl_port->ctl_fd, 0, 0) < 0)
				break;
			pthread_mutex_unlock(&ctrl_port_init_lock);
		}
	}
	QCCI_LOG_DBG("%s: closing control port thread\n", __func__);
	return NULL;
}

/*!
 * @brief	This function reads all the data messages for a specific client.
 *
 * @param[in] arg	Pointer to the argument passed to the thread.
 *
 * @return	Transport handle or NULL in case of error.
 */
static void *data_msg_reader_thread(void *arg)
{
	struct xport_handle *xp = (struct xport_handle *)arg;
	unsigned char ch, *buf;
	int i;
	ssize_t rx_len;
	struct pollfd pbits[2];
	struct xport_qrtr_server_addr src_addr;
	struct sockaddr_qrtr addr;

	buf = (unsigned char *)calloc(xp->max_rx_len, 1);
	if(!buf) {
		QCCI_LOG_ERR("%s: Unable to allocate read buffer for %p of size %d\n",
			     __func__, xp, xp->max_rx_len);
		return NULL;
	}

	while(1) {
		pbits[0].fd = xp->rdr_tdata.wakeup_pipe[0];
		pbits[0].events = POLLIN;
		pbits[1].fd = xp->fd;
		pbits[1].events = POLLIN;

		i = poll(pbits, 2, -1);
		if(i < 0) {
			if (errno == EINTR)
				QCCI_LOG_DBG("%s: poll error (%d)\n", __func__, errno);
			else
				QCCI_LOG_ERR("%s: poll error (%d)\n", __func__, errno);
			continue;
		}

		if((pbits[1].revents & POLLIN)) {
			socklen_t addr_size;

			addr_size = sizeof(struct sockaddr_qrtr);
			rx_len = recvfrom(xp->fd, buf, xp->max_rx_len, MSG_DONTWAIT,
					  (struct sockaddr *)&addr, &addr_size);
			if (rx_len < 0) {
				QCCI_LOG_ERR("%s: Error recvfrom %p - rc : %d\n", __func__, xp, errno);
				close(xp->rdr_tdata.wakeup_pipe[0]);
				close(xp->rdr_tdata.wakeup_pipe[1]);
				QCCI_LOG_ERR("data_msg_reader_thread Close[%d]\n", xp->fd);
				close(xp->fd);
				pthread_attr_destroy(&xp->rdr_tdata.reader_tattr);
				release_xp(xp);
				break;
			} else if (rx_len == 0) {
				if (addr_size == sizeof(struct sockaddr_qrtr)) {
					QCCI_LOG_DBG("QCCI Received Resume_Tx on FD %d from port %08x:%08x\n",
						      xp->fd, addr.sq_node, addr.sq_port);
					qcci_xport_resume(xp->clnt);
				} else {
					QCCI_LOG_ERR("%s: No data read from %d\n", __func__, xp->fd);
				}
				continue;
			} else if (addr.sq_port == QRTR_PORT_CTRL) {
				/* NOT expected to receive data from control port */
				QCCI_LOG_ERR("%s: DATA from control port len[%d]\n", __func__, (int)rx_len);
				continue;
			}

			QCCI_LOG_DBG("XP[%d] Received %d bytes from svc 0x%x at 0x%X:0x%x\n", xp->fd,
						 (int)rx_len, xp->srv_name.service, addr.sq_node,addr.sq_port);
			src_addr.service = 0;
			src_addr.instance = 0;
			src_addr.node_id = addr.sq_node;
			src_addr.port_id = addr.sq_port;
			qcci_xport_recv(xp->clnt, (void *)&src_addr, buf, (uint32_t)rx_len);
		}
		if (pbits[0].revents & POLLIN) {
			if(read(xp->rdr_tdata.wakeup_pipe[0], &ch, 1) < 0) {
				QCCI_LOG_ERR("%s: Error reading from pipe\n", __func__);
				continue;
			}
			QCCI_LOG_DBG("%s: wakeup_pipe[0]=%x ch=%c\n", __func__, pbits[0].revents, ch);
			if(ch == 'd') {
				close(xp->rdr_tdata.wakeup_pipe[0]);
				close(xp->rdr_tdata.wakeup_pipe[1]);
				QCCI_LOG_DBG("Close[%d] for service:[%d]\n", xp->fd, xp->srv_name.service);
				close(xp->fd);
				pthread_attr_destroy(&xp->rdr_tdata.reader_tattr);
				release_xp(xp);
				break;
			} else if (ch == 'r') {
				if (xp->srv_conn_reset)
					qcci_xport_event_remove_server(xp->clnt, &xp->svc_addr);
			}
		}
		if (pbits[1].revents & POLLERR) {
			int sk_size;
			int flags;
			int err;

			rx_len = recvfrom(xp->fd, (void *)&err, sizeof(err), MSG_DONTWAIT, NULL, NULL);
			if (errno != ENETRESET)
				continue;

			QCCI_LOG_ERR("%s: data thread received ENETRESET %d\n", __func__, errno);
			qcci_xport_event_remove_server(xp->clnt, &xp->svc_addr);
			close(xp->fd);
			xp->fd = socket(AF_QIPCRTR, SOCK_DGRAM | SOCK_CLOEXEC, 0);
			if(xp->fd < 0)
				break;
			flags = fcntl(xp->fd, F_GETFL, 0);
			fcntl(xp->fd, F_SETFL, flags | O_NONBLOCK);
			sk_size = INT_MAX;
			setsockopt(xp->fd, SOL_SOCKET, SO_RCVBUF, (char *)&sk_size, sizeof(sk_size));
		}
	}
	free(buf);
	QCCI_LOG_DBG("%s data thread exiting\n", __func__);
	return NULL;
}

/*!
 * @brief	This function initializes the reader threads and the pipes associated with it.
 *
 * @param[in] tdata: Pointer to the reader thread data structure.
 * @param[in] targs: Pointer to the arguments passed to the thread.
 * @param[in] rdr_thread: Function pointer to the reader thread function.
 *
 * @return	0 on success or -1 otherwise.
 */
static int reader_thread_data_init(struct reader_tdata *tdata, void *targs,
				   void *(*rdr_thread)(void *arg))
{
	if (pipe(tdata->wakeup_pipe) == -1) {
		QCCI_LOG_ERR("%s: failed to create pipe\n", __func__);
		return -1;
	}

	if (pthread_attr_init(&tdata->reader_tattr)) {
		QCCI_LOG_ERR("%s: Pthread reader thread attribute init failed\n", __func__);
		goto thread_init_close_pipe;
	}
	if (pthread_attr_setdetachstate(&tdata->reader_tattr,
					PTHREAD_CREATE_DETACHED)) {
		QCCI_LOG_ERR("%s: Pthread Set Detach State failed\n", __func__);
		goto thread_init_close_pipe;
	}
	/* create reader thread */
	if(pthread_create(&tdata->reader_tid, &tdata->reader_tattr, rdr_thread,
			  targs)) {
		QCCI_LOG_ERR("%s: Reader thread creation failed\n", __func__);
		goto thread_init_close_pipe;
	}
	return 0;

thread_init_close_pipe:
	close(tdata->wakeup_pipe[0]);
	close(tdata->wakeup_pipe[1]);
	return -1;
}

/*!
 * @brief	Deinitialize the control port.
 *
 * @return	None
 *
 * @note	This function should be only called when the qcci library
 *			is unloadedas a result of process exit.
 */
static void qcci_xport_ctrl_port_deinit(void)
{
	pthread_mutex_lock(&ctrl_port_init_lock);
	if (!ctrl_port) {
		pthread_mutex_unlock(&ctrl_port_init_lock);
		return;
	}
	if (write(ctrl_port->rdr_tdata.wakeup_pipe[1], "d", 1) < 0)
		QCCI_LOG_ERR("%s: Error writing to pipe\n", __func__);
	pthread_mutex_unlock(&ctrl_port_init_lock);
}

/*!
 * @brief	Initialize the control port only for the first time in the process context.
 *
 * @return	0 on success, -1 in case of any error.
 */
static int qcci_xport_ctrl_port_init(void)
{
	if (ctrl_port)
		return 0;

	ctrl_port = calloc(sizeof(struct xport_ctrl_port), 1);
	if (!ctrl_port) {
		QCCI_LOG_ERR("%s: Control port calloc failed\n", __func__);
		return -1;
	}
	ctrl_port->ctl_fd = socket(AF_QIPCRTR, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if(ctrl_port->ctl_fd < 0) {
		QCCI_LOG_ERR("%s: control socket creation failed - %d\n", __func__, errno);
		goto init_free_ctrl_port;
	}

	if(send_lookup_cmd(ctrl_port->ctl_fd, 0, 0) < 0) { //register for all services
		QCCI_LOG_ERR("%s: failed to register as control port\n", __func__);
		goto init_close_ctrl_fd;
	}
	LIST_INIT(ctrl_port->xport);
	if (reader_thread_data_init(&ctrl_port->rdr_tdata,(void *)ctrl_port,
				    ctrl_msg_reader_thread) < 0)
		goto init_close_ctrl_fd;
	QCCI_LOG_DBG("Control Port opened[%d]\n", ctrl_port->ctl_fd);
	return 0;

init_close_ctrl_fd:
	close(ctrl_port->ctl_fd);
init_free_ctrl_port:
	free(ctrl_port);
	ctrl_port = NULL;
	return -1;
}

/*!
 * @brief	This function opens a transport handle for a specific client.
 *
 * @param[in] xport_data: Pointer to the transport data.
 * @param[in] clnt: Pointer to the client type.
 * @param[in] service_id: Service ID for the transport.
 * @param[in] version: Version of the service.
 * @param[in] addr: Pointer to the address.
 * @param[in] max_rx_len: Maximum receive length.
 *
 * @return Transport handle or NULL in case of error.
 */
static void *xport_open
(
	void *xport_data,
	qcci_client_type *clnt,
	uint32_t service_id,
	uint32_t version,
	void *addr,
	uint32_t max_rx_len
)
{
	struct xport_handle *xp = calloc(sizeof(struct xport_handle), 1);
	int sk_size = INT_MAX;
	int align_size = 0;
	int flags;

	if (!xp) {
		QCCI_LOG_ERR("%s: xp calloc failed\n", __func__);
		return NULL;
	}

	xp->clnt = clnt;
	xp->srv_name.service = service_id;
	xp->srv_name.instance = version;
	xp->max_rx_len = (max_rx_len + QMI_HEADER_SIZE);
	align_size = ALIGN_SIZE(xp->max_rx_len);
	xp->max_rx_len += align_size;
	LINK_INIT(xp->link);

	pthread_mutex_lock(&ctrl_port_init_lock);
	if (qcci_xport_ctrl_port_init() < 0) {
		pthread_mutex_unlock(&ctrl_port_init_lock);
		goto xport_open_free_xp;
	}
	pthread_mutex_unlock(&ctrl_port_init_lock);

	if (!addr)
		/* No need to create data port as this is a notifier port. */
		goto xport_open_success;

	xp->fd = socket(AF_QIPCRTR, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if(xp->fd < 0) {
		QCCI_LOG_ERR("%s: socket creation failed - %d\n", __func__, errno);
		goto xport_open_free_xp;
	}

	setsockopt(xp->fd, SOL_SOCKET, SO_RCVBUF, (char *)&sk_size, sizeof(sk_size));

	if (reader_thread_data_init(&xp->rdr_tdata, (void *)xp,
				    data_msg_reader_thread) < 0)
		goto xport_open_close_fd;
	memcpy(xp->svc_addr, addr, sizeof(struct xport_qrtr_server_addr));
	xp->is_client = 1;
	flags = fcntl(xp->fd, F_GETFL, 0);
	fcntl(xp->fd, F_SETFL, flags | O_NONBLOCK);
	if(write(xp->rdr_tdata.wakeup_pipe[1], "a", 1) < 0)
		QCCI_LOG_ERR("%s: Error writing to pipe\n", __func__);
	QCCI_LOG_DBG("xport_open[%d]: max_rx_len=%d for service:[0x%x]\n", xp->fd, max_rx_len, service_id);

xport_open_success:
	pthread_mutex_lock(&ctrl_port->xport_list_lock);
	LIST_ADD(ctrl_port->xport, xp, link);
	pthread_mutex_unlock(&ctrl_port->xport_list_lock);
	return xp;
xport_open_close_fd:
	close(xp->fd);
xport_open_free_xp:
	free(xp);
	return NULL;
}

/*!
 * @brief	This function sends data to a specified address.
 *
 * @param[in] handle: Pointer to the transport handle.
 * @param[in] addr: Pointer to the address.
 * @param[in] buf: Pointer to the buffer containing data to be sent.
 * @param[in] len: Length of the data to be sent.
 *
 * @return	QMI_NO_ERR on success, error code otherwise.
 */
static qmi_cci_error_type xport_send
(
	void *handle,
	void *addr,
	uint8_t *buf,
	uint32_t len
)
{
	struct xport_handle *xp = (struct xport_handle *)handle;
	struct sockaddr_qrtr dest_addr;
	struct xport_qrtr_server_addr *s_addr = (struct
			xport_qrtr_server_addr *)addr;
	int send_ret_val;

	if (!s_addr) {
		QCCI_LOG_ERR("%s: Invalid address parameter\n", __func__);
		return QMI_CLIENT_TRANSPORT_ERR;
	}

	dest_addr.sq_family = AF_QIPCRTR;
	dest_addr.sq_node = s_addr->node_id;
	dest_addr.sq_port = s_addr->port_id;
	send_ret_val = sendto(xp->fd, buf, len, MSG_DONTWAIT,
			      (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_qrtr));
	if ((send_ret_val < 0) && (errno == EAGAIN)) {
		QCCI_LOG_DBG("%s: Remote port %08x:%08x is busy for FD - %d\n",
			     __func__, s_addr->node_id, s_addr->port_id, xp->fd);
		return QMI_XPORT_BUSY_ERR;
	} else if ((send_ret_val < 0) && (errno == ENODEV || errno == EHOSTUNREACH)) {
		QCCI_LOG_ERR("%s: sendto failed errno = [%d]\n", __func__, errno);
		return QMI_SERVICE_ERR;
	} else if(send_ret_val < 0) {
		QCCI_LOG_ERR("%s: Sendto failed for port %d error %d \n", __func__,
			     ntohs(s_addr->port_id), errno);
		return QMI_CLIENT_TRANSPORT_ERR;
	}
	QCCI_LOG_DBG("Sent[%d]: %d bytes to service:[0x%x] at [0x%x:0x%x] \n", xp->fd, len,
		     xp->srv_name.service, s_addr->node_id, s_addr->port_id);
	return QMI_NO_ERR;
}


/*!
 * @brief	This function closes a transport handle.
 *
 * @param[in] handle: Pointer to the transport handle.
 *
 * @return	None
 */
static void xport_close(void *handle)
{
	struct xport_handle *xp = (struct xport_handle *)handle;

	if(!xp) {
		QCCI_LOG_ERR("%s: Invalid Handle %p\n", __func__, xp);
		return;
	}
	if (xp->is_client) {
		if(write(xp->rdr_tdata.wakeup_pipe[1], "d", 1) < 0)
			QCCI_LOG_ERR("%s: Error writing to pipe\n", __func__);
	} else {
		QCCI_LOG_DBG("%s: It is notifier port no need to exit the control thread\n",
			     __func__);
		release_xp(xp);
	}
}

/*!
 * @brief	This function looks up services for a specific transport.
 *
 * @param[in] xport_data: Pointer to the transport data.
 * @param[in] xport_num: Transport number.
 * @param[in] service_id: Service ID to look up.
 * @param[in] version: Version of the service.
 * @param[out] num_entries: Pointer to the number of entries found.
 * @param[out] service_info: Pointer to the service information.
 *
 * @return	Number of entries found.
 */
static uint32_t xport_lookup
(
	void *xport_data,
	uint8_t xport_num,
	uint32_t service_id,
	uint32_t version,
	uint32_t *num_entries,
	qcci_service_info *service_info
)
{
	struct xport_qrtr_server_addr addr;
	uint32_t num_entries_to_fill = 0;
	uint32_t num_entries_filled = 0;
	struct qrtr_ctrl_pkt pkt;
	uint32_t i = 0;
	int len;
	xport_data = xport_data;
	version = version;
	QCCI_LOG_DBG("Lookup: type=%d instance=%d\n", service_id, version);
	if (num_entries) {
		num_entries_to_fill = *num_entries;
		*num_entries = 0;
	}

	if (open_lookup_sock_fd() < 0)
		return 0;

	if(send_lookup_cmd(lookup_sock_fd, service_id, 0) < 0)
		return 0;

	while ((len = recv(lookup_sock_fd, &pkt, sizeof(pkt), 0)) > 0) {
		unsigned int type = qcci_os_le32_to_cpu(pkt.cmd);

		if (len < (int)sizeof(pkt) || type != QRTR_TYPE_NEW_SERVER) {
			QCCI_LOG_ERR("%s: invalid/short packet\n", __func__);
			continue;
		}

		if (!pkt.server.service && !pkt.server.instance &&
		    !pkt.server.node && !pkt.server.port)
			break;

		addr.service = qcci_os_le32_to_cpu(pkt.server.service);
		addr.instance = qcci_os_le32_to_cpu(pkt.server.instance);
		addr.node_id = qcci_os_le32_to_cpu(pkt.server.node);
		addr.port_id = qcci_os_le32_to_cpu(pkt.server.port);

		if (service_info && (i < num_entries_to_fill)) {
			service_info[i].xport = xport_num;
			service_info[i].version = GET_VERSION(pkt.server.instance);
			service_info[i].instance = GET_INSTANCE(pkt.server.instance);
			service_info[i].reserved = 0;
			memcpy(&service_info[i].addr, &addr,
			       sizeof(struct xport_qrtr_server_addr));
			num_entries_filled++;
		}

		i++;
	}

	if (len < 0) {
		QCCI_LOG_ERR("%s: No RX for lookup %d\n", __func__, len);
		return 0;
	}

	if (num_entries)
		*num_entries = num_entries_filled;

	close_lookup_sock_fd();
	return i;
}

/**
 * @brief	This function returns the length of the transport address.
 *
 * @return	Length of the transport address.
 */
static uint32_t xport_addr_len(void)
{
	return sizeof(struct xport_qrtr_server_addr);
}

/**
 * @brief	Structure containing the operations for the QCCI QRTR transport.
 */
qcci_xport_ops_type qcci_qrtr_ops = {
	xport_open,
	xport_send,
	xport_close,
	xport_lookup,
	xport_addr_len
};
