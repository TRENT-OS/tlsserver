/*
 * Copyright (C) 2020-2024, HENSOLDT Cyber GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

/**
 * @defgroup TlsServer component
 * @{
 *
 * @file
 *
 * @brief TlsServer interface
 *
 */
#pragma once

#include "OS_Tls.h"

#include "if_TlsServer.h"

#include <stdint.h>

/**
 * @brief Initialize TlsServer
 *
 * No functionality implemented yet.
 *
 * @param rpc (required) pointer to CAmkES rpc struct
 *
 * @retval OS_SUCCESS always
 */
OS_Error_t
TlsServer_init(
    const if_TlsServer_t *rpc);

/**
 * @brief Connect client's socket to a remote host
 *
 * The TlsServer has one socket per RPC client. Before a TLS connection can be
 * used, the respective socket has to be connected via this function.
 *
 * @param rpc (required) pointer to CAmkES rpc struct
 * @param host (required) IP address of the remote host
 * @param port (required) Port number to use
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 * @retval OS_ERROR_INVALID_STATE if the socket is already connected
 * @retval OS_ERROR_NOT_FOUND if the state of the RPC client could not be found
 */
OS_Error_t
TlsServer_connect(
    const if_TlsServer_t *rpc,
    const char *host,
    const uint16_t port);

/**
 * @brief Disconnect socket
 *
 * If a client's socket is connected to a remote host, this function will terminate
 * the connection and close the socket.
 *
 * @param rpc (required) pointer to CAmkES rpc struct
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 * @retval OS_ERROR_INVALID_STATE if the socket is already connected
 * @retval OS_ERROR_NOT_FOUND if the state of the RPC client could not be found
 */
OS_Error_t
TlsServer_disconnect(
    const if_TlsServer_t *rpc);

/** @} */
