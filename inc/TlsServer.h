/**
 * Copyright (C) 2020, Hensoldt Cyber GmbH
 *
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

#include <stdint.h>

/**
 * @brief Connect clien'ts socket to a remote host
 *
 * The TlsServer has one socket per RPC client. Before a TLS connection can be
 * used via the TlsLibServer RPC interface, the respective socket has to be
 * connected via this function.
 *
 * @param host (required) IP address of the remote host
 * @param port (required) Port number to use
 *
 * @return an error code
 * @retval SEOS_SUCCESS if operation succeeded
 * @retval SEOS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 * @retval SEOS_ERROR_INVALID_STATE if the socket is already connected
 * @retval SEOS_ERROR_NOT_FOUND if the state of the RPC client could not be found
 */
OS_Error_t
TlsServer_connect(
    const char*    host,
    const uint16_t port);

/**
 * @brief Disconnect socket
 *
 * If a client's socket is connected to a remote host, this function will terminate
 * the connection and close the socket.
 *
 * @return an error code
 * @retval SEOS_SUCCESS if operation succeeded
 * @retval SEOS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 * @retval SEOS_ERROR_INVALID_STATE if the socket is already connected
 * @retval SEOS_ERROR_NOT_FOUND if the state of the RPC client could not be found
 */
OS_Error_t
TlsServer_disconnect(
    void);

/** @} */