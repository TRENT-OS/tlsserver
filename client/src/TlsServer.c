/* Copyright (C) 2020, Hensoldt Cyber GmbH */

#include "OS_Tls.h"

#include <stdint.h>

#include <camkes.h>

OS_Error_t
TlsServer_connect(
    const char*    host,
    const uint16_t port)
{
    return tlsServer_rpc_connect(host, port);
}

OS_Error_t
TlsServer_disconnect(
    void)
{
    return tlsServer_rpc_disconnect();
}