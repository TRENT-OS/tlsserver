/*
 * Copyright (C) 2020-2021, HENSOLDT Cyber GmbH
 */

#include "TlsServer_client.h"


OS_Error_t
TlsServer_init(
    const if_TlsServer_t* rpc)
{
    if (NULL == rpc)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    return rpc->init();
}

OS_Error_t
TlsServer_connect(
    const if_TlsServer_t* rpc,
    const char*           host,
    const uint16_t        port)
{
    if (NULL == rpc)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    return rpc->connect(host, port);
}

OS_Error_t
TlsServer_disconnect(
    const if_TlsServer_t* rpc)
{
    if (NULL == rpc)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    return rpc->disconnect();
}