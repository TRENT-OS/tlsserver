/*
 * Copyright (C) 2020-2021, HENSOLDT Cyber GmbH
 */

#include "TlsServer_client.h"
#include "lib_macros/Check.h"


OS_Error_t
TlsServer_init(
    const if_TlsServer_t* rpc)
{
    CHECK_PTR_NOT_NULL(rpc);
    CHECK_PTR_NOT_NULL(rpc->init);

    return rpc->init();
}

OS_Error_t
TlsServer_connect(
    const if_TlsServer_t* rpc,
    const char*           host,
    const uint16_t        port)
{
    CHECK_PTR_NOT_NULL(rpc);
    CHECK_PTR_NOT_NULL(rpc->connect);

    return rpc->connect(host, port);
}

OS_Error_t
TlsServer_disconnect(
    const if_TlsServer_t* rpc)
{
    CHECK_PTR_NOT_NULL(rpc);
    CHECK_PTR_NOT_NULL(rpc->disconnect);

    return rpc->disconnect();
}