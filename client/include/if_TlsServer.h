/*
 * Copyright (C) 2020-2021, HENSOLDT Cyber GmbH
 */

#pragma once

#include "OS_Tls.h"

typedef struct
{
    OS_Error_t (*init)(void);
    OS_Error_t (*connect)(const char* host, const uint16_t port);
    OS_Error_t (*disconnect)(void);
} if_TlsServer_t;

#define IF_TLSSERVER_ASSIGN(_prefix_)         \
{                                             \
    .init       = _prefix_##_rpc_init,        \
    .connect    = _prefix_##_rpc_connect,     \
    .disconnect = _prefix_##_rpc_disconnect,   \
}
