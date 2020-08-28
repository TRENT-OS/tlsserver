/* Copyright (C) 2019-2020, Hensoldt Cyber GmbH */

#pragma once

#include "OS_Tls.h"

typedef struct
{
    OS_Error_t (*connect)(const char* host, const uint16_t port);
    OS_Error_t (*disconnect)(void);
} if_TlsServer_t;

#define IF_TLSSERVER_ASSIGN(_rpc_)          \
{                                           \
    .connect    = _rpc_ ## _connect,        \
    .disconnect = _rpc_ ## _disconnect,     \
}
