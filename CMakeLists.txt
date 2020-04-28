cmake_minimum_required(VERSION 3.7.2)

seos_use_libs(
    SEOS_LIBS
    SEOS_CHANMUX
    SEOS_LIBS_LOGGER
    SEOS_NW_STACK
    SEOS_NETWORK_DRIVER_TAP_PROXY
    SEOS_CRYPTO
    SEOS_TLS_WITH_RPC_SERVER
)

project(tlsserver C)

DeclareCAmkESComponent(TlsServer
    INCLUDES
        inc
    SOURCES
        src/TlsServer.c
    C_FLAGS
        -Wall -Werror
        # For NW stack
        -DCLIENT_CONFIG=1
    LIBS
        seos_core_api
        seos_libs
        seos_crypto
        seos_network_api
        seos_tls_with_rpc_server
)