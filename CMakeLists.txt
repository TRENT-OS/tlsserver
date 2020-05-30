cmake_minimum_required(VERSION 3.7.2)

os_use_libs(
    OS_LIBS
    OS_CHANMUX
    OS_LIBS_LOGGER
    OS_NW_STACK
    OS_NETWORK_DRIVER_TAP_PROXY
    OS_CRYPTO
    OS_TLS_WITH_RPC_SERVER
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
