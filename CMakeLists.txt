cmake_minimum_required(VERSION 3.7.2)

seos_use_libs(
    SEOS_LIBS
    SEOS_CHANMUX
    SEOS_LIBS_LOGGER
    SEOS_NW_STACK
    SEOS_NETWORK_DRIVER_TAP_PROXY
    SEOS_CRYPTO
    SEOS_CRYPTO_IMPL_MBEDTLS
    SEOS_TLS_WITH_RPC_SERVER
    SEOS_TLS_IMPL_MBEDTLS
)

project(tlsserver C)

DeclareCAmkESComponent(TlsServer
    INCLUDES
        inc
    SOURCES
        src/TlsServer.c
    C_FLAGS
        -Wall -Werror
        # We need to ensure that when compiling this file we have set all the
        # mbedTLS defines set when compiling the TLS library. The reason for this
        # is that it pulls in mbedTLS structs on its own and these need to match
        # those in the lib.
        -DMBEDTLS_CONFIG_FILE="${SEOS_LIBS_DIR}/seos_tls/configs/MbedTLS_Config.h"
        # For NW stack
        -DCLIENT_CONFIG=1
    LIBS
        seos_core_api
        seos_libs
        seos_crypto
        seos_network_api
        seos_tls_with_rpc_server
)