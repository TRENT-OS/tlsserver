#
# TLS Server
#
# Copyright (C) 2020-2024, HENSOLDT Cyber GmbH
# 
# SPDX-License-Identifier: GPL-2.0-or-later
#
# For commercial licensing, contact: info.cyber@hensoldt.net
#

cmake_minimum_required(VERSION 3.17)


#-------------------------------------------------------------------------------
#
# Declare TLS Server CAmkES Component
#
# Parameters:
#
#   <name>
#       component instance name
#
function(TlsServer_DeclareCAmkESComponent
    name
)
    DeclareCAmkESComponent(${name}
        SOURCES
            ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/server/src/TlsServer.c
        C_FLAGS
            -Wall
            -Werror
        LIBS
            os_core_api
            lib_debug
            lib_macros
            os_tls
            os_crypto
            os_socket_client
    )

endfunction()

#-------------------------------------------------------------------------------
# Create the corresponding client project, which every client of this TlsServer
# component instance must include.
project(TlsServer_client C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        ${CMAKE_CURRENT_LIST_DIR}/client/src/TlsServer_client.c
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        ${CMAKE_CURRENT_LIST_DIR}/client/include
)
