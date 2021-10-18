#
# TLS Server
#
# Copyright (C) 2020-2021, HENSOLDT Cyber GmbH
#

cmake_minimum_required(VERSION 3.17)


#-------------------------------------------------------------------------------
#
# Declare TLS Server CAmkES Component
#
# Parameters:
#
#   <name>
#     required, component instance name
#
#   LIBS <lib_1> <lib_2> ...
#     optional, define libraries with specific implementations that the
#     component shall use, e.g. crypto library or network stack.
#
function(TlsServer_DeclareCAmkESComponent name)

    cmake_parse_arguments(
        PARSE_ARGV
        1
        TLS_SERVER
        "" # Option arguments
        "" # Single arguments
        "LIBS" # Multiple arguments
    )

    #---------------------------------------------------------------------------
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
            ${TLS_SERVER_LIBS}
    )
endfunction()

#---------------------------------------------------------------------------
# create the corresponding client project, which every client of this TlsServer
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
