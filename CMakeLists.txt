#
# TLS Server CAmkES Component
#
# Copyright (C) 2020, Hensoldt Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

#-------------------------------------------------------------------------------
# we can't use CMAKE_CURRENT_LIST_DIR in a function/macro, because that will
# give us the dir of the file that is invoking the function/macro. Until we
# have CmMake 3.17 which provides CMAKE_CURRENT_FUNCTION_LIST_DIR, the work
# around is creating a global variable here with the directory and then use
# this in the function below.
set(COMPONENT_TlsServer_DIR ${CMAKE_CURRENT_LIST_DIR})


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
function(DeclareCAmkESComponent_TlsServer name)

    cmake_parse_arguments(
        PARSE_ARGV
        1
        TLS_SERVER
        "" # Option arguments
        "" # Single arguments
        "LIBS" # Multiple arguments
    )

    os_use_libs(
        OS_LIBS
        OS_TLS_WITH_RPC_SERVER
        OS_TLS_WITH_RPC_CLIENT
    )

    #---------------------------------------------------------------------------
    DeclareCAmkESComponent(${name}
        INCLUDES
            # we state this folder explicitly and don't put TlsServer_client
            # into the libs, because it's semantically broken when the server
            # uses the client lib.
            ${COMPONENT_TlsServer_DIR}/inc
        SOURCES
            ${COMPONENT_TlsServer_DIR}/src/TlsServer.c
        C_FLAGS
            -Wall
            -Werror
        LIBS
            os_core_api
            os_libs
            os_tls_with_rpc_server
            ${TLS_SERVER_LIBS}
    )

    #---------------------------------------------------------------------------
    # create the corresponding client project, which every client of this TLS
    # server instance must include. We do not define this globally, because
    # the clients may have server specific configurations in the future.
    project(${name}_client C)

    add_library(${PROJECT_NAME} INTERFACE)

    target_include_directories(${PROJECT_NAME}
        INTERFACE
            ${COMPONENT_TlsServer_DIR}/inc
    )

    target_link_libraries(${PROJECT_NAME}
        INTERFACE
            os_tls_with_rpc_client
    )

endfunction()
