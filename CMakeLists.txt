#
# TLS Server
#
# Copyright (C) 2020, Hensoldt Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

#-------------------------------------------------------------------------------
# we cannot use CMAKE_CURRENT_LIST_DIR in a function or macro, because that
# would give us the dir of the file that is invoking the macro. The work around
# is that we create a global (ie cached and flagged as internal) variable here
# and then use it in the macro below. As a convenient side effect we don't
# require anybody else to provide any helper variables, this CMake file becomes
# fully self-contained and "copy&paste safe".
set(
    OS_COMPONENT_TlsServer_DIR
    "${CMAKE_CURRENT_LIST_DIR}"
    CACHE INTERNAL ""
)


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

    #---------------------------------------------------------------------------
    DeclareCAmkESComponent(${name}
        SOURCES
            ${OS_COMPONENT_TlsServer_DIR}/server/src/tlsServer_rpc.c
        C_FLAGS
            -Wall
            -Werror
        LIBS
            os_core_api
            os_libs
            os_tls
            ${TLS_SERVER_LIBS}
    )

    #---------------------------------------------------------------------------
    # create the corresponding client project, which every client of this TLS
    # server instance must include. We do not define this globally, because
    # the clients may have server specific configurations in the future.
    project(${name}_client C)

    add_library(${PROJECT_NAME} INTERFACE)

    target_sources(${PROJECT_NAME}
        INTERFACE
            ${OS_COMPONENT_TlsServer_DIR}/client/src/TlsServer.c
    )

    target_include_directories(${PROJECT_NAME}
        INTERFACE
            ${OS_COMPONENT_TlsServer_DIR}/client/include
    )

endfunction()
