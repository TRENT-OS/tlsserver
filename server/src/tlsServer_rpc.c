/**
 * Copyright (C) 2020, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"
#include "OS_Tls.h"
#include "OS_Network.h"
#include "OS_NetworkStackClient.h"

#include "lib_debug/Debug.h"
#include "lib_macros/Check.h"

#include <camkes.h>
#include <stdint.h>
#include <string.h>

#define GET_CLIENT(cli, cid) \
    do { \
        if ((cli = getClient(cid)) == NULL) \
        { \
            Debug_LOG_ERROR("Could not get state for client with client ID %u, " \
                            "the badge number is most likely not properly " \
                            "configured", cid); \
            return OS_ERROR_NOT_FOUND; \
        } \
    } while(0)

// Forward declarations
static int send(void* ctx, const unsigned char* buf, size_t len);
static int recv(void* ctx, unsigned char* buf, size_t len);

static OS_Crypto_Config_t cryptoCfg =
{
    .mode = OS_Crypto_MODE_LIBRARY,
    .entropy = IF_OS_ENTROPY_ASSIGN(
        entropy_rpc,
        entropy_port),

};
static OS_Tls_Config_t tlsCfg =
{
    .mode = OS_Tls_MODE_LIBRARY,
    .library = {
        .socket = {
            .recv = recv,
            .send = send,
        },
        .flags = OS_Tls_FLAG_DEBUG,
        .crypto.cipherSuites =
        OS_Tls_CIPHERSUITE_FLAGS(
            OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256)
    }
};

seL4_Word tlsServer_rpc_get_sender_id(void);

// Translate between badge IDs and array index
#define CID_TO_IDX(cid) ((cid)-101)
#define IDX_TO_CID(idx) ((idx)+101)

typedef struct
{
    unsigned int cid;
    OS_Tls_Handle_t hTls;
    OS_Crypto_Handle_t hCrypto;
    OS_Dataport_t dataport;
    OS_NetworkSocket_Handle_t hSocket;
    bool connected;
} TlsServer_Client;

// ToDo: We can currently only have one client
#define TLS_CLIENTS_MAX 1

// We limit the amount of data we send per call to the NW stack; this is a
// workaround which may at some point no longer be required.
#define MAX_NW_SIZE 2048

typedef struct
{
    TlsServer_Client clients[TLS_CLIENTS_MAX];
} TlsServer_State;

// Here we keep track of all the respective contexts for the RPC clients
static TlsServer_State serverState =
{
    .clients[0] = {
        .dataport = OS_DATAPORT_ASSIGN(tlsServer_port)
    }
};

// Private static functions ----------------------------------------------------

static int
send(
    void*                ctx,
    const unsigned char* buf,
    size_t               len)
{
    OS_Error_t err;
    OS_NetworkSocket_Handle_t* hSocket = (OS_NetworkSocket_Handle_t*) ctx;
    size_t n;

    n = len > MAX_NW_SIZE ? MAX_NW_SIZE : len;
    if ((err = OS_NetworkSocket_write(*hSocket, buf, n, &n)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_NetworkSocket_write() failed with %d", err);
        return -1;
    }

    return n;
}

static int
recv(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    OS_Error_t err;
    OS_NetworkSocket_Handle_t* hSocket = (OS_NetworkSocket_Handle_t*) ctx;
    size_t n;

    n = len > MAX_NW_SIZE ? MAX_NW_SIZE : len;
    if ((err = OS_NetworkSocket_read(*hSocket, buf, n, &n)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_NetworkSocket_read() failed with %d", err);
        return -1;
    }

    return n;
}

static TlsServer_Client*
getClient(
    seL4_Word cid)
{
    const int idx = CID_TO_IDX(cid);
    TlsServer_Client* client;

    client = ((idx < 0) || (idx >= TLS_CLIENTS_MAX))
             ? NULL : (serverState.clients[idx].cid != cid)
             ? NULL : &serverState.clients[idx];

    return client;
}

static void
init_network_client_api()
{
    static OS_NetworkStackClient_SocketDataports_t config;
    static OS_Dataport_t dataport = OS_DATAPORT_ASSIGN(networkStack_port);

    config.number_of_sockets = 1;

    config.dataport = &dataport;
    OS_NetworkStackClient_init(&config);
}

// Public functions ------------------------------------------------------------

void
post_init()
{
    TlsServer_Client* client;
    OS_Error_t err;

    // Check the trusted cert is not empty
    Debug_ASSERT(strlen(tlsServer_config.trustedCert) > 0);

    Debug_LOG_INFO("Starting up");

    init_network_client_api();
    Debug_LOG_INFO("Networking initialized");

    tlsCfg.library.crypto.caCerts = tlsServer_config.trustedCert;
    for (size_t i = 0; i < TLS_CLIENTS_MAX; i++)
    {
        client = &serverState.clients[i];

        // Assign ID
        client->cid = IDX_TO_CID(i);
        // Socket is initially disconnected
        client->connected = false;

        // Create Crypto instance
        if ((err = OS_Crypto_init(&client->hCrypto, &cryptoCfg)) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_Crypto_init() failed with %d", err);
            return;
        }

        // We have the crypto set up here already, but the socket will be connected
        // later when the user calls connect()
        tlsCfg.library.crypto.handle  = client->hCrypto;
        tlsCfg.library.socket.context = &client->hSocket;
        if ((err = OS_Tls_init(&client->hTls, &tlsCfg)) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_Tls_init() failed with %d", err);
            return;
        }
    }

    Debug_LOG_INFO("Initialized state(s) for up to %i clients", TLS_CLIENTS_MAX);
}

// TlsServer specific interface functions --------------------------------------

OS_Error_t
tlsServer_rpc_connect(
    const char*    host,
    const uint16_t port)
{
    static OS_Network_Socket_t socketCfg =
    {
        .domain = OS_AF_INET,
        .type   = OS_SOCK_STREAM,
    };
    OS_Error_t err;
    TlsServer_Client* client;

    GET_CLIENT(client, tlsServer_rpc_get_sender_id());

    /*
     * Check the paramter are OK; this should actually be done by the NW layer
     * but at this point it doesn't do much and if it cannot connect then it
     * simply blocks indefinetely.
     */
    CHECK_STR_NOT_EMPTY(host);
    CHECK_VALUE_IN_CLOSED_INTERVAL(port, 1, 65535);

    if (client->connected)
    {
        Debug_LOG_ERROR("Socket of client ID %u is already connected", client->cid);
        return OS_ERROR_INVALID_STATE;
    }

    strncpy(socketCfg.name, host, sizeof(socketCfg.name) - 1);
    socketCfg.port = port;

    if ((err = OS_NetworkSocket_create(NULL, &socketCfg,
                                       &client->hSocket)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_NetworkSocket_create() failed with %d", err);
        return err;
    }

    client->connected = true;

    return OS_SUCCESS;
}

OS_Error_t
tlsServer_rpc_disconnect(
    void)
{
    OS_Error_t err;
    TlsServer_Client* client;

    GET_CLIENT(client, tlsServer_rpc_get_sender_id());

    if (!client->connected)
    {
        Debug_LOG_ERROR("Socket of client ID %u is not connected", client->cid);
        return OS_ERROR_INVALID_STATE;
    }

    if ((err = OS_NetworkSocket_close(client->hSocket)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_NetworkSocket_close() failed with %d", err);
        return err;
    }

    client->connected = false;

    return OS_SUCCESS;
}

// if_OS_Tls interface functions -----------------------------------------------

OS_Error_t
tlsServer_rpc_handshake(
    void)
{
    TlsServer_Client* client;

    GET_CLIENT(client, tlsServer_rpc_get_sender_id());

    return OS_Tls_handshake(client->hTls);
}

OS_Error_t
tlsServer_rpc_write(
    size_t* dataSize)
{
    TlsServer_Client* client;

    GET_CLIENT(client, tlsServer_rpc_get_sender_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(*dataSize, 0,
                                   OS_Dataport_getSize(client->dataport));

    return OS_Tls_write(client->hTls, OS_Dataport_getBuf(client->dataport),
                        dataSize);
}

OS_Error_t
tlsServer_rpc_read(
    size_t* dataSize)
{
    TlsServer_Client* client;

    GET_CLIENT(client, tlsServer_rpc_get_sender_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(*dataSize, 0,
                                   OS_Dataport_getSize(client->dataport));

    return OS_Tls_read(client->hTls, OS_Dataport_getBuf(client->dataport),
                       dataSize);
}

OS_Error_t
tlsServer_rpc_reset(
    void)
{
    TlsServer_Client* client;

    GET_CLIENT(client, tlsServer_rpc_get_sender_id());

    return OS_Tls_reset(client->hTls);
}
