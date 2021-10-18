/*
 * Copyright (C) 2020-2021, HENSOLDT Cyber GmbH
 */

#include "OS_Crypto.h"
#include "OS_Tls.h"
#include "OS_Network.h"

#include "lib_debug/Debug.h"
#include "lib_macros/Check.h"

#include <camkes.h>
#include <stdint.h>
#include <string.h>

#define GET_CLIENT(cli, cid) \
    do { \
        if ((cli = getClient(cid)) == NULL) \
        { \
            Debug_LOG_ERROR("Could not get state for client with clientId %u, " \
                            "the badge number is most likely not properly " \
                            "configured", cid); \
            return OS_ERROR_NOT_FOUND; \
        } \
    } while(0)

// In its current implementation, the component supports a maximum of 8 clients
// to be connected to it.
#define MAX_CLIENTS_NUM 8

// The TlsServer_CLIENT_ASSIGN_BADGES() macro will start assigning badge
// numbers with the minimum value below. Adjusting the value below will also
// require an adaptation in the main CAmkES file of this component for the
// above mentioned macro.
#define MIN_BADGE_ID 101

static OS_Crypto_Config_t cryptoCfg =
{
    .mode = OS_Crypto_MODE_LIBRARY,
    .entropy = IF_OS_ENTROPY_ASSIGN(
        entropy_rpc,
        entropy_port)
};

static OS_Tls_Config_t tlsCfg =
{
    .mode = OS_Tls_MODE_LIBRARY,
    .library = {
        .flags = OS_Tls_FLAG_NON_BLOCKING,
        .crypto = {
            .cipherSuites =
            OS_Tls_CIPHERSUITE_FLAGS(
                OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256)
        }
    }
};

typedef enum
{
    DISCONNECTED,
    CONNECTION_WAITING,
    CONNECTION_CONFIRMED,
    CONNECTION_ERROR,
    CONNECTED,
    PENDING_HANDSHAKE,
    HANDSHAKED
} TlsServer_State_t;

typedef struct
{
    bool inUse;
    unsigned int clientId;
    OS_Tls_Handle_t hTls;
    OS_Crypto_Handle_t hCrypto;
    OS_NetworkSocket_Handle_t hSocket;
    TlsServer_State_t state;
    OS_Error_t error;
} TlsServer_Client_t;

static bool initializationComplete = false;

static TlsServer_Client_t instanceClients[MAX_CLIENTS_NUM];

static const if_OS_Socket_t networkStackCtx =
    IF_OS_SOCKET_ASSIGN(networkStack);

// Forward declarations --------------------------------------------------------
seL4_Word tlsServer_rpc_get_sender_id(void);

// Private static functions ----------------------------------------------------
static int
get_client_id(
    void)
{
    return tlsServer_rpc_get_sender_id();
}

static uint8_t*
get_client_id_buf(
    void)
{
    return tlsServer_rpc_buf(tlsServer_rpc_get_sender_id());
}

static int
get_client_id_buf_size(
    void)
{
    return tlsServer_rpc_buf_size(tlsServer_rpc_get_sender_id());
}

static TlsServer_Client_t*
getClient(
    int clientId)
{
    for (int i = 0; i < MAX_CLIENTS_NUM; i++)
    {
        if ((instanceClients[i].inUse) &&
            (instanceClients[i].clientId == clientId))
        {
            return &instanceClients[i];
        }
    }

    return NULL;
}

static TlsServer_Client_t*
getClientBySocketHandle(
    int socketHandle)
{
    for (int i = 0; i < MAX_CLIENTS_NUM; i++)
    {
        if ((instanceClients[i].inUse) &&
            (instanceClients[i].hSocket.handleID == socketHandle))
        {
            return &instanceClients[i];
        }
    }

    return NULL;
}

static OS_Error_t closeClientConnection(
    TlsServer_Client_t* client)
{
    OS_Error_t err;

    if (client == NULL)
    {
        Debug_LOG_ERROR("closeClientConnection: invalid handle");
        return OS_ERROR_GENERIC;
    }

    if (client->state == DISCONNECTED)
    {
        Debug_LOG_ERROR("Socket of clientId %u is not connected",
                        client->clientId);
        return OS_ERROR_INVALID_STATE;
    }

    if ((err = OS_Tls_reset(client->hTls)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_Tls_reset() failed with %d", err);
    }

    if ((err = OS_NetworkSocket_close(client->hSocket)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_NetworkSocket_close() failed with %d", err);
    }

    client->state = DISCONNECTED;

    return err;
}

static OS_Error_t
initializeClients(
    void)
{
    OS_Error_t err;

    const unsigned int numberConnectedClients = tlsServer_rpc_num_badges();

    if (MAX_CLIENTS_NUM < numberConnectedClients)
    {
        Debug_LOG_ERROR(
            "[TlsServer '%s'] is configured for %d clients, but %d clients are"
            " connected",
            get_instance_name(),
            MAX_CLIENTS_NUM,
            numberConnectedClients);
        return OS_ERROR_OUT_OF_BOUNDS;
    }

    // Check the trusted cert is not empty
    Debug_ASSERT(strlen(tlsServer_config.trustedCert) > 0);
    if (strlen(tlsServer_config.trustedCert) <= 0)
    {
        Debug_LOG_ERROR(
            "[TlsServer '%s'] Configuration for trustedCert not found",
            get_instance_name());
        return OS_ERROR_NOT_INITIALIZED;
    }

    tlsCfg.library.crypto.caCerts = tlsServer_config.trustedCert;

    for (int i = 0; i < numberConnectedClients; i++)
    {
        Debug_LOG_DEBUG(
            "[TlsServer '%s'] clientId (%d): %d, Min: %d, Max: %d",
            get_instance_name(),
            i,
            tlsServer_rpc_enumerate_badge(i),
            MIN_BADGE_ID,
            MIN_BADGE_ID + numberConnectedClients - 1);

        if ((tlsServer_rpc_enumerate_badge(i) < MIN_BADGE_ID) ||
            (tlsServer_rpc_enumerate_badge(i) >= MIN_BADGE_ID +
             numberConnectedClients))
        {
            Debug_LOG_ERROR(
                "[TlsServer '%s'] Badge Id is out of bounds: %d, Min: %d,"
                " Max: %d",
                get_instance_name(),
                tlsServer_rpc_enumerate_badge(i),
                MIN_BADGE_ID,
                MIN_BADGE_ID + numberConnectedClients - 1);
            return OS_ERROR_OUT_OF_BOUNDS;
        }

        instanceClients[i].inUse = true;
        instanceClients[i].state = DISCONNECTED;
        instanceClients[i].clientId = MIN_BADGE_ID + i;

        // Create Crypto instance
        if ((err = OS_Crypto_init(&instanceClients[i].hCrypto, &cryptoCfg)) !=
            OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_Crypto_init() failed with %d", err);
            return OS_ERROR_NOT_INITIALIZED;
        }

        // We have the crypto set up here already, but the socket will be
        // connected later when the user calls connect()
        tlsCfg.library.crypto.handle  = instanceClients[i].hCrypto;
        tlsCfg.library.socket.context = &instanceClients[i].hSocket;
        if ((err = OS_Tls_init(&instanceClients[i].hTls, &tlsCfg)) != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_Tls_init() failed with %d", err);
            return OS_ERROR_NOT_INITIALIZED;
        }
    }

    return OS_SUCCESS;
}

// if_TlsServer specific interface RPC functions -------------------------------
OS_Error_t
tlsServer_rpc_init()
{
    return 0;
}

OS_Error_t
tlsServer_rpc_connect(
    const char*    host,
    const uint16_t port)
{
    OS_Error_t err;
    TlsServer_Client_t* client;

    GET_CLIENT(client, get_client_id());

    /*
     * Check the paramter are OK; this should actually be done by the NW layer
     * but at this point it doesn't do much and if it cannot connect then it
     * simply blocks indefinitely.
     */
    CHECK_STR_NOT_EMPTY(host);
    CHECK_VALUE_IN_CLOSED_INTERVAL(port, 1, 65535);

    if (client->state == CONNECTION_WAITING)
    {
        // waiting for network stack to confirm the connection
        return OS_ERROR_WOULD_BLOCK;
    }

    if (client->state == CONNECTION_CONFIRMED)
    {
        // confirm once to the client, then go to connected state
        client->state = CONNECTED;
        return OS_SUCCESS;
    }

    if (client->state == CONNECTION_ERROR)
    {
        // confirm once to the client, then go to disconnected state
        client->state = DISCONNECTED;
        return client->error;
    }

    if (client->state != DISCONNECTED)
    {
        return OS_ERROR_INVALID_STATE;
    }

    // client->state == DISCONNECTED; start connection
    do
    {
        seL4_Yield();
        err = OS_NetworkSocket_create(
                  &networkStackCtx,
                  &client->hSocket,
                  OS_AF_INET,
                  OS_SOCK_STREAM);
    }
    while (err == OS_ERROR_NOT_INITIALIZED);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_NetworkSocket_create() failed, code %d", err);
        return err;
    }

    OS_NetworkSocket_Addr_t dstAddr;
    strncpy(dstAddr.addr, host, sizeof(dstAddr.addr) - 1);
    dstAddr.port = port;

    err = OS_NetworkSocket_connect(client->hSocket, &dstAddr);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_NetworkSocket_create() failed, code %d", err);
        OS_NetworkSocket_close(client->hSocket);
        return err;
    }

    // wait for connected event
    client->state = CONNECTION_WAITING;

    return OS_ERROR_WOULD_BLOCK;
}

OS_Error_t
tlsServer_rpc_disconnect(
    void)
{
    OS_Error_t err;
    TlsServer_Client_t* client;

    GET_CLIENT(client, get_client_id());

    Debug_LOG_DEBUG("TLS connection disconnect of clientId %u ",
                    client->clientId);

    err = closeClientConnection(client);
    return err;
}

// if_OS_Tls interface RPC functions -------------------------------------------
OS_Error_t
tlsServer_rpc_handshake(
    void)
{
    OS_Error_t err;
    TlsServer_Client_t* client;

    GET_CLIENT(client, get_client_id());

    if ((client->state != CONNECTED) &&
        (client->state != PENDING_HANDSHAKE) &&
        (client->state != HANDSHAKED))
    {
        Debug_LOG_ERROR("Socket of clientId %u is not connected",
                        client->clientId);
        return OS_ERROR_INVALID_STATE;
    }

    err = OS_Tls_handshake(client->hTls);

    switch (err)
    {
    case OS_SUCCESS:
        // handshake successful,
        // will only be returned once
        client->state = HANDSHAKED;
        break;
    case OS_ERROR_WOULD_BLOCK:
        // handshake in progress,
        // client needs to call tlsServer_rpc_handshake() again until another
        // return code arrives
        client->state = PENDING_HANDSHAKE;
        break;
    case OS_ERROR_OPERATION_DENIED:
        // OS_Tls_handshake() says, that the connection is already up
        client->state = HANDSHAKED;
        break;
    default:
        // OS_Tls_handshake() returned with an error,
        // we move to CONNECTED state,
        // socket errors are handled in run()
        client->state = CONNECTED;
    }
    return err;
}

OS_Error_t
tlsServer_rpc_write(
    size_t* dataSize)
{
    TlsServer_Client_t* client;

    GET_CLIENT(client, get_client_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(*dataSize, 0,
                                   get_client_id_buf_size());

    if (client->state != HANDSHAKED)
    {
        Debug_LOG_ERROR("TLS connection of clientId %u is not established",
                        client->clientId);
        return OS_ERROR_INVALID_STATE;
    }

    return OS_Tls_write(client->hTls, get_client_id_buf(),
                        dataSize);
}

OS_Error_t
tlsServer_rpc_read(
    size_t* dataSize)
{
    OS_Error_t err;
    TlsServer_Client_t* client;

    GET_CLIENT(client, get_client_id());

    CHECK_VALUE_IN_CLOSED_INTERVAL(*dataSize, 0,
                                   get_client_id_buf_size());

    if (client->state != HANDSHAKED)
    {
        Debug_LOG_ERROR("TLS connection of clientId %u is not established",
                        client->clientId);
        return OS_ERROR_INVALID_STATE;
    }

    err = OS_Tls_read(client->hTls, get_client_id_buf(),
                      dataSize);
    return err;
}

OS_Error_t
tlsServer_rpc_reset(
    void)
{
    TlsServer_Client_t* client;

    GET_CLIENT(client, get_client_id());

    if ((client->state == PENDING_HANDSHAKE) ||
        (client->state == HANDSHAKED))
    {
        client->state = CONNECTED;
    }

    Debug_LOG_DEBUG("TLS connection reset of clientId %u ", client->clientId);

    return OS_Tls_reset(client->hTls);
}

// CAmkES component specific functions -----------------------------------------
void
post_init()
{
    OS_Error_t err;

    err = initializeClients();

    if (err == OS_SUCCESS)
    {
        initializationComplete = true;
    }
    else
    {
        initializationComplete = false;
    }

    return;
}

int
run(
    void)
{
    OS_Error_t err;

    Debug_LOG_INFO("[TlsServer '%s'] starting", get_instance_name());

    // PAGE_SIZE is normally 4KiB, should be able to hold two
    // complete Ethernet frames with MTU of 1500 bytes.
    static char evtBuffer[PAGE_SIZE];
    size_t evtBufferSize = sizeof(evtBuffer);
    int numberOfSocketsWithEvents;


    if (!initializationComplete)
    {
        Debug_LOG_ERROR("TlsServer initialization failed, stopping");
        return -1;
    }

    // start loop to retrieve network stack event notifications
    for (;;)
    {
        // Wait until we get an event for the listening socket.
        err = OS_NetworkSocket_wait(&networkStackCtx);
        if (err != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_NetworkSocket_wait() failed, code %d", err);
            return -1;
        }

        err = OS_NetworkSocket_getPendingEvents(
                  &networkStackCtx,
                  evtBuffer,
                  evtBufferSize,
                  &numberOfSocketsWithEvents);

        if (err != OS_SUCCESS)
        {
            Debug_LOG_ERROR("OS_NetworkSocket_getPendingEvents() failed, err %d",
                            err);
            continue;
        }

        Debug_LOG_TRACE("[TlsServer '%s'] received %d events",
                        get_instance_name(),
                        numberOfSocketsWithEvents);

        int offset = 0;
        for (int i = 0; i < numberOfSocketsWithEvents; i++)
        {
            OS_NetworkSocket_Evt_t event;
            memcpy(&event, &evtBuffer[offset], sizeof(event));
            offset += sizeof(event);

            // => handle socket events
            Debug_LOG_TRACE("handle event - handle: %d, parentSocketHandle: %d,"
                            "eventMask 0x%x, currentError %d",
                            event.socketHandle,
                            event.parentSocketHandle,
                            event.eventMask,
                            event.currentError);

            if (event.socketHandle < 0)
            {
                Debug_LOG_ERROR("handle event - received invalid handle: %d",
                                event.socketHandle);
                continue;
            }

            TlsServer_Client_t* client = getClientBySocketHandle(
                                             event.socketHandle);

            if (client == NULL)
            {
                Debug_LOG_ERROR("OS_NetworkSocket_getPendingEvents: unknown"
                                " handle received: %d",
                                event.socketHandle);
                continue;
            }

            // socket has been closed by network stack
            if (event.eventMask & OS_SOCK_EV_FIN)
            {
                Debug_LOG_ERROR("OS_NetworkSocket_getPendingEvents:"
                                " OS_SOCK_EV_FIN for clientId %d, handle: %d",
                                client->clientId,
                                event.socketHandle);
                closeClientConnection(client);
                continue;
            }

            // Connection event successful - not used in this application
            if (event.eventMask & OS_SOCK_EV_CONN_EST)
            {
                client->state = CONNECTION_CONFIRMED;
                Debug_LOG_DEBUG("Connection established for clientId %d,"
                                "handle: %d",
                                client->clientId,
                                event.socketHandle);
            }

            // new client connection (TCP only)
            if (event.eventMask & OS_SOCK_EV_CONN_ACPT)
            {
                Debug_LOG_ERROR("OS_NetworkSocket_getPendingEvents: Unexpected"
                                " event - OS_SOCK_EV_CONN_ACPT handle: %d",
                                event.socketHandle);
            }

            // new data to read - only clients
            if (event.eventMask & OS_SOCK_EV_READ)
            {
                // do nothing
                // currently the client needs to poll for new data
            }

            // socket is available for sending - ignore for now
            if (event.eventMask & OS_SOCK_EV_WRITE)
            {
                // do nothing
                // currently the client needs to try to write data
            }

            // remote socket requested to be closed
            if (event.eventMask & OS_SOCK_EV_CLOSE)
            {
                // do nothing
                // closing of the connection will be handled by
                // TlsServer_disconnect()
            }

            // Error received - print error
            if (event.eventMask & OS_SOCK_EV_ERROR)
            {
                Debug_LOG_ERROR("OS_NetworkSocket_getPendingEvents:"
                                " OS_SOCK_EV_ERROR handle: %d, code: %d",
                                event.socketHandle,
                                event.currentError);
                // handle failed connection events:
                if (client->state == CONNECTION_WAITING)
                {
                    client->state = CONNECTION_ERROR;
                    client->error = event.currentError;
                }
            }
        }
    }

    return 0;
}
