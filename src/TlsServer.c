/**
 * Copyright (C) 2020, Hensoldt Cyber GmbH
 */

#include "TlsServer.h"

#include "OS_Crypto.h"
#include "OS_Tls.h"
#include "OS_Network.h"

#include "LibDebug/Debug.h"

#include <camkes.h>
#include <stdint.h>
#include <string.h>

// We need this to wait for NW to complete init process
extern seos_err_t OS_NetworkAPP_RT(OS_Network_Context_t ctx);

/*
 * These are auto-generated based on interface names; they give unique ID
 * assigned to the user of the interface.
 *
 * Sender IDs can be assigned via a configuration for each interface/user
 * individually, when following this convention:
 *   <interface_user>.<interface>_attributes = ID
 *
 * IDs must be same for each interface user on both interfaces, see also the
 * comment below.
 */
seL4_Word TlsServer_get_sender_id(void);
seL4_Word TlsLibServer_get_sender_id(void);

typedef struct
{
    unsigned int id;
    OS_Tls_Handle_t hTls;
    OS_Crypto_Handle_t hCrypto;
    OS_NetworkSocket_Handle_t hSocket;
    bool connected;
} TlsServer_Client;

// We can currently only have one client, because the OS supports only one
// socket GLOBALLY. This will hopefully be fixed soon.
#define TLS_CLIENTS_MAX 1

// We limit the amount of data we send per call to the NW stack; this is a
// workaround which may at some point no longer be required.
#define MAX_NW_SIZE 2048

typedef struct
{
    TlsServer_Client clients[TLS_CLIENTS_MAX];
} TlsServer_State;

// Here we keep track of all the respective contexts for the RPC clients
static TlsServer_State serverState;

// Private static functions ----------------------------------------------------

static int
send(
    void*                ctx,
    const unsigned char* buf,
    size_t               len)
{
    seos_err_t err;
    OS_NetworkSocket_Handle_t* hSocket = (OS_NetworkSocket_Handle_t*) ctx;
    size_t n;

    n = len > MAX_NW_SIZE ? MAX_NW_SIZE : len;
    if ((err = OS_NetworkSocket_write(*hSocket, buf, &n)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("Error during hSocket write...error:%d", err);
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
    seos_err_t err;
    OS_NetworkSocket_Handle_t* hSocket = (OS_NetworkSocket_Handle_t*) ctx;
    size_t n;

    n = len > MAX_NW_SIZE ? MAX_NW_SIZE : len;
    if ((err = OS_NetworkSocket_read(*hSocket, buf, &n)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("Error during hSocket read...error:%d", err);
        return -1;
    }

    return n;
}

static int
entropy(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    // This would be the platform specific function to obtain entropy
    memset(buf, 0, len);
    return 0;
}

/*
 * Here we map the RPC client to his respective data structures. What is important
 * to understand is that the TlsServer offers TWO interfaces:
 * 1. The TlsServer interface, as explicitly defined in the relevant CAmkES
 *    file and as visible in TlsServer.h and this file.
 * 2. The TlsLibServer interface, due to the fact that this component is
 *    linked with SEOS_TLS_WITH_RCP_SERVER and thus contains the TLS API
 *    LIB and RPC Server code.
 * Mapping to the data structure is based on the numeric "sender ID" which each
 * CAmkES call to an interface provides. However, we need to ensure that
 * sender IDs are the same for each RPC client ON BOTH INTERFACES. If it is not
 * so, one component initializes data structures with ID=1 via the TlsServer
 * interface, and then uses data structures with ID=2 (or whatever) via the
 * TlsLibServer interface! This mismatch leads to problems.
 *
 * The way to make sure both IDs are the same, is to explicitly assign the IDs
 * in a configuration:
 *
 *  assembly {
 *      composition {
 *          component   TestApp_1   testApp_1;
 *          component   TestApp_2   testApp_2;
 *          ...
 *      }
 *      configuration{
 *          testApp_1.TlsServer_attributes      = 0;
 *          testApp_1.TlsLibServer_attributes   = 0;
 *          testApp_2.TlsServer_attributes      = 1;
 *          testApp_2.TlsLibServer_attributes   = 1;
 *      }
 *  }
 */
static TlsServer_Client*
getClient(
    seL4_Word id)
{
    TlsServer_Client* client;

    // Before we acces the server state, make sure it is initialized.
    Debug_ASSERT_PRINTFLN(sem_init_wait() == 0, "Failed to wait for semaphore");

    client = (id >= config.numClients) ? NULL :
             (serverState.clients[id].id != id) ? NULL :
             &serverState.clients[id];

    Debug_ASSERT_PRINTFLN(sem_init_post() == 0, "Failed to post semaphore");

    return client;
}

static TlsServer_Client*
TlsServer_getClient()
{
    return getClient(TlsServer_get_sender_id());
}

static TlsServer_Client*
TlsLibServer_getClient()
{
    return getClient(TlsLibServer_get_sender_id());
}

// Public functions ------------------------------------------------------------

/*
 * We need to give the TLS RPC Server the context to use for a specific client;
 * we have only one client here, so it is easy.
 */
OS_Tls_Handle_t
TlsLibServer_getTls(
    void)
{
    TlsServer_Client* client = TlsLibServer_getClient();
    return (NULL == client) ? NULL : client->hTls;
}

/*
 * The run function sets up the TLS/Crypto contexts per client and initializes
 * the whole network stack. After this is done, the thread exits.
 */
int run()
{
    static OS_Crypto_Config_t cryptoCfg =
    {
        .mode = OS_Crypto_MODE_LIBRARY_ONLY,
        .library.rng.entropy = entropy
    };
    static OS_Tls_Config_t tlsCfg =
    {
        .mode = OS_Tls_MODE_SERVER,
        .config.server.library = {
            .socket = {
                .recv = recv,
                .send = send,
            },
            .flags = OS_Tls_FLAG_DEBUG,
            .crypto = {
                .cipherSuites = {
                    OS_Tls_CIPHERSUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    OS_Tls_CIPHERSUITE_DHE_RSA_WITH_AES_128_GCM_SHA256
                },
                .cipherSuitesLen = 2
            }
        }
    };
    TlsServer_Client* client;
    seos_err_t err;

    // Check the configuration is somewhat sane
    Debug_ASSERT(strlen(config.trustedCert) <= OS_Tls_SIZE_CA_CERT_MAX);
    Debug_ASSERT(strlen(config.trustedCert)  > 0);
    Debug_ASSERT(config.numClients <= TLS_CLIENTS_MAX);
    Debug_ASSERT(config.numClients  > 0);

    Debug_LOG_INFO("Starting up");

    OS_NetworkAPP_RT(NULL);
    Debug_LOG_INFO("Networking initialized");

    tlsCfg.config.server.dataport = TlsLibDataport;
    strcpy(tlsCfg.config.server.library.crypto.caCert, config.trustedCert);
    for (size_t i = 0; i < config.numClients; i++)
    {
        client = &serverState.clients[i];

        // Assign ID
        client->id = i;
        // Socket is initially disconnected
        client->connected = false;

        // Create Crypto instance
        if ((err = OS_Crypto_init(&client->hCrypto, &cryptoCfg)) != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("Failed to init Crypto API instance [err=%i]", err);
            return err;
        }

        // We have the crypto set up here already, but the socket will be connected
        // later when the user calls connect()
        tlsCfg.config.server.library.crypto.handle  = client->hCrypto;
        tlsCfg.config.server.library.socket.context = &client->hSocket;
        if ((err = OS_Tls_init(&client->hTls, &tlsCfg)) != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("Failed to init TLS API instance [err=%i]", err);
            return err;
        }
    }

    /*
     * We have to post twice, because we may have the two RPC threads for the
     * two interfaces waiting in parallel for the init to complete. The two
     * interfaces are:
     * 1. TlsServer      (implemented here)
     * 2. TlsLibServer   (provided via the RPC server module of the TLS API)
     */
    Debug_ASSERT_PRINTFLN(sem_init_post() == 0, "Failed to post semaphore");
    Debug_ASSERT_PRINTFLN(sem_init_post() == 0, "Failed to post semaphore");

    Debug_LOG_INFO("Initialized state(s) for %i clients", config.numClients);

    return 0;
}

seos_err_t
TlsServer_connect(
    const char*    host,
    const uint16_t port)
{
    static OS_Network_Socket_t socketCfg =
    {
        .domain = OS_AF_INET,
        .type   = OS_SOCK_STREAM,
    };
    seos_err_t err;
    TlsServer_Client* client;

    /*
     * Check the paramter are OK; this should actually be done by the NW layer
     * but at this point it doesn't do much and if it cannot connect then it
     * simply blocks indefinetely.
     */
    if (0 == strlen(host))
    {
        Debug_LOG_ERROR("host cannot be empty");
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    if (port < 1 || port > 65535)
    {
        Debug_LOG_ERROR("Port number is invalid");
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    if ((client = TlsServer_getClient()) == NULL)
    {
        Debug_LOG_ERROR("Could not get corresponding client state");
        return SEOS_ERROR_NOT_FOUND;
    }
    if (client->connected)
    {
        Debug_LOG_ERROR("Socket of client (%i) is already connected", client->id);
        return SEOS_ERROR_INVALID_STATE;
    }

    socketCfg.name = host;
    socketCfg.port = port;

    if ((err = OS_NetworkSocket_create(NULL, &socketCfg,
                                       &client->hSocket)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("Creating NetworkSocket failed [err=%i]", err);
        return err;
    }

    client->connected = true;

    return SEOS_SUCCESS;
}

seos_err_t
TlsServer_disconnect(
    void)
{
    seos_err_t err;
    TlsServer_Client* client;

    if ((client = TlsServer_getClient()) == NULL)
    {
        Debug_LOG_ERROR("Could not get corresponding client state");
        return SEOS_ERROR_NOT_FOUND;
    }
    if (!client->connected)
    {
        Debug_LOG_ERROR("Socket of client (%i) is not connected", client->id);
        return SEOS_ERROR_INVALID_STATE;
    }

    if ((err = OS_NetworkSocket_close(client->hSocket)) != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("Closing NetworkSocket failed [err=%i]", err);
        return err;
    }

    client->connected = false;

    return SEOS_SUCCESS;
}