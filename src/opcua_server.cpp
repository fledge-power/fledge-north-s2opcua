/*
 * Fledge north service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Amandeep Singh Arora / Jeremie Chabod
 */

#define USE_TLS 0 // TODO!

#include <opcua_server.h>
#include <opcua_server_config.h>

#include <exception>

extern "C" {
// S2OPC Headers
#include "s2opc/common/sopc_atomic.h"
#include "s2opc/common/sopc_common.h"
#include "s2opc/common/sopc_encodeabletype.h"
#include "s2opc/common/sopc_log_manager.h"
#include "s2opc/common/sopc_logger.h"
#include "s2opc/common/sopc_types.h"
#include "s2opc/clientserver/frontend/libs2opc_common_config.h"
#include "s2opc/clientserver/frontend/libs2opc_server_config.h"
#include "s2opc/clientserver/sopc_toolkit_config.h"
#if USE_TLS
#include "threading_alt.h"
#endif
}

// Include generated JSON file
#include "default_config.inc"

namespace
{
}

namespace fledge_power_s2opc_north
{

/**************************************************************************/
Exception::
Exception(const std::string& msg):
        mMsg(msg)
{}

/**************************************************************************/
/**************************************************************************/
OPCUA_Server* OPCUA_Server::mInstance = NULL;
/**************************************************************************/
OPCUA_Server::
OPCUA_Server(const ConfigCategory& configData):
    mConfig(configData),
    mBuildInfo(SOPC_CommonHelper_GetBuildInfo()),
    mServerOnline(false)
{
#if USE_TLS
    /* Initialize MbedTLS */
    tls_threading_initialize();
#endif

    /* Configure the server logger: */
    // TODO: configure logger (see south plugin)
    SOPC_Log_Configuration logConfig;
    if (mConfig.withLogs)
    {
        logConfig.logLevel = mConfig.logLevel;
        logConfig.logSystem = SOPC_LOG_SYSTEM_FILE;
    }
    else
    {
        logConfig.logLevel = SOPC_LOG_LEVEL_INFO;
        logConfig.logSystem = SOPC_LOG_SYSTEM_NO_LOG;
    }
    SOPC_ReturnStatus status = SOPC_Common_Initialize(logConfig);

    if (SOPC_STATUS_OK != status)
    {
        throw Exception("SOPC_Common_Initialize failed");
    }
    SOPC_Logger_TraceDebug(SOPC_LOG_MODULE_CLIENTSERVER, "OPCUA_Server::SOPC_Common_Initialize() OK");

    status = SOPC_Toolkit_Initialize(&Server_Event);
    if (SOPC_STATUS_OK != status)
    {
        throw Exception("SOPC_Toolkit_Initialize failed");
    }
    SOPC_Logger_TraceDebug(SOPC_LOG_MODULE_CLIENTSERVER, "OPCUA_Server::SOPC_Toolkit_Initialize() OK");


    // TODO Server_LoadAddressSpace
    // TODO Server_ConfigureStartServer

    mInstance = this;
    SOPC_S2OPC_Config_Initialize(&mConfig);
}

/**************************************************************************/
OPCUA_Server::
~OPCUA_Server()
{
    /** TODO
     * From ZEPHYR SAMPLE:
     * Server_StopAndClear(&s2opcConfig);
     */

    mInstance = NULL;
    SOPC_Toolkit_Clear();
    SOPC_Common_Clear();
}

/**************************************************************************/
void
OPCUA_Server::
Server_Event(SOPC_App_Com_Event event, uint32_t idOrStatus, void* param, uintptr_t appContext)
{
    (void) idOrStatus;
    if (NULL == mInstance)
    {
        return;
    }

    SOPC_EncodeableType* message_type = NULL;

    OpcUa_WriteResponse* writeResponse = NULL;

    switch (event)
    {
    case SE_CLOSED_ENDPOINT:
        printf("# Info: Closed endpoint event.\n");
        SOPC_Atomic_Int_Set(&mInstance->mServerOnline, 0);
        return;
    case SE_LOCAL_SERVICE_RESPONSE:
        message_type = *(reinterpret_cast<SOPC_EncodeableType**>(param));
        /* Listen for WriteResponses, which only contain status codes */
        /*if (message_type == &OpcUa_WriteResponse_EncodeableType)
        {
            OpcUa_WriteResponse* write_response = param;
            bool ok = (write_response->ResponseHeader.ServiceResult == SOPC_GoodGenericStatus);
        }*/
        /* Listen for ReadResponses, used in GetSourceVariables
         * This can be used for example when PubSub is defined and uses address space */

        /*if (message_type == &OpcUa_ReadResponse_EncodeableType && NULL != ctx)
        {
            ctx = (SOPC_PubSheduler_GetVariableRequestContext*) appContext;
            // Then copy content of response to ctx...
        } */
        if (message_type == &OpcUa_WriteResponse_EncodeableType)
        {
            writeResponse = reinterpret_cast<OpcUa_WriteResponse*>(param);
            // Service should have succeeded
            assert(0 == (SOPC_GoodStatusOppositeMask & writeResponse->ResponseHeader.ServiceResult));
        }
        else
        {
            assert(false);
        }
        return;
    default:
        printf("# Warning: Unexpected endpoint event: %d.\n", event);
        return;
    }
}

/**************************************************************************/
uint32_t
OPCUA_Server::
send(const Readings& readings)
{
    SOPC_Logger_TraceDebug(SOPC_LOG_MODULE_CLIENTSERVER,
            "OPCUA_Server::send(%ld elements)",
            readings.size());

    return 0; // TODO
}

/**************************************************************************/
void
OPCUA_Server::
setpointCallbacks(north_write_event_t write, north_operation_event_t operation)
{
    SOPC_Logger_TraceDebug(SOPC_LOG_MODULE_CLIENTSERVER,
            "OPCUA_Server::setpointCallbacks(.., ..)");
    return; // TODO
}

} // namespace fledge_power_s2opc_north


