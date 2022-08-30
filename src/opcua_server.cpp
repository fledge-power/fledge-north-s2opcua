/*
 * Fledge north service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Amandeep Singh Arora / Jeremie Chabod
 */

#define USE_MBEDTLS 0

#include <opcua_server.h>
#include <opcua_server_config.h>

#include <exception>
#include <unistd.h>
#include <sys/stat.h>

extern "C" {
// S2OPC Headers
#include "s2opc/common/sopc_assert.h"
#include "s2opc/common/sopc_atomic.h"
#include "s2opc/common/sopc_common.h"
#include "s2opc/common/sopc_encodeabletype.h"
#include "s2opc/common/sopc_log_manager.h"
#include "s2opc/common/sopc_logger.h"
#include "s2opc/common/sopc_types.h"
#include "s2opc/clientserver/frontend/libs2opc_common_config.h"
#include "s2opc/clientserver/frontend/libs2opc_server_config.h"
#include "s2opc/clientserver/sopc_toolkit_config.h"
#if USE_MBEDTLS
#include "threading_alt.h"
#else
#warning "TODO : use MBEDTLS"
#endif
}

// Include generated JSON file
/* See "mkjson" and "default_config.json"
   Note that the source file syntax supports enhanced features so as to
   allow a visual intuitive edition:
   - Using simple quotes inside strings is actuallty replaced by \"(typical usage for JSON) avoids the use
        This is useful for filling in JSON content without needing backslashing everything
        e.g.:  "default" : "{ 'name' : 'value'} ",
   - As a consequence the character ' cannot be used inside strings. The escape sequence "\x27" can be used if required
*/
#include "default_config.inc"

namespace
{
}

namespace fledge_power_s2opc_north
{

/**************************************************************************/
/**************************************************************************/
OPCUA_Server* OPCUA_Server::mInstance = NULL;
/**************************************************************************/
OPCUA_Server::
OPCUA_Server(const ConfigCategory& configData):
    mConfig(configData),
    mBuildInfo(SOPC_CommonHelper_GetBuildInfo()),
    mServerOnline(false),
    s2opc_config (mConfig.extractOpcConfig(configData))
{
#if USE_MBEDTLS
    /* Initialize MbedTLS */
    tls_threading_initialize();
#endif

    SOPC_ASSERT(mInstance == NULL && "OPCUA_Server may not be instanced twice within the same plugin");

    /* Configure the server logger: */
    SOPC_Log_Configuration logConfig = SOPC_Common_GetDefaultLogConfiguration();
    if (mConfig.withLogs)
    {
        const std::string traceFilePath = getDataDir() + string("/logs/");
        logConfig.logLevel = mConfig.logLevel;
        logConfig.logSystem = SOPC_LOG_SYSTEM_FILE;

        // Note : other fields of fileSystemLogConfig are initialized by SOPC_Common_GetDefaultLogConfiguration()
        const char* logDirPath = mConfig.logPath.c_str();
        logConfig.logSysConfig.fileSystemLogConfig.logDirPath = logDirPath;

        // Check if log folder exist and create it if needed
        if (not access(logDirPath, W_OK | R_OK))
        {
            mkdir(logDirPath,0777);
        }
        SOPC_ASSERT(access(logDirPath, W_OK | R_OK) && "Cannot create log folder");
    }
    else
    {
        logConfig.logLevel = SOPC_LOG_LEVEL_INFO;
        logConfig.logSystem = SOPC_LOG_SYSTEM_NO_LOG;
    }
    SOPC_ReturnStatus status = SOPC_Common_Initialize(logConfig);
    SOPC_ASSERT(status == SOPC_STATUS_OK && "SOPC_Common_Initialize failed");

    Logger::getLogger()->debug ("OPCUA_Server::SOPC_Common_Initialize() OK");

    status = SOPC_Toolkit_Initialize(&Server_Event);
    SOPC_ASSERT(status == SOPC_STATUS_OK && "SOPC_Toolkit_Initialize failed");

    Logger::getLogger()->debug ("OPCUA_Server::SOPC_Toolkit_Initialize() OK");

#warning "TODO : SOPC_Embedded_AddressSpace_Load"
#warning "TODO : SOPC_ToolkitServer_SetAddressSpaceConfig"
#warning "TODO : SOPC_ToolkitServer_SetAddressSpaceNotifCb"
#warning "TODO : Server_ConfigureStartServer"

    mInstance = this;
    SOPC_S2OPC_Config_Initialize(s2opc_config);
}

/**************************************************************************/
OPCUA_Server::
~OPCUA_Server()
{
#warning "TODO : Server_StopAndClear"

    mInstance = NULL;
    if (NULL != s2opc_config)
    {
        SOPC_S2OPC_Config_Clear(s2opc_config);
        free (s2opc_config);
    }
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
    Logger::getLogger()->debug("OPCUA_Server::send(%ld elements)", readings.size());
    Logger::getLogger()->warn("OPCUA_Server::send() : NOT IMPLEMENTED YET");

#warning "TODO : OPCUA_Server::send"
    return 0;
}

/**************************************************************************/
void
OPCUA_Server::
setpointCallbacks(north_write_event_t write, north_operation_event_t operation)
{
    Logger::getLogger()->debug("OPCUA_Server::setpointCallbacks(.., ..)");
    Logger::getLogger()->warn("OPCUA_Server::setpointCallbacks() : NOT IMPLEMENTED YET");
#warning "TODO : OPCUA_Server::setpointCallbacks"
    return;
}

} // namespace fledge_power_s2opc_north


