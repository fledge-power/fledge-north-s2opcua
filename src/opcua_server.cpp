/*
 * Fledge north service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Jeremie Chabod
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
#include "s2opc/common/sopc_macros.h"
#include "s2opc/common/sopc_builtintypes.h"
#include "s2opc/common/sopc_encodeabletype.h"
#include "s2opc/common/sopc_log_manager.h"
#include "s2opc/common/sopc_pki.h"
#include "s2opc/common/sopc_pki_stack.h"
#include "s2opc/common/sopc_logger.h"
#include "s2opc/common/sopc_types.h"
#include "s2opc/common/sopc_mem_alloc.h"
#include "s2opc/clientserver/frontend/libs2opc_common_config.h"
#include "s2opc/clientserver/frontend/libs2opc_server_config.h"
#include "s2opc/clientserver/frontend/libs2opc_server_config_custom.h"
#include "s2opc/clientserver/sopc_toolkit_config.h"
#include "s2opc/clientserver/sopc_user_manager.h"
#include "s2opc/clientserver/embedded/sopc_addspace_loader.h"

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
   - Using simple quotes inside strings is actually replaced by \"(typical usage for JSON)
        This is useful for filling in JSON content without needing backslashing everything
        e.g.:  "default" : "{ 'name' : 'value'} ",
   - As a consequence the character ' cannot be used inside strings. The escape sequence "\x27" can be used if required
*/
#include "default_config.inc"

/**************************************************************************/
// Reminder: all callbacks/events called from s2opc must be enclosed in
// extern "C" context!
extern "C"
{
/**
 * This function is called to check for user credentials.
 * @param authn The manager context (which contains reference to the server)
 * @param token The authorization token received.
 * @param authenticated The authentication result. Set to SOPC_USER_AUTHENTICATION_REJECTED_TOKEN
 *          or SOPC_USER_AUTHENTICATION_OK
 * @return SOPC_STATUS_OK
 */
static SOPC_ReturnStatus authentication_check(SOPC_UserAuthentication_Manager* authn,
                                              const SOPC_ExtensionObject* token,
                                              SOPC_UserAuthentication_Status* authenticated)
{
    assert(NULL != token && NULL != authenticated && NULL != authn);
    const s2opc_north::OPCUA_Server& server = *reinterpret_cast<const s2opc_north::OPCUA_Server*>(authn->pData);

    const SOPC_tools::StringMap_t& users(server.config().users);

    *authenticated = SOPC_USER_AUTHENTICATION_REJECTED_TOKEN;
    assert(SOPC_ExtObjBodyEncoding_Object == token->Encoding);

    if (&OpcUa_UserNameIdentityToken_EncodeableType == token->Body.Object.ObjType)
    {
        OpcUa_UserNameIdentityToken* userToken =
                reinterpret_cast<OpcUa_UserNameIdentityToken*>(token->Body.Object.Value);

        const char* username = SOPC_String_GetRawCString(&userToken->UserName);
        SOPC_ByteString* pwd = &userToken->Password;

        for (SOPC_tools::StringPair_t pair : users)
        {
            if (pair.first == username)
            {
                // check password
                if (pwd->Length == pair.second.length() &&
                        memcmp(pwd->Data, pair.second.c_str(), pwd->Length) == 0)
                {
                    *authenticated = SOPC_USER_AUTHENTICATION_OK;
                }
            }
        }
    }

    return SOPC_STATUS_OK;
}

/** Configuration of callbacks for authentication */
static const SOPC_UserAuthentication_Functions authentication_functions = {
    .pFuncFree = (SOPC_UserAuthentication_Free_Func*) &SOPC_Free,
    .pFuncValidateUserIdentity = &authentication_check};

} // extern C

namespace SOPC_tools
{
/**************************************************************************/
const char* statusCodeToCString(const int code)
{
#define HANDLE_CODE(x) case x: return #x
    switch (code) {
    HANDLE_CODE(SOPC_STATUS_OK);
    HANDLE_CODE(SOPC_STATUS_NOK);
    HANDLE_CODE(SOPC_STATUS_INVALID_PARAMETERS);
    HANDLE_CODE(SOPC_STATUS_INVALID_STATE);
    HANDLE_CODE(SOPC_STATUS_ENCODING_ERROR);
    HANDLE_CODE(SOPC_STATUS_WOULD_BLOCK);
    HANDLE_CODE(SOPC_STATUS_TIMEOUT);
    HANDLE_CODE(SOPC_STATUS_OUT_OF_MEMORY);
    HANDLE_CODE(SOPC_STATUS_CLOSED);
    HANDLE_CODE(SOPC_STATUS_NOT_SUPPORTED);
        default:
            return ("Invalid code");
    }
}
} // namespace SOPC_tools

/**************************************************************************/
namespace s2opc_north
{

/**************************************************************************/
OPCUA_Server* OPCUA_Server::mInstance = NULL;
/**************************************************************************/
OPCUA_Server::
OPCUA_Server(const ConfigCategory& configData):
    mConfig(configData),
    mBuildInfo(SOPC_CommonHelper_GetBuildInfo()),
    mServerOnline(false)
{
    SOPC_ReturnStatus status;
#if USE_MBEDTLS
    /* Initialize MbedTLS */
    tls_threading_initialize();
#endif

    ASSERT(mInstance == NULL, "OPCUA_Server may not be instanced twice within the same plugin");

    // Configure the server according to mConfig

    // Global initialization
    init_sopc_lib_and_logs();
    Logger::getLogger()->debug ("S2OPC initialization OK");

    // Namespaces initialization
    status = SOPC_HelperConfigServer_SetNamespaces(mConfig.namespacesUri.size, mConfig.namespacesUri.vect);
    ASSERT(status == SOPC_STATUS_OK,
            "SOPC_HelperConfigServer_SetNamespaces returned code %s(%d)",
            statusCodeToCString(status), status);

    const char* localesArray [2] = {mConfig.localeId.c_str(), NULL};
#warning "TODO : remove this ugly cast when S2OPC #1012 is merged"
    status = SOPC_HelperConfigServer_SetLocaleIds(1, (char**)localesArray);
    ASSERT(status == SOPC_STATUS_OK, "SOPC_HelperConfigServer_SetLocaleIds failed");

    // Global descriptions initialization
    status = SOPC_HelperConfigServer_SetApplicationDescription(
            mConfig.appUri.c_str(), mConfig.productUri.c_str(),
            mConfig.serverDescription.c_str(), mConfig.localeId.c_str(),
            OpcUa_ApplicationType_Server);
    ASSERT(status == SOPC_STATUS_OK,
            "SOPC_HelperConfigServer_SetApplicationDescription() returned code %s(%d)",
            statusCodeToCString(status), status);

    // Create endpoints configuration
    SOPC_Endpoint_Config* ep = SOPC_HelperConfigServer_CreateEndpoint(mConfig.url.c_str(), true);
    SOPC_ASSERT(ep != NULL);

    mConfig.setupServerSecurity(ep);

    // Server certificates configuration
    status = SOPC_HelperConfigServer_SetKeyCertPairFromPath(
            mConfig.serverCertPath.c_str(),
            mConfig.serverKeyPath.c_str());
    ASSERT(status == SOPC_STATUS_OK,
            "SOPC_HelperConfigServer_SetKeyCertPairFromPath() returned code %s(%d)",
            statusCodeToCString(status), status);

    // Set PKI configuration
    char* lPathsTrustedLinks[] = {NULL};
    char* lPathsUntrustedRoots[] = {NULL};
    char* lPathsUntrustedLinks[] = {NULL};
    char* lPathsIssuedCerts[] = {NULL};
    SOPC_PKIProvider* pkiProvider = NULL;

    status = SOPC_PKIProviderStack_CreateFromPaths(
            mConfig.trustedRootCert.vect, mConfig.trustedIntermCert.vect,
            mConfig.untrustedRootCert.vect, mConfig.untrustedIntermCert.vect,
            mConfig.issuedCert.vect, mConfig.revokedCert.vect, &pkiProvider);
    ASSERT(status == SOPC_STATUS_OK,
            "SOPC_PKIProviderStack_CreateFromPaths() returned code %s(%d)",
            statusCodeToCString(status), status);

    status = SOPC_HelperConfigServer_SetPKIprovider(pkiProvider);
    ASSERT(status == SOPC_STATUS_OK,
            "SOPC_HelperConfigServer_SetPKIprovider() returned code %s(%d)",
            statusCodeToCString(status), status);

    Logger::getLogger()->info("Test_Server_Client: Certificates and key loaded");

#warning WIP_JCH BEGIN

    // from toolkit_test_server.c : Server_SetDefaultAddressSpace
    // TODO fill in sopc_embedded_is_const_addspace, SOPC_Embedded_AddressSpace_nNodes
    // SOPC_Embedded_AddressSpace_Nodes
    SOPC_AddressSpace* addSpace = SOPC_Embedded_AddressSpace_Load();
    SOPC_ASSERT(addSpace != NULL);

    status = SOPC_HelperConfigServer_SetAddressSpace(addSpace);
    ASSERT(status == SOPC_STATUS_OK,
            "SOPC_HelperConfigServer_SetAddressSpace() returned code %s(%d)",
            statusCodeToCString(status), status);

#warning "TODO : make a user-access level ?"
    SOPC_UserAuthorization_Manager* authorizationManager = SOPC_UserAuthorization_CreateManager_AllowAll();

    /* User Management configuration */
    SOPC_UserAuthentication_Manager* authenticationManager = new SOPC_UserAuthentication_Manager;
    SOPC_ASSERT(authenticationManager != NULL && authorizationManager != NULL);

    memset(authenticationManager, 0, sizeof (*authenticationManager));

    // Store the reference of the server so that authentication callback can
    // proceed to checks towards configuration.
    authenticationManager->pData = (void*) this;

    authenticationManager->pFunctions = &authentication_functions;
    SOPC_HelperConfigServer_SetUserAuthenticationManager(authenticationManager);
    SOPC_HelperConfigServer_SetUserAuthorizationManager(authorizationManager);


#warning WIP_JCH END


#warning "TODO : Server_ConfigureStartServer"

    mInstance = this;
}

/**************************************************************************/
OPCUA_Server::
~OPCUA_Server()
{
    SOPC_HelperConfigServer_Clear();
    SOPC_CommonHelper_Clear();

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
void
OPCUA_Server::
init_sopc_lib_and_logs(void)
{
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
    SOPC_ReturnStatus status = SOPC_CommonHelper_Initialize(&logConfig);
    SOPC_ASSERT(status == SOPC_STATUS_OK && "SOPC_CommonHelper_Initialize failed");

    status = SOPC_HelperConfigServer_Initialize();
    SOPC_ASSERT(status == SOPC_STATUS_OK && "SOPC_HelperConfigServer_Initialize failed");
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

} // namespace s2opc_north


