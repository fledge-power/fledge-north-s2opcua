/*
 * Fledge north service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Jeremie Chabod
 */

#define USE_TLS 0 // TODO!

#include <opcua_server_config.h>

#include <algorithm>
#include <string>
#include <logger.h>
#include <exception>

extern "C" {
// S2OPC Headers
#include "s2opc/common/sopc_assert.h"
#include "s2opc/common/sopc_atomic.h"
#include "s2opc/common/sopc_common.h"
#include "s2opc/common/sopc_encodeabletype.h"
#include "s2opc/common/sopc_log_manager.h"
#include "s2opc/common/sopc_builtintypes.h"
#include "s2opc/common/sopc_types.h"
#include "s2opc/common/sopc_crypto_decl.h"
#include "s2opc/common/sopc_key_manager.h"
#include "s2opc/common/sopc_pki_stack.h"
#include "s2opc/clientserver/frontend/libs2opc_common_config.h"
#include "s2opc/clientserver/frontend/libs2opc_server_config.h"
#include "s2opc/clientserver/sopc_toolkit_config.h"
#include "s2opc/clientserver/sopc_user_manager.h"
}

namespace
{
// Plugin data storage
static const std::string dataDir (getDataDir());
// logs folder
static const std::string logDir (dataDir + "/logs/");
// Certificate folder
static const std::string certDir (dataDir + "/etc/cert/");

// TODO : to replace by a real configuration of certificates management.
static char* default_trusted_certs[] = {NULL, NULL};
static char* default_revoked_certs[] = {NULL, NULL};
static char* empty_certs[] = {NULL};

std::string toUpper(const std::string & str)
{
    std::string copy (str);
    std::transform(copy.begin(), copy.end(), copy.begin(), ::toupper);
    return copy;
}

SOPC_Log_Level toSOPC_Log_Level(const std::string & str)
{
    const std::string sUpper (::toUpper(str));
    if (sUpper == "DEBUG")
    {
        return SOPC_LOG_LEVEL_DEBUG;
    }
    if (sUpper == "INFO")
    {
        return SOPC_LOG_LEVEL_INFO;
    }
    if (sUpper == "WARNING")
    {
        return SOPC_LOG_LEVEL_WARNING;
    }
    if (sUpper == "ERROR")
    {
        return SOPC_LOG_LEVEL_ERROR;
    }
    // Default value
    return SOPC_LOG_LEVEL_INFO;
}

void SOPC_String_CopyFromStdString(SOPC_String* dest, const std::string& ref)
{
    const SOPC_ReturnStatus status = ::SOPC_String_CopyFromCString(dest, ref.c_str());
    if (status != SOPC_STATUS_OK)
    {
        Logger::getLogger()->fatal("SOPC_String_CopyFromStdString failed()");
    }
}

}

namespace fledge_power_s2opc_north
{

// Important note: OPC stack is not initialized yet while parsing configuration,
// thus it is not possible to use S2OPC logging at this point.
/**************************************************************************/
OpcUa_Server_Config::
OpcUa_Server_Config(const ConfigCategory& configData):
    url(extractString(configData, "url")),
    appUri(extractString(configData, "appUri")),
    productUri(extractString(configData, "productUri")),
    serverDescription(extractString(configData, "productUri")),
    serverCertPath(extractCertificate(configData, "serverCertPath", ".der")),
    serverKeyPath(extractCertificate(configData, "serverKeyPath", ".pem")),
    caCertPath(extractCertificate(configData, "caCertPath", ".der")),
    caCrlPath(extractCertificate(configData, "caCrlPath", ".der")),
    withLogs(extractStringIs(configData, "logging", "none")),
    logLevel(toSOPC_Log_Level(extractString(configData, "logging"))),
    logPath(::logDir)
{
    Logger::getLogger()->info("OpcUa_Server_Config() OK.");
    Logger::getLogger()->debug("Conf : url = %s", url.c_str());
    Logger::getLogger()->debug("Conf : serverCertPath = %s", serverCertPath.c_str());
    Logger::getLogger()->debug("Conf : serverKeyPath = %s", serverKeyPath.c_str());
    Logger::getLogger()->debug("Conf : caCertPath = %s", caCertPath.c_str());
    Logger::getLogger()->debug("Conf : caCrlPath = %s", caCrlPath.c_str());
    Logger::getLogger()->debug("Conf : logLevel = %d", logLevel);
    Logger::getLogger()->debug("Conf : withLogs = %d", withLogs);

    SOPC_ASSERT(not serverCertPath.empty() && "serverCertPath is missing");
    SOPC_ASSERT(not serverKeyPath.empty() && "serverKeyPath is missing");
    SOPC_ASSERT(not caCertPath.empty() && "caCertPath is missing");
    SOPC_ASSERT(not caCrlPath.empty() && "caCrlPath is missing");
}

/**************************************************************************/
std::string
OpcUa_Server_Config::
extractCertificate(const ConfigCategory& config, const std::string& name, const std::string& extenstion)
{
    std::string result;
    const std::string value (config.getValue(name));
    const char* p = value.c_str();
    Logger::getLogger()->warn("DEBUG %s = '%s'" ,name.c_str(), p);
    while (*p){
        Logger::getLogger()->warn("TODO: char = 0x%02X" ,*p);
        p++;
    };
    if (not value.empty())
    {
        result = ::certDir + extractString(config, "serverCertPath") + extenstion;
    }
    return result;
}

/**************************************************************************/
std::string
OpcUa_Server_Config::
extractString(const ConfigCategory& config, const std::string& name)
{
    if (config.itemExists(name))
    {
        return config.getValue(name);
    }
    Logger::getLogger()->fatal("Missing config parameter:'%s'" ,name.c_str());
    SOPC_ASSERT("Missing config parameter");
}

/**************************************************************************/
inline bool
OpcUa_Server_Config::
extractStringIs(const ConfigCategory& config, const std::string& name, const std::string& compare)
{
    return ::toUpper(extractString(config, name)) == ::toUpper(compare);
}

/**************************************************************************/
SOPC_S2OPC_Config*
OpcUa_Server_Config::
extractOpcConfig(const ConfigCategory& config) const
{
    SOPC_S2OPC_Config* pOpc_config = new SOPC_S2OPC_Config;
    SOPC_ASSERT(pOpc_config != NULL && "extractOpcConfig() failed to allocate a configuration");

    SOPC_S2OPC_Config_Initialize(pOpc_config);
    SOPC_S2OPC_Config& opc_config = *pOpc_config;

    // Initialize content to empty configuration
    memset(reinterpret_cast<void*>(&opc_config), 0, sizeof(opc_config));
    OpcUa_ApplicationDescription_Initialize(&opc_config.serverConfig.serverDescription);
    OpcUa_ApplicationDescription_Initialize(&opc_config.clientConfig.clientDescription);
    opc_config.clientConfig.clientDescription.ApplicationType = OpcUa_ApplicationType_Client;

    // Build opc_config based on "ConfigCategory" received

    SOPC_UserAuthentication_Manager* authenticationManager = NULL;
    SOPC_UserAuthorization_Manager* authorizationManager = NULL;

    /* Application description configuration */
    OpcUa_ApplicationDescription* appSrvDescr = &opc_config.serverConfig.serverDescription;
    OpcUa_ApplicationDescription_Initialize(appSrvDescr);
    SOPC_String_CopyFromStdString(&appSrvDescr->ApplicationUri, appUri);
    SOPC_String_CopyFromStdString(&appSrvDescr->ProductUri, productUri);
    appSrvDescr->ApplicationType = OpcUa_ApplicationType_Server;
    SOPC_String_CopyFromStdString(&appSrvDescr->ApplicationName.defaultText, serverDescription);

    /* Cryptographic configuration */
    SOPC_ReturnStatus status = SOPC_STATUS_OK;

    opc_config.serverConfig.serverCertPath = NULL;
    opc_config.serverConfig.serverKeyPath = NULL;
    opc_config.serverConfig.trustedRootIssuersList = default_trusted_certs;
    opc_config.serverConfig.trustedIntermediateIssuersList = empty_certs;
    opc_config.serverConfig.issuedCertificatesList = empty_certs;
    opc_config.serverConfig.untrustedRootIssuersList = empty_certs;
    opc_config.serverConfig.untrustedIntermediateIssuersList = empty_certs;
    opc_config.serverConfig.certificateRevocationPathList = default_revoked_certs;

    SOPC_SerializedCertificate* static_cacert = NULL;
    SOPC_CRLList* static_cacrl = NULL;

    status = SOPC_KeyManager_SerializedCertificate_CreateFromFile(serverCertPath.c_str(),
            &opc_config.serverConfig.serverCertificate);
    SOPC_ASSERT(SOPC_STATUS_OK == status && "extractOpcConfig() failed to open server certificate");

    status = SOPC_KeyManager_SerializedAsymmetricKey_CreateFromFile(serverKeyPath.c_str(),
            &opc_config.serverConfig.serverKey);
    SOPC_ASSERT(SOPC_STATUS_OK == status && "extractOpcConfig() failed to open server KEY");

    status = SOPC_KeyManager_SerializedCertificate_CreateFromFile(caCertPath.c_str(), &static_cacert);
    SOPC_ASSERT(SOPC_STATUS_OK == status && "extractOpcConfig() failed to open CA certificate");

    status = SOPC_KeyManager_CRL_CreateOrAddFromFile(caCrlPath.c_str(), &static_cacrl);
    SOPC_ASSERT(SOPC_STATUS_OK == status && "extractOpcConfig() failed to open CA revocation list");

    status = SOPC_PKIProviderStack_Create(static_cacert, static_cacrl, &opc_config.serverConfig.pki);

    /* Clean in all cases */
    SOPC_KeyManager_SerializedCertificate_Delete(static_cacert);

    SOPC_ASSERT(SOPC_STATUS_OK == status && "extractOpcConfig() Failed loading certificates and key (check paths are valid)");

    /* Configuration of the endpoint descriptions */
    opc_config.serverConfig.nbEndpoints = 1;

    opc_config.serverConfig.endpoints = new SOPC_Endpoint_Config;
    SOPC_ASSERT(opc_config.serverConfig.endpoints != NULL);

    if (NULL == opc_config.serverConfig.endpoints)
    {
        return SOPC_STATUS_NOK;
    }
    // Configure endpoints
#warning "TODO: Configure endpoints"
    Logger::getLogger()->fatal("# Error: WIP JCH. To be continued: Set up endpoint(s)\n");
    throw exception();



    SOPC_Endpoint_Config* pEpConfig = &opc_config.serverConfig.endpoints[0];
    pEpConfig->nbSecuConfigs = 3;
//
//    /* Server's listening endpoint */
//    pEpConfig->serverConfigPtr = &opc_config.serverConfig;
//    pEpConfig->endpointURL = CONFIG_SOPC_ENDPOINT_ADDRESS;
//
//    /* 1st Security policy is None without user (users on unsecure channel shall be forbidden) */
//    if (SOPC_STATUS_OK == status)
//    {
//        SOPC_String_Initialize(&pEpConfig->secuConfigurations[0].securityPolicy);
//        status = SOPC_String_AttachFromCstring(&pEpConfig->secuConfigurations[0].securityPolicy,
//                                               SOPC_SecurityPolicy_None_URI);
//        pEpConfig->secuConfigurations[0].securityModes = SOPC_SECURITY_MODE_NONE_MASK;
//        pEpConfig->secuConfigurations[0].nbOfUserTokenPolicies = 1;
//        pEpConfig->secuConfigurations[0].userTokenPolicies[0] = SOPC_UserTokenPolicy_Anonymous;
//    }
//
//    /* 2nd Security policy is Basic256 with anonymous or username authentication allowed
//     * (without password encryption) */
//    if (SOPC_STATUS_OK == status)
//    {
//        SOPC_String_Initialize(&pEpConfig->secuConfigurations[1].securityPolicy);
//        status = SOPC_String_AttachFromCstring(&pEpConfig->secuConfigurations[1].securityPolicy,
//                                               SOPC_SecurityPolicy_Basic256_URI);
//        pEpConfig->secuConfigurations[1].securityModes =
//            SOPC_SECURITY_MODE_SIGN_MASK | SOPC_SECURITY_MODE_SIGNANDENCRYPT_MASK;
//        pEpConfig->secuConfigurations[1].nbOfUserTokenPolicies = 2;
//        pEpConfig->secuConfigurations[1].userTokenPolicies[0] = SOPC_UserTokenPolicy_Anonymous;
//        pEpConfig->secuConfigurations[1].userTokenPolicies[1] =
//            SOPC_UserTokenPolicy_UserName_Basic256Sha256SecurityPolicy;
//    }
//
//    /* 3rd Security policy is Basic256Sha256 with anonymous or username authentication allowed
//     * (without password encryption) */
//    if (SOPC_STATUS_OK == status)
//    {
//        SOPC_String_Initialize(&pEpConfig->secuConfigurations[2].securityPolicy);
//        status = SOPC_String_AttachFromCstring(&pEpConfig->secuConfigurations[2].securityPolicy,
//                                               SOPC_SecurityPolicy_Basic256Sha256_URI);
//        pEpConfig->secuConfigurations[2].securityModes = SOPC_SECURITY_MODE_SIGNANDENCRYPT_MASK;
//        pEpConfig->secuConfigurations[2].nbOfUserTokenPolicies = 2;
//        pEpConfig->secuConfigurations[2].userTokenPolicies[0] = SOPC_UserTokenPolicy_Anonymous;
//        pEpConfig->secuConfigurations[2].userTokenPolicies[1] =
//            SOPC_UserTokenPolicy_UserName_Basic256Sha256SecurityPolicy;
//    }
//
//    /* User authentication and authorization */
//    if (SOPC_STATUS_OK == status)
//    {
//        authenticationManager = SOPC_UserAuthentication_CreateManager_AllowAll();
//        authorizationManager = SOPC_UserAuthorization_CreateManager_AllowAll();
//        if (NULL == authenticationManager || NULL == authorizationManager)
//        {
//            printf("# Error: Failed to create user authentication and authorization managers.\n");
//            status = SOPC_STATUS_OUT_OF_MEMORY;
//        }
//    }
//    if (SOPC_STATUS_OK == status)
//    {
//        pEpConfig->authenticationManager = authenticationManager;
//        pEpConfig->authorizationManager = authorizationManager;
//    }
//    else
//    {
//        SOPC_UserAuthentication_FreeManager(&authenticationManager);
//        SOPC_UserAuthorization_FreeManager(&authorizationManager);
//        Logger::getLogger()->fatal("extractOpcConfig failed with code %d", status);
//        throw exception();
//    }

    return pOpc_config;
}

/**************************************************************************/
OpcUa_Server_Config::
~OpcUa_Server_Config(void)
{

}

} // namespace fledge_power_s2opc_north


