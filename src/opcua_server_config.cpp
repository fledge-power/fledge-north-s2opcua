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
#include "s2opc/common/sopc_crypto_profiles.h"
#include "s2opc/common/sopc_key_manager.h"
#include "s2opc/common/sopc_pki_stack.h"
#include "s2opc/clientserver/frontend/libs2opc_common_config.h"
#include "s2opc/clientserver/frontend/libs2opc_server_config.h"
#include "s2opc/clientserver/sopc_toolkit_config.h"
#include "s2opc/clientserver/sopc_user_manager.h"
#include "s2opc/clientserver/sopc_user_app_itf.h"
}

namespace
{
using namespace fledge_power_s2opc_north;
// Plugin data storage
static const std::string dataDir (getDataDir());
// logs folder
static const std::string logDir (dataDir + "/logs/");
// Certificate folder
static const std::string certDir (dataDir + "/etc/certs/s2opc_srv/");

// TODO : to replace by a real configuration of certificates management.
static char* default_trusted_certs[] = {NULL, NULL};
static char* default_revoked_certs[] = {NULL, NULL};
static char* empty_certs[] = {NULL};

/**************************************************************************/
static std::string toUpper(const std::string & str)
{
    std::string copy (str);
    std::transform(copy.begin(), copy.end(), copy.begin(), ::toupper);
    return copy;
}
/**************************************************************************/
static std::string splitString(std::string & src, const char separator = '/')
{
    std::string result;
    size_t pos (src.find_first_of(separator));

    if (pos == string::npos)
    {
        result = src;
        src.clear();
    }
    else
    {
        if (pos == 0)
        {
            result = "";
        }
        else
        {
            result = src.substr(0, pos);
        }
        src.erase (0, pos + 1);
    }
    return result;
}

/**************************************************************************/
static SOPC_Log_Level toSOPC_Log_Level(const std::string & str)
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

/**************************************************************************/
static void SOPC_String_CopyFromStdString(SOPC_String* dest, const std::string& ref)
{
    const SOPC_ReturnStatus status = ::SOPC_String_CopyFromCString(dest, ref.c_str());
    SOPC_ASSERT(status == SOPC_STATUS_OK && "SOPC_String_CopyFromStdString failed");
}

/**************************************************************************/
static std::string toSecurityPolicy(const std::string& policy)
{
    static const std::string prefix("http://opcfoundation.org/UA/SecurityPolicy#");
    const std::string result = prefix + policy;

    const SOPC_CryptoProfile* profile(SOPC_CryptoProfile_Get(result.c_str()));

    if (profile == NULL)
    {
        Logger::getLogger()->error("Invalid security profile '%s'" , result.c_str());
        SOPC_ASSERT(false && "Invalid security profile");
        throw exception();
    }

    return result;
}

/**************************************************************************/
static uint16_t toSecurityMode(const std::string& mode)
{
    const std::string sUpper (::toUpper(mode));
    if (sUpper == "NONE")
    {
        return SOPC_SECURITY_MODE_NONE_MASK;
    }
    if (sUpper == "SIGN")
    {
        return SOPC_SECURITY_MODE_SIGN_MASK;
    }
    if (sUpper == "SIGNANDENCRYPT")
    {
        return SOPC_SECURITY_MODE_SIGNANDENCRYPT_MASK;
    }

    Logger::getLogger()->error("Invalid security mode '%s'" , mode.c_str());
    throw exception();
}

/**************************************************************************/
/**
 * @param toekn the token amongst [Anonymous|UserName_None|UserName|UserName_Basic256Sha256]
 */
static const OpcUa_UserTokenPolicy& toUserToken(const std::string& token)
{
    if (token == SOPC_UserTokenPolicy_Anonymous_ID)
    {
        return SOPC_UserTokenPolicy_Anonymous;
    }
    if (token == SOPC_UserTokenPolicy_UserNameNone_ID)
    {
        return SOPC_UserTokenPolicy_UserName_NoneSecurityPolicy;
    }
    if (token == SOPC_UserTokenPolicy_UserName_ID)
    {
        return SOPC_UserTokenPolicy_UserName_DefaultSecurityPolicy;
    }
    if (token == SOPC_UserTokenPolicy_UserNameBasic256Sha256_ID)
    {
        return SOPC_UserTokenPolicy_UserName_Basic256Sha256SecurityPolicy;
    }

    Logger::getLogger()->error("Invalid user token policy '%s'" , token.c_str());
    throw exception();
}

typedef void (*processConfigArrayCb)(const std::string&);
/**************************************************************************/
static OpcUa_Server_Config::StringVect extractStrArray(const std::string& endpointCfg, const char* section)
{
    SOPC_ASSERT(NULL != section);
    OpcUa_Server_Config::StringVect result;

    rapidjson::Document doc;
    doc.Parse(endpointCfg.c_str());
    if (doc.HasParseError() || (!doc.HasMember(section) && doc[section].IsArray()))
    {
        Logger::getLogger()->error("Invalid section configuration :%s", section);
        SOPC_ASSERT(false);
    }

    const rapidjson::Value& subs = doc[section];
    for (rapidjson::SizeType i = 0; i < subs.Size(); i++)
    {
        const std::string value (subs[i].GetString()) ;
        result.push_back(value);
    }
    return result;
}


} // namespace

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
    withLogs(extractStringEquals(configData, "logging", "none")),
    logLevel(toSOPC_Log_Level(extractString(configData, "logging"))),
    logPath(::logDir),
    policies(::extractStrArray(extractString(configData, "endpoint"), "policies"))
{
    Logger::getLogger()->info("OpcUa_Server_Config() OK.");
    Logger::getLogger()->info("Conf : logPath = %s", logPath.c_str());
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
extractCertificate(const ConfigCategory& config, const std::string& name, const std::string& extenstion)const
{
    std::string result;
    const std::string value (extractString(config, name));
    if (not value.empty())
    {
        result = ::certDir + value + extenstion;
    }
    return result;
}

/**************************************************************************/
std::string
OpcUa_Server_Config::
extractString(const ConfigCategory& config, const std::string& name)const
{
    if (not config.itemExists(name))
    {
        Logger::getLogger()->fatal("Missing config parameter:'%s'" ,name.c_str());
        SOPC_ASSERT(false && "Missing config parameter");
    }
    return config.getValue(name);
}

/**************************************************************************/
inline bool
OpcUa_Server_Config::
extractStringEquals(const ConfigCategory& config, const std::string& name, const std::string& compare)const
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

    /* Configuration of the endpoints descriptions (Only one endpoint in this plugin*/
    opc_config.serverConfig.nbEndpoints = 1;

    opc_config.serverConfig.endpoints = new SOPC_Endpoint_Config;
    SOPC_ASSERT(opc_config.serverConfig.endpoints != NULL);

    // Configure endpoints
    /*  As configuration does not provide deep JSON (arrays of list), the solution chosen is
     * to use an array of string to define all possible policies.
     * The expected format is :
     * "<Mode>/<Policy>/<token1>[+<token2>[+...]]"
     * For example "None/None/anonymous" or "SignAndEncrypt/Basic256Sha256/anonymous+username_Basic256Sha256"
     */

    SOPC_Endpoint_Config* pEpConfig = &opc_config.serverConfig.endpoints[0];

    /* Server's listening endpoint */
    pEpConfig->serverConfigPtr = &opc_config.serverConfig;
    pEpConfig->endpointURL = strdup(url.c_str()); // Freed by SOPC_S2OPC_Config_Clear

    /* Setup policies */
    pEpConfig->nbSecuConfigs = policies.size();
    size_t i;
    for (size_t i = 0 ; i < pEpConfig->nbSecuConfigs; i ++)
    {
        SOPC_SecurityPolicy& secPolicy (pEpConfig->secuConfigurations[i]);
        std::string rawPolicy(policies[i]);
        Logger::getLogger()->debug("process policy %s", rawPolicy.c_str()); // TODO

        bool valid = true;

        const std::string mode(::splitString(rawPolicy));
        const std::string policy(::splitString(rawPolicy));

        if (not (policy.empty() or mode.empty()))
        {
            const std::string  policyStr(toSecurityPolicy(policy));
            status = SOPC_String_InitializeFromCString(&secPolicy.securityPolicy, policyStr.c_str());
            SOPC_ASSERT(status == SOPC_STATUS_OK && "SOPC_String_InitializeFromCString failed");

            secPolicy.securityModes = ::toSecurityMode(mode);

            // Read user tokens
            valid = true;
            StringVect tokens;

            while (valid and not rawPolicy.empty())
            {
                const std::string token(::splitString(rawPolicy, '+'));
                if (not token.empty())
                {
                    tokens.push_back(token);
                }
                else
                {
                    valid = false;
                }
            }

            secPolicy.nbOfUserTokenPolicies = tokens.size();
            for (size_t j = 0 ; j < secPolicy.nbOfUserTokenPolicies; j ++)
            {
                const std::string& token (tokens[j]);
                secPolicy.userTokenPolicies[j] = ::toUserToken (token);
            }
        }

        if (not valid)
        {
            Logger::getLogger()->error("Invalid security policy '%s'", policies[i].c_str());
            Logger::getLogger()->warn("Expected format is \"Mode/Policy/token1+token2+...\" "\
                    "with mode = None|Sign|SingAndEncrypt, Policy = None|Basic256|Basic256Sha256"\
                    "and tokenX = anonymous|username_None|username|username_Basic256Sha256");
            SOPC_ASSERT(false && "Invalid security policy");
        }
    }

    /* User authentication and authorization */
#warning "TODO : "

    pEpConfig->authenticationManager = SOPC_UserAuthentication_CreateManager_AllowAll();
    pEpConfig->authorizationManager = SOPC_UserAuthorization_CreateManager_AllowAll();
    SOPC_ASSERT (NULL != pEpConfig->authenticationManager && NULL != pEpConfig->authorizationManager && "Failed to create user authentication and authorization managers.");

    return pOpc_config;
}

/**************************************************************************/
OpcUa_Server_Config::
~OpcUa_Server_Config(void)
{

}

} // namespace fledge_power_s2opc_north


