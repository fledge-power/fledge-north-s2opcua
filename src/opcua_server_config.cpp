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
#include <exception>

// FLEDGE headers
#include <logger.h>
#include <rapidjson/document.h>

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
#include "s2opc/common/sopc_mem_alloc.h"
#include "s2opc/common/sopc_pki_stack.h"
#include "s2opc/clientserver/frontend/libs2opc_server.h"
#include "s2opc/clientserver/frontend/libs2opc_server_config.h"
#include "s2opc/clientserver/frontend/libs2opc_server_config_custom.h"
#include "s2opc/clientserver/sopc_toolkit_config.h"
#include "s2opc/clientserver/sopc_user_manager.h"
#include "s2opc/clientserver/sopc_user_app_itf.h"
}

namespace
{
using namespace SOPC_tools;
// Plugin data storage
static const std::string dataDir (getDataDir());
// logs folder
static const std::string logDir (dataDir + "/logs/");
// Certificate folder
static const std::string certDir (dataDir + "/etc/certs/s2opc_srv/");

static const std::string pemExt (".pem");
static const std::string derExt (".der");

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
static SOPC_SecurityPolicy_URI toSecurityPolicy(const std::string& policy)
{
    Logger::getLogger()->debug("Converting value '%s' to security policy" ,policy.c_str());
    if (policy == "None")
    {
        return SOPC_SecurityPolicy_None;
    }
    if (policy == "Basic256")
    {
        return SOPC_SecurityPolicy_Basic256;
    }
    if (policy == "Basic256Sha256")
    {
        return SOPC_SecurityPolicy_Basic256Sha256;
    }
    if (policy == "Aes128Sha256RsaOaep")
    {
        return SOPC_SecurityPolicy_Aes128Sha256RsaOaep;
    }
    if (policy == "Aes128Sha256RsaOaep")
    {
        return SOPC_SecurityPolicy_Aes256Sha256RsaPss;
    }

    Logger::getLogger()->error("Invalid security policy '%s'" , policy.c_str());
    throw exception();
}

/**************************************************************************/
static SOPC_SecurityModeMask toSecurityMode(const std::string& mode)
{
    Logger::getLogger()->debug("Converting value '%s' to security mode" ,mode.c_str());
    const std::string sUpper (::toUpper(mode));
    if (sUpper == "NONE")
    {
        return SOPC_SecurityModeMask_None;
    }
    if (sUpper == "SIGN")
    {
        return SOPC_SecurityModeMask_Sign;
    }
    if (sUpper == "SIGNANDENCRYPT")
    {
        return SOPC_SecurityModeMask_SignAndEncrypt;
    }

    Logger::getLogger()->error("Invalid security mode '%s'" , mode.c_str());
    throw exception();
}

/**************************************************************************/
/**
 * @param toekn the token amongst [Anonymous|UserName_None|UserName|UserName_Basic256Sha256]
 */
static const OpcUa_UserTokenPolicy* toUserToken(const std::string& token)
{
    Logger::getLogger()->debug("Converting value '%s' to user token Id" ,token.c_str());
    if (token == SOPC_UserTokenPolicy_Anonymous_ID)
    {
        return &SOPC_UserTokenPolicy_Anonymous;
    }
    if (token == SOPC_UserTokenPolicy_UserNameNone_ID)
    {
        return &SOPC_UserTokenPolicy_UserName_NoneSecurityPolicy;
    }
    if (token == SOPC_UserTokenPolicy_UserName_ID)
    {
        return &SOPC_UserTokenPolicy_UserName_DefaultSecurityPolicy;
    }
    if (token == SOPC_UserTokenPolicy_UserNameBasic256Sha256_ID)
    {
        return &SOPC_UserTokenPolicy_UserName_Basic256Sha256SecurityPolicy;
    }

    Logger::getLogger()->error("Invalid user token policy '%s'" , token.c_str());
    throw exception();
}

/**************************************************************************/
static std::string
extractString(const ConfigCategory& config, const std::string& name)
{
    ASSERT(config.itemExists(name),"Missing config parameter:'%s'" ,name.c_str());

    Logger::getLogger()->debug("Reading config parameter:'%s'" ,name.c_str());
    return config.getValue(name);
}


typedef void (*processConfigArrayCb)(const std::string&);
/**************************************************************************/
static StringVect_t extractStrArray(const std::string& value, const char* section)
{
    SOPC_ASSERT(NULL != section);
    StringVect_t result;

    rapidjson::Document doc;
    doc.Parse(value.c_str());
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

/**************************************************************************/
static StringMap_t extractUsersPasswords(const std::string& config)
{
    using namespace rapidjson;
    StringMap_t result;
    rapidjson::Value::ConstMemberIterator it;

    Logger::getLogger()->debug("extractUsersPasswords(%s)", config.c_str()); //TOO remove

    Document doc;
    doc.Parse(config.c_str());
    ASSERT(not doc.HasParseError(),
            "Invalid users configuration :%s", config.c_str());

    Logger::getLogger()->debug("extractUsersPasswords - 2"); //TOO remove

    for (it = doc.MemberBegin() ; it != doc.MemberEnd(); it++)
    {
        const char* user = it->name.GetString();
        const char* pass = it->value.GetString();
        result.push_back(std::make_pair(user, pass));
    }

    return result;
}


/**************************************************************************/
static SOPC_tools::CStringVect extractCStrArray(const std::string& value, const char* section)
{
    return SOPC_tools::CStringVect(extractStrArray(value, section));
}
} // namespace


/**************************************************************************/
/**************************************************************************/
namespace SOPC_tools
{
/**************************************************************************/
CStringVect::
CStringVect(const SOPC_tools::StringVect_t& ref):
    size(ref.size()),
    vect(new char*[size + 1])
{
    for (size_t i=0 ; i < size; i++)
    {
        vect[i] = strdup(ref[i].c_str());
    }
    vect[size] = NULL;
}

/**************************************************************************/
CStringVect::
~ CStringVect(void)
{
    for (size_t i=0 ; i < size; i++)
    {
        delete (vect[i]);
    }
    delete vect;
}
} // namespace SOPC_tools

/**************************************************************************/
namespace s2opc_north
{
using namespace SOPC_tools;

// Important note: OPC stack is not initialized yet while parsing configuration,
// thus it is not possible to use S2OPC logging at this point.
/**************************************************************************/
OpcUa_Server_Config::
OpcUa_Server_Config(const ConfigCategory& configData):
    url(extractString(configData, "url")),
    appUri(extractString(configData, "appUri")),
    productUri(extractString(configData, "productUri")),
    localeId(extractString(configData, "localeId")),
    serverDescription(extractString(configData, "description")),
    serverCertPath(extractCertificate(configData, "serverCertPath", derExt)),
    serverKeyPath(extractCertificate(configData, "serverKeyPath", pemExt)),
    certificates(extractString(configData, "certificates")),
    trustedRootCert(extractCStrArray(certificates, "trusted_root")),
    trustedIntermCert(extractCStrArray(certificates, "trusted_intermediate")),
    untrustedRootCert(extractCStrArray(certificates, "untrusted_root")),
    untrustedIntermCert(extractCStrArray(certificates, "untrusted_intermediate")),
    issuedCert(extractCStrArray(certificates, "issued")),
    revokedCert(extractCStrArray(certificates, "revoked")),
    withLogs(extractStringEquals(configData, "logging", "none")),
    logLevel(toSOPC_Log_Level(extractString(configData, "logging"))),
    logPath(::logDir),
    policies(extractStrArray(extractString(configData, "endpoint"), "policies")),
    namespacesStr(extractString(configData, "namespaces")),
    namespacesUri(extractCStrArray(namespacesStr, "namespaces")),
    users(extractUsersPasswords(extractString(configData, "users")))
{
    Logger::getLogger()->info("OpcUa_Server_Config() OK.");
    Logger::getLogger()->info("Conf : logPath = %s", logPath.c_str());
    Logger::getLogger()->debug("Conf : url = %s", url.c_str());
    Logger::getLogger()->debug("Conf : serverCertPath = %s", serverCertPath.c_str());
    Logger::getLogger()->debug("Conf : serverKeyPath = %s", serverKeyPath.c_str());
    Logger::getLogger()->debug("Conf : certificates = %s", certificates.c_str());
    Logger::getLogger()->debug("Conf : logLevel = %d", logLevel);
    Logger::getLogger()->debug("Conf : withLogs = %d", withLogs);

    ASSERT(not serverCertPath.empty(), "serverCertPath is missing");
    ASSERT(not serverKeyPath.empty(), "serverKeyPath is missing");
    ASSERT(serverDescription.length() > 0,
            "Application description cannot be empty");
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
inline bool
OpcUa_Server_Config::
extractStringEquals(const ConfigCategory& config, const std::string& name, const std::string& compare)const
{
    return ::toUpper(extractString(config, name)) == ::toUpper(compare);
}

/**************************************************************************/
void
OpcUa_Server_Config::
setupServerSecurity(SOPC_Endpoint_Config* ep)const
{
    for (std::string rawPolicy : policies)
    {
        Logger::getLogger()->debug("process policy %s", rawPolicy.c_str());
        const SOPC_SecurityModeMask mode(::toSecurityMode(::splitString(rawPolicy)));
        const SOPC_SecurityPolicy_URI policy(::toSecurityPolicy(::splitString(rawPolicy)));
        SOPC_SecurityPolicy* sp = SOPC_EndpointConfig_AddSecurityConfig(ep, policy);
        SOPC_ASSERT(sp != NULL);

        SOPC_ReturnStatus status = SOPC_SecurityConfig_SetSecurityModes(sp, mode);
        ASSERT(status == SOPC_STATUS_OK,
                "SOPC_SecurityConfig_SetSecurityModes failed");

        bool valid = true;

        do
        {
            const std::string token(::splitString(rawPolicy, '+'));
            const SOPC_UserTokenPolicy* userPolicy (::toUserToken(token));
            status = SOPC_SecurityConfig_AddUserTokenPolicy(sp, userPolicy);
            ASSERT(status == SOPC_STATUS_OK,
                    "SOPC_SecurityConfig_AddUserTokenPolicy returned code %s(%d)",
                    statusCodeToCString(status), status);
        } while (not rawPolicy.empty());
    }
}

/**************************************************************************/
OpcUa_Server_Config::
~OpcUa_Server_Config(void)
{
}

} // namespace s2opc_north


