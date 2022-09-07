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
#include <unistd.h>

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
static const std::string certDirServer (::certDir + "server/");
static const std::string certDirTrusted (::certDir + "trusted/");
static const std::string certDirUntrusted (::certDir + "untrusted/");
static const std::string certDirIssued (::certDir + "issued/");
static const std::string certDirRevoked (::certDir + "revoked/");

/**************************************************************************/
/** \brief return an uppercase version of str */
static std::string toUpper(const std::string & str)
{
    std::string copy (str);
    std::transform(copy.begin(), copy.end(), copy.begin(), ::toupper);
    return copy;
}

/**************************************************************************/
/** \brief split a string.
 * \param src [inout] As input contains the string to split.
 *  As output, contains the remaining after the separator (or empty)
 * \param separator The string separator
 **/
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
    DEBUG("Converting value '%s' to security policy" ,policy.c_str());
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

    ERROR("Invalid security policy '%s'" , policy.c_str());
    throw exception();
}

/**************************************************************************/
static SOPC_SecurityModeMask toSecurityMode(const std::string& mode)
{
    DEBUG("Converting value '%s' to security mode" ,mode.c_str());
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

    ERROR("Invalid security mode '%s'" , mode.c_str());
    throw exception();
}

/**************************************************************************/
/**
 * @param toekn the token amongst [Anonymous|UserName_None|UserName|UserName_Basic256Sha256]
 */
static const OpcUa_UserTokenPolicy* toUserToken(const std::string& token)
{
    DEBUG("Converting value '%s' to user token Id" ,token.c_str());
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

    ERROR("Invalid user token policy '%s'" , token.c_str());
    throw exception();
}

/**************************************************************************/
/** \brief reads a value from configuration, or raise an error if not found*/
static std::string
extractString(const ConfigCategory& config, const std::string& name)
{
    ASSERT(config.itemExists(name),"Missing config parameter:'%s'" ,name.c_str());

    DEBUG("Reading config parameter:'%s'" ,name.c_str());
    return config.getValue(name);
}


typedef void (*processConfigArrayCb)(const std::string&);
/**************************************************************************/
/**
 * \brief convert a string containing a JSON-like array of string into a StringVect_t object
 * \param value A JSON-like string (e.g. <{"policies" : [ "A", "B", "C" ] }>
 * \param section The name of the section to read (e.g. "policies")
 * \param string A suffix to append to each element
 * \param prefix A prefix to prepend to each element
 * \return a vector of string (e.g. {string("A"), string("B"), string("C")} )
 */
static StringVect_t extractStrArray(const std::string& value, const char* section,
        const std::string & prefix="", const std::string& suffix="")
{
    SOPC_ASSERT(NULL != section);
    StringVect_t result;

    rapidjson::Document doc;
    doc.Parse(value.c_str());
    if (doc.HasParseError() || (!doc.HasMember(section) && doc[section].IsArray()))
    {
        ERROR("Invalid section configuration :%s", section);
        SOPC_ASSERT(false);
    }

    const rapidjson::Value& subs = doc[section];
    for (rapidjson::SizeType i = 0; i < subs.Size(); i++)
    {
        const std::string value (prefix + subs[i].GetString() + suffix);
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

    DEBUG("extractUsersPasswords(%s)", config.c_str()); //TOO remove

    Document doc;
    doc.Parse(config.c_str());
    ASSERT(not doc.HasParseError(),
            "Invalid users configuration :%s", config.c_str());

    DEBUG("extractUsersPasswords - 2"); //TOO remove

    for (it = doc.MemberBegin() ; it != doc.MemberEnd(); it++)
    {
        const char* user = it->name.GetString();
        const char* pass = it->value.GetString();
        result.push_back(std::make_pair(user, pass));
    }

    return result;
}


/**************************************************************************/
static SOPC_tools::CStringVect extractCStrArray(const std::string& value, const char* section,
        const std::string & prefix="", const std::string& suffix="")
{
    return SOPC_tools::CStringVect(extractStrArray(value, section, prefix, suffix));
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
    vect(new char*[size + 1]),
    cVect((const char**)(vect))
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
    serverCertPath(::certDirServer + extractString(configData, "serverCertPath")),
    serverKeyPath(::certDirServer + extractString(configData, "serverKeyPath")),
    certificates(extractString(configData, "certificates")),
    trustedRootCert(extractCStrArray(certificates, "trusted_root", ::certDirTrusted)),
    trustedIntermCert(extractCStrArray(certificates, "trusted_intermediate", ::certDirTrusted)),
    untrustedRootCert(extractCStrArray(certificates, "untrusted_root", ::certDirUntrusted)),
    untrustedIntermCert(extractCStrArray(certificates, "untrusted_intermediate", ::certDir + "untrusted")),
    issuedCert(extractCStrArray(certificates, "issued", ::certDirIssued)),
    revokedCert(extractCStrArray(certificates, "revoked", ::certDirRevoked)),
    withLogs(::toUpper(extractString(configData, "logging")) != "NONE"),
    logLevel(toSOPC_Log_Level(extractString(configData, "logging"))),
    logPath(::logDir),
    policies(extractStrArray(extractString(configData, "endpoint"), "policies")),
    namespacesStr(extractString(configData, "namespaces")),
    namespacesUri(extractCStrArray(namespacesStr, "namespaces")),
    users(extractUsersPasswords(extractString(configData, "users"))),
    addrSpace(extractString(configData, "exchanged_data"))
{
    INFO("OpcUa_Server_Config() OK.");
    INFO("Conf : logPath = %s", logPath.c_str());
    DEBUG("Conf : url = %s", url.c_str());
    DEBUG("Conf : serverCertPath = %s", serverCertPath.c_str());
    DEBUG("Conf : serverKeyPath = %s", serverKeyPath.c_str());
    DEBUG("Conf : certificates = %s", certificates.c_str());
    DEBUG("Conf : logLevel = %d", logLevel);
    DEBUG("Conf : withLogs = %d", withLogs);

    ASSERT(not serverCertPath.empty(), "serverCertPath is missing");
    ASSERT(not serverKeyPath.empty(), "serverKeyPath is missing");
    ASSERT(serverDescription.length() > 0,
            "Application description cannot be empty");
    ASSERT(0 == access(serverCertPath.c_str(), R_OK),"Missing Server certificate file: %s" ,
            serverCertPath.c_str());
    ASSERT(0 == access(serverKeyPath.c_str(), R_OK),"Missing Server key file: %s" ,
            serverKeyPath.c_str());
}

/**************************************************************************/
void
OpcUa_Server_Config::
setupServerSecurity(SOPC_Endpoint_Config* ep)const
{
    for (std::string rawPolicy : policies)
    {
        DEBUG("process policy %s", rawPolicy.c_str());
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


