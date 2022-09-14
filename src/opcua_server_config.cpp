/*
 * Fledge north service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Jeremie Chabod
 */

#include "opcua_server_config.h"

// System headers
#include <unistd.h>
#include <algorithm>
#include <string>
#include <map>
#include <exception>

// FLEDGE headers
#include "logger.h"
#include "rapidjson/document.h"

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

using SOPC_tools::getArray;
using SOPC_tools::getString;
using SOPC_tools::getObject;
using SOPC_tools::checkObject;
using SOPC_tools::StringVect_t;
using SOPC_tools::StringMap_t;
using SOPC_tools::loggableString;
namespace {

// Plugin data storage
static const std::string dataDir(getDataDir());
// logs folder
static const std::string logDir(dataDir + "/logs/");
// Certificate folder
static const std::string certDir(dataDir + "/etc/certs/s2opc_srv/");
static const std::string certDirServer(::certDir + "server/");
static const std::string certDirTrusted(::certDir + "trusted/");
static const std::string certDirUntrusted(::certDir + "untrusted/");
static const std::string certDirIssued(::certDir + "issued/");
static const std::string certDirRevoked(::certDir + "revoked/");

/**************************************************************************/
/** \brief return an uppercase version of str */
static std::string toUpperString(const std::string & str) {
    std::string copy(str);
    for (char& c : copy) {
        c = ::toupper(c);
    }
    return copy;
}

/**************************************************************************/
static SOPC_Log_Level toSOPC_Log_Level(const std::string & str) {
    const std::string sUpper(::toUpperString(str));
    typedef std::pair<std::string, SOPC_Log_Level> Pair;
    typedef std::map<std::string, SOPC_Log_Level> LevelMap;
    // Note:  static_cast is only used to help editor parser.
    static const LevelMap map {
        {"DEBUG", static_cast<SOPC_Log_Level>(SOPC_LOG_LEVEL_DEBUG)},
        {"INFO", static_cast<SOPC_Log_Level>(SOPC_LOG_LEVEL_INFO)},
        {"WARNING", static_cast<SOPC_Log_Level>(SOPC_LOG_LEVEL_WARNING)},
        {"ERROR", static_cast<SOPC_Log_Level>(SOPC_LOG_LEVEL_ERROR)}
    };
    LevelMap::const_iterator it(map.find(sUpper));

    if (it != map.end()) {
        return (*it).second;
    }
    // Default value
    return SOPC_LOG_LEVEL_INFO;
}

/**************************************************************************/
static SOPC_SecurityPolicy_URI toSecurityPolicy(const std::string& policy) {
    typedef std::pair<std::string, SOPC_SecurityPolicy_URI> Pair;
    typedef std::map<std::string, SOPC_SecurityPolicy_URI> PolicyMap;
    static const PolicyMap map {
        {"None", SOPC_SecurityPolicy_None},
        {"Basic256", SOPC_SecurityPolicy_Basic256},
        {"Basic256Sha256", SOPC_SecurityPolicy_Basic256Sha256},
        {"Aes128Sha256RsaOaep", SOPC_SecurityPolicy_Aes128Sha256RsaOaep},
        {"Aes128Sha256RsaPss", SOPC_SecurityPolicy_Aes256Sha256RsaPss}
    };
    DEBUG("Converting value '%s' to security policy", LOGGABLE(policy));
    PolicyMap::const_iterator it(map.find(policy));

    if (it != map.end()) {
        return (*it).second;
    }
    ERROR("Invalid security policy '%s'" , policy.c_str());
    throw exception();
}

/**************************************************************************/
static SOPC_SecurityModeMask toSecurityMode(const std::string& mode) {
    const std::string sUpper(::toUpperString(mode));
    typedef std::pair<std::string, SOPC_SecurityModeMask> Pair;
    typedef std::map<std::string, SOPC_SecurityModeMask> ModeMap;
    static const ModeMap map {
        {"NONE", SOPC_SecurityModeMask_None},
        {"SIGN", SOPC_SecurityModeMask_Sign},
        {"SIGNANDENCRYPT", SOPC_SecurityModeMask_SignAndEncrypt}
    };
    DEBUG("Converting value '%s' to security mode", LOGGABLE(mode));
    ModeMap::const_iterator it(map.find(sUpper));

    if (it != map.end()) {
        return (*it).second;
    }

    ERROR("Invalid security mode: '%s'" , LOGGABLE(mode));
    throw exception();
}

/**************************************************************************/
/**
 * @param token the token amongst [Anonymous|UserName_None|UserName|UserName_Basic256Sha256]
 */
static const OpcUa_UserTokenPolicy* toUserToken(const std::string& token) {
    DEBUG("Converting value '%s' to user token Id", LOGGABLE(token));
    if (token == SOPC_UserTokenPolicy_Anonymous_ID) {
        return &SOPC_UserTokenPolicy_Anonymous;
    }
    if (token == SOPC_UserTokenPolicy_UserNameNone_ID) {
        return &SOPC_UserTokenPolicy_UserName_NoneSecurityPolicy;
    }
    if (token == SOPC_UserTokenPolicy_UserName_ID) {
        return &SOPC_UserTokenPolicy_UserName_DefaultSecurityPolicy;
    }
    if (token == SOPC_UserTokenPolicy_UserNameBasic256Sha256_ID) {
        return &SOPC_UserTokenPolicy_UserName_Basic256Sha256SecurityPolicy;
    }
    return NULL;
}

/**************************************************************************/
/** \brief reads a value from configuration, or raise an error if not found*/
static std::string
extractString(const ConfigCategory& config, const std::string& name) {
    ASSERT(config.itemExists(name), "Missing config parameter:'%s'", LOGGABLE(name));

    DEBUG("Reading config parameter:'%s'", LOGGABLE(name));
    return config.getValue(name);
}

/**************************************************************************/
static SOPC_tools::CStringVect extractCStrArray(
        const rapidjson::Value& value, const char* section,
        const std::string & prefix = "", const std::string& suffix = "") {
    using rapidjson::Value;
    StringVect_t result;
    ASSERT(value.HasMember(section), "Missing section '%s' for ARRAY", LOGGABLE(section));
    const Value& array(value[section]);
    ASSERT(array.IsArray(), "Section '%s' must be an ARRAY", LOGGABLE(section));

    for (const rapidjson::Value& subV : array.GetArray()) {
        ASSERT(subV.IsString(), "Section '%s' must be an ARRAY of STRINGS", LOGGABLE(section));
        const std::string str(prefix + subV.GetString() + suffix);
        result.push_back(str);
    }
    return SOPC_tools::CStringVect(result);
}

/**************************************************************************/
static StringMap_t extractUsersPasswords(const rapidjson::Value& config) {
    using rapidjson::Document;
    using rapidjson::Value;
    StringMap_t result;
    Value::ConstMemberIterator it;

    ASSERT(config.IsObject(),
            "Invalid users configuration.");

    for (it = config.MemberBegin() ; it != config.MemberEnd(); it++) {
        const char* user = it->name.GetString();
        const char* pass = it->value.GetString();
        result.push_back(std::make_pair(user, pass));
    }

    return result;
}
}   // namespace


/**************************************************************************/
/**************************************************************************/
namespace SOPC_tools {

/**************************************************************************/
const std::string loggableString(const std::string& log) {
    // Using a static variable allows to return a reference to content, but this will be
    // overwritten by any further call.
    string str(log);
    // Remmove chars from 0 ..31 and 128..255 (As char is signed, this is simplified in < ' ')
    str.erase(std::remove_if(str.begin(), str.end(), [](const char& c) {return c < ' ';}), str.end());
    return str;
}

/**************************************************************************/
CStringVect::
CStringVect(const StringVect_t& ref):
size(ref.size()),
vect(new char*[size + 1]),
cVect((const char**)(vect)) {
    for (size_t i=0 ; i < size; i++) {
        cppVect.push_back(ref[i]);
        vect[i] = strdup(cppVect.back().c_str());
    }
    vect[size] = NULL;
}

/**************************************************************************/
CStringVect::
CStringVect(const rapidjson::Value& ref, const std::string& context):
size(ref.GetArray().Size()),
vect(new char*[size + 1]),
cVect((const char**)(vect)) {
    size_t i(0);
    for (const rapidjson::Value& value : ref.GetArray()) {
        ASSERT(value.IsString(), "Expecting a String in array '%s'", LOGGABLE(context));
        cppVect.push_back(value.GetString());
        vect[i] = strdup(cppVect.back().c_str());
        i++;
    }
    vect[size] = NULL;
}

/**************************************************************************/
CStringVect::
~CStringVect(void) {
    for (size_t i =0 ; i < size ; i++) {
        delete vect[i];
    }
    delete vect;
}
}   // namespace SOPC_tools

/**************************************************************************/
namespace s2opc_north {
using SOPC_tools::statusCodeToCString;

// Important note: OPC stack is not initialized yet while parsing configuration,
// thus it is not possible to use S2OPC logging at this point.


ExchangedDataC::
ExchangedDataC(const rapidjson::Value& json):
mPreCheck(internalChecks(json)),
address(json[JSON_PROT_ADDR].GetString()),
typeId(json[JSON_PROT_TYPEID].GetString()) {
}

ExchangedDataC::
~ExchangedDataC(void) {
}

bool
ExchangedDataC::internalChecks(const rapidjson::Value& json) {
    ASSERT(json.IsObject(), "datapoint protocol description must be JSON");
    ASSERT(json.HasMember(JSON_PROT_NAME) || json[JSON_PROT_NAME].IsString()
            , "datapoint protocol description must have a 'name' key defining a STRING");
    const std::string protocolName(json[JSON_PROT_NAME].GetString());
    if (protocolName != PROTOCOL_S2OPC) {
        throw NotAnS2opcInstance();
    }
    ASSERT(json.HasMember(JSON_PROT_ADDR) || json[JSON_PROT_ADDR].IsString()
            , "datapoint protocol description must have a '" JSON_PROT_ADDR "' key defining a STRING");
    ASSERT(json.HasMember(JSON_PROT_TYPEID) || json[JSON_PROT_TYPEID].IsString()
            , "datapoint protocol description must have a '" JSON_PROT_TYPEID "' key defining a STRING");
    return true;
}


/**************************************************************************/
OpcUa_Protocol::
OpcUa_Protocol(const std::string& protocol):
mDoc(initDoc(protocol)),
mProtocol(mDoc["protocol_stack"]),
mTransport(mProtocol["transport_layer"]),
url(mTransport["url"].GetString()),
appUri(mTransport["appUri"].GetString()),
productUri(mTransport["productUri"].GetString()),
localeId(mTransport["localeId"].GetString()),
serverDescription(mTransport["appDescription"].GetString()),
certificates(mTransport["certificates"]),
serverCertPath(::certDirServer + certificates["serverCertPath"].GetString()),
serverKeyPath(::certDirServer + certificates["serverKeyPath"].GetString()),
trustedRootCert(extractCStrArray(certificates, "trusted_root", ::certDirTrusted)),
trustedIntermCert(extractCStrArray(certificates, "trusted_intermediate", ::certDirTrusted)),
untrustedRootCert(extractCStrArray(certificates, "untrusted_root", ::certDirUntrusted)),
untrustedIntermCert(extractCStrArray(certificates, "untrusted_intermediate", ::certDir + "untrusted")),
issuedCert(extractCStrArray(certificates, "issued", ::certDirIssued)),
revokedCert(extractCStrArray(certificates, "revoked", ::certDirRevoked)),
policies(PoliciesVect(mTransport)),
namespacesUri(SOPC_tools::CStringVect(mTransport["namespaces"], "namespaces")),
users(extractUsersPasswords(mTransport["users"])) {
    DEBUG("Conf : url = %s", url.c_str());
    DEBUG("Conf : appUri = %s", appUri.c_str());
    DEBUG("Conf : productUri = %s", productUri.c_str());
    DEBUG("Conf : serverDescription = %s", serverDescription.c_str());
    DEBUG("Conf : serverCertPath = %s", serverCertPath.c_str());
    DEBUG("Conf : serverKeyPath = %s", serverKeyPath.c_str());
    ASSERT(!serverCertPath.empty(), "serverCertPath is missing");
    ASSERT(!serverKeyPath.empty(), "serverKeyPath is missing");
    ASSERT(appUri.length() > 0, "Application URI cannot be empty");
    ASSERT(productUri.length() > 0, "Product URI cannot be empty");
    ASSERT(serverDescription.length() > 0, "Application description cannot be empty");
    ASSERT(0 == access(serverCertPath.c_str(), R_OK), "Missing Server certificate file: %s" ,
            serverCertPath.c_str());
    ASSERT(0 == access(serverKeyPath.c_str(), R_OK), "Missing Server key file: %s" ,
            serverKeyPath.c_str());
}

/**************************************************************************/
OpcUa_Protocol::
~OpcUa_Protocol(void) {
}

/**************************************************************************/
rapidjson::Document
OpcUa_Protocol::
initDoc(const std::string& json)const {
    rapidjson::Document doc;
    doc.Parse(json.c_str());
    ASSERT(!doc.HasParseError(), "Malformed JSON (section '%s', offset= %u) :%s",
            JSON_PROTOCOLS, doc.GetErrorOffset(), LOGGABLE(json));

    ASSERT(doc.HasMember("protocol_stack") && doc["protocol_stack"].IsObject(),
            "Invalid section 'protocol_stack'");

    const rapidjson::Value& protocol(doc["protocol_stack"]);

    ASSERT(protocol.HasMember("transport_layer") && protocol["transport_layer"].IsObject(),
            "Invalid section 'protocol_stack':'transport_layer'");
    return doc;
}

/**************************************************************************/
OpcUa_Protocol::PolicyS::
PolicyS(const std::string& modeStr, const std::string& policyStr,
        const rapidjson::Value::ConstArray& userPolicies):
name(modeStr + "/" + policyStr) {
    using rapidjson::Value;

    mode = (::toSecurityMode(modeStr));
    policy = (::toSecurityPolicy(policyStr));
    for (const Value& policy : userPolicies) {
        const string userPolicyStr(getString(policy, "userPolicies"));
        DEBUG("Identify user token policy: '%s'", LOGGABLE(userPolicyStr));
        const SOPC_UserTokenPolicy* userPolicy(::toUserToken(userPolicyStr));
        ASSERT(NULL != userPolicy,
                "Unknown/invalid user policy : '%s'", LOGGABLE(userPolicyStr));
        userTokens.push_back(userPolicy);
    }
}

/**************************************************************************/
OpcUa_Protocol::PoliciesVect::
PoliciesVect(const rapidjson::Value& transport) {
    using rapidjson::Value;
    const Value::ConstArray& policies(getArray(transport, "policies", "transport_layer"));
    for (const Value& policy : policies) {
        checkObject(policy, "'policies' elements");
        const string secuPolicyStr(getString(policy, "securityPolicy", "policies"));
        const string secuModeStr(getString(policy, "securityMode", "policies"));
        const rapidjson::Value::ConstArray userPolicies(getArray(policy, "userPolicies", "policies"));

        this->push_back(PolicyS(secuModeStr, secuPolicyStr, userPolicies));
    }
    ASSERT(false, "OK!");
}

/**************************************************************************/
void
OpcUa_Protocol::
setupServerSecurity(SOPC_Endpoint_Config* ep)const {
    for (const PolicyS& policy : policies) {
        DEBUG("process policy %s", LOGGABLE(policy.name));
        SOPC_SecurityPolicy* sp = SOPC_EndpointConfig_AddSecurityConfig(ep, policy.policy);
        SOPC_ASSERT(sp != NULL);

        SOPC_ReturnStatus status = SOPC_SecurityConfig_SetSecurityModes(sp, policy.mode);
        ASSERT(status == SOPC_STATUS_OK,
                "SOPC_SecurityConfig_SetSecurityModes failed");

        for (const SOPC_UserTokenPolicy* userToken : policy.userTokens) {
            status = SOPC_SecurityConfig_AddUserTokenPolicy(sp, userToken);
            ASSERT(status == SOPC_STATUS_OK,
                    "SOPC_SecurityConfig_AddUserTokenPolicy returned code %s(%d)",
                    statusCodeToCString(status), status);
        }
    }
}

/**************************************************************************/
OpcUa_Server_Config::
OpcUa_Server_Config(const ConfigCategory& configData):
        withLogs(::toUpperString(extractString(configData, "logging")) != "NONE"),
        logLevel(toSOPC_Log_Level(extractString(configData, "logging"))),
        logPath(::logDir),
        addrSpace(extractString(configData, "exchanged_data")) {
    INFO("OpcUa_Server_Config() OK.");
    INFO("Conf : logPath = %s", logPath.c_str());
    DEBUG("Conf : logLevel = %d", logLevel);
    DEBUG("Conf : withLogs = %d", withLogs);
}

/**************************************************************************/
OpcUa_Server_Config::
~OpcUa_Server_Config(void) {
}

}   // namespace s2opc_north


