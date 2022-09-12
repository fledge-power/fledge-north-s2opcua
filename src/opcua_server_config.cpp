/*
 * Fledge north service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Jeremie Chabod
 */

#define USE_TLS 0   // TODO(JCH) remove that!

#include "opcua_server_config.h"

// System headers
#include <unistd.h>
#include <algorithm>
#include <string>
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

namespace {
using SOPC_tools::StringVect_t;
using SOPC_tools::StringMap_t;

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
static std::string toUpper(const std::string & str) {
    std::string copy(str);
    std::transform(copy.begin(), copy.end(), copy.begin(), ::toupper);
    return copy;
}

/**************************************************************************/
/** \brief split a string.
 * \param src [inout] As input contains the string to split.
 *  As output, contains the remaining after the separator (or empty)
 * \param separator The string separator
 **/
static std::string splitString(std::string* src, const char separator = '/') {
    std::string result;
    size_t pos(src->find_first_of(separator));

    if (pos == string::npos) {
        result = *src;
        src->clear();
    } else {
        if (pos == 0) {
            result = "";
        } else {
            result = src->substr(0, pos);
        }
        src->erase(0, pos + 1);
    }
    return result;
}

/**************************************************************************/
static SOPC_Log_Level toSOPC_Log_Level(const std::string & str) {
    const std::string sUpper(::toUpper(str));
    if (sUpper == "DEBUG") {
        return SOPC_LOG_LEVEL_DEBUG;
    }
    if (sUpper == "INFO") {
        return SOPC_LOG_LEVEL_INFO;
    }
    if (sUpper == "WARNING") {
        return SOPC_LOG_LEVEL_WARNING;
    }
    if (sUpper == "ERROR") {
        return SOPC_LOG_LEVEL_ERROR;
    }
    // Default value
    return SOPC_LOG_LEVEL_INFO;
}

/**************************************************************************/
static SOPC_SecurityPolicy_URI toSecurityPolicy(const std::string& policy) {
    DEBUG("Converting value '%s' to security policy", policy.c_str());
    if (policy == "None") {
        return SOPC_SecurityPolicy_None;
    }
    if (policy == "Basic256") {
        return SOPC_SecurityPolicy_Basic256;
    }
    if (policy == "Basic256Sha256") {
        return SOPC_SecurityPolicy_Basic256Sha256;
    }
    if (policy == "Aes128Sha256RsaOaep") {
        return SOPC_SecurityPolicy_Aes128Sha256RsaOaep;
    }
    if (policy == "Aes128Sha256RsaOaep") {
        return SOPC_SecurityPolicy_Aes256Sha256RsaPss;
    }

    ERROR("Invalid security policy '%s'" , policy.c_str());
    throw exception();
}

/**************************************************************************/
static SOPC_SecurityModeMask toSecurityMode(const std::string& mode) {
    DEBUG("Converting value '%s' to security mode", mode.c_str());
    const std::string sUpper(::toUpper(mode));
    if (sUpper == "NONE") {
        return SOPC_SecurityModeMask_None;
    }
    if (sUpper == "SIGN") {
        return SOPC_SecurityModeMask_Sign;
    }
    if (sUpper == "SIGNANDENCRYPT") {
        return SOPC_SecurityModeMask_SignAndEncrypt;
    }

    ERROR("Invalid security mode '%s'" , mode.c_str());
    throw exception();
}

/**************************************************************************/
/**
 * @param token the token amongst [Anonymous|UserName_None|UserName|UserName_Basic256Sha256]
 */
static const OpcUa_UserTokenPolicy* toUserToken(const std::string& token) {
    DEBUG("Converting value '%s' to user token Id", token.c_str());
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

    ERROR("Invalid user token policy '%s'" , token.c_str());
    throw exception();
}

/**************************************************************************/
/** \brief reads a value from configuration, or raise an error if not found*/
static std::string
extractString(const ConfigCategory& config, const std::string& name) {
    ASSERT(config.itemExists(name), "Missing config parameter:'%s'", name.c_str());

    DEBUG("Reading config parameter:'%s'", name.c_str());
    return config.getValue(name);
}

/**************************************************************************/
static SOPC_tools::CStringVect extractCStrArray(
        const rapidjson::Value& value, const char* section,
        const std::string & prefix = "", const std::string& suffix = "") {
    using rapidjson::Value;
    StringVect_t result;
    ASSERT(value.HasMember(section), "Missing section '%s' for ARRAY", section);
    const Value& array(value[section]);
    ASSERT(array.IsArray(), "Section '%s' must be an ARRAY", section);

    for (const rapidjson::Value& subV : array.GetArray()) {
        ASSERT(subV.IsString(), "Section '%s' must be an ARRAY of STRINGS", section);
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
        ASSERT(value.IsString(), "Expecting a String in array '%s'", context);
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
ExchangedDataC::internalChecks(const rapidjson::Value& json)
{
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
policies(SOPC_tools::CStringVect(mTransport["policies"], "policies")),
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
            JSON_PROTOCOLS, doc.GetErrorOffset(), json.c_str());

    ASSERT(doc.HasMember("protocol_stack") && doc["protocol_stack"].IsObject(),
            "Invalid section 'protocol_stack'");

    const rapidjson::Value& protocol(doc["protocol_stack"]);

    ASSERT(protocol.HasMember("transport_layer") && protocol["transport_layer"].IsObject(),
            "Invalid section 'protocol_stack':'transport_layer'");
    return doc;
}

/**************************************************************************/
void
OpcUa_Protocol::
setupServerSecurity(SOPC_Endpoint_Config* ep)const {
    for (std::string rawPolicy : policies.cppVect) {
        DEBUG("process policy %s", rawPolicy.c_str());
        const SOPC_SecurityModeMask mode(::toSecurityMode(::splitString(&rawPolicy)));
        const SOPC_SecurityPolicy_URI policy(::toSecurityPolicy(::splitString(&rawPolicy)));
        SOPC_SecurityPolicy* sp = SOPC_EndpointConfig_AddSecurityConfig(ep, policy);
        SOPC_ASSERT(sp != NULL);

        SOPC_ReturnStatus status = SOPC_SecurityConfig_SetSecurityModes(sp, mode);
        ASSERT(status == SOPC_STATUS_OK,
                "SOPC_SecurityConfig_SetSecurityModes failed");

        bool valid = true;

        do {
            const std::string token(::splitString(&rawPolicy, '+'));
            const SOPC_UserTokenPolicy* userPolicy(::toUserToken(token));
            status = SOPC_SecurityConfig_AddUserTokenPolicy(sp, userPolicy);
            ASSERT(status == SOPC_STATUS_OK,
                    "SOPC_SecurityConfig_AddUserTokenPolicy returned code %s(%d)",
                    statusCodeToCString(status), status);
        } while (!rawPolicy.empty());
    }
}

/**************************************************************************/
OpcUa_Server_Config::
OpcUa_Server_Config(const ConfigCategory& configData):
        withLogs(::toUpper(extractString(configData, "logging")) != "NONE"),
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


