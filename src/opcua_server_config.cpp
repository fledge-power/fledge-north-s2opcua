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
#include "sopc_atomic.h"
#include "sopc_common.h"
#include "sopc_encodeabletype.h"
#include "sopc_log_manager.h"
#include "sopc_builtintypes.h"
#include "sopc_types.h"
#include "sopc_crypto_decl.h"
#include "sopc_crypto_profiles.h"
#include "sopc_key_manager.h"
#include "sopc_mem_alloc.h"
#include "sopc_pki_stack.h"
// From S2OPC "clientserver/frontend"
#include "libs2opc_server.h"
#include "libs2opc_server_config.h"
#include "libs2opc_server_config_custom.h"
// From S2OPC "clientserver"
#include "sopc_toolkit_config.h"
#include "sopc_user_manager.h"
#include "sopc_user_app_itf.h"
}

using std::exception;
using SOPC_tools::getArray;
using SOPC_tools::getString;
using SOPC_tools::getObject;
using SOPC_tools::checkObject;
using SOPC_tools::StringVect_t;
using SOPC_tools::StringMap_t;
using SOPC_tools::toUpperString;
using SOPC_tools::loggableString;
namespace {

// Plugin data storage
const std::string dataDir(getDataDir());
// logs folder
const std::string logDir(dataDir + "/logs/");
// Certificate folder
const std::string certDir(dataDir + "/etc/certs/s2opc_srv/");
const std::string certDirServer(::certDir + "server/");
const std::string certDirTrusted(::certDir + "trusted/");
const std::string certDirUntrusted(::certDir + "untrusted/");
const std::string certDirIssued(::certDir + "issued/");
const std::string certDirRevoked(::certDir + "revoked/");


/**************************************************************************/
/** \brief reads a value from configuration, or raise an error if not found*/
std::string
extractString(const ConfigCategory& config, const std::string& name) {
    ASSERT(config.itemExists(name), "Missing config parameter:'%s'", LOGGABLE(name));

    DEBUG("Reading config parameter:'%s'", LOGGABLE(name));
    return config.getValue(name);
}

/**************************************************************************/
SOPC_tools::CStringVect extractCStrArray(
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
StringMap_t extractUsersPasswords(const rapidjson::Value& config) {
    using rapidjson::Document;
    using rapidjson::Value;
    StringMap_t result;
    ASSERT(config.IsObject(),
            "Invalid users configuration.");

    for (Value::ConstMemberIterator  it = config.MemberBegin() ; it != config.MemberEnd(); it++) {
        const char* user = it->name.GetString();
        const char* pass = it->value.GetString();
        result.emplace_back(SOPC_tools::StringPair_t{user, pass});
    }

    return result;
}
}   // namespace


/**************************************************************************/
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

bool
ExchangedDataC::internalChecks(const rapidjson::Value& json)const {
    ASSERT(json.IsObject(), "datapoint protocol description must be JSON");
    ASSERT(json.HasMember(JSON_PROT_NAME) && json[JSON_PROT_NAME].IsString()
            , "datapoint protocol description must have a 'name' key defining a STRING");
    const std::string protocolName(json[JSON_PROT_NAME].GetString());
    if (protocolName != PROTOCOL_S2OPC) {
        throw NotAnS2opcInstance();
    }
    ASSERT(json.HasMember(JSON_PROT_ADDR) && json[JSON_PROT_ADDR].IsString()
            , "datapoint protocol description must have a '%s' key defining a STRING",
            JSON_PROT_ADDR);
    ASSERT(json.HasMember(JSON_PROT_TYPEID) && json[JSON_PROT_TYPEID].IsString()
            , "datapoint protocol description must have a '%s' key defining a STRING",
            JSON_PROT_TYPEID);
    return true;
}


/**************************************************************************/
OpcUa_Protocol::
OpcUa_Protocol(const std::string& protocol):
mDoc(initDoc(protocol)),
mProtocol(mDoc["protocol_stack"]),
mTransport(mProtocol["transport_layer"]),
url(getString(mTransport, "url", "transport_layer")),
appUri(getString(mTransport, "appUri", "transport_layer")),
productUri(getString(mTransport, "productUri", "transport_layer")),
localeId(getString(mTransport, "localeId", "transport_layer")),
serverDescription(getString(mTransport, "appDescription", "transport_layer")),
certificates(mTransport["certificates"]),
serverCertPath(::certDirServer + getString(certificates, "serverCertPath", "certificates")),
serverKeyPath(::certDirServer + getString(certificates, "serverKeyPath", "certificates")),
trustedRootCert(extractCStrArray(certificates, "trusted_root", ::certDirTrusted)),
trustedIntermCert(extractCStrArray(certificates, "trusted_intermediate", ::certDirTrusted)),
untrustedRootCert(extractCStrArray(certificates, "untrusted_root", ::certDirUntrusted)),
untrustedIntermCert(extractCStrArray(certificates, "untrusted_intermediate", ::certDir + "untrusted")),
issuedCert(extractCStrArray(certificates, "issued", ::certDirIssued)),
revokedCert(extractCStrArray(certificates, "revoked", ::certDirRevoked)),
policies(PoliciesVect(mTransport)),
namespacesUri(SOPC_tools::CStringVect(mTransport["namespaces"], "namespaces")),
users(extractUsersPasswords(mTransport["users"])) {
    DEBUG("Conf : url = %s", LOGGABLE(url));
    DEBUG("Conf : appUri = %s", LOGGABLE(appUri));
    DEBUG("Conf : productUri = %s", LOGGABLE(productUri));
    DEBUG("Conf : serverDescription = %s", LOGGABLE(serverDescription));
    DEBUG("Conf : serverCertPath = %s", LOGGABLE(serverCertPath));
    DEBUG("Conf : serverKeyPath = %s", LOGGABLE(serverKeyPath));
    ASSERT(!serverCertPath.empty(), "serverCertPath is missing");
    ASSERT(!serverKeyPath.empty(), "serverKeyPath is missing");
    ASSERT(appUri.length() > 0, "Application URI cannot be empty");
    ASSERT(productUri.length() > 0, "Product URI cannot be empty");
    ASSERT(serverDescription.length() > 0, "Application description cannot be empty");
    ASSERT(0 == access(serverCertPath.c_str(), R_OK), "Missing Server certificate file: %s" ,
            LOGGABLE(serverCertPath));
    ASSERT(0 == access(serverKeyPath.c_str(), R_OK), "Missing Server key file: %s" ,
            LOGGABLE(serverKeyPath));
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

    mode = (SOPC_tools::toSecurityMode(modeStr));
    policy = (SOPC_tools::toSecurityPolicy(policyStr));
    for (const Value& loopPolicy : userPolicies) {
        const string userPolicyStr(getString(loopPolicy, "userPolicies"));
        DEBUG("Identify user token policy: '%s'", LOGGABLE(userPolicyStr));
        const SOPC_UserTokenPolicy* userPolicy(SOPC_tools::toUserToken(userPolicyStr));
        ASSERT(nullptr != userPolicy,
                "Unknown/invalid user policy : '%s'", LOGGABLE(userPolicyStr));
        userTokens.push_back(userPolicy);
    }
}

/**************************************************************************/
OpcUa_Protocol::PolicyS::
PolicyS(PolicyS && ref):
name(std::move(ref.name)),
mode(ref.mode),
policy(ref.policy),
userTokens(std::move(ref.userTokens)) {}

/**************************************************************************/
OpcUa_Protocol::PoliciesVect::
PoliciesVect(const rapidjson::Value& transport) {
    using rapidjson::Value;
    const Value::ConstArray& policies(getArray(transport, "policies", "transport_layer"));
    for (const Value& loopPolicy : policies) {
        checkObject(loopPolicy, "'policies' elements");
        const string secuPolicyStr(getString(loopPolicy, "securityPolicy", "policies"));
        const string secuModeStr(getString(loopPolicy, "securityMode", "policies"));
        const rapidjson::Value::ConstArray userPolicies(getArray(loopPolicy, "userPolicies", "policies"));

        this->emplace_back(secuModeStr, secuPolicyStr, userPolicies);
    }
}

/**************************************************************************/
void
OpcUa_Protocol::
setupServerSecurity(SOPC_Endpoint_Config* ep)const {
    for (const PolicyS& loopPolicy : policies) {
        DEBUG("process policy %s", LOGGABLE(loopPolicy.name));
        SOPC_SecurityPolicy* sp = SOPC_EndpointConfig_AddSecurityConfig(ep, loopPolicy.policy);
        ASSERT(sp != nullptr);

        SOPC_ReturnStatus status = SOPC_SecurityConfig_SetSecurityModes(sp, loopPolicy.mode);
        ASSERT(status == SOPC_STATUS_OK,
                "SOPC_SecurityConfig_SetSecurityModes failed");

        for (const SOPC_UserTokenPolicy* userToken : loopPolicy.userTokens) {
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
        withLogs(SOPC_tools::toUpperString(extractString(configData, "logging")) != "NONE"),
        logLevel(SOPC_tools::toSOPC_Log_Level(extractString(configData, "logging"))),
        logPath(::logDir),    // //NOSONAR logDir is not visible in .h level
        addrSpace(extractString(configData, "exchanged_data")) {
    INFO("OpcUa_Server_Config() OK.");
    INFO("Conf : logPath = %s", LOGGABLE(logPath));
    DEBUG("Conf : logLevel = %d", logLevel);
    DEBUG("Conf : withLogs = %d", withLogs);
}

}   // namespace s2opc_north


