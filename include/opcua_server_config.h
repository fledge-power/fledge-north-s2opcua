#ifndef  INCLUDE_OPCUA_SERVER_CONFIG_H_
#define  INCLUDE_OPCUA_SERVER_CONFIG_H_
/*
 * Fledge north service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Jeremie Chabod
 */

// System includes
#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <utility>
#include <string>

// Fledge includes
#include "config_category.h"
#include "logger.h"
#include "utils.h"
#include "rapidjson/document.h"

extern "C" {
// S2OPC Headers
#include "sopc_log_manager.h"
// From S2OPC "clientserver"
#include "sopc_user_app_itf.h"
#include "sopc_toolkit_config.h"
// From S2OPC "clientserver/frontend"
#include "libs2opc_server_config.h"
#include "libs2opc_server_config_custom.h"
};

/// Project includes
#include "opcua_server_tools.h"
#include "opcua_server_addrspace.h"


namespace SOPC_tools {

}   // namespace SOPC_tools

namespace s2opc_north {

/**************************************************************************/
/**
 * This class parses the configuration of a single OPC UA variable (as Datapoint)
 */
class ExchangedDataC {
 public:
    class NotAnS2opcInstance : public std::exception{};
    /** Expected format:
      {
          "name":"s2opcua",
          "address":"<nodeid>",
          "typeid":"<Boolean|SByte|...>",  // See SOPC_BuiltinId
       }
     */
    explicit ExchangedDataC(const rapidjson::Value& json);
    virtual ~ExchangedDataC(void);

 private:
    const bool mPreCheck;
    bool internalChecks(const rapidjson::Value& json);

 public:
    const std::string address;
    const std::string typeId;
};  // class ExchangedDataC


/**
 * Configuration of the OPCUA protocol
 */
class OpcUa_Protocol {
 public:
    explicit OpcUa_Protocol(const std::string& protocol);
    virtual ~OpcUa_Protocol(void);
    /**
     * \brief  set up a \a SOPC_Endpoint_Config object with the  current configuration
     * \param ep The object to initialize
     */
    void setupServerSecurity(SOPC_Endpoint_Config* ep)const;

    struct PolicyS {
        explicit PolicyS(const std::string& modeStr,
                const std::string& policyStr,
                const rapidjson::Value::ConstArray& userPolicies);
        const std::string name;
        SOPC_SecurityModeMask mode;
        SOPC_SecurityPolicy_URI policy;
        std::vector<const SOPC_UserTokenPolicy*> userTokens;
    };
    struct PoliciesVect : public std::vector<PolicyS> {
        explicit PoliciesVect(const rapidjson::Value& transport);
    };

 private:
    rapidjson::Document initDoc(const std::string& json)const;

    rapidjson::Document mDoc;
    rapidjson::Value& mProtocol;
    rapidjson::Value& mTransport;

 public:
    // All fields are constants, and thus can be public.
    const std::string url;
    const std::string appUri;
    const std::string productUri;
    const std::string localeId;
    const std::string serverDescription;
    const rapidjson::Value& certificates;
    const std::string serverCertPath;
    const std::string serverKeyPath;
    const SOPC_tools::CStringVect trustedRootCert;
    const SOPC_tools::CStringVect trustedIntermCert;
    const SOPC_tools::CStringVect untrustedRootCert;
    const SOPC_tools::CStringVect untrustedIntermCert;
    const SOPC_tools::CStringVect revokedCert;
    const SOPC_tools::CStringVect issuedCert;
    const PoliciesVect policies;
    const SOPC_tools::CStringVect namespacesUri;
    const SOPC_tools::StringMap_t users;
};

/**
 * Configuration holder for a S2OPC server.
 * This class intends at interpreting all parameters provided by the configuration
 * and storing them into directly usable items.
 */
class OpcUa_Server_Config {
 public:
    explicit OpcUa_Server_Config(const ConfigCategory& configData);
    virtual ~OpcUa_Server_Config(void);

 public:
    // All fields are constants, and thus can be public.
    const bool withLogs;
    const SOPC_Log_Level logLevel;  // only relevant if withLogs is true
    const std::string logPath;
    const Server_AddrSpace addrSpace;
};

}   // namespace s2opc_north

#endif  //   INCLUDE_OPCUA_SERVER_CONFIG_H_
