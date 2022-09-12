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
#include "s2opc/common/sopc_log_manager.h"
#include "s2opc/clientserver/sopc_user_app_itf.h"
#include "s2opc/clientserver/sopc_toolkit_config.h"
};

/// Project includes
#include "opcua_server_addrspace.h"


#define JSON_EXCHANGED_DATA "exchanged_data"
#define JSON_DATAPOINTS "datapoints"
#define JSON_PROTOCOLS "protocols"
#define JSON_LABEL "label"
#define JSON_PIVOT_ID "pivot_id"
#define JSON_PIVOT_TYPE "pivot_type"

#define PROTOCOL_S2OPC "opcua"
#define JSON_PROT_NAME "name"
#define JSON_PROT_ADDR "address"
#define JSON_PROT_TYPEID "typeid"


namespace SOPC_tools {

/**
 * @param status a S2OPC status code
 * @return a human-readable representation of a status code
 */
extern const char* statusCodeToCString(const int status);

/** Vector of string */
typedef std::vector<std::string> StringVect_t;

/**
 * CStringVect intends at making a String vector useable by C S2OPC layer.
 * @field vect Contains a C-representation of the array, including a
 *  NULL terminating string
 * @field size The number of non-NULL elements in vect
 */
struct CStringVect {
    /**
     * Build a C vector using  C+ STL vector
     */
    explicit CStringVect(const StringVect_t& ref);
    explicit CStringVect(const rapidjson::Value& ref, const std::string& context);
    /** Frees vect */
    virtual ~CStringVect(void);
    /**
     * \brief Checks (using ASSERT) that all elements in vector are R-O accessible files
     */
    void checkAllFilesExist(void)const;
    size_t size;
    char** vect;
    const char** cVect;
    StringVect_t cppVect;
};

typedef std::pair<std::string, std::string> StringPair_t;
typedef std::vector<StringPair_t> StringMap_t;

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
          "gi_groups":"station|1|2"   // TODO Ignored ?
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
   const SOPC_tools::CStringVect policies;
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
