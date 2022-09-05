#ifndef _OPCUA_SERVER_CONFIG_H
#define _OPCUA_SERVER_CONFIG_H
/*
 * Fledge north service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Jeremie Chabod
 */
#include <config_category.h>
#include <string>
#include <logger.h>
#include <utils.h>
#include <stdint.h>
#include <stdlib.h>
#include <vector>

extern "C" {
// S2OPC Headers
#include "s2opc/common/sopc_log_manager.h"
#include "s2opc/clientserver/sopc_user_app_itf.h"
#include "s2opc/clientserver/sopc_toolkit_config.h"
};

#define ASSERT(c,  ...) do \
{\
    if(!(c))\
    {\
        Logger::getLogger()->fatal ("ASSERT FAILED:" __VA_ARGS__);\
        SOPC_ASSERT(false);\
    }\
} while(0)


namespace SOPC_tools
{

extern const char* statusCodeToCString(const int status);

typedef std::vector<std::string> StringVect_t;
struct CStringVect
{
    CStringVect(const StringVect_t& ref);
    virtual ~ CStringVect(void);
    void checkAllFilesExist(void)const;
    size_t size;
    char** vect;
};

typedef std::pair<std::string, std::string> StringPair_t;
typedef std::vector<StringPair_t> StringMap_t;

}

namespace s2opc_north
{
using namespace SOPC_tools;

/**
 * Configuration holder for a S2OPC server
 */
class OpcUa_Server_Config
{
public:
    OpcUa_Server_Config(const ConfigCategory& configData);
    virtual ~OpcUa_Server_Config(void);
private:
    std::string extractCertificate(const ConfigCategory& config, const std::string& name)const;
    bool extractStringEquals(const ConfigCategory& config, const std::string& name, const std::string& compare)const;
public:
    void setupServerSecurity(SOPC_Endpoint_Config* ep)const;
    SOPC_S2OPC_Config* extractOpcConfig(const ConfigCategory& config)const;

    const std::string url;
    const std::string appUri;
    const std::string productUri;
    const std::string localeId;
    const std::string serverDescription;
    const std::string serverCertPath;
    const std::string serverKeyPath;
    const std::string certificates;
    SOPC_tools::CStringVect trustedRootCert;
    SOPC_tools::CStringVect trustedIntermCert;
    SOPC_tools::CStringVect untrustedRootCert;
    SOPC_tools::CStringVect untrustedIntermCert;
    SOPC_tools::CStringVect revokedCert;
    SOPC_tools::CStringVect issuedCert;
    const bool withLogs;
    const SOPC_Log_Level logLevel;
    const std::string logPath;
    const SOPC_tools::StringVect_t policies;
    const std::string namespacesStr;
    const SOPC_tools::CStringVect namespacesUri;
    const StringMap_t users;
};


}

#endif
