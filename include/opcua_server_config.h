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

extern "C" {
// S2OPC Headers
#include "s2opc/common/sopc_log_manager.h"
#include "s2opc/clientserver/sopc_user_app_itf.h"
#include "s2opc/clientserver/sopc_toolkit_config.h"
};

namespace fledge_power_s2opc_north
{

/**
 * Configuration holder for a S2OPC server
 */
class OpcUa_Server_Config
{
public:
    OpcUa_Server_Config(const ConfigCategory& configData);
    virtual ~OpcUa_Server_Config(void);
private:
    std::string extractString(const ConfigCategory& config, const std::string& name)const;
    std::string extractCertificate(const ConfigCategory& config, const std::string& name, const std::string& extenstion)const;
    bool extractStringEquals(const ConfigCategory& config, const std::string& name, const std::string& compare)const;
public:
    SOPC_S2OPC_Config* extractOpcConfig(const ConfigCategory& config)const;

    typedef std::vector<std::string> StringVect;
    const std::string url;
    const std::string appUri;
    const std::string productUri;
    const std::string serverDescription;
    const std::string serverCertPath;
    const std::string serverKeyPath;
    const std::string caCertPath;
    const std::string caCrlPath;
    const bool withLogs;
    const SOPC_Log_Level logLevel;
    const std::string logPath;
    const StringVect policies;
};


}

#endif
