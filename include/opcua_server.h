#ifndef _OPCUA_SERVER_H
#define _OPCUA_SERVER_H
/*
 * Fledge north service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Amandeep Singh Arora / Jeremie Chabod
 */
#include <config_category.h>
#include <string>
#include <reading.h>
#include <logger.h>
#include <utils.h>
#include <mutex>
#include <thread>
#include <stdint.h>
#include <stdlib.h>
#include <map>
#include <plugin_api.h>

extern "C" {
// S2OPC Headers
#include "s2opc/common/sopc_logger.h"
#include "s2opc/clientserver/sopc_user_app_itf.h"
#include "s2opc/clientserver/sopc_toolkit_config.h"
};

namespace fledge_power_s2opc_north
{

/*****************************************************
 *  CONFIGURATION
 *****************************************************/
extern const char* plugin_default_config;

/*****************************************************
 *  TYPES DEFINITIONS
 *****************************************************/
// Redefinition of plugin callbacks types to ease readability
typedef bool (*north_write_event_t)(char *name, char *value, ControlDestination destination, ...);
typedef int (*north_operation_event_t)(char *operation, int paramCount, char *parameters[], ControlDestination destination, ...);
typedef std::vector<Reading*> Readings;

class Exception:public std::exception
{
public:
    Exception(const std::string& msg);
    const std::string mMsg;
};

/**
 * Configuration holder for a S2OPC server
 */
class OpcUa_Server_Config
{
public:
    OpcUa_Server_Config(const ConfigCategory& configData);
    virtual ~OpcUa_Server_Config(void);private:
    std::string extractString(const ConfigCategory& config, const std::string& name);
    std::string mUrl;
};

/**
 * Interface to the S2 OPCUA library for a S2OPC server
 */
class OPCUA_Server
{
public:
    OPCUA_Server(const ConfigCategory& configData);
    virtual ~OPCUA_Server(void);
    uint32_t send(const Readings& readings);
    void setpointCallbacks(north_write_event_t write, north_operation_event_t operation);
private:
    static void Server_Event_Toolkit(SOPC_App_Com_Event event,
            uint32_t idOrStatus, void* param, uintptr_t appContext);
    // It is mandatory that mEnvironment is the first member
    const OpcUa_Server_Config mConfig;
    const SOPC_Toolkit_Build_Info mBuildInfo;
    int32_t mServerOnline;
    static OPCUA_Server* mInstance;
};

}

#endif // _OPCUA_SERVER_H
