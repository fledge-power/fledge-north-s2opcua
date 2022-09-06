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
#include "s2opc/common/sopc_types.h"
#include "s2opc/common/sopc_builtintypes.h"
#include "s2opc/common/sopc_logger.h"
#include "s2opc/clientserver/sopc_user_app_itf.h"
#include "s2opc/clientserver/sopc_toolkit_config.h"
};

#include "opcua_server_config.h"

namespace s2opc_north
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

/**
 * Interface to the S2 OPCUA library for a S2OPC server
 */
class OPCUA_Server
{
public:

    /** Create a new OPC server with the given configuration
     * @param configData The configuration of the plugin
     */
    OPCUA_Server(const ConfigCategory& configData);

    /**
     * Destructor
     */
    virtual ~OPCUA_Server(void);

    /**
     * Sends the readings on the OPC server
     * @param readings The objects to update
     * @return The number of element written
     */
    uint32_t send(const Readings& readings);
    /**
     * TODO
     */
    void setpointCallbacks(north_write_event_t write, north_operation_event_t operation);

    inline const OpcUa_Server_Config& config(void)const{return mConfig;}

    /**
     * Process a write event on the server
     * \param callContextPtr The write context (including user)
     * \param  writeValue The value written
     */
    void writeNotificationCallback(
            const SOPC_CallContext* callContextPtr,
            OpcUa_WriteValue* writeValue);
private:
    void init_sopc_lib_and_logs(void);
    /**
     * This function is called when an event is received on the server
     */
    static void Server_Event(SOPC_App_Com_Event event,
            uint32_t idOrStatus, void* param, uintptr_t appContext);

public:
    // It is mandatory that mEnvironment is the first member
    const OpcUa_Server_Config mConfig;
    const SOPC_Toolkit_Build_Info mBuildInfo;
    static OPCUA_Server* mInstance;
private:
    int32_t mServerOnline;
};

}

#endif // _OPCUA_SERVER_H
