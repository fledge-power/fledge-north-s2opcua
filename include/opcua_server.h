#ifndef INCLUDE_OPCUA_SERVER_H_
#define INCLUDE_OPCUA_SERVER_H_
/*
 * Fledge north service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Amandeep Singh Arora / Jeremie Chabod
 */

// System headers
#include <stdint.h>
#include <stdlib.h>
#include <atomic>
#include <string>
#include <mutex>
#include <thread>
#include <map>
#include <vector>

// Fledge headers
#include "config_category.h"
#include "reading.h"
#include "logger.h"
#include "utils.h"
#include "plugin_api.h"

extern "C" {
// S2OPC Headers
#include "s2opc/common/sopc_types.h"
#include "s2opc/common/sopc_builtintypes.h"
#include "s2opc/common/sopc_logger.h"
#include "s2opc/clientserver/sopc_user_app_itf.h"
#include "s2opc/clientserver/sopc_toolkit_config.h"
};

// Plugin headers
#include "opcua_server_config.h"

namespace s2opc_north {

/*****************************************************
 *  CONFIGURATION
 *****************************************************/
extern const char* plugin_default_config;

/*****************************************************
 *  TYPES DEFINITIONS
 *****************************************************/
// Redefinition of plugin callbacks types to ease readability
typedef bool (*north_write_event_t)
        (char *name, char *value, ControlDestination destination, ...);
typedef int (*north_operation_event_t)
        (char *operation, int paramCount, char *parameters[], ControlDestination destination, ...);
typedef std::vector<Reading*> Readings;

/**
 * Interface to the S2 OPCUA library for a S2OPC server
 */
class OPCUA_Server {
 public:
    /** Create a new OPC server with the given configuration
     * @param configData The configuration of the plugin
     */
    explicit OPCUA_Server(const ConfigCategory& configData);

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

    const OpcUa_Server_Config& config(void)const;

    /**
     * Process a write event on the server
     * \param callContextPtr The write context (including user)
     * \param  writeValue The value written
     */
    void writeNotificationCallback(
            const SOPC_CallContext* callContextPtr,
            OpcUa_WriteValue* writeValue);
    void setStopped(void);

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
    std::atomic<bool> mStopped;

 private:
    int32_t mServerOnline;
    SOPC_Endpoint_Config* mEpConfig;
};

inline void
OPCUA_Server::
setStopped(void) {
    mStopped = true;
}

inline const OpcUa_Server_Config&
OPCUA_Server::config(void)const {
    return mConfig;
}

}   // namespace s2opc_north

#endif  // INCLUDE_OPCUA_SERVER_H_
