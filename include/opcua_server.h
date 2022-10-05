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

// Plugin headers
#include "opcua_server_tools.h"
#include "opcua_server_config.h"

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
#include "sopc_types.h"
#include "sopc_builtintypes.h"
#include "sopc_logger.h"
#include "sopc_user_app_itf.h"
#include "sopc_toolkit_config.h"
};

namespace s2opc_north {

/*****************************************************
 *  CONFIGURATION
 *****************************************************/
extern const char* const plugin_default_config;

/*****************************************************
 *  TYPES DEFINITIONS
 *****************************************************/
// Redefinition of plugin callbacks types to ease readability
using north_write_event_t = bool (*)
        (char *name, char *value, ControlDestination destination, ...);  //NOSONAR
using north_operation_event_t =
        int (*)(char *operation, int paramCount,
                char *names[], char *parameters[],  //NOSONAR
                ControlDestination destination, ...);
using Readings = std::vector<Reading*>;

static const char unknownUserName[] = "-UnknownUserName-";
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
     * Stops the server and waits for its termination
     */
    void stop(void);

    /**
     * Sends the readings on the OPC server
     * @param readings The objects to update
     * @return The number of element written
     */
    uint32_t send(const Readings& readings);

    /**
     * Register the "operation" callback.
     * This function can be called when a command is received from controller side (opc client)
     * and needs to be sent back to any south plugin.
     */
    void setpointCallbacks(north_operation_event_t operation);

    /**
     * Process a write event on the server
     * \param callContextPtr The write context (including user)
     * \param  writeValue The value written
     */
    void writeNotificationCallback(
            const SOPC_CallContext* callContextPtr,
            OpcUa_WriteValue* writeValue);

    /**
     * Send an asynchronous request to the server.
     * @param request An object created by SOPC_ReadRequest_Create or
     *      SOPC_WriteRequest_Create. It shall not be freed by caller
     */
    void sendAsynchRequest(void* request)const;

    virtual void asynchWriteResponse(const OpcUa_WriteResponse* writeResp);
    virtual void asynchReadResponse(const OpcUa_ReadResponse* readResp);
    void setStopped(void);

    /** Call this method to clean up SOPC libraries in the case
     * the constructor failed (in that case the destructor will not be called,
     * so that calling this clean up will be required to re-instanciate plugin
     */
    static void uninitialize(void);

 protected:
    virtual void writeEventNotify(const std::string& username) {
        // This method intends at providing a child class the ability to
        // monitor events
    }
    inline void setShutdownDuration(const int nbMs) {m_nbMillisecondShutdown = nbMs;}

 private:
    void init_sopc_lib_and_logs(void);

    /**
     * This function updates a node Id in the address space given a DatapointValue
     */
    void updateAddressSpace(SOPC_NodeId* nodeId, const string& typeId,
            const DatapointValue* dv, SOPC_StatusCode quality, SOPC_DateTime timestamp)const;

    int m_nbMillisecondShutdown;

 public:
    const OpcUa_Protocol mProtocol;
    const OpcUa_Server_Config mConfig;
    const SOPC_Toolkit_Build_Info mBuildInfo;
    static OPCUA_Server* instance(void) {return mInstance;}

 private:
    static OPCUA_Server* mInstance;
    std::atomic<bool> mStopped;
    int32_t mServerOnline;
    SOPC_Endpoint_Config* mEpConfig;
    north_operation_event_t m_oper;
};

inline void
OPCUA_Server::
setStopped(void) {
    mStopped = true;
}

}   // namespace s2opc_north

#endif  // INCLUDE_OPCUA_SERVER_H_
