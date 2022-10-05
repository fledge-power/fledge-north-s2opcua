/*
 * Fledge north plugin.
 *
 * Copyright (c) 2018 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Jeremie Chabod / Mark Riddoch
 */

// System headers

#include <vector>
#include <exception>

// Fledge includes
#include "logger.h"
#include "config_category.h"
#include "reading.h"
#include "rapidjson/document.h"
#include "version.h"
#include "plugin_api.h"

/// Project includes
#include "opcua_server.h"

extern "C" {
// S2OPC Headers
#include "sopc_assert.h"
}

/* This file implements a north OPCUA bridge for Fledge.
 * In particular, this file simply routes the required interfaces to the C++ class
 * "OPCUA_Server".
 * The interface is specified in:
 *      https://fledge-iot.readthedocs.io/en/develop/plugin_developers_guide/04_north_plugins.html#c-c-plugins
 * The following services must be defined:
 * - plugin_info
 * - plugin_init
 * - plugin_shutdown
 * - plugin_send
 * - plugin_register
 */

namespace {
#define PLUGIN_NAME  "s2opcua"      // //NOSONAR interpreted in macros
#define INTERFACE_VERSION  "1.0.0"  // //NOSONAR interpreted in macros
#define PLUGIN_FLAGS SP_CONTROL

/**************************************************************************/
static s2opc_north::OPCUA_Server* handleToPlugin(const PLUGIN_HANDLE handle) {
    SOPC_ASSERT(handle != nullptr && "OPC UA called with NULL plugin");
    return static_cast<s2opc_north::OPCUA_Server *> (handle);
}

class PulginInitFailedE : public std::exception {};
}   // namespace

/**
 * The OPCUA plugin interface
 */
extern "C" {
/**************************************************************************/
// The callback for ASSERTION failure (SOPC_ASSERT macro)
void plugin_Assert_UserCallback(const char* context) {
#ifdef UNIT_TESTING
    (void) context;
    assert(false);
#else  // UNIT_TESTING not defined
    FATAL("ASSERT failed. Context = %s", (context ? LOGGABLE(context) : "[NULL]"));
    // leave some time to flush logs.
    usleep(100 * 1000);
    // Throwing an exception may not be enough in case the ASSERT was raised in a separate thread.
    // Calling exit will ensure the full process is stopped.
    std::exit(1);
#endif
}

/**************************************************************************/
PLUGIN_INFORMATION* plugin_info(void) {
    /**
     * The plugin information structure
     */
    static PLUGIN_INFORMATION g_plugin_info = {
        PLUGIN_NAME,              // Name
        FLEDGE_NORTH_S2OPC_VERSION,                  // Version
        PLUGIN_FLAGS,             // Flags
        PLUGIN_TYPE_NORTH,        // Type
        INTERFACE_VERSION,        // Interface version
        s2opc_north::plugin_default_config  // Default configuration
    };   // //NOSONAR FLEDGE API

    Logger::getLogger()->debug("OPC UA Server Config is %s", LOGGABLE(g_plugin_info.config));
    return &g_plugin_info;
}

/**************************************************************************/
PLUGIN_HANDLE plugin_init(ConfigCategory *configData) {
    PLUGIN_HANDLE handle = nullptr;
    // the very first thing to do is to configure ASSERTs to be routed to Logger
    SOPC_Assert_Set_UserCallback(&plugin_Assert_UserCallback);
    try {
        Logger::getLogger()->setMinLevel("debug");
        INFO("----------------------------");
        DEBUG("OPC UA Server plugin_init()");
        handle = (PLUGIN_HANDLE)
                (new s2opc_north::OPCUA_Server(*configData));  // //NOSONAR FLEDGE API
    }
    catch (const std::exception& e) {
        FATAL(std::string("OPC UA server plugin creation failed:") + e.what());
        s2opc_north::OPCUA_Server::uninitialize();  // Force cleanup
        throw PulginInitFailedE();
    }
    WARNING("Created S2OPC server plugin (%p)...", (void*)handle);
    return handle;
}

/**************************************************************************/
void plugin_shutdown(PLUGIN_HANDLE handle) {
    WARNING("Quitting S2OPC server plugin (%p)...", (void*)handle);
    s2opc_north::OPCUA_Server* plugin(handleToPlugin(handle));
    plugin->stop();
    delete plugin;  // //NOSONAR FLEDGE API
}

/**************************************************************************/
uint32_t plugin_send(PLUGIN_HANDLE handle, s2opc_north::Readings& readings) {
    return handleToPlugin(handle)->send(readings);
}

/**************************************************************************/
void plugin_register(PLUGIN_HANDLE handle,
        s2opc_north::north_write_event_t write,  // //NOSONAR FLEDGE API
        s2opc_north::north_operation_event_t operation) {  // //NOSONAR FLEDGE API
    INFO("plugin_register...");
    handleToPlugin(handle)->setpointCallbacks(operation);
}

}

