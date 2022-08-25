/*
 * Fledge north plugin.
 *
 * Copyright (c) 2018 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Jeremie Chabod / Mark Riddoch
 */

//#include <stdio.h>
//#include <stdlib.h>
//#include <strings.h>
//#include <string>

#include <vector>

#include <logger.h>
// #include <plugin_exception.h>
#include <config_category.h>
#include <reading.h>
#include <rapidjson/document.h>
#include <version.h>

#include "opcua_server.h"

#include <plugin_api.h>

/* This file implements a north OPCUA bridge for Fledge.
 * The interface is specified in:
 *      https://fledge-iot.readthedocs.io/en/develop/plugin_developers_guide/04_north_plugins.html#c-c-plugins
 * The following services must be defined:
 * - plugin_info
 * - plugin_init
 * - plugin_shutdown
 * - plugin_send
 * - plugin_register
 */

namespace
{
#define PLUGIN_NAME  "s2opcua"
#define INTERFACE_VERSION  "1.0.0"
#define PLUGIN_FLAGS 0  // Supported NORTH flags are: SP_PERSIST_DATA, SP_BUILTIN

/**************************************************************************/
static fledge_power_s2opc_north::OPCUA_Server* handleToPlugin(void* handle)
{
    if (handle == NULL)
    {
        Logger::getLogger()->fatal("OPC UA called with NULL plugin");
        throw exception();
    }
    return reinterpret_cast<fledge_power_s2opc_north::OPCUA_Server *> (handle);
}

/**
 * The plugin information structure
 */
static PLUGIN_INFORMATION g_plugin_info = {
    PLUGIN_NAME,              // Name
    FLEDGE_NORTH_S2OPC_VERSION,                  // Version
    PLUGIN_FLAGS,             // Flags
    PLUGIN_TYPE_NORTH,        // Type
    INTERFACE_VERSION,        // Interface version
    fledge_power_s2opc_north::plugin_default_config  // Default configuration
};

} // namespace

/**
 * The OPCUA plugin interface
 */
extern "C" {

/**
 * Return the information about this plugin
 */
PLUGIN_INFORMATION* plugin_info()
{
    Logger::getLogger()->info("OPC UA Server Config is %s", ::g_plugin_info.config);
    return &::g_plugin_info;
}

PLUGIN_HANDLE plugin_init(ConfigCategory *configData)
{
    using namespace fledge_power_s2opc_north;
    try
    {
        Logger::getLogger()->warn("OPC UA Server plugin_init()");
        return (PLUGIN_HANDLE)(new OPCUA_Server(*configData));
    }
    catch (const Exception& e)
    {
        Logger::getLogger()->fatal(std::string("OPC UA server plugin creation failed:") + e.what());
        throw exception();
    }
}

void plugin_shutdown(PLUGIN_HANDLE handle)
{
    delete handleToPlugin(handle);
}

uint32_t plugin_send(PLUGIN_HANDLE handle, fledge_power_s2opc_north::Readings& readings)
{
    return handleToPlugin(handle)->send(readings);
}

void plugin_register(PLUGIN_HANDLE handle,
        fledge_power_s2opc_north::north_write_event_t write,
        fledge_power_s2opc_north::north_operation_event_t operation)
{
    handleToPlugin(handle)->setpointCallbacks(write, operation);
}// TODO JCH

}

