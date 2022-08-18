/*
 * Fledge north plugin.
 *
 * Copyright (c) 2018 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Jeremie Chabod / Mark Riddoch
 */
#include <opcua.h>
#undef QUOTE    // S2OPC Toolkit has its own definition of QUOTE which conflicts with Fledge
#include <plugin_api.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <strings.h>
//#include <string>

#include <vector>

#include <logger.h>
#include <plugin_exception.h>
#include <config_category.h>
#include <reading.h>
#include <rapidjson/document.h>
#include <version.h>

/* This file implements a north OPCUA bridge for Fledge.
 * The interface is specified in:
 *      https://fledge-iot.readthedocs.io/en/develop/plugin_developers_guide/04_north_plugins.html#c-c-plugins
 */

namespace
{
#define PLUGIN_NAME  "s2opcua"
#define INTERFACE_VERSION  "1.0.0"
#define PLUGIN_FLAGS 0  // Supported NORTH flags are: SP_PERSIST_DATA, SP_BUILTIN

/**
 * Default configuration
 */
static const char *default_config = QUOTE({
    "plugin" : {
        "description" : "Simple OPC UA data change plugin",
        "type" : "string",
        "default" : PLUGIN_NAME,
        "readonly" : "true"
    },
    "todo" : {} // TODO
});

/*****************************************************
 *  TYPES DEFINITIONS
 *****************************************************/
// Redefintion of plugin callbacks types to ease readability
typedef bool (*north_write_event_t)(char *name, char *value, ControlDestination destination, ...);
typedef int (*north_operation_event_t)(char *operation, int paramCount, char *parameters[], ControlDestination destination, ...);

typedef std::vector<Reading*> Readings;
} // namespace

/**
 * The OPCUA plugin interface
 */
extern "C" {

/**
 * The plugin information structure
 */
static PLUGIN_INFORMATION info = {
    PLUGIN_NAME,              // Name
    VERSION,                  // Version
    PLUGIN_FLAGS,             // Flags
    PLUGIN_TYPE_SOUTH,        // Type
    INTERFACE_VERSION,        // Interface version
    default_config            // Default configuration
};

/**
 * Return the information about this plugin
 */
PLUGIN_INFORMATION *plugin_info()
{
    Logger::getLogger()->info("OPC UA Server Config is %s", info.config);
    return &info;
}


PLUGIN_HANDLE plugin_init(ConfigCategory *configData)
{
    return (PLUGIN_HANDLE)(new myNorthPlugin(configData));
} // TODO JCH

uint32_t plugin_send(PLUGIN_HANDLE handle, Readings& readings)
{
    myNorthPlugin *plugin = (myNorthPlugin *)handle;
    return plugin->send(readings);
} // TODO JCH

void plugin_shutdown(PLUGIN_HANDLE handle)
{
     myNorthPlugin *plugin = (myNorthPlugin *)handle;
     delete plugin;
} // TODO JCH

void plugin_register(PLUGIN_HANDLE handle, north_write_event_t write, north_operation_event_t operation)
{
     myNorthPlugin *plugin = (myNorthPlugin *)handle;
     plugin->setpointCallbacks(write, operation);
}// TODO JCH

}

