#include <string.h>
#include <string>
#include <rapidjson/document.h>

extern "C" {
// S2OPC Headers
#include "s2opc/common/sopc_assert.h"
#include "sopc_log_manager.h"
#include "libs2opc_common_config.h"
}

// Tested files
#include "opcua_server.h"
#include "opcua_server_tools.h"

// Fledge / tools  includes
#include "main_test_configs.h"
#include <gtest/gtest.h>
#include <plugin_api.h>
#include <logger.h>

using namespace std;
using namespace rapidjson;
using namespace s2opc_north;


TEST(S2OPCUA, OPCUA_Server) {
    CATCH_C_ASSERTS;

    const SOPC_Toolkit_Build_Info buildInfo(SOPC_CommonHelper_GetBuildInfo());
    Logger::getLogger()->info("Common build date: %s", LOGGABLE(buildInfo.commonBuildInfo.buildBuildDate));
    Logger::getLogger()->info("Common build dock: %s", LOGGABLE(buildInfo.commonBuildInfo.buildDockerId));
    Logger::getLogger()->info("Common build sha1: %s", LOGGABLE(buildInfo.commonBuildInfo.buildSrcCommit));
    Logger::getLogger()->info("Common build vers: %s", LOGGABLE(buildInfo.commonBuildInfo.buildVersion));

    Logger::getLogger()->info("Server build date: %s", LOGGABLE(buildInfo.clientServerBuildInfo.buildBuildDate));
    Logger::getLogger()->info("Server build dock: %s", LOGGABLE(buildInfo.clientServerBuildInfo.buildDockerId));
    Logger::getLogger()->info("Server build sha1: %s", LOGGABLE(buildInfo.clientServerBuildInfo.buildSrcCommit));
    Logger::getLogger()->info("Server build vers: %s", LOGGABLE(buildInfo.clientServerBuildInfo.buildVersion));

    ConfigCategory testConf;
    testConf.addItem("logging", "Configure S2OPC logging level", "Info",
            "Info", {"None", "Error", "Warning", "Info", "Debug"});
    testConf.addItem("exchanged_data", "exchanged_data", "JSON", config_exData,
            config_exData);
    testConf.addItem("protocol_stack", "protocol_stack", "JSON", protocolJsonOK,
            protocolJsonOK);
    OPCUA_Server server(testConf);
}
