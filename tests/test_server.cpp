#include <string.h>
#include <string>
#include <thread>
#include <rapidjson/document.h>

extern "C" {
// S2OPC Headers
#include "sopc_assert.h"
#include "libs2opc_common_config.h"
#include "libs2opc_request_builder.h"
#include "libs2opc_server.h"
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

#define NB_VAR_PER_READING 10

extern "C" {
static int north_operation_event_nbCall = 0;
static int north_operation_event (
        char *operation,
        int paramCount,
        char *names[],
        char *parameters[],
        ControlDestination destination,
        ...) {

    WARNING("Received operation '%s', paramCount=%d", operation, paramCount);
    north_operation_event_nbCall++;
    return paramCount;
}
}

#define CHECK_NO_ADD_SPC_UPDATE(readings) do {\
        server.reset(); \
        server.send(readings); \
        this_thread::sleep_for(chrono::milliseconds(15)); \
        ASSERT_EQ(server.nbResponses, 0); } while (0)
#define CHECK_ADD_SPC_UPDATE_FAIL(readings) do {\
        server.reset(); \
        server.send(readings); \
        this_thread::sleep_for(chrono::milliseconds(15)); \
        ASSERT_GT(server.nbResponses, 0);  \
        ASSERT_EQ(server.nbResponses, server.nbBadResponses); } while (0)
#define CHECK_ADD_SPC_UPDATE_OK(readings) do {\
        server.reset(); \
        server.send(readings); \
        this_thread::sleep_for(chrono::milliseconds(15)); \
        ASSERT_GT(server.nbResponses, 0);  \
        ASSERT_EQ(server.nbBadResponses, 0);} while (0)

TEST(S2OPCUA, OPCUA_Server) {
    ERROR("*** TEST S2OPCUA OPCUA_Server");
    ASSERT_NO_C_ASSERTION;

    north_operation_event_nbCall = 0;

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
    s2opc_north::OPCUA_Server::uninitialize(); // Ensure no previous server still exists
    OPCUA_Server_Test server(testConf);

    Readings readings;

    // Create valid Reading with 5 data
    // Create READING 1
    {
        TestReading elem("opcua_dps", "pivotDPS", 0x80000000);
        elem.pushStrValue("on", &readings);
    }

    // Create READING 2
    {
        TestReading elem("opcua_sps", "pivotSPS", 0x1234);
        elem.pushIntValue(0, &readings);
    }
    // Create READING 3 (MVA : INT32)
    {
        TestReading elem("opcua_mvi", "pivotMVI");
        elem.pushIntValue(560, &readings);
    }
    // Create READING 4 (MVA : FLOAT but encoded as int)
    {
        TestReading elem("opcua_mvf", "pivotMVF");
        elem.pushIntValue(44, &readings);
    }

    // Create READING 5 (MVA : FLOAT)
    {
        TestReading elem("opcua_mvf", "pivotMVF");
        elem.pushFloatValue(56.14, &readings);
    }

    server.reset();
    // Send READINGs
    server.send(readings);
    this_thread::sleep_for(chrono::milliseconds(10));

    // Read back values from server
    ASSERT_EQ(server.nbBadResponses, 0);
    ASSERT_EQ(server.nbResponses, readings.size() * NB_VAR_PER_READING);

    {
        SOPC_ReturnStatus status;
        OpcUa_ReadRequest* req(SOPC_ReadRequest_Create(4, OpcUa_TimestampsToReturn_Both));
        ASSERT_NE(nullptr, req);

        status = SOPC_ReadRequest_SetReadValueFromStrings(req, 0, "ns=1;s=sps/Value", SOPC_AttributeId_Value, NULL);
        ASSERT_EQ(status, SOPC_STATUS_OK);
        status = SOPC_ReadRequest_SetReadValueFromStrings(req, 1, "ns=1;s=dps/Value", SOPC_AttributeId_Value, NULL);
        ASSERT_EQ(status, SOPC_STATUS_OK);
        status = SOPC_ReadRequest_SetReadValueFromStrings(req, 2, "ns=1;s=mvi/Value", SOPC_AttributeId_Value, NULL);
        ASSERT_EQ(status, SOPC_STATUS_OK);
        status = SOPC_ReadRequest_SetReadValueFromStrings(req, 3, "ns=1;s=mvf/Value", SOPC_AttributeId_Value, NULL);
        ASSERT_EQ(status, SOPC_STATUS_OK);

        server.readResults.clear();
        server.sendAsynchRequest(req);
        ASSERT_EQ(status, SOPC_STATUS_OK);

        WAIT_UNTIL(server.readResults.size() >= 4, 1000);
        ASSERT_EQ(server.readResults.size(), 4);
        ASSERT_EQ(server.readResults[0], "Q=0x00001234,V=0");
        ASSERT_EQ(server.readResults[1], "Q=0x80000000,V=on");
        ASSERT_EQ(server.readResults[2], "Q=0x00000000,V=560");
        ASSERT_EQ(server.readResults[3], "Q=0x00000000,V=56.(...)");
    }

    // Invalid reading
    readings.clear();
    // Create READING 1
    {
        TestReading elem("opcua_dps", "dps", 0x80000000);
        // ** HERE ** INVALID "do_value"
        std::vector<double> doubleVect;
        DatapointValue dpv(doubleVect);
        elem.mValue = new Datapoint("do_value", dpv);
        elem.pushReading(&readings);

        CHECK_NO_ADD_SPC_UPDATE(readings);
    }

    // Invalid reading
    readings.clear();
    // Create READING 1
    {
        TestReading elem("opcua_dps", "pivotDPS", 0x80000000);
        // ** HERE ** MISMATCHING "do_value" type
        elem.pushIntValue(561, &readings);

        CHECK_NO_ADD_SPC_UPDATE(readings);
    }

    // Invalid reading
    readings.clear();
    // Create READING 1
    {
        // ** HERE ** INVALID "do_type"
        TestReading elem("opcua_xxx", "pivotSPS", 0x1234);
        elem.pushIntValue(0, &readings);

        CHECK_NO_ADD_SPC_UPDATE(readings);
    }


    // Invalid reading
    readings.clear();
    // Create READING 1
    {
        // ** HERE ** INVALID "do_id"
        TestReading elem("opcua_mvi", "pivotMVI_unknown");
        elem.pushIntValue(561, &readings);

        CHECK_ADD_SPC_UPDATE_FAIL(readings);
    }

    // Cover LOG cases
    SOPC_Logger_SetTraceLogLevel(SOPC_LOG_LEVEL_DEBUG);
    SOPC_Logger_TraceError(SOPC_LOG_MODULE_CLIENTSERVER, "Demo ERROR Log");
    SOPC_Logger_TraceWarning(SOPC_LOG_MODULE_CLIENTSERVER, "Demo WARNING Log");
    SOPC_Logger_TraceInfo(SOPC_LOG_MODULE_CLIENTSERVER, "Demo INFO Log");
    SOPC_Logger_TraceDebug(SOPC_LOG_MODULE_CLIENTSERVER, "Demo DEBUG Log");
    SOPC_Logger_SetTraceLogLevel(SOPC_LOG_LEVEL_INFO);

    // Check "operation" event
    server.setpointCallbacks(north_operation_event);
    ASSERT_EQ(north_operation_event_nbCall, 0);

    OPCUA_ClientNone clientN("opc.tcp://localhost:55345");
    OPCUA_ClientSecu clientS("opc.tcp://localhost:55345");
    ///////////////////////////////////////////
    // Use an external client to make requests
    {
        string readLog(clientS.readValue("i=84", 3));
        ASSERT_STR_CONTAINS(readLog, "QualifiedName = 0:Root");
        ASSERT_STR_NOT_CONTAINS(readLog, "Failed session activation");
    }

    // Invalid password
    {
        OPCUA_ClientSecu client("opc.tcp://localhost:55345", "user", "password2");
        string readLog(client.readValue("i=84", 3));
        ASSERT_STR_NOT_CONTAINS(readLog, "QualifiedName = 0:Root");
        ASSERT_STR_CONTAINS(readLog, "Failed session activation");
    }
    // Invalid password (length OK
    {
        OPCUA_ClientSecu client("opc.tcp://localhost:55345", "user", "passworD");
        string readLog(client.readValue("i=84", 3));
        ASSERT_STR_NOT_CONTAINS(readLog, "QualifiedName = 0:Root");
        ASSERT_STR_CONTAINS(readLog, "Failed session activation");
    }

    // Invalid user
    {
        OPCUA_ClientSecu client("opc.tcp://localhost:55345", "User");
        string readLog(client.readValue("i=84", 3));
        ASSERT_STR_NOT_CONTAINS(readLog, "QualifiedName = 0:Root");
        ASSERT_STR_CONTAINS(readLog, "Failed session activation");
    }

    // Write request to server
    // Check type SPC (BOOL)
    {
        string writeLog(clientN.writeValue("ns=1;s=spc/Value", SOPC_Boolean_Id, "1"));
        ASSERT_STR_CONTAINS(writeLog, "Write node \"ns=1;s=spc/Value\", attribute 13:"); // Result OK, no error
        ASSERT_STR_CONTAINS(writeLog, "StatusCode: 0x00000000"); // OK

        string readLog(clientN.readValue("ns=1;s=spc/Value", 13));
        ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x00000000"); // OK
        ASSERT_EQ(server.lastWriterName, s2opc_north::unknownUserName);
    }

    // Write request to server
    // Check type DPC (Byte)
    {
        string writeLog(clientN.writeValue("ns=1;s=dpc/Value", SOPC_Byte_Id, "17"));

        ASSERT_STR_CONTAINS(writeLog, "Write node \"ns=1;s=dpc/Value\", attribute 13:"); // Result OK, no error
        ASSERT_STR_CONTAINS(writeLog, "StatusCode: 0x00000000"); // OK

        string readLog(clientN.readValue("ns=1;s=dpc/Value", 13));
        ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x00000000"); // OK
        ASSERT_STR_CONTAINS(readLog, "Value: 17"); // Written value
        ASSERT_EQ(server.lastWriterName, s2opc_north::unknownUserName);
    }

    // Write request to server
    // Check with non-anonymous login
    {
        OPCUA_ClientSecu clientS2("opc.tcp://localhost:55345", "user2", "xGt4sdE3Z+");
        string writeLog(clientS2.writeValue("ns=1;s=dpc/Value", SOPC_Byte_Id, "18"));
        ASSERT_STR_CONTAINS(writeLog, "Write node \"ns=1;s=dpc/Value\", attribute 13:"); // Result OK, no error
        ASSERT_STR_CONTAINS(writeLog, "StatusCode: 0x00000000"); // OK
        ASSERT_EQ(server.lastWriterName, "user2");

        string readLog(clientN.readValue("ns=1;s=dpc/Value", 13));
        ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x00000000"); // OK
        ASSERT_STR_CONTAINS(readLog, "Value: 18"); // Written value
    }

    // Read request to server
    // Check type MVF (float / Read only)
    {
        string writeLog(clientN.writeValue("ns=1;s=mvf/Value", SOPC_Float_Id, "3.14"));
        ASSERT_STR_CONTAINS(writeLog, "Write node \"ns=1;s=mvf/Value\", attribute 13:"); // Result OK, no error
        ASSERT_STR_CONTAINS(writeLog, "StatusCode: 0x803B0000"); // NOde not writeable
    }

    // Read request to server
    // Check type APC (float)
    {
        string writeLog(clientN.writeValue("ns=1;s=apc/Value", SOPC_Float_Id, "31.4"));
        ASSERT_STR_CONTAINS(writeLog, "Write node \"ns=1;s=apc/Value\", attribute 13:"); // Result OK, no error
        ASSERT_STR_CONTAINS(writeLog, "StatusCode: 0x00000000");

        string readLog(clientN.readValue("ns=1;s=apc/Value", 13));
        ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x00000000"); // OK
        ASSERT_STR_CONTAINS(readLog, "Value: 31.4"); // Written value
    }

    // Read request to server
    // Check type INC (INT32)
    {
        string writeLog(clientN.writeValue("ns=1;s=inc/Value", SOPC_Int32_Id, "314"));
        ASSERT_STR_CONTAINS(writeLog, "Write node \"ns=1;s=inc/Value\", attribute 13:"); // Result OK, no error
        ASSERT_STR_CONTAINS(writeLog, "StatusCode: 0x00000000");

        string readLog(clientN.readValue("ns=1;s=inc/Value", 13));
        ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x00000000"); // OK
        ASSERT_STR_CONTAINS(readLog, "Value: 314"); // Written value
    }

    // Check (uninitialized) Analog value
    {
        string readLog(clientN.readValue("ns=1;s=mvi/Value", 13));
        ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x00000000");
        ASSERT_STR_CONTAINS(readLog, "Value: 560");
    }

    ///////////////////////////////////////////////////
    /////// ADDITIONAL COVERAGE ///////////////////////
    // Check invalid do_id type
    {
        readings.clear();
        TestReading elem("opcua_mvi", "pivotMVI");
        // Prebuild and patch "do_id" reading with an int value
        elem.mValue = createIntDatapointValue("do_value", 54L);
        elem.prebuild();
        DatapointValue* dv(elem.getElement("do_id"));
        ASSERT_NE(nullptr, dv);
        dv->setValue((long)42);
        elem.pushPrebuiltReading( &readings);
        CHECK_NO_ADD_SPC_UPDATE(readings);
    }
    // Check invalid do_type type
    {
        readings.clear();
        TestReading elem("opcua_mvi", "pivotMVI");
        // Prebuild and patch "do_type" reading with an int value
        elem.mValue = createIntDatapointValue("do_value", 54L);
        elem.prebuild();
        DatapointValue* dv(elem.getElement("do_type"));
        ASSERT_NE(nullptr, dv);
        dv->setValue((long)42);
        elem.pushPrebuiltReading( &readings);
        CHECK_NO_ADD_SPC_UPDATE(readings);
    }
    // Check invalid do_cot type
    {
        readings.clear();
        TestReading elem("opcua_mvi", "pivotMVI");
        // Prebuild and patch "do_cot" reading with a float value
        elem.mValue = createIntDatapointValue("do_value", 54L);
        elem.prebuild();
        DatapointValue* dv(elem.getElement("do_cot"));
        ASSERT_NE(nullptr, dv);
        dv->setValue(4.2);
        elem.pushPrebuiltReading( &readings);
        CHECK_NO_ADD_SPC_UPDATE(readings);
    }
    // Check invalid do_comingfrom type
    {
        readings.clear();
        TestReading elem("opcua_mvi", "pivotMVI");
        // Prebuild and patch "do_comingfrom" reading with a float value
        elem.mValue = createIntDatapointValue("do_value", 54L);
        elem.prebuild();
        DatapointValue* dv(elem.getElement("do_comingfrom"));
        ASSERT_NE(nullptr, dv);
        dv->setValue(4.2);
        elem.pushPrebuiltReading( &readings);
        CHECK_NO_ADD_SPC_UPDATE(readings);
    }
    // Check valid type for "do_value_quality"
    {
        readings.clear();
        TestReading elem("opcua_mvi", "pivotMVI", 0x40000000);
        elem.pushIntValue(560, &readings);
        CHECK_ADD_SPC_UPDATE_OK(readings);
        // Check value for "do_value"
        {
            string readLog(clientN.readValue("ns=1;s=mvi/Value", 13));
            ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x40000000");
            ASSERT_STR_CONTAINS(readLog, "Value: 560");
        }
    }
    // Check invalid type for "do_value_quality"
    {
        readings.clear();
        Logger::getLogger()->error(" --> do_value_quality");
        TestReading elem("opcua_mvi", "pivotMVI");
        // Prebuild and patch "do_value_quality" reading with a float value
        elem.mValue = createIntDatapointValue("do_value", 54L);
        elem.prebuild();
        DatapointValue* dv(elem.getElement("do_value_quality"));
        ASSERT_NE(nullptr, dv);
        dv->setValue(5.32);
        elem.pushPrebuiltReading(&readings);
        CHECK_ADD_SPC_UPDATE_OK(readings);
        // Check value for "do_value" (quality ignored)
        {
            string readLog(clientN.readValue("ns=1;s=mvi/Value", 13));
            ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x00000000");
            ASSERT_STR_CONTAINS(readLog, "Value: 54");
        }
    }
    // Check invalid type for "do_ts_org"
    {
        readings.clear();
        Logger::getLogger()->error(" --> do_ts_org");
        TestReading elem("opcua_mvi", "pivotMVI");
        // Prebuild and patch "do_value_quality" reading with a float value
        elem.mValue = createIntDatapointValue("do_value", 54L);
        elem.prebuild();
        DatapointValue* dv(elem.getElement("do_ts_org"));
        ASSERT_NE(nullptr, dv);
        dv->setValue(5.32);
        elem.pushPrebuiltReading(&readings);
        CHECK_NO_ADD_SPC_UPDATE(readings);
    }
    // Check invalid type for "do_ts_validity"
    {
        readings.clear();
        Logger::getLogger()->error(" --> do_ts_validity");
        TestReading elem("opcua_mvi", "pivotMVI");
        // Prebuild and patch "do_value_quality" reading with a float value
        elem.mValue = createIntDatapointValue("do_value", 54L);
        elem.prebuild();
        DatapointValue* dv(elem.getElement("do_ts_validity"));
        ASSERT_NE(nullptr, dv);
        dv->setValue(5.32);
        elem.pushPrebuiltReading(&readings);
        CHECK_NO_ADD_SPC_UPDATE(readings);
    }
    // Check invalid type for "do_source"
    {
        readings.clear();
        Logger::getLogger()->error(" --> do_source");
        TestReading elem("opcua_mvi", "pivotMVI");
        // Prebuild and patch "do_source" reading with a float value
        elem.mValue = createIntDatapointValue("do_value", 54L);
        elem.prebuild();
        DatapointValue* dv(elem.getElement("do_source"));
        ASSERT_NE(nullptr, dv);
        dv->setValue(5.32);
        elem.pushPrebuiltReading(&readings);
        CHECK_ADD_SPC_UPDATE_OK(readings);
        // Check default value for "do_source" (="process")
        {
            string readLog(clientN.readValue("ns=1;s=mvi/Source", 13));
            ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x00000000");
            ASSERT_STR_CONTAINS(readLog, QUOTE(Value: "process"));
        }
    }

    ///////////////////////////////////////////////////
    /////// CHECK TimeQuality /////////////////////////
    // Check default value for TimeQuality = "do_ts_quality"
    {
        string readLog(clientN.readValue("ns=1;s=mvi/TimeQuality", 13));
        ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x0000000");
        ASSERT_STR_CONTAINS(readLog, "Value: 0");
    }
    readings.clear();
    // Create READING (MVI : INT32)
    {
        TestReading elem("opcua_mvi", "pivotMVI");
        elem.addProperty(createIntDatapointValue("do_ts_quality", 0x5));
        elem.pushIntValue(580, &readings);
    }
    CHECK_ADD_SPC_UPDATE_OK(readings);

    // Check value for "do_value"
    {
        string readLog(clientN.readValue("ns=1;s=mvi/Value", 13));
        ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x00000000");
        ASSERT_STR_CONTAINS(readLog, "Value: 580");
    }
    // Check value for "do_ts_quality"
    {
        string readLog(clientN.readValue("ns=1;s=mvi/TimeQuality", 13));
        ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x00000000");
        ASSERT_STR_CONTAINS(readLog, "Value: 5");
    }

    ///////////////////////////////////////////////////
    /////// CHECK Confirmation ////////////////////////
    // Check default value for "do_confirmation"
    {
        string readLog(clientN.readValue("ns=1;s=mvi/Confirmation", 13));
        ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x0000000");
        ASSERT_STR_CONTAINS(readLog, "Value: 0");
    }

    readings.clear();
    // Create READING (MVI : INT32)
    {
        TestReading elem("opcua_mvi", "pivotMVI");
        elem.addProperty(createIntDatapointValue("do_confirmation", 1));
        elem.pushIntValue(570, &readings);
    }
    CHECK_ADD_SPC_UPDATE_OK(readings);

    // Check value for "do_value"
    {
        string readLog(clientN.readValue("ns=1;s=mvi/Value", 13));
        ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x00000000");
        ASSERT_STR_CONTAINS(readLog, "Value: 570");
    }
    // Check value for "do_confirmation"
    {
        string readLog(clientN.readValue("ns=1;s=mvi/Confirmation", 13));
        ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x00000000");
        ASSERT_STR_CONTAINS(readLog, "Value: 1");
    }


    server.stop();
};

#warning "TODO : check all sub (non-value) variables"

TEST(S2OPCUA, OPCUA_Server_MissingFile) {
    ERROR("*** TEST S2OPCUA OPCUA_Server_MissingFile");
    //ASSERT_C_RAISES_ASSERTION_START;

    ConfigCategory testConf;
    testConf.addItem("logging", "Configure S2OPC logging level", "Info",
            "Info", {"None", "Error", "Warning", "Info", "Debug"});
    testConf.addItem("exchanged_data", "exchanged_data", "JSON", config_exData,
            config_exData);
    testConf.addItem("protocol_stack", "protocol_stack", "JSON", protocolMissingFile,
            protocolMissingFile);

    s2opc_north::OPCUA_Server::uninitialize(); // Ensure no previous server still exists
    ASSERT_ANY_THROW(OPCUA_Server_Test server(testConf));

    OPCUA_Server::uninitialize();
}

TEST(S2OPCUA, OPCUA_Server_MissingNamespaces) {
    ERROR("*** TEST S2OPCUA OPCUA_Server_MissingNamespaces");
    //ASSERT_C_RAISES_ASSERTION_START;
    const string proto(replace_in_string(protocolJsonOK, QUOTE("urn:S2OPC:ns1"), ""));
    ConfigCategory testConf;
    testConf.addItem("logging", "Configure S2OPC logging level", "Info",
            "Info", {"None", "Error", "Warning", "Info", "Debug"});
    testConf.addItem("exchanged_data", "exchanged_data", "JSON", config_exData,
            config_exData);
    testConf.addItem("protocol_stack", "protocol_stack", "JSON", proto,
            proto);

    s2opc_north::OPCUA_Server::uninitialize(); // Ensure no previous server still exists
    ASSERT_ANY_THROW(OPCUA_Server_Test server(testConf));

    OPCUA_Server::uninitialize();

}

