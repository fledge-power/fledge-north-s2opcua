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

    // Create valid Reading with 4 data
    // Create READING 1
    {
        vector<Datapoint *>* dp_vect = new vector<Datapoint *>;
        dp_vect->push_back(createStringDatapointValue("do_type", "opcua_dps"));
        dp_vect->push_back(createStringDatapointValue("do_nodeid", "ns=1;s=/label1/addr1"));
        dp_vect->push_back(createIntDatapointValue("do_value", 17));
        dp_vect->push_back(createIntDatapointValue("do_quality", 0x80000000));
        dp_vect->push_back(createIntDatapointValue("do_ts", 42));
        DatapointValue do_1(dp_vect, true);
        readings.push_back(new Reading("reading1", new Datapoint("data_object", do_1)));
    }

    // Create READING 2
    {
        vector<Datapoint *>* dp_vect = new vector<Datapoint *>;
        dp_vect->push_back(createStringDatapointValue("do_type", "opcua_sps"));
        dp_vect->push_back(createStringDatapointValue("do_nodeid", "ns=1;s=/label2/addr2"));
        dp_vect->push_back(createIntDatapointValue("do_value", 0));
        dp_vect->push_back(createStringDatapointValue("do_quality", "0x1234"));
        dp_vect->push_back(createIntDatapointValue("do_ts", 42));
        DatapointValue do_1(dp_vect, true);
        readings.push_back(new Reading("reading2", new Datapoint("data_object", do_1)));
    }
    // Create READING 3 (MVA : INT32)
    {
        vector<Datapoint *>* dp_vect = new vector<Datapoint *>;
        dp_vect->push_back(createStringDatapointValue("do_type", "opcua_mva"));
        dp_vect->push_back(createStringDatapointValue("do_nodeid", "ns=1;s=/labelMVA/mva"));
        dp_vect->push_back(createIntDatapointValue("do_value", 560));
        dp_vect->push_back(createStringDatapointValue("do_quality", "0"));
        dp_vect->push_back(createIntDatapointValue("do_ts", 42));
        DatapointValue do_1(dp_vect, true);
        readings.push_back(new Reading("mva", new Datapoint("data_object", do_1)));
    }
    // Create READING 4 (MVA : FLOAT but encoded as int)
    {
        vector<Datapoint *>* dp_vect = new vector<Datapoint *>;
        dp_vect->push_back(createStringDatapointValue("do_type", "opcua_mvf"));
        dp_vect->push_back(createStringDatapointValue("do_nodeid", "ns=1;s=/labelMVF/mvf"));
        dp_vect->push_back(createIntDatapointValue("do_value", 44));
        dp_vect->push_back(createStringDatapointValue("do_quality", "0"));
        dp_vect->push_back(createIntDatapointValue("do_ts", 42));
        DatapointValue do_1(dp_vect, true);
        readings.push_back(new Reading("mvf", new Datapoint("data_object", do_1)));
    }

    // Create READING 5 (MVA : FLOAT)
    {
        vector<Datapoint *>* dp_vect = new vector<Datapoint *>;
        dp_vect->push_back(createStringDatapointValue("do_type", "opcua_mvf"));
        dp_vect->push_back(createStringDatapointValue("do_nodeid", "ns=1;s=/labelMVF/mvf"));
        dp_vect->push_back(createFloatDatapointValue("do_value", 56.14));
        dp_vect->push_back(createStringDatapointValue("do_quality", "0"));
        dp_vect->push_back(createIntDatapointValue("do_ts", 42));
        DatapointValue do_1(dp_vect, true);
        readings.push_back(new Reading("mvf", new Datapoint("data_object", do_1)));
    }

    server.reset();
    // Send READINGs
    server.send(readings);
    this_thread::sleep_for(chrono::milliseconds(10));

    // Read back values from server
    ASSERT_EQ(server.nbBadResponses, 0);
    ASSERT_EQ(server.nbResponses, 5);

    {
        SOPC_ReturnStatus status;
        OpcUa_ReadRequest* req(SOPC_ReadRequest_Create(4, OpcUa_TimestampsToReturn_Both));
        ASSERT_NE(nullptr, req);

        status = SOPC_ReadRequest_SetReadValueFromStrings(req, 0, "ns=1;s=/label2/addr2", SOPC_AttributeId_Value, NULL);
        ASSERT_EQ(status, SOPC_STATUS_OK);
        status = SOPC_ReadRequest_SetReadValueFromStrings(req, 1, "ns=1;s=/label1/addr1", SOPC_AttributeId_Value, NULL);
        ASSERT_EQ(status, SOPC_STATUS_OK);
        status = SOPC_ReadRequest_SetReadValueFromStrings(req, 2, "ns=1;s=/labelMVA/mva", SOPC_AttributeId_Value, NULL);
        ASSERT_EQ(status, SOPC_STATUS_OK);
        status = SOPC_ReadRequest_SetReadValueFromStrings(req, 3, "ns=1;s=/labelMVF/mvf", SOPC_AttributeId_Value, NULL);
        ASSERT_EQ(status, SOPC_STATUS_OK);

        server.readResults.clear();
        server.sendAsynchRequest(req);
        ASSERT_EQ(status, SOPC_STATUS_OK);

        WAIT_UNTIL(server.readResults.size() >= 4, 1000);
        ASSERT_EQ(server.readResults.size(), 4);
        ASSERT_EQ(server.readResults[0], "Q=0x00001234,V=0");
        ASSERT_EQ(server.readResults[1], "Q=0x80000000,V=17");
        ASSERT_EQ(server.readResults[2], "Q=0x00000000,V=560");
        ASSERT_EQ(server.readResults[3], "Q=0x00000000,V=56.(...)");
    }

    // Invalid reading
    readings.clear();
    // Create READING 1
    {
        vector<Datapoint *>* dp_vect = new vector<Datapoint *>;
        dp_vect->push_back(createStringDatapointValue("do_type", "opcua_dps"));
        dp_vect->push_back(createStringDatapointValue("do_nodeid", "ns=1;s=/label1/addr1"));
        // ** HERE ** INVALID "do_value"
        std::vector<double> doubleVect;
        DatapointValue dpv(doubleVect);
        dp_vect->push_back(new Datapoint("do_value", dpv));
        dp_vect->push_back(createIntDatapointValue("do_quality", 0x80000000));
        dp_vect->push_back(createIntDatapointValue("do_ts", 42));
        DatapointValue do_1(dp_vect, true);
        readings.push_back(new Reading("reading3", new Datapoint("data_object", do_1)));

        server.reset();
        // Send READINGs
        server.send(readings);
        this_thread::sleep_for(chrono::milliseconds(10));

        // Read back values from server
        ASSERT_EQ(server.nbResponses, 1);
        ASSERT_EQ(server.nbBadResponses, 0);
    }

    // Invalid reading
    readings.clear();
    // Create READING 1
    {
        vector<Datapoint *>* dp_vect = new vector<Datapoint *>;
        dp_vect->push_back(createStringDatapointValue("do_type", "opcua_dps"));
        dp_vect->push_back(createStringDatapointValue("do_nodeid", "ns=1;s=/label1/addr1"));
        dp_vect->push_back(createIntDatapointValue("do_quality", 0x80000000));
        // ** HERE ** INVALID "do_value"
        dp_vect->push_back(createStringDatapointValue("do_value", "NoValue"));
        dp_vect->push_back(createIntDatapointValue("do_ts", 42));
        DatapointValue do_1(dp_vect, true);
        readings.push_back(new Reading("reading3", new Datapoint("data_object", do_1)));

        server.reset();
        // Send READINGs
        server.send(readings);
        this_thread::sleep_for(chrono::milliseconds(10));

        // Read back values from server
        ASSERT_EQ(server.nbResponses, 1);
        ASSERT_EQ(server.nbBadResponses, 0);
    }

    // Invalid reading
    readings.clear();
    // Create READING 1
    {
        vector<Datapoint *>* dp_vect = new vector<Datapoint *>;
        dp_vect->push_back(createStringDatapointValue("do_type", "opcua_dps"));
        dp_vect->push_back(createStringDatapointValue("do_nodeid", "ns=1;s=/label1/addr1"));
        dp_vect->push_back(createIntDatapointValue("do_quality", 0x80000000));
        dp_vect->push_back(createIntDatapointValue("do_value", 1));
        // ** HERE ** INVALID "do_ts"
        dp_vect->push_back(createStringDatapointValue("do_ts", "hello world!"));
        DatapointValue do_1(dp_vect, true);
        readings.push_back(new Reading("reading3", new Datapoint("data_object", do_1)));

        server.reset();
        // Send READINGs
        server.send(readings);
        this_thread::sleep_for(chrono::milliseconds(10));

        // Read back values from server
        ASSERT_EQ(server.nbResponses, 1);
        ASSERT_EQ(server.nbBadResponses, 0);
    }


    // Invalid reading
    readings.clear();
    // Create READING 1
    {
        vector<Datapoint *>* dp_vect = new vector<Datapoint *>;
        dp_vect->push_back(createStringDatapointValue("do_type", "opcua_dps"));
        dp_vect->push_back(createIntDatapointValue("do_nodeid", 84));
        dp_vect->push_back(createIntDatapointValue("do_quality", 0x80000000));
        dp_vect->push_back(createIntDatapointValue("do_value", 1));
        // ** HERE ** INVALID "do_ts"
        std::vector<double> doubleVect;
        DatapointValue dpv(doubleVect);
        dp_vect->push_back(new Datapoint("do_ts", dpv));
        DatapointValue do_1(dp_vect, true);
        readings.push_back(new Reading("reading3", new Datapoint("data_object", do_1)));

        server.reset();
        // Send READINGs
        server.send(readings);
        this_thread::sleep_for(chrono::milliseconds(10));

        // Read back values from server
        ASSERT_EQ(server.nbResponses, 1);
        ASSERT_EQ(server.nbBadResponses, 1);  // cannot update node "i=84"
    }

    // Invalid reading
    readings.clear();
    // Create READING 1
    {
        vector<Datapoint *>* dp_vect = new vector<Datapoint *>;
        dp_vect->push_back(createStringDatapointValue("do_type", "opcua_dps"));
        // ** HERE ** INVALID "do_nodeid"
        std::vector<double> doubleVect;
        DatapointValue dpv(doubleVect);
        dp_vect->push_back(new Datapoint("do_nodeid", dpv));
        dp_vect->push_back(createIntDatapointValue("do_quality", 0x80000000));
        dp_vect->push_back(createIntDatapointValue("do_value", 1));
        dp_vect->push_back(createIntDatapointValue("do_ts", 42));
        DatapointValue do_1(dp_vect, true);
        readings.push_back(new Reading("reading3", new Datapoint("data_object", do_1)));

        server.reset();
        // Send READINGs
        server.send(readings);
        this_thread::sleep_for(chrono::milliseconds(10));

        // Read back values from server (No update done because NodeId is invalid)
        ASSERT_EQ(server.nbResponses, 0);
        ASSERT_EQ(server.nbBadResponses, 0);
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

    ///////////////////////////////////////////
    // Use an external client to make requests
    {
        SOPC_tools::CStringVect read_cmd({"./s2opc_read",
            "-e", "opc.tcp://localhost:55345", "--encrypt",
            "-n", "i=84",
            "--username=user", "--password=password",
            "--user_policy_id=username_Basic256Sha256",
            "--client_cert=cert/client_public/client_2k_cert.der",
            "--client_key=cert/client_private/client_2k_key.pem",
            "--server_cert=cert/server_public/server_2k_cert.der",
            "--ca=cert/trusted/cacert.der",
            "--crl=cert/revoked/cacrl.der",
            "-a", "3"});

        string execLog(launch_and_check(read_cmd));

        // cout << "EXECLOG=<" <<execLog << ">" << endl;
        ASSERT_STR_CONTAINS(execLog, "QualifiedName = 0:Root");
        ASSERT_STR_NOT_CONTAINS(execLog, "Failed session activation");
    }

    // Invalid password
    {
        SOPC_tools::CStringVect read_cmd({"./s2opc_read",
            "-e", "opc.tcp://localhost:55345", "--encrypt",
            "-n", "i=84",
            "--username=user", "--password=password2",
            "--user_policy_id=username_Basic256Sha256",
            "--client_cert=cert/client_public/client_2k_cert.der",
            "--client_key=cert/client_private/client_2k_key.pem",
            "--server_cert=cert/server_public/server_2k_cert.der",
            "--ca=cert/trusted/cacert.der",
            "--crl=cert/revoked/cacrl.der",
            "-a", "3"});

        string execLog(launch_and_check(read_cmd));

        // cout << "EXECLOG=<" <<execLog << ">" << endl;
        ASSERT_STR_NOT_CONTAINS(execLog, "QualifiedName = 0:Root");
        ASSERT_STR_CONTAINS(execLog, "Failed session activation");
    }

    // Invalid user
    {
        SOPC_tools::CStringVect read_cmd({"./s2opc_read",
            "-e", "opc.tcp://localhost:55345", "--encrypt",
            "-n", "i=84",
            "--username=User", "--password=password",
            "--user_policy_id=username_Basic256Sha256",
            "--client_cert=cert/client_public/client_2k_cert.der",
            "--client_key=cert/client_private/client_2k_key.pem",
            "--server_cert=cert/server_public/server_2k_cert.der",
            "--ca=cert/trusted/cacert.der",
            "--crl=cert/revoked/cacrl.der",
            "-a", "3"});

        string execLog(launch_and_check(read_cmd));

        // cout << "EXECLOG=<" <<execLog << ">" << endl;
        ASSERT_STR_NOT_CONTAINS(execLog, "QualifiedName = 0:Root");
        ASSERT_STR_CONTAINS(execLog, "Failed session activation");
    }

    // Write request to server
    // Check type SPC (BOOL)
    {
        SOPC_tools::CStringVect write_cmd({"./s2opc_write",
            "-e", "opc.tcp://localhost:55345", "--none",
            "--ca=cert/trusted/cacert.der",
            "--crl=cert/revoked/cacrl.der",
            "-n", "ns=1;s=/labelSPC/spc",
            "-t", "1",
            "1"});

        string writeLog(launch_and_check(write_cmd));
        // cout << "WRITELOG=<" <<writeLog << ">" << endl;

        ASSERT_STR_CONTAINS(writeLog, "Write node \"ns=1;s=/labelSPC/spc\", attribute 13:"); // Result OK, no error
        ASSERT_STR_CONTAINS(writeLog, "StatusCode: 0x00000000"); // OK

        SOPC_tools::CStringVect read_cmd({"./s2opc_read",
            "-e", "opc.tcp://localhost:55345", "--none",
            "--ca=cert/trusted/cacert.der",
            "--crl=cert/revoked/cacrl.der",
            "-n", "ns=1;s=/labelSPC/spc",
            "-a", "13"});

        string readLog(launch_and_check(read_cmd));
        // cout << "READLOG=<" <<readLog << ">" << endl;
        ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x00000000"); // OK
        ASSERT_EQ(server.lastWriterName, s2opc_north::unknownUserName);
    }


    // Write request to server
    // Check type DPC (Byte)
    {
        SOPC_tools::CStringVect write_cmd({"./s2opc_write",
            "-e", "opc.tcp://localhost:55345", "--none",
            "--ca=cert/trusted/cacert.der",
            "--crl=cert/revoked/cacrl.der",
            "-n", "ns=1;s=/labelDPC/dpc",
            "-t", "3",
            "17"});

        string writeLog(launch_and_check(write_cmd));
        // cout << "WRITELOG=<" <<writeLog << ">" << endl;

        ASSERT_STR_CONTAINS(writeLog, "Write node \"ns=1;s=/labelDPC/dpc\", attribute 13:"); // Result OK, no error
        ASSERT_STR_CONTAINS(writeLog, "StatusCode: 0x00000000"); // OK

        SOPC_tools::CStringVect read_cmd({"./s2opc_read",
            "-e", "opc.tcp://localhost:55345", "--none",
            "--ca=cert/trusted/cacert.der",
            "--crl=cert/revoked/cacrl.der",
            "-n", "ns=1;s=/labelDPC/dpc",
            "-a", "13"});

        string readLog(launch_and_check(read_cmd));
        // cout << "READLOG=<" <<readLog << ">" << endl;
        ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x00000000"); // OK
        ASSERT_STR_CONTAINS(readLog, "Value: 17"); // Written value
        ASSERT_EQ(server.lastWriterName, s2opc_north::unknownUserName);
    }

    // Write request to server
    // Check with non-anonymous login
    {
        SOPC_tools::CStringVect write_cmd({"./s2opc_write",
            "-e", "opc.tcp://localhost:55345", "--encrypt",
            "--username=user2", "--password=xGt4sdE3Z+",
            "--user_policy_id=username_Basic256Sha256",
            "--client_cert=cert/client_public/client_2k_cert.der",
            "--client_key=cert/client_private/client_2k_key.pem",
            "--server_cert=cert/server_public/server_2k_cert.der",
            "--ca=cert/trusted/cacert.der",
            "--crl=cert/revoked/cacrl.der",
            "-n", "ns=1;s=/labelDPC/dpc",
            "-t", "3",
            "18"});

        string writeLog(launch_and_check(write_cmd));
        // cout << "WRITELOG=<" <<writeLog << ">" << endl;

        ASSERT_STR_CONTAINS(writeLog, "Write node \"ns=1;s=/labelDPC/dpc\", attribute 13:"); // Result OK, no error
        ASSERT_STR_CONTAINS(writeLog, "StatusCode: 0x00000000"); // OK
        ASSERT_EQ(server.lastWriterName, "user2");

        SOPC_tools::CStringVect read_cmd({"./s2opc_read",
            "-e", "opc.tcp://localhost:55345", "--none",
            "--ca=cert/trusted/cacert.der",
            "--crl=cert/revoked/cacrl.der",
            "-n", "ns=1;s=/labelDPC/dpc",
            "-a", "13"});

        string readLog(launch_and_check(read_cmd));
        // cout << "READLOG=<" <<readLog << ">" << endl;
        ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x00000000"); // OK
        ASSERT_STR_CONTAINS(readLog, "Value: 18"); // Written value
    }

    // Read request to server
    // Check type MVF (float / Read only)
    {
        SOPC_tools::CStringVect write_cmd({"./s2opc_write",
            "-e", "opc.tcp://localhost:55345", "--none",
            "--ca=cert/trusted/cacert.der",
            "--crl=cert/revoked/cacrl.der",
            "-n", "ns=1;s=/labelMVF/mvf",
            "-t", "10",
            "3.14"});

        string writeLog(launch_and_check(write_cmd));
        // cout << "WRITELOG=<" <<writeLog << ">" << endl;

        ASSERT_STR_CONTAINS(writeLog, "Write node \"ns=1;s=/labelMVF/mvf\", attribute 13:"); // Result OK, no error
        ASSERT_STR_CONTAINS(writeLog, "StatusCode: 0x803B0000"); // NOde not writeable
    }

    // Read request to server
    // Check type APC (float)
    {
        SOPC_tools::CStringVect write_cmd({"./s2opc_write",
            "-e", "opc.tcp://localhost:55345", "--none",
            "--ca=cert/trusted/cacert.der",
            "--crl=cert/revoked/cacrl.der",
            "-n", "ns=1;s=/labelAPC/apc",
            "-t", "10",
            "3.14"});

        string writeLog(launch_and_check(write_cmd));
        // cout << "WRITELOG=<" <<writeLog << ">" << endl;

        ASSERT_STR_CONTAINS(writeLog, "Write node \"ns=1;s=/labelAPC/apc\", attribute 13:"); // Result OK, no error
        ASSERT_STR_CONTAINS(writeLog, "StatusCode: 0x00000000");

        SOPC_tools::CStringVect read_cmd({"./s2opc_read",
            "-e", "opc.tcp://localhost:55345", "--none",
            "--ca=cert/trusted/cacert.der",
            "--crl=cert/revoked/cacrl.der",
            "-n", "ns=1;s=/labelAPC/apc",
            "-a", "13"});

        string readLog(launch_and_check(read_cmd));
        // cout << "READLOG=<" <<readLog << ">" << endl;
        ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x00000000"); // OK
        ASSERT_STR_CONTAINS(readLog, "Value: 3.14"); // Written value
    }

    // Read request to server
    // Check type INC (INT32)
    {
        SOPC_tools::CStringVect write_cmd({"./s2opc_write",
            "-e", "opc.tcp://localhost:55345", "--none",
            "--ca=cert/trusted/cacert.der",
            "--crl=cert/revoked/cacrl.der",
            "-n", "ns=1;s=/labelINC/inc",
            "-t", "6",
            "314"});

        string writeLog(launch_and_check(write_cmd));
        // cout << "WRITELOG=<" <<writeLog << ">" << endl;

        ASSERT_STR_CONTAINS(writeLog, "Write node \"ns=1;s=/labelINC/inc\", attribute 13:"); // Result OK, no error
        ASSERT_STR_CONTAINS(writeLog, "StatusCode: 0x00000000");

        SOPC_tools::CStringVect read_cmd({"./s2opc_read",
            "-e", "opc.tcp://localhost:55345", "--none",
            "--ca=cert/trusted/cacert.der",
            "--crl=cert/revoked/cacrl.der",
            "-n", "ns=1;s=/labelINC/inc",
            "-a", "13"});

        string readLog(launch_and_check(read_cmd));
        // cout << "READLOG=<" <<readLog << ">" << endl;
        ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x00000000"); // OK
        ASSERT_STR_CONTAINS(readLog, "Value: 314"); // Written value
    }

    // Check (uninitialized) Analog value
    {
        SOPC_tools::CStringVect read_cmd({"./s2opc_read",
            "-e", "opc.tcp://localhost:55345", "--none",
            "--ca=cert/trusted/cacert.der",
            "--crl=cert/revoked/cacrl.der",
            "-n", "ns=1;s=/labelMVA/mva",
            "-a", "13"});

        string readLog(launch_and_check(read_cmd));
        // cout << "READLOG=<" <<readLog << ">" << endl;
        ASSERT_STR_CONTAINS(readLog, "StatusCode: 0x00000000");
        ASSERT_STR_CONTAINS(readLog, "Value: 560");
    }
    server.stop();
};

TEST(S2OPCUA, OPCUA_Server_MissingFile) {
    ERROR("*** TEST S2OPCUA OPCUA_Server_MissingFile");
    //ASSERT_C_RAISES_ASSERTION_START;

    ASSERT_C_RAISES_ASSERTION_START;

    ConfigCategory testConf;
    testConf.addItem("logging", "Configure S2OPC logging level", "Info",
            "Info", {"None", "Error", "Warning", "Info", "Debug"});
    testConf.addItem("exchanged_data", "exchanged_data", "JSON", config_exData,
            config_exData);
    testConf.addItem("protocol_stack", "protocol_stack", "JSON", protocolMissingFile,
            protocolMissingFile);

    s2opc_north::OPCUA_Server::uninitialize(); // Ensure no previous server still exists
    OPCUA_Server_Test server(testConf);
    ASSERT_C_RAISES_ASSERTION_END;

    OPCUA_Server::uninitialize();

}

