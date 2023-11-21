#include <plugin_api.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>
#include <string>
#include <algorithm>
#include <rapidjson/document.h>
#include <gtest/gtest.h>

extern "C" {
// S2OPC Headers
#include "opcua_statuscodes.h"
#include "sopc_assert.h"
#include "sopc_log_manager.h"
}

// Tested files
#include "opcua_server_tools.h"
#include "opcua_server_config.h"

#include "main_test_configs.h"

#define ASSERT_SOPC_STREQ(a,b) ASSERT_STREQ((const char*)a.Data, b);
using namespace std;
using namespace rapidjson;
using namespace s2opc_north;
using rapidjson::Value;

static const string exDataJson =
        QUOTE({\
    "ok1" : {"name":"opcua", "address":"S_1145_6_21_28","typeid":"Boolean_Id"}, \
    "ko1" : {"name":"iec104", "address":"S_1145_6_21_28","typeid":"Boolean_Id"}, \
    "ko3" : {"address":"S_1145_6_21_28","typeid":"Boolean_Id"}, \
    "ko4" : {"name":["opcua"], "address":"S_1145_6_21_28","typeid":"Boolean_Id"}, \
    "ko5" : {"name":"opcua", "address":33,"typeid":"Boolean_Id"}, \
    "ko6" : {"name":"opcua","typeid":"Boolean_Id"}, \
    "ko7" : {"name":"opcua", "address":"S_1145_6_21_28","typeid":32}, \
    "ko8" : {"name":"opcua", "address":"S_1145_6_21_28"}, \
    "ko" : ["name" ,"typeid"] \
    });


TEST(S2OPCUA, ExchangedDataC) {
    ERROR("*** TEST S2OPCUA ExchangedDataC");
    ASSERT_NO_C_ASSERTION;

    ExchangedDataC* pdata = nullptr;
    rapidjson::Document doc;
    Logger::getLogger()->debug("Parsing ExchangedDataC '%s'", exDataJson.c_str());
    ASSERT_NO_THROW(doc.Parse(exDataJson.c_str()));
    Logger::getLogger()->debug("Parsing ExchangedDataC OK!");
    ASSERT_EQ(doc.HasParseError(), false);

    // test a valid case
    {
        const Value& jValue(SOPC_tools::getObject(doc, "ok1", "ok1"));
        ASSERT_TRUE(jValue.IsObject());
        ASSERT_NO_THROW(pdata = new ExchangedDataC(jValue));
        ASSERT_EQ(pdata->address, "S_1145_6_21_28");
        ASSERT_EQ(pdata->typeId, "Boolean_Id");
        delete pdata;
    }

    ASSERT_THROW(ExchangedDataC(SOPC_tools::getObject(doc, "ko1", "bad protocol")), ExchangedDataC::NotAnS2opcInstance);
    ASSERT_NO_THROW(SOPC_tools::getObject(doc, "ko3", "missing protocol"));
    ASSERT_THROW(ExchangedDataC(SOPC_tools::getObject(doc, "ko3", "missing protocol")), exception);
    ASSERT_THROW(ExchangedDataC(SOPC_tools::getObject(doc, "ko4", "bad protocol type")), exception);
    ASSERT_THROW(ExchangedDataC(SOPC_tools::getObject(doc, "ko5", "bad address type")), exception);
    ASSERT_THROW(ExchangedDataC(SOPC_tools::getObject(doc, "ko6", "bad address type")), exception);
    ASSERT_THROW(ExchangedDataC(SOPC_tools::getObject(doc, "ko7", "bad typeid type")), exception);
    ASSERT_THROW(ExchangedDataC(SOPC_tools::getObject(doc, "ko8", "bad typeid type")), exception);
    ASSERT_THROW(SOPC_tools::getObject(doc, "ko", "not an object object"), exception);
}

static const string protocolJson2 =
        QUOTE({"protocol_stack" : { "name" : "s2opcserver",\
                "version":"1.0", \
                "transport_layer":{ \
                    "url" : "opc.tcp://localhost:4841", \
                    "appUri" : "appUri", \
                    "productUri" : "productUri", \
                    "appDescription": "appDescription", \
                    "localeId" : "en-US", \
                    "namespaces" : [ "urn:S2OPC:localhost" ], \
                    "policies" : [ \
                      { "securityMode" : "None", "securityPolicy" : "None", "userPolicies" : [ "anonymous" ] } ], \
                    "users" : {}, \
                    "certificates" : { \
                        "serverCertPath" : "server_2k_cert.der", \
                        "serverKeyPath" : "server_2k_key.pem", \
                        "trusted_root" : [ "cacert.der" ],  \
                        "trusted_intermediate" : [ ], \
                        "revoked" : [ "cacrl.der" ], \
                        "untrusted_root" : [ ], \
                        "untrusted_intermediate" : [ ], \
                        "issued" : [  ] } \
                  } \
              } });
static const string protocolJson3 = // Missing "appUri"
        QUOTE({"protocol_stack" : { "name" : "s2opcserver",\
                "version":"1.0", \
                "transport_layer":{ \
                    "url" : "opc.tcp://localhost:4841", \
                    "productUri" : "productUri", \
                    "appDescription": "appDescription", \
                    "localeId" : "en-US", \
                    "namespaces" : [ "urn:S2OPC:localhost" ], \
                    "policies" : [ \
                      { "securityMode" : "None", "securityPolicy" : "None", "userPolicies" : [ "anonymous" ] } ], \
                    "users" : {}, \
                    "certificates" : { \
                        "serverCertPath" : "server_2k_cert.der", \
                        "serverKeyPath" : "server_2k_key.pem", \
                        "trusted_root" : [ "cacert.der" ],  \
                        "trusted_intermediate" : [ ], \
                        "revoked" : [ "cacrl.der" ], \
                        "untrusted_root" : [ ], \
                        "untrusted_intermediate" : [ ], \
                        "issued" : [  ] } \
                  } \
              } });
static const string protocolJson4 = // Invalid issued certificate
        QUOTE({"protocol_stack" : { "name" : "s2opcserver",\
                "version":"1.0", \
                "transport_layer":{ \
                    "url" : "opc.tcp://localhost:4840", \
                    "appUri" : "appUri", \
                    "productUri" : "productUri", \
                    "appDescription": "appDescription", \
                    "localeId" : "en-US", \
                    "namespaces" : [ "urn:S2OPC:localhost" ], \
                    "policies" : [ \
                      { "securityMode" : "None", "securityPolicy" : "None", "userPolicies" : [ "anonymous" ] } ], \
                    "users" : {}, \
                    "certificates" : { \
                        "serverCertPath" : "", \
                        "serverKeyPath" : "", \
                        "trusted_root" : [ ],  \
                        "trusted_intermediate" : [ ], \
                        "revoked" : [ ], \
                        "untrusted_root" : [ ], \
                        "untrusted_intermediate" : [ ], \
                        "issued" : "" } \
                  } \
              } });
static const string protocolJson5 = // Invalid policies
        QUOTE({"protocol_stack" : { "name" : "s2opcserver",\
                "version":"1.0", \
                "transport_layer":{ \
                    "url" : "opc.tcp://localhost:4840", \
                    "appUri" : "appUri", \
                    "productUri" : "productUri", \
                    "appDescription": "appDescription", \
                    "localeId" : "en-US", \
                    "namespaces" : [ "urn:S2OPC:localhost" ], \
                    "policies" : [ \
                      { "securityMode" : "Unknown", "securityPolicy" : "None", "userPolicies" : [ "anonymous" ] } ], \
                    "users" : {}, \
                    "certificates" : { \
                        "serverCertPath" : "", \
                        "serverKeyPath" : "", \
                        "trusted_root" : [ ],  \
                        "trusted_intermediate" : [ ], \
                        "revoked" : [ ], \
                        "untrusted_root" : [ ], \
                        "untrusted_intermediate" : [ ], \
                        "issued" : "" } \
                  } \
              } });
static const string protocolJsonNoAppURI =
        QUOTE({"protocol_stack" : { "name" : "s2opcserver",\
                "version":"1.0", \
                "transport_layer":{ \
                    "url" : "opc.tcp://localhost:4841", \
                    "appUri" : "", \
                    "productUri" : "", \
                    "appDescription": "", \
                    "localeId" : "en-US", \
                    "namespaces" : [ "urn:S2OPC:localhost" ], \
                    "policies" : [ \
                      { "securityMode" : "None", "securityPolicy" : "None", "userPolicies" : [ "anonymous" ] } ], \
                    "users" : {}, \
                    "certificates" : { \
                        "serverCertPath" : "server_2k_cert.der",        \
                        "serverKeyPath" : "server_2k_key.pem", \
                        "trusted_root" : [ "cacert.der" ],  \
                        "trusted_intermediate" : [ ], \
                        "revoked" : [ "cacrl.der" ], \
                        "untrusted_root" : [ ], \
                        "untrusted_intermediate" : [ ], \
                        "issued" : [  ] } \
                  } \
              } });
static const string protocolJsonNoProductURI =
        QUOTE({"protocol_stack" : { "name" : "s2opcserver",\
                "version":"1.0", \
                "transport_layer":{ \
                    "url" : "opc.tcp://localhost:4841", \
                    "appUri" : "appURI", \
                    "productUri" : "", \
                    "appDescription": "", \
                    "localeId" : "en-US", \
                    "namespaces" : [ "urn:S2OPC:localhost" ], \
                    "policies" : [ \
                      { "securityMode" : "None", "securityPolicy" : "None", "userPolicies" : [ "anonymous" ] } ], \
                    "users" : {}, \
                    "certificates" : { \
                        "serverCertPath" : "server_2k_cert.der",        \
                        "serverKeyPath" : "server_2k_key.pem", \
                        "trusted_root" : [ "cacert.der" ],  \
                        "trusted_intermediate" : [ ], \
                        "revoked" : [ "cacrl.der" ], \
                        "untrusted_root" : [ ], \
                        "untrusted_intermediate" : [ ], \
                        "issued" : [  ] } \
                  } \
              } });
static const string protocolJsonNoAppDesc =
        QUOTE({"protocol_stack" : { "name" : "s2opcserver",\
                "version":"1.0", \
                "transport_layer":{ \
                    "url" : "opc.tcp://localhost:4841", \
                    "appUri" : "appURI", \
                    "productUri" : "productURI", \
                    "appDescription": "", \
                    "localeId" : "en-US", \
                    "namespaces" : [ "urn:S2OPC:localhost" ], \
                    "policies" : [ \
                      { "securityMode" : "None", "securityPolicy" : "None", "userPolicies" : [ "anonymous" ] } ], \
                    "users" : {}, \
                    "certificates" : { \
                        "serverCertPath" : "server_2k_cert.der",        \
                        "serverKeyPath" : "server_2k_key.pem", \
                        "trusted_root" : [ "cacert.der" ],  \
                        "trusted_intermediate" : [ ], \
                        "revoked" : [ "cacrl.der" ], \
                        "untrusted_root" : [ ], \
                        "untrusted_intermediate" : [ ], \
                        "issued" : [  ] } \
                  } \
              } });


static string strReplacer(const string& src, const string& textOld, const string& textNew) {
    size_t pos = src.find(textOld);
    if (pos == string::npos) return src;
    string result(src);
    result.replace(pos, pos + textOld.length() - 1, textNew);
    return result;
}

static const string protocolJson6 = strReplacer(protocolJsonOK, "protocol_stack", "PROTO");
static const string protocolJson7 = strReplacer(protocolJsonOK, "server_2k_cert.der", "nocertxxx.der");
static const string protocolJson8 = strReplacer(protocolJsonOK, "server_2k_key.pem", "nocertxxx.pem");
static const string protocolJson9 = strReplacer(protocolJsonOK, "cacert.der", "nocert.der");
static const string protocolJson10 = strReplacer(protocolJsonOK, "transport_layer", "transport_layerXXX");
static const string protocolJson11 = strReplacer(protocolJsonOK, "username_None", "username_NoneXXX");

TEST(S2OPCUA, OpcUa_Protocol) {
    ERROR("*** TEST S2OPCUA OpcUa_Protocol");
    ASSERT_NO_C_ASSERTION;

    int abortReceived = setjmp(abort_jump_env);
    ASSERT_EQ(abortReceived, 0);

    OpcUa_Protocol* proto = NULL;
    SOPC_Endpoint_Config ep;
    memset(&ep, 0, sizeof(ep));

    ep.endpointURL = strdup("opc.tcp://localhost:4841");

    ep.hasDiscoveryEndpoint = false;
    ep.serverConfigPtr = new SOPC_Server_Config;
    memset(ep.serverConfigPtr, 0, sizeof(SOPC_Server_Config));


    // Check correct configuration
    ASSERT_NO_THROW(proto = new OpcUa_Protocol(protocolJsonOK));
    proto->setupServerSecurity(&ep);
    ASSERT_EQ(ep.serverConfigPtr->nbEndpoints, 0);
    ASSERT_EQ(ep.nbSecuConfigs, 3);

    /////////////////
    // Check policies
    const SOPC_SecurityPolicy* secPol(ep.secuConfigurations);
    /* Reminder:
             "policies" : [ \
          { "securityMode" : "None", "securityPolicy" : "None", "userPolicies" : [ "anonymous" ] },\
          { "securityMode" : "Sign", "securityPolicy" : "Basic256", "userPolicies" : [ "anonymous", "username" ] }, \
          { "securityMode" : "SignAndEncrypt", "securityPolicy" : "Basic256Sha256", "userPolicies" : \
            [ "anonymous", "anonymous", "username_Basic256Sha256", "username_None" ] } ], \
        "users" : {"user" : "password", "user2" : "xGt4sdE3Z+" }, \
     */
    ASSERT_EQ(secPol->nbOfUserTokenPolicies, 1);
    ASSERT_SOPC_STREQ(secPol->userTokenPolicies[0].PolicyId, "anonymous");
    ASSERT_EQ(secPol->securityModes, SOPC_SECURITY_MODE_NONE_MASK);
    ASSERT_SOPC_STREQ(secPol->securityPolicy, SOPC_SecurityPolicy_None_URI);

    secPol++;
    ASSERT_EQ(secPol->nbOfUserTokenPolicies, 2);
    ASSERT_SOPC_STREQ(secPol->userTokenPolicies[1].PolicyId, "username");
    ASSERT_EQ(secPol->securityModes, SOPC_SECURITY_MODE_SIGN_MASK);
    ASSERT_SOPC_STREQ(secPol->securityPolicy, SOPC_SecurityPolicy_Basic256_URI);

    secPol++;
    ASSERT_EQ(secPol->nbOfUserTokenPolicies, 4);
    ASSERT_SOPC_STREQ(secPol->userTokenPolicies[3].PolicyId, "username_None");
    ASSERT_EQ(secPol->securityModes, SOPC_SECURITY_MODE_SIGNANDENCRYPT_MASK);
    ASSERT_SOPC_STREQ(secPol->securityPolicy, SOPC_SecurityPolicy_Basic256Sha256_URI);
    ASSERT_NO_THROW(delete proto);

    ASSERT_NO_THROW(proto = new OpcUa_Protocol(protocolJson2));
    ASSERT_NO_THROW(delete proto);

    ASSERT_THROW(proto = new OpcUa_Protocol(protocolJson3), exception);
    ASSERT_THROW(proto = new OpcUa_Protocol(protocolJson4), exception);
    ASSERT_THROW(proto = new OpcUa_Protocol(protocolJson5), exception);
    ASSERT_THROW(proto = new OpcUa_Protocol(protocolJson6), exception);
    ASSERT_THROW(proto = new OpcUa_Protocol(protocolJson7), exception);
    ASSERT_THROW(proto = new OpcUa_Protocol(protocolJson8), exception);
    ASSERT_THROW(proto = new OpcUa_Protocol(protocolJson9), exception);
    ASSERT_THROW(proto = new OpcUa_Protocol(protocolJson10), exception);
    ASSERT_THROW(proto = new OpcUa_Protocol(protocolJson11), exception);
    ASSERT_THROW(proto = new OpcUa_Protocol(protocolJsonNoAppURI), exception);
    ASSERT_THROW(proto = new OpcUa_Protocol(protocolJsonNoProductURI), exception);
    ASSERT_THROW(proto = new OpcUa_Protocol(protocolJsonNoAppDesc), exception);
}

TEST(S2OPCUA, OpcUa_Server_Config) {
    ERROR("*** TEST S2OPCUA OpcUa_Server_Config");
    ASSERT_NO_C_ASSERTION;

    int abortReceived = setjmp(abort_jump_env);
    ASSERT_EQ(abortReceived, 0);

    ConfigCategory testConf;
    testConf.addItem("logging", "Configure S2OPC logging level", "Info",
            "Info", {"None", "Error", "Warning", "Info", "Debug"});
    testConf.addItem("exchanged_data", "exchanged_data", config_exData,
            config_exData, {"None", "Error", "Warning", "Info", "Debug"});
    OpcUa_Server_Config config(testConf);

    ASSERT_TRUE(config.withLogs);
    ASSERT_EQ(config.logLevel, SOPC_LOG_LEVEL_INFO);
    NodeVect_t::const_iterator it;

    // Check that the nodes provided in configuration are in address space
    const SOPC_AddressSpace_Node* pNode = nullptr;

    it = findNodeInASpc(config.addrSpace, "ns=1;s=dps/Value");
    GTEST_ASSERT_NE(it, config.addrSpace.getNodes().end());

    {
        const NodeInfo_t& nodeInfo(*it);
        pNode = nodeInfo.mNode;
        GTEST_ASSERT_NE(nodeInfo.mNode, nullptr);

        ASSERT_EQ(pNode->node_class, OpcUa_NodeClass_Variable);
        ASSERT_EQ(nodeInfo.mContext.mPivotType, ""); // Only TC are filled up
        ASSERT_EQ(nodeInfo.mContext.mOpcParentAddress, "dps");
        ASSERT_EQ(nodeInfo.mContext.mPivotId, "pivotDPS");
        ASSERT_EQ(nodeInfo.mContext.mEvent, we_Read_Only);
        ASSERT_EQ(SOPC_tools::toString(pNode->data.variable.NodeId), "ns=1;s=dps/Value");
    }

    it = findNodeInASpc(config.addrSpace, "ns=1;s=dps");
    GTEST_ASSERT_NE(it, config.addrSpace.getNodes().end());
    {
        const NodeInfo_t& nodeInfo(*it);
        pNode = nodeInfo.mNode;
        GTEST_ASSERT_NE(nodeInfo.mNode, nullptr);

        ASSERT_EQ(pNode->node_class, OpcUa_NodeClass_Object);
        ASSERT_EQ(nodeInfo.mContext.mPivotType, "");  // Folder objects are unnamed
        ASSERT_EQ(SOPC_tools::toString(pNode->data.object.NodeId), "ns=1;s=dps");
    }

    // Additional defaults to increase coverage
    {
        using s2opc_north::OpcUa_Protocol;
        ConfigCategory testConf2;
        testConf2.addItem("exchanged_data", "exchanged_data", config_exData,
                config_exData, {"None", "Error", "Warning", "Info", "Debug"});
        ASSERT_ANY_THROW(OpcUa_Server_Config config2(testConf2));

        OpcUa_Protocol* proto = nullptr;
        string sTest;

        // full section missing
        sTest = replace_in_string(protocolJsonOK, QUOTE("protocol_stack"), QUOTE("protocol_stak"));
        ASSERT_ANY_THROW(proto = new OpcUa_Protocol(sTest));
        sTest = QUOTE({"protocol_stack" : 33});
        ASSERT_ANY_THROW(proto = new OpcUa_Protocol(sTest));
        sTest = replace_in_string(protocolJsonOK, QUOTE("transport_layer"), QUOTE("transport_layers"));
        ASSERT_ANY_THROW(proto = new OpcUa_Protocol(sTest));
        sTest = replace_in_string(protocolJsonOK, QUOTE("transport_layer"), QUOTE("transport_layers" : 33, "x"));
        ASSERT_ANY_THROW(proto = new OpcUa_Protocol(sTest));

        // Bad user policy
        sTest = replace_in_string(protocolJsonOK, QUOTE("username_Basic256Sha256"), QUOTE("username_Basic256Sha257"));
        ASSERT_ANY_THROW(proto = new OpcUa_Protocol(sTest));

        // String array section missing
        sTest = replace_in_string(protocolJsonOK, QUOTE("trusted_root"), QUOTE("trusted_rooot"));
        ASSERT_ANY_THROW(proto = new OpcUa_Protocol(sTest));

        // String array section contains non-string elements
        sTest = replace_in_string(protocolJsonOK, QUOTE("cacrl.der"), QUOTE("cacrl.der", 3.14));
        ASSERT_ANY_THROW(proto = new OpcUa_Protocol(sTest));

        // String array section is not an array
        sTest = replace_in_string(protocolJsonOK, QUOTE(\\[ "cacrl.der" \\]), QUOTE("cacrl.der"));
        ASSERT_ANY_THROW(proto = new OpcUa_Protocol(sTest));

        // Bad User section
        sTest = replace_in_string(protocolJsonOK, "\"users\" *: *\\{[^\\}]*\\}", QUOTE("users" : ""));
        ASSERT_ANY_THROW(proto = new OpcUa_Protocol(sTest));

        // Missing file
        sTest = replace_in_string(protocolJsonOK, "server_2k_cert.der", "server_2k_certs.der");
        ASSERT_ANY_THROW(proto = new OpcUa_Protocol(sTest));
        sTest = replace_in_string(protocolJsonOK, "server_2k_key.pem", "server_2k_keys.pem");
        ASSERT_ANY_THROW(proto = new OpcUa_Protocol(sTest));
    }
    // Bad protocol
    {
        OpcUa_Server_Config* config2;
        ConfigCategory testConf2;
        static const std::string config_exData2 = QUOTE({"exchanged_data" : {
                    "name" : "data1",
                    "version" : "1.0",
                    "datapoints" : [{"label":"l","pivot_id":"p","pivot_type": "t","protocols":[33]}]
        }});
        testConf2.addItem("logging", "Configure S2OPC logging level", "Info",
                "Info", {"None", "Error", "Warning", "Info", "Debug"});
        testConf2.addItem("exchanged_data", "exchanged_data", config_exData2,
                config_exData2, {"None", "Error", "Warning", "Info", "Debug"});
        ASSERT_ANY_THROW(config2 = new OpcUa_Server_Config(testConf2));
    }
}
