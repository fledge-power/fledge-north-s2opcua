#include <plugin_api.h>
#include <string.h>
#include <string>
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

static const string protocolJson1 =
        QUOTE({"protocol_stack" : { "name" : "s2opcserver",\
                "version":"1.0", \
                "transport_layer":{ \
                    "url" : "opc.tcp://localhost:4841", \
                    "appUri" : "urn:S2OPC:localhost", \
                    "productUri" : "urn:S2OPC:localhost", \
                    "appDescription": "Application description", \
                    "localeId" : "en-US", \
                    "namespaces" : [ "urn:S2OPC:localhost" ], \
                    "policies" : [ \
                      { "securityMode" : "None", "securityPolicy" : "None", "userPolicies" : [ "anonymous" ] },\
                      { "securityMode" : "Sign", "securityPolicy" : "Basic256", "userPolicies" : [ "anonymous", "username" ] }, \
                      { "securityMode" : "SignAndEncrypt", "securityPolicy" : "Basic256Sha256", "userPolicies" : \
                        [ "anonymous", "anonymous", "username_Basic256Sha256", "username_None" ] } ], \
                    "users" : {"user" : "password", "user2" : "xGt4sdE3Z+" }, \
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

TEST(S2OPCUA, OpcUa_Protocol) {
    OpcUa_Protocol* proto = NULL;
    ASSERT_NO_THROW(proto = new OpcUa_Protocol(protocolJson1));
    ASSERT_NO_THROW(delete proto);
    ASSERT_NO_THROW(proto = new OpcUa_Protocol(protocolJson2));
    ASSERT_NO_THROW(delete proto);
    ASSERT_THROW(proto = new OpcUa_Protocol(protocolJson3), exception);
    ASSERT_THROW(proto = new OpcUa_Protocol(protocolJson4), exception);

}
