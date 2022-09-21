#include <gtest/gtest.h>
#include <plugin_api.h>
#include <string.h>
#include <string>
#include <rapidjson/document.h>

extern "C" {
// S2OPC Headers
#include "sopc_assert.h"
#include "sopc_log_manager.h"
}

// Tested files
#include "opcua_server_tools.h"

using namespace std;
using namespace rapidjson;


extern "C" {
	PLUGIN_INFORMATION *plugin_info();
};

TEST(S2OPCUA, PluginInfo) {
	PLUGIN_INFORMATION *info = plugin_info();
	ASSERT_STREQ(info->name, "s2opcua");
	ASSERT_STREQ(info->type, PLUGIN_TYPE_NORTH);
}

TEST(S2OPCUA, PluginInfoConfigParse) {
	PLUGIN_INFORMATION *info = plugin_info();
	Document doc;
	doc.Parse(info->config);
	ASSERT_EQ(doc.HasParseError(), false);
	ASSERT_EQ(doc.IsObject(), true);
    ASSERT_EQ(doc.HasMember("plugin"), true);
    ASSERT_EQ(doc.HasMember("protocol_stack"), true);
    ASSERT_EQ(doc.HasMember("exchanged_data"), true);
}

TEST(S2OPCUA, ServerToolsHelpers) {
    using namespace SOPC_tools;

    ASSERT_ANY_THROW(ASSERT(false, "Test that assert throws"));
    ASSERT_NO_THROW(ASSERT(10 + 10 < 25));

    // loggableString
    const std::string strOK1("No problem/+'9? ");
    const std::string strNOK1("No problèem/+'9? ");
    ASSERT_EQ(loggableString(strOK1), strOK1);
    ASSERT_EQ(loggableString(strNOK1), strOK1);

    // statusCodeToCString
    ASSERT_STREQ(statusCodeToCString(SOPC_STATUS_OK), "SOPC_STATUS_OK");
    ASSERT_STREQ(statusCodeToCString(SOPC_STATUS_NOK), "SOPC_STATUS_NOK");
    ASSERT_STREQ(statusCodeToCString(SOPC_STATUS_INVALID_PARAMETERS), "SOPC_STATUS_INVALID_PARAMETERS");
    ASSERT_STREQ(statusCodeToCString(SOPC_STATUS_INVALID_STATE), "SOPC_STATUS_INVALID_STATE");
    ASSERT_STREQ(statusCodeToCString(SOPC_STATUS_ENCODING_ERROR), "SOPC_STATUS_ENCODING_ERROR");
    ASSERT_STREQ(statusCodeToCString(SOPC_STATUS_WOULD_BLOCK), "SOPC_STATUS_WOULD_BLOCK");
    ASSERT_STREQ(statusCodeToCString(SOPC_STATUS_TIMEOUT), "SOPC_STATUS_TIMEOUT");
    ASSERT_STREQ(statusCodeToCString(SOPC_STATUS_OUT_OF_MEMORY), "SOPC_STATUS_OUT_OF_MEMORY");
    ASSERT_STREQ(statusCodeToCString(SOPC_STATUS_CLOSED), "SOPC_STATUS_CLOSED");
    ASSERT_STREQ(statusCodeToCString(SOPC_STATUS_NOT_SUPPORTED), "SOPC_STATUS_NOT_SUPPORTED");
    ASSERT_STREQ(statusCodeToCString(-1), "Invalid code");

    // toUpperString
    ASSERT_EQ(toUpperString("Hello World!09"), "HELLO WORLD!09");

    // JSON helpers
    Document doc;
    doc.Parse("{\"a\":{\"b\":\"B\", \"c\":[\"C1\", \"C2\"]}}");
    ASSERT_EQ(doc.HasParseError(), false);
    ASSERT_EQ(doc.IsObject(), true);
    const Value& root(doc.GetObject());
    ASSERT_NO_THROW(checkObject(root, ""));

    const Value& vA(getObject(root, "a", "a"));
    ASSERT_EQ(SOPC_tools::getString(vA["b"], "b"), "B");
    ASSERT_EQ(SOPC_tools::getString(vA, "b", "a"), "B");

    const Value::ConstArray& vC(getArray(vA, "c", "c"));
    ASSERT_EQ(getString(vC[0], "c1"), "C1");
    ASSERT_EQ(getString(vC[1], "c2"), "C2");

    // SOPC helpers
    SOPC_NodeId* nodeId = createNodeId("ns=3;s=anything");
    ASSERT_NE(nullptr, nodeId);
    ASSERT_EQ(toString(*nodeId), "ns=3;s=anything");
    delete nodeId;

    ASSERT_EQ(toSOPC_Log_Level("DeBug"), SOPC_LOG_LEVEL_DEBUG);
    ASSERT_EQ(toSOPC_Log_Level("What"), SOPC_LOG_LEVEL_INFO);

    ASSERT_EQ(toBuiltinId("Boolean_Id"), SOPC_Boolean_Id);
    ASSERT_ANY_THROW(toBuiltinId("BadId"));

    ASSERT_EQ(pivotTypeToReadOnly("SpcTyp"), false);
    ASSERT_EQ(pivotTypeToReadOnly("SpsTyp"), true);

    ASSERT_EQ(toSecurityPolicy("Basic256"), SOPC_SecurityPolicy_Basic256);
    ASSERT_ANY_THROW(toSecurityPolicy("Basic266"));

    ASSERT_EQ(toSecurityMode("SiGn"), SOPC_SecurityModeMask_Sign);
    ASSERT_ANY_THROW(toSecurityMode("Basic256"));

    ASSERT_EQ(toUserToken("anonymous"), &SOPC_UserTokenPolicy_Anonymous);
    ASSERT_EQ(toUserToken("username_None"), &SOPC_UserTokenPolicy_UserName_NoneSecurityPolicy);
    ASSERT_EQ(toUserToken("username"), &SOPC_UserTokenPolicy_UserName_DefaultSecurityPolicy);
    ASSERT_EQ(toUserToken("username_Basic256Sha256"), &SOPC_UserTokenPolicy_UserName_Basic256Sha256SecurityPolicy);
    ASSERT_EQ(toUserToken("BadToken"), nullptr);
}

TEST(S2OPCUA, CStringVect) {
    using namespace SOPC_tools;

    {
        CStringVect cVect({"str1", "str2"});
        ASSERT_EQ(cVect.size, 2);
        ASSERT_EQ(cVect.cppVect.size(), 2);
        ASSERT_EQ(cVect.cppVect[0], "str1");
        ASSERT_STREQ(cVect.cVect[0], "str1");
        ASSERT_STREQ(cVect.vect[1], "str2");
        ASSERT_STREQ(cVect.vect[2], nullptr);
    }

    {
        Document doc;
        doc.Parse("{\"a\":{\"b\":\"B\", \"c\":[\"C1\", \"C2\"]}}");
        ASSERT_EQ(doc.HasParseError(), false);
        CStringVect cVect(doc["a"]["c"], "No context");
        ASSERT_EQ(cVect.size, 2);
        ASSERT_EQ(cVect.cppVect.size(), 2);
        ASSERT_EQ(cVect.cppVect[0], "C1");
        ASSERT_STREQ(cVect.cVect[0], "C1");
        ASSERT_STREQ(cVect.vect[1], "C2");
        ASSERT_STREQ(cVect.vect[2], nullptr);
    }
}



