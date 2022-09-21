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
#include "opcua_server_addrspace.h"

using namespace std;
using namespace rapidjson;
using namespace s2opc_north;

static const string nodeId("ns=1;s=something");
static const string browsename("browsename");
static const string displayName("displayName");
static const string description("description");
static const SOPC_NodeId* parentId(SOPC_tools::createNodeId("i=84"));
static const CVarInfo vInfo(nodeId, browsename, displayName, description, *parentId, true);

TEST(S2OPCUA, CVarInfo) {
    ASSERT_EQ(vInfo.mNodeId, nodeId);
    ASSERT_EQ(vInfo.mBrowseName, browsename);
    ASSERT_EQ(vInfo.mDisplayName, displayName);
    ASSERT_EQ(vInfo.mDescription, description);
    int32_t comparison = -1;
    SOPC_NodeId_Compare(&vInfo.mParentNodeId, parentId, &comparison);
    ASSERT_EQ(comparison, 0);
}

TEST(S2OPCUA, CVarNode) {
    CVarNode node(vInfo, SOPC_UInt32_Id);
    SOPC_AddressSpace_Node* aNode(node.get());
    GTEST_ASSERT_NE(nullptr, aNode);
    GTEST_ASSERT_EQ(aNode->node_class, OpcUa_NodeClass_Variable);
    GTEST_ASSERT_EQ((long long)aNode->value_status, OpcUa_BadWaitingForInitialData);
    GTEST_ASSERT_EQ((long long)aNode->value_source_ts.timestamp, 0);
    GTEST_ASSERT_EQ(aNode->data.variable.encodeableType, &OpcUa_VariableNode_EncodeableType);

    GTEST_ASSERT_EQ(SOPC_tools::toString(aNode->data.variable.NodeId), nodeId);
    GTEST_ASSERT_EQ(aNode->data.variable.NodeClass, OpcUa_NodeClass_Variable);
    GTEST_ASSERT_EQ(aNode->data.variable.BrowseName.NamespaceIndex, 1);
    ASSERT_STREQ(SOPC_String_GetRawCString(&aNode->data.variable.BrowseName.Name), browsename.c_str());

    GTEST_ASSERT_EQ(aNode->data.variable.WriteMask, 0);
    GTEST_ASSERT_EQ(aNode->data.variable.UserWriteMask, 0);
    GTEST_ASSERT_EQ(aNode->data.variable.NoOfReferences, 2);
    GTEST_ASSERT_EQ(aNode->data.variable.Value.ArrayType, SOPC_VariantArrayType_SingleValue);
    GTEST_ASSERT_EQ(aNode->data.variable.Value.BuiltInTypeId, SOPC_UInt32_Id);
    // Value irrelevant (BAD quality)
    GTEST_ASSERT_EQ(aNode->data.variable.NoOfArrayDimensions, 0);
    GTEST_ASSERT_EQ(aNode->data.variable.ArrayDimensions, nullptr);
    GTEST_ASSERT_EQ(aNode->data.variable.AccessLevel, 1);
    GTEST_ASSERT_EQ(aNode->data.variable.UserAccessLevel, 0);
}

namespace {
struct nodeVarFinder {
    nodeVarFinder(const std::string& name):m_name(name){}
    bool operator()(const SOPC_AddressSpace_Node* node){
        return node != NULL &&
                node->node_class == OpcUa_NodeClass_Variable &&
                SOPC_tools::toString(node->data.variable.NodeId) == m_name;
    }
    const std::string m_name;
};
struct nodeVarTypeFinder {
    nodeVarTypeFinder(const std::string& name):m_name(name){}
    bool operator()(const SOPC_AddressSpace_Node* node){
        return node != NULL &&
                node->node_class == OpcUa_NodeClass_VariableType &&
                SOPC_tools::toString(node->data.variable_type.NodeId) == m_name;
    }
    const std::string m_name;
};
struct nodeObjFinder {
    nodeObjFinder(const std::string& name):m_name(name){}
    bool operator()(const SOPC_AddressSpace_Node* node){
        return node != NULL &&
                node->node_class == OpcUa_NodeClass_Object &&
                SOPC_tools::toString(node->data.object.NodeId) == m_name;
    }
    const std::string m_name;
};
}  // namespace

TEST(S2OPCUA, Server_AddrSpace) {
    CVarNode node(vInfo, SOPC_UInt32_Id);
    static const string aSpaceJson = QUOTE( { "exchanged_data" : {\
            "name" : "FESSE_6_FESS5.1_DFAIL.DJ",\
            "version" : "1.0", \
            "datapoints" : [\
                {\
                   "label":"FESSE_6_FESS5.1_DFAIL.DJ",\
                   "pivot_id":"S114562128",\
                   "pivot_type":"SpsTyp",\
                   "protocols":[\
                      {\
                         "name":"iec104",\
                         "address":"18325-6468171",\
                         "typeid":"M_SP_TB_1",\
                         "gi_groups":"station"\
                      },\
                      {\
                         "name":"opcua",\
                         "address":"S_1145_6_21_28",\
                         "typeid":"Boolean_Id"\
                      }\
                   ]\
                }\
                ,\
                {\
                   "label":"FESSE_6_6CHAL7.1_SA.1",\
                   "pivot_id":"C11456181",\
                   "pivot_type":"DpcTyp",\
                   "protocols":[\
                      {\
                         "name":"iec104",\
                         "address":"18325-6441925",\
                         "typeid":"C_DC_TA_1"\
                      },\
                      {\
                         "name":"opcua",\
                         "address":"C_1145_6_18_1",\
                         "typeid":"Byte_Id"\
                      }\
                   ] \
                }\
            ]\
    }});
    Logger::getLogger()->warn("Parsing '%s'", aSpaceJson.c_str());
    Server_AddrSpace aSpace(aSpaceJson);
    NodeVect_t::const_iterator it;
    const SOPC_AddressSpace_Node* pNode = nullptr;

    it = std::find_if(aSpace.nodes.begin(), aSpace.nodes.end(),
            nodeVarFinder("ns=1;s=/FESSE_6_FESS5.1_DFAIL.DJ/S_1145_6_21_28"));
    GTEST_ASSERT_NE(it, aSpace.nodes.end());
    pNode = (*it);
    GTEST_ASSERT_EQ(pNode->data.variable.Value.BuiltInTypeId, SOPC_Boolean_Id);

    it = std::find_if(aSpace.nodes.begin(), aSpace.nodes.end(),
            nodeVarFinder("ns=1;s=/FESSE_6_6CHAL7.1_SA.1/C_1145_6_18_1"));
    GTEST_ASSERT_NE(it, aSpace.nodes.end());
    pNode = (*it);

    // Check references (Root.Object + HasTypeDefinition)
    GTEST_ASSERT_EQ(pNode->data.variable.Value.BuiltInTypeId, SOPC_Byte_Id);
    GTEST_ASSERT_EQ(pNode->data.variable.NoOfReferences, 2);
    bool foundRootObject = false;
    bool foundHasDefintion = false;
    for (size_t i = 0; i < pNode->data.variable.NoOfReferences ; i++) {
        const OpcUa_ReferenceNode& ref(pNode->data.variable.References[i]);
        const std::string target(SOPC_tools::toString(ref.TargetId.NodeId));
        const std::string refId(SOPC_tools::toString(ref.ReferenceTypeId));
        if (target == "i=85" && ref.IsInverse)
            foundRootObject = true;
        if (target == "i=63" && refId == "i=40" && !ref.IsInverse)
            foundHasDefintion = true;
    }

    GTEST_ASSERT_EQ(foundRootObject, true);
    GTEST_ASSERT_EQ(foundHasDefintion, true);

    // Check that inverse references are added
    bool foundInvRootObject = false;
    bool foundInvHasDefintion = false;

    // Find Root.Object
    it = std::find_if(aSpace.nodes.begin(), aSpace.nodes.end(), nodeObjFinder("i=85"));

    GTEST_ASSERT_NE(it, aSpace.nodes.end());
    pNode = (*it);
    for (size_t i = 0; i < pNode->data.variable.NoOfReferences ; i++) {
        const OpcUa_ReferenceNode& ref(pNode->data.variable.References[i]);
        const std::string iName(SOPC_tools::toString(ref.TargetId.NodeId));
        if (iName == "ns=1;s=/FESSE_6_FESS5.1_DFAIL.DJ/S_1145_6_21_28" && !ref.IsInverse)
            foundInvRootObject = true;
    }

    // Find HasReference
    it = std::find_if(aSpace.nodes.begin(), aSpace.nodes.end(), nodeVarTypeFinder("i=63"));
    GTEST_ASSERT_NE(it, aSpace.nodes.end());
    pNode = (*it);
    for (size_t i = 0; i < pNode->data.variable.NoOfReferences ; i++) {
        const OpcUa_ReferenceNode& ref(pNode->data.variable.References[i]);
        const std::string iName(SOPC_tools::toString(ref.TargetId.NodeId));
        Logger::getLogger()->debug("found ref 63'%s'", iName.c_str());
        if (iName == "ns=1;s=/FESSE_6_FESS5.1_DFAIL.DJ/S_1145_6_21_28" && ref.IsInverse)
            foundInvHasDefintion = true;

    }

    GTEST_ASSERT_EQ(foundInvRootObject, true);
    GTEST_ASSERT_EQ(foundInvHasDefintion, true);
}
