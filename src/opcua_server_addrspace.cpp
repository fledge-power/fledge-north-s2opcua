/*
 * Fledge Power north plugin.
 *
 * Copyright (c) 2022 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Jeremie Chabod
 */

#include "opcua_server_addrspace.h"

// System headers
#include <stdio.h>

extern "C" {
// S2OPC headers
#include "s2opc/common/sopc_macros.h"
#include "s2opc/common/sopc_common.h"
#include "s2opc/common/sopc_enums.h"
#include "s2opc/common/sopc_builtintypes.h"
#include "s2opc/common/opcua_statuscodes.h"
#include "s2opc/common/sopc_types.h"
#include "s2opc/clientserver/sopc_address_space.h"
}

// Fledge headers
#include "config_category.h"
#include "logger.h"

namespace {
using std::string;

s2opc_north::NodeVect_t getNS0(void) {
    s2opc_north::NodeVect_t result;

    const uint32_t nbNodes(SOPC_Embedded_AddressSpace_nNodes_nano);
    SOPC_AddressSpace_Node* nodes(SOPC_Embedded_AddressSpace_Nodes_nano);

    for (uint32_t i = 0 ; i < nbNodes; i++) {
        SOPC_AddressSpace_Node* node(nodes + i);
        result.push_back(node);
    }

    return result;
}

static void toLocalizedText(SOPC_LocalizedText* localText, const std::string& text) {
    static const SOPC_LocalizedText emptyLocal = {{0, 0, NULL}, {0, 0, NULL}, NULL};
    *localText = emptyLocal;

    SOPC_String_InitializeFromCString(&localText->defaultText, text.c_str());
}

}   // namespace


namespace s2opc_north {

/**************************************************************************/
CNode::
CNode(SOPC_StatusCode defaultStatusCode) {
    mNode.node_class = OpcUa_NodeClass_Unspecified;     // Filled by child classes
    mNode.value_status = defaultStatusCode;
    mNode.value_source_ts = {0, 0};
}

/**************************************************************************/
CVarNode::
CVarNode(const CVarInfo& varInfo, uint32_t defVal):
CCommonVarNode(varInfo) {
    OpcUa_VariableNode& variableNode = mNode.data.variable;
    variableNode.Value.ArrayType = SOPC_VariantArrayType_SingleValue;
    variableNode.Value.BuiltInTypeId = SOPC_UInt32_Id;
    variableNode.Value.DoNotClear = true;
    variableNode.Value.Value.Uint32 = defVal;
    variableNode.DataType.IdentifierType = SOPC_IdentifierType_Numeric;
    variableNode.DataType.Namespace = 0;
    variableNode.DataType.Data.Numeric = 7;
    variableNode.ValueRank = -1;
}

/**************************************************************************/
CCommonVarNode::
CCommonVarNode(const CVarInfo& varInfo) {
    SOPC_ReturnStatus status;

    mNode.node_class = OpcUa_NodeClass_Variable;
    OpcUa_VariableNode& variableNode = mNode.data.variable;
    variableNode.NodeClass = OpcUa_NodeClass_Variable;
    variableNode.encodeableType = &OpcUa_VariableNode_EncodeableType;
    variableNode.AccessLevel = (varInfo.mReadOnly ? ReadOnlyAccess : ReadWriteAccess);
    variableNode.UserAccessLevel = 0;
    variableNode.MinimumSamplingInterval = 0.0;

    // Node Id
    status = SOPC_NodeId_InitializeFromCString(
            &variableNode.NodeId, varInfo.mNodeId.c_str(), varInfo.mNodeId.length());
    ASSERT(status == SOPC_STATUS_OK, "Invalid NodeId : %s", varInfo.mNodeId.c_str());

    // Browse name
    variableNode.BrowseName.NamespaceIndex = variableNode.NodeId.Namespace;
    SOPC_String_InitializeFromCString(&variableNode.BrowseName.Name, varInfo.mBrowseName.c_str());

    ::toLocalizedText(&variableNode.DisplayName, varInfo.mDisplayName);
    ::toLocalizedText(&variableNode.Description, varInfo.mDescription);

#warning "TODO(JCH) => complete references"
    variableNode.NoOfReferences = 0;
    variableNode.References = NULL;
}

/**************************************************************************/
Server_AddrSpace::
Server_AddrSpace(const std::string& json):
    nodes(getNS0()) {
#warning "TODO : Add possibility to setup nano/mbedded ns0"
#warning "TODO : fill address space!"
    WARNING("[JCH] : json = %s", json.c_str());

#warning "WIP : parsing example"
    using rapidjson::Document;
    using rapidjson::Value;

    rapidjson::Document doc;
    if (doc.Parse(const_cast<char*>(json.c_str())).HasParseError()) {
        ERROR("Parsing error in data exchange configuration");
        return;
    }

    ASSERT(doc.IsObject() && doc.HasMember("nodes") , "Invalid configuration section :%s", json.c_str());

    const Value& vNodes = doc["nodes"];
    ASSERT(vNodes.IsArray(), "Invalid configuration section : %s", json.c_str());

    // Parse all item under array 'nodes'
    for (rapidjson::SizeType i = 0; i < vNodes.Size(); i++) {
        const Value& vNode = vNodes[i];
        ASSERT(vNode.IsObject(), "Invalid configuration section : nodes[%u]", i);

        ASSERT(vNode.HasMember("nodeid"), "Missing 'nodeid' for nodes[%u]", i);
        ASSERT(vNode["nodeid"].IsString(), "Value for 'nodeid' must be a STRING for node[%u]", i);
        const std::string nodeId(vNode["nodeid"].GetString());

        bool readOnly = false;
        if (vNode.HasMember("readonly")) {
            ASSERT(vNode["readonly"].IsBool(), "Value for 'readonly' must be a BOOL for node[%u]", i);
            readOnly = vNode["readonly"].GetBool();
        }

#warning "TODO : display, 'description', 'parent', 'value', 'type'"
        const std::string browseName;
        const std::string displayName;
        const std::string description;
        const std::string parent;
        const uint32_t value(45);
        CVarInfo cVarInfo(nodeId, browseName, displayName, description, parent, readOnly);
        CVarNode* pNode= new CVarNode(cVarInfo, value);
        nodes.push_back(pNode->get());

#warning "TODO : create node for each value"
        WARNING("JCH nodeid :'%s' -> '%s'", nodeId.c_str(), displayName.c_str());
    }
}

/**************************************************************************/
Server_AddrSpace::
~Server_AddrSpace(void) {
    // Note: nodes are freed automatically (See call to ::SOPC_AddressSpace_Create)
}

}   // namespace s2opc_north

