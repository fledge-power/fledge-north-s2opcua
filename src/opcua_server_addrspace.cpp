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
#include <map>

extern "C" {
// S2OPC headers
#include "sopc_macros.h"
#include "sopc_common.h"
#include "sopc_enums.h"
#include "sopc_builtintypes.h"
#include "opcua_statuscodes.h"
#include "sopc_types.h"
// From S2OPC "clientserver"
#include "sopc_address_space.h"
}

// Fledge headers
#include "config_category.h"
#include "logger.h"

/// Project includes
#include "opcua_server_config.h"
#include "opcua_server_tools.h"

using SOPC_tools::toString;
using SOPC_tools::getArray;
using SOPC_tools::getString;
using SOPC_tools::getObject;

extern "C" {
    extern const bool sopc_embedded_is_const_addspace;

    extern SOPC_AddressSpace_Node SOPC_Embedded_AddressSpace_Nodes[];  // //NOSONAR  Interface with S2OPC
    extern const uint32_t SOPC_Embedded_AddressSpace_nNodes;  // //NOSONAR  Interface with S2OPC
}

namespace {
using std::string;

/**************************************************************************/
s2opc_north::NodeVect_t getNS0(void) {
    s2opc_north::NodeVect_t result;

    ASSERT(sopc_embedded_is_const_addspace == false, "Cannot use CONST address space!");
    const uint32_t nbNodes(SOPC_Embedded_AddressSpace_nNodes);
    SOPC_AddressSpace_Node* nodes(SOPC_Embedded_AddressSpace_Nodes);

    for (uint32_t i = 0 ; i < nbNodes; i++) {
        SOPC_AddressSpace_Node* node(nodes + i);
        s2opc_north::NodeInfo_t info = {node, string("")};
        result.push_back(info);
    }

    return result;
}

/**************************************************************************/
void toLocalizedText(SOPC_LocalizedText* localText, const std::string& text) {
    static const SOPC_LocalizedText emptyLocal = {
            {0, false, nullptr}, {0, false, nullptr}, nullptr
    };
    *localText = emptyLocal;

    SOPC_String_InitializeFromCString(&localText->defaultText, text.c_str());
}

/**************************************************************************/
/**
 * \brief This "Garbage collector" is used to allow multiple realloc on the same object
 * while the first realloc must not FREE the initial value. This is use by Address space
 * references which are statically generated but are also completed depending on configuration.
 */
template <typename T>
class GarbageCollectorC {  // //NOSONAR
 public:
    GarbageCollectorC() = default;
    using pointer =  T*;
    void reallocate(pointer* ptr, size_t oldSize, size_t newSize);
    virtual ~GarbageCollectorC(void);  // //NOSONAR

 private:
    GarbageCollectorC (const GarbageCollectorC&) = delete;
    GarbageCollectorC& operator= (const GarbageCollectorC&) = delete;
    using ptrMap = std::map<pointer, bool>;  // Note that only key is used
    ptrMap mAllocated;
};
static GarbageCollectorC<OpcUa_ReferenceNode> referencesGarbageCollector;   // //NOSONAR

template<typename T>
void
GarbageCollectorC<T>::
reallocate(pointer* ptr, size_t oldSize, size_t newSize) {
    ASSERT(nullptr != ptr);
    const pointer oldPtr(*ptr);
    auto it = mAllocated.find(oldPtr);

    *ptr = new T[newSize];   // //NOSONAR
    ASSERT(nullptr != *ptr);

    memcpy(*ptr, oldPtr, oldSize * sizeof(T));

    if (it != mAllocated.end()) {
        delete oldPtr;   // //NOSONAR
        mAllocated.erase(it);
    }
    mAllocated.insert({*ptr, true});
}

template<typename T>
GarbageCollectorC<T>::
~GarbageCollectorC(void) {
    for (auto alloc : mAllocated) {
        delete alloc.first;   // //NOSONAR
    }
}

}   // namespace

namespace {
const uint16_t nameSpace0(0);
const uint32_t serverIndex(0);
const SOPC_String String_NULL = {0, false, nullptr};
const SOPC_NodeId NodeId_HasTypeDefinition = {SOPC_IdentifierType_Numeric, nameSpace0, 40};
const SOPC_NodeId NodeId_HasComponent = {SOPC_IdentifierType_Numeric, nameSpace0, 47};
const SOPC_NodeId NodeId_BaseDataVariableType = {SOPC_IdentifierType_Numeric, nameSpace0, 63};
const SOPC_NodeId NodeId_Root_Objects = {SOPC_IdentifierType_Numeric, nameSpace0, 85};
}

namespace s2opc_north {

/**************************************************************************/
CNode::
CNode(SOPC_StatusCode defaultStatusCode) {
    memset(get(), 0, sizeof(SOPC_AddressSpace_Node));
    get()->node_class = OpcUa_NodeClass_Unspecified;     // Filled by child classes
    get()->value_status = defaultStatusCode;
    get()->value_source_ts = {0, 0};
}

/**************************************************************************/
void
CNode::
createReverseRef(NodeVect_t* nodes, const OpcUa_ReferenceNode& ref,
        const SOPC_NodeId& nodeId)const {
    // create a reverse reference
    const SOPC_NodeId& refTargetId(ref.TargetId.NodeId);
    // Find matching node in 'nodes'
    bool found(false);
    for (const NodeInfo_t& loopInfoy : *nodes) {
        SOPC_AddressSpace_Node* pNode(loopInfoy.first);
        if (nullptr != pNode && SOPC_NodeId_Equal(&pNode->data.variable.NodeId, &refTargetId)) {
            // Insert space in target references
            ASSERT(!found, "Several match for the same Node Id");
            found = true;
            // Initial setup provides RO-Mem allocation. Thus deallocation shall only be done for
            // elements explicitly allocated here
            const size_t oldSize(pNode->data.variable.NoOfReferences);
            const size_t newSize(oldSize + 1);
            referencesGarbageCollector.reallocate(&pNode->data.variable.References,
                    oldSize, newSize);

            // Fill new reference with inverted reference
            OpcUa_ReferenceNode& reverse(pNode->data.variable.References[oldSize]);
            reverse.IsInverse = !ref.IsInverse;
            reverse.ReferenceTypeId = ref.ReferenceTypeId;
            reverse.TargetId.NodeId = nodeId;
            reverse.TargetId.ServerIndex = serverIndex;
            reverse.TargetId.NamespaceUri = String_NULL;

            ASSERT(newSize < UINT32_MAX);
            pNode->data.variable.NoOfReferences = static_cast<uint32_t>(newSize);
        }
    }
    if (!found) {
        WARNING("No reverse reference found for nodeId '%s'", toString(nodeId).c_str());
    }
}

/**************************************************************************/
void
CNode::
insertAndCompleteReferences(NodeVect_t* nodes,
        NodeMap_t* nodeMap, const std::string& typeId) {
    SOPC_AddressSpace_Node& node(*get());
    const SOPC_NodeId& nodeId(node.data.variable.NodeId);
    NodeInfo_t refInfo(&node, typeId);
    nodes->push_back(refInfo);
    nodeMap->emplace(toString(nodeId), refInfo);
    // Find references and invert them
    const uint32_t nbRef(node.data.variable.NoOfReferences);
    for (uint32_t i = 0 ; i < nbRef; i++) {
        const OpcUa_ReferenceNode& ref(node.data.variable.References[i]);
        if (ref.TargetId.ServerIndex == serverIndex) {
            createReverseRef(nodes, ref, nodeId);
        }
    }
}

/**************************************************************************/
CVarNode::
CVarNode(const CVarInfo& varInfo, SOPC_BuiltinId sopcTypeId):
CCommonVarNode(varInfo) {
    OpcUa_VariableNode& variableNode = get()->data.variable;
    variableNode.Value.BuiltInTypeId = sopcTypeId;
    variableNode.Value.DoNotClear = true;

    variableNode.DataType.IdentifierType = SOPC_IdentifierType_Numeric;
    variableNode.DataType.Namespace = 0;
    variableNode.DataType.Data.Numeric = static_cast<uint32_t>(sopcTypeId);

    memset(&variableNode.Value.Value, 0, sizeof(variableNode.Value.Value));

    get()->value_status = (varInfo.mReadOnly ? OpcUa_BadWaitingForInitialData : GoodStatus);
}

/**************************************************************************/
CCommonVarNode::
CCommonVarNode(const CVarInfo& varInfo) {
    SOPC_ReturnStatus status;

    get()->node_class = OpcUa_NodeClass_Variable;
    OpcUa_VariableNode& variableNode = get()->data.variable;
    variableNode.NodeClass = OpcUa_NodeClass_Variable;
    variableNode.encodeableType = &OpcUa_VariableNode_EncodeableType;
    variableNode.AccessLevel = (varInfo.mReadOnly ? ReadOnlyAccess : ReadWriteAccess);
    variableNode.UserAccessLevel = 0;
    variableNode.MinimumSamplingInterval = 0.0;
    variableNode.Value.BuiltInTypeId = SOPC_Null_Id;
    variableNode.ValueRank = -1;
    variableNode.Value.ArrayType = SOPC_VariantArrayType_SingleValue;

    // Node Id
    status = SOPC_NodeId_InitializeFromCString(
            &variableNode.NodeId, varInfo.mNodeId.c_str(),
            static_cast<uint32_t>(varInfo.mNodeId.length()));
    ASSERT(status == SOPC_STATUS_OK, "Invalid NodeId : %s", varInfo.mNodeId.c_str());

    // Browse name
    variableNode.BrowseName.NamespaceIndex = variableNode.NodeId.Namespace;
    SOPC_String_InitializeFromCString(&variableNode.BrowseName.Name, varInfo.mBrowseName.c_str());

    ::toLocalizedText(&variableNode.DisplayName, varInfo.mDisplayName);
    ::toLocalizedText(&variableNode.Description, varInfo.mDescription);

    variableNode.NoOfReferences = 2;
    variableNode.References = new OpcUa_ReferenceNode[variableNode.NoOfReferences];   // //NOSONAR (managed by S2OPC)

    OpcUa_ReferenceNode* ref(variableNode.References);
    // Reference #0: Organized by Root.Objects
    ref->encodeableType = &OpcUa_ReferenceNode_EncodeableType;
    ref->ReferenceTypeId = NodeId_HasComponent;
    ref->IsInverse = true;
    ref->TargetId.NodeId = NodeId_Root_Objects;
    ref->TargetId.NamespaceUri = String_NULL;
    ref->TargetId.ServerIndex = serverIndex;
    ref++;
    // Reference #1: Has Type Definition
    ref->encodeableType = &OpcUa_ReferenceNode_EncodeableType;
    ref->ReferenceTypeId = NodeId_HasTypeDefinition;
    ref->IsInverse = false;
    ref->TargetId.NodeId = NodeId_BaseDataVariableType;
    ref->TargetId.NamespaceUri = String_NULL;
    ref->TargetId.ServerIndex = serverIndex;
}

/**************************************************************************/
Server_AddrSpace::
Server_AddrSpace(const std::string& json) {
    using rapidjson::Value;
    nodes = getNS0();

    /* "nodes" are initially set-up with namespace 0 default nodes.
     Now this will be completed with configuration-extracted data
     */
    rapidjson::Document doc;
    doc.Parse(json.c_str());
    ASSERT(!doc.HasParseError() && doc.HasMember(JSON_EXCHANGED_DATA),
            "Malformed JSON (section '%s', index = %u)", JSON_EXCHANGED_DATA, doc.GetErrorOffset());

    const Value& exData(::getObject(doc, JSON_EXCHANGED_DATA, JSON_EXCHANGED_DATA));
    const Value::ConstArray datapoints(getArray(exData, JSON_DATAPOINTS, JSON_EXCHANGED_DATA));

    for (const Value& datapoint : datapoints) {
        const string label(::getString(datapoint, JSON_LABEL, JSON_DATAPOINTS));
        DEBUG("Parsing DATAPOINT(%s)", LOGGABLE(label));
        const string pivot_id(::getString(datapoint, JSON_PIVOT_ID, JSON_DATAPOINTS));
        const string pivot_type(::getString(datapoint, JSON_PIVOT_TYPE, JSON_DATAPOINTS));
        const Value::ConstArray& protocols(getArray(datapoint, JSON_PROTOCOLS, JSON_DATAPOINTS));

        for (const Value& protocol : protocols) {
            try {
                static const string ns1("ns=1;s=");
                static const string pivotDescr("Pivot Id#");
                const ExchangedDataC data(protocol);
                const std::string nodeIdName(ns1 + "/" + label + "/" + data.address);
                const std::string browseName(data.address);
                const std::string displayName(data.address);
                const std::string description(pivotDescr + pivot_id);
                const SOPC_NodeId& parent(NodeId_Root_Objects);
                const SOPC_BuiltinId sopcTypeId(SOPC_tools::toBuiltinId(data.typeId));
                const bool readOnly(SOPC_tools::pivotTypeToReadOnly(data.typeId));
                const char* readOnlyStr(readOnly ? "RO" : "RW");
                CVarInfo cVarInfo(nodeIdName, browseName, displayName, description, parent, readOnly);
                CVarNode* pNode(new CVarNode(cVarInfo, sopcTypeId));   // //NOSONAR (deletion managed by S2OPC)
                DEBUG("Adding node data '%s' of type '%s-%d' (%s)",
                        LOGGABLE(nodeIdName), LOGGABLE(data.typeId), sopcTypeId, readOnlyStr);
                pNode->insertAndCompleteReferences(&nodes, &mByNodeId, data.typeId);

                if (readOnly == false) {
                    // in case of "writeable" nodes, the plugin shall generate a "_reply" string variable
                    static const string replyAddr(nodeIdName + "_reply");
                    static const string replyDescr("Status of command '" + data.address +"'");
                    CVarInfo cVarInfoReply(replyAddr, replyAddr, replyAddr, replyDescr, parent, true);
                    // note: deletion handled by S2OPC
                    CVarNode* pNode(new CVarNode(cVarInfoReply, SOPC_String_Id));   // //NOSONAR
                    DEBUG("Adding node data '%s' of type '%s-%d' (RO)",
                            LOGGABLE(replyAddr), "SOPC_String_Id", SOPC_String_Id);
                    pNode->insertAndCompleteReferences(&nodes, &mByNodeId, data.typeId);
                }
            }
            catch (const ExchangedDataC::NotAnS2opcInstance&) {
                // Just ignore other protocols
            }
        }
    }
}

/**************************************************************************/
const NodeInfo_t*
Server_AddrSpace::
getByNodeId(const string& nodeId)const {
    NodeMap_t::const_iterator it = mByNodeId.find(nodeId);
    if (it != mByNodeId.end()) {
        return &(it->second);
    }
    return nullptr;
}

}   // namespace s2opc_north

