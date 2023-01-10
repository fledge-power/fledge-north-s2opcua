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
#include "opcua_identifiers.h"
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

    const uint32_t nbNodes(SOPC_Embedded_AddressSpace_nNodes);
    SOPC_AddressSpace_Node* nodes(SOPC_Embedded_AddressSpace_Nodes);

    for (uint32_t i = 0 ; i < nbNodes; i++) {
#warning "TODO: a copy should be made, otherwise the inverse reference added will be" \
    "maintained if several calls are made"
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
    // ASSERT(nullptr != ptr);  // useless: only static calls using addresses
    const pointer oldPtr(*ptr);
    auto it = mAllocated.find(oldPtr);

    *ptr = new T[newSize];   // //NOSONAR

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

/**************************************************************************/
namespace {
static const string ns1("ns=1;s=");    // NOLINT Explicitely want to avoid construction on each use
}    // namespace
inline string getNodeIdName(const string &address) {return ::ns1 + address;}

/**************************************************************************/
inline const SOPC_NodeId* getNodeIdFromAddrSpace(const SOPC_AddressSpace_Node &node) {
    const SOPC_NodeId* nodeId = nullptr;
    if (node.node_class == OpcUa_NodeClass_Variable) {
        nodeId = &node.data.variable.NodeId;
    }
    if (node.node_class == OpcUa_NodeClass_VariableType) {
        nodeId = &node.data.variable_type.NodeId;
    }
    if (node.node_class == OpcUa_NodeClass_Object) {
        nodeId = &node.data.object.NodeId;
    }
    if (node.node_class == OpcUa_NodeClass_ObjectType) {
        nodeId = &node.data.object_type.NodeId;
    }
    return nodeId;
}

}   // namespace

namespace {
const uint16_t nameSpace0(0);
const uint32_t serverIndex(0);
const SOPC_String String_NULL = {0, false, nullptr};
const SOPC_NodeId NodeId_Organizes = {
        SOPC_IdentifierType_Numeric, nameSpace0, OpcUaId_Organizes
};      // 35
const SOPC_NodeId NodeId_HasTypeDefinition = {
        SOPC_IdentifierType_Numeric, nameSpace0, OpcUaId_HasTypeDefinition
};  // 40
const SOPC_NodeId NodeId_HasComponent = {
        SOPC_IdentifierType_Numeric, nameSpace0, OpcUaId_HasComponent
};    // 47
const SOPC_NodeId NodeId_FolderType = {
        SOPC_IdentifierType_Numeric, nameSpace0, OpcUaId_FolderType
};        // 61
const SOPC_NodeId NodeId_BaseDataVariableType = {
        SOPC_IdentifierType_Numeric, nameSpace0, OpcUaId_BaseDataVariableType
};    //63
const SOPC_NodeId NodeId_Root_Objects = {
        SOPC_IdentifierType_Numeric, nameSpace0, OpcUaId_ObjectsFolder
};   // 85
}       // namespace

namespace s2opc_north {

/**************************************************************************/
CNode::
CNode(const string& nodeName, OpcUa_NodeClass nodeClass, SOPC_StatusCode defaultStatusCode) {
    const string nodeId(::getNodeIdName(nodeName));
    mNodeId.reset(SOPC_NodeId_FromCString(nodeId.c_str(), nodeId.length()));
    memset(get(), 0, sizeof(SOPC_AddressSpace_Node));
    get()->node_class = nodeClass;     // Filled by child classes
    get()->value_status = defaultStatusCode;
    get()->value_source_ts = {0, 0};
}

/**************************************************************************/
CNode::
~CNode(void) {
    SOPC_NodeId_Clear(mNodeId.get());
}


/**************************************************************************/
void
CNode::
createReverseRef(NodeVect_t* nodes, const OpcUa_ReferenceNode& ref)const {
    // create a reverse reference
    const SOPC_NodeId& refTargetId(ref.TargetId.NodeId);
    DEBUG("Create reverse reference from '%s' to '%s'",
            toString(*mNodeId.get()).c_str(), toString(refTargetId).c_str());
    // Find matching node in 'nodes'
    bool found(false);
    for (const NodeInfo_t& loopInfo : *nodes) {
        SOPC_AddressSpace_Node* pNode(loopInfo.first);
        const SOPC_NodeId* nodeId = ::getNodeIdFromAddrSpace(*pNode);
        if (nodeId != nullptr && !found && SOPC_NodeId_Equal(nodeId, &refTargetId)) {
            // Insert space in target references
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
            DEBUG("Create rev ref from '%s' to '%s'",
                   SOPC_tools::toString(*mNodeId.get()).c_str(),
                   SOPC_tools::toString(*nodeId).c_str());
            SOPC_NodeId_Copy(&reverse.TargetId.NodeId, mNodeId.get());
            reverse.TargetId.ServerIndex = serverIndex;
            reverse.TargetId.NamespaceUri = String_NULL;

            pNode->data.variable.NoOfReferences = static_cast<uint32_t>(newSize);
        }
    }
}

/**************************************************************************/
void
CNode::
insertAndCompleteReferences(NodeVect_t* nodes,
        NodeMap_t* nodeMap, const std::string& typeId) {
    NodeInfo_t refInfo(&mNode, typeId);
    nodes->push_back(refInfo);
    if (nodeMap != nullptr) {
        nodeMap->emplace(toString(*mNodeId.get()), refInfo);
    }

    // Find references and invert them
    const uint32_t nbRef(mNode.data.variable.NoOfReferences);
    for (uint32_t i = 0 ; i < nbRef; i++) {
        const OpcUa_ReferenceNode& ref(mNode.data.variable.References[i]);
        if (ref.TargetId.ServerIndex == serverIndex) {
            createReverseRef(nodes, ref);
        }
    }
}

/**************************************************************************/
CFolderNode::
CFolderNode(const string& nodeName, const SOPC_NodeId& parent):
CNode(nodeName, OpcUa_NodeClass_Object) {
    OpcUa_ObjectNode& node = get()->data.object;
    SOPC_NodeId_Copy(&node.NodeId, &nodeId());
    node.NodeClass = OpcUa_NodeClass_Object;

    node.BrowseName.NamespaceIndex = node.NodeId.Namespace;
    SOPC_String_InitializeFromCString(&node.BrowseName.Name, nodeName.c_str());

    ::toLocalizedText(&node.DisplayName, nodeName);
    ::toLocalizedText(&node.Description, nodeName);

    node.WriteMask = 0;
    node.UserWriteMask = 0;

    node.NoOfReferences = 2;
    node.References = new OpcUa_ReferenceNode[node.NoOfReferences];   // //NOSONAR (managed by S2OPC)

    OpcUa_ReferenceNode* ref(node.References);
    // Reference #0: Is Organized by parent
    ref->encodeableType = &OpcUa_ReferenceNode_EncodeableType;
    ref->ReferenceTypeId = NodeId_Organizes;
    ref->IsInverse = true;
    SOPC_NodeId_Copy(&ref->TargetId.NodeId, &parent);
    ref->TargetId.NamespaceUri = String_NULL;
    ref->TargetId.ServerIndex = serverIndex;
    ref++;
    // Reference #1: Has Type Definition (Folder Type)
    ref->encodeableType = &OpcUa_ReferenceNode_EncodeableType;
    ref->ReferenceTypeId = NodeId_HasTypeDefinition;
    ref->IsInverse = false;
    ref->TargetId.NodeId = NodeId_FolderType;
    ref->TargetId.NamespaceUri = String_NULL;
    ref->TargetId.ServerIndex = serverIndex;
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

    get()->value_status = (varInfo.mReadOnly ? OpcUa_BadWaitingForInitialData : GoodStatus);

    // setup a consistent value anyway
    switch (sopcTypeId) {
    case SOPC_String_Id:
        SOPC_String_Initialize(&variableNode.Value.Value.String);
        SOPC_String_CopyFromCString(&variableNode.Value.Value.String, "");
        break;
    default :
        memset(&variableNode.Value.Value, 0, sizeof(variableNode.Value.Value));
        break;
    }
}

/**************************************************************************/
CCommonVarNode::
CCommonVarNode(const CVarInfo& varInfo) :
CNode(varInfo.mAddress, OpcUa_NodeClass_Variable) {
    SOPC_ReturnStatus status;

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
    status = SOPC_NodeId_Copy(&variableNode.NodeId, &nodeId());

    // Browse name
    variableNode.BrowseName.NamespaceIndex = variableNode.NodeId.Namespace;
    SOPC_String_InitializeFromCString(&variableNode.BrowseName.Name, varInfo.mBrowseName.c_str());

    ::toLocalizedText(&variableNode.DisplayName, varInfo.mDisplayName);
    ::toLocalizedText(&variableNode.Description, varInfo.mDescription);

    variableNode.NoOfReferences = 2;
    variableNode.References = new OpcUa_ReferenceNode[variableNode.NoOfReferences];   // //NOSONAR (managed by S2OPC)

    OpcUa_ReferenceNode* ref(variableNode.References);
    // Reference #0: Organized by parent
    ref->encodeableType = &OpcUa_ReferenceNode_EncodeableType;
    ref->ReferenceTypeId = NodeId_HasComponent;
    ref->IsInverse = true;
    SOPC_NodeId_Copy(&ref->TargetId.NodeId, &varInfo.mParentNodeId);
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
CNode*
Server_AddrSpace::
createFolderNode(const string& nodeId, const SOPC_NodeId& parent) {
    // Parent object folder node
    CNode* pNode(new CFolderNode(nodeId, parent));
    DEBUG("Adding node object '%s' under '%s'",
            toString(pNode->nodeId()).c_str(), SOPC_tools::toString(parent).c_str());
    pNode->insertAndCompleteReferences(&mNodes);
    return pNode;
}

/**************************************************************************/
void
Server_AddrSpace::
insertUnrefVarNode(const string& address, const std::string &name, const std::string &descr, SOPC_BuiltinId type,
        const SOPC_NodeId& parent) {
    CVarInfo cVarInfo(address + "/" + name, name, name, descr, parent);
    CVarNode* pNode(new CVarNode(cVarInfo, type));   // //NOSONAR (deletion managed by S2OPC)
    DEBUG("Adding node data '%s' of type '%d' (RO)", SOPC_tools::toString(pNode->nodeId()).c_str(), type);
    pNode->insertAndCompleteReferences(&mNodes);
}

/**************************************************************************/
void
Server_AddrSpace::
createPivotNodes(const string& label, const string& pivotId,
        const string& address, const string& pivotType) {
    const SOPC_BuiltinId sopcTypeId(SOPC_tools::toBuiltinId(pivotType));

    // Parent object folder node
    CNode* parentNode;
    parentNode = createFolderNode(address, NodeId_Root_Objects);
    const SOPC_NodeId& parent(parentNode->nodeId());

    insertUnrefVarNode(address, "Cause", "Cause of transmission", SOPC_UInt32_Id, parent);
    insertUnrefVarNode(address, "Confirmation", "Confirmation", SOPC_Boolean_Id, parent);
    insertUnrefVarNode(address, "Source", "Source", SOPC_String_Id, parent);
    insertUnrefVarNode(address, "ComingFrom", "Origin protocol", SOPC_String_Id, parent);
    insertUnrefVarNode(address, "TmOrg", "Origin Timestamp", SOPC_String_Id, parent);
    insertUnrefVarNode(address, "TmValidity", "Timestamp validity", SOPC_String_Id, parent);
    insertUnrefVarNode(address, "DetailQuality", "Quality default details", SOPC_UInt32_Id, parent);
    insertUnrefVarNode(address, "TimeQuality", "Time default details", SOPC_UInt32_Id, parent);
    insertUnrefVarNode(address, "SecondSinceEpoch", "Timestamp", SOPC_UInt64_Id, parent);

    // Create <..>/Value, (dynamic type, based on 'pivotType')
    const bool readOnly(SOPC_tools::pivotTypeToReadOnly(pivotType));
    const char* readOnlyStr(readOnly ? "RO" : "RW");
    const string nodeIdName(address + "/Value");
    DEBUG("Adding node data '%s' of type '%s-%d' (%s)",
            nodeIdName.c_str(), pivotType.c_str(), sopcTypeId, readOnlyStr);
    CVarInfo cVarInfo(nodeIdName, "Value", "Value", string("Value of type ") + pivotType, parent, readOnly);
    CVarNode* pNode(new CVarNode(cVarInfo, sopcTypeId));   // //NOSONAR (deletion managed by S2OPC)
    pNode->insertAndCompleteReferences(&mNodes, &mByNodeId, pivotType);
    mByPivotId.emplace(pivotId, address);
    // For writeable nodes, adding a "Reply" node
    if (readOnly == false) {
        insertUnrefVarNode(address, "Reply", "Reply", SOPC_String_Id, parent);
    }
}

/**************************************************************************/
Server_AddrSpace::
Server_AddrSpace(const std::string& json) {
    using rapidjson::Value;
    mNodes = getNS0();

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
        const string pivot_id(::getString(datapoint, JSON_PIVOT_ID, JSON_DATAPOINTS));
        DEBUG("Parsing DATAPOINT(%s/%s)", label.c_str(), pivot_id.c_str());
        // const string pivot_type(::getString(datapoint, JSON_PIVOT_TYPE, JSON_DATAPOINTS));
        const Value::ConstArray& protocols(getArray(datapoint, JSON_PROTOCOLS, JSON_DATAPOINTS));

        for (const Value& protocol : protocols) {
            try {
                const ExchangedDataC data(protocol); // throws NotAnS2opcInstance if not OPCUA protocol

                // Create a parent node of type Folder
                createPivotNodes(label, pivot_id, data.address, data.typeId);
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

/**************************************************************************/
string
Server_AddrSpace::
getByPivotId(const string& pivotId)const {
    NodeIdMap_t::const_iterator it = mByPivotId.find(pivotId);
    if (it != mByPivotId.end()) {
        return it->second;
    }
    return "";
}
}   // namespace s2opc_north

