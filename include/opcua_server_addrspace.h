/*
 * Fledge north service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Amandeep Singh Arora / Jeremie Chabod
 */
#ifndef INCLUDE_OPCUA_SERVER_ADDRSPACE_H_
#define INCLUDE_OPCUA_SERVER_ADDRSPACE_H_

// Plugin headers
#include "opcua_server_tools.h"

// System headers
#include <stdint.h>
#include <stdlib.h>
#include <unordered_map>
#include <vector>
#include <string>
#include <memory>
#include <utility>

// Fledge headers
#include "logger.h"
#include "plugin_api.h"
#include "rapidjson/document.h"

extern "C" {
// S2OPC headers
#include "sopc_assert.h"
#include "sopc_builtintypes.h"
// From S2OPC "clientserver"
#include "sopc_address_space.h"
};

extern "C" {
// Nano NS0 namespace
extern const uint32_t SOPC_Embedded_AddressSpace_nNodes_nano;   // //NOSONAR  Interface with S2OPC
extern SOPC_AddressSpace_Node SOPC_Embedded_AddressSpace_Nodes_nano[];   // //NOSONAR  Interface with S2OPC
}

namespace s2opc_north {
using std::string;

static const SOPC_StatusCode GoodStatus = 0x00000000;
static const SOPC_Byte ReadOnlyAccess = 0x01;
static const SOPC_Byte ReadWriteAccess = 0x03;

typedef enum {
    we_Read_Only,
    we_Trigger,
    we_Value
} SOPC_AddressSpace_WriteEvent;

string getNodeIdName(const string &address);

struct NodeInfoCtx_t{
    SOPC_AddressSpace_WriteEvent mEvent;
    string mOpcParentAddress;
    string mPivotId;
    string mPivotType;
    explicit NodeInfoCtx_t(SOPC_AddressSpace_WriteEvent event = we_Read_Only,
            const string& opcParentAddr = "", const string& pivotId = "", const string& pivotType = ""):
        mEvent(event),
        mOpcParentAddress(opcParentAddr),
        mPivotId(pivotId),
        mPivotType(pivotType){}
};
static const NodeInfoCtx_t NodeInfoCtx_empty;

struct NodeInfo_t {
    SOPC_AddressSpace_Node* mNode;
    const NodeInfoCtx_t mContext;
    explicit NodeInfo_t(SOPC_AddressSpace_Node* node, const NodeInfoCtx_t& context = NodeInfoCtx_empty):
        mNode(node),
        mContext(context){}
};
/** vector of \a NodeInfo_t */
using NodeVect_t = std::vector<NodeInfo_t>;
/** NodeInfo_t = <NodeId, NodeInfo_t> */
using NodeMap_t = std::unordered_map<string, NodeInfo_t>;
/** NodeIdMap_t = {PivotId : Pivot address} */
using NodeIdMap_t = std::unordered_map<string, string>;

struct ControlInfo {
    const NodeInfo_t* mTrigger;
    const NodeInfo_t* mValue;
    const NodeInfo_t* mReply;
    mutable string mStrValue;
};

/** ControlMap_t = {PivotId : contorl info}*/
using ControlMap_t = std::unordered_map<string, ControlInfo>;

/**************************************************************************/
struct CVarInfo {
    CVarInfo(const string& address,
            const string& browseName,
            const string& displayName,
            const string& description,
            const SOPC_NodeId& parentNodeId,
            const bool readOnly = true):
                mAddress(address),
                mBrowseName(browseName),
                mDisplayName(displayName),
                mDescription(description),
                mParentNodeId(parentNodeId),
                mReadOnly(readOnly) {
    }
    const string mAddress;
    const string mBrowseName;
    const string mDisplayName;
    const string mDescription;
    const SOPC_NodeId mParentNodeId;
    const bool mReadOnly;
};  // class CVarInfo

/**************************************************************************/
/**
 * \brief an OPCUA Node class
 */
class CNode {
 public:
    inline SOPC_AddressSpace_Node* get(void) {return &mNode;}
    inline const SOPC_NodeId& nodeId(void)const {return *mNodeId.get();}
    void insertAndCompleteReferences(NodeVect_t* nodes,
            NodeMap_t* nodeMap = nullptr, const NodeInfoCtx_t& context = NodeInfoCtx_empty);

 protected:
    explicit CNode(const string& nodeName, OpcUa_NodeClass nodeClass, SOPC_StatusCode defaultStatusCode = GoodStatus);
    virtual ~CNode(void);

 private:
    void createReverseRef(NodeVect_t* nodes, const OpcUa_ReferenceNode& ref)const;

    SOPC_AddressSpace_Node mNode;
    std::unique_ptr<SOPC_NodeId> mNodeId;
};  // class CNode

/**
 * \brief Contains code for Folder nodes
 */
class CFolderNode : public CNode {
 public:
    explicit CFolderNode(const string& nodeName, const SOPC_NodeId& parent);
    virtual ~CFolderNode(void) = default;
};

/**
 * \brief Contains common code to all Variable nodes
 */
class CCommonVarNode : public CNode {
 public:
    explicit CCommonVarNode(const CVarInfo& varInfo);
    virtual ~CCommonVarNode(void) = default;
};

/**
 * \brief Contains specialization of a variable node
 */
class CVarNode : public CCommonVarNode {
 public:
    explicit CVarNode(const CVarInfo& varInfo, SOPC_BuiltinId sopcTypeId);
    virtual ~CVarNode(void) = default;

 private:
    void initializeCommonFields(const CVarInfo& varInfo);
};

/**
 * \brief This calls represents the content of an address space
 */
class Server_AddrSpace{
 public:
    /**
     * \brief Builds up an address space from a json configuration string
     * \param json A string containing the "exchanged_data" JSON section
     *  it is expected to contain a JSON with following format:
     *  {
     *      'datapoints' : [
                {'label':'..','pivot_id':'..','pivot_type':'..',
                 'protocols':
                 [ { 'name' : 'opcua',
                     'address':'<nodeId>',
                     'typeid':'UInt32',
                     'default': '1'}
                 ]
                }
            ]
        }
     */
    explicit Server_AddrSpace(const std::string& json);
    /**
     * \brief Deletes an address space
     */
    virtual ~Server_AddrSpace(void) = default;

    const NodeInfo_t* getByNodeId(const string& nodeId)const;
    string getByPivotId(const string& pivotId)const;
    const ControlInfo* getControlByPivotId(const string& pivotId)const;

 public:
    inline const NodeVect_t& getNodes(void)const {return mNodes;}
    inline NodeVect_t& getNodes(void) {return mNodes;}

 private:
    /**
     * Create folder node object. Create the references (in new node and parent)
     * @param nodeId The expected nodeId
     * @param parent The parent nodeId
     * @return The CNode of the created object
     */
    CNode* createFolderNode(const string& nodeId, const SOPC_NodeId& parent);
    void createPivotNodes(const string& label, const string& pivotId,
            const string& address, const string& pivotType);
    void insertUnrefVarNode(const string& address, const string& pivotId, const std::string &name,
            const std::string &descr, SOPC_BuiltinId type,
            const SOPC_NodeId& parent,
            bool isReadOnly = true,
            const SOPC_AddressSpace_WriteEvent& event = we_Read_Only,
            const string& pivotType = "");

    inline const NodeInfo_t* getNodeInfo(const string& addr, const string& subNode)const {
        return getByNodeId(getNodeIdName(addr + "/" + subNode));
    }

    /**
     * The content of the address space.
     */
    NodeVect_t mNodes;
    // Note: nodes are freed automatically (See call to ::SOPC_AddressSpace_Create)

    /**
     * Map containing functional nodes which can be written by clients
     */
    NodeMap_t mByNodeId;
    /**
     * Map containing addresses, sorted by PivotId
     */
    NodeIdMap_t mByPivotId;
    /**
     * Map of all controls, indexed by PivotId
     */
    ControlMap_t mControls;
};  // Server_AddrSpace

}   // namespace s2opc_north

#endif  // INCLUDE_OPCUA_SERVER_ADDRSPACE_H_
