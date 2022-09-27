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

// System headers
#include <stdint.h>
#include <stdlib.h>
#include <map>
#include <vector>
#include <string>

extern "C" {
// S2OPC headers
#include "sopc_assert.h"
#include "sopc_builtintypes.h"
// From S2OPC "clientserver"
#include "sopc_address_space.h"
};

// Fledge headers
#include "logger.h"
#include "rapidjson/document.h"

extern "C" {
// Nano NS0 namespace
extern const uint32_t SOPC_Embedded_AddressSpace_nNodes_nano;
extern SOPC_AddressSpace_Node SOPC_Embedded_AddressSpace_Nodes_nano[];
}

namespace s2opc_north {
using std::string;

static const SOPC_StatusCode GoodStatus = 0x00000000;
static const SOPC_Byte ReadOnlyAccess = 0x01;
static const SOPC_Byte ReadWriteAccess = 0x03;

/** Vector of nodes */
typedef std::pair<SOPC_AddressSpace_Node*, std::string> NodeInfo_t;
typedef std::vector<NodeInfo_t> NodeVect_t;

/**************************************************************************/
struct CVarInfo {
    CVarInfo(const string& nodeId,
            const string& browseName,
            const string& displayName,
            const string& description,
            const SOPC_NodeId& parentNodeId,
            const bool readOnly):
                mNodeId(nodeId),
                mBrowseName(browseName),
                mDisplayName(displayName),
                mDescription(description),
                mParentNodeId(parentNodeId),
                mReadOnly(readOnly) {
    }
    const string mNodeId;
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
    void insertAndCompleteReferences(NodeVect_t* nodes, const std::string& typeId);
 protected:
    explicit CNode(SOPC_StatusCode defaultStatusCode = GoodStatus);
    SOPC_AddressSpace_Node mNode;
};  // class CNode

/**
 * \brief Contains common code to all Variable nodes
 */
class CCommonVarNode : public CNode {
 public:
    explicit CCommonVarNode(const CVarInfo& varInfo);
};

/**
 * \brief Contains specialization of a variable node
 */
class CVarNode : public CCommonVarNode {
 public:
    explicit CVarNode(const CVarInfo& varInfo, SOPC_BuiltinId sopcTypeId);

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
    virtual ~Server_AddrSpace(void);

    /**
     * The content of the address space.
     */
    NodeVect_t nodes;
};  // Server_AddrSpace

}   // namespace s2opc_north

#endif  // INCLUDE_OPCUA_SERVER_ADDRSPACE_H_
