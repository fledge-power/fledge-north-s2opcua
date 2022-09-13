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
#include <vector>
#include <string>

extern "C" {
// S2OPC headers
#include "s2opc/common/sopc_assert.h"
#include "s2opc/common/sopc_builtintypes.h"
#include "s2opc/clientserver/sopc_address_space.h"
};

// Fledge headers
#include "logger.h"
#include "rapidjson/document.h"

/* HELPER MACROS*/
#define DEBUG Logger::getLogger()->debug
#define INFO Logger::getLogger()->info
#define WARNING Logger::getLogger()->warn
#define ERROR Logger::getLogger()->error
#define FATAL Logger::getLogger()->fatal

// Improve SOPC_ASSERT to allow run-time elaborated messages
#define ASSERT(c,  ...) do { \
    if (!(c)) {\
        FATAL("ASSERT FAILED:" __VA_ARGS__);\
        SOPC_ASSERT(false);\
    }\
} while (0)

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
typedef std::vector<SOPC_AddressSpace_Node*> NodeVect_t;

/**************************************************************************/
struct CVarInfo {
    explicit CVarInfo(const string& json);
    CVarInfo(const string& nodeId,
            const string& browseName,
            const string& displayName,
            const string& description,
            const string& parentNodeId,
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
    const string mParentNodeId;
    const bool mReadOnly;
};  // class CVarInfo

/**************************************************************************/
/**
 * \brief an OPCUA Node class
 */
class CNode {
 public:
    inline SOPC_AddressSpace_Node* get(void) {return &mNode;}
    void insertAndCompleteReferences(NodeVect_t* nodes);
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
    explicit CVarNode(const CVarInfo& varInfo, uint32_t defVal);

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
     * \param json A string providing the Address space content, with following format:
     *  "[ { "TODO" : "TODO", } ]
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
