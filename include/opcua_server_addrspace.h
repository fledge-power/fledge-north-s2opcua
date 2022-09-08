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
#include "s2opc/common/sopc_builtintypes.h"
#include "s2opc/clientserver/sopc_address_space.h"
};

// Fledge headers
#include "logger.h"

extern "C" {
// Nano NS0 namespace
extern const uint32_t SOPC_Embedded_AddressSpace_nNodes_nano;
extern SOPC_AddressSpace_Node SOPC_Embedded_AddressSpace_Nodes_nano[];
}

namespace s2opc_north {
/** Vector of nodes */
typedef std::vector<SOPC_AddressSpace_Node*> NodeVect_t;

/**
 * \brief THis calls represents the content of an address space
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
