/*
 * Fledge north service plugin
 *
 * Copyright (c) 2021 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Amandeep Singh Arora / Jeremie Chabod
 */
#ifndef _OPCUA_SERVER_ADDRSPACE_H
#define _OPCUA_SERVER_ADDRSPACE_H

// System headers
#include <stdint.h>
#include <stdlib.h>
#include <vector>

extern "C" {
// S2OPC headers
#include "s2opc/common/sopc_builtintypes.h"
#include "s2opc/clientserver/sopc_address_space.h"
};

// Fledge headers
#include <logger.h>

namespace s2opc_north
{
/** Vector of nodes */
typedef std::vector<SOPC_AddressSpace_Node> NodeVect_t;

class Server_AddrSpace
{
public:
    Server_AddrSpace(const std::string& json);
    virtual ~Server_AddrSpace(void);
    mutable NodeVect_t nodes;
};
}

#endif // _OPCUA_SERVER_ADDRSPACE_H
